#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "task_sendfile.h"
#include "upstream.h"
#include "define.h"
#include "magic.h"

/* forward decl: defined after sendfile_rx (used by the rx path) */
static int sendfile_meta_record(struct sendfile_task *sft, int seg_index,
				uint32_t checksum);

/** task_create_sendfile - create subtask
 *
 */
struct task *task_create_sendfile(unsigned short n)
{
	size_t task_size =
		sizeof(struct sendfile_task) +
		sizeof(struct sendfile_subtask) * n;

	struct task *task = (struct task*)malloc(task_size);
	if (!task) {
		return NULL;
	}
	memset(task, 0, task_size);
	task->init = sendfile_init;
	task->nego = sendfile_nego;
	task->nego_ack = sendfile_nego_ack;
	task->exit = sendfile_exit;

	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);

	/* stream 0 */
	struct subtask *sub = &sft->sfst[0].sub;
	sub->task = task;
	sub->rx_func = sendfile_ctrl_rx;
	sub->tx_func = sendfile_ctrl_tx;
	sub->done = sendfile_done;
	sub->no = 0;
	// rlog("sub %d %p", 0, sub);

	for (int i = 1; i < n; i++) {
		struct subtask *sub = &sft->sfst[i].sub;
		sub->task = task;
		sub->rx_func = sendfile_rx;
		sub->tx_func = sendfile_tx;
		sub->done = sendfile_done;
		sub->no = i;
		// rlog("sub %d %p", i, sub);
	}

	return task;
}


/* Arm the SEND side's data streams for transmit.  Completed segments
 * (resume_bitmap) are skipped and counted done (their write side is closed
 * so the receiver sees EOF); the rest get their tx buffer pointed at the
 * mmap and wantwrite.  Returns 0 on success, -1 on protocol error. */
static int sendfile_arm_streams(struct sendfile_task *sft,
				struct lsquic_conn_ctx *lconn_ctx)
{
	struct task *task = &sft->task;
	unsigned short n_seg = (unsigned short)(task->n_sub - 1);
	struct lsquic_stream_ctx *pos = NULL;

	list_for_each_entry(pos, &lconn_ctx->running_stream_head, stream_node) {
		struct sendfile_subtask *sfst = (struct sendfile_subtask*)pos->subtask;
		int seg = (int)sfst->sub.no - 1;
		if (seg < 0 || seg >= n_seg)
			return -1;

		if (sft->resuming && sft->resume_bitmap[seg]) {
			/* Receiver already holds this segment: send nothing. */
			sfst->length = 0;
			sfst->data = NULL;
			if (sfst->sub.done(pos) != TASK_DONE)
				return -1;
			lsquic_stream_wantwrite(pos->stream, 0);
			lsquic_stream_shutdown(pos->stream, 1);
			clog("stream %p seg %d already complete, skipped",
			     pos->stream, seg);
			continue;
		}

		struct sk_buff *skb = pos->tx;
		skb->head = sfst->data;
		skb->data = skb->head;
		skb->len = sfst->length;
		skb->tail = skb->len;
		skb->end = skb->len;
		skb->offset = 0;
		lsquic_stream_wantwrite(pos->stream, 1);
	}

	return 0;
}

ssize_t sendfile_ctrl_rx(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = sc->rx;
	struct upstream_skb_head head;

	/* decode the wire control frame (nego echo / done) */
	int frame_status = task_frame_validate(skb->head, skb->len, &head);
	if (frame_status == 0) {
		return 0;   /* need more bytes */
	}
	if (frame_status < 0) {
		return TASK_FAIL;   /* malformed */
	}

	uint16_t flags = task_frame_peek_flags(skb->head);
	if (flags & ACE_FRAME_FLAG_LAST) {
		ylog("TASK_DONE");
		return TASK_DONE;
	}

	ylog("length %u sendfile %u stream %u flags %u",
			head.length, head.theme, head.serial, flags);

	/* start each stream except stream 0 the control */
	struct lsquic_conn *lconn = lsquic_stream_conn(sc->stream);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
	if (!lconn_ctx || sc->stream != lconn_ctx->s0 || !lconn_ctx->task) {
		return TASK_FAIL;
	}
	struct task *task = (struct task*)lconn_ctx->task;
	struct sendfile_task *sft =
		container_of(task, struct sendfile_task, task);
	struct lsquic_stream_ctx *pos = NULL;

	if (flags & ACE_FRAME_FLAG_CONTROL) {
		/* Resume bitmap frame — SEND side only.  Decode the per-segment
		 * done flags, then arm only the missing segments. */
		if (task->role != TASK_ROLE_SEND)
			return TASK_FAIL;
		const unsigned char *bitmap = NULL;
		uint16_t n_seg = 0;
		if (ace_sendfile_resume_decode(skb->head + ACE_FRAME_HDR_LEN,
					       head.length, &n_seg, &bitmap) != 0)
			return TASK_FAIL;
		if (n_seg != task->n_sub - 1)
			return TASK_FAIL;
		memcpy(sft->resume_bitmap, bitmap, n_seg);
		sft->resuming = 1;
		ylog("resume bitmap received: %u segments", n_seg);
		if (sendfile_arm_streams(sft, lconn_ctx) != 0)
			return TASK_FAIL;
		/* SEND resets the control-stream rx buffer. */
		sc->rx->len = 0;
		sc->rx->tail = 0;
		sc->rx->data = sc->rx->head;
	} else if (TASK_ROLE_SEND == task->role) {
		if (sendfile_arm_streams(sft, lconn_ctx) != 0)
			return TASK_FAIL;
		/* TASK_ROLE_SEND should reset skb */
		sc->rx->len = 0;
		sc->rx->tail = 0;
		sc->rx->data = sc->rx->head;
	} else {
		list_for_each_entry(pos, &lconn_ctx->pending_stream_head, stream_node) {
			struct sendfile_subtask *sfst = (struct sendfile_subtask*)pos->subtask;
			if (sft->resuming &&
			    sft->resume_bitmap[(int)sfst->sub.no - 1]) {
				/* Already complete: leave the default rx buffer so
				 * the stream's EOF is handled normally. */
				continue;
			}
			struct sk_buff *skb = pos->rx;
			clog("stream %p subtask %p write on %p length %d",
					pos->stream, sfst, skb->data, skb->len);
			/* set rx buffer to mmap()ed area */
			skb->head = sfst->data;
			skb->data = skb->head;
			skb->len = 0;
			skb->tail = 0;
			skb->end = sfst->length;
			skb->offset = 0;
			SKB_DUMP(skb);
			clog("stream %p sc %p subtask %p", pos->stream, pos, sfst);
		}
		/* no reset because TASK_ROLE_RECV use this skb to echo back */
	}

	return 0;
}

ssize_t sendfile_ctrl_tx(struct lsquic_stream_ctx *sc)
{
	lsquic_stream_flush(sc->stream);
	clog("write off and read on");
	lsquic_stream_wantwrite(sc->stream, 0);
	lsquic_stream_wantread(sc->stream, 1);
	return TASK_GOON;
}

ssize_t sendfile_rx(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = sc->rx;

	struct sendfile_subtask *sfst = (struct sendfile_subtask*)sc->subtask;

	if (unlikely(sfst->length <= skb->len)) {
		/* segment fully received: record its checksum in the metadata
		 * sidecar (used for resume-time verification). */
		struct sendfile_task *sft =
			container_of(sfst->sub.task, struct sendfile_task, task);
		uint32_t cksum = task_checksum32(sfst->data, sfst->length);
		if (sendfile_meta_record(sft, (int)sfst->sub.no - 1, cksum) != 0)
			return TASK_FAIL;
		// SKB_DUMP(skb);
		// clog("sc %p rx_bytes %lu", sc, sc->rx_bytes);
		/* reset skb memory */
		/* there is only one skb in list, and the memory is unmap()ed,
		 * so just reset everything */
		skb->head = NULL;
		skb->data = NULL;
		skb->offset = 0;
		skb->len = 0;
		skb->tail = 0;
		skb->end = 0;
		return TASK_DONE;
	} else {
		// clog();
	}
	return TASK_GOON;
}

/**
 * on_write() must make sure len == offset
 */
ssize_t sendfile_tx(struct lsquic_stream_ctx *sc)
{
	// clog();
	struct sk_buff *skb = sc->tx;

	struct sendfile_subtask *sfst = (struct sendfile_subtask*)sc->subtask;

	if (unlikely(sfst->length <= skb->offset)) {
		lsquic_stream_wantwrite(sc->stream, 0);
		lsquic_stream_flush(sc->stream);
		// SKB_DUMP(skb);
		// clog("sc %p tx_bytes %lu", sc, sc->tx_bytes);
		/* reset skb memory */
		/* there is only one skb in list, and the memory is unmap()ed,
		 * so just reset everything */
		skb->head = NULL;
		skb->data = NULL;
		skb->offset = 0;
		skb->len = 0;
		skb->tail = 0;
		skb->end = 0;
		return TASK_DONE;
	}
	// clog();
	return TASK_GOON;
}

/* magic - determine file type
 * @file: the file whose type is to be determined
 *
 * Caller should free the returned value
 */

char *magic(const char *file)
{
	char *type = NULL;
	magic_t ctx = magic_open(0);
	if (!ctx) {
		eslog("magic_open(0)");
		return NULL;
	}
	if (magic_load(ctx, NULL) != 0) {
		eslog("magic_load(%p system database)", ctx);
		goto DONE;
	}
	/* libmagic frees this pointer */
	const char *file_desc = magic_file(ctx, file);
	if (file_desc) {
		/* so we may as well copy the result */
		type = (char*)malloc(strlen(file_desc) + 1);
		memcpy(type, file_desc, strlen(file_desc) + 1);
	} else {
		eslog("magic_file(%p %s)", ctx, file);
	}

DONE:
	magic_close(ctx);
	return type;
}

/*
   int sendfile_init_client(struct task *task)
   {
   return 0;
   }
   */


/* ---- Phase 2: .part segments + metadata sidecar ---- */

static int sendfile_part_path(char *out, size_t outsz, const char *file, int k)
{
	int n = snprintf(out, outsz, "%s/%s.part.%d", TASK_RECEIVE_ROOT, file, k);
	return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

static int sendfile_meta_path(char *out, size_t outsz, const char *file)
{
	int n = snprintf(out, outsz, "%s/%s.acemeta", TASK_RECEIVE_ROOT, file);
	return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

/* Write the metadata header + zeroed per-segment records (crash-safe: the
 * records are pre-allocated so in-place pwrite updates never move data). */
static int sendfile_meta_init(struct sendfile_task *sft, int n_segments,
			      const struct ace_sendfile_chunk *chunks)
{
	char meta_path[PATH_MAX];
	if (sendfile_meta_path(meta_path, sizeof(meta_path), sft->file) != 0)
		return -1;

	int fd = open(meta_path, O_CREAT | O_WRONLY | O_TRUNC,
		      S_IRUSR | S_IWUSR);
	if (fd < 0) {
		eslog("open(%s)", meta_path);
		return -1;
	}

	struct ace_sf_meta_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));
	memcpy(hdr.magic, ACE_SF_META_MAGIC, 4);
	hdr.version = ACE_SF_META_VERSION;
	hdr.n_segments = (uint16_t)n_segments;
	hdr.file_length = (uint32_t)sft->length;
	hdr.file_hash = sft->nego->file_hash;

	if (write(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
		goto fail;
	for (int k = 0; k < n_segments; k++) {
		struct ace_sf_meta_seg seg;
		memset(&seg, 0, sizeof(seg));
		seg.offset = chunks[k].offset;
		seg.size = chunks[k].size;
		if (write(fd, &seg, sizeof(seg)) != (ssize_t)sizeof(seg))
			goto fail;
	}
	if (fsync(fd) != 0)
		goto fail;
	close(fd);
	return 0;

fail:
	close(fd);
	return -1;
}

/* Mark one segment complete + verified (checksum recorded for resume). */
static int sendfile_meta_record(struct sendfile_task *sft, int seg_index,
				uint32_t checksum)
{
	/* Flush the segment's .part bytes to disk BEFORE marking it done, so a
	 * crash can never leave a done flag pointing at torn data.  The .part
	 * is written via MAP_SHARED; fsync on the file flushes those dirty
	 * pages too.  Ordering (part fsync → pwrite done → acemeta fsync) is
	 * the crash-safety invariant — do NOT reorder. */
	char part_path[PATH_MAX];
	if (sendfile_part_path(part_path, sizeof(part_path),
			       sft->file, seg_index) != 0)
		return -1;
	int pfd = open(part_path, O_RDONLY | O_NOFOLLOW);
	if (pfd < 0) {
		eslog("open(%s)", part_path);
		return -1;
	}
	if (fsync(pfd) != 0) {
		eslog("fsync(%s)", part_path);
		close(pfd);
		return -1;
	}
	close(pfd);

	char meta_path[PATH_MAX];
	if (sendfile_meta_path(meta_path, sizeof(meta_path), sft->file) != 0)
		return -1;

	int fd = open(meta_path, O_WRONLY);
	if (fd < 0) {
		eslog("open(%s)", meta_path);
		return -1;
	}

	struct ace_sf_meta_seg seg;
	memset(&seg, 0, sizeof(seg));
	seg.offset = (uint64_t)sft->sfst[seg_index + 1].offset;
	seg.size = (uint32_t)sft->sfst[seg_index + 1].length;
	seg.checksum = checksum;
	seg.done = 1;

	off_t off = (off_t)(sizeof(struct ace_sf_meta_hdr) +
			    (size_t)seg_index * sizeof(struct ace_sf_meta_seg));
	ssize_t n = pwrite(fd, &seg, sizeof(seg), off);
	if (n != (ssize_t)sizeof(seg)) {
		close(fd);
		return -1;
	}
	if (fsync(fd) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/* Load the metadata sidecar and fill sft->resume_bitmap with per-segment
 * done flags.  A segment is marked complete only if the metadata record is
 * flagged done, its .part exists with the recorded size, and its content
 * still verifies against the recorded checksum.  Returns:
 *   1  metadata present and matched this transfer (bitmap filled)
 *   0  no usable metadata — fresh transfer (bitmap left as-is)
 *  -1  I/O error reading metadata (caller aborts) */
static int sendfile_meta_load(struct sendfile_task *sft, int n_segments)
{
	char meta_path[PATH_MAX];
	if (sendfile_meta_path(meta_path, sizeof(meta_path), sft->file) != 0)
		return -1;

	int fd = open(meta_path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;   /* no prior transfer */
		eslog("open(%s)", meta_path);
		return -1;
	}

	struct ace_sf_meta_hdr hdr;
	if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
		close(fd);
		return -1;
	}

	/* The header must describe exactly this transfer, including the source
	 * file identity: a same-name same-length but different-content file has
	 * a different file_hash, so its stale .part files are rejected. */
	if (memcmp(hdr.magic, ACE_SF_META_MAGIC, 4) != 0 ||
	    hdr.version != ACE_SF_META_VERSION ||
	    hdr.n_segments != (uint16_t)n_segments ||
	    hdr.file_length != (uint32_t)sft->length ||
	    hdr.file_hash != sft->nego->file_hash) {
		close(fd);
		return 0;   /* stale / mismatched: start over */
	}

	memset(sft->resume_bitmap, 0, sizeof(sft->resume_bitmap));
	for (int k = 0; k < n_segments; k++) {
		struct ace_sf_meta_seg seg;
		if (read(fd, &seg, sizeof(seg)) != (ssize_t)sizeof(seg)) {
			close(fd);
			return -1;
		}
		if (!seg.done)
			continue;

		char part_path[PATH_MAX];
		if (sendfile_part_path(part_path, sizeof(part_path),
				       sft->file, k) != 0) {
			close(fd);
			return -1;
		}

		/* The part must exist with the recorded size, and its content
		 * must still verify.  Re-checksums the whole segment, so resume
		 * validation is O(bytes already transferred). */
		int pfd = open(part_path, O_RDONLY | O_NOFOLLOW);
		if (pfd < 0)
			continue;
		struct stat st;
		if (fstat(pfd, &st) != 0 || st.st_size != (off_t)seg.size) {
			close(pfd);
			continue;
		}
		if (seg.size > 0) {
			void *p = mmap(NULL, seg.size, PROT_READ, MAP_SHARED, pfd, 0);
			if (p == MAP_FAILED) {
				close(pfd);
				continue;
			}
			uint32_t cksum = task_checksum32(p, seg.size);
			munmap(p, seg.size);
			if (cksum != seg.checksum) {
				close(pfd);
				continue;
			}
		}
		close(pfd);
		sft->resume_bitmap[k] = 1;
	}

	close(fd);
	return 1;
}

/* Concatenate all .part files into the final file, in segment order.
 * Writes to a sibling temp file and atomically renames it into place, so a
 * crash mid-concat never exposes a truncated/partial final file. */
static int sendfile_concat(struct sendfile_task *sft, int n_segments)
{
	char final_path[PATH_MAX];
	if (task_receive_path(final_path, sizeof(final_path),
			      TASK_RECEIVE_ROOT, sft->file) != 0)
		return -1;

	char tmp_path[PATH_MAX];
	if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path) >=
	    (int)sizeof(tmp_path))
		return -1;

	int out_fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW,
			  S_IRUSR | S_IWUSR);
	if (out_fd < 0) {
		eslog("open(%s)", tmp_path);
		return -1;
	}

	char buf[65536];
	for (int k = 0; k < n_segments; k++) {
		char part_path[PATH_MAX];
		if (sendfile_part_path(part_path, sizeof(part_path),
				       sft->file, k) != 0)
			goto fail;
		int in_fd = open(part_path, O_RDONLY);
		if (in_fd < 0) {
			eslog("open(%s)", part_path);
			goto fail;
		}
		ssize_t r;
		while ((r = read(in_fd, buf, sizeof(buf))) > 0) {
			ssize_t w = write(out_fd, buf, (size_t)r);
			if (w != r) {
				close(in_fd);
				goto fail;
			}
		}
		if (r < 0) {
			/* A read error (not EOF) would otherwise publish a truncated
			 * final file via the atomic rename. */
			eslog("read(%s)", part_path);
			close(in_fd);
			goto fail;
		}
		close(in_fd);
	}

	if (fsync(out_fd) != 0)
		goto fail;
	if (close(out_fd) != 0) {
		unlink(tmp_path);
		return -1;
	}

	if (rename(tmp_path, final_path) != 0) {
		eslog("rename(%s -> %s)", tmp_path, final_path);
		unlink(tmp_path);
		return -1;
	}

	/* Make the rename durable. */
	int dir_fd = open(TASK_RECEIVE_ROOT, O_RDONLY | O_DIRECTORY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	return 0;

fail:
	close(out_fd);
	unlink(tmp_path);
	return -1;
}

/* Remove the .part files and metadata sidecar. */
static void sendfile_cleanup_parts(struct sendfile_task *sft, int n_segments)
{
	char path[PATH_MAX];
	for (int k = 0; k < n_segments; k++) {
		if (sendfile_part_path(path, sizeof(path), sft->file, k) == 0)
			unlink(path);
	}
	if (sendfile_meta_path(path, sizeof(path), sft->file) == 0)
		unlink(path);
}

/* Build the explicit chunk plan: n_segments contiguous segments that tile
 * the file exactly.  Chunk k covers [quota*k, quota*k + size).  Caller owns
 * the returned array. */
static struct ace_sendfile_chunk *sendfile_build_chunks(size_t length,
							unsigned short n_segments)
{
	if (n_segments == 0)
		return NULL;

	struct ace_sendfile_chunk *chunks =
		(struct ace_sendfile_chunk*)calloc(n_segments, sizeof(*chunks));
	if (!chunks)
		return NULL;

	size_t quota = length / n_segments;
	for (unsigned short i = 0; i < n_segments; i++) {
		chunks[i].offset = quota * i;
		chunks[i].size = (i == n_segments - 1)
			? (length - quota * i) : quota;
	}

	return chunks;
}

/* Snapshot the source file into an immutable, sealed memfd.  A direct mmap()
 * of the source is unsafe: MAP_PRIVATE only makes writes *through the mapping*
 * copy-on-write — an external write to the source after mmap() is still
 * visible, and a truncate can raise SIGBUS on access, so the identity hash
 * and the transmitted bytes could silently diverge.  The snapshot is a
 * separate, anonymous inode: external writes to the source path can never
 * touch it.  On any inconsistency (read/write error, or the file shrank
 * mid-copy) it fails rather than hash half a file. */
static int sendfile_snapshot(int src_fd, off_t length, int *snap_fd_out,
			     unsigned int *seals_out)
{
	int snap_fd = memfd_create("ace-sendfile", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (snap_fd < 0) {
		eslog("memfd_create()");
		return -1;
	}

	char buf[65536];
	off_t remaining = length;
	while (remaining > 0) {
		size_t want = (remaining < (off_t)sizeof(buf))
			? (size_t)remaining : sizeof(buf);
		ssize_t r = read(src_fd, buf, want);
		if (r <= 0) {
			/* r == 0: the source shrank between fstat and copy;
			 * r < 0: read error.  Either way the snapshot would be
			 * inconsistent with the negotiated length. */
			eslog("read(%d) snapshot", src_fd);
			close(snap_fd);
			return -1;
		}
		char *p = buf;
		ssize_t left = r;
		while (left > 0) {
			ssize_t w = write(snap_fd, p, (size_t)left);
			if (w < 0) {
				eslog("write(memfd) snapshot");
				close(snap_fd);
				return -1;
			}
			p += w;
			left -= w;
		}
		remaining -= r;
	}

	/* Harden the snapshot: F_SEAL_WRITE | F_SEAL_SEAL makes the memfd
	 * permanently read-only.  This works because memfd_create was called
	 * with MFD_ALLOW_SEALING — without it the kernel (>= 5.1) pre-applies
	 * F_SEAL_SEAL, so F_ADD_SEALS here would ALWAYS fail with EPERM.  The
	 * seal is still best-effort: if a sandbox forbids F_ADD_SEALS outright,
	 * the snapshot stays immutable anyway — the memfd is anonymous (no
	 * path) and the only fd is closed right after mmap, leaving a read-only
	 * mapping as the sole reference. */
	if (fcntl(snap_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SEAL) != 0)
		blog("F_ADD_SEALS unavailable (%s); snapshot is anonymous but unsealed",
		     strerror(errno));

	/* Read the seals back so the caller (and the test) can assert the seal
	 * actually took effect, rather than trusting the fcntl return value. */
	if (seals_out) {
		int seals = fcntl(snap_fd, F_GET_SEALS);
		*seals_out = (seals >= 0) ? (unsigned int)seals : 0u;
	}

	*snap_fd_out = snap_fd;
	return 0;
}

int sendfile_init(struct task *task)
{
	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);
	clog("sft %p task %p", sft, task);
	if (!sft->task.n_sub) {
		errno = EPERM;
		return -1;
	}

	int fd = 0;

	/* stream 0 is not carrying data */
	unsigned short int n_sub_data = task->n_sub - 1;
	if (!ace_task_memory_valid(n_sub_data, SENDFILE_BLOCK_SIZE)) {
		errno = ENOMEM;
		return -1;
	}

	if (TASK_ROLE_RECV == task->role) {
		struct ace_sendfile_nego *nego = sft->nego;
		char receive_file[PATH_MAX];
		sft->path = strdup(nego->path);
		if (!sft->path)
			return -1;
		sft->file = strdup(nego->file);
		if (!sft->file)
			return -1;
		sft->type = strdup(nego->type);
		if (!sft->type)
			return -1;
		sft->length = nego->file_length;
		if (task_receive_path(receive_file, sizeof(receive_file),
				TASK_RECEIVE_ROOT, sft->file) != 0) {
			errno = EINVAL;
			return -1;
		}
		if (mkdir(TASK_RECEIVE_ROOT, 0700) != 0 && errno != EEXIST) {
			eslog("mkdir(%s)", TASK_RECEIVE_ROOT);
			return -1;
		}
		struct stat root_st;
		if (lstat(TASK_RECEIVE_ROOT, &root_st) != 0 || !S_ISDIR(root_st.st_mode) ||
				S_ISLNK(root_st.st_mode)) {
			errno = ENOTDIR;
			eslog("unsafe receive root %s", TASK_RECEIVE_ROOT);
			return -1;
		}
		clog("about to receive file \"%s\"", receive_file);

		if (!sft->nego || !sft->nego->chunks ||
		    sft->nego->n_segments != n_sub_data) {
			errno = EPROTO;
			return -1;
		}
		const struct ace_sendfile_chunk *chunks = sft->nego->chunks;

		/* Phase 3: detect a prior partial transfer.  resume_bitmap is
		 * filled with done flags only for segments whose .part exists,
		 * matches the recorded size, and still verifies. */
		int meta_status = sendfile_meta_load(sft, (int)n_sub_data);
		if (meta_status < 0)
			return -1;
		int n_done = 0;
		for (int k = 0; k < n_sub_data; k++)
			n_done += sft->resume_bitmap[k] != 0;
		/* Partial resume: at least one complete and one missing segment.
		 * All-zero (fresh) retransfers everything.  All-done (every
		 * segment already present + verified) skips transfer entirely:
		 * the segments are counted done up front, and the completion
		 * frame is emitted right after the resume bitmap is flushed. */
		if (n_done == n_sub_data && n_sub_data > 0) {
			sft->resuming = 1;
			task->done_after_reply = 1;
		} else if (n_done > 0) {
			sft->resuming = 1;
		} else {
			sft->resuming = 0;
			memset(sft->resume_bitmap, 0, sizeof(sft->resume_bitmap));
		}

		/* subtask 0 is for stream 0; each data stream writes its own
		 * contiguous segment to a separate .part file. */
		sft->index = 1;
		for (int k = 0; k < n_sub_data; k++) {
			struct sendfile_subtask *sfst = &sft->sfst[k + 1];
			sfst->length = chunks[k].size;
			sfst->offset = chunks[k].offset;
			if (sft->resume_bitmap[k]) {
				/* Already complete + verified: keep the .part,
				 * skip the mmap, count it done up front. */
				sfst->data = NULL;
				task->n_sub_done++;
				continue;
			}
			if (chunks[k].size == 0) {
				sfst->data = NULL;
				continue;
			}
			char part_path[PATH_MAX];
			if (sendfile_part_path(part_path, sizeof(part_path),
					       sft->file, k) != 0) {
				errno = ENAMETOOLONG;
				return -1;
			}
			fd = open(part_path, O_CREAT | O_RDWR | O_TRUNC | O_NOFOLLOW,
				  S_IRUSR | S_IWUSR);
			if (fd < 0) {
				eslog("open(%s)", part_path);
				return -1;
			}
			/* Stretch the part to the segment size for the mmap. */
			if (-1 == lseek(fd, (off_t)chunks[k].size - 1, SEEK_SET)) {
				eslog("lseek(%d %lu)", fd,
				      (unsigned long)chunks[k].size);
				close(fd);
				return -1;
			}
			if (1 != write(fd, "", 1)) {
				eslog("write(%d)", fd);
				close(fd);
				return -1;
			}
			sfst->data = (char*)mmap(NULL, chunks[k].size,
						 PROT_READ | PROT_WRITE,
						 MAP_SHARED, fd, 0);
			close(fd);
			if ((void*)-1 == sfst->data) {
				eslog("mmap(%s)", part_path);
				sfst->data = NULL;
				return -1;
			}
			log("mmap part %s", part_path);
		}

		/* Write the metadata sidecar header + zeroed segment records on a
		 * fresh transfer.  On resume the existing sidecar is preserved so
		 * completed segments stay recorded. */
		if (!sft->resuming &&
		    sendfile_meta_init(sft, n_sub_data, chunks) != 0)
			return -1;
		return 0;
	} else {
		/* TASK_ROLE_SEND */
		/* init sendfile task */
		size_t len = strlen((const char*)task->data + sizeof(struct upstream_skb_head));
		if (!len) {
			return -1;
		}

		/* TODO File too large */
		/* EFBIG 27 */
		/* File name too long */
		/* ENAMETOOLONG	36 */
		clog("TODO File too large");

		char *file = (char*)malloc(len + 1);
		if (!file) {
			return -1;
		}
		memcpy(file, (const char*)task->data + sizeof(struct upstream_skb_head), len + 1);
		sft->source_path = file;
		fd = open(file, O_RDONLY);
		if (-1 == fd) {
			elog("open(%s), %d %s", file, errno, strerror(errno));
			return -1;
		}
		struct stat st;
		if (-1 == fstat(fd, &st)) {
			elog("fstat(%d), %d %s", fd, errno, strerror(errno));
			close(fd);
			return -1;
		} else {
			;
		}
		sft->length = st.st_size;
		if (!sft->length) {
			rlog("file %s is empty", file);
		}

		/* Reject a segment count above the byte length: it would yield
		 * zero-length segments, which the receiver cannot complete
		 * (its EOF path never bumps n_sub_done). */
		if ((size_t)n_sub_data > sft->length) {
			elog("segment count %u exceeds file length %lu",
			     n_sub_data, (unsigned long)sft->length);
			close(fd);
			free(sft->source_path);
			sft->source_path = NULL;
			return -1;
		}

		/* Snapshot the source into an immutable, sealed memfd first, then
		 * mmap that snapshot.  Mapping the source directly is unsafe: the
		 * identity hash is computed once, but the transmitted bytes must
		 * match it exactly — an external write to the source after mmap()
		 * would break that invariant (and a truncate could SIGBUS). */
		int snap_fd;
		if (sendfile_snapshot(fd, (off_t)sft->length, &snap_fd,
				      &sft->snapshot_seals) != 0) {
			close(fd);
			free(sft->source_path);
			sft->source_path = NULL;
			return -1;
		}
		close(fd);

		sft->data = (char*)mmap(NULL, sft->length, PROT_READ, MAP_PRIVATE,
					snap_fd, 0);
		close(snap_fd);
		if ((void*)-1 == sft->data) {
			eslog("mmap(snapshot %s)", file);
			sft->data = NULL;
			free(sft->source_path);
			sft->source_path = NULL;
			return -1;
		}
		/* Whole-file identity hash over the sealed snapshot: byte-identical
		 * to what is transmitted, so the receiver can reject a same-name
		 * same-length but different-content source with confidence. */
		sft->file_hash = task_checksum32(sft->data, sft->length);
		unsigned int n = sft->length / 4;
		clog("file %s %ld %d\n"
				"mmap %p - %p", file, sft->length, n,
				sft->data, sft->data + sft->length);

		char *type = magic(file);
		if (type) {
			sft->type = type;
			clog("%s: %ld \"%s\"", file, strlen(type) + 1, sft->type);
		} else {
			static const char fallback_type[] = "application/octet-stream";
			sft->type = strdup(fallback_type);
			if (!sft->type) {
				munmap(sft->data, sft->length);
				return -1;
			}
		}
		sft->file = basename(file);
		sft->path = dirname(file);
	}

	/* SEND: build the chunk plan and lay out the data-stream subtasks. */
	struct ace_sendfile_chunk *chunks =
		sendfile_build_chunks(sft->length, n_sub_data);
	if (!chunks) {
		munmap(sft->data, sft->length);
		return -1;
	}
	sft->chunks = chunks;

	log("subtask %u", n_sub_data);
	struct sendfile_subtask *sfst = NULL;
	size_t tl = 0;
	for (int i = 1; i <= n_sub_data; i++) {
		sfst = &sft->sfst[i];
		sfst->data = sft->data + chunks[i - 1].offset;
		sfst->length = chunks[i - 1].size;
		sfst->offset = chunks[i - 1].offset;
		tl += sfst->length;
		ylog("sfst[%d] %p data %p offset %lu length %ld",
				i, sfst, sfst->data,
				(unsigned long)chunks[i - 1].offset, sfst->length);
	}
	ylog("%s %s %ld <=> %ld", sft->path, sft->file, sft->length, tl);
	if (sft->length != tl) {
		return -1;
	}

	return 0;
}


static void sendfile_nego_free(struct ace_sendfile_nego *nego)
{
	if (!nego)
		return;

	free((void *)nego->path);
	free((void *)nego->file);
	free((void *)nego->type);
	free((void *)nego->chunks);
	free(nego);
}

static struct ace_sendfile_nego *sendfile_nego_dup(
	const struct ace_sendfile_nego *source)
{
	struct ace_sendfile_nego *copy = calloc(1, sizeof(*copy));
	if (!copy)
		return NULL;

	*copy = *source;
	copy->path = NULL;
	copy->file = NULL;
	copy->type = NULL;
	copy->chunks = NULL;
	copy->path = strdup(source->path);
	copy->file = strdup(source->file);
	copy->type = strdup(source->type);
	if (source->n_segments > 0) {
		struct ace_sendfile_chunk *dup_chunks =
			(struct ace_sendfile_chunk*)malloc(
				(size_t)source->n_segments * sizeof(*dup_chunks));
		if (!dup_chunks) {
			sendfile_nego_free(copy);
			return NULL;
		}
		memcpy(dup_chunks, source->chunks,
		       (size_t)source->n_segments * sizeof(*dup_chunks));
		copy->chunks = dup_chunks;
	}
	if (!copy->path || !copy->file || !copy->type) {
		sendfile_nego_free(copy);
		return NULL;
	}

	return copy;
}

int sendfile_nego(struct task *task, struct sk_buff* skb)
{
	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);

	if (TASK_ROLE_RECV == task->role) {
		struct upstream_skb_head head;
		if (task_frame_validate(skb->head, skb->len, &head) != 1 ||
		    task_payload_validate(&head,
			skb->head + ACE_FRAME_HDR_LEN) != 0) {
			errno = EPROTO;
			return -1;
		}

		/* Decode from wire into an owned struct. */
		struct ace_sendfile_nego *nego = calloc(1, sizeof(*nego));
		if (!nego)
			return -1;

		if (ace_sendfile_nego_decode(
			(const unsigned char *)skb->head + ACE_FRAME_HDR_LEN,
			head.length, nego) != 0) {
			free(nego);
			errno = EPROTO;
			return -1;
		}

		/* Dup strings into owned memory (wire buffer is temporary); decode
		 * already materialized the chunk array, which dup copies again. */
		struct ace_sendfile_nego *owned = sendfile_nego_dup(nego);
		free((void *)nego->chunks);
		free(nego);
		if (!owned)
			return -1;
		nego = owned;

		sendfile_nego_dump(nego);
		sft->nego = nego;
		return 0;
	}

	/* Sender: build decoded nego, then encode to wire. */
	struct ace_sendfile_nego nego = {
		.code        = 0,
		.path        = sft->path,
		.path_len    = (uint16_t)(strlen(sft->path) + 1),
		.file        = sft->file,
		.file_len    = (uint16_t)(strlen(sft->file) + 1),
		.type        = sft->type,
		.type_len    = (uint16_t)(strlen(sft->type) + 1),
		.file_length = (uint32_t)sft->length,
		.n_segments  = (uint16_t)(task->n_sub - 1),
		.file_hash   = sft->file_hash,
		.chunks      = sft->chunks,
	};

	/* Allocate owned copy for internal use. */
	struct ace_sendfile_nego *nego_copy = sendfile_nego_dup(&nego);
	if (!nego_copy)
		return -1;

	sendfile_nego_dump(nego_copy);

	/* Encode the wire frame at skb->head and set data/len explicitly,
	 * mirroring the probe path (client_on_new_stream). */
	struct upstream_skb_head *oh = (struct upstream_skb_head*)task->data;
	size_t total = ace_sendfile_nego_encode((unsigned char *)skb->head,
						skb->end, oh->serial, nego_copy);
	if (total == 0) {
		sendfile_nego_free(nego_copy);
		return -1;
	}
	skb->data = skb->head;
	skb->len = (unsigned int)total;
	skb->tail = skb->len;
	skb->offset = 0;

	sft->nego = nego_copy;

	return 0;
}

int sendfile_nego_ack(struct task *task, struct sk_buff *tx, struct sk_buff *rx)
{
	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);

	if (!sft->resuming) {
		/* Fresh transfer: echo the nego back verbatim. */
		if (tx->end < rx->len)
			return -1;
		memcpy(tx->head, rx->head, rx->len);
		tx->data = tx->head;
		tx->len = rx->len;
		tx->tail = rx->len;
		tx->offset = 0;
		return 0;
	}

	/* Resume: answer with an ACE_FRAME_FLAG_CONTROL resume bitmap. */
	ylog("resume: answering nego with %u-segment bitmap",
	     task->n_sub - 1);
	size_t n = ace_sendfile_resume_encode(tx->head, tx->end, 1,
					      (uint16_t)(task->n_sub - 1),
					      sft->resume_bitmap);
	if (n == 0)
		return -1;
	tx->data = tx->head;
	tx->len = (unsigned int)n;
	tx->tail = tx->len;
	tx->offset = 0;
	return 0;
}

/** sendfile_done - the way a task exits
 *
 * @Return: 0 do nothing, 1 shutdown stream read/write
 *   2 close conn, -1 abort conn
 */
int sendfile_done(struct lsquic_stream_ctx *sc)
{
	struct task *task = ((struct subtask*)(sc->subtask))->task;

	// rlog();
	task->n_sub_done++;
	// rlog("task->n_sub_done %lu %u id %lu", task->n_sub_done, task->n_sub, lsquic_stream_id(sc->stream));

	if (task->n_sub_done < (size_t)(task->n_sub - 1)) {
		/* partially done */
		return TASK_DONE;
	}

	if (task->n_sub_done == (size_t)(task->n_sub - 1)) {
		rlog("all done except s0");
		/* all done, except s0 */
		if (TASK_ROLE_RECV == task->role) {
			/* notify sender with a wire frame flagged ACE_FRAME_FLAG_LAST */
			struct lsquic_conn_ctx *lconn_ctx =
				lsquic_conn_get_ctx(lsquic_stream_conn(sc->stream));
			struct lsquic_stream_ctx *s0sc = lsquic_stream_get_ctx(lconn_ctx->s0);
			struct sk_buff *skb = list_first_entry(&s0sc->txq, struct sk_buff, skb_node);
			skb->len = (unsigned int)ace_done_frame_encode(
				(unsigned char *)skb->head, (uint16_t)task->type);
			skb->data = skb->head;
			skb->tail = skb->len;
			skb->offset = 0;
			lsquic_stream_wantwrite(lconn_ctx->s0, 1);
		}
		return TASK_DONE;
	}

	if (task->n_sub_done == (size_t)(task->n_sub)) {
		/* this is stream 0 */
		if (lsquic_stream_id(sc->stream) != 0) {
			return TASK_FAIL;
		}
		ylog("all %lu streams are done, task exiting", task->n_sub_done);
		task->data = (void*)lstream_ctx_del_rxq_first(sc);
		return TASK_EXIT;
	}

	return TASK_FAIL;
}


struct sk_buff *sendfile_exit(struct task *task)
{
	TASK_DUMP(task);
	task_exit(task);
	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);
	unsigned short n_sub_data =
		(unsigned short)(task->n_sub > 0 ? task->n_sub - 1 : 0);

	if (task->role == TASK_ROLE_RECV) {
		/* munmap each segment's .part mapping */
		for (int k = 0; k < n_sub_data; k++) {
			struct sendfile_subtask *sfst = &sft->sfst[k + 1];
			if (sfst->data && sfst->length > 0)
				munmap(sfst->data, sfst->length);
			sfst->data = NULL;
		}
		/* Concatenate on success and drop parts + metadata.  On an
		 * incomplete transfer keep them so the next attempt can resume. */
		if (task->n_sub_done >= task->n_sub) {
			if (sendfile_concat(sft, n_sub_data) != 0)
				eslog("concat failed; leaving .part files for recovery");
			else
				sendfile_cleanup_parts(sft, n_sub_data);
		} else {
			blog("transfer incomplete; keeping .part files + metadata for resume");
		}
		free(sft->path);
		free(sft->file);
		free(sft->type);
	} else {
		if (sft->data && sft->length > 0) {
			if (munmap(sft->data, sft->length) != 0) {
				eslog("munmap(%p %lu)", sft->data, sft->length);
			}
			sft->data = NULL;
		}
		free(sft->source_path);
		free(sft->type);
		free(sft->chunks);
	}
	/* nego owns strdup'd strings in both roles */
	sendfile_nego_free(sft->nego);
	sft->nego = NULL;
	free(sft);
	return NULL;
}


struct subtask *task_get_sendfile_sub_at(struct task *t, unsigned short int n)
{
	struct sendfile_task *sft = container_of(t, struct sendfile_task, task);
	return &sft->sfst[n].sub;
}


struct subtask *task_get_sendfile_sub_next(struct task *t)
{
	struct sendfile_task *sft = container_of(t, struct sendfile_task, task);
	if (sft->index >= t->n_sub) {
		return NULL;
	}
	struct subtask *sub = &sft->sfst[sft->index].sub;
	if (sub) {
		sft->index++;
	}
	return sub;
}

