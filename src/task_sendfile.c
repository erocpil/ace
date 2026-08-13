#include <assert.h>
#include "task_sendfile.h"
#include "upstream.h"
#include "define.h"
#include "magic.h"

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

	if (task_frame_peek_flags(skb->head) & ACE_FRAME_FLAG_LAST) {
		ylog("TASK_DONE");
		return TASK_DONE;
	}

	ylog("length %u sendfile %u stream %u",
			head.length, head.theme, head.serial);

	/* start each stream except stream 0 the control */
	struct lsquic_conn *lconn = lsquic_stream_conn(sc->stream);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
	if (!lconn_ctx || sc->stream != lconn_ctx->s0 || !lconn_ctx->task) {
		return TASK_FAIL;
	}
	struct lsquic_stream_ctx *pos = NULL;
	if (TASK_ROLE_SEND == ((struct task*)lconn_ctx->task)->role) {
		list_for_each_entry(pos, &lconn_ctx->running_stream_head, stream_node) {
			struct sendfile_subtask *sfst = (struct sendfile_subtask*)pos->subtask;
			struct sk_buff *skb = pos->tx;
			clog("stream %p subtask %p write on %p length %d",
					pos->stream, sfst, skb->data, skb->len);
			/* set tx buffer to mmap()ed area */
			skb->head = sfst->data;
			skb->data = skb->head;
			skb->len = sfst->length;
			skb->tail = skb->len;
			skb->end = skb->len;
			skb->offset = 0;
			clog("stream %p sc %p subtask %p read on %p length %d",
					pos->stream, pos, sfst, skb->data, skb->len);
			lsquic_stream_wantwrite(pos->stream, 1);
		}
		/* TASK_ROLE_SEND should reset skb */
		sc->rx->len = 0;
		sc->rx->tail = 0;
		sc->rx->data = sc->rx->head;
	} else {
		list_for_each_entry(pos, &lconn_ctx->pending_stream_head, stream_node) {
			struct sendfile_subtask *sfst = (struct sendfile_subtask*)pos->subtask;
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

int sendfile_init(struct task *task)
{
	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);
	clog("sft %p task %p", sft, task);
	if (!sft->task.n_sub) {
		errno = EPERM;
		return -1;
	}

	int fd = 0;

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

		ylog("receive file %s / %s", sft->path, sft->file);
		/* subtask 0 is for stream 0 */
		/* other stream consume subtask from [1] */
		sft->index = 1;
		ylog("TODO mmap()");
		fd = open(receive_file, O_CREAT | O_RDWR | O_TRUNC | O_NOFOLLOW,
				S_IRUSR | S_IWUSR);
		if (fd < 0) {
			eslog("open(%s)", receive_file);
			return -1;
		}
		/* Stretch the file size to the size of the (mmapped) array of ints */
		if (-1 == lseek(fd, sft->length - 1, SEEK_SET)) {
			eslog("lseek(%d %lu)", fd, sft->length);
			close(fd);
			return -1;
		} else {
			/* Something needs to be written at the end of the file to
			 * have the file actually have the new size.
			 * Just writing an empty string at the current file position will do.
			 */
			if (1 != write(fd, "", 1)) {
				eslog("write(%d)", fd);
				close(fd);
				return -1;
			}
			log("lseek(%ld) and write last byte", sft->length - 1);
		}
		struct stat st;
		if (fstat(fd, &st) == -1 ) {
			eslog("fstat()");
			close(fd);
			return -1;
		} else {
			log("%ld <-> %ld", st.st_size, sft->length);
		}
		sft->data = (char*)mmap(NULL, sft->length, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
		close(fd);
		if ((void*)-1 == sft->data) {
			eslog();
			sft->data = NULL;
			return -1;
		} else {
			log("mmap(%d %s)", fd, receive_file);
		}
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

		/* mmap() the whole file */
		sft->data = (char*)mmap(NULL, sft->length, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if ((void*)-1 == sft->data) {
			eslog("mmap(%s)", file);
			sft->data = NULL;
			return -1;
		} else {
			log("mmap(%d %s)", fd, file);
		}
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

	/* init sendfile subtask */
	/* stream 0 is not carrying data */
	unsigned short int n_sub_data = task->n_sub - 1;
	if (!ace_task_memory_valid(n_sub_data, SENDFILE_BLOCK_SIZE)) {
		errno = ENOMEM;
		return -1;
	}

	/* Determine the chunk plan.  The sender builds it and encodes it in the
	 * nego; the receiver validates the one it received. */
	const struct ace_sendfile_chunk *chunks = NULL;
	if (TASK_ROLE_SEND == task->role) {
		struct ace_sendfile_chunk *built =
			sendfile_build_chunks(sft->length, n_sub_data);
		if (!built) {
			munmap(sft->data, sft->length);
			return -1;
		}
		sft->chunks = built;
		chunks = built;
	} else {
		if (!sft->nego || !sft->nego->chunks ||
		    sft->nego->n_segments != n_sub_data) {
			munmap(sft->data, sft->length);
			errno = EPROTO;
			return -1;
		}
		chunks = sft->nego->chunks;
	}

	log("subtask %u", n_sub_data);
	struct sendfile_subtask *sfst = NULL;
	size_t tl = 0;
	for (int i = 1; i <= n_sub_data; i++) {
		sfst = &sft->sfst[i];
		sfst->data = sft->data + chunks[i - 1].offset;
		sfst->length = chunks[i - 1].size;
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
			struct ace_frame f = {
				.payload_len = 0,
				.theme       = (uint16_t)task->type,
				.stream_id   = 1,
				.flags       = ACE_FRAME_FLAG_LAST,
				.version     = ACE_PROTO_VERSION,
			};
			ace_frame_encode((unsigned char *)skb->head, &f);
			skb->data = skb->head;
			skb->len = ACE_FRAME_HDR_LEN;
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
	if (sft->data && sft->length > 0) {
		if (munmap(sft->data, sft->length) != 0) {
			eslog("munmap(%p %lu)", sft->data, sft->length);
		}
		sft->data = NULL;
	}
	if (task->role == TASK_ROLE_RECV) {
		free(sft->path);
		free(sft->file);
		free(sft->type);
	} else {
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

