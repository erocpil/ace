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
	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;

	/* wait for head */
	if (skb->len < sizeof(struct upstream_skb_head)) {
		return 0;
	}

	/*
	clog();
	SKB_DUMP(sc->rx);
	upstream_skb_head_dump(head);
	*/

	if (!head->length) {
		if ((unsigned short int)-1 == head->theme) {
			ylog("TASK_DONE");
			return TASK_DONE;
		}
	}

	/* check if whole head was received */
	if (skb->len < sizeof(*head) + head->length) {
		clog("skb->len %u head->length %u", skb->len, head->length);
		return TASK_GOON;
	}

	ylog("length %u sendfile %u stream %u info %s",
			head->length, head->theme, head->serial, (char*)(head + 1));
	/*
	upstream_skb_head_dump(head);
	SKB_DUMP(skb);
	*/

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
	size_t quota = sft->length / n_sub_data;

	ylog("checking if quota(%lu) exceeds 4G %lu SENDFILE_BLOCK_SIZE(%lu)",
			quota, (size_t)((unsigned int)(-1)), (size_t)SENDFILE_BLOCK_SIZE);
	if (quota > (size_t)(unsigned int)(-1)) {
		munmap(sft->data, sft->length);
		return -1;
	}

	log("subtask %u quota %ld", n_sub_data, quota);
	struct sendfile_subtask *sfst = NULL;
	int i = 0;
	for (i = 1; i < n_sub_data; i++) {
		sfst = &sft->sfst[i];
		sfst->data = sft->data + quota * (i - 1);
		sfst->length = quota;
		ylog("sfst[%d] %p data %p offset %ld length %ld",
				i, sfst, sfst->data, quota * (i - 1), sfst->length);
	}
	/* the last subtask */
	sfst = &sft->sfst[i];
	sfst->data = sft->data + quota * (i - 1);
	sfst->length = sft->length - quota * (i - 1);
	ylog("sfst[%d] %p data %p offset %ld length %ld",
			i, sfst, sfst->data, quota * (i - 1), sfst->length);
	size_t tl = 0;
	for (int i = 1; i <= n_sub_data; i++) {
		tl += sft->sfst[i].length;
	}
	ylog("%s %s %ld <=> %ld", sft->path, sft->file, sft->length, tl);
	if (sft->length != tl) {
		return -1;
	}

	return 0;
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

		/* Dup strings into owned memory (wire buffer is temporary). */
		nego->path = strdup(nego->path);
		nego->file = strdup(nego->file);
		nego->type = strdup(nego->type);

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
	};

	/* Allocate owned copy for internal use. */
	struct ace_sendfile_nego *nego_copy = malloc(sizeof(*nego_copy));
	if (!nego_copy)
		return -1;
	*nego_copy = nego;
	nego_copy->path = strdup(nego.path);
	nego_copy->file = strdup(nego.file);
	nego_copy->type = strdup(nego.type);

	sendfile_nego_dump(nego_copy);

	/* Encode to wire. */
	struct upstream_skb_head *oh = (struct upstream_skb_head*)task->data;
	size_t total = ace_sendfile_nego_encode(NULL, 0, oh->serial, nego_copy);
	if (total == 0) {
		free(nego_copy);
		return -1;
	}

	void *data = skb_reserve(skb, total);
	if (!data) {
		free(nego_copy);
		return -1;
	}

	total = ace_sendfile_nego_encode((unsigned char *)skb->head, total,
					 oh->serial, nego_copy);
	if (total == 0) {
		free(nego_copy);
		return -1;
	}

	skb_put(skb, total);

	upstream_skb_head_dump((struct upstream_skb_head*)skb->head);
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
			/* notify sender */
			struct lsquic_conn_ctx *lconn_ctx =
				lsquic_conn_get_ctx(lsquic_stream_conn(sc->stream));
			struct lsquic_stream_ctx *s0sc = lsquic_stream_get_ctx(lconn_ctx->s0);
			struct sk_buff *skb = list_first_entry(&s0sc->txq, struct sk_buff, skb_node);
			// SKB_DUMP(skb);
			/* push data to head to send the whole buffer */
			struct upstream_skb_head head = {
				.length = 0,
				.theme = (unsigned short int)(-1),
				.serial = 0,
			};
			skb->len = sizeof(struct upstream_skb_head);
			skb->tail = skb->len;
			skb->data = skb->head;
			skb->offset = 0;
			memcpy(skb->head, &head, sizeof(head));
			// lstream_ctx_add_txq(s0sc, skb);
			lsquic_stream_wantwrite(lconn_ctx->s0, 1);
			// upstream_skb_head_dump(&head);
			// SKB_DUMP(skb);
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
	}
	/* nego owns strdup'd strings in both roles */
	if (sft->nego) {
		free((void *)sft->nego->path);
		free((void *)sft->nego->file);
		free((void *)sft->nego->type);
		free(sft->nego);
		sft->nego = NULL;
	}
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


