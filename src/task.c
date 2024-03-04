#include <assert.h>
#include "task.h"
#include "upstream.h"
#include "define.h"
#include "magic.h"

struct task *task_create_perf(unsigned short n)
{
	size_t task_size =
		sizeof(struct perf_task) +
		sizeof(struct perf_subtask) * n;

	struct task *task = (struct task*)malloc(task_size);
	if (!task) {
		return NULL;
	}
	memset(task, 0, task_size);
	task->init = perf_init;
	task->nego = perf_nego;
	task->exit = perf_exit;

	struct perf_task *pft = container_of(task, struct perf_task, task);

	/* stream 0 */
	struct subtask *sub = &pft->pfst[0].sub;
	sub->task = task;
	sub->rx_func = perf_ctrl_rx;
	sub->tx_func = perf_ctrl_tx;
	sub->done = perf_done;
	sub->no = 0;
	rlog("sub %d %p", 0, sub);

	for (int i = 1; i < n; i++) {
		struct subtask *sub = &pft->pfst[i].sub;
		sub->task = task;
		sub->rx_func = perf_rx;
		sub->tx_func = perf_tx;
		sub->done = perf_done;
		sub->no = i;
		rlog("sub %d %p", i, sub);
	}

	return task;
}

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

static inline void task_exit(struct task *task)
{
	task->end = rdtsc();

	unsigned long c = task->end - task->start;
	hplog("task %p sub %u done %lu start %lu end %lu cycle %lu %fms",
			task, task->n_sub, task->n_sub_done,
			task->start, task->end, c, c / 1000/ MHz);
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
	assert(sc->stream == lconn_ctx->s0);
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
	char *mgc_file="../share/misc/magic.mgc";

	magic_t ctx = magic_open(0);
	if (!ctx) {
		eslog("magic_open(0)");
		return NULL;
	}
	if (magic_load(ctx, mgc_file) != 0) {
		eslog("magic_load(%p %s)", ctx, mgc_file);
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
		struct sendfile_nego *nego = sft->nego;
		char *p = &nego->head[0];
		sft->path = (char*)malloc(nego->path_len);
		if (sft->path) {
			memcpy(sft->path, p, nego->path_len);
		}
		p += nego->path_len;
		sft->file = (char*)malloc(nego->file_len);
		if (sft->file) {
			memcpy(sft->file, p, nego->file_len);
		}
		p += nego->file_len;
		sft->type = (char*)malloc(nego->type_len);
		if (sft->type) {
			memcpy(sft->type, p, nego->type_len);
		}
		sft->length = nego->length;
		char *file = &nego->head[nego->path_len];
		clog("about to receive file \"%s\"", file);

		ylog("receive file %s / %s", sft->path, sft->file);
		/* subtask 0 is for stream 0 */
		/* other stream consume subtask from [1] */
		sft->index = 1;
		ylog("TODO mmap()");
		fd = open(file, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
		if (fd < 0) {
			eslog("open(\"/tmp/data\")");
			exit(-EXIT_FAILURE);
		}
		/* Stretch the file size to the size of the (mmapped) array of ints */
		if (-1 == lseek(fd, sft->length - 1, SEEK_SET)) {
			eslog("lseek(%d %lu)", fd, sft->length);
			exit(-EXIT_FAILURE);
		} else {
			/* Something needs to be written at the end of the file to
			 * have the file actually have the new size.
			 * Just writing an empty string at the current file position will do.
			 */
			if (1 != write(fd, "", 1)) {
				eslog("write(%d)", fd);
				exit(-EXIT_FAILURE);
			}
			log("lseek(%ld) and write last byte", sft->length - 1);
		}
		struct stat st;
		if (fstat(fd, &st) == -1 ) {
			eslog("fstat()");
			exit(-EXIT_FAILURE);
		} else {
			log("%ld <-> %ld", st.st_size, sft->length);
		}
		size_t length =
			(sft->length / sysconf(_SC_PAGE_SIZE) + 1) * sysconf(_SC_PAGE_SIZE);
		sft->data = (char*)mmap(NULL, length, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
		close(fd);
		if ((void*)-1 == sft->data) {
			eslog();
			exit(-EXIT_FAILURE);
		} else {
			log("mmap(%d %s)", fd, file);
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
		memcpy(file, (const char*)task->data + sizeof(struct upstream_skb_head), len + 1);
		fd = open(file, O_RDONLY);
		if (-1 == fd) {
			elog("open(%s), %d %s", file, errno, strerror(errno));
			// exit(-EXIT_FAILURE);
			return -1;
		}
		struct stat st;
		if (-1 == fstat(fd, &st)) {
			elog("fstat(%d), %d %s", fd, errno, strerror(errno));
			return -1;
			// exit(-EXIT_FAILURE);
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
			size_t tlen = strlen(type) + 1;
			sft->type = (char*)malloc(tlen);
			if (sft->type) {
				memcpy(sft->type, type, tlen);
				clog("%s: %ld \"%s\"", file, tlen, sft->type);
			}
		} else {
			/* TODO */
			rlog("TODO");
		}
		sft->file = basename(file);
		sft->path = dirname(file);
	}

	/* init sendfile subtask */
	/* stream 0 is not carrying data */
	unsigned short int n_sub_data = task->n_sub - 1;
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
	assert(sft->length == tl);

	return 0;
}

int sendfile_nego(struct task *task, struct sk_buff* skb)
{
	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);

	if (TASK_ROLE_RECV == task->role) {
		struct sendfile_nego *nego =
			(struct sendfile_nego*)((char*)skb->head +
					sizeof(struct upstream_skb_head));
		sendfile_nego_dump(nego);
		sft->nego = nego;
		return 0;
	}
	size_t total_length =
		sizeof(struct sendfile_nego) +
		strlen(sft->path) + 1 +
		strlen(sft->file) + 1 +
		strlen(sft->type) + 1;
	struct sendfile_nego *nego =
		(struct sendfile_nego*)malloc(total_length);
	if (!nego) {
		return -1;
	}
	memset(nego, 0, sizeof(*nego));
	// nego->code = 0;
	nego->path_len = strlen(sft->path) + 1;
	nego->file_len = strlen(sft->file) + 1;
	nego->type_len = strlen(sft->type) + 1;
	nego->length = sft->length;
	char *p = (char*)&nego->head[0];
	memcpy(p, sft->path, nego->path_len);
	p += nego->path_len;
	memcpy(p, sft->file, nego->file_len);
	p += nego->file_len;
	memcpy(p, sft->type, nego->type_len);

	sendfile_nego_dump(nego);

	/* write head */
	struct upstream_skb_head *oh = (struct upstream_skb_head*)task->data;
	struct upstream_skb_head nh = {
		.length = total_length,
		.theme = oh->theme,
		.serial = oh->serial,
	};
	void *data = skb_reserve(skb, sizeof(nh));
	if (data) {
		memcpy(skb->head, &nh, sizeof(nh));
	} else {
		rlog("TODO free()");
		return -1;
	}
	/* write data */
	/* set length so server knows how much to receive */
	// ((struct upstream_skb_head*)sc->tx->head)->length = info_len;
	void *tail = skb_put(skb, total_length);
	if (tail) {
		memcpy(data, (void*)nego, total_length);
	} else {
		rlog("TODO free()");
	}
	upstream_skb_head_dump((struct upstream_skb_head*)skb->head);

	sft->nego = nego;

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
		assert(!lsquic_stream_id(sc->stream));
		ylog("all %lu streams are done, task exiting", task->n_sub_done);
		task->data = (void*)lstream_ctx_del_rxq_first(sc);
		return TASK_EXIT;
	}

	struct sendfile_task *sft = container_of(task, struct sendfile_task, task);
	/* all done */
	if (-1 == munmap(sft->data, sft->length)) {
		eslog("munmap(%p %lu", sft->data, sft->length);
		return TASK_FAIL;
	}
	ylog("%s / %s munmap(%p %lu) done",
			sft->path, sft->file, sft->data, sft->length);

	return TASK_EXIT;
}

struct sk_buff *sendfile_exit(struct task *task)
{
	TASK_DUMP(task);
	// SKB_DUMP((struct sk_buff*)task->data);
	task_exit(task);
	return (struct sk_buff*)task->data;
}

struct task* (*task_create_entity_func[TASK_TYPE_MAX])(unsigned short) = {
	task_create_sendfile,
	task_create_perf,
	// NULL,
};

struct task *task_create(struct sk_buff *skb, int role)
{
	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;

	if (role >= TASK_ROLE_MAX) {
		return NULL;
	}

	int type = head->theme;
	int num = 0;
	/* including stream(0) */
	num = head->serial + 1;
	if (type >= TASK_TYPE_MAX) {
		return NULL;
	}

	struct task *task = task_create_entity_func[type](num);
	if (!task) {
		eslog("task_create_entity_func[%d] %p",
				type, task_create_entity_func[type]);
		return NULL;
	}
	clog("task %p type %s", task, task_type[type].command);

	task->role = role;
	task->type = type;
	task->n_sub = num;
	task->data = (void*)head;
	task->start = rdtsc();
	hplog("task %p start %lu", task, task->start);

	return task;

}

struct subtask *task_get_sendfile_sub_at(struct task *t, unsigned short int n)
{
	struct sendfile_task *sft = container_of(t, struct sendfile_task, task);
	return &sft->sfst[n].sub;
}

struct subtask *task_get_perf_sub_at(struct task *t, unsigned short int n)
{
	struct perf_task *pft = container_of(t, struct perf_task, task);
	return &pft->pfst[n].sub;
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

struct subtask *task_get_perf_sub_next(struct task *t)
{
	return NULL;
}

struct subtask* (*task_get_sub_at_func[TASK_TYPE_MAX])(struct task *t, unsigned short int) = {
	task_get_sendfile_sub_at,
	task_get_perf_sub_at,
	// NULL,
};

struct subtask* (*task_get_sub_next_func[TASK_TYPE_MAX])(struct task *t) = {
	task_get_sendfile_sub_next,
	task_get_perf_sub_next,
	// NULL,
};

struct subtask *task_get_sub_at(struct task *t, unsigned short int n)
{
	return task_get_sub_at_func[t->type](t, n);
}

struct subtask *task_get_sub_next(struct task *t)
{
	return task_get_sub_next_func[t->type](t);
}

int perf_init(struct task *task)
{
	struct perf_task *pft = container_of(task, struct perf_task, task);
	struct perf_subtask *pfst = NULL;
	unsigned short int n_sub_data = task->n_sub - 1;

	log("pfst[0] %p", &pft->pfst[0]);
	for (int i = 1; i <= n_sub_data; i++) {
		pfst = &pft->pfst[i];
		pfst->data = (void*)malloc(SENDFILE_BLOCK_SIZE);
		if (!pfst->data) {
			exit(-EXIT_FAILURE);
		}
		pfst->length = SENDFILE_BLOCK_SIZE;
		pfst->offset = 0;
		log("pfst[%d] %p", i, pfst);
	}
	return 0;
}

int perf_nego(struct task *task, struct sk_buff* skb)
{
	struct perf_task *pft = container_of(task, struct perf_task, task);

	if (TASK_ROLE_RECV == task->role) {
		struct perf_nego *nego =
			(struct perf_nego*)((char*)skb->head +
					sizeof(struct upstream_skb_head));
		perf_nego_dump(nego);
		pft->nego = nego;
		return 0;
	}

	size_t total_length =
		sizeof(struct perf_nego) +
		sizeof(struct upstream_skb_head);
	struct perf_nego *nego =
		(struct perf_nego*)malloc(total_length);
	if (!nego) {
		return -1;
	}
	memset(nego, 0, sizeof(*nego));
	/* TEST */
	nego->code = 1;
	nego->dual = 1;

	/* write head */
	struct upstream_skb_head *oh = (struct upstream_skb_head*)task->data;
	struct upstream_skb_head nh = {
		.length = total_length,
		.theme = oh->theme,
		.serial = oh->serial,
	};
	void *data = skb_reserve(skb, sizeof(nh));
	if (data) {
		memcpy(skb->head, &nh, sizeof(nh));
	} else {
		rlog("TODO free()");
		return -1;
	}
	void *tail = skb_put(skb, total_length);
	if (tail) {
		memcpy(data, (void*)nego, total_length);
	} else {
		rlog("TODO free()");
	}

	return 0;
}

struct sk_buff *perf_exit(struct task *task)
{
	return 0;
}

ssize_t perf_ctrl_rx(struct lsquic_stream_ctx *sc)
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

	ylog("length %u perf %u stream %u info %s",
			head->length, head->theme, head->serial, (char*)(head + 1));
	/*
	upstream_skb_head_dump(head);
	SKB_DUMP(skb);
	*/
	/* start each stream except stream 0 the control */
	struct lsquic_conn *lconn = lsquic_stream_conn(sc->stream);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
	assert(sc->stream == lconn_ctx->s0);
	struct lsquic_stream_ctx *pos = NULL;
	if (TASK_ROLE_SEND == ((struct task*)lconn_ctx->task)->role) {
		list_for_each_entry(pos, &lconn_ctx->running_stream_head, stream_node) {
			struct perf_subtask *pfst = (struct perf_subtask*)pos->subtask;
			struct sk_buff *skb = pos->tx;
			clog("stream %p subtask %p write on %p length %d",
					pos->stream, pfst, skb->data, skb->len);
			/* set tx buffer to mmap()ed area */
			skb->head = pfst->data;
			skb->data = pfst->data;
			skb->tail = pfst->length;
			skb->end = pfst->length;
			skb->len = pfst->length;
			skb->offset = 0;
			clog("stream %p sc %p subtask %p read on %p length %d",
					pos->stream, pos, pfst, skb->data, skb->len);
			lsquic_stream_wantwrite(pos->stream, 1);
		}
		/* TASK_ROLE_SEND should reset skb */
		sc->rx->len = 0;
		sc->rx->tail = 0;
		sc->rx->data = sc->rx->head;
	} else {
		/* TASK_ROLE_RECV */
		list_for_each_entry(pos, &lconn_ctx->pending_stream_head, stream_node) {
			struct perf_subtask *pfst = (struct perf_subtask*)pos->subtask;
			struct sk_buff *skb = pos->rx;
			clog("stream %p subtask %p write on %p length %d",
					pos->stream, pfst, skb->data, skb->len);
			/* set rx buffer to external area */
			skb->head = pfst->data;
			skb->data = pfst->data;
			skb->tail = pfst->length;
			skb->end = pfst->length;
			skb->len = 0;
			skb->offset = 0;
			SKB_DUMP(skb);
			clog("stream %p sc %p subtask %p", pos->stream, pos, pfst);
		}
		/* no reset because TASK_ROLE_RECV use this skb to echo back */
	}

	return 0;
}

ssize_t perf_ctrl_tx(struct lsquic_stream_ctx *sc)
{
	lsquic_stream_flush(sc->stream);
	clog("write off and read on");
	lsquic_stream_wantwrite(sc->stream, 0);
	lsquic_stream_wantread(sc->stream, 1);
	return TASK_GOON;
}

ssize_t perf_rx(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = sc->rx;

	skb->tail = 0;
	skb->len = 0;
	skb->offset = 0;

	return 0;
}

ssize_t perf_tx(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = sc->tx;

	skb->offset = 0;

	return 0;
}

int perf_done(struct lsquic_stream_ctx *sc)
{
	return 0;
}
