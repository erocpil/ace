#include <assert.h>
#include "task_perf.h"
#include "upstream.h"
#include "define.h"

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

struct subtask *task_get_perf_sub_at(struct task *t, unsigned short int n)
{
	struct perf_task *pft = container_of(t, struct perf_task, task);
	return &pft->pfst[n].sub;
}

struct subtask *task_get_perf_sub_next(struct task *t)
{
	(void)t;
	return NULL;
}

int perf_init(struct task *task)
{
	struct perf_task *pft = container_of(task, struct perf_task, task);
	struct perf_subtask *pfst = NULL;
	unsigned short int n_sub_data = task->n_sub - 1;
	if (!ace_task_memory_valid(n_sub_data, SENDFILE_BLOCK_SIZE)) {
		errno = ENOMEM;
		return -1;
	}

	log("pfst[0] %p", &pft->pfst[0]);
	for (int i = 1; i <= n_sub_data; i++) {
		pfst = &pft->pfst[i];
		pfst->data = (void*)malloc(SENDFILE_BLOCK_SIZE);
		if (!pfst->data) {
			for (int j = 1; j < i; ++j) {
				free(pft->pfst[j].data);
				pft->pfst[j].data = NULL;
			}
			return -1;
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
		struct upstream_skb_head head;
		if (task_frame_validate(skb->head, skb->len, &head) != 1 ||
		    task_payload_validate(&head,
			skb->head + ACE_FRAME_HDR_LEN) != 0) {
			errno = EPROTO;
			return -1;
		}

		struct ace_perf_nego *nego = calloc(1, sizeof(*nego));
		if (!nego)
			return -1;

		if (ace_perf_nego_decode(
			(const unsigned char *)skb->head + ACE_FRAME_HDR_LEN,
			head.length, nego) != 0) {
			free(nego);
			errno = EPROTO;
			return -1;
		}

		perf_nego_dump(nego);
		pft->nego = nego;
		return 0;
	}

	/* Sender */
	struct ace_perf_nego *nego = calloc(1, sizeof(*nego));
	if (!nego)
		return -1;
	nego->code = 1;
	nego->dual = 1;

	/* Encode the wire frame at skb->head and set data/len explicitly,
	 * mirroring the probe path. */
	struct upstream_skb_head *oh = (struct upstream_skb_head*)task->data;
	size_t total = ace_perf_nego_encode((unsigned char *)skb->head,
					    skb->end, oh->serial, nego);
	if (total == 0) {
		free(nego);
		return -1;
	}
	skb->data = skb->head;
	skb->len = (unsigned int)total;
	skb->tail = skb->len;
	skb->offset = 0;
	pft->nego = nego;

	return 0;
}

struct sk_buff *perf_exit(struct task *task)
{
	struct perf_task *pft = container_of(task, struct perf_task, task);
	task_exit(task);

	/* Free per-subtask data buffers allocated in perf_init(). */
	for (unsigned short int i = 1; i < task->n_sub; i++) {
		free(pft->pfst[i].data);
		pft->pfst[i].data = NULL;
	}

	/* Free the negotiation struct (perf nego owns no strings). */
	free(pft->nego);
	pft->nego = NULL;

	free(pft);
	return NULL;
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
	if (!lconn_ctx || sc->stream != lconn_ctx->s0 || !lconn_ctx->task) {
		return TASK_FAIL;
	}
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
	(void)sc;
	return 0;
}
