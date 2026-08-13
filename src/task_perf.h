#ifndef __TASK_PERF_H__
#define __TASK_PERF_H__

#include "task.h"

struct perf_subtask {
	/* this element must be the first */
	struct subtask sub;
	void *data;
	size_t length;
	size_t offset;
};

struct perf_task {
	/* this element must be the first */
	struct task task;
	struct ace_perf_nego *nego;
	struct perf_subtask pfst[0];
};

/* entity factory + subtask accessors (used by task.c dispatch) */
struct task *task_create_perf(unsigned short n);
struct subtask *task_get_perf_sub_at(struct task *t, unsigned short int n);
struct subtask *task_get_perf_sub_next(struct task *t);

/* perf task callbacks */
int perf_init(struct task *task);
int perf_nego(struct task *task, struct sk_buff *skb);
struct sk_buff *perf_exit(struct task *task);
ssize_t perf_ctrl_rx(struct lsquic_stream_ctx *sc);
ssize_t perf_ctrl_tx(struct lsquic_stream_ctx *sc);
ssize_t perf_rx(struct lsquic_stream_ctx *sc);
ssize_t perf_tx(struct lsquic_stream_ctx *sc);
int perf_done(struct lsquic_stream_ctx *sc);

#endif
