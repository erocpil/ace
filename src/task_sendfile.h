#ifndef __TASK_SENDFILE_H__
#define __TASK_SENDFILE_H__

#include "task.h"

struct sendfile_subtask {
	/* this element must be the first */
	struct subtask sub;
	void *data;
	size_t length;
	size_t offset;
};

struct sendfile_task {
	/* this element must be the first */
	struct task task;
	char *path;
	char *file;
	char *type;
	char *source_path;
	void *data;
	size_t length;
	size_t offset;
	struct ace_sendfile_nego *nego;
	/* explicit chunk plan (offset/size per data stream); sender-owned */
	struct ace_sendfile_chunk *chunks;
	/* FIXME unsigned short int -> size_t */
	unsigned short int index;
	struct sendfile_subtask sfst[0];
} __attribute__((aligned(sizeof(char*))));

/* entity factory + subtask accessors (used by task.c dispatch) */
struct task *task_create_sendfile(unsigned short n);
struct subtask *task_get_sendfile_sub_at(struct task *t, unsigned short int n);
struct subtask *task_get_sendfile_sub_next(struct task *t);

/* sendfile task callbacks */
int sendfile_init(struct task *task);
int sendfile_nego(struct task *task, struct sk_buff *skb);
struct sk_buff *sendfile_exit(struct task *task);
ssize_t sendfile_ctrl_rx(struct lsquic_stream_ctx *sc);
ssize_t sendfile_ctrl_tx(struct lsquic_stream_ctx *sc);
ssize_t sendfile_rx(struct lsquic_stream_ctx *sc);
ssize_t sendfile_tx(struct lsquic_stream_ctx *sc);
int sendfile_done(struct lsquic_stream_ctx *sc);

#endif
