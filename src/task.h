#ifndef __TASK_H__
#define __TASK_H__

#include <sys/mman.h>
#include <libgen.h>
#include "sk_buff.h"
#include "service.h"
#include "task_protocol.h"

// #define SENDFILE_BLOCK_SIZE ((unsigned int)-1)
#define SENDFILE_BLOCK_SIZE ((unsigned short int)-1)

enum {
	TASK_ROLE_SEND = 0,
	TASK_ROLE_RECV,
	TASK_ROLE_MAX,
};

enum {
	TASK_GOON = 0,
	TASK_DONE,
	TASK_FAIL,
	TASK_EXIT,
};

struct task_type {
	char *cmd;
	char *command;
	unsigned short code;
};

static struct task_type task_type[] = {
	{ "sf", "sendfile", 0, },
	{ "perf", "performance", 1, },
	{ "", "", -1, },
};

#define TASK_TYPE_SIZE (sizeof(task_type) / sizeof(task_type[0]) - 1)

#define upstream_skb_head_dump(h) \
	do { \
		struct upstream_skb_head *_h = (h); \
		log("upstream skb head %p", _h); \
		log("  length \t %u", _h->length); \
		log("  theme \t %u \t %s", _h->theme, \
				_h->theme < TASK_TYPE_SIZE ? \
				task_type[_h->theme].command : "nil"); \
		log("  serial \t %u", _h->serial); \
	} while (0)

#define sendfile_nego_dump(n) \
	do { \
		struct ace_sendfile_nego *_n = (n); \
		log("sendfile nego %p", _n); \
		log("  path %u 	 %s", _n->path_len, _n->path); \
		log("  file %u 	 %s", _n->file_len, _n->file); \
		log("  type %u 	 %s", _n->type_len, _n->type); \
		log("  length 	 %u", _n->file_length); \
	} while (0)

#define perf_nego_dump(n) \
	do { \
		struct ace_perf_nego *_n = (n); \
		log("perf nego %p", _n); \
		log("  code %u", _n->code); \
		log("  dual %u", _n->dual); \
	} while (0)

enum {
	TASK_TYPE_SENDFILE = 0,
	TASK_TYPE_PERF,
	TASK_TYPE_MAX,
};

static int task_type_num = TASK_TYPE_SIZE;

/* conn's task */
struct task {
	/* sender or receiver */
	int role : 2;
	int no : 30;
	/* sendfile, performance, etc, ... */
	/* FIXME unsigned short int -> size_t */
	unsigned short int type;
	/* number of subtasks */
	/* FIXME unsigned short int -> size_t */
	unsigned short int n_sub;
	size_t n_sub_done;
	/* Request head (native struct upstream_skb_head + payload).
	 * Valid only for TASK_ROLE_SEND (local upstream queue); NULL for
	 * TASK_ROLE_RECV, which decodes the wire frame via task->nego. */
	void *data;
	int (*init)(struct task*);
	int (*nego)(struct task*, struct sk_buff*);
	/* RECV-only: after nego+init, write the stream-0 reply into tx.
	 * NULL means "echo the received nego back verbatim" (legacy).  rx is
	 * the received nego frame (needed for the echo copy).  Returns 0 on
	 * success, -1 on failure.  Used by tasks that answer negotiation with
	 * something other than an echo (e.g. sendfile resume bitmap). */
	int (*nego_ack)(struct task*, struct sk_buff *tx, struct sk_buff *rx);
	/* RECV-only: after the stream-0 reply (nego echo / resume bitmap) has
	 * been flushed, emit the completion ("done") frame ourselves.  Used
	 * when nothing is left to transfer — e.g. sendfile with every segment
	 * already present — so there is no data-stream completion to trigger
	 * sendfile_done.  1 = emit done frame after reply, 0 = normal. */
	int done_after_reply;
	struct sk_buff *(*exit)(struct task*);
	unsigned long start;
	unsigned long end;
} __attribute__((aligned(sizeof(char*))));

/* stream's task */
struct subtask {
	struct task *task;
	ssize_t (*rx_func)(struct lsquic_stream_ctx*);
	ssize_t (*tx_func)(struct lsquic_stream_ctx*);
	int (*done)(struct lsquic_stream_ctx*);
	unsigned short int no;
} __attribute__((aligned(sizeof(char*))));

/* Record task completion time (used by task exit callbacks). */
static inline void task_exit(struct task *task)
{
	task->end = rdtsc();

	unsigned long c = task->end - task->start;
	hplog("task %p sub %u done %lu start %lu end %lu cycle %lu",
		task, task->n_sub, task->n_sub_done,
		task->start, task->end, c);
}

static int task_find_type(const char *c)
{
	clog("task_type_num %d", task_type_num);
	for (int i = 0; i < task_type_num; i++) {
		clog("%s <-> %s %s", c, task_type[i].cmd, task_type[i].command);
		if (!strcmp(c, task_type[i].cmd) || !strcmp(c, task_type[i].command)) {
			return task_type[i].code;
		}
	}

	return -1;
}

#define TASK_DUMP(t) \
	do { \
		struct task *_t = (t); \
		log("task %p", _t); \
		log("  role \t\t%s", _t->role == TASK_ROLE_RECV ? "receiver" : "sender"); \
		log("  no \t\t%d", _t->no); \
		log("  type \t\t%u %s", _t->type, \
				_t->type < TASK_TYPE_SIZE ? \
				task_type[_t->type].command : "nil"); \
		log("  n_sub \t\t%u", _t->n_sub); \
		log("  n_sub_done \t%lu", _t->n_sub_done); \
		log("  data \t\t%p", _t->data); \
		log("  init \t\t%p", _t->init); \
		log("  nego \t\t%p", _t->nego); \
		log("  exit \t\t%p", _t->exit); \
	} while (0)

void task_add_sub(struct task *t, struct subtask *s);

#endif
