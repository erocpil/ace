#ifndef __TASK_H__
#define __TASK_H__

#include <sys/mman.h>
#include <libgen.h>
#include "sk_buff.h"
#include "service.h"

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

struct upstream_skb_head {
	/* payload size */
	unsigned int length;
	/* app topic */
	unsigned short int theme;
	/* operation code */
	unsigned short int serial;
};

enum {
	TASK_THEME_SENDFILE = 0,
	TASK_THEME_PERF,
	TASK_THEME_MAX,
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

#define TASK_TYPE_SIZE (sizeof(task_type) - 1)

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
		struct sendfile_nego *_n = (n); \
		char *p = &_n->head[0]; \
		log("sendfile nego %p", _n); \
		log("  path %d \t %s", _n->path_len, p); \
		p += _n->path_len; \
		log("  file %d \t %s", _n->file_len, p); \
		p += _n->file_len; \
		log("  type %d \t %s", _n->type_len, p); \
		log("  length \t %lu", _n->length); \
	} while (0)

#define perf_nego_dump(n) \
	do { \
		struct perf_nego *_n = (n); \
		log("perf nego %p", _n); \
		log("  code %u", _n->code); \
		log("  dual %u", _n->dual); \
	} while (0)

enum {
	TASK_TYPE_SENDFILE = 0,
	TASK_TYPE_PERF,
	TASK_TYPE_MAX,
};

static int task_type_num = (sizeof(task_type) / sizeof(struct task_type));

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
	void *data;
	int (*init)(struct task*);
	int (*nego)(struct task*, struct sk_buff*);
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

struct sendfile_subtask {
	/* this element must be the first */
	struct subtask sub;
	void *data;
	size_t length;
	size_t offset;
};

struct sendfile_nego {
	/* reserved code */
	unsigned short int code;
	/* /usr/include/linux/limits.h:
	 * NAME_MAX         255
	 * PATH_MAX        4096
	 */
	unsigned short int path_len;
	unsigned short int file_len;
	/* 65535 */
	unsigned short int type_len;
	size_t length;
	char head[0];
} __attribute__((aligned(sizeof(char*))));

struct sendfile_task {
	/* thie element must be the first */
	struct task task;
	// struct subtask subtask;
	// struct task *task;
	char *path;
	char *file;
	char *type;
	void *data;
	size_t length;
	size_t offset;
	struct sendfile_nego *nego;
	/* FIXME unsigned short int -> size_t */
	unsigned short int index;
	struct sendfile_subtask sfst[0];
} __attribute__((aligned(sizeof(char*))));

struct perf_subtask{
	struct subtask sub;
	void *data;
	size_t length;
	size_t offset;
};

struct perf_nego {
	unsigned short int code;
	unsigned short int dual;
} __attribute__((aligned(sizeof(char))));

struct perf_task {
	/* thie element must be the first */
	struct task task;
	struct perf_nego *nego;
	struct perf_subtask pfst[0];
};

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
struct task *task_create(struct sk_buff *skb, int role);
struct subtask *task_get_sub_at(struct task *t, unsigned short int n);
struct subtask *task_get_sub_next(struct task *t);

int sendfile_init(struct task *task);
int sendfile_nego(struct task *task, struct sk_buff* skb);
struct sk_buff *sendfile_exit(struct task *task);
ssize_t sendfile_ctrl_rx(struct lsquic_stream_ctx *sc);
ssize_t sendfile_ctrl_tx(struct lsquic_stream_ctx *sc);
ssize_t sendfile_rx(struct lsquic_stream_ctx *sc);
ssize_t sendfile_tx(struct lsquic_stream_ctx *sc);
int sendfile_done(struct lsquic_stream_ctx *sc);

int perf_init(struct task *task);
int perf_nego(struct task *task, struct sk_buff* skb);
struct sk_buff *perf_exit(struct task *task);
ssize_t perf_ctrl_rx(struct lsquic_stream_ctx *sc);
ssize_t perf_ctrl_tx(struct lsquic_stream_ctx *sc);
ssize_t perf_rx(struct lsquic_stream_ctx *sc);
ssize_t perf_tx(struct lsquic_stream_ctx *sc);
int perf_done(struct lsquic_stream_ctx *sc);

#endif
