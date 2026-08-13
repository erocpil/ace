#ifndef __TASK_SENDFILE_H__
#define __TASK_SENDFILE_H__

#include "task.h"

/* Metadata sidecar for a sendfile transfer (RECV side).  Fixed binary layout,
 * written incrementally as each segment completes, read back on resume.
 * Local file, native byte order, naturally packed (no padding). */
#define ACE_SF_META_MAGIC   "ACEM"
#define ACE_SF_META_VERSION 1

struct ace_sf_meta_hdr {
	char     magic[4];      /* "ACEM" */
	uint8_t  version;       /* 1 */
	uint8_t  reserved;      /* 0 */
	uint16_t n_segments;
	uint32_t file_length;
};                          /* 12 bytes */

struct ace_sf_meta_seg {
	uint64_t offset;        /* segment byte offset in the file */
	uint32_t size;          /* segment byte length */
	uint32_t checksum;      /* task_checksum32, valid when done */
	uint8_t  done;          /* 0 = pending, 1 = complete + verified */
	uint8_t  pad[3];
};                          /* 20 bytes */

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
