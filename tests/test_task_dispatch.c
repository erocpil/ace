#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "task_dispatch.h"
#include "task_sendfile.h"
#include "task_perf.h"
#include "task_protocol.h"

static unsigned char wire[4096];

/* Wrap an encoded frame in a freshly allocated sk_buff. */
static struct sk_buff *make_skb(const unsigned char *frame, size_t len)
{
	struct sk_buff *skb = skb_malloc((ssize_t)len);
	assert(skb != NULL);
	memcpy(skb->head, frame, len);
	skb->len = (unsigned int)len;
	return skb;
}

int main(void)
{
	/* --- sendfile frame dispatches to the sendfile entity --- */
	struct ace_sendfile_nego snego = {
		.code        = 0,
		.path        = "tmp",
		.path_len    = 4,   /* "tmp\0" */
		.file        = "data.bin",
		.file_len    = 9,   /* "data.bin\0" */
		.type        = "binary",
		.type_len    = 7,   /* "binary\0" */
		.file_length = 4096,
	};
	size_t slen = ace_sendfile_nego_encode(wire, sizeof(wire), 2, &snego);
	assert(slen > 0);

	struct sk_buff *s = make_skb(wire, slen);
	struct task *st = task_create(s, TASK_ROLE_SEND);
	assert(st != NULL);
	assert(st->type == TASK_TYPE_SENDFILE);
	assert(st->role == TASK_ROLE_SEND);
	assert(st->n_sub == 3);                 /* serial 2 + 1 */
	assert(st->init == sendfile_init);
	assert(st->nego == sendfile_nego);
	assert(st->exit == sendfile_exit);

	/* subtask accessor dispatches on task->type */
	struct subtask *s0 = task_get_sub_at(st, 0);
	assert(s0 != NULL);
	assert(s0->rx_func == sendfile_ctrl_rx);
	struct subtask *s1 = task_get_sub_at(st, 1);
	assert(s1 != NULL);
	assert(s1->rx_func == sendfile_rx);

	free(st);
	skb_free(s);

	/* --- perf frame dispatches to the perf entity --- */
	struct ace_perf_nego pnego = { .code = 1, .dual = 1 };
	size_t plen = ace_perf_nego_encode(wire, sizeof(wire), 1, &pnego);
	assert(plen > 0);

	struct sk_buff *p = make_skb(wire, plen);
	struct task *pt = task_create(p, TASK_ROLE_RECV);
	assert(pt != NULL);
	assert(pt->type == TASK_TYPE_PERF);
	assert(pt->role == TASK_ROLE_RECV);
	assert(pt->n_sub == 2);                 /* serial 1 + 1 */
	assert(pt->init == perf_init);

	struct subtask *p0 = task_get_sub_at(pt, 0);
	assert(p0 != NULL);
	assert(p0->rx_func == perf_ctrl_rx);
	assert(p0->tx_func == perf_ctrl_tx);

	free(pt);
	skb_free(p);

	/* --- invalid inputs are rejected before dispatch --- */
	assert(task_create(NULL, TASK_ROLE_SEND) == NULL);

	struct sk_buff *bad = make_skb(wire, plen);
	assert(task_create(bad, TASK_ROLE_MAX) == NULL);   /* role out of range */
	assert(task_create(bad, -1) == NULL);              /* role negative */
	skb_free(bad);

	return 0;
}
