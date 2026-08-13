#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "task_dispatch.h"
#include "task_sendfile.h"
#include "task_perf.h"
#include "task_protocol.h"

static unsigned char wire[4096];

/* Wrap an encoded wire frame in a freshly allocated sk_buff. */
static struct sk_buff *make_wire_skb(const unsigned char *frame, size_t len)
{
	struct sk_buff *skb = skb_malloc((ssize_t)len);
	assert(skb != NULL);
	memcpy(skb->head, frame, len);
	skb->len = (unsigned int)len;
	return skb;
}

/* Build the native-layout skb the local upstream queue produces: a
 * struct upstream_skb_head at skb->head followed by the payload, exactly as
 * upstream_read_char() (src/upstream.c) constructs it before client.c hands
 * it to task_create(TASK_ROLE_SEND). */
static struct sk_buff *make_native_skb(unsigned short theme,
				       unsigned short serial,
				       const char *payload)
{
	size_t len = strlen(payload) + 1;
	struct sk_buff *skb = skb_malloc(sizeof(struct upstream_skb_head) + len);
	assert(skb != NULL);

	skb_reserve(skb, sizeof(struct upstream_skb_head));
	skb_put(skb, len);
	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
	head->length = (uint32_t)len;
	head->theme = theme;
	head->serial = serial;
	memcpy(skb->data, payload, len);
	skb_push(skb, sizeof(struct upstream_skb_head));

	return skb;
}

int main(void)
{
	/* --- SEND path: native upstream_skb_head + payload --- */
	{
		struct sk_buff *s = make_native_skb(TASK_THEME_SENDFILE, 2,
						    "/tmp/out.bin");
		struct task *st = task_create(s, TASK_ROLE_SEND);
		assert(st != NULL);
		assert(st->type == TASK_TYPE_SENDFILE);
		assert(st->role == TASK_ROLE_SEND);
		assert(st->n_sub == 3);                 /* serial 2 + 1 */
		assert(st->init == sendfile_init);
		assert(st->nego == sendfile_nego);
		assert(st->exit == sendfile_exit);

		/* task->data contract: native head at skb->head, payload follows */
		struct upstream_skb_head *h = (struct upstream_skb_head*)st->data;
		assert(h != NULL);
		assert(h->theme == TASK_THEME_SENDFILE);
		assert(h->serial == 2);
		assert(strcmp((const char*)st->data + sizeof(struct upstream_skb_head),
			      "/tmp/out.bin") == 0);

		struct subtask *s0 = task_get_sub_at(st, 0);
		assert(s0 != NULL && s0->rx_func == sendfile_ctrl_rx);

		free(st);
		skb_free(s);
	}

	/* --- SEND path: perf --- */
	{
		struct sk_buff *p = make_native_skb(TASK_THEME_PERF, 1, "x");
		struct task *pt = task_create(p, TASK_ROLE_SEND);
		assert(pt != NULL);
		assert(pt->type == TASK_TYPE_PERF);
		assert(pt->role == TASK_ROLE_SEND);
		assert(pt->n_sub == 2);                 /* serial 1 + 1 */
		assert(pt->init == perf_init);

		/* perf_nego reads oh->serial from task->data on the SEND path */
		struct upstream_skb_head *h = (struct upstream_skb_head*)pt->data;
		assert(h != NULL && h->serial == 1);

		free(pt);
		skb_free(p);
	}

	/* --- RECV path: wire frame --- */
	{
		struct ace_sendfile_chunk snego_chunks[1] = { { .offset = 0, .size = 4096 } };
		struct ace_sendfile_nego snego = {
			.code        = 0,
			.path        = "tmp",
			.path_len    = 4,   /* "tmp\0" */
			.file        = "data.bin",
			.file_len    = 9,   /* "data.bin\0" */
			.type        = "binary",
			.type_len    = 7,   /* "binary\0" */
			.file_length = 4096,
			.n_segments  = 1,
			.chunks      = snego_chunks,
		};
		size_t slen = ace_sendfile_nego_encode(wire, sizeof(wire), 2, &snego);
		assert(slen > 0);

		struct sk_buff *s = make_wire_skb(wire, slen);
		struct task *st = task_create(s, TASK_ROLE_RECV);
		assert(st != NULL);
		assert(st->type == TASK_TYPE_SENDFILE);
		assert(st->role == TASK_ROLE_RECV);
		assert(st->n_sub == 3);                 /* serial 2 + 1 */
		assert(st->init == sendfile_init);
		assert(st->data == NULL);               /* RECV never reads task->data */

		struct subtask *s0 = task_get_sub_at(st, 0);
		assert(s0 != NULL && s0->rx_func == sendfile_ctrl_rx);

		free(st);
		skb_free(s);
	}

	/* --- RECV path: perf --- */
	{
		struct ace_perf_nego pnego = { .code = 1, .dual = 1 };
		size_t plen = ace_perf_nego_encode(wire, sizeof(wire), 1, &pnego);
		assert(plen > 0);

		struct sk_buff *p = make_wire_skb(wire, plen);
		struct task *pt = task_create(p, TASK_ROLE_RECV);
		assert(pt != NULL);
		assert(pt->type == TASK_TYPE_PERF);
		assert(pt->role == TASK_ROLE_RECV);
		assert(pt->n_sub == 2);

		free(pt);
		skb_free(p);
	}

	/* --- invalid inputs are rejected before dispatch --- */
	assert(task_create(NULL, TASK_ROLE_SEND) == NULL);

	{
		struct sk_buff *s = make_native_skb(TASK_THEME_SENDFILE, 2, "x");
		assert(task_create(s, TASK_ROLE_MAX) == NULL);   /* role out of range */
		assert(task_create(s, -1) == NULL);              /* role negative */

		/* native head with a garbage theme is rejected */
		((struct upstream_skb_head*)s->head)->theme = 0xFF;
		assert(task_create(s, TASK_ROLE_SEND) == NULL);

		skb_free(s);
	}

	return 0;
}
