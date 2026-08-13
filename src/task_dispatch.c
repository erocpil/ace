#include <assert.h>
#include "task_dispatch.h"
#include "task.h"
#include "task_sendfile.h"
#include "task_perf.h"
#include "upstream.h"
#include "define.h"
#include "magic.h"

struct task* (*task_create_entity_func[TASK_TYPE_MAX])(unsigned short) = {
	task_create_sendfile,
	task_create_perf,
	// NULL,
};

struct task *task_create(struct sk_buff *skb, int role)
{
	struct upstream_skb_head head;

	if (!skb || role < 0 || role >= TASK_ROLE_MAX) {
		return NULL;
	}

	/*
	 * The request head arrives in one of two layouts, keyed by role:
	 *   - TASK_ROLE_RECV: the 14-byte wire frame (struct ace_frame), decoded
	 *     and validated by task_frame_validate().
	 *   - TASK_ROLE_SEND: the native internal head (struct upstream_skb_head)
	 *     placed at skb->head by the local upstream queue.
	 * Reading the wrong layout yields garbage theme/serial and rejects or
	 * corrupts every request, so dispatch on role here.
	 */
	if (TASK_ROLE_RECV == role) {
		if (task_frame_validate(skb->head, skb->len, &head) != 1) {
			return NULL;
		}
	} else {
		if (skb->len < sizeof(struct upstream_skb_head)) {
			return NULL;
		}
		head = *(struct upstream_skb_head*)skb->head;
	}

	int type = head.theme;
	/* including stream(0) */
	int num = head.serial + 1;
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
	/* task->data holds the native request head + payload; it is only read on
	 * the SEND path (sendfile_init / *_nego).  RECV decodes via task->nego
	 * and never dereferences task->data. */
	task->data = (TASK_ROLE_SEND == role) ? (void*)skb->head : NULL;
	task->start = rdtsc();
	hplog("task %p start %lu", task, task->start);

	return task;

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
