#include <assert.h>
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
	struct upstream_skb_head validated;
	struct upstream_skb_head *head;

	if (!skb || role < 0 || role >= TASK_ROLE_MAX ||
			task_frame_validate(skb->head, skb->len, &validated) != 1) {
		return NULL;
	}
	head = (struct upstream_skb_head*)skb->head;

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
