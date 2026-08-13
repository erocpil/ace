#ifndef __TASK_DISPATCH_H__
#define __TASK_DISPATCH_H__

#include "task.h"

/* Dispatch entry: build a task from a validated control frame. */
struct task *task_create(struct sk_buff *skb, int role);

/* Subtask accessors, dispatched on task->type. */
struct subtask *task_get_sub_at(struct task *t, unsigned short int n);
struct subtask *task_get_sub_next(struct task *t);

#endif
