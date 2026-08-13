#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include "task_perf.h"

int main(void)
{
	struct task *t = task_create_perf(3);
	assert(t != NULL);

	/* callbacks wired to the perf family */
	assert(t->init == perf_init);
	assert(t->nego == perf_nego);
	assert(t->exit == perf_exit);

	/* stream 0 is the control stream */
	struct subtask *s0 = task_get_perf_sub_at(t, 0);
	assert(s0 != NULL);
	assert(s0->no == 0);
	assert(s0->rx_func == perf_ctrl_rx);
	assert(s0->tx_func == perf_ctrl_tx);
	assert(s0->done == perf_done);
	assert(s0->task == t);

	/* streams 1..n-1 are data streams */
	struct subtask *s1 = task_get_perf_sub_at(t, 1);
	assert(s1 != NULL);
	assert(s1->no == 1);
	assert(s1->rx_func == perf_rx);
	assert(s1->tx_func == perf_tx);
	assert(s1->done == perf_done);

	/* n_sub is set by task_create (the dispatch entry), not by the
	 * entity factory; mirror that before exercising the iterator. */
	t->n_sub = 3;

	/* the perf sequential iterator is a stub and always returns NULL;
	 * per-subtask access is the supported path (see task_get_perf_sub_at). */
	assert(task_get_perf_sub_next(t) == NULL);

	free(t);
	return 0;
}
