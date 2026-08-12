#ifndef __RUNNER_H__
#define __RUNNER_H__

#include <pthread.h>
#include "ev.h"
#include "define.h"
#include "service.h"
#include "list.h"

/* shared init */
void ace_runner_init_signal(struct ev_loop *loop,
		ev_signal *sq, ev_signal *si, ev_signal *st,
		void *data);

/* shared add/runtime */
void ace_runner_add_service(struct list_head *head, size_t *n_service,
		struct service *se);
int ace_runner_run_service(size_t *n_running, struct service *se);
void ace_runner_stop_services(struct list_head *head);
int ace_runner_join_services(struct list_head *head, size_t *n_running);
int ace_runner_run(struct ev_loop *loop, ev_timer *tw,
		size_t n_service, void *data,
		void (*timeout_func)(EV_P_ ev_timer*, int));
void ace_runner_recv_data(EV_P_ ev_io *w, int revents);

#endif
