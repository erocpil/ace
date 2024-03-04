/* a simple application for client */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include "upstream.h"
#include "define.h"
#include "git_version.h"

struct channel {
	struct upstream_echo *echo;
	volatile int fd;
	pthread_barrier_t barrier;
	pthread_barrier_t barrier_end;
	pthread_t thread_id;
	char thread_name[16];
};

#define PRINT_VERSION(msg) \
	do { \
		printf(Blue "Quic:" Cyan "%s " \
				Blue "Commit:" Yellow "%s%s " \
				Blue "Branch:" Green "%s" RESET "\n\n", \
				(msg), git_hash, git_status, git_branch); \
	} while (0)

int set_affinity(int c)
{
	int r = 0;
	int s = 0;
	cpu_set_t mask;
	cpu_set_t cpuset;
	pthread_t thread = pthread_self();

	CPU_ZERO(&mask);
	CPU_SET(c, &mask);

	r = pthread_setaffinity_np(thread, sizeof(mask), &mask);
	if (r != 0) {
		eslog();
	} else {
		log("thread %lu, cpu %d", pthread_self(), c);
	}

	s = pthread_getaffinity_np(thread, sizeof(cpuset), &cpuset);
	if (s != 0) {
		eslog("pthread_getaffinity_np()");
	} else {
		log("Set returned by pthread_getaffinity_np() contained:");
		for (size_t j = 0; j < CPU_SETSIZE; j++) {
			if (CPU_ISSET(j, &cpuset)) {
				log("    CPU %zu", j);
			}
		}
	}

	return r;
}

void *alpha_func(void *arg)
{
	struct channel *ch = (struct channel*)arg;
	struct upstream_echo *echo = ch->echo;
	pthread_barrier_t *barrier = &ch->barrier;
	pthread_barrier_t *barrier_end = &ch->barrier_end;

	glog("send");
	// set_affinity(0);

	ch->fd = upstream_socket_connect("127.0.0.1", 9999);
	if (ch->fd < 0) {
		exit(-EXIT_FAILURE);
	}

	pthread_barrier_wait(barrier);

	int n = 0;
	unsigned char msg[256] = { 0 };
	unsigned char *p1 = (unsigned char*)"alpha";
	int l1 = strlen((const char*)p1) + 1;
	unsigned char *p2 = (unsigned char*)"beta";
	int l2 = strlen((const char*)p2) + 1;
	memcpy(msg, p1, l1);
	memcpy(msg + l1, p2, l2);
	while (n++ < 3) {
		ssize_t s = send(ch->fd, msg, l1 + l2, 0);
		if (s > 0) {
			usleep(100000);
		} else if (-1 == s) {
			eslog("send(%d)", ch->fd);
			break;
		} else {
			eslog();
			break;
		}
	}
	ylog();
	// usleep(100000);
	sleep(1);

	glog("about to cancel %lu", ch->thread_id);
	pthread_cancel(ch->thread_id);
	glog("pthread_cancel(%lu)", ch->thread_id);
	fflush(stdout);

	pthread_barrier_wait(barrier_end);

	glog("return");
	// sleep(1);
	return NULL;
}

static void looper_cleanup_func(void *arg)
{
	struct channel *ch = (struct channel*)arg;
	pthread_barrier_t *barrier_end = &ch->barrier_end;
	clog("ch %p", ch);
	fflush(stdout);
	pthread_barrier_wait(barrier_end);
}

void *looper_func(void *arg)
{
	struct channel *ch = (struct channel*)arg;
	struct upstream_echo *echo = ch->echo;
	pthread_barrier_t *barrier = &ch->barrier;

	// set_affinity(1);

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

	clog("pid %d tid %d thread %lu ch %p",
			getpid(), gettid(), pthread_self(), ch);

	pthread_barrier_wait(barrier);

	pthread_cleanup_push(looper_cleanup_func, ch);

	struct sk_buff *skb = echo->rbuf;
	unsigned char *head = skb->head;
	unsigned int end = skb->end;
	unsigned int *offset = &skb->offset;

	while (1) {
		printf("pthread_testcancel() 1 %lu\n", rdtsc());
		printf("pthread_testcancel() 2 %lu\n", rdtsc());
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		printf("recv\n");
		pthread_testcancel();
		ssize_t n = recv(ch->fd, head, end - *offset, 0);
		pthread_testcancel();
		ylog("n %ld", n);
		if (n > 0) {
			*offset += n;
			unsigned char *p1 = head;
			unsigned char *p2 = head;
			while (p2 < head + *offset) {
				if (*p2 == 0x0d || *p2 == 0x0a) {
					*p2 = 0;
				}
				if (*p2 == 0 && strlen((char*)p1)) {
					ylog("read(%d %lu \"%s\")", ch->fd, p2 - p1, p1);
					p1 = p2 + 1;
				}
				p2++;
			}
			if (p1 == head) {
				;
			} else if (p1 == head + *offset - 1) {
				*offset = 0;
			} else if (p1 > head) {
				*offset = head + *offset - p1;
				memcpy(head, p1, *offset);
			}
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			printf("pthread_testcancel() 3 %lu\n", rdtsc());
			printf("pthread_testcancel() 4 %lu\n", rdtsc());
			// fflush(stdout);
		} else {
			elog();
		}
	}
	clog("pthread_cleanup_pop(0)");
	sleep(-1);
	clog("sleep(-1) returned");
	pthread_cleanup_pop(0);
	clog("return");
	return NULL;
}

int main(int argc, char *argv[])
{
	PRINT_VERSION("ALPHA");
	clog("pid %d tid %d thread %lu",
			getpid(), gettid(), pthread_self());

	// pthread_t thread_id;
	int s = 0;

	struct channel ch;
	memset(&ch, 0, sizeof(ch));
	ch.echo = upstream_echo_create(-1);
	pthread_barrier_init(&ch.barrier, NULL, 2);
	pthread_barrier_init(&ch.barrier_end, NULL, 2);

	s = pthread_create(&ch.thread_id, NULL, looper_func, (void*)&ch);
	if (s) {
		elog("pthread_create(looper)");
		exit(-EXIT_FAILURE);
	}
	pthread_setname_np(ch.thread_id, "looper");
	pthread_getname_np(ch.thread_id, ch.thread_name, 16);
	log("pthread_getname_np(%lu %s)", ch.thread_id, ch.thread_name);
	// pthread_detach(thread_id);

	alpha_func(&ch);

	s = pthread_join(ch.thread_id, NULL);
	if (s) {
		elog("pthread_join(looper)");
		exit(-EXIT_FAILURE);
	}

	pthread_barrier_destroy(&ch.barrier);
	pthread_barrier_destroy(&ch.barrier_end);

	return 0;
}
