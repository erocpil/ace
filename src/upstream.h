#ifndef __UPSTREAM_H__
#define __UPSTREAM_H__

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "ev.h"
#include "hash.h"
#include "sk_buff.h"
#include "define.h"

struct upstream;

/* for each upstream socket and quic conn */
struct upstream_echo {
	struct list_head echo_node;
	int fd;
	/* if upstream is disconnected, client should not write anything */
	int valid;
	struct ev_io w;
	/* current receive buffer, linked to no list */
	struct sk_buff *rbuf;
	struct list_head recv_queue;
	/* current send buffer, picked from send_queue */
	struct sk_buff *sbuf;
	struct list_head send_queue;
	uint32_t n_rq;
	uint32_t n_sq;
	/* quic conn */
	void *external;
	struct upstream *up;
} __attribute__((aligned(sizeof(char))));

struct upstream {
	int fd;
	/* the entity who uses this upstream */
	void *entity;
	// struct sockaddr_in addr;

	int (*rx_process_func)(struct upstream_echo*);
	int (*tx_process_func)(struct upstream_echo*, struct sk_buff*);

	struct list_head echo_head;
	size_t n_echo;

	uint32_t n_skb_batch;

	struct ev_io w;
	struct ev_loop *loop;

	unsigned int retry;
	unsigned int retry_timeout;
	char *file;

	/* indicate structured data or chars */
	int mode;
} __attribute__((aligned(sizeof(char))));

struct upstream_gateway {
	struct ace_hash *in_hash;
	struct ace_hash *out_hash;
	struct upstream *up;
};

#define upstream_is_un(up) ((up) && (up)->file && strlen((up)->file))
#define upstream_is_simple(up) (!upstream_is_un(up))

struct upstream* upstream_init(struct ev_loop *loop, uint32_t n_skb_batch,
		unsigned int retry, unsigned int retry_timeout, char *file,
		int (*rx_process_func)(struct upstream_echo*),
		int (*tx_process_func)(struct upstream_echo*, struct sk_buff*), int mode);
int upstream_listen(struct upstream *up);
int upstream_connect_socket();
ssize_t upstream_alpha_send();
ssize_t upstream_looper_recv();
ssize_t upstream_send_socket();
ssize_t upstream_recv_socket();
int upstream_listen(struct upstream *up);
void upstream_readwrite(struct ev_loop *loop, struct ev_io *watcher, int revents);
void upstream_readwrite_char(struct ev_loop *loop, struct ev_io *watcher, int revents);
void upstream_free(struct upstream *up);
struct upstream_echo *upstream_echo_create(ssize_t len);
int upstream_socket_create(char *ipaddr, unsigned short int port);
int upstream_socket_connect(char *ipaddr, unsigned short int port);
int upstream_set_sockopt(int fd);
void upstream_echo_add_rq(struct upstream_echo *echo, struct sk_buff *skb);
void upstream_echo_del_rq(struct upstream_echo *echo, struct sk_buff *skb);
void upstream_echo_add_sq(struct upstream_echo *echo, struct sk_buff *skb);
void upstream_echo_del_sq(struct upstream_echo *echo, struct sk_buff *skb);

#endif
