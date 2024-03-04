#include <assert.h>
#include "sk_buff.h"
#include "upstream.h"
#include "task.h"

inline void upstream_echo_add_rq(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_add_tail(&skb->skb_node, &echo->recv_queue);
	echo->n_rq++;
}

inline void upstream_echo_del_rq(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_del(&skb->skb_node);
	echo->n_rq--;
}

static void upstream_echo_add_rq_external(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_add_tail(&skb->skb_node, &echo->recv_queue);
	echo->n_rq++;
}

inline void upstream_echo_add_sq(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_add_tail(&skb->skb_node, &echo->send_queue);
	echo->n_sq++;
}

inline void upstream_echo_del_sq(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_del(&skb->skb_node);
	echo->n_sq--;
}

static void upstream_echo_replace_skb(struct upstream_echo *echo)
{
	upstream_echo_add_rq(echo, echo->rbuf);
	echo->rbuf = skb_malloc(echo->rbuf->end);
}

static void upstream_add_echo(struct upstream *up, struct upstream_echo *echo)
{
	struct list_head *head = &up->echo_head;
	struct list_head *node = &echo->echo_node;
	list_add_tail(node, head);
	up->n_echo++;
	log("up %p n_echo %lu", up, up->n_echo);
}

static void upstream_del_echo(struct upstream *up, struct upstream_echo *echo)
{
	if (!echo) {
		return;
	}

	struct list_head *node = &echo->echo_node;
	list_del(node);
	up->n_echo--;
	log("up %p n_echo %lu", up, up->n_echo);
}

int upstream_set_sockopt(int fd)
{
	int reuse = 1;

	if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
		eslog("setsockopt(%d SO_REUSEADDR)", fd);
		exit(-EXIT_FAILURE);
	} else {
		log("setsockopt(%d SO_REUSEADDR)", fd);
	}

	reuse = fcntl(fd, F_GETFL);
	if (-1 == reuse) {
		eslog("fcntl(%d F_GETFL)", fd);
		return -1;
	}

	if (0 != fcntl(fd, F_SETFL, reuse | O_NONBLOCK)) {
		eslog("fcntl(%d F_SETFL)", fd);
		return -1;
	} else {
		log("fcntl(%d O_NONBLOCK)", fd);
	}

	return 0;
}

int upstream_socket_create(char *ipaddr, unsigned short int port)
{
	int saved_errno = 0;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sock) {
		eslog("socket(AF_INET, SOL_SOCKET, 0)");
		return -1;
	}

	if (0 != upstream_set_sockopt(sock)) {
		return -1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0 , sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (NULL == ipaddr) {
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		addr.sin_addr.s_addr = inet_addr(ipaddr);
	}

	if (-1 == bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		eslog("bind(%d)", sock);
		saved_errno = errno;
		close(sock);
		errno = saved_errno;
		return -1;
	}
	log("Upstream socket %s:%u", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	return sock;
}

int upstream_socket_connect(char *ipaddr, unsigned short int port)
{
	int n = 0;
	int fd = 0;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == fd) {
		eslog("socket()");
		return -1;
	}
	struct sockaddr_in addr;
	memset(&addr, 0 , sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ipaddr);
	log("Upstream socket %s:%u", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	n = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	if (-1 == n) {
		eslog("connect(%d)", fd);
		return -1;
	}

	return fd;
}

static int upstream_socket_un_create(const char *file)
{
	struct sockaddr_un sun;

	if (!file || strlen(file) + 1 > sizeof(sun.sun_path)) {
		errno = EINVAL;
		return -1;
	}

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	if (!access((const char*)file, F_OK)) {
		ylog("unlink %s", file);
		if (-1 == unlink((const char*)file)) {
			return -1;
		}
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, file, sizeof(sun.sun_path) - 1);
	// FIXME
	// int size = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
		return -1;
	}

	return fd;
}

void upstream_destroy_echo(struct upstream_echo *echo)
{
	if (!echo) {
		return;
	}

	// XXX
	if (echo->rbuf) {
		free(echo->rbuf);
	}
	// XXX
	if (echo->sbuf) {
		free(echo->sbuf);
	}

	// TODO foreach free skb_head
}

struct upstream_echo *upstream_echo_create(ssize_t len)
{
	struct upstream_echo *echo =
		(struct upstream_echo*)malloc(sizeof(struct upstream_echo));
	memset(echo, 0, sizeof(*echo));

	echo->rbuf = skb_malloc(len);
	INIT_LIST_HEAD(&echo->echo_node);
	INIT_LIST_HEAD(&echo->recv_queue);
	INIT_LIST_HEAD(&echo->send_queue);

	return echo;
}

static void upstream_echo_delete(struct upstream_echo *echo)
{
	clog("echo %p n_rq %u n_tq %u", echo, echo->n_rq, echo->n_sq);
	if (!echo) {
		return;
	}

	/* XXX */
	/* 1. free rbuf */
	if (echo->rbuf) {
		// free(echo->rbuf);
	}

	/* 2. free skb in skb_head */
	struct sk_buff *pos = NULL;
	struct sk_buff *n = NULL;
	if (echo->n_rq) {
		list_for_each_entry_safe(pos, n, &echo->recv_queue, skb_node) {
			log();
		}
	}
	pos = NULL;
	n = NULL;
	if (echo->n_sq) {
		list_for_each_entry_safe(pos, n, &echo->send_queue, skb_node) {
			log();
		}
	}

	/* 3. free echo itself */
	// delete(echo);
	log("free(echo %p)", echo);
	free(echo);
}

static int upstream_create_socket(struct upstream *up)
{
	int fd = 0;

	if (upstream_is_simple(up)) {
		fd = upstream_socket_create(NULL, 9999);
	} else {
		fd = upstream_socket_un_create(up->file);
	}
	if (fd < 0) {
		return -1;
	}
	up->fd = fd;
	clog("fd %d", fd);

	return 0;
}

static inline int upstream_call_rx_process_func(struct upstream_echo *echo)
{
	int n = 0;

	n = echo->up->rx_process_func(echo);
	if (n == (int)echo->n_rq) {
		/* all skbs are processed */
		glog("n %d n_rq %u", n, echo->n_rq);
		assert(0 == echo->n_rq);
	} else if (n > 0) {
		glog("%d skb not processed", n);
		echo->n_rq -= n;
	} else if (!n) {
		glog("no skb processed");
	}

	return n;
}

static void upstream_write_char(struct ev_loop *loop, struct ev_io *watcher, int revents);
static inline int upstream_call_tx_process_func(struct upstream_echo *echo, struct sk_buff *skb)
{
	ylog();
	upstream_echo_add_sq(echo, skb);
	/* TODO FIXME XXX */
	/* still here is some work to do about closed fd and inactive wather */
	/* if fd was closed before client know it */
	if (ev_is_active(&echo->w)) {
		ylog("active");
		ev_io_modify(&echo->w, EV_WRITE);
		ev_io_start(echo->up->loop, &echo->w);
	} else {
		ylog("no active");
		upstream_write_char(echo->up->loop, &echo->w, 0);
	}
	return 0;
}

static void upstream_accept(struct ev_loop *loop,
		struct ev_io *watcher, int revents)
{
	int fd = watcher->fd;
	struct sockaddr_in client_addr;
	socklen_t len = sizeof(client_addr);
	memset(&client_addr, 0, len);

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	int sock = accept(fd, (struct sockaddr*)&client_addr, &len);
	if (-1 == sock) {
		eslog("accept(%d)", fd);
		return;
	}

	log("accept socket %u %s:%u", sock,
			inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

	upstream_set_sockopt(sock);

	struct upstream_echo *echo = upstream_echo_create(-1);
	// skb_reserve(echo->skb, sizeof(struct upstream_skb_head));

	log("echo %p sock %d", echo, sock);

	echo->up = watcher->data;
	// echo->up->entity;
	echo->external = NULL;

	echo->w.data = (void*)echo;
	echo->fd = sock;
	ev_io_init(&echo->w, echo->up->mode ?
			upstream_readwrite : upstream_readwrite_char,
			sock, EV_READ | EV_WRITE);
	ev_io_start(loop, &echo->w);

	rlog("n_echo %lu", echo->up->n_echo);
	upstream_add_echo(echo->up, echo);
	rlog("n_echo %lu", echo->up->n_echo);

	if (ev_is_active(&echo->w)) {
		rlog("active");
	} else {
		rlog("no active");
	}

	if (upstream_call_rx_process_func(echo) < 0) {
		upstream_echo_delete(echo);
		close(sock);
		elog("upstream_call_rx_process_func()");
		return;
	}
	echo->valid = 1;
}

/* XXX */
static void upstream_accept_un(struct ev_loop *loop,
		struct ev_io *watcher, int revents)
{
	rlog();
	int fd = watcher->fd;
	struct sockaddr_un addr;
	int len = sizeof(addr);
	memset(&addr, 0, len);

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	int sock = accept(fd, (struct sockaddr*)&addr, (socklen_t*)&len);
	if (-1 == sock) {
		elog("accept() %d %s", errno, strerror(errno));
		return;
	}

	log("accept %s:%u", inet_ntoa(((struct sockaddr_in*)&addr)->sin_addr), ntohs(((struct sockaddr_in*)&addr)->sin_port));

	len = sizeof(addr);
	if (-1 == getpeername(sock, (struct sockaddr*)&addr,
				(socklen_t*)&len)) {
		eslog("getpeername(%d)", sock);
	} else {
		log("accept alpha %d %s", sock, addr.sun_path);
	}

	upstream_set_sockopt(sock);

	struct upstream_echo *echo = upstream_echo_create(-1);
	// skb_reserve(echo->skb, sizeof(struct upstream_skb_head));
	echo->w.data = (void*)echo;
	ev_io_init(&echo->w, upstream_readwrite, sock, EV_READ | EV_WRITE);
	ev_io_start(loop, &echo->w);

	upstream_add_echo(echo->up, echo);
}

int upstream_listen(struct upstream *up)
{
	struct upstream_echo *echo = NULL;

	if (!up) {
		errno = EINVAL;
		return -1;
	}

	if (listen(up->fd, 2) < 0) {
		eslog("listen(%d 2)", echo->fd);
		return -1;
	}

	ev_io_init(&up->w, upstream_accept, up->fd, EV_READ);
	up->w.data = (void*)up;
	ev_io_start(up->loop, &up->w);

	return 0;
}

/** upstream_read_one - receive one sk_buff
 * @param echo
 *   where to read and write
 * @return
 *   1: skb received completely
 *   0: skb received incompletely
 *   -1: error occurred
 */
static int upstream_read_skb(struct upstream_echo *echo)
{
	ssize_t n = 0;
	int fd = echo->fd;
	struct sk_buff *skb = echo->rbuf;
	unsigned int *length = (unsigned int*)skb->head;
	unsigned int *offset = (unsigned int*)&skb->offset;

	if (skb->data != skb->head) {
		goto READ_HEAD;
	}

	/* read length, theme and serial */
	n = read(fd, (void*)((char*)length + *offset),
			sizeof(struct upstream_skb_head) - *offset);
	if (n > 0) {
		*offset += n;
		if (sizeof(struct upstream_skb_head) == *offset) {
			if (!*length) {
				/* */
				return 1;
			}
			SKB_DUMP(skb);
			if (!skb_reserve(skb, sizeof(struct upstream_skb_head))) {
				errno = EMSGSIZE;
				eslog("head(%lu) exceeds buffer size(%u)",
						sizeof(struct upstream_skb_head), skb->end);
				goto ERROR;
			}
			SKB_DUMP(skb);
			if (!skb_put(skb, *length)) {
				errno = EMSGSIZE;
				eslog("length(%u) exceeds buffer size(%u)", *length, skb->end);
				goto ERROR;
			}
			SKB_DUMP(skb);
			/* reset to recv data part */
			*offset = 0;
			SKB_DUMP(skb);
			goto READ_HEAD;
		}
		return 0;
	} else if (!n) {
		goto ERROR;
	} else if (n < 0) {
		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
			return 0;
		}
		eslog("read(%d)", echo->fd);
		goto ERROR;
	}

READ_HEAD:
	/* read data */
	n = read(fd, skb->data + *offset, skb->len - *offset);
	if (n > 0) {
		*offset += n;
		if (*offset == skb->len) {
			;
		}
	} else if (!n) {
		elog("fd %d closed", fd);
		goto ERROR;
	} else if (n < 0) {
		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
			return n;
		}
		eslog("read(%d)", echo->fd);
		goto ERROR;
	}
	return n;

ERROR:
	close(fd);
	return -1;
}

static int upstream_write_skb(struct upstream_echo *echo)
{
	return 0;
}

static void upstream_read(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	int fd = watcher->fd;
	struct upstream_echo *echo = (struct upstream_echo*)watcher->data;

	assert(fd == echo->fd);
	int n = upstream_read_skb(echo);

	switch (n) {
		case 1:
			/* 1. no skb handler was provided, just start over */
			if (unlikely(echo->up->rx_process_func)) {
				// TODO
				struct sk_buff *skb = echo->rbuf;
				skb_push(skb, skb->data - skb->head);
				skb_reset_tail_pointer(skb);
				break;
			}
			/* 2. pend this skb and malloc a new one */
			upstream_echo_replace_skb(echo);
			/* 3. check if recv()ed enough skb */
			if (echo->n_rq < echo->up->n_skb_batch) {
				break;
			}
			/* 4. process all pending skb */
			if (upstream_call_rx_process_func(echo) < 0) {
				goto ERROR;
			}
			break;
		case 0:
			if (echo->n_rq) {
				if (upstream_call_rx_process_func(echo) < 0) {
					goto ERROR;
				}
			}
			break;
		case -1:
			goto ERROR;
			break;
		default:
			goto ERROR;
			break;
	}

	return;

ERROR:
	ev_io_stop(loop, watcher);
	upstream_del_echo(echo->up, echo);
	log("up ->n_echo %lu", echo->up->n_echo);
	upstream_echo_delete(echo);
}

static void upstream_write(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	/* TODO */
#if 0
	ssize_t n = 0;
	int fd = watcher->fd;
	struct upstream_echo *echo = (struct upstream_echo*)watcher->data;
	struct sk_buff *skb = echo->skb;
	unsigned int *length = (unsigned int*)skb->head;

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	n = write(fd, skb->data + skb->offset, skb->len - skb->offset);
	if (likely(n > 0)) {
		skb->offset += n;
		if (skb->offset == skb->len) {
		}
	} else if (!n) {
		elog("fd %d closed", fd);
		goto ERROR;
	} else {
		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
			return;
		}
		eslog("read(%d)", echo->fd);
		goto ERROR;
	}

ERROR:
	ev_io_stop(loop, watcher);
	close(fd);
	free(echo);
	return;

#endif
}

void upstream_readwrite(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (revents & EV_READ) {
		upstream_read(loop, watcher, revents);
	}
	if (revents & EV_WRITE) {
		upstream_write(loop, watcher, revents);
	}

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}
}

struct upstream* upstream_init(struct ev_loop *loop, uint32_t n_skb_batch,
		unsigned int retry, unsigned int retry_timeout, char *file,
		int (*rx_process_func)(struct upstream_echo*),
		int (*tx_process_func)(struct upstream_echo*, struct sk_buff*), int mode)
{
	if (!loop) {
		errno = EINVAL;
		return NULL;
	}
	struct upstream *up = (struct upstream*)malloc(sizeof(struct upstream));

	memset(up, 0, offsetof(struct upstream, loop));
	if (upstream_create_socket(up) < 0) {
		upstream_free(up);
		return NULL;
	}
	up->n_skb_batch = n_skb_batch > 0 ? n_skb_batch : 1;
	up->retry = retry;
	up->retry_timeout = retry_timeout;
	up->file = file;
	up->loop = loop;
	if (rx_process_func) {
		up->rx_process_func = rx_process_func;
	} else {
		ylog("TODO default rx_process_func");
	}
	if (tx_process_func) {
		ylog("tx_process_func from downstream");
		up->tx_process_func = tx_process_func;
	} else {
		up->tx_process_func = upstream_call_tx_process_func;
	}
	up->mode = mode;
	INIT_LIST_HEAD(&up->echo_head);

	return up;
}

void upstream_free(struct upstream *up)
{
	if (up) {
		free(up);
	}

	// TODO FIXME XXX
	upstream_del_echo(up, NULL);
}

static void upstream_read_char(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	ssize_t n = 0;
	int fd = watcher->fd;
	struct upstream_echo *echo = (struct upstream_echo*)watcher->data;
	struct sk_buff *skb = echo->rbuf;
	unsigned char *head = skb->head;
	unsigned int end = skb->end;
	unsigned int *offset = &skb->offset;

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	ev_io_stop(loop, watcher);

	/* read chars */
	n = read(fd, head + *offset, end - *offset);
	if (n > 0) {
		*offset += n;
		unsigned char *p1 = head;
		unsigned char *p2 = head;
		while (p2 < head + *offset) {
			if (*p2 == 0x0d || *p2 == 0x0a) {
				*p2 = 0;
			}
			if (*p2 == 0) {
				if (strlen((char*)p1)) {
					ylog("read(%d %lu \"%s\")", fd, p2 - p1, p1);
#if 1
					char *p3 = strstr((char*)p1, " ");
					if (!p3) {
						rlog("TODO");
					}
					*p3 = '\0';
					int type = task_find_type((char*)p1);
					if (-1 == type) {
						elog("invalid command %s", p1);
						goto ERROR;
					}
					clog("type %d", type);
					*p3 = ' ';
					p3++;
#endif

					char *p4 = strstr(p3, " ");
					p4++;
					/* including trailing '\0' */
					unsigned int len = p2 - (unsigned char*)p4 + 1;
					// rlog("len %d", len);
					struct sk_buff *skb =
						skb_malloc(sizeof(struct upstream_skb_head) + len);
					skb_reserve(skb, sizeof(struct upstream_skb_head));
					skb_put(skb, len);
					/* make the cmd */
					struct upstream_skb_head *head =
						(struct upstream_skb_head*)skb->head;
					/* string from telnet */
					head->length = len;
					/* 0: sendfile */
					head->theme = type;
					/* use 3 streams */
					head->serial = atoi(p3);
					rlog("serial %u", head->serial);
					memcpy(skb->data, p4, len);
					log("%p %u %u %u", head, head->length, head->theme, head->serial);
					upstream_echo_add_rq_external(echo, skb);
					/* TODO register write event to echo back */
					// ev_io_modify(watcher, EV_WRITE);
					if (upstream_call_rx_process_func(echo) < 0) {
						upstream_echo_delete(echo);
						close(fd);
						elog("upstream_call_rx_process_func()");
						return;
					}
#if 1
					if (write(fd, p1, p2 - p1) < 0) {
						eslog("write(%d %u \"%s\")", fd, len, p1);
					} else {
						ylog("write(%d %u \"%s\")", fd, len, p1);
					}
#endif
				}
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

		if (*offset == end) {
			rlog("message too long");
			goto ERROR;
		}
		return;
	} else if (!n) {
		eslog("read(%d 0), close", fd);
		goto ERROR;
	} else if (n < 0) {
		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
			return;
		}
		eslog("read(%d)", echo->fd);
		goto ERROR;
	}

	return;

ERROR:
	/* FIXME */
	echo->valid = 0;
	if (EBADF == errno) { /* fd may be closed previously */
		return;
	}
	ev_io_stop(loop, watcher);
	ylog("stop echo %p(%p %p) loop %p watcher %p",
			echo, echo->up->loop, &echo->w, loop, watcher);
	close(fd);
	rlog("%d closed", fd);
	upstream_del_echo(echo->up, echo);
	/* FIXME if echo is to be deleted, client should know */
	// upstream_echo_delete(echo);
}

static void upstream_write_char(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	ssize_t n = 0;
	int fd = watcher->fd;

	struct upstream_echo *echo = (struct upstream_echo*)watcher->data;
	if (!echo->valid) {
		/* TODO may need clean echo and its conn*/
		// upstream_echo_delete(echo);
		ylog("invalid fd %d", fd);
		ev_io_stop(loop, watcher);
		return;
	}
	if (ev_is_active(&echo->w)) {
		rlog("active");
		ev_io_stop(loop, watcher);
	} else {
		rlog("no active");
	}
	if (!echo->n_sq) {
		rlog();
		return;
	}
	if (!echo->sbuf) {
		echo->sbuf = list_first_entry(&echo->send_queue, struct sk_buff, skb_node);
	}
	// goto ERROR;

	struct sk_buff *skb = echo->sbuf;
	// SKB_DUMP(skb);
	unsigned int *length = (unsigned int*)skb->head;

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
	// upstream_skb_head_dump(head);

	/* assume there are enough space in skb->head */
	unsigned char *p = (unsigned char*)skb->head + sizeof(*head);
	if (skb->len != sizeof(*head)) {
		n = write(fd, p, skb->len - sizeof(*head));
		/* TODO */
		if (n < 0) {
			eslog("write(%d)", fd);
			goto ERROR;
		}
	}

	p = (unsigned char*)(skb->head) + sizeof(*head);
	sprintf((char*)p, "\n%u %u %u\n", head->length, head->theme, head->serial);
	skb->data = p;
	skb->offset = 0;
	skb->len = strlen((char*)p) + 1;
	n = write(fd, skb->data + skb->offset, skb->len - skb->offset);
	if (likely(n > 0)) {
		skb->offset += n;
		if (skb->offset == skb->len) {
			upstream_echo_del_sq(echo, skb);
			echo->sbuf = NULL; /* this is important! */
			if (!echo->n_sq) {
#if 1
				if ((unsigned short int)-1 == head->theme &&
						(unsigned short int)-1 != head->serial) {
					/* task exit, close upstream */
					char *msg = (char*)"task exit, close upstream\n";
					write(fd, msg, strlen(msg) + 1);
					goto ERROR;
				} else if (!head->length && !head->theme && !head->serial) {
					/* conn not established */
					char *msg = (char*)"conn not established\n";
					write(fd, msg, strlen(msg) + 1);
					goto ERROR;
				}
#endif
				ylog("switch fd %d to r/w", fd);
				ev_io_modify(watcher, EV_READ);
			}
		}
		ev_io_start(loop, watcher);
	} else if (!n) {
		elog("fd %d closed", fd);
		goto ERROR;
	} else {
		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
			return;
		}
		eslog("read(%d)", echo->fd);
		goto ERROR;
	}
	return;

ERROR:
	/* FIXME */
	echo->valid = 0;
	if (EBADF == errno) { /* fd may be closed previously */
		return;
	}
	ev_io_stop(loop, watcher);
	ylog("stop echo %p(%p %p) loop %p watcher %p",
			echo, echo->up->loop, &echo->w, loop, watcher);
	close(fd);
	rlog("%d closed", fd);
	upstream_del_echo(echo->up, echo);
	// upstream_echo_delete(echo);
}

void upstream_readwrite_char(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	if (revents & EV_READ) {
		upstream_read_char(loop, watcher, revents);
	}
	if (revents & EV_WRITE) {
		upstream_write_char(loop, watcher, revents);
		ylog();
	}
}

/* XXX */
struct upstream_gateway *upstream_gw_init(unsigned int n_bucket, unsigned int max_elem)
{
	ace_hash_create(n_bucket, max_elem);
	ace_hash_create(n_bucket, max_elem);
	return NULL;
}
