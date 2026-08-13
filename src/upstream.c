#include <assert.h>
#include "sk_buff.h"
#include "upstream.h"
#include "task.h"
#include "control_socket.h"
#include "control_command.h"

inline int upstream_echo_add_rq(struct upstream_echo *echo, struct sk_buff *skb)
{
	if (!echo || !skb || !ace_quota_can_add(echo->n_rq, ACE_MAX_UPSTREAM_QUEUE)) {
		errno = ENOBUFS;
		return -1;
	}
	list_add_tail(&skb->skb_node, &echo->recv_queue);
	echo->n_rq++;
	return 0;
}

inline void upstream_echo_del_rq(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_del(&skb->skb_node);
	echo->n_rq--;
}

static int upstream_echo_add_rq_external(struct upstream_echo *echo, struct sk_buff *skb)
{
	return upstream_echo_add_rq(echo, skb);
}

inline int upstream_echo_add_sq(struct upstream_echo *echo, struct sk_buff *skb)
{
	if (!echo || !skb || !ace_quota_can_add(echo->n_sq, ACE_MAX_UPSTREAM_QUEUE)) {
		errno = ENOBUFS;
		return -1;
	}
	list_add_tail(&skb->skb_node, &echo->send_queue);
	echo->n_sq++;
	return 0;
}

inline void upstream_echo_del_sq(struct upstream_echo *echo, struct sk_buff *skb)
{
	list_del(&skb->skb_node);
	echo->n_sq--;
}

static int upstream_echo_replace_skb(struct upstream_echo *echo)
{
	struct sk_buff *replacement;
	if (!echo || !echo->rbuf || !ace_quota_can_add(echo->n_rq, ACE_MAX_UPSTREAM_QUEUE)) {
		errno = ENOBUFS;
		return -1;
	}
	replacement = skb_malloc(echo->rbuf->end);
	if (!replacement || upstream_echo_add_rq(echo, echo->rbuf) != 0) {
		skb_free(replacement);
		return -1;
	}
	echo->rbuf = replacement;
	return 0;
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
		return -1;
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

struct upstream_echo *upstream_echo_create(ssize_t len)
{
	struct upstream_echo *echo =
		(struct upstream_echo*)malloc(sizeof(struct upstream_echo));
	if (!echo) {
		return NULL;
	}
	memset(echo, 0, sizeof(*echo));
	echo->fd = -1;

	echo->rbuf = skb_malloc(len);
	if (!echo->rbuf) {
		free(echo);
		return NULL;
	}
	INIT_LIST_HEAD(&echo->echo_node);
	INIT_LIST_HEAD(&echo->recv_queue);
	INIT_LIST_HEAD(&echo->send_queue);

	return echo;
}

/* upstream_echo_delete — the single destroy entry for an echo.
 * Owns the client fd, rbuf, queued sk_buffs, and the echo struct itself:
 * removes the echo from its upstream's list (if linked), closes the fd, then
 * frees everything.  Callers must not also del_echo()/close() the echo. */
static void upstream_echo_delete(struct upstream_echo *echo)
{
	if (!echo) {
		return;
	}
	clog("echo %p n_rq %u n_tq %u", echo, echo->n_rq, echo->n_sq);

	/* Remove from the upstream's echo list, if it was ever linked. */
	if (echo->up) {
		upstream_del_echo(echo->up, echo);
	}

	/* Close the client fd (owned by the echo). */
	if (echo->fd >= 0) {
		close(echo->fd);
		echo->fd = -1;
	}

	/* 1. free rbuf */
	skb_free(echo->rbuf);
	echo->rbuf = NULL;

	/* 2. free skb in skb_head */
	struct sk_buff *pos = NULL;
	struct sk_buff *n = NULL;
	if (echo->n_rq) {
		list_for_each_entry_safe(pos, n, &echo->recv_queue, skb_node) {
			upstream_echo_del_rq(echo, pos);
			skb_free(pos);
		}
	}
	pos = NULL;
	n = NULL;
	if (echo->n_sq) {
		list_for_each_entry_safe(pos, n, &echo->send_queue, skb_node) {
			upstream_echo_del_sq(echo, pos);
			skb_free(pos);
		}
	}

	/* 3. free echo itself */
	log("free(echo %p)", echo);
	free(echo);
}

static int upstream_create_socket(struct upstream *up)
{
	int fd = 0;

	if (upstream_is_simple(up)) {
		fd = upstream_socket_create(NULL, 9999);
	} else {
		fd = control_socket_un_create(up->file);
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
	if (upstream_echo_add_sq(echo, skb) != 0) {
		return -1;
	}
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
	struct sockaddr_storage client_addr;
	socklen_t len = sizeof(client_addr);
	memset(&client_addr, 0, len);

	if (EV_ERROR & revents) {
		elog("invalid event");
		return;
	}

	int sock = control_socket_accept(fd, (struct sockaddr*)&client_addr, &len);
	if (-1 == sock) {
		eslog("accept(%d)", fd);
		return;
	}

	if (client_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)&client_addr;
		log("accept socket %u %s:%u", sock,
		    inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
	} else {
		/* Unix-socket peer: no INET address to log. */
		log("accept socket %u (family %u)", sock, client_addr.ss_family);
	}

	upstream_set_sockopt(sock);

	struct upstream_echo *echo = upstream_echo_create(-1);
	if (!echo) {
		close(sock);
		return;
	}
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
		elog("upstream_call_rx_process_func()");
		return;
	}
	echo->valid = 1;
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

	if (fd != echo->fd) {
		errno = EBADF;
		goto ERROR;
	}
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
				if (upstream_echo_replace_skb(echo) != 0) {
					goto ERROR;
				}
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
	struct upstream *up = calloc(1, sizeof(struct upstream));
	if (!up) {
		return NULL;
	}
	up->fd = -1;
	up->loop = loop;
	up->file = file;
	INIT_LIST_HEAD(&up->echo_head);
	if (upstream_create_socket(up) < 0) {
		upstream_free(up);
		return NULL;
	}
	up->n_skb_batch = n_skb_batch > 0 ? n_skb_batch : 1;
	up->retry = retry;
	up->retry_timeout = retry_timeout;
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
	return up;
}

void upstream_free(struct upstream *up)
{
	if (!up) {
		return;
	}
	struct upstream_echo *echo = NULL;
	struct upstream_echo *next = NULL;
	list_for_each_entry_safe(echo, next, &up->echo_head, echo_node) {
		if (up->loop) {
			ev_io_stop(up->loop, &echo->w);
		}
		upstream_echo_delete(echo);
	}
	if (up->loop) {
		ev_io_stop(up->loop, &up->w);
	}
	if (up->fd >= 0) {
		close(up->fd);
		up->fd = -1;
	}
	free(up);
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

		size_t off = 0;
		while (off < *offset) {
			size_t consumed = 0;
			size_t line_start = off;
			struct sk_buff *out = NULL;
			enum control_parse_status st = control_command_parse(
				head + off, *offset - off, &consumed, &out);

			if (st == CONTROL_PARSE_INCOMPLETE)
				break;   /* need more bytes for a full line */

			off += consumed;
			if (st == CONTROL_PARSE_INVALID) {
				elog("invalid control command");
				goto ERROR;
			}

			if (!out)
				continue;   /* empty line, already consumed */

			/* enqueue first, then run the rx callback — on failure the
			 * client must NOT get a success-looking echo back. */
			if (upstream_echo_add_rq_external(echo, out) != 0) {
				skb_free(out);
				goto ERROR;
			}
			if (upstream_call_rx_process_func(echo) < 0) {
				upstream_echo_delete(echo);
				elog("upstream_call_rx_process_func()");
				return;
			}

			/* best-effort echo of the raw command line */
			size_t echo_len = consumed;
			while (echo_len > 0 &&
			       (head[line_start + echo_len - 1] == '\n' ||
			        head[line_start + echo_len - 1] == '\r'))
				echo_len--;
			if (write(fd, head + line_start, echo_len) < 0)
				eslog("write(%d %zu)", fd, echo_len);
			else
				ylog("write(%d %zu)", fd, echo_len);
		}

		/* shift any leftover partial line to the front of the buffer */
		if (off < *offset) {
			size_t leftover = *offset - off;
			memmove(head, head + off, leftover);
			*offset = leftover;
		} else {
			*offset = 0;
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
	echo->valid = 0;
	if (EBADF == errno) { /* fd may be closed previously */
		return;
	}
	ev_io_stop(loop, watcher);
	ylog("stop echo %p(%p %p) loop %p watcher %p",
			echo, echo->up->loop, &echo->w, loop, watcher);
	upstream_echo_delete(echo);
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
	{
		size_t written = 0;
		if (control_response_encode(skb, p, skb->end - sizeof(*head),
					    &written) != 0) {
			eslog("control_response_encode()");
			goto ERROR;
		}
		skb->len = (unsigned int)written;
	}
	skb->data = p;
	skb->offset = 0;
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
	echo->valid = 0;
	if (EBADF == errno) { /* fd may be closed previously */
		return;
	}
	ev_io_stop(loop, watcher);
	ylog("stop echo %p(%p %p) loop %p watcher %p",
			echo, echo->up->loop, &echo->w, loop, watcher);
	upstream_echo_delete(echo);
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
