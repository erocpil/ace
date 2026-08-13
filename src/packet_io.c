#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include "packet_io.h"
#include "connote.h"
#include "service.h"

int connote_init_server(struct connote *ce)
{
	int fd = -1;
	int saved_errno = 0;
	socklen_t socklen = 0;
	int s = 0;
	int optval = 1;
	struct co_config *cc = ce->cc;
	struct sockaddr_in *const sa4 = (struct sockaddr_in*)&ce->sas;
	struct sockaddr_in6 *const sa6 = (struct sockaddr_in6*)&ce->sas;
	struct sockaddr *sa_local = (struct sockaddr*)&ce->sas;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	char addr_str[0x20] = { 0 };

	if (ce->fd != -1) {
		errno = EALREADY;
		return -1;
	}

	if (inet_pton(AF_INET, cc->host, &sa4->sin_addr)) {
		sa4->sin_family = AF_INET;
		sa4->sin_port = htons(cc->port);
	} else if (memset(sa6, 0, sizeof(*sa6)), inet_pton(AF_INET6, cc->host, &sa6->sin6_addr)) {
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = htons(cc->port);
	} else {
		int s = 0;
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICSERV;
		switch (cc->ipver) {
			case 4:
				hints.ai_family = AF_INET;
				break;
			case 6:
				hints.ai_family = AF_INET6;
				break;
			default:
				hints.ai_family = AF_UNSPEC;
				break;
		}
		char port[8];
		sprintf(port, "%u", cc->port);
		s = getaddrinfo(cc->host, port, &hints, &res);
		if (0 != s) {
			elog("getaddrinfo(%s) %s", cc->host, gai_strerror(s));
			goto ERROR;
		} else {
			log("getaddrinfo(%s)", cc->host);
		}
		if (res->ai_addrlen > sizeof(ce->sas)) {
			elog("getaddrinfo(%s) returned address %d too long", cc->host, res->ai_addrlen);
			goto ERROR;
		}
		memcpy(&ce->sas, res->ai_addr, res->ai_addrlen);
	}

	switch(sa_local->sa_family) {
		case AF_INET:
			socklen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			socklen = sizeof(struct sockaddr_in6);
			break;
		default:
			errno = EINVAL;
			goto ERROR;
	}

	fd = socket(sa_local->sa_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		eslog("socket()");
		goto ERROR;
	} else {
		log("socket(%d)", fd);
	}

	if (0 != bind(fd, sa_local, socklen)) {
		// FIXME
		eslog("bind(%d %s:%d)", fd,
				inet_ntoa(((struct sockaddr_in*)sa_local)->sin_addr),
				ntohs(((struct sockaddr_in*)sa_local)->sin_port));
		goto ERROR;
	} else {
		log("bind(%d %s:%d)", fd,
				inet_ntoa(((struct sockaddr_in*)sa_local)->sin_addr),
				ntohs(((struct sockaddr_in*)sa_local)->sin_port));
	}

	if (0 != set_nonblocking(fd)) {
		eslog("set_nonblock(%d)", fd);
		goto ERROR;
	} else {
		log("set_nonblock(%d)", fd);
	}

	/* FIXME so many setsockopt() */
	optval = 1;
	if (AF_INET == sa_local->sa_family) {
		s = setsockopt(fd, IPPROTO_IP,
#if defined(IP_RECVORIGDSTADDR)
				IP_RECVORIGDSTADDR,
#else
				IP_PKTINFO,
#endif
				(const void*)&optval, sizeof(optval));
	} else {
		s = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const void*)&optval, sizeof(optval));
	}
	if (0 != s) {
		eslog("setsockopt(%d IP_RECVORIGDSTADDR/IP_PKTINFO or IPV6_RECVPKTINFO)", fd);
		goto ERROR;
	} else {
		log("setsockopt(%d IP_RECVORIGDSTADDR/IP_PKTINFO or IPV6_RECVPKTINFO)", fd);
	}

#if defined(SO_RXQ_OVFL)
	optval = 1;
	s = setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, (const void*)&optval, sizeof(optval));
	if (0 != s) {
		eslog("setsockopt(%d SO_RXQ_OVFL)", fd);
		goto ERROR;
	} else {
		log("setsockopt(%d SO_RXQ_OVFL)", fd);
	}
#endif

#if LSQUIC_DONTFRAG_SUPPORTED
	blog("LSQUIC_DONTFRAG_SUPPORTED");
#endif

#if ECN_SUPPORTED
	optval = 1;
	if (AF_INET == sa_local->sa_family) {
		s = setsockopt(fd, IPPROTO_IP, IP_RECVTOS, (const void*)optval, sizeof(optval));
	} else {
		s = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, (const void*)optval, sizeof(optval));
	}
	if (0 != s) {
		goto ERROR;
	} else {
		log("setsockopt(%d IP_RECVTOS or IPV6_RECVTCLASS", fd);
	}
#endif

#if 0
	/* this will cause CPU high load */
	optval = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, (const void*)&optval, sizeof(optval))) {
		eslog("setsockopt zerocopy");
	} else {
		log("setsockopt(%d SO_ZEROCOPY)", fd);
	}
#endif

	/* TODO */
	/* setsockopt(fd, SOL_SOCKET, SO_SNDBUF, ); */
	/* setsockopt(fd, SOL_SOCKET, SO_RCVBUF, ); */

	if (0 != getsockname(fd, (struct sockaddr*)sa_local, &socklen)) {
		eslog("getsockname(%d)", fd);
		goto ERROR;
	} else {
		log("getsockname(%d)", fd);
	}
	memcpy((void*)&ce->local_addr, sa_local, sa_local->sa_family == AF_INET ?
			sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	switch (sa_local->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &((struct sockaddr_in*)sa_local)->sin_addr, addr_str, sizeof(addr_str));
			log("local address %s port %u", addr_str, ntohs(((struct sockaddr_in*)sa_local)->sin_port));
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa_local)->sin6_addr,
					addr_str, sizeof(addr_str));
			log("local address %s port %u", addr_str,
					ntohs(((struct sockaddr_in6*)sa_local)->sin6_port));
			break;
		default:
			errno = EAFNOSUPPORT;
			goto ERROR;
	}

	ce->fd = fd;

	return 0;

ERROR:
	if (res) {
		freeaddrinfo(res);
	}
	if (fd >= 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		ce->fd = -1;
	}

	return -1;
}

int connote_init_client(struct connote *ce)
{
	int fd = -1;
	socklen_t socklen = 0;
	socklen_t peer_socklen = 0;
	struct co_config *cc = ce->cc;
	struct sockaddr_in *const sa4 = (struct sockaddr_in*)&ce->sas;
	struct sockaddr_in6 *const sa6 = (struct sockaddr_in6*)&ce->sas;
	const struct sockaddr *sa_peer = (struct sockaddr*)&ce->sas;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int saved_errno = 0;
	int s = 0;
	char addr_str[0x20] = { 0 };

	if (ce->fd != -1) {
		errno = EALREADY;
		return -1;
	}

	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} u;

	struct sockaddr *sa_local = (struct sockaddr*)&u;

	if (inet_pton(AF_INET, cc->host, &sa4->sin_addr)) {
		sa4->sin_family = AF_INET;
		sa4->sin_port = htons(cc->port);
	} else if (memset(sa6, 0, sizeof(*sa6)), inet_pton(AF_INET6, cc->host, &sa6->sin6_addr)) {
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = htons(cc->port);
	} else {
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICSERV;
		switch (cc->ipver) {
			case 4:
				hints.ai_family = AF_INET;
				break;
			case 6:
				hints.ai_family = AF_INET6;
				break;
			default:
				hints.ai_family = AF_UNSPEC;
				break;
		}
		char port[8];
		sprintf(port, "%u", cc->port);
		s = getaddrinfo(cc->host, port, &hints, &res);
		if (0 != s) {
			elog("getaddrinfo(%s) %s", cc->host, gai_strerror(s));
			goto ERROR;
		} else {
			log("getaddrinfo(%s)", cc->host);
		}
		if (res->ai_addrlen > sizeof(ce->sas)) {
			elog("getaddrinfo(%s) returned address %d too long", cc->host, res->ai_addrlen);
			goto ERROR;
		}
		memcpy(&ce->sas, res->ai_addr, res->ai_addrlen);
	}

	switch (sa_peer->sa_family) {
		case AF_INET:
			socklen = sizeof(struct sockaddr_in);
			u.sin.sin_family = AF_INET;
			u.sin.sin_addr.s_addr = INADDR_ANY;
			u.sin.sin_port = 0;
			break;
		case AF_INET6:
			socklen = sizeof(struct sockaddr_in6);
			memset(&u.sin6, 0, sizeof(u.sin6));
			u.sin6.sin6_family = AF_INET6;
			break;
		default:
			elog("invalid peer address");
			errno = EINVAL;
			goto ERROR;
	}

	fd = socket(sa_peer->sa_family, SOCK_DGRAM, 0);
	if (-1 == fd) {
		eslog("socket()");
		goto ERROR;
	} else {
		log("socket(%d)", fd);
	}

	if (0 != bind(fd, sa_local, socklen)) {
		eslog("bind(%d %s:%d)", fd,
				inet_ntoa(((struct sockaddr_in*)sa_local)->sin_addr),
				ntohs(((struct sockaddr_in*)sa_local)->sin_port));
		goto ERROR;
	} else {
		log("bind(%d %s:%d)", fd,
				inet_ntoa(((struct sockaddr_in*)sa_local)->sin_addr),
				ntohs(((struct sockaddr_in*)sa_local)->sin_port));
	}

	peer_socklen = AF_INET == sa_peer->sa_family ?
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	if (0 != connect(fd, sa_peer, peer_socklen)) {
		eslog("connect(%d %s:%d)", fd,
				inet_ntoa(((struct sockaddr_in*)sa_peer)->sin_addr),
				ntohs(((struct sockaddr_in*)sa_peer)->sin_port));
		goto ERROR;
	} else {
		log("connect(%d %s:%d)", fd,
				inet_ntoa(((struct sockaddr_in*)sa_peer)->sin_addr),
				ntohs(((struct sockaddr_in*)sa_peer)->sin_port));
	}

#ifdef __linux__
	if (strlen(cc->if_name) > 0) {
		if (0 != setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, cc->if_name, IFNAMSIZ)) {
			eslog("setsockopt(%d SO_BINDTODEVICE %s)", fd, cc->if_name);
			goto ERROR;
		} else {
			ylog("setsockopt(%d SO_BINDTODEVICE %s)", fd, cc->if_name);
			cc->bindtodevice = 1;
		}
	} else {
		cc->bindtodevice = 0;
	}
#endif

	if (0 != set_nonblocking(fd)) {
		eslog("set_nonblock(%d)", fd);
		goto ERROR;
	} else {
		log("set_nonblock(%d)", fd);
	}

#if 0
	/* this will cause CPU high load */
	int optval = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY,
				(const void*)&optval, sizeof(optval))) {
		eslog("setsockopt zerocopy");
	} else {
		log("setsockopt(%d SO_ZEROCOPY)", fd);
	}
#endif

#if LSQUIC_DONTFRAG_SUPPORTED
	blog("LSQUIC_DONTFRAG_SUPPORTED");
#endif

#if ECN_SUPPORTED
	optval = 1;
	if (AF_INET == sa_local->sa_family) {
		s = setsockopt(fd, IPPROTO_IP, IP_RECVTOS, (const void*)optval, sizeof(optval));
	} else {
		s = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, (const void*)optval, sizeof(optval));
	}
	if (0 != s) {
		goto ERROR;
	} else {
		log("setsockopt(%d IP_RECVTOS or IPV6_RECVTCLASS", fd);
	}
#endif

	// TODO
	// setsockopt(fd, SOL_SOCKET, SO_SNDBUF, );
	// setsockopt(fd, SOL_SOCKET, SO_RCVBUF, );

	if (0 != getsockname(fd, (struct sockaddr*)sa_local, &socklen)) {
		eslog("getsockname(%d)", fd);
		goto ERROR;
	} else {
		log("getsockname(%d)", fd);
	}
	memcpy((void*)&ce->local_addr, sa_local, sa_local->sa_family == AF_INET ?
			sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	switch (sa_local->sa_family) {
		case AF_INET:
			log("local address %s port %u",
					inet_ntop(AF_INET, &((struct sockaddr_in*)sa_local)->sin_addr, addr_str, sizeof(addr_str)),
					ntohs(((struct sockaddr_in*)sa_local)->sin_port)
			   );
			break;
		case AF_INET6:
			log("local address %s port %u",
					inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa_local)->sin6_addr,
						addr_str, sizeof(addr_str)),
					ntohs(((struct sockaddr_in6*)sa_local)->sin6_port)
			   );
			break;
		default:
			errno = EAFNOSUPPORT;
			goto ERROR;
	}

	ce->fd = fd;

	return 0;

ERROR:
	if (res) {
		freeaddrinfo(res);
	}
	if (fd >= 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
	}
	return -1;
}

int service_packets_out(void *packets_out_ctx,
		const struct lsquic_out_spec *out_spec,
		unsigned int n_packets_out)
{
	struct service *se = (struct service*)packets_out_ctx;
	size_t out_limit = se->config.out_limit;
	struct msghdr msg = {
		.msg_flags = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
	};

	size_t n = 0;

	// TODO cmsg(3)

	if (!n_packets_out) {
		return 0;
	}

#if 0
	if (out_limit > n_packets_out) {
		out_limit = n_packets_out;
	}
#else
	out_limit = n_packets_out;
#endif

	do {
		struct connote *ce = (struct connote*)out_spec[n].peer_ctx;
		msg.msg_name = (void*)out_spec[n].dest_sa;
		msg.msg_namelen = ace_sockaddr_len(out_spec[n].dest_sa);
		if (msg.msg_namelen == 0) {
			errno = EAFNOSUPPORT;
			break;
		}
		msg.msg_iov = out_spec[n].iov;
		msg.msg_iovlen = out_spec[n].iovlen;
		msg.msg_flags = 0;
		// TODO send unsent
		// TODO LSQUIC_PREFERRED_ADDR
		// TODO cmsg, ecn
		// if server
		if (ace_udp_sendmsg(ce->fd, &msg, sendmsg) < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				eslog("sendmsg(%d %lu)", ce->fd, msg.msg_iovlen);
			}
			break;
		} else {
			// log("sendmsg(%d #%lu)", ce->fd, n);
		}
	} while (++n < out_limit);

	if (n > 0) {
		return n;
	}

	return -1;
}

void service_packets_in(struct connote *ce)
{
	int ecn = 0;
	ssize_t nread = 0;
	struct sockaddr_storage peer_sas;
	struct sockaddr_storage local_sas;
	// TODO buffer size
	unsigned char buf[0x1000] = { 0 };
	// struct connote *ce = (struct connote*)w->data;
	struct service *se = ce->service;

	struct iovec vec[1] = {{ buf, sizeof(buf) }};
	unsigned char ctl_buf[CTL_SZ];
	struct msghdr msg = {
		.msg_name       = &peer_sas,
		.msg_namelen    = sizeof(peer_sas),
		.msg_iov        = vec,
		.msg_iovlen     = 1,
		.msg_control    = ctl_buf,
		.msg_controllen = sizeof(ctl_buf),
		.msg_flags = 0,
	};
	nread = recvmsg(ce->fd, &msg, 0);
	// ylog("nread %ld", nread);
	if (-1 == nread) {
		if (!(EAGAIN == errno || EWOULDBLOCK == errno)) {
			hpeslog("recvmsg(%d)", ce->fd);
		}
		return;
	}
	// FIXME
	memcpy(&local_sas, &ce->local_addr, sizeof(local_sas));
	ecn = 0;

	ace_parse_ancillary(&msg, &local_sas, &ecn);

	int n = lsquic_engine_packet_in(
			ce->service->engine, buf, nread,
			(struct sockaddr*)&local_sas,
			(struct sockaddr*)&peer_sas,
			(void *)ce, ecn);
#if 0
	log("local_sas %s:%u", inet_ntoa(((struct sockaddr_in*)&local_sas)->sin_addr), ntohs(((struct sockaddr_in*)&local_sas)->sin_port));
	log("peer_sas %s:%u", inet_ntoa(((struct sockaddr_in*)&peer_sas)->sin_addr), ntohs(((struct sockaddr_in*)&peer_sas)->sin_port));
#endif
	switch (n) {
		case 0:
			se->process(*(struct ev_loop **)ce->service->loop, ce->service);
			break;
		case 1:
			blog();
			// FIXME
			se->process(*(struct ev_loop **)ce->service->loop, ce->service);
			break;
		case -1:
			elog("lsquic_engine_packet_in()");
			break;
		default:
			break;
	}
}
