#ifndef ACE_NET_ADDR_H
#define ACE_NET_ADDR_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static inline socklen_t ace_sockaddr_len(const struct sockaddr *sa)
{
	if (!sa) return 0;
	if (sa->sa_family == AF_INET) return sizeof(struct sockaddr_in);
	if (sa->sa_family == AF_INET6) return sizeof(struct sockaddr_in6);
	return 0;
}

static inline int ace_sockaddr_format(const struct sockaddr *sa,
		char *output, size_t size)
{
	char address[INET6_ADDRSTRLEN];
	unsigned port;
	if (!sa || !output || size == 0) return -1;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sa4 = (const struct sockaddr_in *)sa;
		if (!inet_ntop(AF_INET, &sa4->sin_addr, address, sizeof(address))) return -1;
		port = ntohs(sa4->sin_port);
		return snprintf(output, size, "%s:%u", address, port) < (int)size ? 0 : -1;
	}
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)sa;
		if (!inet_ntop(AF_INET6, &sa6->sin6_addr, address, sizeof(address))) return -1;
		port = ntohs(sa6->sin6_port);
		return snprintf(output, size, "[%s]:%u", address, port) < (int)size ? 0 : -1;
	}
	errno = EAFNOSUPPORT;
	return -1;
}

static inline int ace_sockaddr_key(const struct sockaddr *sa,
		char *output, size_t size)
{
	char address[INET6_ADDRSTRLEN];
	unsigned port;
	const void *source;
	if (!sa || !output || size == 0) return -1;
	if (sa->sa_family == AF_INET) {
		source = &((const struct sockaddr_in *)sa)->sin_addr;
		port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		source = &((const struct sockaddr_in6 *)sa)->sin6_addr;
		port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
	} else return -1;
	if (!inet_ntop(sa->sa_family, source, address, sizeof(address))) return -1;
	for (char *p = address; *p; ++p) if (*p == ':') *p = '_';
	return snprintf(output, size, "%s_%u", address, port) < (int)size ? 0 : -1;
}

static inline void ace_parse_ancillary(const struct msghdr *msg,
		struct sockaddr_storage *local, int *ecn)
{
	if (!msg || !local || !ecn) return;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR((struct msghdr *)msg);
			cmsg; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
#ifdef IP_ORIGDSTADDR
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_ORIGDSTADDR &&
				cmsg->cmsg_len >= CMSG_LEN(sizeof(struct sockaddr_in))) {
			memcpy(local, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
			continue;
		}
#endif
#ifdef IP_PKTINFO
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
				cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)local;
			const struct in_pktinfo *pi = (const struct in_pktinfo *)CMSG_DATA(cmsg);
			sa4->sin_family = AF_INET;
			sa4->sin_addr = pi->ipi_addr;
			continue;
		}
#endif
#ifdef IPV6_PKTINFO
		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
				cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)local;
			const struct in6_pktinfo *pi6 = (const struct in6_pktinfo *)CMSG_DATA(cmsg);
			sa6->sin6_family = AF_INET6;
			sa6->sin6_addr = pi6->ipi6_addr;
			continue;
		}
#endif
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
			*ecn = (*(const unsigned char *)CMSG_DATA(cmsg)) & 0x3;
		}
#ifdef IPV6_TCLASS
		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS) {
			*ecn = (*(const int *)CMSG_DATA(cmsg)) & 0x3;
		}
#endif
	}
}

#endif
