#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include "net_addr.h"

int main(void)
{
	char text[80];
	struct sockaddr_in sa4 = {.sin_family = AF_INET, .sin_port = htons(443)};
	assert(inet_pton(AF_INET, "127.0.0.1", &sa4.sin_addr) == 1);
	assert(ace_sockaddr_len((struct sockaddr *)&sa4) == sizeof(sa4));
	assert(ace_sockaddr_format((struct sockaddr *)&sa4, text, sizeof(text)) == 0);
	assert(strcmp(text, "127.0.0.1:443") == 0);

	struct sockaddr_in6 sa6 = {.sin6_family = AF_INET6, .sin6_port = htons(8443)};
	assert(inet_pton(AF_INET6, "::1", &sa6.sin6_addr) == 1);
	assert(ace_sockaddr_len((struct sockaddr *)&sa6) == sizeof(sa6));
	assert(ace_sockaddr_format((struct sockaddr *)&sa6, text, sizeof(text)) == 0);
	assert(strcmp(text, "[::1]:8443") == 0);
	assert(ace_sockaddr_key((struct sockaddr *)&sa6, text, sizeof(text)) == 0);
	assert(strcmp(text, "__1_8443") == 0);
	assert(ace_sockaddr_len(NULL) == 0);

	unsigned char control[CMSG_SPACE(sizeof(int))] = {0};
	struct msghdr msg = {.msg_control = control, .msg_controllen = sizeof(control)};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_TCLASS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cmsg) = 3;
	struct sockaddr_storage local = {0};
	int ecn = 0;
	ace_parse_ancillary(&msg, &local, &ecn);
	assert(ecn == 3);

#ifdef IP_PKTINFO
	unsigned char pkt_control[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0};
	msg.msg_control = pkt_control;
	msg.msg_controllen = sizeof(pkt_control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
	assert(inet_pton(AF_INET, "192.0.2.7", &pi->ipi_addr) == 1);
	memset(&local, 0, sizeof(local));
	ace_parse_ancillary(&msg, &local, &ecn);
	assert(((struct sockaddr_in *)&local)->sin_family == AF_INET);
	assert(((struct sockaddr_in *)&local)->sin_addr.s_addr == pi->ipi_addr.s_addr);
#endif
	return 0;
}
