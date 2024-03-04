#ifndef __LINK_H__
#define __LINK_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include "define.h"

#define MAX_PAYLOAD 1024
#define MAX_RECV_BUF_LEN 32768
static char buf[MAX_RECV_BUF_LEN];

static inline int link_get_dev_index(const char *ifname)
{
	return if_nametoindex(ifname);
}

static int link_open_socket(unsigned int *nl_pid)
{
	struct sockaddr_nl local;
	socklen_t addrlen = 0;
	int sock = 0;
	int one = 1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;

	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0) {
		eslog("socket()");
		return sock;
	}

	if (setsockopt(sock, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one)) < 0) {
		eslog("setsockopt(%d)", sock);
	}

	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
		eslog("bind(%d)", sock);
		goto cleanup;
	}

	addrlen = sizeof(local);
	if (getsockname(sock, (struct sockaddr*)&local, &addrlen) < 0) {
		eslog("getsockname(%d)", sock);
		goto cleanup;
	}

	if (addrlen != sizeof(local)) {
		elog("address length not equal");
		errno = EPERM;
		goto cleanup;
	}

	*nl_pid = local.nl_pid;
	return sock;

cleanup:
	close(sock);
	return -1;
}

static int link_recv_status(int fd, unsigned nl_pid, unsigned int seq)
{
	int len = 0;
	int multipart = 1;
	struct nlmsgerr *err = NULL;
	struct nlmsghdr *nh = NULL;
	int up_and_running = 0;

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;
	/* PID is from getsockname(), it will be reset to 0 after recvmsg() */
	sa.nl_pid = nl_pid;

	struct iovec iov = {
		.iov_base = &buf,
		.iov_len = MAX_RECV_BUF_LEN
	};
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (multipart) {
		multipart = 0;
		len = recvmsg(fd, &msg, 0);
		if (len < 0) {
			eslog("recvmsg(%d)", fd);
			return -1;
		}

		if (!len) {
			break;
		}
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned int)len);
				nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_pid != nl_pid) {
				return -EPERM;
			}
			if (nh->nlmsg_seq != seq) {
				return -EPERM;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI) {
				multipart = 1;
			}
			char *ifUpp = (char*)"DOWN";
			char *ifRunn = (char*)"NOT RUNNING";
			struct ifinfomsg *ifi = (struct ifinfomsg*) NLMSG_DATA(nh);
			if (ifi->ifi_flags & IFF_UP) {
				ifUpp = (char*)"UP";
				up_and_running |= IFF_UP;
			}
			if (ifi->ifi_flags & IFF_RUNNING) {
				ifRunn = (char*)"RUNNING";
				up_and_running |= IFF_RUNNING;
			}
			char ifname[IF_NAMESIZE] = { 0 };
			if_indextoname(ifi->ifi_index, ifname);

			switch (nh->nlmsg_type) {
				case NLMSG_ERROR:
					log();
					err = (struct nlmsgerr *)NLMSG_DATA(nh);
					if (!err->error) {
						continue;
					}
					return err->error;
				case NLMSG_DONE:
					log("NLMSG_DONE");
					return 0;
				case RTM_DELADDR:
					log("RTM_DELADDR");
					break;
				case RTM_DELLINK:
					log("RTM_DELLINK");
					break;
				case RTM_NEWLINK: // 16
					log("RTM_NEWLINK %d %d \"%s\" %s %s",
							nh->nlmsg_type, ifi->ifi_index, ifname, ifUpp, ifRunn);
					break;
				case RTM_NEWADDR:
					log("RTM_NEWADDR");
					break;
				case RTM_GETLINK: // 18
					log("RTM_GETLINK");
					break;
				default:
					elog();
					break;
			}
		}
	}

	close(fd);

	return ((up_and_running == (IFF_UP | IFF_RUNNING)) ? 0 : -1);
}

static int link_get_link(int fd, int ifindex, unsigned nl_pid)
{
	unsigned int seq = time(NULL);

	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req;
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = seq;
	req.nlh.nlmsg_pid = getpid();
	req.ifm.ifi_family = AF_UNSPEC;
	req.ifm.ifi_index = ifindex;
	req.ifm.ifi_type = ARPHRD_ETHER;
	req.ifm.ifi_change = 0;

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;
	/* when query with sendmsg(), nl_pid must be 0 */
	sa.nl_pid = 0;

	struct iovec iov = { &req, req.nlh.nlmsg_len };
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

	if (sendmsg(fd, &msg, 0) < 0) {
		eslog("sendmsg(%d)", fd);
		return -1;
	}

	return link_recv_status(fd, nl_pid, seq);
}

static int link_get_status(const char *ifname)
{
	if (!ifname) {
		return -EPERM;
	}

	int ifindex = link_get_dev_index(ifname);
	if (!ifindex) {
		eslog("if_nametoindex(%s)", ifname);
		return -1;
	}

	unsigned int nl_pid = 0;
	int fd = link_open_socket(&nl_pid);
	if (fd < 0) {
		elog("link_open_socket() %d %s", errno, strerror(errno));
		return -errno;
	}

	return link_get_link(fd, ifindex, nl_pid);
}

#endif
