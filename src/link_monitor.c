#include "link_monitor.h"
#include "define.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define LINK_MONITOR_MAX_IFS 64
#define LINK_MONITOR_BUF_LEN 32768

/* Per-interface tracked carrier state.  Indexed by a small fixed table —
 * enough for a host with a handful of NICs; more are simply ignored. */
struct link_state {
	int ifindex;
	int carrier; /* last observed carrier (0/1) */
	int seen;    /* first sighting already recorded */
};

struct link_monitor {
	struct ev_loop *loop;
	struct ev_io w;
	int fd;
	link_monitor_carrier_cb cb;
	void *user;
	struct link_state states[LINK_MONITOR_MAX_IFS];
	size_t n_states;
	unsigned char buf[LINK_MONITOR_BUF_LEN];
};

int link_monitor_parse(const struct nlmsghdr *nh, int len,
		       struct ace_link_event *out)
{
	const struct ifinfomsg *ifi;

	if (!nh || !out)
		return -1;
	if (len < (int)NLMSG_LENGTH(sizeof(struct ifinfomsg)))
		return -1;
	if (nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK)
		return -1;

	ifi = (const struct ifinfomsg *)NLMSG_DATA(nh);
	out->ifindex = ifi->ifi_index;
	out->flags = ifi->ifi_flags;
	out->deleted = (nh->nlmsg_type == RTM_DELLINK);
	if (!if_indextoname(ifi->ifi_index, out->ifname))
		out->ifname[0] = '\0';

	return 0;
}

static struct link_state *link_monitor_find(struct link_monitor *lm, int ifindex)
{
	for (size_t i = 0; i < lm->n_states; ++i) {
		if (lm->states[i].ifindex == ifindex)
			return &lm->states[i];
	}
	return NULL;
}

static struct link_state *link_monitor_remember(struct link_monitor *lm,
						int ifindex)
{
	struct link_state *st = link_monitor_find(lm, ifindex);

	if (st)
		return st;
	if (lm->n_states >= LINK_MONITOR_MAX_IFS)
		return NULL;

	st = &lm->states[lm->n_states++];
	st->ifindex = ifindex;
	st->carrier = 0;
	st->seen = 0;
	return st;
}

/* Snapshot the current link states at startup so a later transition on an
 * interface that was ALREADY up (e.g. lo before the client starts) is seen as
 * a flip, not a first sighting.  Runs before the fd is set non-blocking, so
 * the dump reads synchronously. */
static void link_monitor_dump(struct link_monitor *lm)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req;
	struct sockaddr_nl sa;
	struct iovec req_iov = { &req, sizeof(req) };
	struct msghdr req_msg;
	unsigned char buf[LINK_MONITOR_BUF_LEN];

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.ifm.ifi_family = AF_UNSPEC;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	req_msg = (struct msghdr){ &sa, sizeof(sa), &req_iov, 1, NULL, 0, 0 };

	if (sendmsg(lm->fd, &req_msg, 0) < 0) {
		eslog("link_monitor dump sendmsg(%d)", lm->fd);
		return;
	}

	for (;;) {
		struct iovec rcv_iov = { buf, sizeof(buf) };
		struct msghdr rcv_msg = { &sa, sizeof(sa), &rcv_iov, 1, NULL, 0, 0 };
		ssize_t n = recvmsg(lm->fd, &rcv_msg, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			eslog("link_monitor dump recvmsg(%d)", lm->fd);
			return;
		}
		if (n == 0)
			break;

		for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nh, (unsigned)n);
		     nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_type == NLMSG_DONE)
				return;
			if (nh->nlmsg_type == RTM_NEWLINK) {
				struct ace_link_event ev;
				struct link_state *st;

				if (link_monitor_parse(nh, (int)n, &ev) != 0)
					continue;
				st = link_monitor_remember(lm, ev.ifindex);
				if (!st || st->seen)
					continue;
				st->seen = 1;
				st->carrier = ace_link_carrier_up(&ev);
				log("link monitor: %s ifindex=%d carrier=%s",
				    ev.ifname[0] ? ev.ifname : "?",
				    ev.ifindex, st->carrier ? "up" : "down");
			}
		}
	}
}

static void link_monitor_read_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct link_monitor *lm = (struct link_monitor *)w->data;
	struct sockaddr_nl sa;
	struct iovec iov = { lm->buf, sizeof(lm->buf) };
	struct msghdr msg;
	ssize_t n;

	(void)loop;
	(void)revents;

	for (;;) {
		memset(&sa, 0, sizeof(sa));
		sa.nl_family = AF_NETLINK;
		msg = (struct msghdr){ &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

		n = recvmsg(lm->fd, &msg, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return;
			eslog("link_monitor recvmsg(%d)", lm->fd);
			return;
		}
		if (n == 0)
			return;

		for (struct nlmsghdr *nh = (struct nlmsghdr *)lm->buf;
		     NLMSG_OK(nh, (unsigned int)n);
		     nh = NLMSG_NEXT(nh, n)) {
			struct ace_link_event ev;
			struct link_state *st;
			int carrier;

			if (link_monitor_parse(nh, (int)n, &ev) != 0)
				continue;

			st = link_monitor_remember(lm, ev.ifindex);
			if (!st)
				continue;

			carrier = ev.deleted ? 0 : ace_link_carrier_up(&ev);

			if (!st->seen) {
				st->seen = 1;
				st->carrier = carrier;
				log("link monitor: %s ifindex=%d carrier=%s",
				    ev.ifname[0] ? ev.ifname : "?",
				    ev.ifindex, carrier ? "up" : "down");
				continue;
			}
			if (st->carrier == carrier)
				continue; /* no transition */

			st->carrier = carrier;
			if (lm->cb)
				lm->cb(ev.ifname[0] ? ev.ifname : "?",
				       carrier, lm->user);
		}
	}
}

struct link_monitor *link_monitor_init(struct ev_loop *loop,
				       link_monitor_carrier_cb cb, void *user)
{
	struct link_monitor *lm;
	struct sockaddr_nl local;
	int fd;
	int one = 1;
	int fl;

	if (!loop)
		return NULL;

	lm = calloc(1, sizeof(*lm));
	if (!lm)
		return NULL;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0) {
		eslog("link_monitor socket()");
		free(lm);
		return NULL;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		eslog("link_monitor bind(%d)", fd);
		close(fd);
		free(lm);
		return NULL;
	}

	/* Best-effort: extended ACK is not required for event delivery. */
	if (setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one)) < 0) {
		/* ignore */
	}

	lm->fd = fd;
	lm->loop = loop;
	lm->cb = cb;
	lm->user = user;

	/* Snapshot current link states BEFORE going non-blocking so the dump
	 * can read synchronously. */
	link_monitor_dump(lm);

	fl = fcntl(fd, F_GETFL);
	if (fl >= 0)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);

	ev_io_init(&lm->w, link_monitor_read_cb, fd, EV_READ);
	lm->w.data = lm;
	ev_io_start(loop, &lm->w);

	return lm;
}

void link_monitor_stop(struct link_monitor *lm)
{
	if (!lm)
		return;
	ev_io_stop(lm->loop, &lm->w);
	if (lm->fd >= 0)
		close(lm->fd);
	lm->fd = -1;
	free(lm);
}
