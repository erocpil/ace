#ifndef ACE_LINK_MONITOR_H
#define ACE_LINK_MONITOR_H

/*
 * link_monitor — continuous link/carrier monitoring via netlink.
 *
 * This is the "Device / Network State" layer's first real piece.  It
 * subscribes to RTMGRP_LINK on a non-blocking NETLINK_ROUTE socket, watches
 * it on a libev loop, and reports carrier transitions (interface gained /
 * lost physical link) through a callback.
 *
 * It does NOT (yet) drive connection teardown or path switching — that is a
 * later phase.  The callback is the single seam where that wiring will land.
 *
 * Contrast with link.h: link.h is a one-shot RTM_GETLINK query used by the
 * client's bindtodevice path; this module is a persistent event subscription
 * with a per-interface carrier state machine.
 */

#include <net/if.h>
#include <linux/rtnetlink.h>
#include "ev.h"

/* IFF_LOWER_UP is Linux-specific (L1 link up, 1<<16) and lives in
 * <linux/if.h>, whose IFF_* enum collides with <net/if.h>'s #defines.
 * Use a local constant instead of the symbol so neither header has to be
 * included after the other. */
#define ACE_LINK_FLAG_LOWER_UP 0x10000u

/* One decoded link event from a RTM_NEWLINK / RTM_DELLINK message. */
struct ace_link_event {
	int ifindex;
	char ifname[IFNAMSIZ];
	unsigned int flags;   /* ifi_flags (IFF_UP / IFF_RUNNING / LOWER_UP) */
	int deleted;          /* 1 for RTM_DELLINK */
};

/* carrier = administratively up AND running AND L1 link up. */
static inline int ace_link_carrier_up(const struct ace_link_event *ev)
{
	return (ev->flags & IFF_UP) && (ev->flags & IFF_RUNNING) &&
	       (ev->flags & ACE_LINK_FLAG_LOWER_UP);
}

/* Decode one netlink message.  Returns 0 and fills @out when @nh is a
 * RTM_NEWLINK / RTM_DELLINK message with a well-formed ifinfomsg body;
 * returns -1 (skip) for any other type or a short message.  Pure: no I/O,
 * no global state. */
int link_monitor_parse(const struct nlmsghdr *nh, int len,
		       struct ace_link_event *out);

/* Fired on a carrier transition.  @up is 1 when the interface gained
 * carrier, 0 when it lost it.  NOT fired for an interface's first sighting. */
typedef void (*link_monitor_carrier_cb)(const char *ifname, int up, void *user);

struct link_monitor;

/* Subscribe to RTMGRP_LINK and watch it on @loop.  Returns NULL on failure
 * (socket/bind error).  @cb may be NULL (transitions are still tracked). */
struct link_monitor *link_monitor_init(struct ev_loop *loop,
				       link_monitor_carrier_cb cb, void *user);

/* Stop the watcher, close the socket, free the monitor.  Idempotent. */
void link_monitor_stop(struct link_monitor *lm);

#endif /* ACE_LINK_MONITOR_H */
