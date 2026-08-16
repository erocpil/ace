#define _GNU_SOURCE
#include <assert.h>
#include <string.h>

#include "link_monitor.h"

static void test_parse_newlink(void)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
	} msg;
	struct ace_link_event ev;

	memset(&msg, 0, sizeof(msg));
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	msg.nh.nlmsg_type = RTM_NEWLINK;
	msg.ifm.ifi_family = AF_UNSPEC;
	msg.ifm.ifi_type = 1; /* ARPHRD_ETHER */
	msg.ifm.ifi_index = 1; /* lo */
	msg.ifm.ifi_flags = IFF_UP | IFF_RUNNING | ACE_LINK_FLAG_LOWER_UP;
	msg.ifm.ifi_change = 0;

	assert(link_monitor_parse(&msg.nh, (int)msg.nh.nlmsg_len, &ev) == 0);
	assert(ev.ifindex == 1);
	assert(ev.deleted == 0);
	assert(ev.flags == (unsigned int)(IFF_UP | IFF_RUNNING | ACE_LINK_FLAG_LOWER_UP));
	assert(ace_link_carrier_up(&ev) == 1);
	assert(ev.ifname[0] != '\0'); /* if_indextoname(1) == "lo" */
}

static void test_parse_dellink(void)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifm;
	} msg;
	struct ace_link_event ev;

	memset(&msg, 0, sizeof(msg));
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	msg.nh.nlmsg_type = RTM_DELLINK;
	msg.ifm.ifi_family = AF_UNSPEC;
	msg.ifm.ifi_type = 1; /* ARPHRD_ETHER */
	msg.ifm.ifi_index = 2;
	msg.ifm.ifi_flags = 0;

	assert(link_monitor_parse(&msg.nh, (int)msg.nh.nlmsg_len, &ev) == 0);
	assert(ev.ifindex == 2);
	assert(ev.deleted == 1);
}

static void test_parse_skip_nonlink(void)
{
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifm;
	} msg;
	struct ace_link_event ev;

	memset(&msg, 0, sizeof(msg));
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	msg.nh.nlmsg_type = RTM_NEWADDR;

	assert(link_monitor_parse(&msg.nh, (int)msg.nh.nlmsg_len, &ev) == -1);
}

static void test_parse_short(void)
{
	struct nlmsghdr nh;
	struct ace_link_event ev;

	memset(&nh, 0, sizeof(nh));
	nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nh.nlmsg_type = RTM_NEWLINK;

	/* body shorter than the declared ifinfomsg */
	assert(link_monitor_parse(&nh,
				  (int)NLMSG_LENGTH(sizeof(struct ifinfomsg)) - 1,
				  &ev) == -1);
}

static void test_parse_null(void)
{
	struct nlmsghdr nh;
	struct ace_link_event ev;

	assert(link_monitor_parse(NULL, 0, &ev) == -1);
	memset(&nh, 0, sizeof(nh));
	assert(link_monitor_parse(&nh, (int)sizeof(nh), NULL) == -1);
}

static void test_carrier_combinations(void)
{
	struct ace_link_event ev;

	memset(&ev, 0, sizeof(ev));

	ev.flags = IFF_UP | IFF_RUNNING | ACE_LINK_FLAG_LOWER_UP;
	assert(ace_link_carrier_up(&ev) == 1);

	ev.flags = IFF_UP | IFF_RUNNING; /* L1 down */
	assert(ace_link_carrier_up(&ev) == 0);

	ev.flags = IFF_UP | ACE_LINK_FLAG_LOWER_UP; /* not running */
	assert(ace_link_carrier_up(&ev) == 0);

	ev.flags = IFF_RUNNING | ACE_LINK_FLAG_LOWER_UP; /* admin down */
	assert(ace_link_carrier_up(&ev) == 0);

	ev.flags = 0;
	assert(ace_link_carrier_up(&ev) == 0);
}

int main(void)
{
	test_parse_newlink();
	test_parse_dellink();
	test_parse_skip_nonlink();
	test_parse_short();
	test_parse_null();
	test_carrier_combinations();
	return 0;
}
