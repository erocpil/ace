#ifndef __DEVICE_H__
#define __DEVICE_H__

/* A network device */
struct device {
	char if_name[IFNAMSIZ];
	struct interface *interface;
	struct link *link;
};

#endif
