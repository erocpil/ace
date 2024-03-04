#ifndef __COMMON_H__
#define __COMMON_H__

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include "connote.h"
#include "service.h"
#include "ev.h"

// FIXME
#if 0
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#define ECN_SZ CMSG_SPACE(sizeof(int))
/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, sizeof(struct sockaddr_in6))) + ECN_SZ)
#endif


#endif
