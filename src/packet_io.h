#ifndef __PACKET_IO_H__
#define __PACKET_IO_H__

#include <sys/socket.h>
#include "net_addr.h"
#include "udp_send.h"

struct connote;
struct service;
struct lsquic_out_spec;

/* UDP socket creation / configuration (server + client roles) */
int connote_init_server(struct connote *ce);
int connote_init_client(struct connote *ce);

/* lsquic packet I/O callbacks */
int service_packets_out(void *packets_out_ctx,
		const struct lsquic_out_spec *out_spec,
		unsigned int n_packets_out);
void service_packets_in(struct connote *ce);

#endif
