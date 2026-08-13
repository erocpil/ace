#ifndef __SERVICE_H__
#define __SERVICE_H__

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "lsquic.h"
#include "connote.h"
#include "config.h"
#include "sk_buff.h"
#include "list.h"
#include "hash.h"
#include "resource_limits.h"

#define SE_RUNNING (1 << 0)
#define SE_STOPPED (1 << 1)

// FIXME
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#define ECN_SZ CMSG_SPACE(sizeof(int))
/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, sizeof(struct sockaddr_in6))) + ECN_SZ)

#include "tls_context.h"
#include "quic_connection.h"
#include "quic_stream.h"
#include "mem_budget.h"

struct ev_loop;

/* one service represents a type of connections driven by an identical lsquic engine,
 * aka. with same params, they all run in the same thread or process */
struct tls_ctx;

struct service {
	struct list_head service_node;
	struct lsquic_engine_settings *engine_settings;
	struct lsquic_engine_api *engine_api;
	struct lsquic_engine *engine;
	struct lsquic_stream_if *stream_if;
	lsquic_packets_out_f packets_out;
	SSL_CTX *ssl_ctx;
	struct tls_ctx *tls;
	struct ace_hash *cert_hash;

	volatile size_t rx_bytes;
	volatile size_t tx_bytes;

	// struct list_head mass_head;
	// all ports listened locally
	struct list_head connote_head;
	size_t n_connote;
	// all conn established by clients
	volatile size_t n_client_conn;
	struct list_head conn_head;

	/* P2: connection outcome counters (aggregated after engine destroy) */
	int n_conn_closed;
	int n_conn_failed;

	/* P3: memory budget for this service */
	struct ace_mem_budget mem_budget;

	void *loop;
	// size_t (*add_event)();
	int (*run_event)(struct service *);
	void (*process)(struct ev_loop *, struct service*);
	void (*stop_event)(struct service *);
	pthread_t thread;
	int thread_started;
	int run_result;

	/* log */
	FILE *s_log_fh;
	struct lsquic_logger_if file_logger_if;

	// void *data;
	int state;
	int processing;
	int process_pending;

	struct config config;

	char alpn[256];
} __attribute__((aligned(sizeof(long))));

#define service_is_running(se) ((se)->state == SE_RUNNING)
#define service_is_stopped(se) ((se)->state == SE_STOPPED)
#define service_set_running(se) ((se)->state = SE_RUNNING)
#define service_set_stopped(se) ((se)->state = SE_STOPPED)

struct lsquic_conn_ctx {
	struct list_head conn_node;
	struct list_head pending_stream_head;
	struct list_head running_stream_head;
	size_t n_pending_sc;
	size_t n_running_sc;
	struct lsquic_stream *s0;
	/* which ce this conn origin from */
	struct connote *ce;
	lsquic_conn_t *lconn;
	/* internal data from application */
	void *internal;
	void *task;

	volatile size_t rx_bytes;
	volatile size_t tx_bytes;

	/* before conn was established, make several stream
	 * at one time may cause on_new_stream() miss sc */
	struct lsquic_stream_ctx *pending;

	FILE *keylog_file;
	char *session_file;
	int session_resume_saved;

	struct ace_connection conn;  /* P2: connection state machine */

	/* P3: per-connection memory budget (parent = service budget) */
	struct ace_mem_budget mem_budget;
};

static inline struct lsquic_conn_ctx *lconn_ctx_malloc(struct service *se)
{
	struct lsquic_conn_ctx *r = calloc(1, sizeof(*r));
	if (!r) {
		return NULL;
	}
	INIT_LIST_HEAD(&r->conn_node);
	INIT_LIST_HEAD(&r->running_stream_head);
	INIT_LIST_HEAD(&r->pending_stream_head);
	ace_conn_init(&r->conn);

	/* P3: wire connection budget under service budget */
	ace_mem_budget_init(&r->mem_budget, "conn",
	                    ACE_MEM_DEFAULT_CONN_BUDGET,
	                    &se->mem_budget);

	return r;
}

#define lconn_ctx_add_running_stream_ctx(lc, sc) \
	do { \
		struct list_head *head = &(lc)->running_stream_head; \
		struct list_head *node = &(sc)->stream_node; \
		list_add_tail(node, head); \
		(lc)->n_running_sc++; \
	} while (0)

#define lconn_ctx_del_running_stream_ctx(lc) ({ \
		struct lsquic_stream_ctx *sc = \
		list_first_entry_or_null(&(lc)->running_stream_head, struct lsquic_stream_ctx, stream_node); \
		if (sc) { \
		list_del(&sc->stream_node); \
		(lc)->n_running_sc--; \
		} \
		sc; \
		})

#define lconn_ctx_add_pending_stream_ctx(lc, sc) \
	do { \
		struct list_head *head = &(lc)->pending_stream_head; \
		struct list_head *node = &(sc)->stream_node; \
		list_add_tail(node, head); \
		(lc)->n_pending_sc++; \
	} while (0)

#define lconn_ctx_del_pending_stream_ctx(lc) ({ \
		struct lsquic_stream_ctx *sc = \
		list_first_entry_or_null(&(lc)->pending_stream_head, struct lsquic_stream_ctx, stream_node); \
		if (sc) { \
		list_del(&sc->stream_node); \
		(lc)->n_pending_sc--; \
		} \
		sc; \
		})

#define lconn_ctx_dump(cc) \
	do { \
		struct lsquic_conn_ctx *_cc = (cc); \
		log("lconn_ctx %p"); \
		log("  ce %p", _cc->ce); \
		log("  lconn %p", _cc->lconn); \
		log("  rx_bytes %lu", _cc->rx_bytes); \
		log("  tx_bytes %lu", _cc->tx_bytes); \
		log("  pending %p", _cc->pending); \
		log("  keylog_file %p", _cc->keylog_file); \
	} while (0)

static size_t service_add_client_conn(struct service *se, struct lsquic_conn_ctx *lconn_ctx)
{
	struct list_head *head = &se->conn_head;
	struct list_head *node = &lconn_ctx->conn_node;
	list_add_tail(node, head);
	se->n_client_conn++;
	return se->n_client_conn;
}

static size_t service_del_client_conn(struct service *se, struct lsquic_conn_ctx *lconn_ctx)
{
	struct list_head *node = &lconn_ctx->conn_node;
	list_del(node);
	se->n_client_conn--;
	return se->n_client_conn;
}

struct service *service_init(struct config *config);
void service_add_connote(struct service *se, struct connote *ce);
void service_del_connote(struct connote *ce);
void *service_func(void *arg);
struct lsquic_conn *service_connect(struct connote *ce);
struct lsquic_conn *service_connect_nop(struct connote *ce);
struct sk_buff *service_skb_malloc(ssize_t len);
void service_sk_buff(struct sk_buff *stb);

#endif
