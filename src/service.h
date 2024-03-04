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

#define SE_RUNNING (1 << 0)
#define SE_STOPPED (1 << 1)

// FIXME
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#define ECN_SZ CMSG_SPACE(sizeof(int))
/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, sizeof(struct sockaddr_in6))) + ECN_SZ)

/* one service represents a type of connections driven by an identical lsquic engine,
 * aka. with same params, they all run in the same thread or process */
struct service {
	struct list_head service_node;
	struct lsquic_engine_settings *engine_settings;
	struct lsquic_engine_api *engine_api;
	struct lsquic_engine *engine;
	struct lsquic_stream_if *stream_if;
	lsquic_packets_out_f packets_out;
	SSL_CTX *ssl_ctx;
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

	void *loop;
	// size_t (*add_event)();
	int (*run_event)();
	void (*process)(struct service*);

	/* log */
	FILE *s_log_fh;
	struct lsquic_logger_if file_logger_if;

	// void *data;
	int state;

	struct config config;

	char alpn[256];
} __attribute__((aligned(sizeof(long))));

#define service_is_running(se) ((se)->state == SE_RUNNING)
#define service_is_stopped(se) ((se)->state == SE_STOPPED)
#define service_set_running(se) ((se)->state = SE_RUNNING)
#define service_set_stopped(se) ((se)->state = SE_STOPPED)

struct lsquic_stream_ctx {
	struct list_head stream_node;
	lsquic_stream_t *stream;
	void *subtask;
	uint32_t n_rxq;
	uint32_t n_txq;
	struct sk_buff *rx;
	struct sk_buff *tx;
	struct list_head rxq;
	struct list_head txq;
	ssize_t (*rx_func)(lsquic_stream_t*, lsquic_stream_ctx_t*);
	ssize_t (*tx_func)(lsquic_stream_t*, lsquic_stream_ctx_t*);
	size_t rx_bytes;
	size_t tx_bytes;
	unsigned short int new_action;
	unsigned short int end_action;
};

#define lstream_ctx_malloc() \
	({ \
	 size_t len = sizeof(struct lsquic_stream_ctx); \
	 void *r = malloc(len); \
	 memset(r, 0, len); \
	 })

static inline uint32_t lstream_ctx_add_rxq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	list_add_tail(&skb->skb_node, &sc->rxq);
	return ++sc->n_rxq;
}

static inline uint32_t lstream_ctx_del_rxq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	list_del(&skb->skb_node);
	return --sc->n_rxq;
}

static inline uint32_t lstream_ctx_add_txq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	list_add_tail(&skb->skb_node, &sc->txq);
	return ++sc->n_txq;
}

static inline uint32_t lstream_ctx_del_txq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	list_del(&skb->skb_node);
	return --sc->n_txq;
}

static inline struct sk_buff *lstream_ctx_del_rxq_first(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = list_first_entry_or_null(&sc->rxq, struct sk_buff, skb_node);
	lstream_ctx_del_rxq(sc, skb);
	sc->rx = NULL;

	return skb;
}

static inline struct sk_buff *lstream_ctx_del_txq_first(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = list_first_entry_or_null(&sc->txq, struct sk_buff, skb_node);
	lstream_ctx_del_txq(sc, skb);
	sc->tx = NULL;

	return skb;
}

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
};

#define lconn_ctx_malloc() \
	({ \
	 size_t len = sizeof(struct lsquic_conn_ctx); \
	 struct lsquic_conn_ctx *r = malloc(len); \
	 memset(r, 0, len); \
	 INIT_LIST_HEAD(&r->conn_node); \
	 INIT_LIST_HEAD(&r->running_stream_head); \
	 INIT_LIST_HEAD(&r->pending_stream_head); \
	 r; \
	 })

/* XXX */
#if 0
#define lconn_ctx_move_one_stream_ctx(lc) \
	do { \
		struct list_head *head = &(lc)->running_stream_head; \
		struct lsquic_stream_ctx *sc = \
		list_first_entry_or_null(&(lc)->running_stream_head, struct lsquic_stream_ctx, stream_node); \
		struct list_head *node = &(sc)->stream_node; \
		list_del(node); \
		(lc)->n_pending_stream--; \
		list_add_tail(node, head); \
		(lc)->n_running_stream++; \
	} while (0)
#endif

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

#define stream_is_cibi(s) (!(lsquic_stream_id(s) & 0x3))
#define stream_is_sibi(s) (!((lsquic_stream_id(s) & 0x3) ^ 0x01))
#define stream_is_ciun(s) (!((lsquic_stream_id(s) & 0x3) ^ 0x02))
#define stream_is_siun(s) (!((lsquic_stream_id(s) & 0x3) ^ 0x03))

struct service *service_init(struct config *config);
int service_packets_out(void *packets_out_ctx,
		const struct lsquic_out_spec *out_spec,
		unsigned int n_packets_out);
void service_packets_in(struct connote *ce);
void service_add_connote(struct service *se, struct connote *ce);
void service_del_connote(struct connote *ce);
void *service_func(void *arg);
int service_init_cert_hash(struct service *se);
struct lsquic_conn *service_connect(struct connote *ce);
struct lsquic_conn *service_connect_nop(struct connote *ce);
struct sk_buff *service_skb_malloc(ssize_t len);
void service_sk_buff(struct sk_buff *stb);
struct lsquic_stream_ctx *service_stream_ctx_malloc(struct co_config *cc,
		ssize_t rx_len, ssize_t tx_len);
struct lsquic_stream_ctx *service_stream_ctx_malloc_pending(struct lsquic_conn *lconn, ssize_t rx_len, ssize_t tx_len);
void service_stream_ctx_free(struct lsquic_stream_ctx *sc);
ssize_t service_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
ssize_t service_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);

#endif
