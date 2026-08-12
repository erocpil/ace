/*
 * quic_stream.h — QUIC stream context and queue management
 *
 * Extracted from service.h (P5 module boundary).
 * The lsquic_stream_ctx is ACE's per-stream object — one per QUIC stream.
 * It owns RX/TX sk_buff queues and tracks bytes, callbacks, and budget.
 */
#ifndef ACE_QUIC_STREAM_H
#define ACE_QUIC_STREAM_H

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include "lsquic.h"
#include "sk_buff.h"
#include "list.h"
#include "resource_limits.h"
#include "mem_budget.h"

/* --- constants --- */

#define ACE_STREAM_DEFAULT_RX_BUFF_ONCE   (1024U)

/* stream direction helpers (RFC 9000 §2.1) */
#define stream_is_cibi(s)  (!(lsquic_stream_id(s) & 0x3))
#define stream_is_sibi(s)  (!((lsquic_stream_id(s) & 0x3) ^ 0x01))
#define stream_is_ciun(s)  (!((lsquic_stream_id(s) & 0x3) ^ 0x02))
#define stream_is_siun(s)  (!((lsquic_stream_id(s) & 0x3) ^ 0x03))

/* --- stream context --- */

struct lsquic_stream_ctx {
	struct list_head stream_node;
	lsquic_stream_t *stream;
	void            *subtask;
	uint32_t         n_rxq;
	uint32_t         n_txq;
	struct sk_buff  *rx;
	struct sk_buff  *tx;
	struct list_head rxq;
	struct list_head txq;
	ssize_t (*rx_func)(lsquic_stream_t*, lsquic_stream_ctx_t*);
	ssize_t (*tx_func)(lsquic_stream_t*, lsquic_stream_ctx_t*);
	size_t           rx_bytes;
	size_t           tx_bytes;
	unsigned short   new_action;
	unsigned short   end_action;

	/* P3: per-stream memory budget (parent = connection budget) */
	struct ace_mem_budget mem_budget;
};

/* --- inline helpers (lightweight, called on hot path) --- */

static inline struct lsquic_stream_ctx *lstream_ctx_malloc(void)
{
	return calloc(1, sizeof(struct lsquic_stream_ctx));
}

static inline uint32_t
lstream_ctx_add_rxq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	if (!sc || !skb || !ace_quota_can_add(sc->n_rxq, ACE_MAX_STREAM_QUEUE)) {
		errno = ENOBUFS;
		return 0;
	}
	list_add_tail(&skb->skb_node, &sc->rxq);
	return ++sc->n_rxq;
}

static inline uint32_t
lstream_ctx_del_rxq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	if (!sc || !skb || sc->n_rxq == 0)
		return 0;
	list_del(&skb->skb_node);
	return --sc->n_rxq;
}

static inline uint32_t
lstream_ctx_add_txq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	if (!sc || !skb || !ace_quota_can_add(sc->n_txq, ACE_MAX_STREAM_QUEUE)) {
		errno = ENOBUFS;
		return 0;
	}
	list_add_tail(&skb->skb_node, &sc->txq);
	return ++sc->n_txq;
}

static inline uint32_t
lstream_ctx_del_txq(struct lsquic_stream_ctx *sc, struct sk_buff *skb)
{
	if (!sc || !skb || sc->n_txq == 0)
		return 0;
	list_del(&skb->skb_node);
	return --sc->n_txq;
}

static inline struct sk_buff *
lstream_ctx_del_rxq_first(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = list_first_entry_or_null(
		&sc->rxq, struct sk_buff, skb_node);
	if (!skb)
		return NULL;
	lstream_ctx_del_rxq(sc, skb);
	sc->rx = NULL;
	return skb;
}

static inline struct sk_buff *
lstream_ctx_del_txq_first(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = list_first_entry_or_null(
		&sc->txq, struct sk_buff, skb_node);
	if (!skb)
		return NULL;
	lstream_ctx_del_txq(sc, skb);
	sc->tx = NULL;
	return skb;
}

/* --- public API --- */

struct lsquic_conn_ctx;
struct co_config;

struct lsquic_stream_ctx *
service_stream_ctx_malloc(struct lsquic_conn_ctx *lc,
                          ssize_t rx_len, ssize_t tx_len);
struct lsquic_stream_ctx *
service_stream_ctx_malloc_pending(struct lsquic_conn_ctx *lc,
                                  ssize_t rx_len, ssize_t tx_len);
void service_stream_ctx_free(struct lsquic_stream_ctx *sc);

ssize_t service_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
ssize_t service_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);

/* internal: low-level stream I/O (called from service_on_read/write) */
ssize_t service_rx_func(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
ssize_t service_tx_func(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);

#endif /* ACE_QUIC_STREAM_H */
