/*
 * quic_stream.c — QUIC stream lifecycle and I/O
 *
 * Extracted from service.c (P5 module boundary).
 * Stream context allocation/free, RX/TX queuing, lsquic I/O callbacks.
 */
#include "quic_stream.h"
#include "service.h"    /* for struct lsquic_conn_ctx, struct service */
#include "config.h"     /* for struct co_config, DEFAULT_*_ONCE, ACTION_* */
#include "define.h"     /* for log macros */
#include "io_retry.h"   /* for ace_io_retryable */

/* ── lifecycle ──────────────────────────────────────────────────── */

struct lsquic_stream_ctx *
service_stream_ctx_malloc(struct lsquic_conn_ctx *lc,
                          ssize_t rx_len, ssize_t tx_len)
{
	if (!lc || !lc->ce || !lc->ce->cc) {
		errno = EINVAL;
		return NULL;
	}

	/* P3: charge connection budget for the stream ctx itself */
	if (0 != ace_mem_charge(&lc->mem_budget,
	                        sizeof(struct lsquic_stream_ctx))) {
		eslog("stream_ctx charge failed (conn budget)");
		return NULL;
	}

	struct lsquic_stream_ctx *sc = lstream_ctx_malloc();
	if (!sc) {
		ace_mem_release(&lc->mem_budget,
		                sizeof(struct lsquic_stream_ctx));
		return NULL;
	}

	/* P3: wire stream budget under connection budget */
	ace_mem_budget_init(&sc->mem_budget, "stream",
	                    ACE_MEM_DEFAULT_STREAM_BUDGET,
	                    &lc->mem_budget);

	INIT_LIST_HEAD(&sc->stream_node);
	INIT_LIST_HEAD(&sc->rxq);
	INIT_LIST_HEAD(&sc->txq);

	sc->rx = skb_malloc_charged(&sc->mem_budget, rx_len);
	if (!sc->rx || !lstream_ctx_add_rxq(sc, sc->rx)) {
		skb_free(sc->rx);
		free(sc);
		ace_mem_release(&lc->mem_budget,
		                sizeof(struct lsquic_stream_ctx));
		return NULL;
	}
	sc->tx = skb_malloc_charged(&sc->mem_budget, tx_len);
	if (!sc->tx || !lstream_ctx_add_txq(sc, sc->tx)) {
		skb_free(sc->tx);
		lstream_ctx_del_rxq(sc, sc->rx);
		skb_free(sc->rx);
		free(sc);
		ace_mem_release(&lc->mem_budget,
		                sizeof(struct lsquic_stream_ctx));
		return NULL;
	}

	struct co_config *cc = lc->ce->cc;
	sc->rx_func = cc->rx_func;
	sc->tx_func = cc->tx_func;
	sc->new_action = cc->action & ACTION_MASK;
	sc->end_action = cc->action >> ACTION_SHIFT;

	return sc;
}

struct lsquic_stream_ctx *
service_stream_ctx_malloc_pending(struct lsquic_conn_ctx *lc,
                                  ssize_t rx_len, ssize_t tx_len)
{
	lc->pending = service_stream_ctx_malloc(lc, rx_len, tx_len);
	return lc->pending;
}

void service_stream_ctx_free(struct lsquic_stream_ctx *sc)
{
	if (!sc)
		return;

	struct sk_buff *skb, *n;

	list_for_each_entry_safe(skb, n, &sc->rxq, skb_node) {
		lstream_ctx_del_rxq(sc, skb);
		skb_free(skb);
	}
	sc->rx = NULL;

	list_for_each_entry_safe(skb, n, &sc->txq, skb_node) {
		lstream_ctx_del_txq(sc, skb);
		skb_free(skb);
	}
	sc->tx = NULL;

	/* Unlink from the connection's running/pending stream list, if linked.
	 * Stream 0 is never on a list; data streams are added in on_new_stream
	 * and would otherwise leave a dangling node behind after free. */
	if (!list_empty(&sc->stream_node))
		list_del_init(&sc->stream_node);

	/* P3: release stream ctx charge from connection budget */
	struct ace_mem_budget *conn_budget = sc->mem_budget.parent;

	free(sc);

	if (conn_budget) {
		ace_mem_release(conn_budget,
		                sizeof(struct lsquic_stream_ctx));
	}
}

/* ── low-level I/O (transport layer, no task knowledge) ─────────── */

ssize_t service_rx_func(struct lsquic_stream *stream,
                        lsquic_stream_ctx_t *sc)
{
	ssize_t n = 0;
	struct sk_buff *rx = sc->rx;

	/* use len to indicate how long has been received */
	size_t length = rx->end - rx->len;
	if (!length) {
		SKB_DUMP(rx);
		rlog("stream %p sc %p !length", stream, sc);
		lsquic_stream_wantread(stream, 0);
		return -1;
	}

	if (length > DEFAULT_RX_BUFF_ONCE)
		length = DEFAULT_RX_BUFF_ONCE;

	n = lsquic_stream_read(stream, rx->head + rx->len, length);
	if (n > 0) {
		void *tail = skb_put(rx, n);
		if (!tail) {
			SKB_DUMP(rx);
			rlog("TODO receive buffer full");
		}
		sc->rx_bytes += n;
		if (rx->len == rx->end)
			lsquic_stream_wantread(stream, 0);
	} else if (0 == n) {
		ylog("read 0");
	} else {
		if (ace_io_retryable(errno)) {
			;
		} else if (lsquic_stream_is_rejected(stream)) {
			ylog("lsquic_stream_is_rejected(%p)", stream);
			lsquic_stream_close(stream);
		} else {
			if (EBADF == errno)
				elog("EBADF");
			else if (ECONNRESET == errno)
				elog("ECONNRESET");
			else
				elog("unknown errno %d", errno);
			eslog("lsquic_stream_read(%p %p %ld)",
			      stream, rx->head + rx->len, length);
			lsquic_stream_close(stream);
		}
	}

	return n;
}

ssize_t service_tx_func(struct lsquic_stream *stream,
                        lsquic_stream_ctx_t *sc)
{
	if (!sc->n_txq) {
		elog("sc %p has nothing to send, close write", sc);
		lsquic_stream_wantwrite(stream, 0);
		return 0;
	}

	sc->tx = list_first_entry(&sc->txq, struct sk_buff, skb_node);
	struct sk_buff *tx = sc->tx;

	size_t length = tx->len - tx->offset;
	if (!length) {
		rlog();
		return 0;
	}

	if (length > DEFAULT_TX_BUFF_ONCE)
		length = DEFAULT_TX_BUFF_ONCE;

	if (tx->data != tx->head || tx->offset > tx->len) {
		errno = EPROTO;
		lsquic_stream_wantwrite(stream, 0);
		lsquic_conn_abort(lsquic_stream_conn(stream));
		return -1;
	}

	ssize_t n = lsquic_stream_write(stream,
	                                tx->data + tx->offset,
	                                length);
	if (n >= 0) {
		lsquic_stream_flush(stream);
		tx->offset += n;
		sc->tx_bytes += n;
		if (tx->offset > tx->len) {
			errno = EOVERFLOW;
			lsquic_conn_abort(lsquic_stream_conn(stream));
			return -1;
		}
	} else if (ace_io_retryable(errno)) {
		lsquic_stream_wantwrite(stream, 1);
	} else {
		lsquic_stream_wantwrite(stream, 0);
		lsquic_conn_abort(lsquic_stream_conn(stream));
	}

	return n;
}
