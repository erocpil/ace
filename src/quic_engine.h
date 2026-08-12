/*
 * quic_engine.h — lsquic engine assembly and lifecycle
 *
 * Extracted from service.c (P5 module boundary).
 * Owns the creation of the lsquic engine: settings population, engine API
 * callback wiring (TLS, packets-out, ALPN), and the SSL_CTX / SNI lookup
 * table that the engine consults.  Session-resumption save/load lives in
 * service.c (session layer) and is wired in via on_new_session().
 */
#ifndef ACE_QUIC_ENGINE_H
#define ACE_QUIC_ENGINE_H

struct service;

/*
 * Assemble engine settings + API and create the lsquic engine.
 * Reads se->config (flags, log_level, stream_if, packets_out) and the
 * TLS context built by the caller.  On success returns se (engine stored
 * in se->engine); on failure returns NULL.
 */
struct service *service_init_engine(struct service *se);

/*
 * Destroy the engine created by service_init_engine().  Idempotent:
 * safe to call with NULL se or a service whose engine was never created.
 */
void service_destroy_engine(struct service *se);

/*
 * Create the per-service SNI -> SSL_CTX lookup table (se->cert_hash).
 * Returns 0 on success, -1 on failure.
 */
int service_init_cert_hash(struct service *se);

/*
 * Register the service's SSL_CTX (se->ssl_ctx) in the cert hash so
 * service_lookup_cert() can resolve any SNI to it.  Called after the
 * engine and TLS context are built.  Returns 0 on success, -1 on failure.
 */
int service_init_ssl_ctx_map(struct service *se);

#endif /* ACE_QUIC_ENGINE_H */
