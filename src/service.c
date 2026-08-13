#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include "service.h"
#include "task.h"
#include "io_retry.h"
#include "net_addr.h"
#include "quic_engine.h"

struct service *service_init(struct config *c)
{
	log();
	struct service *se = (struct service*)malloc(sizeof(struct service));
	if (!se) {
		eslog("malloc(se)");
		return NULL;
	}
	memset(se, 0, sizeof(*se));

	/* P3: initialise service-level memory budget */
	ace_mem_budget_init(&se->mem_budget, "service",
	                    ACE_MEM_DEFAULT_SERVICE_BUDGET, NULL);

	se->engine_settings = (struct lsquic_engine_settings*)
		malloc(sizeof(struct lsquic_engine_settings));
	if (!se->engine_settings) {
		eslog("malloc(engine_settings se %p)", se);
		free(se);
		return NULL;
	}
	se->engine_api = (struct lsquic_engine_api*)
		malloc(sizeof(struct lsquic_engine_api));
	if (!se->engine_api) {
		eslog("malloc(engine_api se %p)", se);
		free(se->engine_settings);
		free(se);
		return NULL;
	}

	/* stash service reference for callbacks */
	c->owner = se;
	memcpy(&se->config, c, sizeof(*c));

	if (0 != service_init_cert_hash(se)) {
		elog();
		free(se);
		return NULL;
	}

	INIT_LIST_HEAD(&se->service_node);
	INIT_LIST_HEAD(&se->connote_head);
	INIT_LIST_HEAD(&se->conn_head);

	return se;
}

void service_free(struct service *se)
{
	if (!se) {
		return;
	}
	if (se->engine_settings) {
		free(se->engine_settings);
	}
	if (se->engine_api) {
		free(se->engine_api);
	}
	if (se->cert_hash) {
		/* TODO free_func() */
		ace_hash_free(se->cert_hash, NULL);
	}
	if (se->tls) {
		tls_ctx_free(se->tls);
	}

	free(se);
}

/* TODO check path/file length */
/* TODO append alpn */
/* FIXME se->alpn */
static int session_resume_file_path(char *output, size_t output_size,
		const char *path, const struct sockaddr *peer, const char *device)
{
	char key[INET6_ADDRSTRLEN + 16];
	if (!path || ace_sockaddr_key(peer, key, sizeof(key)) != 0) return -1;
	return snprintf(output, output_size, "%s/%s-%s", path, key,
			device ? device : "") < (int)output_size ? 0 : -1;
}

int on_new_session(SSL *ssl, SSL_SESSION *session)
{
	unsigned char *buf;
	size_t bufsz, nw;
	FILE *file;

	/* https://lsquic.readthedocs.io/en/v3.1.1/tutorial.html#get-this-and-that-api
	 * The CID returned by lsquic_conn_id() is that used for logging: server
	 * and client should return the same CID. As noted earlier, you should not
	 * rely on this value to identify a connection! You can get a pointer to
	 * the connection from a stream and a pointer to the engine from a
	 * connection. Calling lsquic_conn_get_sockaddr() will point local and peer
	 * to the socket addressess of the current path. QUIC supports multiple
	 * paths during migration, but access to those paths has not been exposed
	 * via an API yet. This may change when or if QUIC adds true multipath
	 * support.
	 */
	struct lsquic_conn *lconn = lsquic_ssl_to_conn(ssl);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
	if(lconn_ctx->session_resume_saved) {
		return 0;
	}
	const struct sockaddr *local = NULL;
	const struct sockaddr *peer = NULL;
	int addr = lsquic_conn_get_sockaddr(lconn, &local, &peer);
	if (local && peer) {
		char local_text[80] = { 0 };
		char peer_text[80] = { 0 };
		if (ace_sockaddr_format(local, local_text, sizeof(local_text)) != 0 ||
				ace_sockaddr_format(peer, peer_text, sizeof(peer_text)) != 0) {
			return 0;
		}
		log("confirmed connection on net_dev " Yellow "%s " RESET
				"local " Cyan "%s " RESET
				"peer " Green "%s" RESET,
				lconn_ctx->ce->cc->if_name,
				local_text, peer_text);
	} else {
		elog();
		return 0;
	}

	char sess[512] = { 0 };
	const char *session_path = lconn_ctx->ce->service->config.session_path;
	if (mkdir(session_path, 0700) != 0 && errno != EEXIST) {
		eslog("cannot create session directory %s: %s",
				session_path, strerror(errno));
		return 0;
	}
	if (session_resume_file_path(sess, sizeof(sess),
			lconn_ctx->ce->service->config.session_path, peer,
			// lconn_ctx->ce->service->alpn,
			lconn_ctx->ce->cc->if_name) != 0) return 0;

	if (0 != lsquic_ssl_sess_to_resume_info(ssl, session, &buf, &bufsz)) {
		elog("lsquic_ssl_sess_to_resume_info failed");
		return 0;
	}

	file = fopen(sess, "wb");
	if (!file) {
		elog("cannot open %s for writing: %s", sess, strerror(errno));
		free(buf);
		return 0;
	}

	nw = fwrite(buf, 1, bufsz, file);
	if (nw == bufsz) {
		ylog("wrote %zd bytes of session resumption information to %s", nw, sess);
	} else {
		elog("error: fwrite(%s) returns %zd instead of %zd: %s",
				sess, nw, bufsz, strerror(errno));
	}

	fclose(file);
	free(buf);

	lconn_ctx->session_resume_saved = 1;

	return 0;
}

void service_add_connote(struct service *se, struct connote *ce)
{
	struct list_head *head = &se->connote_head;
	struct list_head *node = &ce->connote_node;
	list_add_tail(node, head);
	se->n_connote++;
	ce->service = se;
}

void service_del_connote(struct connote *ce)
{
	struct list_head *node = &ce->connote_node;
	list_del(node);
	ce->service->n_connote--;
	ce->service = NULL;
}

void *service_func(void *arg)
{
	log();
	struct service *se = (struct service*)arg;

	clog("pid %d tid %d thread %lu",
			getpid(), gettid(), pthread_self());
	set_affinity(se->config.cpu);

	se->run_result = 1;
	if (!service_init_engine(se)) {
		se->run_result = -1;
		elog("QUIC_EVENT service_start status=failed stage=engine");
		return NULL;
	}

	service_init_cert_hash(se);

	if (-1 == service_init_ssl_ctx_map(se)) {
		se->run_result = -1;
		elog("QUIC_EVENT service_start status=failed stage=tls");
		service_destroy_engine(se);
		return NULL;
	}

	int event_result = se->run_event(se);
	if (event_result != 0 || se->run_result < 0) {
		se->run_result = -1;
	} else {
		se->run_result = 0;
	}
	log("QUIC_EVENT service_stop status=%s",
			se->run_result == 0 ? "ok" : "failed");

	rlog("service %p destroyed", se);
	service_destroy_engine(se);

	/*
	 * P2: engine destroy may fire late conn_closed callbacks.
	 * Aggregate connection outcomes AFTER all callbacks complete.
	 */
	if (se->n_conn_failed > 0)
		se->run_result = -1;
	log("QUIC_EVENT service_final status=%s closed=%d failed=%d",
	    se->run_result == 0 ? "ok" : "failed",
	    se->n_conn_closed, se->n_conn_failed);

	return NULL;
}

ssize_t load_sess_resume_info(const char *name, unsigned char **info)
{
	log("tring to resume session from file \"%s\"", name);
	FILE *file = fopen(name, "rb");
	if (!file) {
		eslog("\"%s\"", name);
		log("use 1-RTT");
		return 0;
	}
	struct stat st;
	stat(name, &st);
	size_t length = st.st_size;
	*info = (unsigned char*)malloc(length);
	if (!*info) {
		elog("malloc() %d %s", errno, strerror(errno));
		fclose(file);
		return -1;
	}
	ssize_t n = fread(*info, 1, length, file);
	if (!n && !feof(file)) {
		elog("fread() %d %s", errno, strerror(errno));
		free(*info);
		*info = NULL;
	}
	fclose(file);

	return n;
}

struct lsquic_conn *service_connect_nop(struct connote *ce)
{
	struct service *se = ce->service;
	log("se %p ce %p", se, ce);

	char sess[512] = { 0 };
	if (session_resume_file_path(sess, sizeof(sess), ce->service->config.session_path,
			(const struct sockaddr*)&ce->sas,
			// lconn_ctx->ce->service->alpn,
			ce->cc->if_name) != 0) return NULL;

	unsigned char *resume_info = NULL;
	ssize_t resume_info_length =
		load_sess_resume_info(sess, &resume_info);
	if (resume_info_length <= 0) {
		resume_info_length = 0;
	}

	lsquic_conn_t *lconn = lsquic_engine_connect(
			se->engine, N_LSQVER,
			(struct sockaddr *)&ce->local_addr,
			(const struct sockaddr*)&ce->sas,
			(void*)(uintptr_t)ce,
			NULL, NULL, 0,
			resume_info_length ? resume_info : NULL, resume_info_length, /* resume */
			NULL, 0);
	free(resume_info);
	if (!lconn) {
		eslog("lsquic_engine_connect()");
		return NULL;
	} else {
		log("%p", lsquic_conn_get_ctx(lconn));
		log("lsquic_engine_connect()");
	}

	// se->process(se);

	return lconn;
}

struct lsquic_conn *service_connect(struct connote *ce)
{
	struct service *se = ce->service;
	log("se %p ce %p", se, ce);

	char sess[512] = { 0 };
	if (session_resume_file_path(sess, sizeof(sess), ce->service->config.session_path,
			(const struct sockaddr*)&ce->sas,
			// lconn_ctx->ce->service->alpn,
			ce->cc->if_name) != 0) return NULL;

	unsigned char *resume_info = NULL;
	ssize_t resume_info_length =
		load_sess_resume_info(sess, &resume_info);
	if (resume_info_length <= 0) {
		resume_info_length = 0;
	}

	lsquic_conn_t *lconn = lsquic_engine_connect(
			se->engine, N_LSQVER,
			(struct sockaddr *)&ce->local_addr,
			(const struct sockaddr*)&ce->sas,
			(void*)(uintptr_t)ce,
			NULL, NULL, 0,
			resume_info_length ? resume_info : NULL, resume_info_length, /* resume */
			NULL, 0);
	free(resume_info);
	if (!lconn) {
		eslog("lsquic_engine_connect()");
		return NULL;
	} else {
		log("%p", lsquic_conn_get_ctx(lconn));
		log("lsquic_engine_connect()");
	}

	se->process(*(struct ev_loop **)se->loop, se);

	return lconn;
}

ssize_t service_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	ssize_t n = service_rx_func(stream, sc);

	if (n > 0) {
		struct subtask *subtask = (struct subtask*)sc->subtask;
		ssize_t sr = subtask->rx_func(sc);
		// log("sr %ld", sr);
		if (likely(TASK_GOON == sr)) {
			;
		} else if (TASK_DONE == sr) {
			int r = subtask->done(sc);
			// log("r %d", r);
			if (TASK_DONE == r) {
				lsquic_stream_wantread(stream, 0);
				lsquic_stream_shutdown(stream, 0);
				ylog("stream %lu read done and shutdown read",
						lsquic_stream_id(sc->stream));
			} else if (TASK_EXIT == r) {
				lsquic_stream_close(stream);
				lsquic_conn_close(lsquic_stream_conn(stream));
				ylog("stream %lu read done and shutdown conn",
						lsquic_stream_id(sc->stream));
			} else if (TASK_FAIL == r) {
				ylog("abort conn %p due to task exit error",
						lsquic_stream_conn(stream));
				lsquic_stream_close(sc->stream);
				lsquic_conn_abort(lsquic_stream_conn(stream));
			} else {
				elog("Unknown value returned by subtask");
				lsquic_stream_close(stream);
				lsquic_conn_abort(lsquic_stream_conn(stream));
				return 0;
			}
		} else {
			elog("Unknown value returned by subtask");
			lsquic_stream_close(stream);
			lsquic_conn_abort(lsquic_stream_conn(stream));
			return 0;
		}
	} else if (!n) {
		blog("stream %ld read 0 and shutdown 0", lsquic_stream_id(stream));
		lsquic_stream_shutdown(stream, 0);
	} else {
		clog();
		if (ace_io_retryable(errno)) {
		} else {
		}
	}

	return 0;
}

ssize_t service_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	size_t id = lsquic_stream_id(sc->stream);
	// ylog("stream %p %lu writing subtask %p", stream, lsquic_stream_id(stream), sc->subtask);

	if (!id) {
		// SKB_DUMP(sc->tx);
	}
	ssize_t n = service_tx_func(stream, sc);
	if (n >= 0) {
		if (sc->tx->offset == sc->tx->len) {
			/* notify task that a skb is completely sent */
			struct subtask *subtask = (struct subtask*)sc->subtask;
			if (!subtask) {
				ylog("no subtask stream %p", stream);
				lsquic_stream_wantwrite(stream, 0);
				return 0;
			}
			if (!id) {
				// SKB_DUMP(sc->tx);
			}
			ssize_t sr = subtask->tx_func(sc);
			// SKB_DUMP(sc->tx);
			// rlog("id %lu sr %ld", id, sr);
			if (likely(TASK_GOON == sr)) {
				lsquic_stream_flush(sc->stream);
			} else if (TASK_DONE == sr) {
				int r = subtask->done(sc);
				if (TASK_DONE == r) {
					/* peer may not be unable to process streams if conn
					 * were shutdown here */
					lsquic_stream_wantwrite(stream, 0);
					lsquic_stream_shutdown(stream, 1);
					ylog("stream %lu write done and shutdown write", id);
				} else if (TASK_EXIT == r) {
					lsquic_stream_close(sc->stream);
					lsquic_conn_close(lsquic_stream_conn(stream));
					ylog("stream %lu write done and shutdown conn",
							lsquic_stream_id(sc->stream));
				} else if (TASK_FAIL == r) {
					ylog("abort conn %p due to task exit error",
							lsquic_stream_conn(stream));
					lsquic_stream_close(sc->stream);
					lsquic_conn_abort(lsquic_stream_conn(stream));
				} else {
					elog("Unknown value returned by subtask");
					lsquic_stream_close(stream);
					lsquic_conn_abort(lsquic_stream_conn(stream));
					return 0;
				}
			} else {
				elog("Unknown value returned by subtask");
				lsquic_stream_close(stream);
				lsquic_conn_abort(lsquic_stream_conn(stream));
				return 0;
			}
		}
#if 0
	} else if (!n) {
		blog();
		lsquic_stream_wantwrite(stream, 0);
#endif
	} else {
		clog();
		if (ace_io_retryable(errno)) {
		} else {
			eslog("lsquic_stream_write(%p %p), abort conn %p",
					stream, sc->tx->data + sc->tx->offset,
					lsquic_stream_conn(stream));
			lsquic_conn_abort(lsquic_stream_conn(stream));
		}
	}

	/* TODO if txq is empty */

	return 0;
}
