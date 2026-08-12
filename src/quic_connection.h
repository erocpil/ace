#ifndef __QUIC_CONNECTION_H__
#define __QUIC_CONNECTION_H__

#include <sys/time.h>
#include <stddef.h>

/*
 * ACE connection state machine (P2).
 *
 * States track the QUIC lifecycle; close_reason records why a connection
 * ended, independently of the final service run_result.  This decouples
 * late engine-destroy callbacks from the service-level outcome so that
 * run_result is only computed after ALL connection callbacks have fired.
 *
 * Embed this struct inside lsquic_conn_ctx — no separate allocation.
 */

/* ------------------------------------------------------------------ */
/* Connection state                                                    */
/* ------------------------------------------------------------------ */

enum ace_conn_state {
	ACE_CONN_CREATED     = 0,  /* lconn_ctx allocated, not yet connecting */
	ACE_CONN_HANDSHAKING = 1,  /* on_new_conn fired, TLS in progress      */
	ACE_CONN_ACTIVE      = 2,  /* handshake succeeded                     */
	ACE_CONN_CLOSING     = 3,  /* draining / GOAWAY sent or received       */
	ACE_CONN_CLOSED      = 4,  /* normal close, no error                   */
	ACE_CONN_FAILED      = 5,  /* abnormal close / error                   */
};

/* ------------------------------------------------------------------ */
/* Close reason                                                        */
/* ------------------------------------------------------------------ */

enum ace_conn_close_reason {
	ACE_CLOSE_NONE            = 0,
	ACE_CLOSE_USER_REQUEST    = 1,  /* application requested close          */
	ACE_CLOSE_PEER_GRACEFUL   = 2,  /* peer sent CONNECTION_CLOSE no error  */
	ACE_CLOSE_IDLE_TIMEOUT    = 3,  /* idle timeout                          */
	ACE_CLOSE_NO_PROGRESS     = 4,  /* no progress timeout                   */
	ACE_CLOSE_RESET           = 5,  /* peer sent unexpected RESET / loss     */
	ACE_CLOSE_TLS_FAILURE     = 6,  /* handshake failed                      */
	ACE_CLOSE_TRANSPORT_ERROR = 7,  /* transport-level error                 */
	ACE_CLOSE_RESOURCE_LIMIT  = 8,  /* memory / fd exhaustion                */
	ACE_CLOSE_INTERNAL_ERROR  = 9,  /* logic error / assertion               */
};

/* ------------------------------------------------------------------ */
/* Connection tracking struct                                          */
/* ------------------------------------------------------------------ */

struct ace_connection {
	enum ace_conn_state        state;
	enum ace_conn_close_reason close_reason;

	struct timeval created_at;
	struct timeval active_at;   /* when state became ACTIVE   */
	struct timeval closed_at;   /* when state became CLOSED / FAILED */

	/* Flags */
	unsigned int task_complete  : 1;
	unsigned int close_reported : 1;   /* already counted in n_conn_closed / n_conn_failed */
};

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

static inline void ace_conn_init(struct ace_connection *conn)
{
	conn->state         = ACE_CONN_CREATED;
	conn->close_reason  = ACE_CLOSE_NONE;
	conn->task_complete = 0;
	conn->close_reported = 0;
	gettimeofday(&conn->created_at, NULL);
}

void ace_conn_handshaking(struct ace_connection *conn);
void ace_conn_active(struct ace_connection *conn);
void ace_conn_closing(struct ace_connection *conn);
void ace_conn_close(struct ace_connection *conn,
		    enum ace_conn_close_reason reason);
void ace_conn_fail(struct ace_connection *conn,
		   enum ace_conn_close_reason reason);

/* Bulk close-reason inspection (called by service_func after engine destroy). */
int  ace_conn_has_failures(struct ace_connection *conn);

static inline const char *ace_conn_state_str(enum ace_conn_state s)
{
	switch (s) {
	case ACE_CONN_CREATED:     return "CREATED";
	case ACE_CONN_HANDSHAKING: return "HANDSHAKING";
	case ACE_CONN_ACTIVE:      return "ACTIVE";
	case ACE_CONN_CLOSING:     return "CLOSING";
	case ACE_CONN_CLOSED:      return "CLOSED";
	case ACE_CONN_FAILED:      return "FAILED";
	default:                   return "UNKNOWN";
	}
}

static inline const char *ace_conn_close_reason_str(enum ace_conn_close_reason r)
{
	switch (r) {
	case ACE_CLOSE_NONE:            return "none";
	case ACE_CLOSE_USER_REQUEST:    return "user_request";
	case ACE_CLOSE_PEER_GRACEFUL:   return "peer_graceful";
	case ACE_CLOSE_IDLE_TIMEOUT:    return "idle_timeout";
	case ACE_CLOSE_NO_PROGRESS:     return "no_progress";
	case ACE_CLOSE_RESET:           return "reset";
	case ACE_CLOSE_TLS_FAILURE:     return "tls_failure";
	case ACE_CLOSE_TRANSPORT_ERROR: return "transport_error";
	case ACE_CLOSE_RESOURCE_LIMIT:  return "resource_limit";
	case ACE_CLOSE_INTERNAL_ERROR:  return "internal_error";
	default:                        return "unknown";
	}
}

#endif /* __QUIC_CONNECTION_H__ */
