#include "quic_connection.h"
#include <sys/time.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* State transitions                                                   */
/* ------------------------------------------------------------------ */

void ace_conn_handshaking(struct ace_connection *conn)
{
	if (conn->state == ACE_CONN_CREATED) {
		conn->state = ACE_CONN_HANDSHAKING;
	}
}

void ace_conn_active(struct ace_connection *conn)
{
	if (conn->state == ACE_CONN_HANDSHAKING) {
		conn->state = ACE_CONN_ACTIVE;
		gettimeofday(&conn->active_at, NULL);
	}
}

void ace_conn_closing(struct ace_connection *conn)
{
	if (conn->state == ACE_CONN_ACTIVE) {
		conn->state = ACE_CONN_CLOSING;
	}
}

/* Normal close — transitions to CLOSED (not failed). */
void ace_conn_close(struct ace_connection *conn,
		    enum ace_conn_close_reason reason)
{
	if (conn->state == ACE_CONN_CLOSED || conn->state == ACE_CONN_FAILED)
		return;  /* already terminal */
	conn->state        = ACE_CONN_CLOSED;
	conn->close_reason = reason;
	gettimeofday(&conn->closed_at, NULL);
}

/* Abnormal close — transitions to FAILED. */
void ace_conn_fail(struct ace_connection *conn,
		   enum ace_conn_close_reason reason)
{
	if (conn->state == ACE_CONN_CLOSED || conn->state == ACE_CONN_FAILED)
		return;
	conn->state        = ACE_CONN_FAILED;
	conn->close_reason = reason;
	gettimeofday(&conn->closed_at, NULL);
}

/* ------------------------------------------------------------------ */
/* Bulk inspection                                                     */
/* ------------------------------------------------------------------ */

int ace_conn_has_failures(struct ace_connection *conn)
{
	return conn->state == ACE_CONN_FAILED;
}
