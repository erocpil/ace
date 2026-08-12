#include "../src/quic_connection.h"
#include <assert.h>
#include <string.h>

int main(void)
{
	struct ace_connection conn;

	/* ---- 1. Initial state ---- */
	ace_conn_init(&conn);
	assert(conn.state == ACE_CONN_CREATED);
	assert(conn.close_reason == ACE_CLOSE_NONE);
	assert(conn.task_complete == 0);
	assert(conn.close_reported == 0);
	assert(conn.created_at.tv_sec > 0);

	/* ---- 2. CREATED → HANDSHAKING ---- */
	ace_conn_handshaking(&conn);
	assert(conn.state == ACE_CONN_HANDSHAKING);

	/* idempotent */
	ace_conn_handshaking(&conn);
	assert(conn.state == ACE_CONN_HANDSHAKING);

	/* ---- 3. HANDSHAKING → ACTIVE ---- */
	ace_conn_active(&conn);
	assert(conn.state == ACE_CONN_ACTIVE);
	assert(conn.active_at.tv_sec > 0);

	/* wrong-direction guard: ACTIVE should not become HANDSHAKING */
	ace_conn_handshaking(&conn);
	assert(conn.state == ACE_CONN_ACTIVE);

	/* ---- 4. ACTIVE → CLOSING (optional drain phase) ---- */
	ace_conn_closing(&conn);
	assert(conn.state == ACE_CONN_CLOSING);

	/* ---- 5. Normal close → CLOSED ---- */
	ace_conn_close(&conn, ACE_CLOSE_USER_REQUEST);
	assert(conn.state == ACE_CONN_CLOSED);
	assert(conn.close_reason == ACE_CLOSE_USER_REQUEST);
	assert(conn.closed_at.tv_sec > 0);

	/* terminal: cannot transition out of CLOSED */
	ace_conn_fail(&conn, ACE_CLOSE_RESET);
	assert(conn.state == ACE_CONN_CLOSED);
	assert(conn.close_reason == ACE_CLOSE_USER_REQUEST);  /* unchanged */

	/* ---- 6. Abnormal close → FAILED (fresh connection) ---- */
	ace_conn_init(&conn);
	ace_conn_handshaking(&conn);
	ace_conn_fail(&conn, ACE_CLOSE_TLS_FAILURE);
	assert(conn.state == ACE_CONN_FAILED);
	assert(conn.close_reason == ACE_CLOSE_TLS_FAILURE);

	/* terminal again */
	ace_conn_close(&conn, ACE_CLOSE_USER_REQUEST);
	assert(conn.state == ACE_CONN_FAILED);

	/* ---- 7. ace_conn_has_failures ---- */
	assert(ace_conn_has_failures(&conn) == 1);

	ace_conn_init(&conn);
	ace_conn_handshaking(&conn);
	ace_conn_active(&conn);
	ace_conn_close(&conn, ACE_CLOSE_PEER_GRACEFUL);
	assert(ace_conn_has_failures(&conn) == 0);

	/* ---- 8. State string helpers ---- */
	assert(strcmp(ace_conn_state_str(ACE_CONN_CREATED), "CREATED") == 0);
	assert(strcmp(ace_conn_state_str(ACE_CONN_ACTIVE), "ACTIVE") == 0);
	assert(strcmp(ace_conn_state_str(ACE_CONN_FAILED), "FAILED") == 0);
	assert(strcmp(ace_conn_state_str(99), "UNKNOWN") == 0);

	assert(strcmp(ace_conn_close_reason_str(ACE_CLOSE_NONE), "none") == 0);
	assert(strcmp(ace_conn_close_reason_str(ACE_CLOSE_TLS_FAILURE), "tls_failure") == 0);
	assert(strcmp(ace_conn_close_reason_str(99), "unknown") == 0);

	return 0;
}
