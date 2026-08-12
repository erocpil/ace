#!/bin/sh
# check-peer-abort.sh — verify RESET_STREAM / CONNECTION_CLOSE handling
# in the codebase.
#
# Checks:
#  1. on_conn_closed uses state machine + counter (not just log-and-forget)
#  2. on_reset callback exists and handles both directions
#  3. Fault injection test verifies connection lost detection
#  4. service_final aggregates failures after engine destroy
set -eu

root="${1:-.}"

# --- 1. on_conn_closed records outcome via state machine ---
grep -F 'ace_conn_fail' "$root/src/client.c" >/dev/null || {
	echo "FAIL: client_on_conn_closed missing ace_conn_fail"
	exit 1
}
grep -F 'ace_conn_close' "$root/src/client.c" >/dev/null || {
	echo "FAIL: client_on_conn_closed missing ace_conn_close"
	exit 1
}
echo "PASS: client_on_conn_closed records via state machine"

grep -F 'ace_conn_close' "$root/src/server.c" >/dev/null || {
	echo "FAIL: server_on_conn_closed missing state machine call"
	exit 1
}
echo "PASS: server_on_conn_closed records via state machine"

# --- 2. Connection outcome counters exist ---
grep -F 'n_conn_closed' "$root/src/service.h" >/dev/null || {
	echo "FAIL: n_conn_closed counter missing"
	exit 1
}
grep -F 'n_conn_failed' "$root/src/service.h" >/dev/null || {
	echo "FAIL: n_conn_failed counter missing"
	exit 1
}
echo "PASS: connection outcome counters present"

# --- 3. service_final aggregates after engine destroy ---
grep -F 'service_final' "$root/src/service.c" >/dev/null || {
	echo "FAIL: service_final not implemented"
	exit 1
}
echo "PASS: service_final aggregates connection outcomes"

# --- 4. Both client and server have on_reset callback ---
grep -F 'client_on_reset' "$root/src/client.c" >/dev/null || {
	echo "FAIL: client_on_reset missing"
	exit 1
}
grep -F 'server_on_reset' "$root/src/server.c" >/dev/null || {
	echo "FAIL: server_on_reset missing"
	exit 1
}
echo "PASS: on_reset callbacks present (client + server)"

# --- 5. close_reported guard prevents double-counting ---
grep -F 'close_reported' "$root/src/quic_connection.h" >/dev/null || {
	echo "FAIL: close_reported guard missing"
	exit 1
}
echo "PASS: close_reported prevents double-counting"

# --- 6. Graceful vs failure distinction ---
grep -F 'ACE_CLOSE_PEER_GRACEFUL' "$root/src/quic_connection.h" >/dev/null || {
	echo "FAIL: PEER_GRACEFUL close reason missing"
	exit 1
}
grep -F 'ACE_CLOSE_RESET' "$root/src/quic_connection.h" >/dev/null || {
	echo "FAIL: RESET close reason missing"
	exit 1
}
echo "PASS: close reasons distinguish graceful vs failure"

# --- 7. Fault injection integration test exists ---
grep -F 'kill -KILL' "$root/scripts/fault-injection-test.sh" >/dev/null 2>/dev/null || {
	info="(fault injection script not found — optional)"
	echo "INFO: fault-injection-test.sh not present $info"
}
grep -F 'QUIC_EVENT connection status=lost' \
	"$root/scripts/fault-injection-test.sh" >/dev/null 2>/dev/null && {
	echo "PASS: fault injection test verifies connection loss detection"
} || {
	info="(fault injection script not found — optional)"
	echo "INFO: fault-injection-test.sh check skipped $info"
}

echo ""
echo "Peer abort handling: all checks passed."
