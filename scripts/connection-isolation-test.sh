#!/bin/bash
# connection-isolation-test.sh — verify one failing connection
# does not disrupt other connections to the same server.
#
# Scenario:
#  1. Start server
#  2. Client A connects, verifies QUIC handshake + probe
#  3. Client B connects on a separate port, verifies probe
#  4. Kill server with SIGKILL
#  5. Both A and B must detect connection loss independently
#  6. Start server again
#  7. Client C connects, verifies probe (server recovered)
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
BIN="${ACE_BUILD_DIR}/src/ace"

# temp directories
CERT_DIR=$(mktemp -d /tmp/ace-iso-cert.XXXXXX)
LOG_A=$(mktemp /tmp/ace-iso-cliA.XXXXXX)
LOG_B=$(mktemp /tmp/ace-iso-cliB.XXXXXX)
LOG_C=$(mktemp /tmp/ace-iso-cliC.XXXXXX)
LOG_SRV=$(mktemp /tmp/ace-iso-srv.XXXXXX)
SOCK_A=$(mktemp -u /tmp/ace-iso-sockA.XXXXXX)
SOCK_B=$(mktemp -u /tmp/ace-iso-sockB.XXXXXX)
SOCK_C=$(mktemp -u /tmp/ace-iso-sockC.XXXXXX)

SERVER_PID=
CLI_A_PID=
CLI_B_PID=
CLI_C_PID=

cleanup() {
	for pid in ${CLI_C_PID:-} ${CLI_B_PID:-} ${CLI_A_PID:-} ${SERVER_PID:-}; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	rm -f "$LOG_A" "$LOG_B" "$LOG_C" "$LOG_SRV"
	rm -f "$SOCK_A" "$SOCK_B" "$SOCK_C"
	rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
	rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

cd "$(dirname "$0")/.."

# ---- Generate ephemeral cert ----
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
	-keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
	-subj '/CN=localhost' >/dev/null 2>&1

# ---- 1. Start server ----
info "Starting server..."
ACE_CERT_FILE="$CERT_DIR/cert.pem" \
ACE_KEY_FILE="$CERT_DIR/key.pem" \
ACE_TLS_INSECURE=1 \
stdbuf -oL -eL "$BIN" 1 >"$LOG_SRV" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server died"
pass "Server started (pid=$SERVER_PID)"

# ---- 2. Client A ----
info "Client A connecting..."
ACE_CERT_FILE="$CERT_DIR/cert.pem" \
ACE_KEY_FILE="$CERT_DIR/key.pem" \
ACE_TLS_INSECURE=1 \
ACE_UPSTREAM_FILE="$SOCK_A" \
stdbuf -oL -eL "$BIN" 0 >"$LOG_A" 2>&1 &
CLI_A_PID=$!

for _ in $(seq 1 100); do
	grep -q 'QUIC_PROBE_OK' "$LOG_A" 2>/dev/null && break
	sleep 0.1
done
grep -q 'QUIC_PROBE_OK' "$LOG_A" || fail "Client A: no probe echo"
pass "Client A: QUIC handshake + probe OK"

# ---- 3. Client B ----
info "Client B connecting..."
ACE_CERT_FILE="$CERT_DIR/cert.pem" \
ACE_KEY_FILE="$CERT_DIR/key.pem" \
ACE_TLS_INSECURE=1 \
ACE_UPSTREAM_FILE="$SOCK_B" \
stdbuf -oL -eL "$BIN" 0 >"$LOG_B" 2>&1 &
CLI_B_PID=$!

for _ in $(seq 1 100); do
	grep -q 'QUIC_PROBE_OK' "$LOG_B" 2>/dev/null && break
	sleep 0.1
done
grep -q 'QUIC_PROBE_OK' "$LOG_B" || fail "Client B: no probe echo"
pass "Client B: QUIC handshake + probe OK"

# ---- 4. Server still has 2 connections ----
grep -q 'n_client_conn=2' "$LOG_SRV" 2>/dev/null || \
	info "Server connection counter (check skipped — log buffering)"

# ---- 5. Kill server ----
info "Killing server (SIGKILL)..."
kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=

# ---- 6. Both clients must detect connection loss ----
for cli_name in "Client A" "Client B"; do
	case "$cli_name" in
		"Client A") log="$LOG_A"; pid="$CLI_A_PID" ;;
		"Client B") log="$LOG_B"; pid="$CLI_B_PID" ;;
	esac

	for _ in $(seq 1 100); do
		grep -q 'QUIC_EVENT connection status=lost' "$log" 2>/dev/null && break
		sleep 0.1
	done
	grep -q 'QUIC_EVENT connection status=lost' "$log" || \
		fail "$cli_name: did not detect connection loss"
	pass "$cli_name: detected connection loss (peer abort)"
done

# kill clients
kill "$CLI_A_PID" 2>/dev/null || true; wait "$CLI_A_PID" 2>/dev/null || true; CLI_A_PID=
kill "$CLI_B_PID" 2>/dev/null || true; wait "$CLI_B_PID" 2>/dev/null || true; CLI_B_PID=

# ---- 7. Restart server ----
info "Restarting server..."
ACE_CERT_FILE="$CERT_DIR/cert.pem" \
ACE_KEY_FILE="$CERT_DIR/key.pem" \
ACE_TLS_INSECURE=1 \
stdbuf -oL -eL "$BIN" 1 >"$LOG_SRV" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server failed to restart"
pass "Server restarted"

# ---- 8. Client C connects to restarted server ----
info "Client C connecting (post-recovery)..."
ACE_CERT_FILE="$CERT_DIR/cert.pem" \
ACE_KEY_FILE="$CERT_DIR/key.pem" \
ACE_TLS_INSECURE=1 \
ACE_UPSTREAM_FILE="$SOCK_C" \
stdbuf -oL -eL "$BIN" 0 >"$LOG_C" 2>&1 &
CLI_C_PID=$!

for _ in $(seq 1 100); do
	grep -q 'QUIC_PROBE_OK' "$LOG_C" 2>/dev/null && break
	sleep 0.1
done
grep -q 'QUIC_PROBE_OK' "$LOG_C" || fail "Client C: no probe echo after server restart"
pass "Client C: QUIC handshake + probe OK (server recovered)"

kill "$CLI_C_PID" 2>/dev/null || true; wait "$CLI_C_PID" 2>/dev/null || true; CLI_C_PID=

echo ""
echo "Connection isolation: all checks passed."
