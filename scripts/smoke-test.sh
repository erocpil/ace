#!/bin/bash
# smoke-test.sh — minimal ACE server + client smoke test (handshake + probe + shutdown)
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { TEST_FAILED=1; printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }
TEST_FAILED=0

cleanup() {
    info "Cleaning up..."
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "${CLIENT_PID:-}" ]; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
	if [ "$TEST_FAILED" -eq 0 ]; then
		rm -f /tmp/ace-*.log
	else
		info "Failure logs retained in /tmp/ace-server.log and /tmp/ace-client.log"
	fi
	 rm -f /tmp/ace-smoke-input.bin "${ACE_UPSTREAM_FILE:-/var/run/client}"
	 rm -f received/ace-smoke-input.bin
	if [ -n "${CERT_DIR:-}" ]; then
		rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
		rmdir "$CERT_DIR" 2>/dev/null || true
	fi
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
export ACE_IP_VERSION=${ACE_IP_VERSION:-4}
CERT_DIR=$(mktemp -d /tmp/ace-cert.XXXXXX)
export ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
	-keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
	>/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem"
export ACE_KEY_FILE="$CERT_DIR/key.pem"
# Self-signed cert — explicitly opt into insecure mode.
export ACE_TLS_INSECURE=1

# ---- 1. Start server ----
info "Starting server on UDP port 12345..."
stdbuf -oL -eL "./${ACE_BUILD_DIR}/src/ace" 1 > /tmp/ace-server.log 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 $SERVER_PID 2>/dev/null; then
    fail "Server died immediately"
fi
pass "Server started (pid=$SERVER_PID)"

if ss -uln 2>/dev/null | grep -Eq '(^|[.:])12345[[:space:]]'; then
    pass "Server listening on UDP :12345"
else
    fail "Server not listening on UDP port 12345"
fi

# ---- 2. Start client ----
info "Starting client connecting to 127.0.0.1:12345..."
stdbuf -oL -eL "./${ACE_BUILD_DIR}/src/ace" 0 > /tmp/ace-client.log 2>&1 &
CLIENT_PID=$!

for _attempt in $(seq 1 16); do
    if grep -q 'server_on_new_conn' /tmp/ace-server.log 2>/dev/null &&
       grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/ace-client.log 2>/dev/null &&
       grep -q 'QUIC_PROBE_OK.*bytes=4096' /tmp/ace-client.log 2>/dev/null; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null || ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# ---- 3. Verify ----
info "Server log:"
grep -E 'connote|connection|new_conn|handshake|echo' /tmp/ace-server.log 2>/dev/null | tail -10 || echo "  (no connection events)"

info "Client log:"
tail -20 /tmp/ace-client.log 2>/dev/null || echo "  (empty)"

# A startup smoke test is only useful when the client reaches the QUIC server.
if grep -q 'server_on_new_conn' /tmp/ace-server.log 2>/dev/null &&
   grep -q 'QUIC_PROBE_ECHO' /tmp/ace-server.log 2>/dev/null &&
   grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/ace-client.log 2>/dev/null &&
   grep -q 'QUIC_PROBE_OK.*bytes=4096' /tmp/ace-client.log 2>/dev/null; then
    pass "QUIC handshake and validated probe echo completed"
else
    info "Server diagnostics:"
    tail -40 /tmp/ace-server.log 2>/dev/null || true
    info "Client diagnostics:"
    tail -40 /tmp/ace-client.log 2>/dev/null || true
    fail "QUIC handshake or validated probe echo was not observed"
fi

# ---- 4. Verify signal-driven service-loop shutdown and thread join ----
kill -TERM "$CLIENT_PID"
for _attempt in $(seq 1 20); do
    kill -0 "$CLIENT_PID" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$CLIENT_PID" 2>/dev/null; then
    fail "Client did not stop after SIGTERM"
fi
wait "$CLIENT_PID" || info "Client exited with non-zero status (idle timeout is expected)"
CLIENT_PID=
grep -q 'service .* destroyed' /tmp/ace-client.log || fail "Client service thread was not joined"

kill -TERM "$SERVER_PID"
for _attempt in $(seq 1 20); do
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "Server did not stop after SIGTERM"
fi
wait "$SERVER_PID" || fail "Server exited unsuccessfully during graceful shutdown"
SERVER_PID=
grep -q 'service .* destroyed' /tmp/ace-server.log || fail "Server service thread was not joined"
pass "Client and server stopped cleanly and joined service threads"

pass "Smoke test infrastructure works"
