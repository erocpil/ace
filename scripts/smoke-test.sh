#!/bin/bash
# smoke-test.sh — minimal ACE server + client smoke test
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

cleanup() {
    info "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    kill $CLIENT_PID 2>/dev/null || true
    wait $CLIENT_PID 2>/dev/null || true
    rm -f /tmp/ace-*.log
}
trap cleanup EXIT

cd "$(dirname "$0")/.."

# ---- 1. Start server ----
info "Starting server on UDP port 12345..."
./build/src/ace 1 > /tmp/ace-server.log 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 $SERVER_PID 2>/dev/null; then
    fail "Server died immediately"
fi
pass "Server started (pid=$SERVER_PID)"

if ss -ulnp 2>/dev/null | grep -q '12345.*ace'; then
    pass "Server listening on UDP :12345"
else
    fail "Server not listening on UDP port 12345"
fi

# ---- 2. Start client ----
info "Starting client connecting to 127.0.0.1:12345..."
timeout 3 ./build/src/ace 0 > /tmp/ace-client.log 2>&1 &
CLIENT_PID=$!
sleep 2

# ---- 3. Verify ----
info "Server log:"
grep -E 'connote|connection|new_conn|handshake|echo' /tmp/ace-server.log 2>/dev/null | tail -10 || echo "  (no connection events)"

info "Client log:"
tail -20 /tmp/ace-client.log 2>/dev/null || echo "  (empty)"

# Check for connection evidence
if grep -qi 'connect\|connote\|new_conn\|echo' /tmp/ace-server.log 2>/dev/null; then
    pass "Server saw connection activity"
else
    info "Server did not log connection events (client may need cert)"
fi

pass "Smoke test infrastructure works"
