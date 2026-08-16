#!/bin/bash
# file-transfer-test.sh — ACE multi-stream file transfer integration test
# Self-contained: starts its own server+client, transfers a file, verifies.
# Non-blocking in CI (continue-on-error).  Tracked separately as known limitation.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test-lib.sh

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}

CERT_DIR=$(mktemp -d /tmp/ace-ft-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}

cleanup() {
    if [ -n "${CLIENT_PID:-}" ]; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f /tmp/ace-ft-*.log /tmp/ace-ft-input.bin "${ACE_UPSTREAM_FILE}"
    rm -f received/ace-ft-input.bin
    if [ -n "${CERT_DIR:-}" ]; then
        rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
        rmdir "$CERT_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Generate cert
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem"
export ACE_KEY_FILE="$CERT_DIR/key.pem"
# Self-signed cert — explicitly opt into insecure mode.
export ACE_TLS_INSECURE=1
export ACE_UPSTREAM_FILE

# Start server
info "Starting file-transfer server..."
stdbuf -oL -eL "./${ACE_BUILD_DIR}/src/ace" 1 > /tmp/ace-ft-server.log 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 $SERVER_PID 2>/dev/null; then
    fail "File-transfer server died immediately"
fi

# Generate test file
dd if=/dev/urandom of=/tmp/ace-ft-input.bin bs=1024 count=96 status=none

# Start client (will attempt file transfer via upstream)
info "Starting file-transfer client..."
stdbuf -oL -eL "./${ACE_BUILD_DIR}/src/ace" 0 > /tmp/ace-ft-client.log 2>&1 &
CLIENT_PID=$!
sleep 1
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    fail "File-transfer client died immediately"
fi

# Send file-transfer command via upstream socket (retry until the socket is up)
rm -f session/127.0.0.1_12345-
ace_send_control "$ACE_UPSTREAM_FILE" "sf 3 /tmp/ace-ft-input.bin" \
    || fail "upstream socket never accepted the sf command"

# Wait for transfer to complete
for _attempt in $(seq 1 40); do
    if [ -f received/ace-ft-input.bin ] &&
       cmp -s /tmp/ace-ft-input.bin received/ace-ft-input.bin; then
        break
    fi
    sleep 0.25
done

if [ -f received/ace-ft-input.bin ] &&
   cmp -s /tmp/ace-ft-input.bin received/ace-ft-input.bin; then
    pass "Multi-stream file transfer persisted an identical 98304-byte file"
else
    fail "Multi-stream file transfer did not produce a matching file"
fi
