#!/bin/bash
# client-exit-test.sh — the client must exit on its own once the last
# connection closes and no requests are queued (no external kill needed).
#
# Regression for the "client never exits" limitation: before the fix the
# client's event loop kept running forever after a transfer finished and the
# scripts had to tolerate killing it in cleanup (or a `timeout 124`).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test-lib.sh

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}
CERT_DIR=$(mktemp -d /tmp/ace-exit-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
INPUT=/tmp/ace-exit-input.bin
SERVER_PID=
CLIENT_PID=

cleanup() {
    [ -n "$CLIENT_PID" ] && { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
    [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -f /tmp/ace-exit-*.log "$INPUT" "$ACE_UPSTREAM_FILE"
    rm -f received/$(basename "$INPUT")
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1 ACE_UPSTREAM_FILE

dd if=/dev/urandom of="$INPUT" bs=1024 count=32 status=none

info "Starting server..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 1 > /tmp/ace-exit-server.log 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server died immediately"

info "Starting client..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 0 > /tmp/ace-exit-client.log 2>&1 &
CLIENT_PID=$!
sleep 1
kill -0 "$CLIENT_PID" 2>/dev/null || fail "client died immediately"

rm -f session/127.0.0.1_12345-
ace_send_control "$ACE_UPSTREAM_FILE" "sf 3 $INPUT" \
    || fail "upstream socket never accepted the sf command"

# Transfer must complete first.
ok=0
for _ in $(seq 1 40); do
    if [ -f "received/$(basename "$INPUT")" ] && cmp -s "$INPUT" "received/$(basename "$INPUT")"; then
        ok=1; break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || fail "transfer did not complete"

# Then the client must exit on its own (no kill).
exited=0
for _ in $(seq 1 40); do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        exited=1; break
    fi
    sleep 0.25
done
if [ "$exited" = 1 ]; then
    pass "client exited on its own after the last connection closed"
else
    fail "client still alive 10s after transfer finished"
fi

if grep -q 'no active connection and no queued work' /tmp/ace-exit-client.log 2>/dev/null; then
    pass "client logged the idle-exit break"
else
    fail "client exit was not the idle-exit path"
fi
