#!/bin/bash
# multi-command-test.sh — sequential multi-command transfer regression.
# Guards against a client that starts multiple tasks on one connection and
# overwrites lconn_ctx->task / stream-0 negotiation (one task per connection).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test-lib.sh

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}

CERT_DIR=$(mktemp -d /tmp/ace-mc-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
SOCAT_PID=""

cleanup() {
    [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null || true
    [ -n "${CLIENT_PID:-}" ] && { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
    [ -n "${SERVER_PID:-}" ] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -f /tmp/ace-mc-*.log /tmp/ace-mc-a.bin /tmp/ace-mc-b.bin "$ACE_UPSTREAM_FILE"
    rm -f received/ace-mc-a.bin received/ace-mc-b.bin
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1 ACE_UPSTREAM_FILE

info "Starting multi-command server..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 1 > /tmp/ace-mc-server.log 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server died immediately"

dd if=/dev/urandom of=/tmp/ace-mc-a.bin bs=1024 count=96 status=none
dd if=/dev/urandom of=/tmp/ace-mc-b.bin bs=1024 count=80 status=none

info "Starting multi-command client..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 0 > /tmp/ace-mc-client.log 2>&1 &
CLIENT_PID=$!
sleep 1
kill -0 "$CLIENT_PID" 2>/dev/null || fail "client died immediately"

rm -f session/127.0.0.1_12345-
# Wait for the upstream socket to be listening before the hold-open send.
ace_wait_connect "$ACE_UPSTREAM_FILE" || fail "upstream socket never ready"
# Two commands piped at once; hold the socket open so both are drained.
( printf 'sf 3 /tmp/ace-mc-a.bin\nsf 3 /tmp/ace-mc-b.bin\n'; sleep 20 ) | \
    socat - UNIX-CONNECT:"$ACE_UPSTREAM_FILE" >/dev/null 2>&1 &
SOCAT_PID=$!

ok_a=0; ok_b=0
for _ in $(seq 1 80); do
    [ -f received/ace-mc-a.bin ] && cmp -s /tmp/ace-mc-a.bin received/ace-mc-a.bin && ok_a=1
    [ -f received/ace-mc-b.bin ] && cmp -s /tmp/ace-mc-b.bin received/ace-mc-b.bin && ok_b=1
    [ "$ok_a" = 1 ] && [ "$ok_b" = 1 ] && break
    sleep 0.25
done

if [ "$ok_a" = 1 ] && [ "$ok_b" = 1 ]; then
    pass "two queued commands transferred sequentially without task-state overwrite"
else
    fail "multi-command transfer incomplete (a=$ok_a b=$ok_b)"
fi
