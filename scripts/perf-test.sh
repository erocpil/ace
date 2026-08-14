#!/bin/bash
# perf-test.sh — perf transfer completes gracefully (done frame + task exit).
# Regression for the perf_done no-op: before the fix, perf never sent a done
# frame so the transfer never ended; now the receiver emits FLAG_LAST and both
# sides exit the task.
set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}
NSEG=${ACE_PERF_NSEG:-3}          # data-stream count
CERT_DIR=$(mktemp -d /tmp/ace-perf-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
SERVER_PID=
CLIENT_PID=

cleanup() {
    [ -n "$CLIENT_PID" ] && { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
    [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -f /tmp/ace-perf-*.log "$ACE_UPSTREAM_FILE"
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1 ACE_UPSTREAM_FILE

info "Starting perf server..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 1 > /tmp/ace-perf-server.log 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "perf server died immediately"

info "Starting perf client..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 0 > /tmp/ace-perf-client.log 2>&1 &
CLIENT_PID=$!
sleep 1
kill -0 "$CLIENT_PID" 2>/dev/null || fail "perf client died immediately"

rm -f session/127.0.0.1_12345-
info "Sending perf $NSEG ..."
printf "perf $NSEG\n" | socat - UNIX-CONNECT:"$ACE_UPSTREAM_FILE" 2>/dev/null || true

for _ in $(seq 1 40); do
    if grep -q 'task exiting' /tmp/ace-perf-client.log 2>/dev/null &&
       grep -q 'task exiting' /tmp/ace-perf-server.log 2>/dev/null; then
        break
    fi
    sleep 0.25
done

# The sender must have seen the receiver's done frame.
if grep -q 'TASK_DONE' /tmp/ace-perf-client.log 2>/dev/null; then
    pass "client received the done frame (FLAG_LAST)"
else
    fail "client never saw the done frame"
fi

# Both sides must have exited the task gracefully.
if grep -q 'task exiting' /tmp/ace-perf-client.log 2>/dev/null; then
    pass "client task exited"
else
    fail "client task did not exit"
fi
if grep -q 'task exiting' /tmp/ace-perf-server.log 2>/dev/null; then
    pass "server task exited"
else
    fail "server task did not exit"
fi
