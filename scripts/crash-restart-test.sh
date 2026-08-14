#!/bin/bash
# crash-restart-test.sh — real crash recovery test.
# Kills the receiver (SIGKILL) mid-transfer, after the first segment has been
# durably recorded in the metadata sidecar, then restarts server+client and
# asserts the retransfer RESUMES (skip the completed segment) rather than
# starting over from scratch.
set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}
NSEG=4                              # data-stream count (segment count)
SIZE_MB=256                         # large enough that the transfer outlives the first segment
CERT_DIR=$(mktemp -d /tmp/ace-crash-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
INPUT=/tmp/ace-crash-input.bin
NAME=$(basename "$INPUT")
SERVER_PID=
CLIENT_PID=

stop_proc() {
    [ -n "$1" ] || return 0
    kill -KILL "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}

cleanup() {
    stop_proc "$CLIENT_PID"
    stop_proc "$SERVER_PID"
    rm -f /tmp/ace-crash-*.log "$INPUT" "$ACE_UPSTREAM_FILE"
    rm -rf "received/$NAME" "received/$NAME.part."* "received/$NAME.acemeta"
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1 ACE_UPSTREAM_FILE

start_server() {
    stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 1 > /tmp/ace-crash-server.log 2>&1 &
    SERVER_PID=$!
    sleep 1
    kill -0 "$SERVER_PID" 2>/dev/null || fail "server died immediately"
}
start_client() {
    stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 0 > /tmp/ace-crash-client.log 2>&1 &
    CLIENT_PID=$!
    sleep 1
    kill -0 "$CLIENT_PID" 2>/dev/null || fail "client died immediately"
}

dd if=/dev/urandom of="$INPUT" bs=1M count="$SIZE_MB" status=none
mkdir -p received

# ---- Phase 1: transfer, then SIGKILL the receiver once the first segment is
# durably recorded (the .acemeta sidecar appears) but before concat. ----
info "Phase 1: start transfer, kill receiver after first segment completes"
start_server
start_client
rm -f session/127.0.0.1_12345-
printf "sf $NSEG $INPUT\n" | socat - UNIX-CONNECT:"$ACE_UPSTREAM_FILE" 2>/dev/null || true

# Wait for segment 0's done flag to flip to 1 in the sidecar (the .acemeta is
# created at init with all-done=0; a segment's done byte is set + fsync'd only
# after that segment is fully received and its .part fsync'd).  Offset 32 = 16
# header bytes + 16 bytes into the segment-0 record (past offset/size/checksum).
done0=0
for _ in $(seq 1 2000); do
    if [ -f "received/$NAME.acemeta" ]; then
        done0=$(od -An -tu1 -j 32 -N 1 "received/$NAME.acemeta" 2>/dev/null | tr -d ' ')
    fi
    [ "$done0" = "1" ] && break
    sleep 0.005
done
if [ "$done0" != "1" ]; then
    fail "segment 0 never completed within 10s (transfer too fast or hung)"
fi
if [ -f "received/$NAME" ]; then
    fail "transfer already finished before the kill (file too small)"
fi

info "SIGKILL receiver (pid $SERVER_PID) mid-transfer"
kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=
stop_proc "$CLIENT_PID"
CLIENT_PID=

# ---- Phase 2: restart both sides and resume. ----
info "Phase 2: restart server+client, expect resume"
start_server
start_client
rm -f session/127.0.0.1_12345-
printf "sf $NSEG $INPUT\n" | socat - UNIX-CONNECT:"$ACE_UPSTREAM_FILE" 2>/dev/null || true

for _ in $(seq 1 200); do
    if [ -f "received/$NAME" ] && cmp -s "$INPUT" "received/$NAME"; then
        break
    fi
    sleep 0.25
done

if [ -f "received/$NAME" ] && cmp -s "$INPUT" "received/$NAME"; then
    pass "crash-recovered transfer produced an identical $(stat -c %s "$INPUT")-byte file"
else
    fail "post-crash retransfer did not produce a matching file"
fi

# The recovery is only a RESUME (not a fresh retransfer) if the receiver
# answered with a resume bitmap, proving the durable segment was reused.
if grep -q 'resume bitmap received' /tmp/ace-crash-client.log 2>/dev/null; then
    pass "recovery resumed from the durable segment (CONTROL resume bitmap)"
else
    fail "post-crash retransfer started over (no resume bitmap) — crash state was lost"
fi
