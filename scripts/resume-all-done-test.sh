#!/bin/bash
# resume-all-done-test.sh — "already fully transferred" fast-path test.
# Pre-seeds a transfer where EVERY segment is already present + verified in the
# metadata sidecar, then runs `sf` and asserts the receiver skips the transfer
# entirely (concatenates the existing .part files) instead of retransmitting.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test-lib.sh

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}
NSEG=${ACE_RESUME_NSEG:-4}          # data-stream count (segment count)
CERT_DIR=$(mktemp -d /tmp/ace-all-done-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
INPUT=/tmp/ace-all-done-input.bin
NAME=$(basename "$INPUT")

cleanup() {
    [ -n "${CLIENT_PID:-}" ] && { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
    [ -n "${SERVER_PID:-}" ] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -f /tmp/ace-all-done-*.log "$INPUT" "$ACE_UPSTREAM_FILE"
    rm -rf "received/$NAME" "received/$NAME.part."* "received/$NAME.acemeta"
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1 ACE_UPSTREAM_FILE

# 8 MiB source, NSEG segments of 2 MiB each.
dd if=/dev/urandom of="$INPUT" bs=1M count=8 status=none

# Pre-seed a FULLY completed transfer: every segment's .part present with the
# correct checksum, and every sidecar record done=1.
mkdir -p received

python3 - "$INPUT" "$NSEG" <<'PY'
import struct, os, sys
src, nseg = sys.argv[1], int(sys.argv[2])
name = os.path.basename(src)
total = os.path.getsize(src)
quota = total // nseg
whole = open(src, "rb").read()

def fnv1a(data):
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xffffffff
    return h

file_hash = fnv1a(whole)
hdr = struct.pack("<4sBBHII", b"ACEM", 1, 0, nseg, total, file_hash)
segs = b""
for k in range(nseg):
    off = quota * k
    size = quota if k < nseg - 1 else total - quota * (nseg - 1)
    part = whole[off:off+size]
    open(f"received/{name}.part.{k}", "wb").write(part)
    segs += struct.pack("<QIIB3x", off, size, fnv1a(part), 1)  # done=1
open(f"received/{name}.acemeta", "wb").write(hdr + segs)
PY

info "Starting all-done server..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 1 > /tmp/ace-all-done-server.log 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "all-done server died immediately"

info "Starting all-done client..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 0 > /tmp/ace-all-done-client.log 2>&1 &
CLIENT_PID=$!
sleep 1
kill -0 "$CLIENT_PID" 2>/dev/null || fail "all-done client died immediately"

rm -f session/127.0.0.1_12345-
info "Sending sf $NSEG $INPUT ..."
ace_send_control "$ACE_UPSTREAM_FILE" "sf $NSEG $INPUT" \
    || fail "upstream socket never accepted the sf command"

for _ in $(seq 1 80); do
    if [ -f "received/$NAME" ] && cmp -s "$INPUT" "received/$NAME"; then
        break
    fi
    sleep 0.25
done

if [ -f "received/$NAME" ] && cmp -s "$INPUT" "received/$NAME"; then
    pass "all-done fast path produced an identical $(stat -c %s "$INPUT")-byte file"
else
    fail "all-done fast path did not produce a matching file"
fi

# The fast path is only proven if the receiver answered with a resume bitmap
# (CONTROL) AND the sender skipped every segment (no retransmit).
if grep -q 'resume bitmap received' /tmp/ace-all-done-client.log 2>/dev/null; then
    pass "client processed the resume bitmap frame (CONTROL)"
else
    fail "client log shows no resume-bitmap frame"
fi

skipped=$(grep -c 'already complete, skipped' /tmp/ace-all-done-client.log 2>/dev/null || true)
if [ "$skipped" -eq "$NSEG" ]; then
    pass "client skipped all $NSEG segments (no retransmit)"
else
    fail "client skipped $skipped segments, expected $NSEG (a full retransfer happened)"
fi

# The sender must also RECEIVE the completion (done) frame and finish its
# task, not just the receiver.  Regression for the coalesced bitmap+done
# read: the old code zeroed the whole rx buffer after the bitmap and dropped
# a done frame delivered in the same read, leaving the sender hanging.
if grep -q 'task exiting' /tmp/ace-all-done-client.log 2>/dev/null; then
    pass "client received the done frame and completed its task"
else
    fail "client never completed (done frame dropped after resume bitmap)"
fi
