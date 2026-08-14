#!/bin/bash
# resume-mismatch-test.sh — same-name same-length but different-content resume
# rejection.  A stale .acemeta whose file_hash does not match the current source
# must be discarded (fresh retransfer), never reused to produce a mixed file.
set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
ACE_IP_VERSION=${ACE_IP_VERSION:-4}
NSEG=${ACE_RESUME_NSEG:-4}
CERT_DIR=$(mktemp -d /tmp/ace-rxm-cert.XXXXXX)
ACE_UPSTREAM_FILE=${ACE_UPSTREAM_FILE:-$CERT_DIR/client.sock}
INPUT=/tmp/ace-rxm-input.bin     # current source (A)
OTHER=/tmp/ace-rxm-other.bin     # prior, different-content source (B)
NAME=$(basename "$INPUT")

cleanup() {
    [ -n "${CLIENT_PID:-}" ] && { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
    [ -n "${SERVER_PID:-}" ] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -f /tmp/ace-rxm-*.log "$INPUT" "$OTHER" "$ACE_UPSTREAM_FILE"
    rm -rf "received/$NAME" "received/$NAME.part."* "received/$NAME.acemeta"
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
    >/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1 ACE_UPSTREAM_FILE

# Two independent 8 MiB files, same name/length but different content.
dd if=/dev/urandom of="$INPUT" bs=1M count=8 status=none
dd if=/dev/urandom of="$OTHER" bs=1M count=8 status=none

# Seed a "prior partial transfer" whose segment 0 is OTHER's first 2 MiB, and
# whose sidecar carries OTHER's whole-file hash — so it matches name+length but
# NOT the current source's identity.
mkdir -p received
dd if="$OTHER" of="received/$NAME.part.0" bs=1M count=2 status=none

python3 - "$INPUT" "$OTHER" "$NSEG" <<'PY'
import struct, os, sys
src, other, nseg = sys.argv[1], sys.argv[2], int(sys.argv[3])
name = os.path.basename(src)
total = os.path.getsize(src)
quota = total // nseg

def fnv1a(data):
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xffffffff
    return h

part0 = open(f"received/{name}.part.0", "rb").read()
ck0 = fnv1a(part0)
other_hash = fnv1a(open(other, "rb").read())   # OTHER's identity, not src's

hdr = struct.pack("<4sBBHII", b"ACEM", 1, 0, nseg, total, other_hash)
segs = b""
for k in range(nseg):
    off = quota * k
    size = quota if k < nseg - 1 else total - quota * (nseg - 1)
    done = 1 if k == 0 else 0
    ck = ck0 if k == 0 else 0
    segs += struct.pack("<QIIB3x", off, size, ck, done)
open(f"received/{name}.acemeta", "wb").write(hdr + segs)
PY

info "Starting resume-mismatch server..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 1 > /tmp/ace-rxm-server.log 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "server died immediately"

info "Starting resume-mismatch client..."
stdbuf -oL -eL "./$ACE_BUILD_DIR/src/ace" 0 > /tmp/ace-rxm-client.log 2>&1 &
CLIENT_PID=$!
sleep 1
kill -0 "$CLIENT_PID" 2>/dev/null || fail "client died immediately"

rm -f session/127.0.0.1_12345-
info "Sending sf $NSEG $INPUT ..."
printf "sf $NSEG $INPUT\n" | socat - UNIX-CONNECT:"$ACE_UPSTREAM_FILE" 2>/dev/null || true

for _ in $(seq 1 80); do
    if [ -f "received/$NAME" ] && cmp -s "$INPUT" "received/$NAME"; then
        break
    fi
    sleep 0.25
done

if [ -f "received/$NAME" ] && cmp -s "$INPUT" "received/$NAME"; then
    pass "mismatched source produced a byte-identical file (stale .part rejected)"
else
    fail "mismatched source produced a mixed/corrupt file"
fi

if grep -q 'resume bitmap received' /tmp/ace-rxm-client.log 2>/dev/null; then
    fail "client resumed from a mismatched source (should have retransferred fresh)"
fi
pass "client did NOT resume (no resume bitmap) — identity mismatch forced fresh transfer"
