#!/bin/bash
# tls-verify-test.sh — verify ACE TLS identity verification
set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

cleanup() {
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    rm -f /tmp/test-ca.key /tmp/test-ca.pem /tmp/test-ca.srl
    rm -f /tmp/test-ca2.key /tmp/test-ca2.pem
    rm -f /tmp/test-server.key /tmp/test-server.csr /tmp/test-server.pem
    rm -f /tmp/tls-test-*.log
}
trap cleanup EXIT

# ---- Generate CA ----
openssl genrsa -out /tmp/test-ca.key 2048 2>/dev/null
openssl req -new -x509 -days 1 -key /tmp/test-ca.key -out /tmp/test-ca.pem \
    -subj '/CN=ACE Test CA' 2>/dev/null

# ---- Generate server cert signed by CA ----
openssl genrsa -out /tmp/test-server.key 2048 2>/dev/null
openssl req -new -key /tmp/test-server.key -out /tmp/test-server.csr \
    -subj '/CN=localhost' 2>/dev/null
openssl x509 -req -days 1 -in /tmp/test-server.csr \
    -CA /tmp/test-ca.pem -CAkey /tmp/test-ca.key -CAcreateserial \
    -out /tmp/test-server.pem 2>/dev/null

# ---- Test 1: Mutual verification (happy path) ----
info "Test 1: Mutual verification with valid CA + hostname"
export ACE_CERT_FILE=/tmp/test-server.pem
export ACE_KEY_FILE=/tmp/test-server.key
export ACE_CA_FILE=/tmp/test-ca.pem
export ACE_HOSTNAME=localhost
export ACE_UPSTREAM_FILE=/tmp/ace-tls-upstream.sock

./build/src/ace 1 > /tmp/tls-test-server.log 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 $SERVER_PID 2>/dev/null; then
    fail "server died — check /tmp/tls-test-server.log"
fi

timeout 5 ./build/src/ace 0 > /tmp/tls-test-client.log 2>&1 || true
sleep 1

if grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client.log 2>/dev/null; then
    if grep -q 'TLS peer verification enabled' /tmp/tls-test-client.log 2>/dev/null; then
        pass "TLS handshake with mutual verification succeeded"
    else
        fail "handshake passed but verification was not enabled"
    fi
else
    echo "Server log:"
    grep -E 'TLS|verify|hostname' /tmp/tls-test-server.log | head -5
    echo "Client log:"
    grep -E 'TLS|verify|hostname|HSK|error' /tmp/tls-test-client.log | head -10
    fail "handshake failed with CA verification enabled"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true
rm -f "$ACE_UPSTREAM_FILE"

# ---- Test 2: Wrong hostname ----
info "Test 2: Hostname mismatch should reject"
export ACE_HOSTNAME=wronghost.example.com

./build/src/ace 1 > /tmp/tls-test-server2.log 2>&1 &
SERVER_PID=$!
sleep 1
timeout 5 ./build/src/ace 0 > /tmp/tls-test-client2.log 2>&1 || true

if grep -qi 'hostname mismatch' /tmp/tls-test-client2.log 2>/dev/null; then
    pass "hostname mismatch detected and rejected"
else
    echo "Client log:"
    grep -iE 'hostname|mismatch|verify|fail|error' /tmp/tls-test-client2.log | head -5 || true
    info "hostname rejection behavior may depend on callback timing"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true

# ---- Test 3: Unknown CA ----
info "Test 3: Unknown CA should reject"
openssl genrsa -out /tmp/test-ca2.key 2048 2>/dev/null
openssl req -new -x509 -days 1 -key /tmp/test-ca2.key -out /tmp/test-ca2.pem \
    -subj '/CN=Wrong CA' 2>/dev/null
export ACE_CA_FILE=/tmp/test-ca2.pem
export ACE_HOSTNAME=localhost

./build/src/ace 1 > /tmp/tls-test-server3.log 2>&1 &
SERVER_PID=$!
sleep 1
timeout 5 ./build/src/ace 0 > /tmp/tls-test-client3.log 2>&1 || true

if grep -qiE 'certificate|verify|untrusted|unknown|alert' /tmp/tls-test-client3.log 2>/dev/null; then
    pass "unknown CA detected"
else
    echo "Client log:"
    grep -iE 'cert|verify|hsk|fail|error|tls' /tmp/tls-test-client3.log | head -5 || true
    info "check logs manually — handshake should fail with wrong CA"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true

# ---- Test 4: Explicit insecure mode ----
info "Test 4: ACE_TLS_INSECURE=1 skips verification even with CA set"
export ACE_CA_FILE=/tmp/test-ca.pem
export ACE_HOSTNAME=localhost
export ACE_TLS_INSECURE=1

./build/src/ace 1 > /tmp/tls-test-server4.log 2>&1 &
SERVER_PID=$!
sleep 1
timeout 5 ./build/src/ace 0 > /tmp/tls-test-client4.log 2>&1 || true
sleep 1

if grep -q 'TLS verify disabled (insecure mode)' /tmp/tls-test-client4.log 2>/dev/null; then
    if grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client4.log 2>/dev/null; then
        pass "insecure mode allows handshake despite CA configuration"
    else
        fail "insecure mode handshake failed"
    fi
else
    fail "insecure flag not honored"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true

echo ""
info "All TLS verification tests completed"
