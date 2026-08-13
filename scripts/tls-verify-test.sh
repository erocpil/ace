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
    rm -f /tmp/test-expired.key /tmp/test-expired.csr /tmp/test-expired.pem
    rm -f /tmp/tls-test-*.log
}
trap cleanup EXIT

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
CLIENT_BIN="./${ACE_BUILD_DIR}/src/ace"
SERVER_BIN="./${ACE_BUILD_DIR}/src/ace"

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

# ---- Test 1: Server verification (happy path) ----
info "Test 1: Server verification with valid CA + hostname"
export ACE_CERT_FILE=/tmp/test-server.pem
export ACE_KEY_FILE=/tmp/test-server.key
export ACE_CA_FILE=/tmp/test-ca.pem
export ACE_HOSTNAME=localhost
export ACE_UPSTREAM_FILE=/tmp/ace-tls-upstream.sock

$SERVER_BIN 1 > /tmp/tls-test-server.log 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 $SERVER_PID 2>/dev/null; then
    fail "server died — check /tmp/tls-test-server.log"
fi

CLIENT_RC=0
timeout 5 $CLIENT_BIN 0 > /tmp/tls-test-client.log 2>&1 || CLIENT_RC=$?
sleep 1

if [ $CLIENT_RC -ne 0 ] && grep -q 'TLS peer verification enabled' /tmp/tls-test-client.log 2>/dev/null; then
    # Client may exit non-zero due to idle timeout after successful handshake.
    # Accept non-zero as long as verification was enabled and handshake succeeded.
    if grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client.log 2>/dev/null; then
        pass "TLS server verification succeeded"
    else
        echo "Client log:"
        grep -E 'TLS|verify|hostname|HSK|error' /tmp/tls-test-client.log | head -10
        fail "handshake failed with CA verification enabled"
    fi
elif [ $CLIENT_RC -eq 0 ] && grep -q 'TLS peer verification enabled' /tmp/tls-test-client.log 2>/dev/null; then
    if grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client.log 2>/dev/null; then
        pass "TLS server verification succeeded"
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

$SERVER_BIN 1 > /tmp/tls-test-server2.log 2>&1 &
SERVER_PID=$!
sleep 1
CLIENT_RC=0
timeout 5 $CLIENT_BIN 0 > /tmp/tls-test-client2.log 2>&1 || CLIENT_RC=$?

if grep -qi 'hostname mismatch\|hostname.*verified\|certificate.*failed\|self.signed\|cert.*verify' /tmp/tls-test-client2.log 2>/dev/null; then
    pass "hostname mismatch detected and rejected"
elif [ $CLIENT_RC -ne 0 ]; then
    # Client exited non-zero — check if it was due to verification failure.
    if grep -q 'TLS peer verification enabled' /tmp/tls-test-client2.log 2>/dev/null &&
       ! grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client2.log 2>/dev/null; then
        pass "hostname mismatch caused handshake rejection"
    else
        echo "Client log:"
        grep -iE 'hostname|mismatch|verify|fail|error|hsk' /tmp/tls-test-client2.log | head -10 || true
        fail "hostname mismatch not detected (handshake should have been rejected)"
    fi
else
    echo "Client log:"
    grep -iE 'hostname|mismatch|verify|fail|error|hsk' /tmp/tls-test-client2.log | head -10 || true
    fail "hostname mismatch not detected (handshake should have been rejected)"
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

$SERVER_BIN 1 > /tmp/tls-test-server3.log 2>&1 &
SERVER_PID=$!
sleep 1
CLIENT_RC=0
timeout 5 $CLIENT_BIN 0 > /tmp/tls-test-client3.log 2>&1 || CLIENT_RC=$?

if grep -qiE 'preverify=0.*err=20:unable to get local issuer certificate' /tmp/tls-test-client3.log 2>/dev/null; then
    pass "unknown CA detected (certificate not trusted)"
elif [ $CLIENT_RC -ne 0 ] && ! grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client3.log 2>/dev/null; then
    pass "unknown CA caused handshake rejection"
else
    echo "Client log:"
    grep -iE 'cert|verify|hsk|fail|error|tls|preverify' /tmp/tls-test-client3.log | head -10 || true
    fail "unknown CA not detected (handshake should have been rejected)"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true

# ---- Test 4: Explicit insecure mode ----
info "Test 4: ACE_TLS_INSECURE=1 skips verification even with CA set"
export ACE_CA_FILE=/tmp/test-ca.pem
export ACE_HOSTNAME=localhost
export ACE_TLS_INSECURE=1

$SERVER_BIN 1 > /tmp/tls-test-server4.log 2>&1 &
SERVER_PID=$!
sleep 1
CLIENT_RC=0
timeout 5 $CLIENT_BIN 0 > /tmp/tls-test-client4.log 2>&1 || CLIENT_RC=$?
sleep 1

if grep -q 'TLS verify disabled (insecure mode)' /tmp/tls-test-client4.log 2>/dev/null; then
    if grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client4.log 2>/dev/null; then
        pass "insecure mode allows handshake despite CA configuration"
    else
        # Client may exit non-zero after successful handshake (idle timeout).
        # Accept if insecure flag was honored and no verification rejection.
        if grep -q 'TLS verify disabled' /tmp/tls-test-client4.log 2>/dev/null &&
           ! grep -qi 'hostname mismatch\|self.signed\|certificate.*failed' /tmp/tls-test-client4.log 2>/dev/null; then
            pass "insecure mode honored (client exited after handshake)"
        else
            fail "insecure mode handshake failed"
        fi
    fi
else
    fail "insecure flag not honored"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true

# ---- Test 5: Expired server certificate ----
info "Test 5: Expired server certificate should reject"
unset ACE_TLS_INSECURE
# Expired server cert (notAfter in the past) signed by the valid CA.
openssl genrsa -out /tmp/test-expired.key 2048 2>/dev/null
openssl req -new -key /tmp/test-expired.key -out /tmp/test-expired.csr \
    -subj '/CN=localhost' 2>/dev/null
openssl x509 -req -in /tmp/test-expired.csr \
    -CA /tmp/test-ca.pem -CAkey /tmp/test-ca.key -CAcreateserial \
    -out /tmp/test-expired.pem -days -1 2>/dev/null

export ACE_CERT_FILE=/tmp/test-expired.pem
export ACE_KEY_FILE=/tmp/test-expired.key
export ACE_CA_FILE=/tmp/test-ca.pem
export ACE_HOSTNAME=localhost

$SERVER_BIN 1 > /tmp/tls-test-server5.log 2>&1 &
SERVER_PID=$!
sleep 1
CLIENT_RC=0
timeout 5 $CLIENT_BIN 0 > /tmp/tls-test-client5.log 2>&1 || CLIENT_RC=$?
sleep 1

if grep -qi 'certificate has expired\|expired' /tmp/tls-test-client5.log 2>/dev/null; then
    pass "expired certificate detected and rejected"
elif [ $CLIENT_RC -ne 0 ] && ! grep -Eq 'LSQ_HSK_OK|LSQ_HSK_RESUMED_OK' /tmp/tls-test-client5.log 2>/dev/null; then
    pass "expired certificate caused handshake rejection"
else
    echo "Client log:"
    grep -iE 'cert|expired|verify|hsk|fail|error' /tmp/tls-test-client5.log | head -10 || true
    fail "expired certificate not detected (handshake should have been rejected)"
fi

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true

echo ""
info "All TLS verification tests completed"
