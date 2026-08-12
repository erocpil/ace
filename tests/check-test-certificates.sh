#!/bin/sh
set -eu

root=${1:-.}
grep -F 'mktemp -d /tmp/ace-cert.XXXXXX' "$root/scripts/smoke-test.sh" >/dev/null
grep -F 'export ACE_CERT_FILE=' "$root/scripts/smoke-test.sh" >/dev/null
grep -F 'getenv("ACE_CERT_FILE")' "$root/src/service.c" >/dev/null
for secret in cert.pem rsa_private.key certs/server.key; do
	if git -C "$root" ls-files --error-unmatch "$secret" >/dev/null 2>&1; then
		echo "fixed test credential remains tracked: $secret" >&2
		exit 1
	fi
done
