#!/bin/sh
set -eu

script=${1:-scripts/build-deps.sh}

grep -F 'checkout "${BSSL_COMMIT}"' "$script" >/dev/null
grep -F 'BSSL_COMMIT="955ef7991e41ac6c0ea5114b4b9abb98cc5fd614"' "$script" >/dev/null
grep -F 'git fetch --depth 1 origin "$BSSL_COMMIT"' "$script" >/dev/null
grep -F -- '-DCMAKE_C_FLAGS=-Wno-error=stringop-overflow' "$script" >/dev/null
grep -F 'MIRROR="${MIRROR:-github}"' "$script" >/dev/null
grep -F 'submodule update --init --recursive' "$script" >/dev/null
grep -F 'LIBEV_SHA256="507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea"' "$script" >/dev/null
grep -F 'sha256sum -c -' "$script" >/dev/null
grep -F 'LSQUIC_COMMIT="b373fe522048a6885b0cdeebfa583a61dee2ff1f"' "$script" >/dev/null
if grep -F 'GIT_SSL_NO_VERIFY' "$script" >/dev/null; then
	echo "dependency bootstrap disables TLS certificate validation" >&2
	exit 1
fi
if grep -F 'checkout "${BSSL_COMMIT}^"' "$script" >/dev/null; then
	echo "build-deps.sh selects the parent of the API v18 commit" >&2
	exit 1
fi
if grep -F -- '--deepen=' "$script" >/dev/null; then
	echo "build-deps.sh uses a history-depth window for a pinned commit" >&2
	exit 1
fi
