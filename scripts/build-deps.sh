#!/bin/bash
# scripts/build-deps.sh — build lsquic, BoringSSL, and libev static libs
#
# Produces: lib/$(uname -m)/{liblsquic.a, libssl.a, libcrypto.a, libev.a}
#
# Versions (matched from vendored headers in include/):
#   lsquic   v3.3.1   (include/lsquic/lsquic.h)
#   BoringSSL API 18  (include/openssl/base.h)
#   libev    v4.33    (include/libev/ev.h)
#
# Prerequisites: cmake, make, gcc/g++, curl, git, perl, go (BoringSSL needs go)
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
log() { printf "${CYAN}[build-deps]${RESET} %s\n" "$*"; }
ok()  { printf "${GREEN}[build-deps]${RESET} %s\n" "$*"; }
die() { printf "${RED}[build-deps]${RESET} %s\n" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPS_DIR="$PROJECT_DIR/.deps"
ARCH="$(uname -m)"
NPROC="$(nproc 2>/dev/null || echo 4)"

case "$ARCH" in
    x86_64|amd64)  ARCH_DIR="x86_64" ;;
    aarch64|arm64) ARCH_DIR="aarch64" ;;
    *)             ARCH_DIR="$ARCH" ;;
esac
LIB_DIR="$PROJECT_DIR/lib/$ARCH_DIR"

# ---- mirror selection ----
MIRROR="${MIRROR:-gitee}"
case "$MIRROR" in
    gitee)
        BORINGSSL_URL="https://gitee.com/mirrors/boringssl.git"
        LSQUIC_URL="https://gitee.com/mirrors/lsquic.git"
        ;;
    *)
        BORINGSSL_URL="https://github.com/google/boringssl.git"
        LSQUIC_URL="https://github.com/litespeedtech/lsquic.git"
        ;;
esac

# ---- tool check ----
for tool in cmake make gcc g++ curl git perl; do
    command -v "$tool" >/dev/null 2>&1 || die "'$tool' not found"
done

mkdir -p "$DEPS_DIR" "$LIB_DIR"
log "Deps dir:   $DEPS_DIR"
log "Output dir: $LIB_DIR"
log "Mirror:     $MIRROR"

# ===========================================================================
# 1. BoringSSL — API version 18
# ===========================================================================
BORINGSSL_DIR="$DEPS_DIR/boringssl"
if [ ! -d "$BORINGSSL_DIR/.git" ]; then
    rm -rf "$BORINGSSL_DIR"
    log "Cloning BoringSSL (shallow)..."
    GIT_SSL_NO_VERIFY=1 git clone --depth 1 "$BORINGSSL_URL" "$BORINGSSL_DIR"
fi

cd "$BORINGSSL_DIR"
log "Finding BoringSSL commit with BORINGSSL_API_VERSION 18..."
BSSL_COMMIT=$(git log --format='%H' --diff-filter=M -1 \
    -S 'BORINGSSL_API_VERSION 18' -- include/openssl/base.h 2>/dev/null || true)

if [ -z "$BSSL_COMMIT" ]; then
    log "API v18 not in shallow clone, deepening history..."
    git fetch --deepen=3000 2>/dev/null || true
    BSSL_COMMIT=$(git log --format='%H' --diff-filter=M -1 \
        -S 'BORINGSSL_API_VERSION 18' -- include/openssl/base.h)
fi
[ -n "$BSSL_COMMIT" ] || die "Cannot find BoringSSL commit with API v18"

log "→ commit ${BSSL_COMMIT:0:12} (parent of v18→v19 bump)"
git -c advice.detachedHead=false checkout "${BSSL_COMMIT}^"
grep -q 'BORINGSSL_API_VERSION 18' include/openssl/base.h \
    || die "Checked out commit does not have API version 18"

BSSL_BUILD="$BORINGSSL_DIR/build"
mkdir -p "$BSSL_BUILD" && cd "$BSSL_BUILD"
log "Configuring BoringSSL..."
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF \
    .. 2>&1 | tail -1

log "Building BoringSSL (-j$NPROC)..."
make -j"$NPROC" ssl crypto 2>&1 | tail -3

cp ssl/libssl.a       "$LIB_DIR/"
cp crypto/libcrypto.a "$LIB_DIR/"
ok "BoringSSL → libssl.a + libcrypto.a"

# ===========================================================================
# 2. libev v4.33
# ===========================================================================
LIBEV_VER="4.33"
LIBEV_DIR="$DEPS_DIR/libev-$LIBEV_VER"
if [ ! -d "$LIBEV_DIR" ]; then
    log "Downloading libev v$LIBEV_VER..."
    curl -fsSL --retry 2 "http://dist.schmorp.de/libev/libev-${LIBEV_VER}.tar.gz" \
        -o "$DEPS_DIR/libev.tar.gz" \
        || curl -fsSL --retry 2 "https://fossies.org/linux/misc/libev-${LIBEV_VER}.tar.gz" \
        -o "$DEPS_DIR/libev.tar.gz" \
        || die "Cannot download libev tarball"
    tar xzf "$DEPS_DIR/libev.tar.gz" -C "$DEPS_DIR"
fi

cd "$LIBEV_DIR"
log "Configuring libev..."
./configure --enable-static --disable-shared 2>&1 | tail -1
log "Building libev..."
make -j"$NPROC" 2>&1 | tail -1
cp .libs/libev.a "$LIB_DIR/"
ok "libev → libev.a"

# ===========================================================================
# 3. lsquic v3.3.1
# ===========================================================================
LSQUIC_DIR="$DEPS_DIR/lsquic"
if [ ! -d "$LSQUIC_DIR/.git" ]; then
    rm -rf "$LSQUIC_DIR"
    log "Cloning lsquic v3.3.1..."
    GIT_SSL_NO_VERIFY=1 git clone --branch v3.3.1 --depth 1 "$LSQUIC_URL" "$LSQUIC_DIR"
fi

LSQUIC_BUILD="$LSQUIC_DIR/build"
mkdir -p "$LSQUIC_BUILD" && cd "$LSQUIC_BUILD"
log "Configuring lsquic..."
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
    -DBORINGSSL_DIR="$BORINGSSL_DIR" \
    -DBORINGSSL_LIB_ssl="$BSSL_BUILD/ssl/libssl.a" \
    -DBORINGSSL_LIB_crypto="$BSSL_BUILD/crypto/libcrypto.a" \
    -DBORINGSSL_INCLUDE="$BORINGSSL_DIR/include" \
    .. 2>&1 | tail -3

log "Building lsquic (-j$NPROC)..."
make -j"$NPROC" lsquic 2>&1 | tail -3

cp src/liblsquic/liblsquic.a "$LIB_DIR/"
ok "lsquic → liblsquic.a"

# ===========================================================================
# Done
# ===========================================================================
ok ""
ok "All static libs → $LIB_DIR/"
ls -lh "$LIB_DIR/"*.a
echo ""
log "Now run:  cd $PROJECT_DIR && mkdir -p build && cd build && cmake .. && make -j"
