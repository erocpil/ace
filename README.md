## About ACE

ACE is a QUIC-based client/server framework written in C, built on top of [lsquic](https://github.com/litespeedtech/lsquic) (LiteSpeed QUIC library) and [libev](http://software.schmorp.de/pkg/libev.html). It provides:

1. **Layered design** — shields upper-layer services from QUIC protocol details and event-loop internals.
2. **Optimized I/O** — tuned network and disk paths for high-throughput QUIC transfers.
3. **Customizable service interface** — plug in your own upstream handlers via the service layer.
4. **Debugging modules** — built-in `alpha` debug binary, feature libraries, and scripts.

The framework targets near-gigabit line speed on commodity hardware.

## Architecture

![Architecture](images/architecture.png)

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| [lsquic](https://github.com/litespeedtech/lsquic) | **v3.3.1** | Linked via BoringSSL |
| [BoringSSL](https://boringssl.googlesource.com/boringssl) | **API version 18** | TLS stack for lsquic |
| [libev](http://software.schmorp.de/pkg/libev.html) | **v4.33** | Event loop |
| libmagic | system | File type detection |
| CMake ≥ 3.10, GCC/Clang, Go | system | Build toolchain; Go is needed to build BoringSSL |

Pre-built static libraries (`.a`) matching these exact versions live under `lib/{x86_64,aarch64}/`. The headers that lock these API versions are under `include/`.

## Quick Start

### 1. Build dependencies

```bash
# Build lsquic, BoringSSL, and libev. Products land in lib/x86_64/ (or lib/aarch64/).
bash scripts/build-deps.sh
```

The script detects your architecture and builds everything from source. Requires: `cmake`, `make`, `gcc`, `git`, `curl`, `perl`, `go`.

**If GitHub is unreachable**, the script falls back to mirrors (gitee). You may need to manually supply submodule content for lsquic (ls-qpack, ls-hpack) under `.deps/lsquic/`.

### 2. Generate TLS certificate

The server requires a certificate for QUIC TLS handshakes:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=localhost"
```

### 3. Build ACE

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Produces:
- `build/src/ace` — main binary (17 MB, with debug symbols)
- `build/src/alpha` — debug helper (192 KB)

### 4. Smoke test

```bash
bash scripts/smoke-test.sh
```

Verifies: server starts, binds UDP, client initializes, both exit cleanly.

### 5. Run manually

**Server:**
```bash
./build/src/ace 1
```

Binds UDP port 12345, waits for client connections.

**Client:**
```bash
./build/src/ace 0
```

The client initializes the QUIC engine and upstream socket but does not yet
actively initiate a connection (see [Current Status](#current-status)).

**Telnet control interface** (client side, port 9999):
```bash
telnet 127.0.0.1 9999
```

Commands:
```
sf 3 tmp/100m.dat    # send file with 3 streams
perf 1 1             # performance benchmark
```

## Project Layout

```
ace/
├── CMakeLists.txt         # Top-level CMake
├── src/                   # Source + per-component CMakeLists
│   ├── ace.c              # Main entry point
│   ├── server.c           # Server logic
│   ├── client.c           # Client logic
│   ├── service.c          # Service layer (QUIC callbacks)
│   ├── connote.c          # Connection note
│   ├── config.c           # Configuration
│   ├── upstream.c         # Upstream gateway
│   ├── task.c             # Task management
│   ├── runner.c           # Event loop + signal handling (shared)
│   └── alpha.c            # Debug/test binary
├── include/               # Dependency headers (version-locked)
│   ├── lsquic/            # lsquic v3.3.1 API headers
│   ├── libev/             # libev v4.33 API headers
│   └── file/              # libmagic headers
├── lib/                   # Pre-built static libraries
│   ├── x86_64/            # amd64: liblsquic.a, libssl.a, libcrypto.a, libev.a
│   └── aarch64/           # arm64
├── .deps/                 # Dependency source trees (build-deps.sh workspace)
├── scripts/
│   ├── build-deps.sh      # Build lsquic + BoringSSL + libev
│   └── smoke-test.sh      # Minimal server/client smoke test
├── images/                # Architecture + perf screenshots
├── cert.pem / key.pem     # TLS certificate + private key (gitignored)
└── .gitignore
```

## Current Status

**Compiles and links** on x86_64 with lsquic v3.3.1 + BoringSSL API v18 + libev v4.33.

| Check | Status |
|---|---|
| Compile (ace + alpha) | ✓ |
| Server start + bind UDP :12345 | ✓ |
| Server TLS cert loading | ✓ |
| Server graceful shutdown (SIGTERM) | ✓ |
| Client init + upstream socket | ✓ |
| Smoke test infrastructure | ✓ |
| End-to-end QUIC data path | ✗ (client needs explicit `lsquic_engine_connect` call) |

**Known limitation:** The client initializes the QUIC engine but does not yet
actively dial the server. The `service_connect()` function exists in the code
but is not wired into any trigger path. This is the next item on the roadmap.

## Platforms

- x86_64 (tested)
- aarch64 (link path configured, not tested)

## Changes

See the [commit history](https://github.com/erocpil/ace/commits/main).

Recent improvements:

- **Bug fixes** — `server_timeout_cb` / `client_timeout_cb` type errors, cross-thread libev loop access, `ev_timer_init` data field wipe
- **Error handling** — replaced all `exit()` calls with error returns (14 sites)
- **Memory safety** — `inet_ntoa` → `inet_ntop`, config owner field separation
- **Code cleanup** — removed dead `#if 0` blocks, fixed `ace_hash_del` logic
- **Graceful shutdown** — signal handler with `ev_break`, extracted `runner.c`
- **Build system** — `scripts/build-deps.sh` for reproducible dependency builds

## TODO

1. Wire client `lsquic_engine_connect` path for end-to-end QUIC communication.
2. Bidirectional data flow support.
3. More comprehensive upstream gateway.
4. Any feedback is appreciated.
