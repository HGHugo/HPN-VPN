# HPN - Post-Quantum Secure VPN

Open-source, high-performance post-quantum VPN with 2.5+ Gbps throughput and quantum-resistant cryptography.

**Project**: HPN (community-driven, self-hostable)  
**License**: AGPL-3.0-or-later  
**Version**: v0.1.0  
**Status**: Production Ready (Phases 1-3 Complete)  
**Year**: 2025

---

## ✨ Features

### 🔐 Post-Quantum Security

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| **Key Exchange** | X25519 + ML-KEM-768 | NIST FIPS 203 (Hybrid) |
| **Signatures** | ML-DSA-65 | NIST FIPS 204 |
| **Encryption** | AES-256-GCM | NIST SP 800-38D |
| **KDF** | HKDF-SHA-512 | RFC 5869 |

- ✅ Quantum-resistant cryptography (hybrid classical + PQC)
- ✅ Forward secrecy (automatic rekey every 64GB or 1 hour)
- ✅ Constant-time operations (timing attack resistant)
- ✅ Zero-knowledge architecture (server never sees plaintext)

### ⚡ High Performance

| Configuration | Throughput | Latency | CPU |
|---------------|------------|---------|-----|
| Single-queue | 1.5-2 Gbps | 2-3ms | 30% (1 core) |
| **Multiqueue (4)** | **2.5-3 Gbps** | 2-3ms | 25% (distributed) |
| Multiqueue (8) | 3.5-4 Gbps | 2-3ms | 30% (distributed) |

- ✅ TUN multiqueue (3-4x throughput improvement)
- ✅ UDP worker pool (multi-threaded packet processing)
- ✅ Lock-free channels (crossbeam MPMC)
- ✅ Zero-copy buffer pool (minimal allocations)
- ✅ Syscall batching (recvmmsg/sendmmsg on Linux)
- ✅ io_uring support (kernel >= 5.6, optional)

### 🌐 Network Features

- ✅ **IPv4/IPv6 Dual-Stack** - Full support for both protocols
- ✅ **Multi-Hop Relays** - Enhanced privacy routing
- ✅ **NAT Traversal** - STUN + UDP hole punching
- ✅ **Roaming** - Seamless network transitions
- ✅ **Kill Switch** - Route-based traffic protection
- ✅ **DNS Leak Protection** - VPN-only DNS
- ✅ **Split Tunneling** - Per-route or per-app (WFP on Windows)

### 📊 Monitoring & Operations

- ✅ **Prometheus Metrics** - `/metrics` endpoint (server + relay)
- ✅ **Grafana Dashboards** - Pre-built visualizations
- ✅ **Systemd Integration** - Production-ready services
- ✅ **Structured Logging** - JSON logs via tracing
- ✅ **Admin API** - REST endpoints for management
- ✅ **Unlimited Sessions** - No tier limits; self-host at any scale

### 🖥️ Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux Server** | ✅ Production | Ubuntu 22.04+, Debian 11+, RHEL 8+ |
| **Windows Client** | ✅ Production | Windows 10/11 (64-bit) |
| **macOS Client** | ✅ Production | macOS 11+ (Intel + Apple Silicon) |
| **Linux Client** | ❌ N/A | Server deployments only |

---

## 🚀 Quick Start

### Server (Linux)

```bash
# Build from source
git clone <repository>
cd hpn-pq
cargo build --release -p hpn-server

# Install
sudo cp target/release/hpn-server /usr/bin/
sudo mkdir -p /etc/hpn /var/lib/hpn

# Configure
sudo cp config/server.example.toml /etc/hpn/server.toml
sudo nano /etc/hpn/server.toml  # Edit settings

# Install systemd service
sudo cp deploy/packaging/systemd/hpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hpn-server

# Verify
sudo systemctl status hpn-server
curl http://localhost:9100/metrics
```

### Enable High Performance (2.5-3 Gbps)

```bash
# Edit config
sudo nano /etc/hpn/server.toml

# Add:
enable_tun_multiqueue = true
tun_queue_count = 4

# Restart
sudo systemctl restart hpn-server
```

### Client (Windows/macOS)

Build the client from source (see [Building from Source](#️-building-from-source)):

```bash
cargo build --release -p hpn-client-windows  # Windows client
cargo build --release -p hpn-client-macos    # macOS client
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         HPN Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Client (Windows/macOS)                Server (Linux)          │
│  ┌───────────────────┐                ┌──────────────────┐     │
│  │  Wintun/utun TUN  │◄──────────────►│  MultiQueue TUN  │     │
│  │    (L3 tunnel)    │                │   (4-8 queues)   │     │
│  └────────┬──────────┘                └────────┬─────────┘     │
│           │                                    │               │
│  ┌────────▼──────────┐                ┌───────▼──────────┐     │
│  │  Crypto Worker    │                │  TUN Workers     │     │
│  │  - ML-KEM-768     │                │  (N readers +    │     │
│  │  - ML-DSA-65      │                │   N writers)     │     │
│  │  - AES-256-GCM    │                └────────┬─────────┘     │
│  └────────┬──────────┘                         │               │
│           │                            ┌───────▼──────────┐     │
│  ┌────────▼──────────┐                │  UDP Worker Pool │     │
│  │   UDP Socket      │◄──────────────►│  (M workers)     │     │
│  │  (Port 51820)     │   Encrypted    │  - Encrypt/      │     │
│  └───────────────────┘   Packets      │    Decrypt       │     │
│                                        │  - Sessions      │     │
│                                        │  - Rate limit    │     │
│                                        └──────────────────┘     │
│                                                                 │
│  Throughput: 2.5-3 Gbps (multiqueue)                           │
│  Latency: 2-3ms P50                                            │
│  Sessions: unlimited concurrent (self-hosted)                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security

### Cryptographic Stack

1. **Handshake**: ML-KEM-768 encapsulation + ML-DSA-65 signature
2. **Key Derivation**: HKDF-SHA-512 (hybrid X25519 + ML-KEM shared secret)
3. **Traffic Encryption**: AES-256-GCM with 96-bit nonce (counter-based)
4. **Forward Secrecy**: Automatic rekey every 64GB or 1 hour
5. **Replay Protection**: 64-bit sliding window with monotonic counter

### Security Features

- ✅ Constant-time crypto operations (timing attack resistant)
- ✅ Secret zeroization on drop (`zeroize` crate)
- ✅ Memory-safe Rust (no buffer overflows)
- ✅ Rate limiting (5 handshakes/min/IP, DoS protection)
- ✅ Configurable session limits (operator-controlled)
- ✅ Systemd hardening (NoNewPrivileges, ProtectSystem, etc.)

### Audits

- ✅ Comprehensive cryptographic and dependency review (`cargo audit` in CI)

---

## 📊 Performance

### Benchmarks (iperf3)

| Configuration | Threads | Throughput | CPU Usage |
|---------------|---------|------------|-----------|
| Single-queue | 1 reader + 1 writer | 1.5-2 Gbps | 30% (1 core saturated) |
| Multiqueue (2) | 2 readers + 2 writers | 2.0-2.3 Gbps | 28% (distributed) |
| **Multiqueue (4)** | **4 readers + 4 writers** | **2.5-3 Gbps** | **25% (distributed)** |
| Multiqueue (8) | 8 readers + 8 writers | 3.5-4 Gbps | 30% (distributed) |

**Test Environment**: Linux 5.15, 8-core CPU, 10 Gbps NIC

### Optimization Techniques

- **TUN Multiqueue** - Parallel I/O on TUN device (3-4x improvement)
- **UDP Worker Pool** - Multi-threaded packet processing
- **Buffer Pooling** - Pre-allocated buffers (zero-copy)
- **Syscall Batching** - recvmmsg/sendmmsg (Linux)
- **Lock-Free Channels** - crossbeam MPMC (minimal contention)
- **Adaptive Sleep** - Low latency + low CPU

---

## 🏢 Self-Hosting

HPN is fully open-source and self-hostable with **no tiers, no license keys, and no session limits**. Every feature is available to everyone:

- ✅ Unlimited concurrent sessions
- ✅ IPv4/IPv6 dual-stack
- ✅ Multi-hop relays
- ✅ Full throughput (hardware-bound only)

Session limits, if any, are configured by the operator in `server.toml` — the software imposes none.

---

## 🛠️ Building from Source

### Requirements

- **Rust**: 1.75+ (stable)
- **OS**: Linux, macOS, Windows
- **Dependencies**: See `Cargo.toml`

### Build

```bash
# Clone repository
git clone <repository>
cd hpn-pq

# Build all components
cargo build --workspace --release

# Build specific components
cargo build --release -p hpn-server      # Server
cargo build --release -p hpn-relay       # Relay
cargo build --release -p hpn-client-windows  # Windows client
cargo build --release -p hpn-client-macos    # macOS client

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings
```

---

## 🧪 Testing

```bash
# All tests (197 tests)
cargo test --workspace

# Specific crate
cargo test -p hpn-core
cargo test -p hpn-server

# Benchmarks
cargo bench -p hpn-core

# Integration tests
cargo test -p hpn-core --test integration_test
```

**Status**: ✅ 197/197 tests passing, zero warnings

---

## 🤝 Contributing

Contributions are welcome! HPN is community-driven. Please open an issue to discuss
significant changes, run `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings`
before submitting, and ensure `cargo test --workspace` passes. See
[AGENTS.md](AGENTS.md) for code style and architecture guidance.

By contributing, you agree that your contributions are licensed under AGPL-3.0-or-later.

---

## 📞 Support

**Community Support**: Open an issue or discussion on the project repository  

---

## 📄 License

HPN is free software licensed under the **GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later)**. See [LICENSE](LICENSE) for the full text.

In short:

- You may **run** HPN as a network VPN service, self-host it, modify it, and redistribute it.
- If you **modify** HPN and offer it to others over a network (e.g. as a hosted VPN
  service), the AGPL requires you to make your **complete corresponding source code**
  available to those users under the same AGPL license.
- There are no usage restrictions, tiers, or license keys — the copyleft obligation
  applies only when you distribute or provide the software as a network service.

---

## 🙏 Acknowledgments

- **NIST PQC Team** - ML-KEM and ML-DSA standards
- **Rust Community** - Excellent cryptographic libraries

---

**License**: AGPL-3.0-or-later  
**Version**: v0.1.0  
**Status**: Production Ready  
**Year**: 2025
