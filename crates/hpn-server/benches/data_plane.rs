//! Data-plane micro-benchmarks for the HPN server hot path.
//!
//! These benchmarks measure the cumulative cost of the operations the
//! UDP receiver worker performs on every inbound encrypted packet:
//!
//!   1. Parse the wire header (12 bytes, version + type + `session_id` +
//!      `key_id` + counter).
//!   2. AES-256-GCM decrypt the payload in place (the cost-dominant step;
//!      this is what `target-cpu=x86-64-v3 + AES-NI/AVX2` accelerates).
//!   3. Update the per-worker `WorkerStats` counters (4 cross-thread
//!      atomic adds; this is what `CachePadded` accelerates by removing
//!      false sharing between counters).
//!
//! Run with:
//!
//! ```sh
//! cargo bench --package hpn-server --bench data_plane
//! ```
//!
//! Captures a baseline for the Tier 2 perf patch (mimalloc allocator,
//! `target-cpu=x86-64-v3 + AES-NI`, CPU-pinned workers, `CachePadded`
//! atomics). Comparing two runs across the patch boundary gives a
//! ground-truth gain figure rather than guesswork.
//!
//! `harness = false` so we use criterion's own runner.
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crossbeam_utils::CachePadded;

use hpn_core::crypto::aead;
use hpn_core::protocol::header::{HEADER_SIZE, PacketHeader};
use hpn_core::types::{Counter, KeyId, MessageType, SessionId};

/// Local stand-in for `hpn_server::udp_workers::WorkerStats`.
///
/// We do NOT import `WorkerStats` directly because that module is
/// gated `#[cfg(target_os = "linux")]` and we want this benchmark to
/// build (and produce useful numbers) on macOS / Windows developer
/// laptops as well. The struct mirrors the production `WorkerStats`
/// field-for-field, including the `CachePadded` wrapping that is the
/// whole point of the Tier 2 perf patch.
struct LocalStats {
    packets_received: CachePadded<AtomicU64>,
    batches_received: CachePadded<AtomicU64>,
    packets_sent: CachePadded<AtomicU64>,
    batches_sent: CachePadded<AtomicU64>,
}

impl Default for LocalStats {
    fn default() -> Self {
        Self {
            packets_received: CachePadded::new(AtomicU64::new(0)),
            batches_received: CachePadded::new(AtomicU64::new(0)),
            packets_sent: CachePadded::new(AtomicU64::new(0)),
            batches_sent: CachePadded::new(AtomicU64::new(0)),
        }
    }
}

/// Build a header for a synthetic data packet and serialize it.
fn fresh_header(counter: u64) -> [u8; HEADER_SIZE] {
    let header = PacketHeader::new(
        MessageType::Data,
        SessionId(0xDEAD_BEEF_CAFE_F00D),
        KeyId::initial(),
        Counter(counter),
    );
    let mut buf = [0u8; HEADER_SIZE];
    header.encode(&mut buf).expect("header fits");
    buf
}

/// Bench `PacketHeader::decode` in isolation. Trivial baseline; the
/// actual cost should be a few ns per packet — useful to confirm that
/// the more expensive AEAD step below dominates the rest of the path.
fn bench_header_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_plane/header");
    group.throughput(Throughput::Elements(1));

    let buf = fresh_header(0);
    group.bench_function("decode", |b| {
        b.iter(|| {
            let h = PacketHeader::decode(black_box(&buf[..])).expect("valid header");
            black_box(h)
        });
    });

    group.finish();
}

/// Bench the AES-256-GCM decrypt step at the typical VPN packet sizes.
/// This is the part that benefits most from `target-cpu=x86-64-v3`
/// (AES-NI key schedule + AVX2 GHASH).
fn bench_aead_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_plane/aead_decrypt");

    // Sizes mirror the wire packet sizes the data plane sees:
    //   - 64 B   small (keepalives, pings)
    //   - 1420 B typical IPv4 MTU minus VPN overhead (the dominant case)
    //   - 9000 B jumbo frame
    //
    // Use `usize` for the loop variable; we widen to `u64` only when
    // criterion's `Throughput::Bytes` API requires it. This avoids the
    // pedantic cast-may-truncate clippy warning on 32-bit targets.
    for size in [64usize, 256, 1420, 4096, 9000] {
        let key = [0x42u8; 32];
        let nonce_prefix = [0u8; 4];
        let plaintext = vec![0u8; size];
        let aad = b"hdr"; // Realistic AAD = parsed header bytes.

        // Pre-encrypt so the bench measures decryption only.
        let mut ciphertext = vec![0u8; size + aead::TAG_SIZE];
        aead::encrypt(&key, &nonce_prefix, 0, aad, &plaintext, &mut ciphertext)
            .expect("encrypt OK");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let mut output = vec![0u8; size + aead::TAG_SIZE];
            b.iter(|| {
                let n = aead::decrypt(&key, &nonce_prefix, 0, aad, &ciphertext, &mut output)
                    .expect("decrypt OK");
                black_box(n)
            });
        });
    }

    group.finish();
}

/// Bench the cumulative hot-path: header decode + AEAD decrypt +
/// stats counter updates. This is what each UDP receiver worker
/// runs per packet. Measuring it as a unit captures interactions
/// between the three optimisations (target-cpu, `CachePadded`, and
/// `LocalWorkerStats` batching) better than the isolated benches.
fn bench_full_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_plane/hot_path");

    let key = [0x42u8; 32];
    let nonce_prefix = [0u8; 4];
    let plaintext = vec![0u8; 1420]; // Typical MTU.
    let aad = fresh_header(0);
    let mut ciphertext = vec![0u8; plaintext.len() + aead::TAG_SIZE];
    aead::encrypt(&key, &nonce_prefix, 0, &aad, &plaintext, &mut ciphertext).expect("encrypt OK");

    // One byte payload as well as a full-MTU packet — both are realistic
    // and allocate differently on the buffer pool.
    let stats = Arc::new(LocalStats::default());

    group.throughput(Throughput::Bytes(1420));
    group.bench_function("decode_decrypt_counters_1420", |b| {
        let mut output = vec![0u8; ciphertext.len()];
        let mut iter_count: u64 = 0;
        b.iter(|| {
            // Step 1: parse header.
            let header = PacketHeader::decode(black_box(&aad[..])).expect("valid");
            // Step 2: AEAD-decrypt the payload.
            let n =
                aead::decrypt(&key, &nonce_prefix, 0, &aad, &ciphertext, &mut output).expect("ok");
            // Step 3: update worker stats — `packets_received` per packet,
            // `batches_received` once every 64 packets to mirror the real
            // recvmmsg(BATCH=64) cadence in `udp_workers::run_receiver_worker`.
            stats.packets_received.fetch_add(1, Ordering::Relaxed);
            iter_count = iter_count.wrapping_add(1);
            if iter_count.is_multiple_of(64) {
                stats.batches_received.fetch_add(1, Ordering::Relaxed);
            }
            black_box((header, n));
        });
    });

    group.finish();
}

/// Bench the cost of the `WorkerStats` updates in isolation. With
/// `CachePadded` the four counters live on separate cache lines so two
/// threads can update independent counters without invalidating each
/// other's lines; without padding the counters share a line and every
/// cross-core update triggers an MESI cascade. This bench runs in a
/// single thread but measures the total cost of the four atomic
/// `fetch_add`s — a useful baseline for the multi-threaded case
/// (which criterion does not support directly).
fn bench_stats_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_plane/stats");

    let stats = Arc::new(LocalStats::default());
    group.bench_function("four_counter_update", |b| {
        b.iter(|| {
            stats.packets_received.fetch_add(1, Ordering::Relaxed);
            stats.batches_received.fetch_add(1, Ordering::Relaxed);
            stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            stats.batches_sent.fetch_add(1, Ordering::Relaxed);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_header_decode,
    bench_aead_decrypt,
    bench_full_hot_path,
    bench_stats_updates,
);
criterion_main!(benches);
