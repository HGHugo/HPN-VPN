//! Protocol performance benchmarks.
//!
//! Run with: `cargo bench --package hpn-core --bench protocol_benchmark`
//!
//! These benchmarks measure:
//! - Header encoding/decoding
//! - Anti-replay window operations
//! - Session encrypt/decrypt (full packet pipeline)
//! - Codec operations

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use hpn_core::crypto::keys::{HandshakeSecret, SharedSecret};
use hpn_core::crypto::{SessionKeys, aead, derive_session_keys};
use hpn_core::protocol::{AntiReplayWindow, HEADER_SIZE, PacketHeader, Session};
use hpn_core::types::{Counter, KeyId, MessageType, SessionId};

/// Create test session keys for benchmarking.
fn test_session_keys() -> SessionKeys {
    let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
    let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
    let hs = HandshakeSecret::combine(&x25519, &mlkem);
    derive_session_keys(&hs).unwrap()
}

/// Benchmark packet header operations.
fn bench_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("Header");

    // Header encoding
    let header = PacketHeader::new(
        MessageType::Data,
        SessionId(0x1234_5678_9ABC_DEF0),
        KeyId(42),
        Counter(12345),
    );

    group.bench_function("encode", |b| {
        let mut buf = [0u8; 32];
        b.iter(|| {
            let size = header.encode(&mut buf).unwrap();
            black_box(size)
        });
    });

    // Header encoding with timestamp
    let header_ts = header.clone().with_timestamp(0xDEAD_BEEF_CAFE_BABE);

    group.bench_function("encode_with_timestamp", |b| {
        let mut buf = [0u8; 32];
        b.iter(|| {
            let size = header_ts.encode(&mut buf).unwrap();
            black_box(size)
        });
    });

    // Header decoding
    let mut encoded = [0u8; 32];
    header.encode(&mut encoded).unwrap();

    group.bench_function("decode", |b| {
        b.iter(|| {
            let h = PacketHeader::decode(&encoded).unwrap();
            black_box(h)
        });
    });

    // Header decoding with timestamp
    let mut encoded_ts = [0u8; 32];
    header_ts.encode(&mut encoded_ts).unwrap();

    group.bench_function("decode_with_timestamp", |b| {
        b.iter(|| {
            let h = PacketHeader::decode(&encoded_ts).unwrap();
            black_box(h)
        });
    });

    // Full roundtrip
    group.bench_function("roundtrip", |b| {
        let mut buf = [0u8; 32];
        b.iter(|| {
            header.encode(&mut buf).unwrap();
            let h = PacketHeader::decode(&buf).unwrap();
            black_box(h)
        });
    });

    group.finish();
}

/// Benchmark anti-replay window operations.
fn bench_anti_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("AntiReplay");

    // Sequential check (best case - always new packets)
    group.bench_function("check_sequential", |b| {
        let window = AntiReplayWindow::new();
        let mut counter = 1u64;
        b.iter(|| {
            let result = window.check_and_update(Counter(counter));
            counter += 1;
            black_box(result)
        });
    });

    // In-window check (packets arriving out of order within window)
    group.bench_function("check_out_of_order", |b| {
        let window = AntiReplayWindow::new();
        // Advance window to counter 1000
        window.check_and_update(Counter(1000));

        // Test checking packets within window (900-999)
        let mut counter = 900u64;
        b.iter(|| {
            // Reset window state for consistent benchmark
            let result = window.check(Counter(counter));
            counter = if counter >= 999 { 900 } else { counter + 1 };
            black_box(result)
        });
    });

    // Check-only (no update) - for packet validation before decryption
    group.bench_function("check_only", |b| {
        let window = AntiReplayWindow::new();
        let mut counter = 1u64;
        b.iter(|| {
            let result = window.check(Counter(counter));
            counter += 1;
            black_box(result)
        });
    });

    // Large window jump (simulating packet loss)
    group.bench_function("large_jump", |b| {
        let window = AntiReplayWindow::new();
        let mut counter = 1u64;
        b.iter(|| {
            let result = window.check_and_update(Counter(counter));
            counter += 200; // Jump 200 packets
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark session packet encryption/decryption.
fn bench_session_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("SessionPacket");

    // Test various payload sizes relevant to VPN traffic
    let sizes = [64, 128, 256, 512, 1024, 1420, 2048, 4096];

    for size in &sizes {
        let keys = test_session_keys();
        let session_id = SessionId::generate();
        let client_session = Session::new(session_id, keys.clone()).unwrap();
        let _server_session = Session::new(session_id, keys.swap()).unwrap();

        let payload = vec![0xABu8; *size];
        let packet_size = HEADER_SIZE + *size + aead::TAG_SIZE;

        group.throughput(Throughput::Bytes(*size as u64));

        // Encryption benchmark
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            let mut output = vec![0u8; packet_size + 100];
            b.iter(|| {
                let len = client_session
                    .encrypt_packet(MessageType::Data, &payload, &mut output)
                    .unwrap();
                black_box(len)
            });
        });

        // Prepare encrypted packet for decryption benchmark
        let mut encrypted_packet = vec![0u8; packet_size + 100];
        let _packet_len = client_session
            .encrypt_packet(MessageType::Data, &payload, &mut encrypted_packet)
            .unwrap();

        // For decryption, we need fresh sessions each iteration due to anti-replay
        // So we measure the decrypt_packet operation on unique packets
        let keys = test_session_keys();
        let encrypt_session = Session::new(session_id, keys.clone()).unwrap();
        let decrypt_session = Session::new(session_id, keys.swap()).unwrap();

        // Pre-generate multiple unique packets
        let num_packets = 10000;
        let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);
        for _ in 0..num_packets {
            let mut pkt = vec![0u8; packet_size + 100];
            let len = encrypt_session
                .encrypt_packet(MessageType::Data, &payload, &mut pkt)
                .unwrap();
            pkt.truncate(len);
            packets.push(pkt);
        }

        let mut packet_idx = 0usize;
        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, _| {
            let mut output = vec![0u8; *size];
            b.iter(|| {
                let pkt = &packets[packet_idx % num_packets];
                // Note: This will hit anti-replay after first pass, measuring header decode + decrypt attempt
                let result = decrypt_session.decrypt_packet(pkt, &mut output);
                packet_idx = packet_idx.wrapping_add(1);
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark full packet pipeline throughput.
fn bench_pipeline_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("PipelineThroughput");
    group.sample_size(50);

    // Typical VPN packet size (MTU - overhead)
    let packet_size = 1420;
    let packets_per_batch = 64;
    let batch_size = packet_size * packets_per_batch;

    let keys = test_session_keys();
    let session_id = SessionId::generate();

    let payload = vec![0xABu8; packet_size];
    let output_size = HEADER_SIZE + packet_size + aead::TAG_SIZE + 100;

    group.throughput(Throughput::Bytes(batch_size as u64));

    // Encrypt batch
    group.bench_function("encrypt_batch", |b| {
        let session = Session::new(session_id, keys.clone()).unwrap();
        let mut output = vec![0u8; output_size];

        b.iter(|| {
            for _ in 0..packets_per_batch {
                let len = session
                    .encrypt_packet(MessageType::Data, &payload, &mut output)
                    .unwrap();
                black_box(len);
            }
        });
    });

    // Decrypt batch (pre-generate packets)
    let encrypt_session = Session::new(session_id, keys.clone()).unwrap();
    let mut packets: Vec<Vec<u8>> = Vec::with_capacity(packets_per_batch * 100);
    for _ in 0..packets_per_batch * 100 {
        let mut pkt = vec![0u8; output_size];
        let len = encrypt_session
            .encrypt_packet(MessageType::Data, &payload, &mut pkt)
            .unwrap();
        pkt.truncate(len);
        packets.push(pkt);
    }

    let mut batch_idx = 0usize;
    group.bench_function("decrypt_batch", |b| {
        let decrypt_session = Session::new(session_id, keys.swap()).unwrap();
        let mut output = vec![0u8; packet_size];

        b.iter(|| {
            let start = (batch_idx * packets_per_batch) % (packets.len() - packets_per_batch);
            for i in 0..packets_per_batch {
                let pkt = &packets[start + i];
                let result = decrypt_session.decrypt_packet(pkt, &mut output);
                let _ = black_box(result);
            }
            batch_idx = batch_idx.wrapping_add(1);
        });
    });

    group.finish();
}

/// Benchmark header creation variations.
fn bench_header_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("HeaderCreation");

    group.bench_function("new_data", |b| {
        b.iter(|| {
            let h = PacketHeader::new(
                MessageType::Data,
                SessionId(0x1234_5678_9ABC_DEF0),
                KeyId(1),
                Counter(100),
            );
            black_box(h)
        });
    });

    #[allow(clippy::cast_possible_truncation)]
    group.bench_function("new_with_timestamp", |b| {
        b.iter(|| {
            let h = PacketHeader::new(
                MessageType::Keepalive,
                SessionId(0x1234_5678_9ABC_DEF0),
                KeyId(1),
                Counter(100),
            )
            .with_timestamp(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as u64,
            );
            black_box(h)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_header,
    bench_anti_replay,
    bench_session_packet,
    bench_pipeline_throughput,
    bench_header_creation,
);

criterion_main!(benches);
