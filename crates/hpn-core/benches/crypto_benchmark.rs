//! Cryptographic performance benchmarks.
//!
//! Run with: `cargo bench --package hpn-core --bench crypto_benchmark`
//!
//! These benchmarks measure:
//! - KEM operations (key generation, encapsulation, decapsulation)
//! - Signature operations (signing, verification)
//! - AEAD operations (encryption, decryption)
//! - KDF operations (key derivation)

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use hpn_core::crypto::keys::{HandshakeSecret, SharedSecret};
use hpn_core::crypto::signature::MlDsaKeypair;
use hpn_core::crypto::{HybridKem, aead, derive_session_keys};

/// Benchmark KEM operations.
fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM");

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keypair = HybridKem::generate_keypair().unwrap();
            black_box(keypair)
        });
    });

    // Encapsulation
    let (_, public_key) = HybridKem::generate_keypair().unwrap();

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let result = HybridKem::encapsulate(&public_key).unwrap();
            black_box(result)
        });
    });

    // Decapsulation
    let (secret_key, public_key) = HybridKem::generate_keypair().unwrap();
    let (_, ciphertext) = HybridKem::encapsulate(&public_key).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let secret = HybridKem::decapsulate(&secret_key, &ciphertext).unwrap();
            black_box(secret)
        });
    });

    // Full handshake (encap + decap)
    #[allow(clippy::similar_names)]
    group.bench_function("full_exchange", |b| {
        let (server_secret_key, server_public_key) = HybridKem::generate_keypair().unwrap();

        b.iter(|| {
            // Client encapsulates
            let (client_secret, ciphertext) = HybridKem::encapsulate(&server_public_key).unwrap();
            // Server decapsulates
            let server_secret = HybridKem::decapsulate(&server_secret_key, &ciphertext).unwrap();
            black_box((client_secret, server_secret))
        });
    });

    group.finish();
}

/// Benchmark signature operations.
fn bench_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature");

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keypair = MlDsaKeypair::generate();
            black_box(keypair)
        });
    });

    // Signing (various message sizes)
    let keypair = MlDsaKeypair::generate();

    for size in &[32, 256, 1024, 4096] {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("sign", size), size, |b, _| {
            b.iter(|| {
                let sig = keypair.sign(&message).unwrap();
                black_box(sig)
            });
        });
    }

    // Verification (various message sizes)
    for size in &[32, 256, 1024, 4096] {
        let message = vec![0u8; *size];
        let sig = keypair.sign(&message).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                let result = keypair.verify(&message, &sig);
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark AEAD operations.
fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD");

    // Test various packet sizes relevant to VPN traffic
    let sizes = [64, 128, 256, 512, 1024, 1420, 2048, 4096, 8192, 65536];

    for size in &sizes {
        let key = [0x42u8; 32];
        let iv = [0u8; 4]; // 4-byte counter for nonce construction
        let plaintext = vec![0u8; *size];
        let aad = b"header";

        group.throughput(Throughput::Bytes(*size as u64));

        // Encryption
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            let mut output = vec![0u8; *size + aead::TAG_SIZE];
            b.iter(|| {
                let result = aead::encrypt(&key, &iv, 0, aad, &plaintext, &mut output);
                black_box(result)
            });
        });

        // Decryption
        let mut ciphertext = vec![0u8; *size + aead::TAG_SIZE];
        aead::encrypt(&key, &iv, 0, aad, &plaintext, &mut ciphertext).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, _| {
            let mut output = vec![0u8; *size];
            b.iter(|| {
                let result = aead::decrypt(&key, &iv, 0, aad, &ciphertext, &mut output);
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Create a test handshake secret.
fn test_handshake_secret() -> HandshakeSecret {
    let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
    let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
    HandshakeSecret::combine(&x25519, &mlkem)
}

/// Benchmark KDF operations.
fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("KDF");

    let hs = test_handshake_secret();

    // Derive session keys
    group.bench_function("derive_session_keys", |b| {
        b.iter(|| {
            let keys = derive_session_keys(&hs).unwrap();
            black_box(keys)
        });
    });

    // Derive arbitrary length key
    for output_len in &[32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::new("derive_key", output_len),
            output_len,
            |b, len| {
                b.iter(|| {
                    let mut output = vec![0u8; *len];
                    hpn_core::crypto::kdf::derive_key(&hs, b"label", &mut output).unwrap();
                    black_box(output)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark throughput at target rate (2.5 Gbps).
fn bench_throughput_target(c: &mut Criterion) {
    let mut group = c.benchmark_group("Throughput");
    group.sample_size(50);

    // Typical VPN packet size (MTU - overhead)
    let packet_size = 1420;
    let packets_per_batch = 64;
    let batch_size = packet_size * packets_per_batch;

    let key = [0x42u8; 32];
    let iv = [0u8; 4]; // 4-byte counter for nonce construction
    let aad = b"header";

    // Pre-allocate data
    let plaintext = vec![0u8; packet_size];

    group.throughput(Throughput::Bytes(batch_size as u64));

    group.bench_function("encrypt_batch", |b| {
        let mut ciphertext_buf = vec![0u8; packet_size + aead::TAG_SIZE];
        b.iter(|| {
            for i in 0..packets_per_batch {
                aead::encrypt(&key, &iv, i as u64, aad, &plaintext, &mut ciphertext_buf).unwrap();
            }
            black_box(ciphertext_buf.len())
        });
    });

    // Prepare encrypted data for decryption benchmark
    let mut encrypted_packets: Vec<Vec<u8>> = Vec::with_capacity(packets_per_batch);
    for i in 0..packets_per_batch {
        let mut ct = vec![0u8; packet_size + aead::TAG_SIZE];
        aead::encrypt(&key, &iv, i as u64, aad, &plaintext, &mut ct).unwrap();
        encrypted_packets.push(ct);
    }

    group.bench_function("decrypt_batch", |b| {
        // Buffer must be at least ciphertext size for in-place decryption
        let mut decrypted_buf = vec![0u8; packet_size + aead::TAG_SIZE];
        b.iter(|| {
            for (i, ct) in encrypted_packets.iter().enumerate() {
                aead::decrypt(&key, &iv, i as u64, aad, ct, &mut decrypted_buf).unwrap();
            }
            black_box(decrypted_buf.len())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kem,
    bench_signature,
    bench_aead,
    bench_kdf,
    bench_throughput_target,
);

criterion_main!(benches);
