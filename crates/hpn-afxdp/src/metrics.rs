//! Prometheus metrics for AF_XDP.
//!
//! This module provides metrics collection for monitoring AF_XDP performance.

use std::sync::atomic::{AtomicU64, Ordering};

use prometheus::{
    IntCounterVec, IntGaugeVec, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry,
};
use tracing::warn;

use crate::datapath::BatchStats;
use crate::socket::SocketStats;

/// AF_XDP metrics collector.
///
/// Provides Prometheus metrics for monitoring AF_XDP socket performance.
pub struct AfXdpMetrics {
    /// Packets received counter.
    rx_packets: IntCounterVec,
    /// Packets transmitted counter.
    tx_packets: IntCounterVec,
    /// Bytes received counter.
    rx_bytes: IntCounterVec,
    /// Bytes transmitted counter.
    tx_bytes: IntCounterVec,
    /// Decryption errors counter.
    decrypt_errors: IntCounterVec,
    /// Unknown session drops counter.
    unknown_session: IntCounterVec,
    /// Replay attack drops counter.
    replay_drops: IntCounterVec,
    /// Header parse errors counter.
    header_errors: IntCounterVec,
    /// Kernel-reported drops gauge.
    kernel_drops: IntGaugeVec,
    /// UMEM available frames gauge.
    umem_available: IntGaugeVec,
    /// Fill ring free slots gauge.
    fill_ring_free: IntGaugeVec,
    /// RX ring available gauge.
    rx_ring_available: IntGaugeVec,
    /// TX ring free gauge.
    tx_ring_free: IntGaugeVec,
}

impl AfXdpMetrics {
    /// Create new metrics registered with the given registry.
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let rx_packets = register_int_counter_vec_with_registry!(
            "afxdp_rx_packets_total",
            "Total packets received via AF_XDP",
            &["queue"],
            registry
        )?;

        let tx_packets = register_int_counter_vec_with_registry!(
            "afxdp_tx_packets_total",
            "Total packets transmitted via AF_XDP",
            &["queue"],
            registry
        )?;

        let rx_bytes = register_int_counter_vec_with_registry!(
            "afxdp_rx_bytes_total",
            "Total bytes received via AF_XDP",
            &["queue"],
            registry
        )?;

        let tx_bytes = register_int_counter_vec_with_registry!(
            "afxdp_tx_bytes_total",
            "Total bytes transmitted via AF_XDP",
            &["queue"],
            registry
        )?;

        let decrypt_errors = register_int_counter_vec_with_registry!(
            "afxdp_decrypt_errors_total",
            "Total decryption errors",
            &["queue"],
            registry
        )?;

        let unknown_session = register_int_counter_vec_with_registry!(
            "afxdp_unknown_session_drops_total",
            "Packets dropped due to unknown session",
            &["queue"],
            registry
        )?;

        let replay_drops = register_int_counter_vec_with_registry!(
            "afxdp_replay_drops_total",
            "Packets dropped due to replay detection",
            &["queue"],
            registry
        )?;

        let header_errors = register_int_counter_vec_with_registry!(
            "afxdp_header_errors_total",
            "Packets dropped due to header parse errors",
            &["queue"],
            registry
        )?;

        let kernel_drops = register_int_gauge_vec_with_registry!(
            "afxdp_kernel_drops",
            "Packets dropped by kernel",
            &["queue"],
            registry
        )?;

        let umem_available = register_int_gauge_vec_with_registry!(
            "afxdp_umem_available_frames",
            "Available UMEM frames",
            &["queue"],
            registry
        )?;

        let fill_ring_free = register_int_gauge_vec_with_registry!(
            "afxdp_fill_ring_free_slots",
            "Free slots in fill ring",
            &["queue"],
            registry
        )?;

        let rx_ring_available = register_int_gauge_vec_with_registry!(
            "afxdp_rx_ring_available",
            "Available entries in RX ring",
            &["queue"],
            registry
        )?;

        let tx_ring_free = register_int_gauge_vec_with_registry!(
            "afxdp_tx_ring_free_slots",
            "Free slots in TX ring",
            &["queue"],
            registry
        )?;

        Ok(Self {
            rx_packets,
            tx_packets,
            rx_bytes,
            tx_bytes,
            decrypt_errors,
            unknown_session,
            replay_drops,
            header_errors,
            kernel_drops,
            umem_available,
            fill_ring_free,
            rx_ring_available,
            tx_ring_free,
        })
    }

    /// Update metrics from batch stats.
    pub fn update_batch_stats(&self, queue: u32, stats: &BatchStats) {
        let queue_str = queue.to_string();

        self.rx_packets
            .with_label_values(&[&queue_str])
            .inc_by(stats.rx_packets);
        self.tx_packets
            .with_label_values(&[&queue_str])
            .inc_by(stats.tx_packets);
        self.rx_bytes
            .with_label_values(&[&queue_str])
            .inc_by(stats.rx_bytes);
        self.tx_bytes
            .with_label_values(&[&queue_str])
            .inc_by(stats.tx_bytes);
        self.decrypt_errors
            .with_label_values(&[&queue_str])
            .inc_by(stats.decrypt_errors);
        self.unknown_session
            .with_label_values(&[&queue_str])
            .inc_by(stats.unknown_session);
        self.replay_drops
            .with_label_values(&[&queue_str])
            .inc_by(stats.replay_drops);
        self.header_errors
            .with_label_values(&[&queue_str])
            .inc_by(stats.header_errors);
    }

    /// Update metrics from socket stats.
    pub fn update_socket_stats(&self, queue: u32, stats: &SocketStats) {
        let queue_str = queue.to_string();

        self.kernel_drops
            .with_label_values(&[&queue_str])
            .set(stats.rx_dropped as i64);
        self.umem_available
            .with_label_values(&[&queue_str])
            .set(stats.umem_available_frames as i64);
        self.fill_ring_free
            .with_label_values(&[&queue_str])
            .set(stats.fill_ring_free as i64);
        self.rx_ring_available
            .with_label_values(&[&queue_str])
            .set(stats.rx_ring_available as i64);
        self.tx_ring_free
            .with_label_values(&[&queue_str])
            .set(stats.tx_ring_free as i64);
    }
}

/// Lightweight atomic counters for high-frequency updates.
///
/// Use this for fast-path metrics where Prometheus overhead is too high.
/// Periodically sync to Prometheus using `sync_to_prometheus()`.
#[derive(Default)]
pub struct FastMetrics {
    /// RX packets counter.
    pub rx_packets: AtomicU64,
    /// TX packets counter.
    pub tx_packets: AtomicU64,
    /// RX bytes counter.
    pub rx_bytes: AtomicU64,
    /// TX bytes counter.
    pub tx_bytes: AtomicU64,
    /// Decrypt errors counter.
    pub decrypt_errors: AtomicU64,
    /// Unknown session drops.
    pub unknown_session: AtomicU64,
    /// Replay drops.
    pub replay_drops: AtomicU64,
    /// Header errors.
    pub header_errors: AtomicU64,
}

impl FastMetrics {
    /// Create new fast metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a received packet.
    #[inline]
    pub fn record_rx(&self, bytes: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a transmitted packet.
    #[inline]
    pub fn record_tx(&self, bytes: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a decrypt error.
    #[inline]
    pub fn record_decrypt_error(&self) {
        self.decrypt_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an unknown session drop.
    #[inline]
    pub fn record_unknown_session(&self) {
        self.unknown_session.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a replay drop.
    #[inline]
    pub fn record_replay_drop(&self) {
        self.replay_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a header error.
    #[inline]
    pub fn record_header_error(&self) {
        self.header_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get and reset all counters, returning a BatchStats snapshot.
    pub fn snapshot_and_reset(&self) -> BatchStats {
        BatchStats {
            rx_packets: self.rx_packets.swap(0, Ordering::Relaxed),
            tx_packets: self.tx_packets.swap(0, Ordering::Relaxed),
            rx_bytes: self.rx_bytes.swap(0, Ordering::Relaxed),
            tx_bytes: self.tx_bytes.swap(0, Ordering::Relaxed),
            decrypt_errors: self.decrypt_errors.swap(0, Ordering::Relaxed),
            unknown_session: self.unknown_session.swap(0, Ordering::Relaxed),
            replay_drops: self.replay_drops.swap(0, Ordering::Relaxed),
            header_errors: self.header_errors.swap(0, Ordering::Relaxed),
        }
    }

    /// Sync counters to Prometheus metrics.
    pub fn sync_to_prometheus(&self, prom_metrics: &AfXdpMetrics, queue: u32) {
        let stats = self.snapshot_and_reset();
        prom_metrics.update_batch_stats(queue, &stats);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_metrics_default() {
        let metrics = FastMetrics::new();
        assert_eq!(metrics.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.tx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_fast_metrics_record_rx() {
        let metrics = FastMetrics::new();
        metrics.record_rx(100);
        metrics.record_rx(200);

        assert_eq!(metrics.rx_packets.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.rx_bytes.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_fast_metrics_record_tx() {
        let metrics = FastMetrics::new();
        metrics.record_tx(500);

        assert_eq!(metrics.tx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.tx_bytes.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn test_fast_metrics_snapshot_and_reset() {
        let metrics = FastMetrics::new();
        metrics.record_rx(100);
        metrics.record_tx(200);
        metrics.record_decrypt_error();
        metrics.record_unknown_session();
        metrics.record_replay_drop();
        metrics.record_header_error();

        let stats = metrics.snapshot_and_reset();

        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.rx_bytes, 100);
        assert_eq!(stats.tx_bytes, 200);
        assert_eq!(stats.decrypt_errors, 1);
        assert_eq!(stats.unknown_session, 1);
        assert_eq!(stats.replay_drops, 1);
        assert_eq!(stats.header_errors, 1);

        // Counters should be reset
        assert_eq!(metrics.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.tx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_afxdp_metrics_creation() {
        let registry = Registry::new();
        let result = AfXdpMetrics::new(&registry);
        assert!(result.is_ok());
    }

    #[test]
    fn test_afxdp_metrics_update_batch_stats() {
        let registry = Registry::new();
        let metrics = AfXdpMetrics::new(&registry).unwrap();

        let stats = BatchStats {
            rx_packets: 100,
            tx_packets: 50,
            rx_bytes: 10000,
            tx_bytes: 5000,
            decrypt_errors: 2,
            unknown_session: 1,
            replay_drops: 3,
            header_errors: 0,
        };

        // Should not panic
        metrics.update_batch_stats(0, &stats);
    }

    #[test]
    fn test_afxdp_metrics_update_socket_stats() {
        let registry = Registry::new();
        let metrics = AfXdpMetrics::new(&registry).unwrap();

        let stats = SocketStats {
            rx_dropped: 5,
            rx_invalid_descs: 1,
            tx_invalid_descs: 0,
            rx_ring_full: 2,
            rx_fill_ring_empty: 0,
            tx_ring_empty: 1,
            umem_available_frames: 4000,
            fill_ring_free: 2000,
            comp_ring_available: 100,
            rx_ring_available: 50,
            tx_ring_free: 3900,
        };

        // Should not panic
        metrics.update_socket_stats(0, &stats);
    }
}
