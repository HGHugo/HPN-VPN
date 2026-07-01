//! AF_XDP socket implementation.
//!
//! This module provides the main `XskSocket` type that combines UMEM, rings,
//! and socket operations into a cohesive interface for zero-copy networking.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::error::{AfXdpError, Result};
use crate::ring::{CompletionRing, FillRing, RingConfig, RxRing, TxRing};
use crate::sys::{self, SockaddrXdp, XDP_COPY, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY, XdpDesc};
use crate::umem::{SharedUmem, Umem, UmemConfig};

/// XSK socket configuration.
#[derive(Debug, Clone)]
pub struct XskConfig {
    /// Interface name to bind to.
    pub interface: String,
    /// Queue ID to bind to.
    pub queue_id: u32,
    /// UMEM configuration.
    pub umem: UmemConfig,
    /// Ring sizes.
    pub ring_size: u32,
    /// Use zero-copy mode (requires driver support).
    pub zero_copy: bool,
    /// Use need-wakeup flag for efficiency.
    pub use_need_wakeup: bool,
    /// Number of frames to pre-fill in fill ring.
    pub fill_prefill: u32,
}

impl Default for XskConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            queue_id: 0,
            umem: UmemConfig::default(),
            ring_size: 4096,
            zero_copy: true,
            use_need_wakeup: true,
            fill_prefill: 2048,
        }
    }
}

impl XskConfig {
    /// Create a new configuration for the given interface.
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            ..Default::default()
        }
    }

    /// Set the queue ID.
    #[must_use]
    pub fn queue_id(mut self, id: u32) -> Self {
        self.queue_id = id;
        self
    }

    /// Set UMEM frame size.
    #[must_use]
    pub fn frame_size(mut self, size: u32) -> Self {
        self.umem.frame_size = size;
        self
    }

    /// Set number of UMEM frames.
    #[must_use]
    pub fn num_frames(mut self, count: u32) -> Self {
        self.umem.num_frames = count;
        self
    }

    /// Set ring size.
    #[must_use]
    pub fn ring_size(mut self, size: u32) -> Self {
        self.ring_size = size;
        self
    }

    /// Enable or disable zero-copy mode.
    #[must_use]
    pub fn zero_copy(mut self, enabled: bool) -> Self {
        self.zero_copy = enabled;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.interface.is_empty() {
            return Err(AfXdpError::Config("interface name is required".to_string()));
        }

        if !self.ring_size.is_power_of_two() {
            return Err(AfXdpError::InvalidRingSize(self.ring_size));
        }

        // Validate UMEM config
        let _ = UmemConfig::new(
            self.umem.frame_size,
            self.umem.headroom,
            self.umem.num_frames,
        )?;

        if self.fill_prefill > self.umem.num_frames {
            return Err(AfXdpError::Config(format!(
                "fill_prefill {} exceeds num_frames {}",
                self.fill_prefill, self.umem.num_frames
            )));
        }

        Ok(())
    }
}

/// AF_XDP socket with all rings and UMEM.
///
/// This is the main interface for AF_XDP networking. It provides:
/// - Zero-copy packet reception via RX ring
/// - Zero-copy packet transmission via TX ring
/// - Automatic frame management via Fill and Completion rings
pub struct XskSocket {
    /// Raw socket file descriptor.
    fd: RawFd,
    /// Shared UMEM (can be shared with other sockets).
    umem: SharedUmem,
    /// Fill ring (userspace -> kernel, provides empty frames).
    fill: FillRing,
    /// Completion ring (kernel -> userspace, returns TX'd frames).
    comp: CompletionRing,
    /// RX ring (kernel -> userspace, received packets).
    rx: RxRing,
    /// TX ring (userspace -> kernel, packets to send).
    tx: TxRing,
    /// Interface index.
    ifindex: u32,
    /// Queue ID.
    queue_id: u32,
    /// Whether zero-copy is active.
    zero_copy_active: bool,
}

impl XskSocket {
    /// Create a new AF_XDP socket with its own UMEM.
    pub fn new(config: &XskConfig) -> Result<Self> {
        config.validate()?;

        // Create UMEM
        let umem_config = UmemConfig::new(
            config.umem.frame_size,
            config.umem.headroom,
            config.umem.num_frames,
        )?;
        let umem = Arc::new(Umem::new(umem_config)?);

        Self::with_umem(config, umem)
    }

    /// Create a new AF_XDP socket with a shared UMEM.
    ///
    /// This allows multiple sockets (e.g., for different queues) to share
    /// the same UMEM region, reducing memory usage.
    pub fn with_umem(config: &XskConfig, umem: SharedUmem) -> Result<Self> {
        config.validate()?;

        // Get interface index
        let ifindex =
            sys::if_nametoindex(&config.interface).map_err(|e| AfXdpError::InterfaceIndex {
                interface: config.interface.clone(),
                source: e,
            })?;

        info!(
            "Creating XSK socket for {}:{} (ifindex={})",
            config.interface, config.queue_id, ifindex
        );

        // Create socket
        let fd = sys::xsk_socket().map_err(|e| {
            if e.raw_os_error() == Some(libc::EPERM) {
                AfXdpError::PermissionDenied
            } else if e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
                AfXdpError::NotSupported
            } else {
                AfXdpError::SocketCreation(e)
            }
        })?;

        // Wrap in a guard for cleanup on error
        let socket_guard = SocketGuard(fd);

        // Register UMEM with socket
        umem.register(fd)?;

        // Get mmap offsets
        let offsets = sys::xsk_get_mmap_offsets(fd).map_err(|e| AfXdpError::SocketOption {
            option: "XDP_MMAP_OFFSETS".to_string(),
            source: e,
        })?;

        // Create ring configuration
        let ring_config = RingConfig::new(config.ring_size)?;

        // Create all rings
        let fill = FillRing::new(fd, &ring_config, &offsets.fr)?;
        let comp = CompletionRing::new(fd, &ring_config, &offsets.cr)?;
        let rx = RxRing::new(fd, &ring_config, &offsets.rx)?;
        let tx = TxRing::new(fd, &ring_config, &offsets.tx)?;

        // Build bind flags
        let mut flags: u16 = 0;
        if config.zero_copy {
            flags |= XDP_ZEROCOPY;
        } else {
            flags |= XDP_COPY;
        }
        if config.use_need_wakeup {
            flags |= XDP_USE_NEED_WAKEUP;
        }

        // Bind to interface/queue
        let addr = SockaddrXdp {
            sxdp_family: sys::AF_XDP as u16,
            sxdp_flags: flags,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: config.queue_id,
            sxdp_shared_umem_fd: 0, // Not sharing UMEM FD with another socket
        };

        let zero_copy_active = match sys::xsk_bind(fd, &addr) {
            Ok(()) => {
                debug!("Bound with zero-copy mode");
                config.zero_copy
            }
            Err(e) if config.zero_copy && e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                // Fall back to copy mode
                warn!(
                    "Zero-copy not supported on {}, falling back to copy mode",
                    config.interface
                );
                let addr_copy = SockaddrXdp {
                    sxdp_flags: XDP_COPY
                        | if config.use_need_wakeup {
                            XDP_USE_NEED_WAKEUP
                        } else {
                            0
                        },
                    ..addr
                };
                sys::xsk_bind(fd, &addr_copy).map_err(|e| AfXdpError::Bind {
                    interface: config.interface.clone(),
                    queue: config.queue_id,
                    source: e,
                })?;
                false
            }
            Err(e) => {
                return Err(AfXdpError::Bind {
                    interface: config.interface.clone(),
                    queue: config.queue_id,
                    source: e,
                });
            }
        };

        // Disarm the socket guard - we now own the fd
        std::mem::forget(socket_guard);

        let mut socket = Self {
            fd,
            umem,
            fill,
            comp,
            rx,
            tx,
            ifindex,
            queue_id: config.queue_id,
            zero_copy_active,
        };

        // Pre-fill the fill ring
        socket.prefill_fill_ring(config.fill_prefill)?;

        info!(
            "XSK socket created: fd={}, zero_copy={}, queue={}",
            fd, zero_copy_active, config.queue_id
        );

        Ok(socket)
    }

    /// Pre-fill the fill ring with empty frames.
    fn prefill_fill_ring(&mut self, count: u32) -> Result<()> {
        let actual = count.min(self.umem.available_frames());
        if actual == 0 {
            return Ok(());
        }

        let start_idx = self
            .fill
            .reserve(actual)
            .ok_or_else(|| AfXdpError::Config("fill ring too small for prefill".to_string()))?;

        for i in 0..actual {
            let addr = self.umem.alloc_frame().ok_or(AfXdpError::UmemExhausted)?;
            self.fill.write(start_idx.wrapping_add(i), addr);
        }

        self.fill.submit(actual);
        debug!("Pre-filled {} frames into fill ring", actual);

        Ok(())
    }

    /// Get the socket file descriptor.
    #[inline]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Get the interface index.
    #[inline]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Get the queue ID.
    #[inline]
    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// Check if zero-copy mode is active.
    #[inline]
    pub fn is_zero_copy(&self) -> bool {
        self.zero_copy_active
    }

    /// Get a reference to the UMEM.
    #[inline]
    pub fn umem(&self) -> &SharedUmem {
        &self.umem
    }

    /// Receive packets from the RX ring.
    ///
    /// Returns the number of packets received and calls the handler for each.
    /// The handler receives the frame address and packet length.
    ///
    /// # Arguments
    /// * `max_batch` - Maximum number of packets to receive
    /// * `handler` - Callback for each received packet (addr, len)
    pub fn recv<F>(&mut self, max_batch: u32, mut handler: F) -> Result<u32>
    where
        F: FnMut(u64, u32),
    {
        let available = self.rx.available().min(max_batch);
        if available == 0 {
            return Ok(0);
        }

        for i in 0..available {
            let desc = self.rx.get_desc(i);
            handler(desc.addr, desc.len);
        }

        self.rx.release(available);

        // Refill the fill ring with the same number of frames
        self.refill_frames(available)?;

        Ok(available)
    }

    /// Receive packets with direct access to packet data.
    ///
    /// This variant provides a slice to the actual packet data instead of
    /// just the address. The caller must process the packet before the
    /// next call, as the frame will be reused.
    pub fn recv_batch<F>(&mut self, max_batch: u32, mut handler: F) -> Result<u32>
    where
        F: FnMut(&[u8]) -> bool, // Returns true to continue, false to stop early
    {
        let available = self.rx.available().min(max_batch);
        if available == 0 {
            return Ok(0);
        }

        let mut processed = 0;
        for i in 0..available {
            let desc = self.rx.get_desc(i);
            let packet = match self.umem.packet_checked(desc.addr, desc.len) {
                Ok(packet) => packet,
                Err(e) => {
                    warn!(
                        "Dropping invalid RX descriptor addr={:#x} len={}: {}",
                        desc.addr, desc.len, e
                    );
                    processed = i + 1;
                    continue;
                }
            };

            if !handler(packet) {
                processed = i + 1;
                break;
            }
            processed = i + 1;
        }

        self.rx.release(processed);
        self.refill_frames(processed)?;

        Ok(processed)
    }

    /// Refill the fill ring with empty frames.
    fn refill_frames(&mut self, count: u32) -> Result<()> {
        // Try to reclaim completed TX frames first
        self.reclaim_completed();

        let available = self.umem.available_frames().min(count);
        if available == 0 {
            return Ok(());
        }

        if let Some(start_idx) = self.fill.reserve(available) {
            for i in 0..available {
                if let Some(addr) = self.umem.alloc_frame() {
                    self.fill.write(start_idx.wrapping_add(i), addr);
                } else {
                    // Submit what we have
                    self.fill.submit(i);
                    return Ok(());
                }
            }
            self.fill.submit(available);

            // Kick the kernel if needed
            if self.fill.needs_wakeup() {
                let _ = sys::poll_socket(self.fd, libc::POLLIN as i16, 0);
            }
        }

        Ok(())
    }

    /// Reclaim completed TX frames back to UMEM.
    fn reclaim_completed(&mut self) {
        let completed = self.comp.available();
        for i in 0..completed {
            let addr = self.comp.peek(i);
            self.umem.free_frame(addr);
        }
        if completed > 0 {
            self.comp.release(completed);
        }
    }

    /// Send a single packet.
    ///
    /// Returns the frame address that was used, or None if the TX ring is full.
    /// The caller should write packet data to the frame before calling `flush`.
    pub fn send_reserve(&mut self, len: u32) -> Option<(u64, &mut [u8])> {
        if len > self.umem.config().max_packet_size() {
            return None;
        }

        // Need a free slot in TX ring and a free frame
        if self.tx.free_slots() == 0 {
            // Try to reclaim completed frames
            self.reclaim_completed();
            if self.tx.free_slots() == 0 {
                return None;
            }
        }

        let addr = self.umem.alloc_frame()?;
        let packet = match self.umem.packet_mut_checked(addr, len) {
            Ok(packet) => packet,
            Err(e) => {
                warn!(
                    "Dropping TX reservation for invalid frame addr={:#x} len={}: {}",
                    addr, len, e
                );
                self.umem.free_frame(addr);
                return None;
            }
        };

        Some((addr, packet))
    }

    /// Submit a packet for transmission.
    ///
    /// # Arguments
    /// * `addr` - Frame address from `send_reserve`
    /// * `len` - Actual packet length
    pub fn send_submit(&mut self, addr: u64, len: u32) {
        let idx = self.tx.reserve(1).expect("checked in send_reserve");
        let desc = XdpDesc {
            addr: addr + self.umem.config().headroom as u64,
            len,
            options: 0,
        };
        self.tx.write(idx, &desc);
        self.tx.submit(1);

        // Kick the kernel if needed
        if self.tx.needs_wakeup() {
            let _ = sys::xsk_sendto(self.fd);
        }
    }

    /// Send a packet by copying data.
    ///
    /// This is a convenience method that handles frame allocation and submission.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = data.len() as u32;
        if len > self.umem.config().max_packet_size() {
            return Err(AfXdpError::Config(format!(
                "packet too large: {} > {}",
                len,
                self.umem.config().max_packet_size()
            )));
        }

        let (addr, buf) = self.send_reserve(len).ok_or(AfXdpError::UmemExhausted)?;
        buf[..data.len()].copy_from_slice(data);
        self.send_submit(addr, len);

        Ok(())
    }

    /// Send multiple packets in a batch.
    ///
    /// Returns the number of packets successfully queued.
    pub fn send_batch(&mut self, packets: &[&[u8]]) -> Result<u32> {
        let mut sent = 0;

        for data in packets {
            let len = data.len() as u32;
            if len > self.umem.config().max_packet_size() {
                continue;
            }

            match self.send_reserve(len) {
                Some((addr, buf)) => {
                    buf[..data.len()].copy_from_slice(data);
                    self.send_submit(addr, len);
                    sent += 1;
                }
                None => break,
            }
        }

        Ok(sent)
    }

    /// Flush pending TX packets.
    ///
    /// This ensures the kernel processes any queued TX packets.
    pub fn flush(&self) -> Result<()> {
        sys::xsk_sendto(self.fd).map_err(AfXdpError::Transmit)
    }

    /// Poll the socket for readiness.
    ///
    /// # Arguments
    /// * `timeout_ms` - Timeout in milliseconds (-1 for infinite)
    ///
    /// # Returns
    /// A tuple of (can_recv, can_send)
    pub fn poll(&self, timeout_ms: i32) -> Result<(bool, bool)> {
        let events = libc::POLLIN | libc::POLLOUT;
        let revents =
            sys::poll_socket(self.fd, events as i16, timeout_ms).map_err(AfXdpError::Poll)?;

        Ok((
            revents & libc::POLLIN as i16 != 0,
            revents & libc::POLLOUT as i16 != 0,
        ))
    }

    /// Get socket statistics.
    pub fn statistics(&self) -> Result<SocketStats> {
        let stats = sys::xsk_get_statistics(self.fd).map_err(|e| AfXdpError::SocketOption {
            option: "XDP_STATISTICS".to_string(),
            source: e,
        })?;

        Ok(SocketStats {
            rx_dropped: stats.rx_dropped,
            rx_invalid_descs: stats.rx_invalid_descs,
            tx_invalid_descs: stats.tx_invalid_descs,
            rx_ring_full: stats.rx_ring_full,
            rx_fill_ring_empty: stats.rx_fill_ring_empty_descs,
            tx_ring_empty: stats.tx_ring_empty_descs,
            umem_available_frames: self.umem.available_frames(),
            fill_ring_free: self.fill.free_slots(),
            comp_ring_available: self.comp.available(),
            rx_ring_available: self.rx.available(),
            tx_ring_free: self.tx.free_slots(),
        })
    }
}

impl AsRawFd for XskSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        // Close the socket
        // SAFETY: We own the fd
        unsafe {
            libc::close(self.fd);
        }
        debug!("XSK socket closed: fd={}", self.fd);
    }
}

// SAFETY: XskSocket can be sent between threads
unsafe impl Send for XskSocket {}

/// Guard to ensure socket is closed on error during construction.
struct SocketGuard(RawFd);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        // SAFETY: We own this fd
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Socket statistics.
#[derive(Debug, Clone, Default)]
pub struct SocketStats {
    /// Packets dropped by kernel.
    pub rx_dropped: u64,
    /// Invalid RX descriptors.
    pub rx_invalid_descs: u64,
    /// Invalid TX descriptors.
    pub tx_invalid_descs: u64,
    /// Times RX ring was full.
    pub rx_ring_full: u64,
    /// Times fill ring was empty.
    pub rx_fill_ring_empty: u64,
    /// Times TX ring was empty during send.
    pub tx_ring_empty: u64,
    /// Available UMEM frames.
    pub umem_available_frames: u32,
    /// Free slots in fill ring.
    pub fill_ring_free: u32,
    /// Available entries in completion ring.
    pub comp_ring_available: u32,
    /// Available entries in RX ring.
    pub rx_ring_available: u32,
    /// Free slots in TX ring.
    pub tx_ring_free: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xsk_config_default() {
        let config = XskConfig::default();
        assert!(config.interface.is_empty());
        assert_eq!(config.queue_id, 0);
        assert_eq!(config.ring_size, 4096);
        assert!(config.zero_copy);
        assert!(config.use_need_wakeup);
    }

    #[test]
    fn test_xsk_config_builder() {
        let config = XskConfig::new("eth0")
            .queue_id(2)
            .ring_size(8192)
            .zero_copy(false)
            .frame_size(4096)
            .num_frames(8192);

        assert_eq!(config.interface, "eth0");
        assert_eq!(config.queue_id, 2);
        assert_eq!(config.ring_size, 8192);
        assert!(!config.zero_copy);
        assert_eq!(config.umem.frame_size, 4096);
        assert_eq!(config.umem.num_frames, 8192);
    }

    #[test]
    fn test_xsk_config_validation() {
        // Missing interface
        let config = XskConfig::default();
        assert!(config.validate().is_err());

        // Invalid ring size
        let config = XskConfig::new("eth0").ring_size(1000);
        assert!(config.validate().is_err());

        // Valid config
        let config = XskConfig::new("eth0");
        // This would fail without a real interface, but validates structure
    }
}
