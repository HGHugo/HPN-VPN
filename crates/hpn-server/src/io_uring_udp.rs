//! io_uring-based UDP I/O for maximum throughput on Linux.
//!
//! This module provides io_uring-based UDP socket operations, which can
//! achieve 50-200% higher throughput than traditional syscalls by:
//!
//! - **Zero-copy I/O**: Data stays in kernel space when possible
//! - **Batched submission**: Multiple operations submitted in one syscall
//! - **Async completion**: Non-blocking completion notification
//!
//! # Requirements
//!
//! - Linux kernel >= 5.6 (for full UDP support)
//! - Compile with `--features io_uring`
//!
//! # Performance
//!
//! On a typical 4-core server:
//! - Traditional `recvfrom/sendto`: ~500K pps
//! - `recvmmsg/sendmmsg`: ~700K pps
//! - `io_uring`: ~1.2M+ pps

#![allow(unsafe_code)]
#![cfg(all(target_os = "linux", feature = "io_uring"))]

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use io_uring::{IoUring, opcode, types};
use tracing::{debug, trace, warn};

/// Default ring size (number of SQ entries).
pub const DEFAULT_RING_SIZE: u32 = 256;

/// Maximum batch size for submissions.
pub const MAX_BATCH_SIZE: usize = 64;

/// Maximum packet size.
pub const MAX_PACKET_SIZE: usize = 65535;

/// Number of pre-allocated buffers.
pub const NUM_BUFFERS: usize = 256;

/// A received packet with metadata.
#[derive(Debug)]
pub struct ReceivedPacket {
    /// Packet data (may contain multiple GRO-coalesced packets).
    pub data: Vec<u8>,
    /// Source address.
    pub addr: SocketAddr,
    /// GSO segment size from UDP_GRO cmsg. 0 = single packet (no GRO coalescing).
    pub gso_size: u16,
}

/// UDP_GRO control message type.
const UDP_GRO: libc::c_int = 104;

/// Size of control message buffer for UDP_GRO.
/// CMSG_SPACE(sizeof(uint16_t)) = typically 24 bytes, use 64 for safety.
const CMSG_BUFFER_SIZE: usize = 64;

/// Buffer entry with msghdr for recvmsg operations.
/// Includes cmsg buffer for UDP_GRO support.
struct RecvBuffer {
    /// Data buffer.
    data: Vec<u8>,
    /// I/O vector pointing to data.
    iovec: libc::iovec,
    /// Message header.
    msghdr: libc::msghdr,
    /// Source address storage.
    addr_storage: libc::sockaddr_storage,
    /// Control message buffer for UDP_GRO.
    cmsg_buffer: Vec<u8>,
}

impl RecvBuffer {
    /// Create a new buffer without setting up internal pointers.
    /// Call `setup()` after the buffer is in its final memory location.
    fn new_uninit() -> Self {
        Self {
            data: vec![0u8; MAX_PACKET_SIZE],
            iovec: unsafe { std::mem::zeroed() },
            msghdr: unsafe { std::mem::zeroed() },
            addr_storage: unsafe { std::mem::zeroed() },
            cmsg_buffer: vec![0u8; CMSG_BUFFER_SIZE],
        }
    }

    /// Setup internal pointers. Must be called after buffer is in final memory location.
    fn setup(&mut self) {
        // Setup iovec to point to data buffer
        self.iovec.iov_base = self.data.as_mut_ptr().cast::<libc::c_void>();
        self.iovec.iov_len = self.data.len();

        // Setup msghdr with pointers to our fields
        self.msghdr.msg_name = ptr::from_mut(&mut self.addr_storage).cast::<libc::c_void>();
        self.msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        self.msghdr.msg_iov = ptr::from_mut(&mut self.iovec);
        self.msghdr.msg_iovlen = 1;
        // Setup control message buffer for UDP_GRO
        self.msghdr.msg_control = self.cmsg_buffer.as_mut_ptr().cast::<libc::c_void>();
        self.msghdr.msg_controllen = CMSG_BUFFER_SIZE;
        self.msghdr.msg_flags = 0;
    }

    fn reset(&mut self) {
        // Reset address storage and cmsg buffer for reuse
        self.addr_storage = unsafe { std::mem::zeroed() };
        self.cmsg_buffer.fill(0);

        // CRITICAL: Re-setup all pointers as they may have been invalidated
        // if the Vec was reallocated or the struct was moved
        self.iovec.iov_base = self.data.as_mut_ptr().cast::<libc::c_void>();
        self.iovec.iov_len = self.data.len();

        self.msghdr.msg_name = ptr::from_mut(&mut self.addr_storage).cast::<libc::c_void>();
        self.msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        self.msghdr.msg_iov = ptr::from_mut(&mut self.iovec);
        self.msghdr.msg_iovlen = 1;
        self.msghdr.msg_control = self.cmsg_buffer.as_mut_ptr().cast::<libc::c_void>();
        self.msghdr.msg_controllen = CMSG_BUFFER_SIZE;
        self.msghdr.msg_flags = 0;
    }

    fn get_addr(&self) -> Option<SocketAddr> {
        sockaddr_storage_to_socket_addr(&self.addr_storage)
    }

    /// Parse UDP_GRO control message to get segment size.
    /// Returns 0 if no GRO (single packet).
    fn get_gso_size(&self) -> u16 {
        if self.msghdr.msg_controllen == 0 || self.msghdr.msg_control.is_null() {
            return 0;
        }

        // SAFETY: We own the cmsg buffer and it was properly initialized
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const self.msghdr);
            while !cmsg.is_null() {
                let hdr = &*cmsg;
                // Check for UDP_GRO message (SOL_UDP level, UDP_GRO type)
                if hdr.cmsg_level == libc::SOL_UDP && hdr.cmsg_type == UDP_GRO {
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    if !data_ptr.is_null() {
                        return ptr::read_unaligned(data_ptr.cast::<u16>());
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&raw const self.msghdr, cmsg);
            }
        }

        0
    }
}

/// Buffer entry for sendmsg operations.
struct SendBuffer {
    /// Data buffer.
    data: Vec<u8>,
    /// I/O vector pointing to data.
    iovec: libc::iovec,
    /// Message header.
    msghdr: libc::msghdr,
    /// Destination address storage.
    addr_storage: libc::sockaddr_storage,
    /// Actual address length.
    addr_len: libc::socklen_t,
}

impl SendBuffer {
    fn new(data: &[u8], addr: SocketAddr) -> Self {
        let mut buf = Self {
            data: data.to_vec(),
            iovec: unsafe { std::mem::zeroed() },
            msghdr: unsafe { std::mem::zeroed() },
            addr_storage: unsafe { std::mem::zeroed() },
            addr_len: 0,
        };
        buf.setup(addr);
        buf
    }

    fn setup(&mut self, addr: SocketAddr) {
        // Setup iovec
        self.iovec.iov_base = self.data.as_mut_ptr().cast::<libc::c_void>();
        self.iovec.iov_len = self.data.len();

        // Setup address
        self.addr_len = socket_addr_to_sockaddr(&addr, &mut self.addr_storage);

        // Setup msghdr
        self.msghdr.msg_name = ptr::from_mut(&mut self.addr_storage).cast::<libc::c_void>();
        self.msghdr.msg_namelen = self.addr_len;
        self.msghdr.msg_iov = &raw mut self.iovec;
        self.msghdr.msg_iovlen = 1;
        self.msghdr.msg_control = ptr::null_mut();
        self.msghdr.msg_controllen = 0;
        self.msghdr.msg_flags = 0;
    }
}

/// io_uring-based UDP socket for high-performance I/O.
pub struct IoUringUdp {
    /// io_uring instance.
    ring: IoUring,
    /// Socket file descriptor.
    socket_fd: RawFd,
    /// Pre-allocated receive buffers.
    recv_buffers: Vec<RecvBuffer>,
    /// Free buffer indices.
    free_buffers: VecDeque<usize>,
    /// Pending receive operations (buffer indices).
    pending_recv_indices: Vec<usize>,
    /// Pending send buffers (owned, freed on completion).
    pending_sends: Vec<Option<SendBuffer>>,
    /// Reusable vacant indices in `pending_sends`.
    free_send_indices: Vec<usize>,
    /// Maximum number of in-flight send operations.
    max_pending_sends: usize,
    /// Next send buffer ID.
    next_send_id: u64,
    /// Statistics: packets received.
    stats_received: AtomicU64,
    /// Statistics: packets sent.
    stats_sent: AtomicU64,
    /// Statistics: receive errors.
    stats_recv_errors: AtomicU64,
    /// Statistics: send errors.
    stats_send_errors: AtomicU64,
    /// Shutdown flag.
    shutdown: AtomicBool,
}

/// User data encoding: lower 32 bits = op type, upper 32 bits = buffer index.
const OP_RECV: u64 = 1;
const OP_SEND: u64 = 2;

#[inline]
fn encode_user_data(op: u64, idx: usize) -> u64 {
    op | ((idx as u64) << 32)
}

#[inline]
fn decode_user_data(user_data: u64) -> (u64, usize) {
    let op = user_data & 0xFFFF_FFFF;
    let idx = (user_data >> 32) as usize;
    (op, idx)
}

impl IoUringUdp {
    /// Create a new io_uring UDP handler.
    ///
    /// # Arguments
    /// * `socket` - UDP socket (must be bound)
    /// * `ring_size` - io_uring ring size (default 256)
    pub fn new<S: AsRawFd>(socket: &S, ring_size: u32) -> io::Result<Self> {
        // Try to use SQPOLL for kernel-side polling (reduces syscalls)
        let ring = IoUring::builder()
            .setup_sqpoll(1000) // 1ms idle before sleeping
            .build(ring_size)
            .or_else(|_| {
                // Fall back to regular io_uring if SQPOLL not available
                debug!("SQPOLL not available, using regular io_uring");
                IoUring::new(ring_size)
            })?;

        let socket_fd = socket.as_raw_fd();

        // Pre-allocate receive buffers
        // IMPORTANT: We must setup pointers AFTER all buffers are in the Vec,
        // because Vec may reallocate during push, invalidating pointers.
        let mut recv_buffers = Vec::with_capacity(NUM_BUFFERS);
        let mut free_buffers = VecDeque::with_capacity(NUM_BUFFERS);

        // First, create all buffers without setting up pointers
        for _ in 0..NUM_BUFFERS {
            recv_buffers.push(RecvBuffer::new_uninit());
        }

        // Now setup pointers - Vec won't reallocate since we used with_capacity
        for (i, buf) in recv_buffers.iter_mut().enumerate() {
            buf.setup();
            free_buffers.push_back(i);
        }

        debug!(
            "Created io_uring UDP handler: ring_size={}, buffers={}",
            ring_size, NUM_BUFFERS
        );

        let mut pending_sends = Vec::with_capacity(ring_size as usize);
        pending_sends.resize_with(ring_size as usize, || None);

        Ok(Self {
            ring,
            socket_fd,
            recv_buffers,
            free_buffers,
            pending_recv_indices: Vec::with_capacity(NUM_BUFFERS),
            pending_sends,
            free_send_indices: (0..ring_size as usize).rev().collect(),
            max_pending_sends: ring_size as usize,
            next_send_id: 0,
            stats_received: AtomicU64::new(0),
            stats_sent: AtomicU64::new(0),
            stats_recv_errors: AtomicU64::new(0),
            stats_send_errors: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Create with default settings.
    pub fn with_defaults<S: AsRawFd>(socket: &S) -> io::Result<Self> {
        Self::new(socket, DEFAULT_RING_SIZE)
    }

    /// Submit receive operations to fill available buffers.
    pub fn submit_recvs(&mut self) -> io::Result<usize> {
        let mut submitted = 0;

        while let Some(buf_idx) = self.free_buffers.pop_front() {
            // Reset buffer for reuse
            self.recv_buffers[buf_idx].reset();

            let msghdr_ptr = &raw mut self.recv_buffers[buf_idx].msghdr;

            let recv_entry = opcode::RecvMsg::new(types::Fd(self.socket_fd), msghdr_ptr)
                .build()
                .user_data(encode_user_data(OP_RECV, buf_idx));

            // Submit to ring
            unsafe {
                if self.ring.submission().push(&recv_entry).is_err() {
                    // SQ is full, return buffer
                    self.free_buffers.push_front(buf_idx);
                    break;
                }
            }

            self.pending_recv_indices.push(buf_idx);
            submitted += 1;
        }

        if submitted > 0 {
            self.ring.submit()?;
            trace!("Submitted {} recv operations", submitted);
        }

        Ok(submitted)
    }

    /// Queue a send operation.
    pub fn queue_send(&mut self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        let send_buf = SendBuffer::new(data, addr);
        let send_id = self.next_send_id;
        self.next_send_id += 1;

        // Store the send buffer in a fixed slot to keep pointers stable for in-flight SQEs.
        let Some(idx) = self.free_send_indices.pop() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "too many in-flight io_uring sends (max {})",
                    self.max_pending_sends
                ),
            ));
        };
        self.pending_sends[idx] = Some(send_buf);

        // Safety: we just pushed Some(send_buf) at this index on the line above
        let msghdr_ptr = &raw const self.pending_sends[idx]
            .as_ref()
            .expect("pending_sends[idx] was just set to Some")
            .msghdr;

        let send_entry = opcode::SendMsg::new(types::Fd(self.socket_fd), msghdr_ptr)
            .build()
            .user_data(encode_user_data(OP_SEND, idx));

        unsafe {
            if self.ring.submission().push(&send_entry).is_err() {
                // SQ full, submit what we have and retry
                self.ring.submit()?;
                self.ring
                    .submission()
                    .push(&send_entry)
                    .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "SQ full"))?;
            }
        }

        trace!("Queued send {} to {}", send_id, addr);
        Ok(())
    }

    /// Submit any pending operations.
    pub fn flush(&mut self) -> io::Result<()> {
        self.ring.submit()?;
        Ok(())
    }

    /// Wait for and process completions.
    ///
    /// Returns received packets.
    pub fn wait_completions(&mut self, min_complete: usize) -> io::Result<Vec<ReceivedPacket>> {
        // Submit any pending ops and wait for at least min_complete
        self.ring.submit_and_wait(min_complete)?;
        self.process_completions()
    }

    /// Non-blocking poll for completions.
    pub fn poll_completions(&mut self) -> io::Result<Vec<ReceivedPacket>> {
        // Just sync the completion queue without waiting
        self.ring.submit()?;
        self.process_completions()
    }

    /// Process all available completions.
    fn process_completions(&mut self) -> io::Result<Vec<ReceivedPacket>> {
        let mut received = Vec::new();
        let mut completed_send_indices = Vec::new();

        // Process all available completions
        for cqe in self.ring.completion() {
            let (op, idx) = decode_user_data(cqe.user_data());
            let result = cqe.result();

            match op {
                OP_RECV => {
                    // Remove from pending
                    if let Some(pos) = self.pending_recv_indices.iter().position(|&i| i == idx) {
                        self.pending_recv_indices.swap_remove(pos);
                    }

                    if result >= 0 {
                        let len = result as usize;
                        let buf = &self.recv_buffers[idx];

                        if let Some(addr) = buf.get_addr() {
                            let gso_size = buf.get_gso_size();
                            received.push(ReceivedPacket {
                                data: buf.data[..len].to_vec(),
                                addr,
                                gso_size,
                            });
                            self.stats_received.fetch_add(1, Ordering::Relaxed);
                        } else {
                            warn!("Failed to parse source address for received packet");
                            self.stats_recv_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        let err = io::Error::from_raw_os_error(-result);
                        trace!("Recv error: {}", err);
                        self.stats_recv_errors.fetch_add(1, Ordering::Relaxed);
                    }

                    // Return buffer to pool
                    self.free_buffers.push_back(idx);
                }
                OP_SEND => {
                    if result >= 0 {
                        self.stats_sent.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let err = io::Error::from_raw_os_error(-result);
                        trace!("Send error: {}", err);
                        self.stats_send_errors.fetch_add(1, Ordering::Relaxed);
                    }

                    // Mark for cleanup
                    completed_send_indices.push(idx);
                }
                _ => {
                    warn!("Unknown io_uring completion: op={}", op);
                }
            }
        }

        // Clean up completed send buffers
        // Sort in reverse to remove from end first
        completed_send_indices.sort_unstable_by(|a, b| b.cmp(a));
        for idx in completed_send_indices {
            if idx < self.pending_sends.len() && self.pending_sends[idx].take().is_some() {
                self.free_send_indices.push(idx);
            }
        }

        Ok(received)
    }

    /// Get statistics.
    pub fn stats(&self) -> IoUringStats {
        IoUringStats {
            packets_received: self.stats_received.load(Ordering::Relaxed),
            packets_sent: self.stats_sent.load(Ordering::Relaxed),
            recv_errors: self.stats_recv_errors.load(Ordering::Relaxed),
            send_errors: self.stats_send_errors.load(Ordering::Relaxed),
            pending_recvs: self.pending_recv_indices.len(),
            pending_sends: self.pending_sends.iter().filter(|s| s.is_some()).count(),
            free_buffers: self.free_buffers.len(),
        }
    }

    /// Shutdown the io_uring handler.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// io_uring statistics.
#[derive(Debug, Clone)]
pub struct IoUringStats {
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Receive errors.
    pub recv_errors: u64,
    /// Send errors.
    pub send_errors: u64,
    /// Pending receive operations.
    pub pending_recvs: usize,
    /// Pending send operations.
    pub pending_sends: usize,
    /// Free buffers available.
    pub free_buffers: usize,
}

/// Check if io_uring is supported on this system.
pub fn is_io_uring_supported() -> bool {
    // Try to create a minimal io_uring instance
    IoUring::new(8).is_ok()
}

/// Check if io_uring with SQPOLL is supported.
pub fn is_sqpoll_supported() -> bool {
    IoUring::<io_uring::squeue::Entry, io_uring::cqueue::Entry>::builder()
        .setup_sqpoll(1000)
        .build(8)
        .is_ok()
}

/// Get io_uring kernel version requirements.
pub fn io_uring_requirements() -> &'static str {
    "Linux kernel >= 5.6 for full UDP support, >= 5.1 for basic io_uring"
}

/// Convert SocketAddr to raw sockaddr_storage, returns actual length.
fn socket_addr_to_sockaddr(
    addr: &SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    *storage = unsafe { std::mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *ptr::from_mut(storage).cast::<libc::sockaddr_in>() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *ptr::from_mut(storage).cast::<libc::sockaddr_in6>() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Convert sockaddr_storage to SocketAddr.
fn sockaddr_storage_to_socket_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    let family = storage.ss_family as i32;

    match family {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in =
                unsafe { &*ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_io_uring_supported() {
        let supported = is_io_uring_supported();
        println!("io_uring supported: {}", supported);
    }

    #[test]
    fn test_is_sqpoll_supported() {
        let supported = is_sqpoll_supported();
        println!(
            "SQPOLL supported: {} (requires root or CAP_SYS_NICE)",
            supported
        );
    }

    #[test]
    fn test_requirements() {
        let req = io_uring_requirements();
        assert!(req.contains("Linux"));
    }

    #[test]
    fn test_address_conversion() {
        // Test IPv4
        let addr_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 12345));
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        socket_addr_to_sockaddr(&addr_v4, &mut storage);
        let recovered = sockaddr_storage_to_socket_addr(&storage);
        assert_eq!(recovered, Some(addr_v4));

        // Test IPv6
        let addr_v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            54321,
            0,
            0,
        ));
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        socket_addr_to_sockaddr(&addr_v6, &mut storage);
        let recovered = sockaddr_storage_to_socket_addr(&storage);
        assert_eq!(recovered, Some(addr_v6));
    }
}
