//! Batch I/O for high-throughput UDP forwarding on Linux.
//!
//! Uses `recvmmsg`/`sendmmsg` to receive/send multiple UDP packets per
//! syscall, reducing syscall overhead by 15-25% at high packet rates.
//!
//! This module is only available on Linux (`#[cfg(target_os = "linux")]`).

#![allow(unsafe_code)]

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

/// Maximum packets per recvmmsg/sendmmsg call.
pub const MAX_BATCH_SIZE: usize = 64;

/// Default buffer size per packet (MTU + overhead).
pub const DEFAULT_BUFFER_SIZE: usize = 1500;

// ---------------------------------------------------------------------------
// RecvBatch — receive multiple packets in one syscall
// ---------------------------------------------------------------------------

/// Batch receiver using `recvmmsg`.
pub struct RecvBatch {
    msgvec: Vec<libc::mmsghdr>,
    /// Kept alive: `msgvec` entries hold raw pointers into this Vec.
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    buffers: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    batch_size: usize,
    last_count: usize,
}

impl RecvBatch {
    /// Create a new batch receiver.
    pub fn new(batch_size: usize, buffer_size: usize) -> Self {
        let batch_size = batch_size.min(MAX_BATCH_SIZE);

        let mut buffers = Vec::with_capacity(batch_size);
        let mut iovecs = Vec::with_capacity(batch_size);
        let mut addrs: Vec<libc::sockaddr_storage> =
            vec![unsafe { std::mem::zeroed() }; batch_size];

        for _ in 0..batch_size {
            buffers.push(vec![0u8; buffer_size]);
        }

        for buf in &mut buffers {
            iovecs.push(libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            });
        }

        let mut msgvec = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let msghdr = libc::msghdr {
                msg_name: std::ptr::addr_of_mut!(addrs[i]).cast(),
                msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                msg_iov: std::ptr::addr_of_mut!(iovecs[i]),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
            msgvec.push(libc::mmsghdr {
                msg_hdr: msghdr,
                msg_len: 0,
            });
        }

        Self {
            msgvec,
            iovecs,
            buffers,
            addrs,
            batch_size,
            last_count: 0,
        }
    }

    /// Receive a batch of packets (non-blocking).
    ///
    /// Returns the number of packets received (0 if `EAGAIN`/`EWOULDBLOCK`).
    pub fn recv<S: AsRawFd>(&mut self, socket: &S) -> io::Result<usize> {
        // Reset headers
        for i in 0..self.batch_size {
            self.msgvec[i].msg_len = 0;
            self.msgvec[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            self.msgvec[i].msg_hdr.msg_flags = 0;
        }

        let count = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                self.msgvec.as_mut_ptr(),
                self.batch_size as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if count < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                self.last_count = 0;
                return Ok(0);
            }
            return Err(err);
        }

        self.last_count = count as usize;
        Ok(self.last_count)
    }

    /// Get packet data and source address for a received packet.
    ///
    /// Clamps `msg_len` to buffer size defensively (prevents panic if kernel
    /// reports an unexpected length due to a bug or malicious kernel module).
    #[inline]
    pub fn get(&self, index: usize) -> (&[u8], Option<SocketAddr>) {
        debug_assert!(index < self.last_count);
        let len = (self.msgvec[index].msg_len as usize).min(self.buffers[index].len());
        let data = &self.buffers[index][..len];
        let addr = sockaddr_to_std(&self.addrs[index]);
        (data, addr)
    }

    /// Number of packets in the last recv call.
    #[inline]
    pub fn count(&self) -> usize {
        self.last_count
    }
}

// ---------------------------------------------------------------------------
// SendBatch — send multiple packets in one syscall
// ---------------------------------------------------------------------------

/// Batch sender using `sendmmsg`.
pub struct SendBatch {
    msgvec: Vec<libc::mmsghdr>,
    /// Kept alive: `msgvec` entries hold raw pointers into this Vec.
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    buffers: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    count: usize,
    batch_size: usize,
}

impl SendBatch {
    /// Create a new batch sender.
    pub fn new(batch_size: usize, buffer_size: usize) -> Self {
        let batch_size = batch_size.min(MAX_BATCH_SIZE);

        let mut buffers = Vec::with_capacity(batch_size);
        let mut iovecs = Vec::with_capacity(batch_size);
        let addrs: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; batch_size];

        for _ in 0..batch_size {
            buffers.push(vec![0u8; buffer_size]);
        }

        for buf in &mut buffers {
            iovecs.push(libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: 0,
            });
        }

        let mut msgvec = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            msgvec.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: std::ptr::null_mut(),
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        Self {
            msgvec,
            iovecs,
            buffers,
            addrs,
            count: 0,
            batch_size,
        }
    }

    /// Add a packet to the send batch.
    ///
    /// Returns `true` if added, `false` if batch is full.
    pub fn add(&mut self, data: &[u8], addr: SocketAddr) -> bool {
        if self.count >= self.batch_size {
            return false;
        }

        let idx = self.count;
        let len = data.len().min(self.buffers[idx].len());
        self.buffers[idx][..len].copy_from_slice(&data[..len]);

        self.iovecs[idx].iov_base = self.buffers[idx].as_mut_ptr().cast();
        self.iovecs[idx].iov_len = len;

        self.addrs[idx] = std_to_sockaddr(addr);
        let addr_len = match addr {
            SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>(),
            SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>(),
        } as libc::socklen_t;

        self.msgvec[idx].msg_hdr.msg_name = std::ptr::addr_of_mut!(self.addrs[idx]).cast();
        self.msgvec[idx].msg_hdr.msg_namelen = addr_len;
        self.msgvec[idx].msg_hdr.msg_iov = std::ptr::addr_of_mut!(self.iovecs[idx]);
        self.msgvec[idx].msg_len = 0;

        self.count += 1;
        true
    }

    /// Send all batched packets in a single syscall (non-blocking).
    ///
    /// Returns the number of packets successfully sent.
    pub fn flush<S: AsRawFd>(&mut self, socket: &S) -> io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }

        // Attempt the send. `sendmmsg` may return fewer packets than
        // requested under socket-buffer pressure. We retry the unsent tail
        // a bounded number of times before giving up; truly undeliverable
        // packets are reported as a partial-send count to the caller so
        // metrics can reflect real delivery instead of claiming we forwarded
        // everything we enqueued.
        let total = self.count;
        let mut sent_total: usize = 0;

        for _ in 0..3 {
            let remaining = total - sent_total;
            if remaining == 0 {
                break;
            }
            let start = self.msgvec.as_mut_ptr();
            let sent = unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    // SAFETY: we offset by `sent_total` which is < `total == self.count`
                    // and the underlying Vec has capacity `self.batch_size >= self.count`.
                    start.add(sent_total),
                    remaining as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            if sent < 0 {
                let err = io::Error::last_os_error();
                self.count = 0;
                return if err.kind() == io::ErrorKind::WouldBlock {
                    // Report what we did manage to send so the caller sees the
                    // shortfall and can track it.
                    Ok(sent_total)
                } else {
                    Err(err)
                };
            }
            sent_total += sent as usize;
            if (sent as usize) == 0 {
                // Kernel refused to send any more right now — stop retrying
                // to avoid a tight loop. Caller sees the shortfall.
                break;
            }
        }

        self.count = 0;
        Ok(sent_total)
    }

    /// Check if the batch is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= self.batch_size
    }

    /// Check if the batch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Address conversion helpers
// ---------------------------------------------------------------------------

fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

fn std_to_sockaddr(addr: SocketAddr) -> libc::sockaddr_storage {
    use std::net::SocketAddr::{V4, V6};

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    match addr {
        V4(addr_v4) => {
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *(&raw mut storage as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = addr_v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*addr_v4.ip()).to_be();
        }
        V6(addr_v6) => {
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&raw mut storage as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = addr_v6.port().to_be();
            sin6.sin6_addr.s6_addr = addr_v6.ip().octets();
            sin6.sin6_flowinfo = addr_v6.flowinfo();
            sin6.sin6_scope_id = addr_v6.scope_id();
        }
    }

    storage
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_sockaddr_roundtrip_v4() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820));
        let storage = std_to_sockaddr(addr);
        let recovered = sockaddr_to_std(&storage);
        assert_eq!(recovered, Some(addr));
    }

    #[test]
    fn test_sockaddr_roundtrip_v6() {
        let addr: SocketAddr = "[::1]:51820".parse().unwrap();
        let storage = std_to_sockaddr(addr);
        let recovered = sockaddr_to_std(&storage);
        assert_eq!(recovered, Some(addr));
    }

    #[test]
    fn test_recv_batch_new() {
        let batch = RecvBatch::new(32, 1500);
        assert_eq!(batch.count(), 0);
        assert_eq!(batch.batch_size, 32);
    }

    #[test]
    fn test_send_batch_new() {
        let batch = SendBatch::new(32, 1500);
        assert!(batch.is_empty());
        assert!(!batch.is_full());
    }

    #[test]
    fn test_send_batch_add() {
        let mut batch = SendBatch::new(2, 1500);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        assert!(batch.add(b"hello", addr));
        assert!(!batch.is_empty());
        assert!(!batch.is_full());

        assert!(batch.add(b"world", addr));
        assert!(batch.is_full());

        // Batch full
        assert!(!batch.add(b"overflow", addr));
    }

    #[test]
    fn test_max_batch_size_cap() {
        let batch = RecvBatch::new(999, 1500);
        assert_eq!(batch.batch_size, MAX_BATCH_SIZE);
    }
}
