//! Application-layer fragmentation of handshake messages.
//!
//! # Why
//!
//! A post-quantum HPN handshake at Security Level 5 serialises to
//! roughly 5 KB on the client side (`EncryptedHandshakeInit`) and
//! roughly 9 KB on the server side (`HandshakeResponse`). Both exceed
//! the typical 1500-byte Ethernet MTU, so the kernel has to perform
//! IP-level fragmentation. Many commercial hosters (and some home
//! ISPs / middle-boxes) silently drop fragmented UDP as an anti-DDoS
//! measure, which makes the handshake impossible to complete on UDP
//! alone.
//!
//! We solve this at the protocol layer: the handshake payload is
//! split into chunks that each fit cleanly in one UDP datagram, each
//! chunk is wrapped in a [`HandshakeFragment`] message, and the
//! receiver reassembles the original bytes before handing them to the
//! existing handshake state machine. IP-level fragmentation is never
//! triggered.
//!
//! # Wire format
//!
//! Every fragment is carried as a standalone packet with an ordinary
//! [`crate::protocol::PacketHeader`] whose
//! `msg_type = MessageType::HandshakeFragment`, `session_id = 0`,
//! `key_id = 0`, `counter = 0` (pre-session packet, same convention
//! as `HandshakeInit`). After the header comes the fragment payload:
//!
//! ```text
//! offset  size  field
//! ------  ----  -----------------------------------------------
//!   0      1    inner_msg_type (1 = HandshakeInit,
//!                               11 = EncryptedHandshakeInit,
//!                               2 = HandshakeResponse)
//!   1      4    frag_id        (u32 BE, random per handshake attempt)
//!   5      2    frag_index     (u16 BE, 0-indexed)
//!   7      2    frag_total     (u16 BE, total chunks for this handshake)
//!   9      2    payload_len    (u16 BE, length of `payload` below)
//!  11      N    payload        (raw bytes of the original message chunk)
//! ```
//!
//! Header overhead is [`FRAGMENT_HEADER_SIZE`] = 11 bytes. Combined
//! with the outer [`crate::protocol::HEADER_SIZE`] (24 bytes) this
//! leaves 1165 bytes per fragment for a conservative 1200-byte
//! per-packet ceiling, or about 1437 bytes if the operator knows the
//! full Ethernet MTU is available. The default payload ceiling
//! [`MAX_FRAGMENT_PAYLOAD`] = 1165 bytes gives safe margins for PPPoE,
//! IPv6 overhead, and single-hop overlays.
//!
//! # Anti-DoS
//!
//! The [`Reassembly`] buffer is:
//!
//! * keyed by `(SocketAddr, frag_id)` — two different sources, or two
//!   different attempts from one source, do not collide;
//! * bounded in entry count, per-entry fragment count, per-entry byte
//!   count, and total byte count across entries;
//! * age-bounded by a TTL (default 5 s); expired entries are reclaimed
//!   lazily on every insert;
//! * strict on consistency: the `frag_total` and `inner_msg_type` of
//!   subsequent fragments must match the first one, otherwise the
//!   whole entry is dropped.
//!
//! These bounds cap the worst-case memory cost of a source spoofing
//! partial reassemblies. They are also enforced on the client side
//! (when reassembling a [`HandshakeResponse`]), but because the client
//! only talks to one server the cap is trivially met.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::error::ProtocolError;
use crate::types::MessageType;

// ---------------------------------------------------------------------------
// Wire format constants.
// ---------------------------------------------------------------------------

/// Fixed header size of a [`HandshakeFragment`] on the wire (11 bytes).
///
/// `inner_msg_type(1) + frag_id(4) + frag_index(2) + frag_total(2) + payload_len(2)`
pub const FRAGMENT_HEADER_SIZE: usize = 1 + 4 + 2 + 2 + 2;

/// Conservative per-fragment payload ceiling, in bytes.
///
/// 1200-byte target per-UDP-datagram (minus outer
/// [`crate::protocol::HEADER_SIZE`] of 24, minus
/// [`FRAGMENT_HEADER_SIZE`] of 11) = 1165 bytes. This leaves room for
/// IPv6 (40-byte IP header vs 20 for IPv4), PPPoE (+8), typical overlay
/// encapsulations, and still fits comfortably in the common 1500-byte
/// Ethernet path MTU.
pub const MAX_FRAGMENT_PAYLOAD: usize = 1165;

/// Maximum number of fragments a single handshake may be split into.
///
/// 32 fragments × 1165 bytes = 37.28 KB, which comfortably covers the
/// biggest serialised handshake we produce (Level 5 `HandshakeResponse`,
/// ~9 KB). Hard upper bound — anything larger is almost certainly
/// attacker-crafted and is rejected.
pub const MAX_FRAGMENTS_PER_HANDSHAKE: u16 = 32;

/// Threshold above which the client splits an outbound handshake
/// message into fragments. Messages at or below this size are sent as
/// a single UDP datagram with the original [`MessageType`] header.
///
/// Equals the conservative per-UDP-datagram ceiling (1200 bytes)
/// minus the outer [`crate::protocol::HEADER_SIZE`] (24 bytes), i.e.
/// 1176 bytes of payload fit in one un-fragmented packet. Anything
/// above that goes through the fragmentation path.
pub const FRAGMENTATION_THRESHOLD: usize = 1176;

// ---------------------------------------------------------------------------
// Wire message.
// ---------------------------------------------------------------------------

/// A single on-wire chunk of a fragmented handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeFragment {
    /// Which kind of message is being fragmented
    /// ([`MessageType::HandshakeInit`],
    /// [`MessageType::EncryptedHandshakeInit`], or
    /// [`MessageType::HandshakeResponse`]).
    ///
    /// Copied from the first fragment; every subsequent fragment for
    /// the same `frag_id` MUST declare the same inner type, or the
    /// reassembler drops the whole entry.
    pub inner_msg_type: MessageType,
    /// Random identifier for this handshake attempt, chosen by the
    /// sender. Prevents fragments of different concurrent handshakes
    /// from colliding in the receiver's reassembly buffer.
    pub frag_id: u32,
    /// Zero-based chunk index. `frag_index < frag_total`.
    pub frag_index: u16,
    /// Total number of fragments in this handshake. `1..=MAX_FRAGMENTS_PER_HANDSHAKE`.
    pub frag_total: u16,
    /// Raw bytes of the original message's sub-slice for this chunk.
    pub payload: Vec<u8>,
}

impl HandshakeFragment {
    /// Maximum encoded size on the wire for a worst-case full fragment.
    pub const MAX_ENCODED_SIZE: usize = FRAGMENT_HEADER_SIZE + MAX_FRAGMENT_PAYLOAD;

    /// Serialise this fragment to its on-wire bytes (without the outer
    /// [`crate::protocol::PacketHeader`] — the caller prepends it).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_SIZE + self.payload.len());
        out.push(self.inner_msg_type.as_u8());
        out.extend_from_slice(&self.frag_id.to_be_bytes());
        out.extend_from_slice(&self.frag_index.to_be_bytes());
        out.extend_from_slice(&self.frag_total.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a fragment body (everything after the outer `PacketHeader`).
    ///
    /// Validates the structural invariants (`frag_index < frag_total`,
    /// `frag_total >= 1 && <= MAX_FRAGMENTS_PER_HANDSHAKE`,
    /// `inner_msg_type ∈ {HandshakeInit, EncryptedHandshakeInit, HandshakeResponse}`,
    /// declared `payload_len` matches the remaining bytes). Returns a
    /// [`ProtocolError`] on any violation so invalid packets are
    /// dropped before being fed into the reassembler.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < FRAGMENT_HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                needed: FRAGMENT_HEADER_SIZE,
                available: bytes.len(),
            });
        }

        let inner_msg_type = MessageType::from_u8(bytes[0]).ok_or_else(|| {
            ProtocolError::InvalidData(format!(
                "unknown inner_msg_type byte {} in HandshakeFragment",
                bytes[0]
            ))
        })?;
        if !Self::is_valid_inner_type(inner_msg_type) {
            return Err(ProtocolError::InvalidData(format!(
                "inner_msg_type {:?} is not a valid fragmentable handshake message",
                inner_msg_type
            )));
        }

        let frag_id = u32::from_be_bytes(bytes[1..5].try_into().expect("slice length 4"));
        let frag_index = u16::from_be_bytes(bytes[5..7].try_into().expect("slice length 2"));
        let frag_total = u16::from_be_bytes(bytes[7..9].try_into().expect("slice length 2"));
        let payload_len =
            u16::from_be_bytes(bytes[9..11].try_into().expect("slice length 2")) as usize;

        if frag_total == 0 || frag_total > MAX_FRAGMENTS_PER_HANDSHAKE {
            return Err(ProtocolError::InvalidData(format!(
                "frag_total {} out of range (1..={})",
                frag_total, MAX_FRAGMENTS_PER_HANDSHAKE
            )));
        }
        if frag_index >= frag_total {
            return Err(ProtocolError::InvalidData(format!(
                "frag_index {} >= frag_total {}",
                frag_index, frag_total
            )));
        }

        let payload_start = FRAGMENT_HEADER_SIZE;
        let payload_end = payload_start + payload_len;
        if payload_len > MAX_FRAGMENT_PAYLOAD {
            return Err(ProtocolError::InvalidData(format!(
                "payload_len {} exceeds MAX_FRAGMENT_PAYLOAD {}",
                payload_len, MAX_FRAGMENT_PAYLOAD
            )));
        }
        if bytes.len() < payload_end {
            return Err(ProtocolError::PacketTooShort {
                needed: payload_end,
                available: bytes.len(),
            });
        }

        Ok(Self {
            inner_msg_type,
            frag_id,
            frag_index,
            frag_total,
            payload: bytes[payload_start..payload_end].to_vec(),
        })
    }

    /// True if `inner_msg_type` is one of the three messages we
    /// actually fragment. Rejecting everything else prevents an
    /// attacker from wrapping a `Data` packet (or anything else) in a
    /// fragment envelope.
    const fn is_valid_inner_type(ty: MessageType) -> bool {
        matches!(
            ty,
            MessageType::HandshakeInit
                | MessageType::EncryptedHandshakeInit
                | MessageType::HandshakeResponse
        )
    }
}

// ---------------------------------------------------------------------------
// Splitter.
// ---------------------------------------------------------------------------

/// Error returned by [`build_handshake_fragments`] / [`split_payload`]
/// when the caller hands in something the fragmentation layer cannot
/// represent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FragmentError {
    /// The inner message type is not one we fragment.
    InvalidInnerType(MessageType),
    /// The payload would require more than
    /// [`MAX_FRAGMENTS_PER_HANDSHAKE`] chunks.
    PayloadTooLarge {
        payload_len: usize,
        required_fragments: usize,
    },
    /// The caller requested a zero-length payload, which has nothing
    /// useful to fragment.
    EmptyPayload,
}

impl std::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInnerType(ty) => write!(
                f,
                "cannot fragment message of type {:?}; fragmentation only applies to \
                 HandshakeInit / EncryptedHandshakeInit / HandshakeResponse",
                ty
            ),
            Self::PayloadTooLarge {
                payload_len,
                required_fragments,
            } => write!(
                f,
                "payload of {} bytes would need {} fragments (max {})",
                payload_len, required_fragments, MAX_FRAGMENTS_PER_HANDSHAKE
            ),
            Self::EmptyPayload => write!(f, "cannot fragment an empty payload"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Split an already-serialised message body into N fragments.
///
/// `frag_id` is assigned by the caller (so the caller can log / trace
/// a handshake attempt end-to-end). Each fragment carries up to
/// [`MAX_FRAGMENT_PAYLOAD`] bytes of payload. The last fragment carries
/// whatever is left over.
pub fn split_payload(
    inner_msg_type: MessageType,
    frag_id: u32,
    payload: &[u8],
) -> Result<Vec<HandshakeFragment>, FragmentError> {
    if !HandshakeFragment::is_valid_inner_type(inner_msg_type) {
        return Err(FragmentError::InvalidInnerType(inner_msg_type));
    }
    if payload.is_empty() {
        return Err(FragmentError::EmptyPayload);
    }

    let required = payload.len().div_ceil(MAX_FRAGMENT_PAYLOAD);
    if required > usize::from(MAX_FRAGMENTS_PER_HANDSHAKE) {
        return Err(FragmentError::PayloadTooLarge {
            payload_len: payload.len(),
            required_fragments: required,
        });
    }
    let frag_total = required as u16;

    let mut fragments = Vec::with_capacity(required);
    for (index, chunk) in payload.chunks(MAX_FRAGMENT_PAYLOAD).enumerate() {
        fragments.push(HandshakeFragment {
            inner_msg_type,
            frag_id,
            frag_index: index as u16,
            frag_total,
            payload: chunk.to_vec(),
        });
    }
    Ok(fragments)
}

/// Split + serialise each fragment body (still without the outer
/// `PacketHeader`).
///
/// Typical sender usage is to prepend a fresh `PacketHeader` to each
/// returned `Vec<u8>` before putting it on the wire.
pub fn build_handshake_fragments(
    inner_msg_type: MessageType,
    frag_id: u32,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, FragmentError> {
    Ok(split_payload(inner_msg_type, frag_id, payload)?
        .into_iter()
        .map(|f| f.to_bytes())
        .collect())
}

// ---------------------------------------------------------------------------
// Reassembler.
// ---------------------------------------------------------------------------

/// Tunable resource bounds for a [`Reassembly`] buffer.
///
/// All the defaults in [`ReassemblerConfig::server_default`] are
/// intentionally conservative so an attacker flooding spoofed first
/// fragments cannot cost more than ~16 MiB of heap on the server.
#[derive(Clone, Copy, Debug)]
pub struct ReassemblerConfig {
    /// Maximum number of concurrent in-flight reassemblies. When the
    /// cap is reached, inserting a new fragment evicts the oldest
    /// entry (by first-seen timestamp) first.
    pub max_entries: usize,
    /// Maximum total bytes held across all entries. When reached, the
    /// oldest entries are evicted until the total fits again.
    pub max_total_bytes: usize,
    /// Maximum bytes an individual reassembly entry may accumulate.
    /// An entry exceeding this is dropped (not evicted — it will not
    /// be completed, because further fragments will not grow it any
    /// further than this cap).
    pub max_entry_bytes: usize,
    /// Maximum number of chunks a single in-progress reassembly may
    /// carry. Decouples server memory posture from the wire-format
    /// ceiling [`MAX_FRAGMENTS_PER_HANDSHAKE`]: an operator can tighten
    /// this independently (e.g. if an attacker grammar is observed in
    /// production) without recompiling the protocol constant. Defaults
    /// to [`MAX_FRAGMENTS_PER_HANDSHAKE`].
    pub max_fragments_per_entry: u16,
    /// Time-to-live for incomplete entries. Once an entry's
    /// `first_seen` is older than `ttl`, the next
    /// [`Reassembly::insert`] call reclaims it. A client that does
    /// not finish delivering all fragments within this window starts
    /// over with a fresh `frag_id`.
    pub ttl: Duration,
}

impl ReassemblerConfig {
    /// Defaults sized for a busy public HPN server.
    #[must_use]
    pub const fn server_default() -> Self {
        Self {
            max_entries: 1024,
            max_total_bytes: 16 * 1024 * 1024, // 16 MiB
            max_entry_bytes: 64 * 1024,        // 64 KiB
            max_fragments_per_entry: MAX_FRAGMENTS_PER_HANDSHAKE,
            ttl: Duration::from_secs(5),
        }
    }

    /// Defaults sized for a single client reassembling the server's
    /// response. Only one in-flight reassembly, tiny footprint.
    #[must_use]
    pub const fn client_default() -> Self {
        Self {
            max_entries: 4,
            max_total_bytes: 256 * 1024, // 256 KiB
            max_entry_bytes: 64 * 1024,
            max_fragments_per_entry: MAX_FRAGMENTS_PER_HANDSHAKE,
            ttl: Duration::from_secs(5),
        }
    }
}

/// Runtime counters exposed for observability / metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReassemblerStats {
    /// Fragments accepted and inserted into an entry.
    pub fragments_inserted: u64,
    /// Fragments rejected because they would have overflowed a cap,
    /// or were structurally inconsistent with an existing entry.
    pub fragments_dropped: u64,
    /// Fragments accepted as duplicates (same index already present);
    /// the entry is unchanged.
    pub fragments_duplicate: u64,
    /// Entries that completed successfully and were handed back to
    /// the caller.
    pub entries_completed: u64,
    /// Entries evicted before completion because the LRU cap was
    /// reached.
    pub entries_evicted: u64,
    /// Entries reclaimed because they exceeded [`ReassemblerConfig::ttl`].
    pub entries_expired: u64,
    /// Entries dropped because their declared `frag_total` would
    /// exceed [`ReassemblerConfig::max_entry_bytes`] or
    /// [`MAX_FRAGMENTS_PER_HANDSHAKE`].
    pub entries_rejected: u64,
}

/// In-progress reassembly of a single handshake. Private — only the
/// [`Reassembly`] buffer touches this.
#[derive(Debug)]
struct Entry {
    inner_msg_type: MessageType,
    frag_total: u16,
    chunks: Vec<Option<Vec<u8>>>,
    received_count: u16,
    total_bytes: usize,
    first_seen: Instant,
}

/// Bounded, TTL-indexed reassembly buffer for [`HandshakeFragment`]
/// messages.
///
/// The buffer is NOT thread-safe by itself; wrap in
/// `parking_lot::Mutex` if shared across workers. On our server the
/// control-message dispatch is single-threaded so the bare type is
/// enough.
pub struct Reassembly {
    config: ReassemblerConfig,
    entries: HashMap<(SocketAddr, u32), Entry>,
    total_bytes: usize,
    stats: ReassemblerStats,
}

impl Reassembly {
    /// Build a reassembler with the given resource bounds.
    #[must_use]
    pub fn new(config: ReassemblerConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            total_bytes: 0,
            stats: ReassemblerStats::default(),
        }
    }

    /// Current live-entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no reassembly is in progress.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot of the operational counters.
    #[must_use]
    pub fn stats(&self) -> ReassemblerStats {
        self.stats
    }

    /// Whether there is already an in-progress reassembly for this
    /// `(source, frag_id)` key. Used by the server-side dispatch to
    /// charge the per-IP rate limiter only on fragments that would
    /// create a NEW reassembly entry, so a legitimate multi-fragment
    /// handshake still spends exactly one token.
    #[must_use]
    pub fn contains(&self, source: SocketAddr, frag_id: u32) -> bool {
        self.entries.contains_key(&(source, frag_id))
    }

    /// Helper: decrement `self.total_bytes` defensively. The invariant
    /// is that `self.total_bytes` always equals the sum of
    /// `entry.total_bytes` for every entry currently in the map, so a
    /// plain `-=` is arithmetically safe. We use `saturating_sub`
    /// here anyway so that a hypothetical future refactor that
    /// accidentally desynchronises the counter cannot silently wrap to
    /// `usize::MAX` in release builds — the debug assertion surfaces
    /// the bug during development.
    fn debit_bytes(&mut self, bytes: usize) {
        debug_assert!(
            self.total_bytes >= bytes,
            "Reassembly::debit_bytes invariant broken: total_bytes={} < bytes={}",
            self.total_bytes,
            bytes,
        );
        self.total_bytes = self.total_bytes.saturating_sub(bytes);
    }

    /// Insert a newly-arrived fragment. Returns `Some((inner_type,
    /// reassembled_bytes))` iff this fragment completed a reassembly.
    ///
    /// The caller has already decoded the outer `PacketHeader` and
    /// the [`HandshakeFragment`] body. The caller is also responsible
    /// for any per-IP rate limiting; this buffer only enforces
    /// memory / count / TTL bounds.
    pub fn insert(
        &mut self,
        source: SocketAddr,
        fragment: HandshakeFragment,
    ) -> Option<(MessageType, Vec<u8>)> {
        let now = Instant::now();
        self.purge_expired(now);

        let key = (source, fragment.frag_id);

        // Reject fragments that, on their own, already imply a
        // too-big handshake. This lets us drop the entry before
        // allocating anything. Two independent ceilings:
        //   1. the declared total payload size fits in `max_entry_bytes`
        //   2. the declared fragment count fits in `max_fragments_per_entry`
        //      (operator-tunable; decoupled from the wire constant)
        let declared_bytes = usize::from(fragment.frag_total).saturating_mul(MAX_FRAGMENT_PAYLOAD);
        if fragment.frag_total == 0
            || fragment.frag_total > MAX_FRAGMENTS_PER_HANDSHAKE
            || fragment.frag_total > self.config.max_fragments_per_entry
            || declared_bytes > self.config.max_entry_bytes
        {
            self.stats.entries_rejected = self.stats.entries_rejected.saturating_add(1);
            return None;
        }

        if let Some(entry) = self.entries.get_mut(&key) {
            // Validate consistency with the previously-seen fragments.
            if entry.frag_total != fragment.frag_total
                || entry.inner_msg_type != fragment.inner_msg_type
            {
                // An attacker (or a genuinely broken peer) is
                // sending contradictory totals / types. Drop the
                // whole entry so we never reassemble an attacker-
                // composed mixture. Must release the `entry` borrow
                // before calling `self.debit_bytes` (which re-borrows
                // `self` mutably), so we read the bytes count first,
                // then remove the entry, then debit.
                let bytes = entry.total_bytes;
                self.entries.remove(&key);
                self.debit_bytes(bytes);
                self.stats.fragments_dropped = self.stats.fragments_dropped.saturating_add(1);
                return None;
            }

            let index = fragment.frag_index as usize;
            let slot = entry
                .chunks
                .get_mut(index)
                .expect("bounds already validated by from_bytes");

            if slot.is_some() {
                // Duplicate — keep the first copy, ignore the rest.
                self.stats.fragments_duplicate = self.stats.fragments_duplicate.saturating_add(1);
                return None;
            }

            let chunk_len = fragment.payload.len();
            if entry.total_bytes.saturating_add(chunk_len) > self.config.max_entry_bytes {
                // Entry would exceed its own byte cap; drop it —
                // reassembly cannot complete correctly anyway. Same
                // ordering trick as above to avoid the double mutable
                // borrow of `self`.
                let bytes = entry.total_bytes;
                self.entries.remove(&key);
                self.debit_bytes(bytes);
                self.stats.fragments_dropped = self.stats.fragments_dropped.saturating_add(1);
                return None;
            }

            *slot = Some(fragment.payload);
            entry.received_count += 1;
            entry.total_bytes += chunk_len;
            self.total_bytes += chunk_len;
            self.stats.fragments_inserted = self.stats.fragments_inserted.saturating_add(1);

            if entry.received_count == entry.frag_total {
                // Complete — remove and reassemble.
                let entry = self.entries.remove(&key).expect("we just had it");
                self.debit_bytes(entry.total_bytes);
                self.stats.entries_completed = self.stats.entries_completed.saturating_add(1);
                return Some(reassemble(entry));
            }
        } else {
            // New entry — enforce caps before allocating.
            self.enforce_caps_for_new_entry(now);

            let index = fragment.frag_index as usize;
            let mut chunks = vec![None; fragment.frag_total as usize];
            let chunk_len = fragment.payload.len();
            chunks[index] = Some(fragment.payload);

            let entry = Entry {
                inner_msg_type: fragment.inner_msg_type,
                frag_total: fragment.frag_total,
                chunks,
                received_count: 1,
                total_bytes: chunk_len,
                first_seen: now,
            };
            self.total_bytes += chunk_len;
            self.stats.fragments_inserted = self.stats.fragments_inserted.saturating_add(1);

            if entry.received_count == entry.frag_total {
                // A single-fragment "fragment" — complete on the
                // spot, no entry retained.
                self.debit_bytes(entry.total_bytes);
                self.stats.entries_completed = self.stats.entries_completed.saturating_add(1);
                return Some(reassemble(entry));
            }

            self.entries.insert(key, entry);
        }

        None
    }

    /// Drop every entry older than `config.ttl`.
    ///
    /// Called on every `insert`, so this is on the server's hottest
    /// control-plane path. We short-circuit when either (a) the map
    /// is empty, or (b) a cheap pre-scan proves no entry is expired,
    /// so the common case never allocates.
    fn purge_expired(&mut self, now: Instant) {
        if self.entries.is_empty() {
            return;
        }
        let ttl = self.config.ttl;
        if !self
            .entries
            .values()
            .any(|e| now.saturating_duration_since(e.first_seen) > ttl)
        {
            // Hot path: no expired entries, skip the retain + stats
            // bookkeeping entirely.
            return;
        }

        // Rare path: drain expired entries in-place, no intermediate
        // `Vec`. `retain` gives us a mutable closure view of
        // `total_bytes` + `stats` alongside the map walk.
        let total = &mut self.total_bytes;
        let entries_expired = &mut self.stats.entries_expired;
        self.entries.retain(|_, e| {
            if now.saturating_duration_since(e.first_seen) > ttl {
                debug_assert!(
                    *total >= e.total_bytes,
                    "Reassembly::purge_expired invariant broken: total={} < e.total_bytes={}",
                    *total,
                    e.total_bytes
                );
                *total = total.saturating_sub(e.total_bytes);
                *entries_expired = entries_expired.saturating_add(1);
                false
            } else {
                true
            }
        });
    }

    /// Evict oldest entries until a new one will fit within both
    /// `max_entries` and `max_total_bytes`.
    fn enforce_caps_for_new_entry(&mut self, _now: Instant) {
        while self.entries.len() >= self.config.max_entries
            || self.total_bytes >= self.config.max_total_bytes
        {
            let Some(oldest_key) = self.oldest_key() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest_key) {
                self.debit_bytes(entry.total_bytes);
                self.stats.entries_evicted = self.stats.entries_evicted.saturating_add(1);
            }
        }
    }

    fn oldest_key(&self) -> Option<(SocketAddr, u32)> {
        self.entries
            .iter()
            .min_by_key(|(_, e)| e.first_seen)
            .map(|(k, _)| *k)
    }
}

fn reassemble(entry: Entry) -> (MessageType, Vec<u8>) {
    let mut out = Vec::with_capacity(entry.total_bytes);
    for chunk in entry.chunks {
        // Safe: `received_count == frag_total` was the precondition
        // for calling this, so every slot is Some.
        let chunk = chunk.expect("reassemble requires every slot filled");
        out.extend_from_slice(&chunk);
    }
    (entry.inner_msg_type, out)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), port)
    }

    // ---------- HandshakeFragment wire format ----------

    #[test]
    fn fragment_roundtrips() {
        let f = HandshakeFragment {
            inner_msg_type: MessageType::EncryptedHandshakeInit,
            frag_id: 0xDEAD_BEEF,
            frag_index: 3,
            frag_total: 5,
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        let bytes = f.to_bytes();
        // Header layout is exactly 11 bytes + payload.
        assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE + 9);
        // Type byte.
        assert_eq!(bytes[0], MessageType::EncryptedHandshakeInit.as_u8());
        // frag_id big-endian.
        assert_eq!(&bytes[1..5], &[0xDE, 0xAD, 0xBE, 0xEF]);
        // frag_index / frag_total.
        assert_eq!(&bytes[5..7], &[0x00, 0x03]);
        assert_eq!(&bytes[7..9], &[0x00, 0x05]);
        // payload_len.
        assert_eq!(&bytes[9..11], &[0x00, 0x09]);

        let parsed = HandshakeFragment::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn fragment_rejects_bad_inner_type() {
        let mut bytes = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 1,
            payload: vec![0xAA],
        }
        .to_bytes();
        // Overwrite the inner type with MessageType::Data, which we
        // forbid as a fragmentable inner type.
        bytes[0] = MessageType::Data.as_u8();
        assert!(HandshakeFragment::from_bytes(&bytes).is_err());
    }

    #[test]
    fn fragment_rejects_index_at_or_above_total() {
        let mut f = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 1,
            frag_total: 1,
            payload: vec![0],
        };
        assert!(HandshakeFragment::from_bytes(&f.to_bytes()).is_err());

        f.frag_index = 0;
        f.frag_total = 0;
        assert!(HandshakeFragment::from_bytes(&f.to_bytes()).is_err());
    }

    #[test]
    fn fragment_rejects_oversized_total() {
        let bytes = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: MAX_FRAGMENTS_PER_HANDSHAKE + 1,
            payload: vec![0],
        }
        .to_bytes();
        assert!(HandshakeFragment::from_bytes(&bytes).is_err());
    }

    #[test]
    fn fragment_rejects_oversized_payload() {
        let mut bytes = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 1,
            payload: vec![0u8; 10],
        }
        .to_bytes();
        // Tamper the payload_len field so it declares more than MAX_FRAGMENT_PAYLOAD.
        let bad_len = (MAX_FRAGMENT_PAYLOAD as u16 + 1).to_be_bytes();
        bytes[9..11].copy_from_slice(&bad_len);
        assert!(HandshakeFragment::from_bytes(&bytes).is_err());
    }

    #[test]
    fn fragment_rejects_truncated() {
        let bytes = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 1,
            payload: vec![0u8; 50],
        }
        .to_bytes();
        // Chop off the final byte of the payload.
        assert!(HandshakeFragment::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        // Chop off the header.
        assert!(HandshakeFragment::from_bytes(&bytes[..5]).is_err());
    }

    // ---------- Splitter ----------

    #[test]
    fn split_and_rejoin_roundtrip() {
        // Use a payload that forces 4 fragments at 1165 bytes each plus
        // a 321-byte tail.
        let payload: Vec<u8> = (0..4981u32).map(|i| (i % 251) as u8).collect();
        let fragments =
            split_payload(MessageType::EncryptedHandshakeInit, 0xCAFE_BABE, &payload).unwrap();
        assert_eq!(fragments.len(), 5);
        for (i, f) in fragments.iter().enumerate() {
            assert_eq!(f.frag_index as usize, i);
            assert_eq!(f.frag_total, 5);
            assert_eq!(f.frag_id, 0xCAFE_BABE);
        }

        // Round-trip through a reassembler.
        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        let mut final_result = None;
        for f in fragments {
            let r_result = r.insert(addr(1), f);
            if let Some(v) = r_result {
                final_result = Some(v);
            }
        }
        let (ty, reassembled) = final_result.expect("reassembly must complete");
        assert_eq!(ty, MessageType::EncryptedHandshakeInit);
        assert_eq!(reassembled, payload);
        assert_eq!(r.stats().entries_completed, 1);
    }

    #[test]
    fn split_rejects_invalid_inner_type() {
        let err = split_payload(MessageType::Data, 0, b"x").unwrap_err();
        assert_eq!(err, FragmentError::InvalidInnerType(MessageType::Data));
    }

    #[test]
    fn split_rejects_empty_payload() {
        let err = split_payload(MessageType::HandshakeInit, 0, &[]).unwrap_err();
        assert_eq!(err, FragmentError::EmptyPayload);
    }

    #[test]
    fn split_rejects_oversize_payload() {
        let payload = vec![0u8; (MAX_FRAGMENTS_PER_HANDSHAKE as usize + 1) * MAX_FRAGMENT_PAYLOAD];
        let err = split_payload(MessageType::HandshakeInit, 0, &payload).unwrap_err();
        assert!(matches!(err, FragmentError::PayloadTooLarge { .. }));
    }

    // ---------- Reassembler: out-of-order, duplicates, TTL, caps ----------

    #[test]
    fn reassembles_out_of_order() {
        let payload: Vec<u8> = (0..3500u32).map(|i| (i as u8).wrapping_add(0x42)).collect();
        let frags = split_payload(MessageType::HandshakeResponse, 42, &payload).unwrap();
        assert_eq!(frags.len(), 4);

        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        // Deliver in reverse order (3, 2, 1, 0).
        for f in frags.into_iter().rev() {
            let _ = r.insert(addr(1), f);
        }
        // After all four arrive the reassembler should be empty again.
        assert!(r.is_empty());
        assert_eq!(r.stats().entries_completed, 1);
    }

    #[test]
    fn duplicates_are_dropped_silently() {
        let frags = split_payload(MessageType::HandshakeInit, 7, &vec![0u8; 2000]).unwrap();
        assert_eq!(frags.len(), 2);
        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        // Re-deliver fragment 0 three times before delivering fragment 1.
        let f0 = frags[0].clone();
        assert!(r.insert(addr(1), f0.clone()).is_none());
        assert!(r.insert(addr(1), f0.clone()).is_none());
        assert!(r.insert(addr(1), f0).is_none());
        assert_eq!(r.stats().fragments_duplicate, 2);
        // Delivering the missing fragment 1 completes the reassembly.
        assert!(r.insert(addr(1), frags[1].clone()).is_some());
    }

    #[test]
    fn ttl_expires_stale_entries() {
        let mut r = Reassembly::new(ReassemblerConfig {
            ttl: Duration::from_millis(20),
            ..ReassemblerConfig::server_default()
        });
        let frags = split_payload(MessageType::HandshakeInit, 1, &vec![0u8; 2000]).unwrap();
        assert!(r.insert(addr(1), frags[0].clone()).is_none());
        std::thread::sleep(Duration::from_millis(60));
        // Insert a fresh fragment for a different frag_id; purge fires.
        let frags2 = split_payload(MessageType::HandshakeInit, 2, &[0u8; 100]).unwrap();
        let result = r.insert(addr(1), frags2.into_iter().next().unwrap());
        assert!(
            result.is_some(),
            "single-fragment message completes immediately"
        );
        assert!(r.is_empty(), "stale first entry must be reclaimed");
        assert_eq!(r.stats().entries_expired, 1);
    }

    #[test]
    fn different_sources_do_not_collide() {
        let frags_a = split_payload(MessageType::HandshakeInit, 1, &vec![0x11; 2000]).unwrap();
        let frags_b = split_payload(MessageType::HandshakeInit, 1, &vec![0x22; 2000]).unwrap();
        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        // Deliver the first fragment of each source; both sit as
        // distinct entries because the SocketAddr differs.
        assert!(r.insert(addr(1), frags_a[0].clone()).is_none());
        assert!(r.insert(addr(2), frags_b[0].clone()).is_none());
        assert_eq!(r.len(), 2);
        // Finish both.
        let done_a = r.insert(addr(1), frags_a[1].clone()).unwrap();
        assert_eq!(done_a.1, vec![0x11u8; 2000]);
        let done_b = r.insert(addr(2), frags_b[1].clone()).unwrap();
        assert_eq!(done_b.1, vec![0x22u8; 2000]);
    }

    #[test]
    fn inconsistent_frag_total_drops_entry() {
        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        let frag_a = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 3,
            payload: vec![0xAA; 100],
        };
        assert!(r.insert(addr(1), frag_a).is_none());
        // Attacker delivers a fragment with mismatched frag_total for
        // the same (src, frag_id). The entry must be dropped.
        let frag_b = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 1,
            frag_total: 5,
            payload: vec![0xBB; 100],
        };
        assert!(r.insert(addr(1), frag_b).is_none());
        assert!(r.is_empty());
        assert_eq!(r.stats().fragments_dropped, 1);
    }

    #[test]
    fn inconsistent_inner_type_drops_entry() {
        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        let frag_a = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 2,
            payload: vec![0xAA; 100],
        };
        let frag_b = HandshakeFragment {
            inner_msg_type: MessageType::EncryptedHandshakeInit,
            frag_id: 1,
            frag_index: 1,
            frag_total: 2,
            payload: vec![0xBB; 100],
        };
        assert!(r.insert(addr(1), frag_a).is_none());
        assert!(r.insert(addr(1), frag_b).is_none());
        assert!(r.is_empty());
        assert_eq!(r.stats().fragments_dropped, 1);
    }

    #[test]
    fn max_entries_cap_evicts_lru() {
        let mut r = Reassembly::new(ReassemblerConfig {
            max_entries: 2,
            ..ReassemblerConfig::server_default()
        });
        // Three distinct sources, each parks one fragment of a
        // multi-fragment handshake. The third insert must evict one.
        for i in 0..3u16 {
            let frag = HandshakeFragment {
                inner_msg_type: MessageType::HandshakeInit,
                frag_id: u32::from(i),
                frag_index: 0,
                frag_total: 2,
                payload: vec![0u8; 100],
            };
            let _ = r.insert(addr(i + 1), frag);
            // Ensure monotonically-increasing first_seen times.
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(r.len(), 2);
        assert_eq!(r.stats().entries_evicted, 1);
    }

    #[test]
    fn declared_frag_total_above_cap_is_rejected_immediately() {
        let mut r = Reassembly::new(ReassemblerConfig {
            max_entry_bytes: 2000,
            ..ReassemblerConfig::server_default()
        });
        // frag_total that implies > max_entry_bytes when fully filled.
        // 5 * 1165 = 5825 > 2000, so reject.
        let frag = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 5,
            payload: vec![0u8; 10],
        };
        assert!(r.insert(addr(1), frag).is_none());
        assert!(r.is_empty());
        assert_eq!(r.stats().entries_rejected, 1);
    }

    #[test]
    fn single_fragment_message_completes_immediately() {
        let payload = b"hello".to_vec();
        let frag = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeResponse,
            frag_id: 99,
            frag_index: 0,
            frag_total: 1,
            payload: payload.clone(),
        };
        let mut r = Reassembly::new(ReassemblerConfig::client_default());
        let (ty, bytes) = r.insert(addr(1), frag).unwrap();
        assert_eq!(ty, MessageType::HandshakeResponse);
        assert_eq!(bytes, payload);
        assert!(r.is_empty());
    }

    #[test]
    fn splitter_never_returns_fragments_whose_wire_encoding_exceeds_mtu() {
        // Worst case: payload that forces MAX_FRAGMENT_PAYLOAD bytes
        // in every chunk.
        let payload = vec![0u8; MAX_FRAGMENT_PAYLOAD * MAX_FRAGMENTS_PER_HANDSHAKE as usize];
        let fragments = split_payload(MessageType::HandshakeResponse, 1, &payload).unwrap();
        for f in &fragments {
            let encoded = f.to_bytes();
            assert!(
                encoded.len() <= HandshakeFragment::MAX_ENCODED_SIZE,
                "fragment encoded to {} bytes (max {})",
                encoded.len(),
                HandshakeFragment::MAX_ENCODED_SIZE
            );
        }
    }

    // ---------- New-entry detection for rate-limiter gating ----------

    #[test]
    fn contains_tracks_in_progress_reassemblies() {
        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        // 2000 bytes ÷ 1165 (MAX_FRAGMENT_PAYLOAD) ceils to exactly 2
        // fragments.
        let frags = split_payload(MessageType::HandshakeInit, 7, &[0u8; 2000]).unwrap();
        assert_eq!(frags.len(), 2, "test precondition: 2-fragment payload");
        assert!(!r.contains(addr(1), 7));
        assert!(r.insert(addr(1), frags[0].clone()).is_none());
        // In-progress, so contains() returns true — the server dispatch
        // uses this to avoid charging the rate limiter on subsequent
        // fragments of the same attempt.
        assert!(r.contains(addr(1), 7));
        // Different frag_id on the same source is a separate entry.
        assert!(!r.contains(addr(1), 8));
        // Same frag_id on a different source is a separate entry.
        assert!(!r.contains(addr(2), 7));
        // On completion, the entry is removed.
        assert!(r.insert(addr(1), frags[1].clone()).is_some());
        assert!(!r.contains(addr(1), 7));
    }

    // ---------- max_fragments_per_entry ----------

    #[test]
    fn max_fragments_per_entry_rejects_otherwise_valid_totals() {
        let mut r = Reassembly::new(ReassemblerConfig {
            max_fragments_per_entry: 3,
            ..ReassemblerConfig::server_default()
        });
        // frag_total=5 is valid per-wire (<= MAX_FRAGMENTS_PER_HANDSHAKE),
        // but exceeds the operator-configured ceiling -> rejected.
        let frag = HandshakeFragment {
            inner_msg_type: MessageType::HandshakeInit,
            frag_id: 1,
            frag_index: 0,
            frag_total: 5,
            payload: vec![0u8; 10],
        };
        assert!(r.insert(addr(1), frag).is_none());
        assert!(r.is_empty());
        assert_eq!(r.stats().entries_rejected, 1);
    }

    // ---------- Multi-source LRU and max_total_bytes caps ----------

    #[test]
    fn max_total_bytes_cap_evicts_lru_across_sources() {
        // max_entries is comfortably large, the BINDING constraint is
        // the per-byte cap. Fragments of size ~1165 B so each partial
        // entry occupies ~1165 B.
        let mut r = Reassembly::new(ReassemblerConfig {
            max_entries: 1024,
            max_total_bytes: 3 * MAX_FRAGMENT_PAYLOAD, // room for three partials
            ..ReassemblerConfig::server_default()
        });

        // Five distinct sources each park a single fragment of a
        // two-fragment handshake. The fourth insert should evict one
        // prior entry (byte-cap eviction), and the fifth should evict
        // another.
        for i in 0..5u16 {
            let frag = HandshakeFragment {
                inner_msg_type: MessageType::HandshakeInit,
                frag_id: u32::from(i),
                frag_index: 0,
                frag_total: 2,
                payload: vec![0u8; MAX_FRAGMENT_PAYLOAD],
            };
            let _ = r.insert(addr(i + 1), frag);
            // Ensure monotonically-increasing first_seen timestamps so
            // the LRU ordering is deterministic.
            std::thread::sleep(Duration::from_millis(2));
        }
        // After five inserts with a 3-entry byte cap, we expect 3 live
        // entries (the 3 most recent) and 2 evictions.
        assert_eq!(r.len(), 3);
        assert_eq!(r.stats().entries_evicted, 2);
    }

    // ---------- Largest-legitimate-handshake round-trip ----------

    #[test]
    fn reassembles_10kib_handshake_at_level5_size() {
        // 10 KiB payload ≈ upper bound of a Level-5
        // `HandshakeResponse` with full signature + identity hiding.
        // Uses a deterministic pattern so any byte-level corruption
        // during reassembly would be caught by equality.
        let payload: Vec<u8> = (0..10240u32).map(|i| (i as u8).wrapping_mul(31)).collect();
        let fragments =
            split_payload(MessageType::HandshakeResponse, 0x1234_5678, &payload).unwrap();
        assert!(fragments.len() >= 8);

        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        let mut completed = None;
        for f in fragments {
            if let Some(done) = r.insert(addr(1), f) {
                completed = Some(done);
            }
        }
        let (ty, reassembled) = completed.expect("reassembly must complete");
        assert_eq!(ty, MessageType::HandshakeResponse);
        assert_eq!(reassembled, payload);
    }

    // ---------- Shuffled-delivery equality ----------

    #[test]
    fn shuffled_delivery_produces_correct_output() {
        // Property: any permutation of fragment arrival order must
        // reassemble to the same bytes as in-order delivery.
        let payload: Vec<u8> = (0..5000u32).map(|i| (i ^ 0xA5) as u8).collect();
        let fragments = split_payload(MessageType::EncryptedHandshakeInit, 42, &payload).unwrap();

        // Deterministic "shuffle" — ascending-then-descending
        // pattern — without pulling in a PRNG crate.
        let n = fragments.len();
        let mut order: Vec<usize> = Vec::with_capacity(n);
        for i in 0..n {
            if i % 2 == 0 {
                order.push(i / 2);
            } else {
                order.push(n - 1 - (i / 2));
            }
        }

        let mut r = Reassembly::new(ReassemblerConfig::server_default());
        let mut completed = None;
        for idx in order {
            if let Some(done) = r.insert(addr(1), fragments[idx].clone()) {
                completed = Some(done);
            }
        }
        let (_ty, reassembled) = completed.expect("reassembly must complete");
        assert_eq!(reassembled, payload);
    }
}
