//! Handshake state machine for establishing secure sessions.
//!
//! The handshake establishes a shared secret using hybrid KEM and
//! authenticates the server using ML-DSA-65 signatures.

use std::sync::Arc;

use crate::crypto::{
    HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, MlDsaKeypair, MlDsaPublicKey,
    SessionKeys,
};
use crate::error::{CryptoError, ProtocolError};
use crate::protocol::messages::{
    CookieReply, CookieRequest, EncryptedHandshakeInit, HandshakeInit, HandshakeResponse,
    RekeyMessage, RekeyResponse, TunnelConfig,
};
use crate::types::{KeyId, PROTOCOL_VERSION, SessionId};

/// Handshake state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state, ready to start handshake.
    Idle,
    /// Client has sent HandshakeInit, waiting for response or cookie challenge.
    AwaitingResponse,
    /// Client received cookie challenge, solving puzzle.
    SolvingCookie,
    /// Client sent cookie reply, waiting for handshake response.
    AwaitingResponseAfterCookie,
    /// Handshake completed successfully.
    Established,
    /// Handshake failed.
    Failed(String),
}

/// Client-side handshake handler.
pub struct ClientHandshake {
    /// Current state.
    state: HandshakeState,
    /// Client's ephemeral keypair.
    client_keypair: Option<(HybridSecretKey, HybridPublicKey)>,
    /// Client random.
    client_random: Option<[u8; 32]>,
    /// Expected server public key (for pinning).
    expected_server_pk: Option<MlDsaPublicKey>,
    /// Server's static KEM public key for identity hiding (optional).
    /// If provided, HandshakeInit will be encrypted before sending.
    server_kem_pk: Option<HybridPublicKey>,
    /// Session ID assigned by server.
    session_id: Option<SessionId>,
    /// Derived session keys.
    session_keys: Option<SessionKeys>,
    /// Tunnel configuration from server.
    tunnel_config: Option<TunnelConfig>,
    /// Security level for cryptographic operations.
    security_level: crate::crypto::SecurityLevel,
}

impl ClientHandshake {
    /// Create a new client handshake with default security level (Level3).
    #[must_use]
    pub fn new() -> Self {
        Self::with_security_level(crate::crypto::SecurityLevel::default())
    }

    /// Create a new client handshake with specified security level.
    #[must_use]
    pub fn with_security_level(security_level: crate::crypto::SecurityLevel) -> Self {
        Self {
            state: HandshakeState::Idle,
            client_keypair: None,
            client_random: None,
            expected_server_pk: None,
            server_kem_pk: None,
            session_id: None,
            session_keys: None,
            tunnel_config: None,
            security_level,
        }
    }

    /// Create with expected server public key for pinning.
    #[must_use]
    pub fn with_server_pk(server_pk: MlDsaPublicKey) -> Self {
        let mut handshake = Self::new();
        handshake.expected_server_pk = Some(server_pk);
        handshake
    }

    /// Create with expected server public key and security level.
    #[must_use]
    pub fn with_server_pk_and_level(
        server_pk: MlDsaPublicKey,
        security_level: crate::crypto::SecurityLevel,
    ) -> Self {
        let mut handshake = Self::with_security_level(security_level);
        handshake.expected_server_pk = Some(server_pk);
        handshake
    }

    /// Create with full identity hiding support.
    ///
    /// # Arguments
    ///
    /// * `server_signing_pk` - Server's ML-DSA public key for signature verification
    /// * `server_kem_pk` - Server's KEM public key for encrypting HandshakeInit
    /// * `security_level` - Security level for the session
    #[must_use]
    pub fn with_identity_hiding(
        server_signing_pk: MlDsaPublicKey,
        server_kem_pk: HybridPublicKey,
        security_level: crate::crypto::SecurityLevel,
    ) -> Self {
        let mut handshake = Self::with_security_level(security_level);
        handshake.expected_server_pk = Some(server_signing_pk);
        handshake.server_kem_pk = Some(server_kem_pk);
        handshake
    }

    /// Set the server's KEM public key for identity hiding.
    pub fn set_server_kem_pk(&mut self, kem_pk: HybridPublicKey) {
        self.server_kem_pk = Some(kem_pk);
    }

    /// Check if identity hiding is enabled.
    #[must_use]
    pub fn identity_hiding_enabled(&self) -> bool {
        self.server_kem_pk.is_some()
    }

    /// Get the security level for this handshake.
    #[must_use]
    pub const fn security_level(&self) -> crate::crypto::SecurityLevel {
        self.security_level
    }

    /// Get the current handshake state.
    #[must_use]
    pub const fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Check if the handshake is complete.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, HandshakeState::Established)
    }

    /// Create the handshake init message.
    ///
    /// # Errors
    ///
    /// Returns an error if keypair generation fails.
    pub fn create_init(&mut self) -> Result<HandshakeInit, CryptoError> {
        if self.state != HandshakeState::Idle {
            return Err(CryptoError::KeyGeneration);
        }

        // Generate ephemeral keypair with configured security level
        let (sk, pk) = HybridKem::generate_keypair_with_level(self.security_level)?;

        // Create init message with security level
        let init = HandshakeInit::with_security_level(pk.clone(), self.security_level);

        // Store state
        self.client_keypair = Some((sk, pk));
        self.client_random = Some(init.client_random);
        self.state = HandshakeState::AwaitingResponse;

        Ok(init)
    }

    /// Create an encrypted handshake init message for identity hiding.
    ///
    /// This encrypts the `HandshakeInit` using the server's KEM public key,
    /// preventing passive observers from identifying clients by their key patterns.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Server KEM public key is not set (use `set_server_kem_pk` first)
    /// - Keypair generation fails
    /// - Encryption fails
    pub fn create_encrypted_init(&mut self) -> Result<EncryptedHandshakeInit, ProtocolError> {
        // Clone the server KEM public key to avoid borrow conflicts
        let server_kem_pk = self.server_kem_pk.clone().ok_or_else(|| {
            ProtocolError::HandshakeFailed(
                "server KEM public key not set for identity hiding".into(),
            )
        })?;

        // Create the inner init message first
        let inner_init = self.create_init().map_err(|e| {
            ProtocolError::HandshakeFailed(format!("failed to create handshake init: {:?}", e))
        })?;

        // Encrypt it using the server's KEM public key
        EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk)
    }

    /// Process the server's handshake response.
    ///
    /// # Errors
    ///
    /// Returns an error if the response is invalid or verification fails.
    pub fn process_response(
        &mut self,
        response: &HandshakeResponse,
    ) -> Result<(SessionId, SessionKeys, TunnelConfig), ProtocolError> {
        // Can receive response either after initial HandshakeInit or after CookieReply
        if self.state != HandshakeState::AwaitingResponse
            && self.state != HandshakeState::AwaitingResponseAfterCookie
        {
            self.state = HandshakeState::Failed("invalid state".into());
            return Err(ProtocolError::InvalidStateTransition);
        }

        let (client_sk, _client_pk) = self
            .client_keypair
            .as_ref()
            .ok_or(ProtocolError::InvalidStateTransition)?;

        let client_random = self
            .client_random
            .ok_or(ProtocolError::InvalidStateTransition)?;

        // Verify server public key if pinned (constant-time comparison to prevent timing attacks)
        if let Some(ref expected_pk) = self.expected_server_pk {
            use subtle::ConstantTimeEq;
            if expected_pk
                .as_bytes()
                .ct_ne(response.server_static_pk.as_bytes())
                .into()
            {
                self.state = HandshakeState::Failed("server key mismatch".into());
                return Err(ProtocolError::HandshakeFailed(
                    "server public key mismatch".into(),
                ));
            }
        }

        // Verify server public key size matches the requested security level
        // This ensures the server is using the correct ML-DSA variant for the profile
        let expected_pk_size = match self.security_level {
            crate::crypto::SecurityLevel::Level3 => MlDsaPublicKey::SIZE, // 1952 bytes (ML-DSA-65)
            crate::crypto::SecurityLevel::Level5 => MlDsaPublicKey::SIZE_87, // 2592 bytes (ML-DSA-87)
        };
        if response.server_static_pk.as_bytes().len() != expected_pk_size {
            self.state = HandshakeState::Failed("server security level mismatch".into());
            return Err(ProtocolError::HandshakeFailed(format!(
                "server public key size mismatch: expected {} bytes for {:?}, got {}. \
                 Server may not support this security level.",
                expected_pk_size,
                self.security_level,
                response.server_static_pk.as_bytes().len()
            )));
        }

        // Build transcript for signature verification (includes protocol version to prevent downgrade attacks)
        let transcript = build_transcript(
            PROTOCOL_VERSION,
            Some(&response.session_id),
            &client_random,
            &response.server_random,
            &response.server_ciphertext,
            &response.config,
        );

        // Verify signature using the negotiated security level.
        // If this fails, also test the legacy transcript format (without config)
        // to provide a clear diagnostic for mixed-version deployments.
        if crate::crypto::signature::verify(
            &response.server_static_pk,
            &transcript,
            &response.signature,
            self.security_level,
        )
        .is_err()
        {
            let legacy_transcript = build_transcript_legacy_no_config(
                PROTOCOL_VERSION,
                Some(&response.session_id),
                &client_random,
                &response.server_random,
                &response.server_ciphertext,
            );

            let legacy_match = crate::crypto::signature::verify(
                &response.server_static_pk,
                &legacy_transcript,
                &response.signature,
                self.security_level,
            )
            .is_ok();

            self.state = HandshakeState::Failed("signature verification failed".into());
            if legacy_match {
                return Err(ProtocolError::HandshakeFailed(
                    "signature verification failed: server appears to use legacy handshake transcript (missing config binding); update server binary".into(),
                ));
            }
            return Err(ProtocolError::HandshakeFailed(
                "signature verification failed".into(),
            ));
        }

        // Decapsulate to get shared secret
        let handshake_secret = HybridKem::decapsulate(client_sk, &response.server_ciphertext)
            .map_err(|_| {
                self.state = HandshakeState::Failed("decapsulation failed".into());
                ProtocolError::HandshakeFailed("decapsulation failed".into())
            })?;

        // Derive session keys with session context (using server's timestamp)
        tracing::debug!(
            "CLIENT KDF: session_id={}, timestamp={}",
            response.session_id,
            response.kdf_timestamp
        );

        let session_keys = crate::crypto::kdf::derive_session_keys_with_context(
            &handshake_secret,
            &response.session_id,
            response.kdf_timestamp,
        )
        .map_err(|_| {
            self.state = HandshakeState::Failed("key derivation failed".into());
            ProtocolError::HandshakeFailed("key derivation failed".into())
        })?;

        // Keys derived successfully - do NOT log key material
        tracing::debug!("Session keys derived for session {}", response.session_id);

        // Verify key confirmation MAC (proves server has correct keys)
        // Client's recv_key is what server used to compute the MAC (server's send_key)
        verify_key_confirmation(
            &session_keys.recv_key,
            &transcript,
            &response.key_confirmation,
        )
        .inspect_err(|_| {
            self.state = HandshakeState::Failed("key confirmation failed".into());
        })?;

        // Store results
        self.session_id = Some(response.session_id);
        self.session_keys = Some(session_keys.clone());
        self.tunnel_config = Some(response.config.clone());
        self.state = HandshakeState::Established;

        Ok((response.session_id, session_keys, response.config.clone()))
    }

    /// Get the session ID after successful handshake.
    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    /// Take the session keys (consumes them from the handshake).
    #[must_use]
    pub fn take_session_keys(&mut self) -> Option<SessionKeys> {
        self.session_keys.take()
    }

    /// Get the tunnel configuration.
    #[must_use]
    pub fn tunnel_config(&self) -> Option<&TunnelConfig> {
        self.tunnel_config.as_ref()
    }

    /// Process a cookie challenge from the server and create a reply.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The cookie challenge from the server
    ///
    /// # Returns
    ///
    /// Returns a `CookieReply` with the solved proof-of-work.
    ///
    /// # Errors
    ///
    /// Returns an error if the puzzle cannot be solved or if the handshake is in an invalid state.
    pub fn solve_cookie_challenge(
        &mut self,
        challenge: &CookieRequest,
    ) -> Result<CookieReply, ProtocolError> {
        if self.state != HandshakeState::AwaitingResponse {
            return Err(ProtocolError::HandshakeFailed(
                "unexpected cookie challenge".into(),
            ));
        }

        self.state = HandshakeState::SolvingCookie;

        // Get the original HandshakeInit we sent
        let (client_pk, client_random) = self
            .client_keypair
            .as_ref()
            .zip(self.client_random.as_ref())
            .ok_or_else(|| {
                ProtocolError::HandshakeFailed("missing client keypair or random".into())
            })?;

        let handshake_init = HandshakeInit {
            client_ephemeral_pk: client_pk.1.clone(),
            client_random: *client_random,
            security_level: client_pk.1.security_level,
            credentials: None,
        };

        // Solve the puzzle
        let reply = CookieReply::solve(challenge.challenge, challenge.difficulty, handshake_init)?;

        self.state = HandshakeState::AwaitingResponseAfterCookie;
        Ok(reply)
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Cookie HMAC secrets with rotation support.
///
/// The cookie mechanism uses HMAC-SHA256 with a secret known only to the
/// server to self-authenticate stateless `CookieRequest` challenges. Keeping
/// that secret for the full life of the process is a latent risk (memory
/// disclosure = indefinite forgery window), so the secret is rotated
/// periodically. Because legitimately-issued cookies can outlive a rotation
/// (they are valid for `DEFAULT_COOKIE_MAX_AGE_SECS`), one previous secret is
/// kept around: verification tries the current secret first, then the
/// previous one. Both comparisons are constant-time.
struct CookieSecrets {
    /// Current secret, used to sign new `CookieRequest`s.
    current: zeroize::Zeroizing<[u8; 32]>,
    /// Previous secret, accepted during verification for the duration of
    /// `DEFAULT_COOKIE_MAX_AGE_SECS`. `None` before the first rotation.
    previous: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// Instant of the last rotation (or construction).
    last_rotation: std::time::Instant,
}

/// How often the cookie HMAC secret is rotated. 10 minutes is an order of
/// magnitude above the default cookie validity window (60s), so a single
/// previous-secret slot is enough to cover the transition.
const COOKIE_SECRET_ROTATION: std::time::Duration = std::time::Duration::from_secs(600);

/// Server-side handshake handler.
///
/// Uses `Arc<MlDsaKeypair>` to avoid cloning the large keypair (~6KB) on each handshake.
pub struct ServerHandshake {
    /// Server's static keypair for signatures (shared via Arc to avoid cloning).
    server_keypair: Arc<MlDsaKeypair>,
    /// Server's static KEM keypair for identity hiding (optional).
    /// If set, server can decrypt `EncryptedHandshakeInit` messages.
    server_kem_keypair: Option<Arc<(HybridSecretKey, HybridPublicKey)>>,
    /// Cookie mechanism difficulty level (0 = disabled, 8-16 = normal, 20+ = under attack).
    cookie_difficulty: u8,
    /// HMAC-SHA256 secret used to self-authenticate stateless cookie
    /// challenges. Rotated every `COOKIE_SECRET_ROTATION`; one previous
    /// generation is retained so cookies issued just before rotation still
    /// verify until they expire.
    cookie_secrets: parking_lot::Mutex<CookieSecrets>,
}

impl ServerHandshake {
    /// Generate a random cookie secret.
    fn generate_cookie_secret() -> zeroize::Zeroizing<[u8; 32]> {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        zeroize::Zeroizing::new(secret)
    }

    /// Build the initial cookie-secret state.
    fn initial_cookie_secrets() -> parking_lot::Mutex<CookieSecrets> {
        parking_lot::Mutex::new(CookieSecrets {
            current: Self::generate_cookie_secret(),
            previous: None,
            last_rotation: std::time::Instant::now(),
        })
    }

    /// Rotate the cookie secret if the rotation interval has elapsed.
    ///
    /// Kept internal. Called at the top of `create_cookie_request` and
    /// `verify_cookie_reply` — both low-frequency paths (handshake only), so
    /// the Mutex cost is negligible. The rotation is piggy-backed on cookie
    /// operations so we do not need a dedicated background task.
    fn maybe_rotate_cookie_secret(&self) {
        let mut secrets = self.cookie_secrets.lock();
        if secrets.last_rotation.elapsed() >= COOKIE_SECRET_ROTATION {
            let fresh = Self::generate_cookie_secret();
            let old = std::mem::replace(&mut secrets.current, fresh);
            secrets.previous = Some(old);
            secrets.last_rotation = std::time::Instant::now();
        }
    }

    /// Create a new server handshake handler.
    ///
    /// Takes an `Arc<MlDsaKeypair>` to avoid cloning the large keypair (~6KB).
    #[must_use]
    pub fn new(server_keypair: Arc<MlDsaKeypair>) -> Self {
        Self {
            server_keypair,
            server_kem_keypair: None,
            cookie_difficulty: 0, // Disabled by default
            cookie_secrets: Self::initial_cookie_secrets(),
        }
    }

    /// Create a new server handshake handler with identity hiding support.
    ///
    /// # Arguments
    ///
    /// * `server_keypair` - Server's long-term signing keypair (ML-DSA)
    /// * `kem_keypair` - Server's long-term KEM keypair for identity hiding
    #[must_use]
    pub fn with_identity_hiding(
        server_keypair: Arc<MlDsaKeypair>,
        kem_keypair: Arc<(HybridSecretKey, HybridPublicKey)>,
    ) -> Self {
        Self {
            server_keypair,
            server_kem_keypair: Some(kem_keypair),
            cookie_difficulty: 0,
            cookie_secrets: Self::initial_cookie_secrets(),
        }
    }

    /// Create a new server handshake handler with cookie anti-DoS protection enabled.
    ///
    /// # Arguments
    ///
    /// * `server_keypair` - Server's long-term signing keypair
    /// * `difficulty` - Cookie puzzle difficulty (8 = ~256 hashes, 12 = ~4K hashes, 16 = ~65K hashes)
    ///
    /// Recommended values:
    /// - 0: Disabled (for testing or low-traffic servers)
    /// - 8-12: Normal operation (prevents casual DoS)
    /// - 16-20: Under moderate attack
    /// - 20+: Under heavy attack (may impact legitimate clients)
    #[must_use]
    pub fn with_cookie_protection(server_keypair: Arc<MlDsaKeypair>, difficulty: u8) -> Self {
        Self {
            server_keypair,
            server_kem_keypair: None,
            cookie_difficulty: difficulty,
            cookie_secrets: Self::initial_cookie_secrets(),
        }
    }

    /// Create a new server handshake handler with both identity hiding and cookie protection.
    #[must_use]
    pub fn with_identity_hiding_and_cookie(
        server_keypair: Arc<MlDsaKeypair>,
        kem_keypair: Arc<(HybridSecretKey, HybridPublicKey)>,
        difficulty: u8,
    ) -> Self {
        Self {
            server_keypair,
            server_kem_keypair: Some(kem_keypair),
            cookie_difficulty: difficulty,
            cookie_secrets: Self::initial_cookie_secrets(),
        }
    }

    /// Set the KEM keypair for identity hiding.
    pub fn set_kem_keypair(&mut self, kem_keypair: Arc<(HybridSecretKey, HybridPublicKey)>) {
        self.server_kem_keypair = Some(kem_keypair);
    }

    /// Check if identity hiding is supported.
    #[must_use]
    pub fn identity_hiding_supported(&self) -> bool {
        self.server_kem_keypair.is_some()
    }

    /// Get the server's KEM public key (for clients to use in identity hiding).
    #[must_use]
    pub fn kem_public_key(&self) -> Option<&HybridPublicKey> {
        self.server_kem_keypair.as_ref().map(|kp| &kp.1)
    }

    /// Set the cookie difficulty dynamically (e.g., based on server load).
    pub fn set_cookie_difficulty(&mut self, difficulty: u8) {
        self.cookie_difficulty = difficulty;
    }

    /// Get the current cookie difficulty.
    #[must_use]
    pub const fn cookie_difficulty(&self) -> u8 {
        self.cookie_difficulty
    }

    /// Get the server's public key.
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.server_keypair.public_key
    }

    /// Compute HMAC tag for cookie challenge self-authentication using a
    /// specific secret.
    ///
    /// Challenge format: `random_nonce[8] || timestamp[8] || hmac_tag[16]`
    /// HMAC input: `nonce || timestamp || addr_hash || difficulty`
    ///
    /// This makes the challenge stateless and self-authenticating:
    /// the server can verify it issued the challenge without storing state.
    fn compute_cookie_hmac_with(
        secret: &[u8],
        nonce: [u8; 8],
        timestamp: u64,
        addr_hash: [u8; 16],
        difficulty: u8,
    ) -> [u8; 16] {
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let mut data = Vec::with_capacity(8 + 8 + 16 + 1);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&addr_hash);
        data.push(difficulty);
        let tag = hmac::sign(&key, &data);
        let mut result = [0u8; 16];
        result.copy_from_slice(&tag.as_ref()[..16]);
        result
    }

    /// Compute HMAC tag for cookie challenge self-authentication using the
    /// **current** cookie secret.
    ///
    /// Used when issuing new challenges; verification uses
    /// [`Self::compute_cookie_hmac_with`] directly so both the current and
    /// previous secret can be tried without an extra lock acquisition.
    fn compute_cookie_hmac(
        &self,
        nonce: [u8; 8],
        timestamp: u64,
        addr_hash: [u8; 16],
        difficulty: u8,
    ) -> [u8; 16] {
        let secrets = self.cookie_secrets.lock();
        Self::compute_cookie_hmac_with(
            secrets.current.as_ref(),
            nonce,
            timestamp,
            addr_hash,
            difficulty,
        )
    }

    /// Create a cookie challenge request for a client.
    ///
    /// The challenge embeds: `random_nonce[8] || timestamp[8] || HMAC_tag[16]`
    /// This makes it stateless and self-authenticating — the server can verify
    /// on reply that it genuinely issued the challenge, without storing state.
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Client's socket address (for binding cookie to connection)
    ///
    /// Returns a `CookieRequest` that the client must solve before proceeding.
    #[must_use]
    pub fn create_cookie_request(&self, client_addr: &std::net::SocketAddr) -> CookieRequest {
        // Rotate the cookie secret if the interval has elapsed. Piggy-backing
        // on the issue path keeps the secret life-cycle entirely lock-free for
        // the non-cookie (normal) handshake flow.
        self.maybe_rotate_cookie_secret();

        let mut request = CookieRequest::new(self.cookie_difficulty, client_addr);

        // Build self-authenticating challenge:
        // [0..8]   = random nonce (already filled by CookieRequest::new)
        // [8..16]  = timestamp (big-endian u64)
        // [16..32] = HMAC-SHA256 tag (truncated to 16 bytes)
        let nonce: [u8; 8] = request.challenge[0..8]
            .try_into()
            .expect("CookieRequest challenge always has 32 bytes");
        request.challenge[8..16].copy_from_slice(&request.timestamp.to_be_bytes());
        let hmac_tag = self.compute_cookie_hmac(
            nonce,
            request.timestamp,
            request.server_addr_hash,
            request.difficulty,
        );
        request.challenge[16..32].copy_from_slice(&hmac_tag);

        request
    }

    /// Verify a cookie reply from the client.
    ///
    /// Statelessly verifies:
    /// 1. The challenge was genuinely issued by this server (HMAC verification)
    /// 2. The challenge has not expired (timestamp check)
    /// 3. The challenge was bound to this client address
    /// 4. The proof-of-work solution is valid
    ///
    /// # Arguments
    ///
    /// * `reply` - The cookie reply with proof-of-work solution
    /// * `client_addr` - Client's socket address (to verify binding)
    ///
    /// # Errors
    ///
    /// Returns an error if any verification step fails.
    pub fn verify_cookie_reply(
        &self,
        reply: &CookieReply,
        client_addr: &std::net::SocketAddr,
    ) -> Result<(), ProtocolError> {
        // Opportunistic rotation. A cookie issued <10min ago will still
        // verify — its secret becomes the "previous" entry when rotation
        // fires, and we try both below.
        self.maybe_rotate_cookie_secret();

        // Extract embedded fields from the self-authenticating challenge
        let nonce: [u8; 8] = reply.challenge[0..8]
            .try_into()
            .expect("CookieReply challenge always has 32 bytes");
        let timestamp = u64::from_be_bytes(
            reply.challenge[8..16]
                .try_into()
                .expect("CookieReply challenge always has 32 bytes"),
        );
        let received_tag: &[u8] = &reply.challenge[16..32];

        // Recompute client address hash
        let addr_str = client_addr.to_string();
        let mut addr_hash = [0u8; 16];
        let hash = ring::digest::digest(&ring::digest::SHA256, addr_str.as_bytes());
        addr_hash.copy_from_slice(&hash.as_ref()[0..16]);

        // Verify HMAC (constant-time comparison). Accept both the current
        // and (if set) the previous generation's secret: the cookie could
        // have been issued shortly before the last rotation. Both legs are
        // constant-time so verification timing does not leak which secret
        // matched.
        let (current_tag, previous_tag) = {
            let secrets = self.cookie_secrets.lock();
            let current = Self::compute_cookie_hmac_with(
                secrets.current.as_ref(),
                nonce,
                timestamp,
                addr_hash,
                self.cookie_difficulty,
            );
            let previous = secrets.previous.as_ref().map(|prev| {
                Self::compute_cookie_hmac_with(
                    prev.as_ref(),
                    nonce,
                    timestamp,
                    addr_hash,
                    self.cookie_difficulty,
                )
            });
            (current, previous)
        };

        let matches_current = bool::from(subtle::ConstantTimeEq::ct_eq(
            received_tag,
            current_tag.as_ref(),
        ));
        let matches_previous = previous_tag.as_ref().is_some_and(|tag| {
            bool::from(subtle::ConstantTimeEq::ct_eq(received_tag, tag.as_ref()))
        });

        if !matches_current && !matches_previous {
            return Err(ProtocolError::HandshakeFailed(
                "invalid cookie: HMAC verification failed (forged or wrong client)".into(),
            ));
        }

        // Verify timestamp (not expired)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();

        // Allow up to 5 seconds of future clock skew
        if timestamp > now + 5 {
            return Err(ProtocolError::HandshakeFailed(
                "invalid cookie: timestamp in the future".into(),
            ));
        }
        if now.saturating_sub(timestamp) > super::messages::DEFAULT_COOKIE_MAX_AGE_SECS {
            return Err(ProtocolError::HandshakeFailed(
                "invalid cookie: challenge expired".into(),
            ));
        }

        // Verify proof-of-work solution
        if !reply.verify(self.cookie_difficulty) {
            return Err(ProtocolError::HandshakeFailed(
                "invalid cookie solution".into(),
            ));
        }

        Ok(())
    }

    /// Process a client's handshake init and generate response.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_init(
        &mut self,
        init: &HandshakeInit,
        session_id: SessionId,
        config: TunnelConfig,
    ) -> Result<(HandshakeResponse, SessionKeys), ProtocolError> {
        // Generate server random
        let mut server_random = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut server_random);

        // Perform key exchange: encapsulate to client's public key
        // CRITICAL FIX: Use encapsulate() (KEM) not static_exchange() (DH)
        // KEM is unilateral (server → client), DH is bilateral
        // Client will decapsulate() with its secret key to get the same handshake_secret
        let (handshake_secret, ciphertext) = HybridKem::encapsulate(&init.client_ephemeral_pk)
            .map_err(|_| ProtocolError::HandshakeFailed("key exchange failed".into()))?;

        // Build transcript for signing (includes protocol version to prevent downgrade attacks)
        let transcript = build_transcript(
            PROTOCOL_VERSION,
            Some(&session_id),
            &init.client_random,
            &server_random,
            &ciphertext,
            &config,
        );

        // Sign the transcript
        let signature = self
            .server_keypair
            .sign(&transcript)
            .map_err(|_| ProtocolError::HandshakeFailed("signing failed".into()))?;

        // Derive session keys with session context for better isolation
        // Use current Unix timestamp for temporal binding
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session_keys = crate::crypto::kdf::derive_session_keys_with_context(
            &handshake_secret,
            &session_id,
            timestamp,
        )
        .map_err(|_| ProtocolError::HandshakeFailed("key derivation failed".into()))?;

        // Server uses swapped keys (what client sends, server receives)
        let server_keys = session_keys.swap();

        // Compute key confirmation MAC (server proves it has correct keys)
        // Use server's send key (which is client's recv key after swap)
        let key_confirmation = compute_key_confirmation(&server_keys.send_key, &transcript);

        let response = HandshakeResponse {
            session_id,
            server_ciphertext: ciphertext,
            server_static_pk: self.server_keypair.public_key.clone(),
            signature,
            server_random,
            config,
            key_confirmation,
            kdf_timestamp: timestamp,
        };

        Ok((response, server_keys))
    }

    /// Process an encrypted handshake init (identity hiding enabled).
    ///
    /// First decrypts the `EncryptedHandshakeInit` using the server's KEM secret key,
    /// then processes the inner `HandshakeInit` normally.
    ///
    /// # Arguments
    ///
    /// * `encrypted_init` - The encrypted handshake init message
    /// * `session_id` - Session ID to assign to this session
    /// * `config` - Tunnel configuration to send to client
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Server KEM keypair is not configured
    /// - Decryption fails (invalid ciphertext or wrong key)
    /// - Processing the inner init fails
    pub fn process_encrypted_init(
        &mut self,
        encrypted_init: &EncryptedHandshakeInit,
        session_id: SessionId,
        config: TunnelConfig,
    ) -> Result<(HandshakeResponse, SessionKeys), ProtocolError> {
        // Get the KEM secret key for decryption
        let kem_keypair = self.server_kem_keypair.as_ref().ok_or_else(|| {
            ProtocolError::HandshakeFailed(
                "server KEM keypair not configured for identity hiding".into(),
            )
        })?;

        // Decrypt the encrypted handshake init
        let inner_init = encrypted_init.decrypt(&kem_keypair.0)?;

        // Process the decrypted init normally
        self.process_init(&inner_init, session_id, config)
    }

    /// Process a client's rekey request and generate response.
    ///
    /// # Arguments
    ///
    /// * `rekey` - The client's rekey message with new ephemeral keys
    /// * `current_key_id` - The current key ID (response will include next)
    /// * `session_id` - The session ID for key derivation context
    ///
    /// # Returns
    ///
    /// Tuple of (rekey response, new session keys for server).
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_rekey(
        &self,
        rekey: &RekeyMessage,
        current_key_id: KeyId,
        session_id: SessionId,
    ) -> Result<(RekeyResponse, SessionKeys), ProtocolError> {
        // Generate server random
        let mut server_random = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut server_random);

        // CRITICAL FIX: Use encapsulate() (KEM) not static_exchange() (DH)
        // KEM is unilateral (server → client), DH is bilateral
        // Client will decapsulate() with its secret key to get the same handshake_secret
        // This matches the initial handshake pattern for security consistency
        let (handshake_secret, ciphertext) = HybridKem::encapsulate(&rekey.client_ephemeral_pk)
            .map_err(|_| ProtocolError::HandshakeFailed("key encapsulation failed".into()))?;

        // Build transcript for signing (similar to handshake, but for rekey)
        let transcript = build_rekey_transcript(
            session_id,
            &rekey.client_random,
            &server_random,
            &ciphertext,
        );

        // Sign the transcript
        let signature = self
            .server_keypair
            .sign(&transcript)
            .map_err(|_| ProtocolError::HandshakeFailed("signing failed".into()))?;

        // Derive new session keys with session context (matching initial handshake pattern)
        // Use current Unix timestamp for temporal binding
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session_keys = crate::crypto::kdf::derive_session_keys_with_context(
            &handshake_secret,
            &session_id,
            timestamp,
        )
        .map_err(|_| ProtocolError::HandshakeFailed("key derivation failed".into()))?;

        // Server uses swapped keys
        let server_keys = session_keys.swap();

        // Compute key confirmation MAC (server proves it has correct keys)
        // Use server's send key (which is client's recv key after swap)
        let key_confirmation = compute_key_confirmation(&server_keys.send_key, &transcript);

        let new_key_id = current_key_id.next();

        let response = RekeyResponse {
            server_ciphertext: ciphertext,
            signature,
            server_random,
            new_key_id: new_key_id.0,
            key_confirmation,
            kdf_timestamp: timestamp,
            session_id,
        };

        Ok((response, server_keys))
    }
}

/// Client-side rekey handler.
///
/// Manages key rotation for an established session.
pub struct ClientRekey {
    /// Client's new ephemeral keypair for rekey.
    client_keypair: Option<(HybridSecretKey, HybridPublicKey)>,
    /// Client random for this rekey.
    client_random: Option<[u8; 32]>,
    /// Expected server public key.
    server_pk: MlDsaPublicKey,
    /// Security level for cryptographic operations.
    security_level: crate::crypto::SecurityLevel,
    /// Session ID for transcript binding (prevents cross-session relay).
    session_id: SessionId,
}

impl ClientRekey {
    /// Create a new client rekey handler with default security level (Level3).
    #[must_use]
    pub fn new(server_pk: MlDsaPublicKey, session_id: SessionId) -> Self {
        Self::with_security_level(
            server_pk,
            session_id,
            crate::crypto::SecurityLevel::default(),
        )
    }

    /// Create a new client rekey handler with specified security level.
    #[must_use]
    pub fn with_security_level(
        server_pk: MlDsaPublicKey,
        session_id: SessionId,
        security_level: crate::crypto::SecurityLevel,
    ) -> Self {
        Self {
            client_keypair: None,
            client_random: None,
            server_pk,
            security_level,
            session_id,
        }
    }

    /// Create the rekey request message.
    ///
    /// # Errors
    ///
    /// Returns an error if keypair generation fails.
    pub fn create_request(&mut self) -> Result<RekeyMessage, CryptoError> {
        // Generate new ephemeral keypair matching the negotiated session security level.
        let (sk, pk) = HybridKem::generate_keypair_with_level(self.security_level)?;

        // Create rekey message
        let rekey = RekeyMessage::new(pk.clone());

        // Store state
        self.client_keypair = Some((sk, pk));
        self.client_random = Some(rekey.client_random);

        Ok(rekey)
    }

    /// Process the server's rekey response.
    ///
    /// # Errors
    ///
    /// Returns an error if verification or decapsulation fails.
    pub fn process_response(
        &mut self,
        response: &RekeyResponse,
    ) -> Result<SessionKeys, ProtocolError> {
        let (client_sk, _client_pk) = self
            .client_keypair
            .take()
            .ok_or(ProtocolError::InvalidStateTransition)?;

        let client_random = self
            .client_random
            .take()
            .ok_or(ProtocolError::InvalidStateTransition)?;

        // Build transcript for signature verification (bound to session_id)
        let transcript = build_rekey_transcript(
            self.session_id,
            &client_random,
            &response.server_random,
            &response.server_ciphertext,
        );

        // Verify signature using the security level from session state
        crate::crypto::signature::verify(
            &self.server_pk,
            &transcript,
            &response.signature,
            self.security_level,
        )
        .map_err(|_| {
            ProtocolError::HandshakeFailed("rekey signature verification failed".into())
        })?;

        // Decapsulate to get new shared secret
        let handshake_secret = HybridKem::decapsulate(&client_sk, &response.server_ciphertext)
            .map_err(|_| ProtocolError::HandshakeFailed("rekey decapsulation failed".into()))?;

        // Derive new session keys with context (matching server's derivation)
        // Use the timestamp and session_id from response for consistency
        tracing::debug!(
            "CLIENT REKEY KDF: session_id={}, timestamp={}",
            response.session_id,
            response.kdf_timestamp
        );

        let session_keys = crate::crypto::kdf::derive_session_keys_with_context(
            &handshake_secret,
            &response.session_id,
            response.kdf_timestamp,
        )
        .map_err(|_| ProtocolError::HandshakeFailed("key derivation failed".into()))?;

        // Verify key confirmation MAC (proves server has correct keys)
        // Client's recv_key is what server used to compute the MAC (server's send_key)
        verify_key_confirmation(
            &session_keys.recv_key,
            &transcript,
            &response.key_confirmation,
        )
        .map_err(|_| ProtocolError::HandshakeFailed("rekey key confirmation failed".into()))?;

        Ok(session_keys)
    }
}

/// Build the handshake transcript for signing/verification.
///
/// Includes protocol version and session ID to prevent downgrade attacks
/// and provide session binding in the cryptographic transcript.
fn build_transcript(
    protocol_version: u8,
    session_id: Option<&SessionId>,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ciphertext: &HybridCiphertext,
    config: &TunnelConfig,
) -> Vec<u8> {
    let ct_bytes = ciphertext.to_bytes();
    let config_bytes = config.to_bytes();
    let mut transcript =
        Vec::with_capacity(1 + 8 + 32 + 32 + ct_bytes.len() + 4 + config_bytes.len());
    transcript.push(protocol_version);
    if let Some(sid) = session_id {
        transcript.extend_from_slice(&sid.0.to_le_bytes());
    }
    transcript.extend_from_slice(client_random);
    transcript.extend_from_slice(server_random);
    transcript.extend_from_slice(&ct_bytes);
    transcript.extend_from_slice(&(config_bytes.len() as u32).to_be_bytes());
    transcript.extend_from_slice(&config_bytes);
    transcript
}

/// Build the legacy handshake transcript used before config binding hardening.
///
/// This is used only for diagnostics to identify mixed-version client/server deployments.
fn build_transcript_legacy_no_config(
    protocol_version: u8,
    session_id: Option<&SessionId>,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ciphertext: &HybridCiphertext,
) -> Vec<u8> {
    let ct_bytes = ciphertext.to_bytes();
    let mut transcript = Vec::with_capacity(1 + 8 + 32 + 32 + ct_bytes.len());
    transcript.push(protocol_version);
    if let Some(sid) = session_id {
        transcript.extend_from_slice(&sid.0.to_le_bytes());
    }
    transcript.extend_from_slice(client_random);
    transcript.extend_from_slice(server_random);
    transcript.extend_from_slice(&ct_bytes);
    transcript
}

/// Build the rekey transcript for signing/verification.
///
/// Uses a different domain separator than the initial handshake.
/// Binds session_id to prevent cross-session signature relay attacks.
fn build_rekey_transcript(
    session_id: SessionId,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ciphertext: &HybridCiphertext,
) -> Vec<u8> {
    let ct_bytes = ciphertext.to_bytes();
    // Domain separation + session binding
    let prefix = b"HPN-REKEY-V1";
    let mut transcript = Vec::with_capacity(prefix.len() + 1 + 8 + 32 + 32 + ct_bytes.len());
    transcript.extend_from_slice(prefix);
    transcript.push(crate::PROTOCOL_VERSION);
    transcript.extend_from_slice(&session_id.to_bytes());
    transcript.extend_from_slice(client_random);
    transcript.extend_from_slice(server_random);
    transcript.extend_from_slice(&ct_bytes);
    transcript
}

/// Compute key confirmation MAC using HMAC-SHA256.
///
/// This proves that both parties have derived the same session keys.
/// The MAC is computed over the handshake transcript using the send key.
fn compute_key_confirmation(send_key: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, send_key);
    let tag = hmac::sign(&key, transcript);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(tag.as_ref());
    mac
}

/// Recompute handshake response authentication fields after config changes.
///
/// This updates both the server signature and key-confirmation MAC so they
/// remain bound to the final tunnel configuration carried in `response`.
pub fn refresh_handshake_response_auth(
    response: &mut HandshakeResponse,
    client_random: &[u8; 32],
    security_level: crate::crypto::SecurityLevel,
    server_keypair: &crate::crypto::MlDsaKeypair,
    server_send_key: &[u8; 32],
) -> Result<(), ProtocolError> {
    let transcript = build_transcript(
        PROTOCOL_VERSION,
        Some(&response.session_id),
        client_random,
        &response.server_random,
        &response.server_ciphertext,
        &response.config,
    );

    let signature =
        crate::crypto::signature::sign(&server_keypair.secret_key, &transcript, security_level)
            .map_err(|_| {
                ProtocolError::HandshakeFailed("failed to sign handshake transcript".into())
            })?;

    response.signature = signature;
    response.key_confirmation = compute_key_confirmation(server_send_key, &transcript);
    Ok(())
}

/// Verify key confirmation MAC.
fn verify_key_confirmation(
    recv_key: &[u8; 32],
    transcript: &[u8],
    mac: &[u8; 32],
) -> Result<(), ProtocolError> {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, recv_key);
    hmac::verify(&key, transcript, mac).map_err(|_| {
        ProtocolError::HandshakeFailed("key confirmation MAC verification failed".into())
    })
}

#[cfg(test)]
#[allow(clippy::expect_fun_call)]
#[allow(clippy::branches_sharing_code)]
#[allow(clippy::needless_collect)]
#[allow(clippy::redundant_clone)]
mod tests {
    use super::*;

    #[test]
    fn test_client_handshake_state_progression() {
        let mut client = ClientHandshake::new();
        assert_eq!(*client.state(), HandshakeState::Idle);

        let _init = client.create_init().unwrap();
        assert_eq!(*client.state(), HandshakeState::AwaitingResponse);
    }

    #[test]
    fn test_full_handshake() {
        // Server setup
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair);

        // Client setup (with server key pinning)
        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        // Client creates init
        let init = client.create_init().unwrap();

        // Server processes init
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (response, server_keys) = server.process_init(&init, session_id, config).unwrap();

        // Client processes response
        let (client_session_id, client_keys, _config) = client.process_response(&response).unwrap();

        // Verify results
        assert!(client.is_established());
        assert_eq!(client_session_id, session_id);

        // Client's send key should match server's receive key
        assert_eq!(client_keys.send_key, server_keys.recv_key);
        assert_eq!(client_keys.recv_key, server_keys.send_key);
    }

    #[test]
    fn test_full_handshake_with_encryption_roundtrip() {
        // This test verifies that the full handshake produces keys that
        // work for actual encryption/decryption across multiple packets
        use crate::crypto::aead;
        use crate::protocol::Session;
        use crate::protocol::header::HEADER_SIZE;
        use crate::types::MessageType;

        // Server setup
        let server_keypair = MlDsaKeypair::generate();
        let mut server = ServerHandshake::new(Arc::new(server_keypair));

        // Client setup
        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        // Client creates init
        let init = client.create_init().unwrap();

        // Server processes init
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (response, server_keys) = server.process_init(&init, session_id, config).unwrap();

        // Client processes response
        let (_client_session_id, client_keys, _config) =
            client.process_response(&response).unwrap();

        // Create sessions
        let client_session = Session::new(session_id, client_keys).unwrap();
        let server_session = Session::new(session_id, server_keys).unwrap();

        // Test multiple packets with different sizes (matches production scenario)
        let payloads: &[&[u8]] = &[
            &[0x42u8; 40],   // Small packet (counter=0) - like key confirmation ack
            &[0x55u8; 844],  // Medium packet (counter=1) - typical IP packet
            &[0xAAu8; 1400], // Large packet (counter=2) - near MTU
            &[0x11u8; 64],   // Another small one (counter=3)
            &[0xBBu8; 1500], // MTU sized (counter=4)
        ];

        println!("\n=== Testing client -> server encryption with handshake-derived keys ===");
        println!(
            "Client send_key first 8: {:02x?}",
            &client_session.keys().send_key[..8]
        );
        println!(
            "Server recv_key first 8: {:02x?}",
            &server_session.keys().recv_key[..8]
        );

        for (i, payload) in payloads.iter().enumerate() {
            let mut packet = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];

            // Client encrypts
            let packet_len = client_session
                .encrypt_packet(MessageType::Data, payload, &mut packet)
                .unwrap_or_else(|_| panic!("Failed to encrypt packet {}", i));

            println!(
                "Packet {}: payload_len={}, encrypted_len={}, counter={}",
                i,
                payload.len(),
                packet_len,
                i
            );

            // Server decrypts
            let mut decrypted = vec![0u8; payload.len() + aead::TAG_SIZE];
            let (header, decrypted_len) = server_session
                .decrypt_packet(&packet[..packet_len], &mut decrypted)
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to decrypt packet {} (counter={}, payload_len={})",
                        i,
                        i,
                        payload.len()
                    )
                });

            assert_eq!(header.msg_type, MessageType::Data);
            assert_eq!(
                decrypted_len,
                payload.len(),
                "Packet {} decrypted length mismatch",
                i
            );
            assert_eq!(
                &decrypted[..decrypted_len],
                *payload,
                "Packet {} content mismatch",
                i
            );
        }

        // Also test server -> client direction
        println!("\n=== Testing server -> client encryption ===");
        for (i, payload) in payloads.iter().enumerate() {
            let mut packet = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];

            // Server encrypts
            let packet_len = server_session
                .encrypt_packet(MessageType::Data, payload, &mut packet)
                .unwrap_or_else(|_| panic!("Failed to encrypt server packet {}", i));

            // Client decrypts
            let mut decrypted = vec![0u8; payload.len() + aead::TAG_SIZE];
            let (header, decrypted_len) = client_session
                .decrypt_packet(&packet[..packet_len], &mut decrypted)
                .unwrap_or_else(|_| {
                    panic!("Failed to decrypt server packet {} (counter={})", i, i)
                });

            assert_eq!(header.msg_type, MessageType::Data);
            assert_eq!(decrypted_len, payload.len());
            assert_eq!(&decrypted[..decrypted_len], *payload);
        }

        println!("\n=== All packets encrypted/decrypted successfully! ===");
    }

    #[test]
    fn test_wrong_server_key_rejected() {
        // Server setup
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair);

        // Client with different expected key
        let wrong_keypair = MlDsaKeypair::generate();
        let mut client = ClientHandshake::with_server_pk(wrong_keypair.public_key);

        // Client creates init
        let init = client.create_init().unwrap();

        // Server processes init
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (response, _server_keys) = server.process_init(&init, session_id, config).unwrap();

        // Client should reject due to key mismatch
        let result = client.process_response(&response);
        assert!(result.is_err());
        assert!(matches!(*client.state(), HandshakeState::Failed(_)));
    }

    #[test]
    fn test_handshake_config_tampering_rejected() {
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair);
        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        let init = client.create_init().unwrap();
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (mut response, _server_keys) = server.process_init(&init, session_id, config).unwrap();

        // Active tampering attempt on unauthenticated transport fields.
        response.config.mtu = response.config.mtu.saturating_sub(1);

        let result = client.process_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_config_refresh_re_signs_and_verifies() {
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair.clone());
        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        let init = client.create_init().unwrap();
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (mut response, server_keys) = server.process_init(&init, session_id, config).unwrap();

        // Simulate server-side post-allocation tunnel config update.
        response.config.client_ipv4 = [10, 99, 0, 2];

        refresh_handshake_response_auth(
            &mut response,
            &init.client_random,
            init.security_level,
            &server_keypair,
            &server_keys.send_key,
        )
        .unwrap();

        let result = client.process_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut client = ClientHandshake::new();

        // Try to create init twice
        let _init = client.create_init().unwrap();
        let result = client.create_init();
        assert!(result.is_err());
    }

    #[test]
    fn test_full_rekey() {
        // Server setup
        let server_keypair = MlDsaKeypair::generate();
        let server = ServerHandshake::new(Arc::new(server_keypair.clone()));

        // Client rekey handler
        let test_session_id = SessionId::generate();
        let mut client_rekey = ClientRekey::new(server_keypair.public_key, test_session_id);

        // Client creates rekey request
        let rekey_request = client_rekey.create_request().unwrap();

        // Server processes rekey request (must use same session_id as client for transcript binding)
        let current_key_id = KeyId::initial();
        let (rekey_response, server_new_keys) = server
            .process_rekey(&rekey_request, current_key_id, test_session_id)
            .unwrap();

        // Verify new key ID incremented
        assert_eq!(rekey_response.new_key_id, 1);

        // Client processes rekey response
        let client_new_keys = client_rekey.process_response(&rekey_response).unwrap();

        // Verify keys match (client send = server recv, etc.)
        assert_eq!(client_new_keys.send_key, server_new_keys.recv_key);
        assert_eq!(client_new_keys.recv_key, server_new_keys.send_key);
    }

    #[test]
    fn test_rekey_request_uses_configured_security_level() {
        let server_keypair = MlDsaKeypair::generate();

        let sid = SessionId::generate();
        let mut level3 = ClientRekey::with_security_level(
            server_keypair.public_key.clone(),
            sid,
            crate::crypto::SecurityLevel::Level3,
        );
        let req3 = level3.create_request().unwrap();
        assert_eq!(
            req3.client_ephemeral_pk.security_level,
            crate::crypto::SecurityLevel::Level3
        );

        let mut level5 = ClientRekey::with_security_level(
            server_keypair.public_key,
            sid,
            crate::crypto::SecurityLevel::Level5,
        );
        let req5 = level5.create_request().unwrap();
        assert_eq!(
            req5.client_ephemeral_pk.security_level,
            crate::crypto::SecurityLevel::Level5
        );
    }

    #[test]
    fn test_rekey_wrong_signature_rejected() {
        // Two different server keypairs
        let server_keypair = MlDsaKeypair::generate();
        let wrong_keypair = MlDsaKeypair::generate();

        let server = ServerHandshake::new(Arc::new(server_keypair));

        // Client expects the wrong key
        let session_id = SessionId::generate();
        let mut client_rekey = ClientRekey::new(wrong_keypair.public_key, session_id);

        // Client creates rekey request
        let rekey_request = client_rekey.create_request().unwrap();

        // Server processes rekey request (with correct key)
        let current_key_id = KeyId::initial();
        let (rekey_response, _) = server
            .process_rekey(&rekey_request, current_key_id, session_id)
            .unwrap();

        // Client should reject due to signature mismatch
        let result = client_rekey.process_response(&rekey_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_concurrent_rekey() {
        // SECURITY TEST P0-4: Concurrent rekey operations must be safe
        // This test simulates multiple clients rekeying simultaneously with the same server
        // to verify there are no race conditions in key generation or state management.

        use std::sync::Arc;
        use std::thread;

        const NUM_CONCURRENT_REKEYS: usize = 20;

        // Server setup - shared across all threads
        let server_keypair = MlDsaKeypair::generate();
        let server = Arc::new(ServerHandshake::new(Arc::new(server_keypair.clone())));

        // Spawn multiple threads, each performing a complete rekey
        // Collect all results directly by joining threads inline
        let results: Vec<_> = (0..NUM_CONCURRENT_REKEYS)
            .map(|i| {
                let server_clone = Arc::clone(&server);
                let server_pk = server_keypair.public_key.clone();

                thread::spawn(move || {
                    // Each thread creates its own client rekey handler
                    let sid = SessionId::generate();
                    let mut client_rekey = ClientRekey::new(server_pk, sid);

                    // Client creates rekey request
                    let rekey_request = client_rekey.create_request().unwrap();

                    // Server processes rekey request (must use same session_id)
                    let current_key_id = KeyId(i as u32);
                    let (rekey_response, server_new_keys) = server_clone
                        .process_rekey(&rekey_request, current_key_id, sid)
                        .unwrap();

                    // Verify new key ID incremented
                    assert_eq!(rekey_response.new_key_id, i as u32 + 1);

                    // Client processes rekey response
                    let client_new_keys = client_rekey.process_response(&rekey_response).unwrap();

                    // Verify keys match
                    assert_eq!(client_new_keys.send_key, server_new_keys.recv_key);
                    assert_eq!(client_new_keys.recv_key, server_new_keys.send_key);

                    // Return keys to verify uniqueness across threads
                    (client_new_keys, server_new_keys)
                })
            })
            .map(|h| h.join().unwrap())
            .collect();

        // Verify all rekeys succeeded
        assert_eq!(results.len(), NUM_CONCURRENT_REKEYS);

        // Verify all generated keys are unique (no two threads got the same keys)
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                let (client_i, server_i) = &results[i];
                let (client_j, server_j) = &results[j];

                // Client send keys should be different
                assert_ne!(
                    &client_i.send_key, &client_j.send_key,
                    "Thread {} and {} got same client send key",
                    i, j
                );

                // Server send keys should be different
                assert_ne!(
                    &server_i.send_key, &server_j.send_key,
                    "Thread {} and {} got same server send key",
                    i, j
                );

                // Client nonce prefixes should be different
                assert_ne!(
                    client_i.send_nonce_prefix, client_j.send_nonce_prefix,
                    "Thread {} and {} got same client nonce prefix",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_rekey_under_load() {
        // SECURITY TEST P0-4 (Extended): Rekey resilience under heavy load
        // Tests rapid sequential rekeys to verify state consistency

        let server_keypair = MlDsaKeypair::generate();
        let server = ServerHandshake::new(Arc::new(server_keypair.clone()));

        let mut current_key_id = KeyId::initial();

        // Perform 100 rapid rekeys sequentially
        let session_id = SessionId::generate();
        for i in 0..100 {
            let mut client_rekey = ClientRekey::new(server_keypair.public_key.clone(), session_id);

            let rekey_request = client_rekey.create_request().unwrap();
            let (rekey_response, server_new_keys) = server
                .process_rekey(&rekey_request, current_key_id, session_id)
                .unwrap();

            // Verify key ID increments correctly
            assert_eq!(rekey_response.new_key_id, i + 1);

            let client_new_keys = client_rekey.process_response(&rekey_response).unwrap();

            // Verify keys match
            assert_eq!(client_new_keys.send_key, server_new_keys.recv_key);
            assert_eq!(client_new_keys.recv_key, server_new_keys.send_key);

            // Update for next iteration
            current_key_id = KeyId(rekey_response.new_key_id);
        }
    }

    #[test]
    fn test_cookie_challenge_solve_and_verify() {
        // Test cookie challenge anti-DoS mechanism
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::with_cookie_protection(server_keypair, 8); // Difficulty 8

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let challenge = server.create_cookie_request(&client_addr);

        // Verify challenge has correct difficulty
        assert_eq!(challenge.difficulty, 8);

        // Client solves the challenge
        let mut client = ClientHandshake::new();
        let _init = client.create_init().unwrap();

        let reply = client.solve_cookie_challenge(&challenge).unwrap();

        // Verify the solution is valid
        assert!(reply.verify(8));

        // Server should accept the reply
        assert!(server.verify_cookie_reply(&reply, &client_addr).is_ok());
    }

    #[test]
    fn test_cookie_challenge_wrong_difficulty_rejected() {
        // Test that solutions with wrong difficulty are rejected
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::with_cookie_protection(server_keypair, 8); // Difficulty 8

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let challenge = server.create_cookie_request(&client_addr);

        let mut client = ClientHandshake::new();
        let _init = client.create_init().unwrap();

        // Solve with difficulty 8
        let mut reply = client.solve_cookie_challenge(&challenge).unwrap();

        // Verify it passes with difficulty 8
        assert!(reply.verify(8));

        // Manually create a solution that ONLY satisfies difficulty 8, not 16
        // We'll bruteforce a nonce that has exactly 8-15 leading zero bits
        let mut found_valid_low_difficulty = false;
        for nonce in 0u64..100_000 {
            reply.solution_nonce = nonce;
            if reply.verify(8) && !reply.verify(16) {
                found_valid_low_difficulty = true;
                break;
            }
        }

        // If we found a suitable nonce, test it; otherwise skip this check
        // (the test is probabilistic, so we make it robust)
        if found_valid_low_difficulty {
            assert!(reply.verify(8));
            assert!(!reply.verify(16));
        } else {
            // Fallback: just verify the original solution works for its difficulty
            assert!(reply.verify(8));
        }
    }

    #[test]
    fn test_cookie_challenge_dynamic_difficulty() {
        // Test dynamic difficulty adjustment (simulating DoS response)
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::with_cookie_protection(server_keypair, 8);

        // Normal operation - difficulty 8
        assert_eq!(server.cookie_difficulty(), 8);

        // Simulate DoS detection - increase difficulty
        server.set_cookie_difficulty(16);
        assert_eq!(server.cookie_difficulty(), 16);

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let challenge = server.create_cookie_request(&client_addr);
        assert_eq!(challenge.difficulty, 16);

        // Attack subsides - lower difficulty
        server.set_cookie_difficulty(8);
        assert_eq!(server.cookie_difficulty(), 8);
    }

    #[test]
    fn test_cookie_secret_rotation_preserves_previous_cookie() {
        // When the cookie secret rotates, a cookie issued under the old
        // secret must still verify (up to the cookie max-age). Simulate a
        // rotation by swapping the current secret directly; verification
        // should fall back to the "previous" secret and succeed.
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::with_cookie_protection(server_keypair, 4);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 9000);

        // Issue a cookie under the initial secret, solve it.
        let challenge = server.create_cookie_request(&client_addr);
        let mut client = ClientHandshake::new();
        let _init = client.create_init().unwrap();
        let reply = client.solve_cookie_challenge(&challenge).unwrap();

        // Force a rotation: stash the current secret into `previous` and
        // install a fresh one, mimicking what `maybe_rotate_cookie_secret`
        // does once the interval elapses.
        {
            let mut secrets = server.cookie_secrets.lock();
            let old = std::mem::replace(
                &mut secrets.current,
                ServerHandshake::generate_cookie_secret(),
            );
            secrets.previous = Some(old);
            secrets.last_rotation = std::time::Instant::now();
        }

        // Verification must still succeed via the "previous" secret fallback.
        assert!(
            server.verify_cookie_reply(&reply, &client_addr).is_ok(),
            "cookie issued under pre-rotation secret must still verify"
        );
    }

    #[test]
    fn test_cookie_secret_rotation_rejects_very_old_cookie() {
        // Two rotations later, the secret that signed the cookie is gone
        // (only the most-recent previous is kept). Verification must fail.
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::with_cookie_protection(server_keypair, 4);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 9001);

        let challenge = server.create_cookie_request(&client_addr);
        let mut client = ClientHandshake::new();
        let _init = client.create_init().unwrap();
        let reply = client.solve_cookie_challenge(&challenge).unwrap();

        // Rotate twice → original secret evicted.
        for _ in 0..2 {
            let mut secrets = server.cookie_secrets.lock();
            let old = std::mem::replace(
                &mut secrets.current,
                ServerHandshake::generate_cookie_secret(),
            );
            secrets.previous = Some(old);
            secrets.last_rotation = std::time::Instant::now();
        }

        assert!(
            server.verify_cookie_reply(&reply, &client_addr).is_err(),
            "cookie older than one rotation window must be rejected"
        );
    }

    #[test]
    fn test_handshake_response_with_invalid_state() {
        // Test that client rejects response in wrong state
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair);

        let mut client = ClientHandshake::new();
        let init = client.create_init().unwrap();

        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (response, _server_keys) = server.process_init(&init, session_id, config).unwrap();

        // Process response normally (should succeed)
        assert!(client.process_response(&response).is_ok());

        // Try to process again (client already in Established state)
        let result = client.process_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_malformed_response() {
        // Test handling of malformed handshake response
        use crate::crypto::HybridCiphertext;

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let wrong_keypair = MlDsaKeypair::generate();

        let mut client = ClientHandshake::with_server_pk(server_keypair.public_key.clone());
        let _init = client.create_init().unwrap();

        // Create a malformed response with wrong signature
        let malformed_response = HandshakeResponse {
            session_id: SessionId::generate(),
            server_ciphertext: HybridCiphertext::from_bytes_with_level(
                &[0u8; HybridCiphertext::SIZE],
                crate::crypto::SecurityLevel::Level3,
            )
            .unwrap(),
            server_static_pk: server_keypair.public_key.clone(),
            signature: {
                // Sign with wrong keypair
                let transcript = vec![0u8; 64];
                wrong_keypair.sign(&transcript).unwrap()
            },
            server_random: [0u8; 32],
            config: TunnelConfig::default(),
            key_confirmation: [0u8; 32],
            kdf_timestamp: 1_234_567_890,
        };

        // Client should reject due to signature verification failure
        let result = client.process_response(&malformed_response);
        assert!(result.is_err());
        assert!(matches!(*client.state(), HandshakeState::Failed(_)));
    }

    #[test]
    fn test_concurrent_handshake_attempts() {
        // SECURITY TEST: Multiple clients handshaking concurrently
        // Verifies no race conditions in server handshake processing
        use std::sync::Arc;
        use std::thread;

        const NUM_CONCURRENT_CLIENTS: usize = 50;

        let server_keypair = Arc::new(MlDsaKeypair::generate());

        let handles: Vec<_> = (0..NUM_CONCURRENT_CLIENTS)
            .map(|i| {
                let keypair_clone = Arc::clone(&server_keypair);

                thread::spawn(move || {
                    // Each thread creates its own server handler
                    let mut server = ServerHandshake::new(keypair_clone.clone());

                    // Each thread creates its own client
                    let mut client =
                        ClientHandshake::with_server_pk(keypair_clone.public_key.clone());

                    // Client creates init
                    let init = client.create_init().unwrap();

                    // Server processes init
                    let session_id = SessionId::generate();
                    let config = TunnelConfig::default();
                    let (response, server_keys) =
                        server.process_init(&init, session_id, config).unwrap();

                    // Client processes response
                    let (client_session_id, client_keys, _config) =
                        client.process_response(&response).unwrap();

                    // Verify handshake succeeded
                    assert!(client.is_established());
                    assert_eq!(client_session_id, session_id);
                    assert_eq!(client_keys.send_key, server_keys.recv_key);
                    assert_eq!(client_keys.recv_key, server_keys.send_key);

                    (i, client_keys, server_keys)
                })
            })
            .collect();

        // Collect all results
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Verify all handshakes succeeded
        assert_eq!(results.len(), NUM_CONCURRENT_CLIENTS);

        // Verify all generated keys are unique
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                let (_, client_i, server_i) = &results[i];
                let (_, client_j, server_j) = &results[j];

                assert_ne!(
                    &client_i.send_key, &client_j.send_key,
                    "Handshake {} and {} generated same client send key",
                    i, j
                );
                assert_ne!(
                    &server_i.send_key, &server_j.send_key,
                    "Handshake {} and {} generated same server send key",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_cookie_solve_unexpected_state() {
        // Test that cookie challenge in wrong state is rejected
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::with_cookie_protection(server_keypair, 8);

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let challenge = server.create_cookie_request(&client_addr);

        // Client in Idle state (hasn't sent HandshakeInit yet)
        let mut client = ClientHandshake::new();

        // Should reject cookie challenge (client not in AwaitingResponse state)
        let result = client.solve_cookie_challenge(&challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_session_keys_taken() {
        // Test that session keys can only be taken once
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair);

        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        let init = client.create_init().unwrap();
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (response, _) = server.process_init(&init, session_id, config).unwrap();

        client.process_response(&response).unwrap();

        // First take should succeed
        let keys1 = client.take_session_keys();
        assert!(keys1.is_some());

        // Second take should return None
        let keys2 = client.take_session_keys();
        assert!(keys2.is_none());
    }

    #[test]
    fn test_handshake_key_confirmation_invalid() {
        // Test that handshake with invalid key confirmation MAC is rejected
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::new(server_keypair.clone());

        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        let init = client.create_init().unwrap();
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (mut response, _) = server.process_init(&init, session_id, config).unwrap();

        // Corrupt the key confirmation MAC
        response.key_confirmation[0] ^= 0xFF;

        // Client should reject due to MAC verification failure
        let result = client.process_response(&response);
        assert!(result.is_err());
        assert!(matches!(*client.state(), HandshakeState::Failed(_)));
    }

    #[test]
    fn test_handshake_full_cookie_flow() {
        // Test complete handshake flow with cookie challenge
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let mut server = ServerHandshake::with_cookie_protection(server_keypair.clone(), 8);

        let mut client = ClientHandshake::with_server_pk(server.public_key().clone());

        // 1. Client sends HandshakeInit
        let _init = client.create_init().unwrap();
        assert_eq!(*client.state(), HandshakeState::AwaitingResponse);

        // 2. Server decides to challenge (simulating DoS protection)
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let challenge = server.create_cookie_request(&client_addr);

        // 3. Client solves cookie challenge
        let cookie_reply = client.solve_cookie_challenge(&challenge).unwrap();
        assert_eq!(*client.state(), HandshakeState::AwaitingResponseAfterCookie);

        // 4. Server verifies cookie
        assert!(
            server
                .verify_cookie_reply(&cookie_reply, &client_addr)
                .is_ok()
        );

        // 5. Server processes HandshakeInit (from cookie reply) and sends response
        let session_id = SessionId::generate();
        let config = TunnelConfig::default();
        let (response, server_keys) = server
            .process_init(&cookie_reply.handshake_init, session_id, config)
            .unwrap();

        // 6. Client processes response
        let (client_session_id, client_keys, _) = client.process_response(&response).unwrap();

        // Verify handshake completed successfully
        assert!(client.is_established());
        assert_eq!(client_session_id, session_id);
        assert_eq!(client_keys.send_key, server_keys.recv_key);
        assert_eq!(client_keys.recv_key, server_keys.send_key);
    }

    #[test]
    fn test_handshake_state_idle() {
        let client = ClientHandshake::new();

        assert_eq!(*client.state(), HandshakeState::Idle);
        assert!(!client.is_established());
    }

    #[test]
    fn test_handshake_state_transitions() {
        let mut client = ClientHandshake::new();

        // Idle state
        assert_eq!(*client.state(), HandshakeState::Idle);

        // Create init - moves to AwaitingResponse
        let _init = client.create_init().unwrap();
        assert_eq!(*client.state(), HandshakeState::AwaitingResponse);
    }

    #[test]
    fn test_server_handshake_creation() {
        use std::sync::Arc;
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::new(server_keypair);

        // Just verify creation works
        assert!(std::mem::size_of_val(&server) > 0);
    }

    #[test]
    fn test_handshake_established_state() {
        let client = ClientHandshake::new();

        // Client starts not established
        assert!(!client.is_established());
        assert!(client.state() == &HandshakeState::Idle);
    }

    #[test]
    fn test_server_handshake_with_cookie_protection() {
        use std::sync::Arc;
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::with_cookie_protection(server_keypair, 2);

        // Just verify creation works
        assert!(std::mem::size_of_val(&server) > 0);
    }

    #[test]
    fn test_cookie_request_creation() {
        use std::sync::Arc;
        let server_keypair = Arc::new(MlDsaKeypair::generate());
        let server = ServerHandshake::new(server_keypair);

        let addr = "127.0.0.1:12345".parse().unwrap();
        let request = server.create_cookie_request(&addr);

        // Cookie request should have reasonable size
        let bytes = request.to_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.len() < 10000); // Reasonable upper bound
    }
}
