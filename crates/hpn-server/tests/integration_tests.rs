//! Integration tests for hpn-server.
//!
//! These tests verify the server components work correctly together.
//! Note: Some tests require root privileges or specific Linux features.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use hpn_core::crypto::{MlDsaKeypair, SecurityLevel, SessionKeys};
use hpn_core::protocol::Session;
use hpn_core::types::SessionId;

use hpn_server::config::ServerConfig;
use hpn_server::rate_limit::HandshakeRateLimiter;
use hpn_server::session_manager::SessionManager;
use hpn_server::validation::{
    validate_interface_name, validate_ipv4_address, validate_ipv4_cidr, validate_ipv6_address,
    validate_ipv6_cidr,
};

// =============================================================================
// Session Manager Tests
// =============================================================================

mod session_manager_tests {
    use super::*;

    /// Create a test session manager (IPv4 only).
    fn create_test_manager(max_sessions: usize) -> SessionManager {
        SessionManager::new(
            [10, 0, 0, 0],            // base_ip
            24,                       // prefix
            [10, 0, 0, 1],            // server_ip (gateway)
            Duration::from_secs(300), // session_timeout
            max_sessions,
        )
    }

    /// Create a test session manager with dual-stack (IPv4 + IPv6).
    fn create_dual_stack_manager(max_sessions: usize) -> SessionManager {
        let ipv6_base = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let ipv6_server = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        SessionManager::new_dual_stack(
            [10, 0, 0, 0],            // base_ip
            24,                       // prefix
            [10, 0, 0, 1],            // server_ip (gateway)
            ipv6_base,                // base_ipv6
            64,                       // prefix_v6
            ipv6_server,              // server_ipv6
            Duration::from_secs(300), // session_timeout
            max_sessions,
        )
    }

    /// Create a mock session for testing.
    fn create_mock_session() -> (Session, SessionId) {
        // Generate session ID
        let session_id = SessionId::generate();

        // Create session keys with random data
        let keys = SessionKeys {
            send_key: [0x42; 32],
            recv_key: [0x43; 32],
            send_nonce_prefix: [0x01, 0x02, 0x03, 0x04],
            recv_nonce_prefix: [0x05, 0x06, 0x07, 0x08],
        };

        let session = Session::new(session_id, keys).unwrap();
        (session, session_id)
    }

    /// Test basic session creation and lookup.
    #[test]
    fn test_session_create_and_lookup() {
        let manager = create_test_manager(100);

        // Create a mock session
        let (session, session_id) = create_mock_session();
        let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51820));

        // Create session in manager
        let tunnel_ip = manager.create_session(session, client_addr).unwrap();

        // Verify IP was allocated
        assert_eq!(tunnel_ip[0], 10);
        assert_eq!(tunnel_ip[1], 0);
        assert_eq!(tunnel_ip[2], 0);
        // First allocation should be .2 (skip .0 network, .1 gateway)
        assert!(tunnel_ip[3] >= 2);

        // Lookup by session ID
        assert!(manager.get_session(session_id).is_some());

        // Lookup by tunnel IP
        let found_id = manager.get_session_by_ip(tunnel_ip);
        assert_eq!(found_id, Some(session_id));

        // Verify session count
        assert_eq!(manager.session_count(), 1);
    }

    /// Test session removal.
    #[test]
    fn test_session_removal() {
        let manager = create_test_manager(100);

        let (session, session_id) = create_mock_session();
        let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51820));

        let tunnel_ip = manager.create_session(session, client_addr).unwrap();
        assert_eq!(manager.session_count(), 1);

        // Remove session
        let removed = manager.remove_session(session_id);
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);

        // Verify lookups fail
        assert!(manager.get_session(session_id).is_none());
        assert!(manager.get_session_by_ip(tunnel_ip).is_none());
    }

    /// Test IP address reuse after session removal.
    #[test]
    fn test_ip_address_reuse() {
        let manager = create_test_manager(100);

        let (session1, session_id1) = create_mock_session();
        let client_addr1 =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51820));

        let tunnel_ip1 = manager.create_session(session1, client_addr1).unwrap();

        // Remove first session
        manager.remove_session(session_id1);

        // Create second session - should get same IP
        let (session2, _session_id2) = create_mock_session();
        let client_addr2 =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 101), 51820));

        let tunnel_ip2 = manager.create_session(session2, client_addr2).unwrap();

        // IPs should be reused
        assert_eq!(tunnel_ip1, tunnel_ip2);
    }

    /// Test dual-stack session creation.
    #[test]
    fn test_dual_stack_session() {
        let manager = create_dual_stack_manager(100);

        let (session, session_id) = create_mock_session();
        let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51820));

        let (tunnel_ipv4, tunnel_ipv6) = manager
            .create_session_dual_stack(session, client_addr)
            .unwrap();

        // Verify IPv4 allocation
        assert_eq!(tunnel_ipv4[0], 10);
        assert!(tunnel_ipv4[3] >= 2);

        // Verify IPv6 allocation
        assert!(tunnel_ipv6.is_some());
        let ipv6 = tunnel_ipv6.unwrap();
        // First byte should match the base prefix
        assert_eq!(ipv6[0], 0xfd);

        // Verify lookups work for both
        assert_eq!(manager.get_session_by_ip(tunnel_ipv4), Some(session_id));
        assert_eq!(manager.get_session_by_ipv6(ipv6), Some(session_id));
    }

    /// Test session limit enforcement.
    #[test]
    fn test_session_limit() {
        let max_sessions = 5;
        let manager = create_test_manager(max_sessions);

        // Create sessions up to limit
        for i in 0..max_sessions {
            let (session, _) = create_mock_session();
            let client_addr = SocketAddr::V4(SocketAddrV4::new(
                #[allow(clippy::cast_possible_truncation)]
                Ipv4Addr::new(192, 168, 1, i as u8),
                51820,
            ));

            let result = manager.create_session(session, client_addr);
            assert!(result.is_ok(), "Session {i} should succeed");
        }

        assert_eq!(manager.session_count(), max_sessions);

        // Next session should fail
        let (session, _) = create_mock_session();
        let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 200), 51820));

        let result = manager.create_session(session, client_addr);
        assert!(result.is_err(), "Session beyond limit should fail");
    }

    /// Test session statistics (bytes sent/received).
    #[test]
    fn test_session_statistics() {
        let manager = create_test_manager(100);

        let (session, session_id) = create_mock_session();
        let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51820));

        let _tunnel_ip = manager.create_session(session, client_addr).unwrap();

        // Get session and update stats
        {
            let session_ref = manager.get_session(session_id).unwrap();
            session_ref.add_bytes_received(1000);
            session_ref.add_bytes_sent(500);
        }

        // Verify stats
        let session_ref = manager.get_session(session_id).unwrap();
        assert_eq!(session_ref.bytes_received(), 1000);
        assert_eq!(session_ref.bytes_sent(), 500);
        drop(session_ref);
    }

    /// Test combined lookup (session ID and address by IP).
    #[test]
    fn test_session_and_addr_lookup() {
        let manager = create_test_manager(100);

        let (session, session_id) = create_mock_session();
        let client_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51820));

        let tunnel_ip = manager.create_session(session, client_addr).unwrap();

        // Test combined lookup
        let result = manager.get_session_and_addr_by_ip(tunnel_ip);
        assert!(result.is_some());

        let (found_id, found_addr) = result.unwrap();
        assert_eq!(found_id, session_id);
        assert_eq!(found_addr, client_addr);
    }
}

// =============================================================================
// Rate Limiter Tests
// =============================================================================

mod rate_limiter_tests {
    use super::*;

    /// Helper to create `IpAddr` from last octet.
    const fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet))
    }

    /// Test basic rate limiting.
    #[test]
    fn test_rate_limit_basic() {
        // 5 requests per minute
        let limiter = HandshakeRateLimiter::with_limit(5);
        let client_ip = test_ip(100);

        // First 5 requests should be allowed
        for i in 0..5 {
            assert!(limiter.allow(client_ip), "Request {i} should be allowed");
        }

        // 6th request should be blocked
        assert!(!limiter.allow(client_ip), "Request 6 should be blocked");
    }

    /// Test different IPs have separate limits.
    #[test]
    fn test_rate_limit_per_ip() {
        let limiter = HandshakeRateLimiter::with_limit(2);

        let client1 = test_ip(100);
        let client2 = test_ip(101);

        // Client 1 uses up their quota
        assert!(limiter.allow(client1));
        assert!(limiter.allow(client1));
        assert!(!limiter.allow(client1)); // blocked

        // Client 2 should still have full quota
        assert!(limiter.allow(client2));
        assert!(limiter.allow(client2));
        assert!(!limiter.allow(client2)); // blocked
    }

    /// Test check without incrementing counter.
    #[test]
    fn test_check_without_increment() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let client_ip = test_ip(100);

        // Check should not increment
        assert!(limiter.check(client_ip));
        assert!(limiter.check(client_ip));
        assert_eq!(limiter.get_count(client_ip), 0);

        // Allow increments the counter
        assert!(limiter.allow(client_ip));
        assert_eq!(limiter.get_count(client_ip), 1);
    }

    /// Test reset functionality.
    #[test]
    fn test_rate_limit_reset() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let client_ip = test_ip(100);

        // Use up quota
        assert!(limiter.allow(client_ip));
        assert!(limiter.allow(client_ip));
        assert!(!limiter.allow(client_ip));

        // Reset the IP
        limiter.reset(client_ip);

        // Should have new quota
        assert!(limiter.allow(client_ip));
    }
}

// =============================================================================
// Validation Tests
// =============================================================================

mod validation_tests {
    use super::*;

    /// Test IPv4 address validation.
    #[test]
    fn test_ipv4_validation() {
        // Valid addresses
        assert!(validate_ipv4_address("192.168.1.1").is_ok());
        assert!(validate_ipv4_address("10.0.0.1").is_ok());
        assert!(validate_ipv4_address("0.0.0.0").is_ok());
        assert!(validate_ipv4_address("255.255.255.255").is_ok());

        // Invalid addresses
        assert!(validate_ipv4_address("256.0.0.1").is_err());
        assert!(validate_ipv4_address("192.168.1").is_err());
        assert!(validate_ipv4_address("not.an.ip.address").is_err());
        assert!(validate_ipv4_address("").is_err());
    }

    /// Test IPv4 CIDR validation.
    #[test]
    fn test_ipv4_cidr_validation() {
        // Valid CIDRs
        assert!(validate_ipv4_cidr("192.168.1.0/24").is_ok());
        assert!(validate_ipv4_cidr("10.0.0.0/8").is_ok());
        assert!(validate_ipv4_cidr("0.0.0.0/0").is_ok());
        assert!(validate_ipv4_cidr("192.168.1.1/32").is_ok());

        // Invalid CIDRs
        assert!(validate_ipv4_cidr("192.168.1.0/33").is_err()); // prefix too large
        assert!(validate_ipv4_cidr("192.168.1.0").is_err()); // no prefix
        assert!(validate_ipv4_cidr("192.168.1.0/").is_err()); // empty prefix
    }

    /// Test IPv6 address validation.
    #[test]
    fn test_ipv6_validation() {
        // Valid addresses
        assert!(validate_ipv6_address("::1").is_ok());
        assert!(validate_ipv6_address("fd00::1").is_ok());
        assert!(validate_ipv6_address("2001:db8::1").is_ok());

        // Invalid addresses
        assert!(validate_ipv6_address("gggg::1").is_err());
        assert!(validate_ipv6_address("").is_err());
    }

    /// Test IPv6 CIDR validation.
    #[test]
    fn test_ipv6_cidr_validation() {
        // Valid CIDRs
        assert!(validate_ipv6_cidr("fd00::/64").is_ok());
        assert!(validate_ipv6_cidr("2001:db8::/32").is_ok());
        assert!(validate_ipv6_cidr("::/0").is_ok());
        assert!(validate_ipv6_cidr("::1/128").is_ok());

        // Invalid CIDRs
        assert!(validate_ipv6_cidr("fd00::/129").is_err()); // prefix too large
        assert!(validate_ipv6_cidr("fd00::").is_err()); // no prefix
    }

    /// Test interface name validation.
    #[test]
    fn test_interface_name_validation() {
        // Valid names
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("tun0").is_ok());
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("hpn0").is_ok());
        assert!(validate_interface_name("enp0s3").is_ok());

        // Invalid names
        assert!(validate_interface_name("").is_err()); // empty
        assert!(validate_interface_name("this-name-is-way-too-long-for-an-interface").is_err());
        // 16+ chars
    }
}

// =============================================================================
// Config Tests
// =============================================================================

mod config_tests {
    use super::*;

    /// Test config validation passes for valid config.
    #[test]
    fn test_valid_config() {
        let config_str = r#"
            listen_addr = "0.0.0.0:51820"
            ipv4_pool = "10.8.0.0/24"
            server_tunnel_ip = "10.8.0.1"
            dns_servers = ["1.1.1.1", "8.8.8.8"]
            tun_name = "hpn0"
            mtu = 1420
            session_timeout_secs = 300
            max_sessions = 100
        "#;
        let config: ServerConfig = toml::from_str(config_str).expect("Valid config should parse");
        assert!(config.validate().is_ok());
    }

    /// Test config validation catches invalid IPv4 pool.
    #[test]
    fn test_invalid_ipv4_pool() {
        let config_str = r#"
            listen_addr = "0.0.0.0:51820"
            ipv4_pool = "not-a-cidr"
            server_tunnel_ip = "10.8.0.1"
            dns_servers = ["1.1.1.1"]
        "#;
        let config: ServerConfig = toml::from_str(config_str).expect("Config should parse");
        assert!(config.validate().is_err());
    }

    /// Test config parsing with optional fields.
    #[test]
    fn test_config_optional_fields() {
        let config_str = r#"
            listen_addr = "0.0.0.0:51820"
            ipv4_pool = "10.8.0.0/24"
            server_tunnel_ip = "10.8.0.1"
            dns_servers = ["1.1.1.1"]
        "#;
        let config: ServerConfig = toml::from_str(config_str).expect("Config should parse");

        // Optional fields should have defaults
        assert!(config.ipv6_pool.is_none());
        assert!(config.license_key.is_none());
        assert!(!config.enable_metrics);
    }
}

// =============================================================================
// Crypto Integration Tests
// =============================================================================

mod crypto_tests {
    use super::*;

    /// Test ML-DSA keypair generation for both security levels.
    #[test]
    fn test_mldsa_keypair_generation() {
        // Level 3 (ML-DSA-65)
        let keypair_l3 = MlDsaKeypair::generate_with_level(SecurityLevel::Level3);
        assert!(!keypair_l3.public_key.as_bytes().is_empty());
        assert!(!keypair_l3.secret_key.as_bytes().is_empty());
        assert_eq!(keypair_l3.security_level, SecurityLevel::Level3);

        // Level 5 (ML-DSA-87)
        let keypair_l5 = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        assert!(!keypair_l5.public_key.as_bytes().is_empty());
        assert!(!keypair_l5.secret_key.as_bytes().is_empty());
        assert_eq!(keypair_l5.security_level, SecurityLevel::Level5);

        // Level 5 keys should be larger
        assert!(keypair_l5.public_key.as_bytes().len() > keypair_l3.public_key.as_bytes().len());
    }

    /// Test signing and verification.
    #[test]
    fn test_sign_and_verify() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level3);
        let message = b"Test message for signing";

        // Sign
        let signature = keypair.sign(message).expect("Signing should succeed");

        // Verify using the keypair's verify method - returns Result
        let valid = keypair.verify(message, &signature);
        assert!(valid.is_ok(), "Signature should be valid");

        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        let invalid = keypair.verify(wrong_message, &signature);
        assert!(
            invalid.is_err(),
            "Signature should be invalid for wrong message"
        );
    }

    /// Test session encryption/decryption round-trip.
    #[test]
    fn test_session_encryption_roundtrip() {
        use hpn_core::MessageType;

        // Create session keys
        let keys = SessionKeys {
            send_key: [0x42; 32],
            recv_key: [0x43; 32],
            send_nonce_prefix: [0x01, 0x02, 0x03, 0x04],
            recv_nonce_prefix: [0x05, 0x06, 0x07, 0x08],
        };

        // Create sender and receiver sessions (with swapped keys)
        let sender = Session::new(SessionId::generate(), keys.clone()).unwrap();
        let receiver = Session::new(sender.session_id(), keys.swap()).unwrap();

        // Encrypt a packet
        let plaintext = b"Hello, VPN!";
        let mut ciphertext = vec![0u8; plaintext.len() + 64]; // room for header + tag
        let encrypted_len = sender
            .encrypt_packet(MessageType::Data, plaintext, &mut ciphertext)
            .expect("Encryption should succeed");

        // Decrypt the packet
        let mut decrypted = vec![0u8; encrypted_len];
        let (_msg_type, decrypted_len) = receiver
            .decrypt_packet(&ciphertext[..encrypted_len], &mut decrypted)
            .expect("Decryption should succeed");

        // Verify round-trip
        assert_eq!(&decrypted[..decrypted_len], plaintext);
    }
}
