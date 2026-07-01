//! Integration tests for the HPN VPN protocol.
//!
//! Tests the complete handshake and session establishment between
//! client and server components.

use std::sync::Arc;
use std::time::Duration;

use hpn_core::crypto::{MlDsaKeypair, aead};
use hpn_core::protocol::{
    ClientHandshake, ClientRekey, ControlMessage, HEADER_SIZE, KeepaliveMessage,
    KeepaliveReplyMessage, ServerHandshake, Session, TunnelConfig,
};
use hpn_core::types::{KeyId, MessageType, SessionId};

/// Test complete handshake flow between client and server.
#[test]
fn test_full_handshake_flow() {
    // Generate server keypair
    let server_keypair = MlDsaKeypair::generate();

    // Create server handshake handler
    let mut server = ServerHandshake::new(Arc::new(server_keypair.clone()));

    // Create client with pinned server public key
    let mut client = ClientHandshake::with_server_pk(server_keypair.public_key);

    // Step 1: Client creates handshake init
    let init = client.create_init().expect("failed to create init");

    // Verify client state
    assert!(matches!(
        *client.state(),
        hpn_core::protocol::HandshakeState::AwaitingResponse
    ));

    // Step 2: Server processes init and generates response
    let session_id = SessionId::generate();
    let config = TunnelConfig {
        client_ipv4: [10, 99, 0, 5],
        netmask_ipv4: [255, 255, 255, 0],
        gateway_ipv4: [10, 99, 0, 1],
        dns_ipv4: vec![[8, 8, 8, 8], [8, 8, 4, 4]],
        client_ipv6: None,
        prefix_len_ipv6: None,
        gateway_ipv6: None,
        dns_ipv6: vec![],
        mtu: 1420,
    };

    let (response, server_keys) = server
        .process_init(&init, session_id, config.clone())
        .expect("server failed to process init");

    // Step 3: Client processes response
    let (client_session_id, client_keys, client_config) = client
        .process_response(&response)
        .expect("client failed to process response");

    // Verify handshake completed
    assert!(client.is_established());
    assert_eq!(client_session_id, session_id);

    // Verify tunnel config was received
    assert_eq!(client_config.client_ipv4, config.client_ipv4);
    assert_eq!(client_config.mtu, config.mtu);

    // Verify keys are properly swapped (client send = server recv)
    assert_eq!(client_keys.send_key, server_keys.recv_key);
    assert_eq!(client_keys.recv_key, server_keys.send_key);
    assert_eq!(client_keys.send_nonce_prefix, server_keys.recv_nonce_prefix);
    assert_eq!(client_keys.recv_nonce_prefix, server_keys.send_nonce_prefix);
}

/// Test session encryption and decryption roundtrip.
#[test]
fn test_session_encrypted_communication() {
    // Perform handshake
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key);

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let config = TunnelConfig::default();
    let (response, server_keys) = server_hs.process_init(&init, session_id, config).unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    // Create sessions
    let client_session = Session::new(session_id, client_keys).unwrap();
    let server_session = Session::new(session_id, server_keys).unwrap();

    // Test client -> server data
    let payload = b"Hello, VPN server!";
    let mut packet_buf = vec![0u8; HEADER_SIZE + payload.len() + 32];
    let packet_len = client_session
        .encrypt_packet(MessageType::Data, payload, &mut packet_buf)
        .expect("client encryption failed");

    let mut decrypt_buf = vec![0u8; payload.len() + aead::TAG_SIZE];
    let (header, decrypted_len) = server_session
        .decrypt_packet(&packet_buf[..packet_len], &mut decrypt_buf)
        .expect("server decryption failed");

    assert_eq!(header.msg_type, MessageType::Data);
    assert_eq!(&decrypt_buf[..decrypted_len], payload);

    // Test server -> client data
    let server_payload = b"Hello, VPN client!";
    let mut server_packet_buf = vec![0u8; HEADER_SIZE + server_payload.len() + 32];
    let server_packet_len = server_session
        .encrypt_packet(MessageType::Data, server_payload, &mut server_packet_buf)
        .expect("server encryption failed");

    let mut client_decrypt_buf = vec![0u8; server_payload.len() + aead::TAG_SIZE];
    let (client_header, client_decrypted_len) = client_session
        .decrypt_packet(
            &server_packet_buf[..server_packet_len],
            &mut client_decrypt_buf,
        )
        .expect("client decryption failed");

    assert_eq!(client_header.msg_type, MessageType::Data);
    assert_eq!(&client_decrypt_buf[..client_decrypted_len], server_payload);
}

/// Test keepalive message exchange.
#[test]
fn test_keepalive_exchange() {
    // Set up sessions
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key);

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let config = TunnelConfig::default();
    let (response, server_keys) = server_hs.process_init(&init, session_id, config).unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    let client_session = Session::new(session_id, client_keys).unwrap();
    let server_session = Session::new(session_id, server_keys).unwrap();

    // Client sends keepalive
    let keepalive = KeepaliveMessage { sequence: 42 };
    let keepalive_bytes = keepalive.to_bytes();

    let mut packet_buf = vec![0u8; HEADER_SIZE + keepalive_bytes.len() + 32];
    let packet_len = client_session
        .encrypt_packet(MessageType::Keepalive, &keepalive_bytes, &mut packet_buf)
        .unwrap();

    // Server receives and decrypts keepalive
    let mut decrypt_buf = vec![0u8; keepalive_bytes.len() + aead::TAG_SIZE];
    let (header, decrypted_len) = server_session
        .decrypt_packet(&packet_buf[..packet_len], &mut decrypt_buf)
        .unwrap();

    assert_eq!(header.msg_type, MessageType::Keepalive);
    let received_keepalive = KeepaliveMessage::from_bytes(&decrypt_buf[..decrypted_len]).unwrap();
    assert_eq!(received_keepalive.sequence, 42);

    // Server sends keepalive reply
    let reply = KeepaliveReplyMessage {
        sequence: 42,
        server_timestamp: 1_234_567_890,
    };
    let reply_bytes = reply.to_bytes();

    let mut reply_packet_buf = vec![0u8; HEADER_SIZE + reply_bytes.len() + 32];
    let reply_packet_len = server_session
        .encrypt_packet(
            MessageType::KeepaliveReply,
            &reply_bytes,
            &mut reply_packet_buf,
        )
        .unwrap();

    // Client receives reply
    let mut reply_decrypt_buf = vec![0u8; reply_bytes.len() + aead::TAG_SIZE];
    let (reply_header, reply_decrypted_len) = client_session
        .decrypt_packet(
            &reply_packet_buf[..reply_packet_len],
            &mut reply_decrypt_buf,
        )
        .unwrap();

    assert_eq!(reply_header.msg_type, MessageType::KeepaliveReply);
    let received_reply =
        KeepaliveReplyMessage::from_bytes(&reply_decrypt_buf[..reply_decrypted_len]).unwrap();
    assert_eq!(received_reply.sequence, 42);
    assert_eq!(received_reply.server_timestamp, 1_234_567_890);
}

/// Test anti-replay protection.
#[test]
fn test_replay_attack_prevention() {
    // Set up sessions
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key);

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let (response, server_keys) = server_hs
        .process_init(&init, session_id, TunnelConfig::default())
        .unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    let client_session = Session::new(session_id, client_keys).unwrap();
    let server_session = Session::new(session_id, server_keys).unwrap();

    // Client sends packet
    let payload = b"Test packet";
    let mut packet_buf = vec![0u8; HEADER_SIZE + payload.len() + 32];
    let packet_len = client_session
        .encrypt_packet(MessageType::Data, payload, &mut packet_buf)
        .unwrap();

    // Save packet for replay
    let replay_packet = packet_buf[..packet_len].to_vec();

    // Server receives first time - OK
    let mut decrypt_buf = vec![0u8; payload.len() + aead::TAG_SIZE];
    let result = server_session.decrypt_packet(&replay_packet, &mut decrypt_buf);
    assert!(result.is_ok());

    // Server receives same packet again - REPLAY DETECTED
    let result = server_session.decrypt_packet(&replay_packet, &mut decrypt_buf);
    assert!(matches!(
        result,
        Err(hpn_core::error::ProtocolError::ReplayDetected(_))
    ));
}

/// Test rekey protocol flow.
#[test]
fn test_rekey_protocol() {
    // Initial handshake
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key.clone());

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let (response, server_keys) = server_hs
        .process_init(&init, session_id, TunnelConfig::default())
        .unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    // Create sessions with initial keys
    let mut client_session = Session::new(session_id, client_keys).unwrap();
    let mut server_session = Session::new(session_id, server_keys).unwrap();

    // Verify initial key ID
    assert_eq!(client_session.key_id(), KeyId::initial());
    assert_eq!(server_session.key_id(), KeyId::initial());

    // --- Rekey process ---

    // Client initiates rekey
    let mut client_rekey = ClientRekey::new(server_keypair.public_key, client_session.session_id());
    let rekey_request = client_rekey
        .create_request()
        .expect("failed to create rekey request");

    // Server processes rekey request (with session_id for key derivation context)
    let (rekey_response, new_server_keys) = server_hs
        .process_rekey(&rekey_request, client_session.key_id(), session_id)
        .expect("server failed to process rekey");

    // Verify new key ID in response
    assert_eq!(rekey_response.new_key_id, 1);

    // Client processes rekey response
    let new_client_keys = client_rekey
        .process_response(&rekey_response)
        .expect("client failed to process rekey response");

    // Update both sessions with new keys
    client_session.update_keys(new_client_keys).unwrap();
    server_session.update_keys(new_server_keys).unwrap();

    // Verify key ID incremented
    assert_eq!(client_session.key_id(), KeyId::initial().next());
    assert_eq!(server_session.key_id(), KeyId::initial().next());

    // Verify new keys work for communication
    let payload = b"Post-rekey message";
    let mut packet_buf = vec![0u8; HEADER_SIZE + payload.len() + 32];
    let packet_len = client_session
        .encrypt_packet(MessageType::Data, payload, &mut packet_buf)
        .expect("encryption with new keys failed");

    let mut decrypt_buf = vec![0u8; payload.len() + aead::TAG_SIZE];
    let (header, decrypted_len) = server_session
        .decrypt_packet(&packet_buf[..packet_len], &mut decrypt_buf)
        .expect("decryption with new keys failed");

    assert_eq!(header.msg_type, MessageType::Data);
    assert_eq!(header.key_id, KeyId::initial().next());
    assert_eq!(&decrypt_buf[..decrypted_len], payload);
}

/// Test control message (close) handling.
#[test]
fn test_control_close_message() {
    // Set up sessions
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key);

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let (response, server_keys) = server_hs
        .process_init(&init, session_id, TunnelConfig::default())
        .unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    let client_session = Session::new(session_id, client_keys).unwrap();
    let server_session = Session::new(session_id, server_keys).unwrap();

    // Server sends close control message
    let close_msg = ControlMessage::close();
    let close_bytes = close_msg.to_bytes();

    let mut packet_buf = vec![0u8; HEADER_SIZE + close_bytes.len() + 32];
    let packet_len = server_session
        .encrypt_packet(MessageType::Control, &close_bytes, &mut packet_buf)
        .unwrap();

    // Client receives and decrypts
    let mut decrypt_buf = vec![0u8; close_bytes.len() + aead::TAG_SIZE];
    let (header, decrypted_len) = client_session
        .decrypt_packet(&packet_buf[..packet_len], &mut decrypt_buf)
        .unwrap();

    assert_eq!(header.msg_type, MessageType::Control);

    // Parse control message
    let received_control = ControlMessage::from_bytes(&decrypt_buf[..decrypted_len]).unwrap();
    assert_eq!(
        received_control.control_type,
        hpn_core::types::ControlType::Close
    );
}

/// Test that wrong server key is rejected.
#[test]
fn test_wrong_server_key_rejected() {
    let real_server_keypair = MlDsaKeypair::generate();
    let fake_server_keypair = MlDsaKeypair::generate();

    // Server uses real key
    let mut server = ServerHandshake::new(Arc::new(real_server_keypair));

    // Client expects fake key (impersonation attack)
    let mut client = ClientHandshake::with_server_pk(fake_server_keypair.public_key);

    let init = client.create_init().unwrap();
    let session_id = SessionId::generate();
    let (response, _) = server
        .process_init(&init, session_id, TunnelConfig::default())
        .unwrap();

    // Client should reject due to signature verification failure
    let result = client.process_response(&response);
    assert!(result.is_err());
    assert!(matches!(
        *client.state(),
        hpn_core::protocol::HandshakeState::Failed(_)
    ));
}

/// Test session timeout and rekey need detection.
#[test]
fn test_session_needs_rekey() {
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key);

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let (response, _server_keys) = server_hs
        .process_init(&init, session_id, TunnelConfig::default())
        .unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    let session = Session::new(session_id, client_keys).unwrap();

    // Should not need rekey initially
    let max_bytes = 1024 * 1024; // 1 MB
    let max_duration = Duration::from_secs(3600); // 1 hour
    assert!(!session.needs_rekey(max_bytes, max_duration));

    // Simulate data transfer exceeding threshold
    session.add_bytes_sent(max_bytes + 1);
    assert!(session.needs_rekey(max_bytes, max_duration));
}

/// Test message serialization roundtrips.
#[test]
fn test_message_serialization() {
    // TunnelConfig
    let config = TunnelConfig {
        client_ipv4: [192, 168, 1, 100],
        netmask_ipv4: [255, 255, 255, 0],
        gateway_ipv4: [192, 168, 1, 1],
        dns_ipv4: vec![[1, 1, 1, 1], [8, 8, 8, 8]],
        client_ipv6: None,
        prefix_len_ipv6: None,
        gateway_ipv6: None,
        dns_ipv6: vec![],
        mtu: 1280,
    };
    let config_bytes = config.to_bytes();
    let config_decoded = TunnelConfig::from_bytes(&config_bytes).unwrap();
    assert_eq!(config.client_ipv4, config_decoded.client_ipv4);
    assert_eq!(config.dns_ipv4.len(), config_decoded.dns_ipv4.len());

    // ControlMessage
    let error = ControlMessage::error(503, "Service unavailable");
    let error_bytes = error.to_bytes();
    let error_decoded = ControlMessage::from_bytes(&error_bytes).unwrap();
    assert_eq!(error.error_code, error_decoded.error_code);
    assert_eq!(error.message, error_decoded.message);
}

/// Test multiple packets with incrementing counters.
#[test]
fn test_counter_progression() {
    let server_keypair = MlDsaKeypair::generate();
    let mut server_hs = ServerHandshake::new(Arc::new(server_keypair.clone()));
    let mut client_hs = ClientHandshake::with_server_pk(server_keypair.public_key);

    let init = client_hs.create_init().unwrap();
    let session_id = SessionId::generate();
    let (response, server_keys) = server_hs
        .process_init(&init, session_id, TunnelConfig::default())
        .unwrap();
    let (_, client_keys, _) = client_hs.process_response(&response).unwrap();

    let client_session = Session::new(session_id, client_keys).unwrap();
    let server_session = Session::new(session_id, server_keys).unwrap();

    // Send multiple packets and verify counters increment
    for i in 0u64..10 {
        let payload = format!("Packet {i}");
        let mut packet_buf = vec![0u8; 256]; // Generous buffer size
        let packet_len = client_session
            .encrypt_packet(MessageType::Data, payload.as_bytes(), &mut packet_buf)
            .unwrap_or_else(|_| panic!("encryption failed for packet {i}"));

        let mut decrypt_buf = vec![0u8; 256]; // Generous buffer size
        let (header, _) = server_session
            .decrypt_packet(&packet_buf[..packet_len], &mut decrypt_buf)
            .unwrap_or_else(|_| panic!("decryption failed for packet {i}"));

        // Verify counter matches expected value
        assert_eq!(header.counter.0, i);
    }
}
