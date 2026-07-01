//! IPC protocol for communication between Tauri UI and VPN client.
//!
//! This module defines the messages and protocol used for communication
//! between the Tauri-based UI and the VPN client process.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Serialize a `Zeroizing<String>` as a plain string.
fn serialize_zeroizing<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.as_str())
}

/// Deserialize a plain string into a `Zeroizing<String>`.
fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Zeroizing::new(s))
}

/// IPC message from UI to VPN client.
///
/// **WARNING (FIX-034)**: this enum and the matching `ClientResponse`
/// describe a transport-agnostic IPC protocol that was sketched for a
/// future stand-alone CLI / daemon split. NEITHER the Tauri-based macOS
/// build nor the Tauri-based Windows build uses this channel at runtime
/// — both ship the VPN engine in-process and dispatch through Tauri's
/// own IPC. The `serde` derives below therefore exist as a non-public
/// scaffold; the wire format is NOT authenticated, NOT replay-protected,
/// and has no transport-layer integrity beyond `serde_json` parsing.
///
/// Do NOT expose this enum on any externally-reachable socket / pipe
/// without first wrapping it in a MAC (HKDF-derived HMAC over the
/// serialised JSON, keyed by a shared secret established out-of-band).
/// `Connect.credentials` is `Zeroizing<String>` so the in-memory side
/// is covered, but the on-wire side would otherwise be readable by any
/// process able to attach to the same Unix socket.
///
/// `#[non_exhaustive]` is set so a future caller adding a new variant
/// cannot inadvertently rely on exhaustive pattern matching here and
/// silently miss authentication for the new opcode.
///
/// Note: The `Clone` trait is intentionally not derived for security reasons.
/// `ClientRequest::Connect` contains credentials wrapped in `Zeroizing<String>`,
/// which ensures credentials are securely zeroed on drop. Cloning would create
/// copies of sensitive data that might not be properly zeroized.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ClientRequest {
    /// Connect to VPN server.
    Connect {
        /// Server address (IP:port).
        server_addr: String,
        /// User credentials.
        /// Wrapped in `Zeroizing` to ensure credentials are securely zeroed
        /// when dropped, preventing credentials from lingering in memory.
        #[serde(
            serialize_with = "serialize_zeroizing",
            deserialize_with = "deserialize_zeroizing"
        )]
        credentials: Zeroizing<String>,
    },
    /// Disconnect from VPN.
    Disconnect,
    /// Get connection status.
    GetStatus,
    /// Get connection statistics.
    GetStats,
    /// Update configuration.
    UpdateConfig {
        /// New configuration (JSON).
        config: serde_json::Value,
    },
}

/// IPC message from VPN client to UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientResponse {
    /// Connection status update.
    Status {
        /// Current connection state.
        state: ConnectionState,
        /// Server address (if connected).
        server: Option<String>,
        /// Connected since (Unix timestamp).
        connected_since: Option<u64>,
    },
    /// Connection statistics.
    Stats {
        /// Bytes sent.
        bytes_sent: u64,
        /// Bytes received.
        bytes_received: u64,
        /// Packets sent.
        packets_sent: u64,
        /// Packets received.
        packets_received: u64,
        /// Current latency (ms).
        latency_ms: Option<u32>,
    },
    /// Error occurred.
    Error {
        /// Error message.
        message: String,
    },
    /// Success (generic response).
    Success {
        /// Optional message.
        message: Option<String>,
    },
}

/// VPN connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Disconnected.
    Disconnected,
    /// Connecting (handshake in progress).
    Connecting,
    /// Connected and established.
    Connected,
    /// Disconnecting.
    Disconnecting,
    /// Error state.
    Error,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected => write!(f, "Connected"),
            Self::Disconnecting => write!(f, "Disconnecting"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// IPC transport abstraction.
///
/// This trait allows different IPC mechanisms (Unix sockets, named pipes,
/// WebSockets, etc.) to be used for communication between UI and client.
#[async_trait::async_trait]
pub trait IpcTransport: Send + Sync {
    /// Send a request to the client.
    async fn send_request(&mut self, request: ClientRequest) -> std::io::Result<()>;

    /// Receive a response from the client.
    async fn receive_response(&mut self) -> std::io::Result<ClientResponse>;

    /// Check if the connection is still alive.
    fn is_connected(&self) -> bool;

    /// Close the connection.
    async fn close(&mut self) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Disconnected.to_string(), "Disconnected");
        assert_eq!(ConnectionState::Connecting.to_string(), "Connecting");
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
    }

    #[test]
    fn test_client_request_serialization() {
        let request = ClientRequest::Connect {
            server_addr: "1.2.3.4:51820".to_string(),
            credentials: Zeroizing::new("test_key".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Connect"));
        assert!(json.contains("1.2.3.4:51820"));
    }

    #[test]
    fn test_client_response_serialization() {
        let response = ClientResponse::Status {
            state: ConnectionState::Connected,
            server: Some("1.2.3.4:51820".to_string()),
            connected_since: Some(1234567890),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Status"));
        assert!(json.contains("Connected"));
    }

    #[test]
    fn test_client_request_roundtrip() {
        // Test Connect variant separately due to Zeroizing not implementing PartialEq
        let connect_request = ClientRequest::Connect {
            server_addr: "10.0.0.1:51820".to_string(),
            credentials: Zeroizing::new("my_key".to_string()),
        };
        let json = serde_json::to_string(&connect_request).unwrap();
        let parsed: ClientRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, json2);

        // Test other variants
        let requests = vec![
            ClientRequest::Disconnect,
            ClientRequest::GetStatus,
            ClientRequest::GetStats,
            ClientRequest::UpdateConfig {
                config: serde_json::json!({"keepalive": 30}),
            },
        ];

        for request in requests {
            let json = serde_json::to_string(&request).unwrap();
            let parsed: ClientRequest = serde_json::from_str(&json).unwrap();
            // Serialize again to verify
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_client_response_roundtrip() {
        let responses = vec![
            ClientResponse::Status {
                state: ConnectionState::Connected,
                server: Some("1.2.3.4:51820".to_string()),
                connected_since: Some(1234567890),
            },
            ClientResponse::Status {
                state: ConnectionState::Disconnected,
                server: None,
                connected_since: None,
            },
            ClientResponse::Stats {
                bytes_sent: 1000000,
                bytes_received: 2000000,
                packets_sent: 1500,
                packets_received: 2500,
                latency_ms: Some(50),
            },
            ClientResponse::Stats {
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                latency_ms: None,
            },
            ClientResponse::Error {
                message: "Connection failed".to_string(),
            },
            ClientResponse::Success {
                message: Some("Configuration updated".to_string()),
            },
            ClientResponse::Success { message: None },
        ];

        for response in responses {
            let json = serde_json::to_string(&response).unwrap();
            let parsed: ClientResponse = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_connection_state_equality() {
        assert_eq!(ConnectionState::Connected, ConnectionState::Connected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connecting, ConnectionState::Disconnecting);
    }

    #[test]
    fn test_connection_state_clone() {
        let state = ConnectionState::Connected;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_client_request_credentials_zeroized() {
        // Test that credentials are properly wrapped in Zeroizing
        let request = ClientRequest::Connect {
            server_addr: "test.com:51820".to_string(),
            credentials: Zeroizing::new("key123".to_string()),
        };

        // Verify serialization works correctly
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("key123"));
        assert!(json.contains("test.com:51820"));

        // Verify deserialization recreates the Zeroizing wrapper
        let parsed: ClientRequest = serde_json::from_str(&json).unwrap();
        if let ClientRequest::Connect { credentials, .. } = parsed {
            assert_eq!(credentials.as_str(), "key123");
        } else {
            panic!("Expected Connect variant");
        }
    }

    #[test]
    fn test_client_response_clone() {
        let response = ClientResponse::Stats {
            bytes_sent: 100,
            bytes_received: 200,
            packets_sent: 10,
            packets_received: 20,
            latency_ms: Some(25),
        };
        let cloned = response.clone();

        let json1 = serde_json::to_string(&response).unwrap();
        let json2 = serde_json::to_string(&cloned).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_all_connection_states_display() {
        assert_eq!(ConnectionState::Disconnected.to_string(), "Disconnected");
        assert_eq!(ConnectionState::Connecting.to_string(), "Connecting");
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
        assert_eq!(ConnectionState::Disconnecting.to_string(), "Disconnecting");
        assert_eq!(ConnectionState::Error.to_string(), "Error");
    }
}
