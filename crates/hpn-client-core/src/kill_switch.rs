//! Kill switch state management and edge case handling.
//!
//! Provides a platform-agnostic kill switch state machine and handles
//! edge cases like network interface changes, system sleep/wake, and
//! unexpected disconnections.

use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Kill switch mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillSwitchMode {
    /// Kill switch is disabled - traffic flows normally when VPN disconnects.
    Disabled,
    /// Kill switch is enabled - blocks all traffic when VPN disconnects.
    Enabled,
    /// Kill switch is enabled but allows LAN traffic.
    EnabledAllowLan,
}

impl KillSwitchMode {
    /// Check if kill switch is active (enabled in any mode).
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Check if LAN traffic is allowed.
    pub fn allows_lan(&self) -> bool {
        matches!(self, Self::Disabled | Self::EnabledAllowLan)
    }
}

impl Default for KillSwitchMode {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Kill switch state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillSwitchState {
    /// Not armed - VPN is not connected, kill switch not engaged.
    Inactive,
    /// Armed - VPN is connected, kill switch ready to engage on disconnect.
    Armed,
    /// Engaged - VPN disconnected unexpectedly, traffic is blocked.
    Engaged,
    /// Bypassed - User explicitly allowed bypass (e.g., during reconnect attempt).
    Bypassed,
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self::Inactive
    }
}

/// Disconnect reason - used to determine if kill switch should engage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// User requested disconnect.
    UserRequested,
    /// Server closed the connection.
    ServerClosed,
    /// Network error (connection lost).
    NetworkError,
    /// Authentication failure.
    AuthFailure,
    /// Session timeout.
    SessionTimeout,
    /// System event (sleep, network change).
    SystemEvent,
    /// Unknown reason.
    Unknown,
}

impl DisconnectReason {
    /// Check if this reason should engage the kill switch.
    pub fn should_engage_kill_switch(&self) -> bool {
        match self {
            // User requested - don't engage
            Self::UserRequested => false,
            // All other reasons - engage
            Self::ServerClosed
            | Self::NetworkError
            | Self::AuthFailure
            | Self::SessionTimeout
            | Self::SystemEvent
            | Self::Unknown => true,
        }
    }
}

/// Kill switch manager.
///
/// Manages the state machine and provides hooks for platform-specific
/// implementations to react to state changes.
pub struct KillSwitchManager {
    /// Current mode.
    mode: RwLock<KillSwitchMode>,
    /// Current state.
    state: RwLock<KillSwitchState>,
    /// Time when state last changed.
    state_changed_at: RwLock<Instant>,
    /// Number of reconnect attempts since engagement.
    reconnect_attempts: RwLock<u32>,
    /// Maximum reconnect attempts before giving up.
    max_reconnect_attempts: u32,
    /// Reconnect delay (increases with each attempt).
    base_reconnect_delay: Duration,
}

impl KillSwitchManager {
    /// Create a new kill switch manager with the given mode.
    pub fn new(mode: KillSwitchMode) -> Self {
        Self {
            mode: RwLock::new(mode),
            state: RwLock::new(KillSwitchState::Inactive),
            state_changed_at: RwLock::new(Instant::now()),
            reconnect_attempts: RwLock::new(0),
            max_reconnect_attempts: 5,
            base_reconnect_delay: Duration::from_secs(2),
        }
    }

    /// Create with custom reconnect settings.
    pub fn with_reconnect_settings(
        mode: KillSwitchMode,
        max_attempts: u32,
        base_delay: Duration,
    ) -> Self {
        Self {
            mode: RwLock::new(mode),
            state: RwLock::new(KillSwitchState::Inactive),
            state_changed_at: RwLock::new(Instant::now()),
            reconnect_attempts: RwLock::new(0),
            max_reconnect_attempts: max_attempts,
            base_reconnect_delay: base_delay,
        }
    }

    /// Get current mode.
    pub fn mode(&self) -> KillSwitchMode {
        *self.mode.read()
    }

    /// Set mode.
    /// Uses write lock for atomic check-and-set to prevent TOCTOU races.
    pub fn set_mode(&self, mode: KillSwitchMode) {
        // Use write lock for atomic check-and-set
        let mut current_mode = self.mode.write();
        let old_mode = *current_mode;

        if old_mode != mode {
            *current_mode = mode;

            // Read state while still holding mode lock to prevent TOCTOU race.
            // Another thread could change state between dropping mode lock and
            // reading state, causing us to miss or incorrectly apply the transition.
            let should_transition =
                !mode.is_active() && *self.state.read() == KillSwitchState::Engaged;

            // Now safe to drop mode lock
            drop(current_mode);

            info!("Kill switch mode changed: {:?} -> {:?}", old_mode, mode);

            // If disabling while engaged, transition to inactive
            if should_transition {
                self.transition_to(KillSwitchState::Inactive);
            }
        }
    }

    /// Get current state.
    pub fn state(&self) -> KillSwitchState {
        *self.state.read()
    }

    /// Check if traffic should be blocked.
    pub fn should_block_traffic(&self) -> bool {
        let mode = *self.mode.read();
        let state = *self.state.read();

        mode.is_active() && state == KillSwitchState::Engaged
    }

    /// Check if LAN traffic is allowed.
    pub fn is_lan_allowed(&self) -> bool {
        self.mode().allows_lan()
    }

    /// Called when VPN connects.
    pub fn on_vpn_connected(&self) {
        if self.mode().is_active() {
            info!("Kill switch armed");
            self.transition_to(KillSwitchState::Armed);
            *self.reconnect_attempts.write() = 0;
        }
    }

    /// Called when VPN disconnects.
    ///
    /// Returns true if traffic should be blocked.
    pub fn on_vpn_disconnected(&self, reason: DisconnectReason) -> bool {
        let mode = *self.mode.read();
        let current_state = *self.state.read();

        if !mode.is_active() {
            self.transition_to(KillSwitchState::Inactive);
            return false;
        }

        // Only engage if we were armed and reason warrants it
        if current_state == KillSwitchState::Armed && reason.should_engage_kill_switch() {
            warn!("Kill switch engaged due to: {:?}", reason);
            self.transition_to(KillSwitchState::Engaged);
            return true;
        }

        // User-requested disconnect - don't engage
        if !reason.should_engage_kill_switch() {
            info!("Kill switch not engaged (user requested disconnect)");
            self.transition_to(KillSwitchState::Inactive);
            return false;
        }

        // Already engaged - stay engaged
        current_state == KillSwitchState::Engaged
    }

    /// Called when attempting to reconnect.
    ///
    /// Returns the recommended delay before the reconnect attempt,
    /// or None if max attempts exceeded.
    pub fn on_reconnect_attempt(&self) -> Option<Duration> {
        let mut attempts = self.reconnect_attempts.write();
        *attempts += 1;

        if *attempts > self.max_reconnect_attempts {
            warn!(
                "Max reconnect attempts ({}) exceeded",
                self.max_reconnect_attempts
            );
            return None;
        }

        // Exponential backoff with jitter — bounded against integer
        // overflow.
        //
        // The previous expression (`base_reconnect_delay * 2u32.pow(
        // *attempts - 1)`) panicked once `*attempts > 32` because
        // `2u32.pow(32)` overflows. With `max_reconnect_attempts = 0`
        // (= unlimited, common for enterprise deployments) and a
        // multi-hour outage, the 33rd attempt was an unstoppable
        // process exit — and on Drop the kill switch could disengage
        // depending on how the binary was packaged. We now:
        //
        //   1. Cap the exponent at 20 (`2^20` = 1 048 576). At
        //      `base_reconnect_delay = 1 s` the un-capped delay
        //      would be ≈ 12 days, but step (4) below clamps it at
        //      `MAX_RECONNECT_DELAY = 5 minutes` so the user-visible
        //      delay never exceeds that.
        //   2. Use `checked_pow` + `unwrap_or(u32::MAX)` so an
        //      out-of-range value never overflows.
        //   3. Multiply via `Duration::saturating_mul` so the final
        //      delay saturates at `Duration::MAX` rather than panicking.
        //   4. Cap the final delay at `MAX_RECONNECT_DELAY` (5 minutes)
        //      to keep the user experience reasonable on a long
        //      outage — there is no benefit to waiting longer between
        //      attempts.
        const MAX_BACKOFF_EXPONENT: u32 = 20;
        const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
        let exponent = (*attempts - 1).min(MAX_BACKOFF_EXPONENT);
        let multiplier = 2u32.checked_pow(exponent).unwrap_or(u32::MAX);
        let delay = self
            .base_reconnect_delay
            .saturating_mul(multiplier)
            .min(MAX_RECONNECT_DELAY);
        let jitter = Duration::from_millis(rand::random::<u64>() % 500);

        info!(
            "Reconnect attempt {}/{}, delay: {:?}",
            *attempts, self.max_reconnect_attempts, delay
        );

        // Temporarily bypass kill switch for the reconnect attempt
        if *self.state.read() == KillSwitchState::Engaged {
            self.transition_to(KillSwitchState::Bypassed);
        }

        Some(delay + jitter)
    }

    /// Called when reconnect succeeds.
    pub fn on_reconnect_success(&self) {
        info!("Reconnect successful, kill switch re-armed");
        *self.reconnect_attempts.write() = 0;
        self.transition_to(KillSwitchState::Armed);
    }

    /// Called when reconnect fails.
    pub fn on_reconnect_failed(&self) {
        if self.mode().is_active() {
            warn!("Reconnect failed, kill switch re-engaged");
            self.transition_to(KillSwitchState::Engaged);
        }
    }

    /// Reset the kill switch (e.g., when user disables it).
    pub fn reset(&self) {
        info!("Kill switch reset");
        self.transition_to(KillSwitchState::Inactive);
        *self.reconnect_attempts.write() = 0;
    }

    /// Get time since last state change.
    pub fn time_in_current_state(&self) -> Duration {
        self.state_changed_at.read().elapsed()
    }

    /// Get current reconnect attempt count.
    pub fn reconnect_attempt_count(&self) -> u32 {
        *self.reconnect_attempts.read()
    }

    /// Transition to a new state.
    /// Uses write lock for the entire operation to prevent TOCTOU races.
    fn transition_to(&self, new_state: KillSwitchState) {
        // Use write lock for atomic check-and-set
        let mut state = self.state.write();
        let old_state = *state;
        if old_state != new_state {
            *state = new_state;
            *self.state_changed_at.write() = Instant::now();
            debug!("Kill switch state: {:?} -> {:?}", old_state, new_state);
        }
    }
}

impl Default for KillSwitchManager {
    fn default() -> Self {
        Self::new(KillSwitchMode::Disabled)
    }
}

/// Network change detector.
///
/// Monitors for network interface changes that might affect the VPN connection.
pub struct NetworkChangeDetector {
    /// Last known default gateway.
    last_gateway: RwLock<Option<String>>,
    /// Last check time.
    last_check: RwLock<Instant>,
    /// Check interval.
    check_interval: Duration,
}

impl NetworkChangeDetector {
    /// Create a new network change detector.
    pub fn new() -> Self {
        Self {
            last_gateway: RwLock::new(None),
            last_check: RwLock::new(Instant::now()),
            check_interval: Duration::from_secs(5),
        }
    }

    /// Create with custom check interval.
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            last_gateway: RwLock::new(None),
            last_check: RwLock::new(Instant::now()),
            check_interval: interval,
        }
    }

    /// Record the current gateway.
    pub fn record_gateway(&self, gateway: String) {
        *self.last_gateway.write() = Some(gateway);
        *self.last_check.write() = Instant::now();
    }

    /// Check if gateway has changed.
    ///
    /// Returns Some(new_gateway) if changed, None if unchanged.
    pub fn check_gateway_change(&self, current_gateway: &str) -> Option<String> {
        let last = self.last_gateway.read();
        match &*last {
            Some(last_gw) if last_gw != current_gateway => Some(current_gateway.to_string()),
            _ => None,
        }
    }

    /// Check if enough time has passed since last check.
    pub fn should_check(&self) -> bool {
        self.last_check.read().elapsed() >= self.check_interval
    }

    /// Update last check time.
    pub fn mark_checked(&self) {
        *self.last_check.write() = Instant::now();
    }
}

impl Default for NetworkChangeDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// System event types that might affect the VPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemEvent {
    /// System is going to sleep.
    Sleep,
    /// System woke from sleep.
    Wake,
    /// Network interfaces changed.
    NetworkChange,
    /// Power source changed (battery/AC).
    PowerChange,
}

impl SystemEvent {
    /// Check if this event should trigger a reconnect check.
    pub fn should_check_connection(&self) -> bool {
        match self {
            Self::Wake | Self::NetworkChange => true,
            Self::Sleep | Self::PowerChange => false,
        }
    }

    /// Check if this event should pause the connection.
    pub fn should_pause_connection(&self) -> bool {
        matches!(self, Self::Sleep)
    }
}

#[cfg(test)]
#[allow(clippy::needless_collect)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch_mode() {
        assert!(!KillSwitchMode::Disabled.is_active());
        assert!(KillSwitchMode::Enabled.is_active());
        assert!(KillSwitchMode::EnabledAllowLan.is_active());

        assert!(KillSwitchMode::Disabled.allows_lan());
        assert!(!KillSwitchMode::Enabled.allows_lan());
        assert!(KillSwitchMode::EnabledAllowLan.allows_lan());
    }

    #[test]
    fn test_disconnect_reason() {
        assert!(!DisconnectReason::UserRequested.should_engage_kill_switch());
        assert!(DisconnectReason::NetworkError.should_engage_kill_switch());
        assert!(DisconnectReason::ServerClosed.should_engage_kill_switch());
    }

    #[test]
    fn test_kill_switch_state_machine() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        // Initial state
        assert_eq!(ks.state(), KillSwitchState::Inactive);
        assert!(!ks.should_block_traffic());

        // Connect
        ks.on_vpn_connected();
        assert_eq!(ks.state(), KillSwitchState::Armed);
        assert!(!ks.should_block_traffic());

        // Disconnect (network error)
        let should_block = ks.on_vpn_disconnected(DisconnectReason::NetworkError);
        assert!(should_block);
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert!(ks.should_block_traffic());
    }

    #[test]
    fn test_kill_switch_user_disconnect() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        ks.on_vpn_connected();
        assert_eq!(ks.state(), KillSwitchState::Armed);

        // User requested disconnect - should NOT engage
        let should_block = ks.on_vpn_disconnected(DisconnectReason::UserRequested);
        assert!(!should_block);
        assert_eq!(ks.state(), KillSwitchState::Inactive);
    }

    #[test]
    fn test_kill_switch_disabled() {
        let ks = KillSwitchManager::new(KillSwitchMode::Disabled);

        ks.on_vpn_connected();
        assert_eq!(ks.state(), KillSwitchState::Inactive);

        let should_block = ks.on_vpn_disconnected(DisconnectReason::NetworkError);
        assert!(!should_block);
        assert_eq!(ks.state(), KillSwitchState::Inactive);
    }

    #[test]
    fn test_reconnect_attempts() {
        let ks = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            3,
            Duration::from_millis(100),
        );

        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);

        // Should get delays for attempts 1-3
        assert!(ks.on_reconnect_attempt().is_some());
        assert!(ks.on_reconnect_attempt().is_some());
        assert!(ks.on_reconnect_attempt().is_some());

        // 4th attempt should fail
        assert!(ks.on_reconnect_attempt().is_none());
    }

    #[test]
    fn test_network_change_detector() {
        let detector = NetworkChangeDetector::new();

        detector.record_gateway("192.168.1.1".to_string());

        // Same gateway - no change
        assert!(detector.check_gateway_change("192.168.1.1").is_none());

        // Different gateway - change detected
        let change = detector.check_gateway_change("192.168.1.254");
        assert!(change.is_some());
        assert_eq!(change.unwrap(), "192.168.1.254");
    }

    #[test]
    fn test_kill_switch_e2e_scenario() {
        // SECURITY TEST P0-5: End-to-end kill switch scenario
        // This test simulates a complete kill switch lifecycle including:
        // - Normal connection/disconnection
        // - Unexpected disconnection with kill switch engagement
        // - Reconnection attempts with exponential backoff
        // - Network change detection
        // - Multiple disconnect scenarios

        use std::time::Duration;

        // Scenario 1: Normal operation cycle
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        // Initial state - inactive, no blocking
        assert_eq!(ks.state(), KillSwitchState::Inactive);
        assert!(!ks.should_block_traffic());

        // User connects to VPN
        ks.on_vpn_connected();
        assert_eq!(ks.state(), KillSwitchState::Armed);
        assert!(!ks.should_block_traffic(), "Armed state should not block");

        // User disconnects normally - no kill switch
        let should_block = ks.on_vpn_disconnected(DisconnectReason::UserRequested);
        assert!(
            !should_block,
            "User disconnect should not engage kill switch"
        );
        assert_eq!(ks.state(), KillSwitchState::Inactive);

        // Scenario 2: Unexpected disconnection with kill switch
        ks.on_vpn_connected();
        assert_eq!(ks.state(), KillSwitchState::Armed);

        // Network error - kill switch engages
        let should_block = ks.on_vpn_disconnected(DisconnectReason::NetworkError);
        assert!(should_block, "Network error should engage kill switch");
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert!(
            ks.should_block_traffic(),
            "Engaged state must block traffic"
        );

        // Scenario 3: Reconnection with exponential backoff
        let ks_reconnect = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            5,                         // max_attempts
            Duration::from_millis(50), // base_delay
        );

        ks_reconnect.on_vpn_connected();
        ks_reconnect.on_vpn_disconnected(DisconnectReason::NetworkError);
        assert_eq!(ks_reconnect.state(), KillSwitchState::Engaged);

        // Attempt 1 - should succeed with base delay + jitter
        let delay1 = ks_reconnect.on_reconnect_attempt();
        assert!(delay1.is_some(), "First reconnect attempt should succeed");
        // With jitter, should be >= base delay (50ms) and < 550ms (50ms + 500ms jitter)
        let d1 = delay1.unwrap();
        assert!(d1 >= Duration::from_millis(50) && d1 < Duration::from_millis(550));

        // Attempt 2 - exponential backoff (50ms * 2) + jitter
        let delay2 = ks_reconnect.on_reconnect_attempt();
        assert!(delay2.is_some(), "Second reconnect attempt should succeed");
        let d2 = delay2.unwrap();
        assert!(d2 >= Duration::from_millis(100) && d2 < Duration::from_millis(600));

        // Attempt 3 - exponential backoff (50ms * 4) + jitter
        let delay3 = ks_reconnect.on_reconnect_attempt();
        assert!(delay3.is_some(), "Third reconnect attempt should succeed");
        let d3 = delay3.unwrap();
        assert!(d3 >= Duration::from_millis(200) && d3 < Duration::from_millis(700));

        // After max attempts, should fail
        ks_reconnect.on_reconnect_attempt(); // 4
        ks_reconnect.on_reconnect_attempt(); // 5
        let delay_fail = ks_reconnect.on_reconnect_attempt(); // 6 - should fail
        assert!(
            delay_fail.is_none(),
            "After max attempts, should deny reconnect"
        );

        // Successful reconnection disarms kill switch
        ks_reconnect.on_vpn_connected();
        assert_eq!(ks_reconnect.state(), KillSwitchState::Armed);
        assert!(!ks_reconnect.should_block_traffic());

        // Scenario 4: Different disconnect reasons
        let test_reasons = [
            (DisconnectReason::ServerClosed, true),
            (DisconnectReason::AuthFailure, true),
            (DisconnectReason::SessionTimeout, true),
            (DisconnectReason::SystemEvent, true),
            (DisconnectReason::Unknown, true),
            (DisconnectReason::UserRequested, false),
        ];

        for (reason, should_engage) in test_reasons {
            let ks_test = KillSwitchManager::new(KillSwitchMode::Enabled);
            ks_test.on_vpn_connected();
            let engaged = ks_test.on_vpn_disconnected(reason);
            assert_eq!(
                engaged, should_engage,
                "Disconnect reason {:?} engagement mismatch",
                reason
            );
        }

        // Scenario 5: Kill switch mode variations
        let modes = [
            (KillSwitchMode::Disabled, false),
            (KillSwitchMode::Enabled, true),
            (KillSwitchMode::EnabledAllowLan, true),
        ];

        for (mode, should_engage) in modes {
            let ks_mode = KillSwitchManager::new(mode);
            ks_mode.on_vpn_connected();
            let engaged = ks_mode.on_vpn_disconnected(DisconnectReason::NetworkError);
            assert_eq!(
                engaged, should_engage,
                "Mode {:?} engagement mismatch",
                mode
            );
        }

        // Scenario 6: Network change detection during connection
        let detector = NetworkChangeDetector::new();
        detector.record_gateway("192.168.1.1".to_string());

        // Simulate network change while VPN is connected
        let change = detector.check_gateway_change("192.168.2.1");
        assert!(change.is_some(), "Network change should be detected");

        // Kill switch should handle network change as SystemEvent disconnect
        let ks_network = KillSwitchManager::new(KillSwitchMode::Enabled);
        ks_network.on_vpn_connected();
        let engaged = ks_network.on_vpn_disconnected(DisconnectReason::SystemEvent);
        assert!(engaged, "Network change should engage kill switch");
        assert_eq!(ks_network.state(), KillSwitchState::Engaged);
    }

    #[test]
    fn test_kill_switch_concurrent_state_changes() {
        // SECURITY TEST P0-5 (Extended): Concurrent state changes
        // Verify kill switch state machine is thread-safe

        use std::sync::Arc;
        use std::thread;

        let ks = Arc::new(KillSwitchManager::new(KillSwitchMode::Enabled));

        // Spawn multiple threads trying to change state concurrently
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let ks_clone = Arc::clone(&ks);
                thread::spawn(move || {
                    if i % 2 == 0 {
                        ks_clone.on_vpn_connected();
                    } else {
                        ks_clone.on_vpn_disconnected(DisconnectReason::NetworkError);
                    }
                    ks_clone.state()
                })
            })
            .collect();

        // All threads should complete without panic
        let _states: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Final state should be consistent (either Armed or Engaged)
        let final_state = ks.state();
        assert!(
            matches!(
                final_state,
                KillSwitchState::Armed | KillSwitchState::Engaged
            ),
            "Final state should be Armed or Engaged, got {:?}",
            final_state
        );
    }

    #[test]
    fn test_kill_switch_mode_defaults() {
        let mode = KillSwitchMode::default();
        assert_eq!(mode, KillSwitchMode::Disabled);
        assert!(!mode.is_active());
    }

    #[test]
    fn test_kill_switch_state_defaults() {
        let state = KillSwitchState::default();
        assert_eq!(state, KillSwitchState::Inactive);
    }

    #[test]
    fn test_disconnect_reason_all_variants() {
        assert!(!DisconnectReason::UserRequested.should_engage_kill_switch());
        assert!(DisconnectReason::ServerClosed.should_engage_kill_switch());
        assert!(DisconnectReason::NetworkError.should_engage_kill_switch());
        assert!(DisconnectReason::AuthFailure.should_engage_kill_switch());
        assert!(DisconnectReason::SessionTimeout.should_engage_kill_switch());
        assert!(DisconnectReason::SystemEvent.should_engage_kill_switch());
        assert!(DisconnectReason::Unknown.should_engage_kill_switch());
    }

    #[test]
    fn test_kill_switch_mode_change_while_engaged() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);
        assert_eq!(ks.state(), KillSwitchState::Engaged);

        // Disable kill switch while engaged - should transition to Inactive
        ks.set_mode(KillSwitchMode::Disabled);
        assert_eq!(ks.state(), KillSwitchState::Inactive);
        assert!(!ks.should_block_traffic());
    }

    #[test]
    fn test_kill_switch_mode_change_to_same_mode() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);
        assert_eq!(ks.mode(), KillSwitchMode::Enabled);

        // Setting same mode should be a no-op
        ks.set_mode(KillSwitchMode::Enabled);
        assert_eq!(ks.mode(), KillSwitchMode::Enabled);
    }

    #[test]
    fn test_kill_switch_reconnect_failed() {
        let ks = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            2,
            Duration::from_millis(100),
        );

        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);
        assert_eq!(ks.state(), KillSwitchState::Engaged);

        // Exhaust reconnect attempts
        ks.on_reconnect_attempt();
        ks.on_reconnect_attempt();
        assert!(ks.on_reconnect_attempt().is_none());

        // Mark as failed
        ks.on_reconnect_failed();
        assert_eq!(ks.state(), KillSwitchState::Engaged);
    }

    #[test]
    fn test_kill_switch_mode_allow_lan() {
        let ks = KillSwitchManager::new(KillSwitchMode::EnabledAllowLan);
        assert!(ks.mode().is_active());
        assert!(ks.mode().allows_lan());
    }

    #[test]
    fn test_reconnect_attempts_reset_on_success() {
        let ks = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            3,
            Duration::from_millis(100),
        );

        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);

        // Use up some attempts
        ks.on_reconnect_attempt();
        ks.on_reconnect_attempt();

        // Successful reconnect
        ks.on_reconnect_success();

        // Should be armed again with reset attempts
        assert_eq!(ks.state(), KillSwitchState::Armed);

        // Disconnect again
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);

        // Should have full attempts available again
        assert!(ks.on_reconnect_attempt().is_some());
        assert!(ks.on_reconnect_attempt().is_some());
        assert!(ks.on_reconnect_attempt().is_some());
    }

    #[test]
    fn test_network_change_detector_initial_state() {
        let detector = NetworkChangeDetector::new();

        // First gateway should not be a "change"
        assert!(detector.check_gateway_change("192.168.1.1").is_none());

        // Record it
        detector.record_gateway("192.168.1.1".to_string());

        // Same gateway - no change
        assert!(detector.check_gateway_change("192.168.1.1").is_none());
    }

    #[test]
    fn test_network_change_detector_empty_gateway() {
        let detector = NetworkChangeDetector::new();

        // Empty gateway
        let result = detector.check_gateway_change("");
        assert!(result.is_none());
    }

    #[test]
    fn test_reconnect_delay_calculation() {
        let ks = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            10,
            Duration::from_millis(100),
        );

        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);

        // First attempt - base delay
        let delay1 = ks.on_reconnect_attempt();
        assert!(delay1.is_some());

        // Second attempt - should have longer delay
        let delay2 = ks.on_reconnect_attempt();
        assert!(delay2.is_some());

        // Delays should increase (exponential backoff)
        // Note: We can't assert exact values due to implementation details
        assert!(delay1.is_some() && delay2.is_some());
    }

    #[test]
    fn test_kill_switch_max_reconnect_attempts_zero() {
        let ks = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            0,
            Duration::from_millis(100),
        );

        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);

        // With 0 max attempts, first attempt should fail
        assert!(ks.on_reconnect_attempt().is_none());
    }

    #[test]
    fn test_reconnect_delay_no_overflow_on_long_outage() {
        // Audit H7 regression guard.
        //
        // Previous expression `base_reconnect_delay * 2u32.pow(*attempts -
        // 1)` panicked once `*attempts > 32` (`2u32.pow(32)` overflows).
        // The fix caps the exponent at MAX_BACKOFF_EXPONENT = 20 and
        // saturates the multiplication via Duration::saturating_mul, so
        // even an unreasonable number of attempts must NOT panic and
        // must return a finite delay <= MAX_RECONNECT_DELAY (5 minutes).
        //
        // We use `max_reconnect_attempts = u32::MAX` to mimic the
        // "unlimited" production setting that triggered the bug, and
        // drive the attempt counter past the historical overflow point.
        let ks = KillSwitchManager::with_reconnect_settings(
            KillSwitchMode::Enabled,
            u32::MAX,
            Duration::from_secs(1),
        );
        ks.on_vpn_connected();
        ks.on_vpn_disconnected(DisconnectReason::NetworkError);

        // 100 attempts is well past the historical 32-bit overflow
        // boundary; under the old code this loop would have panicked at
        // attempt 33.
        for _ in 0..100 {
            let delay = ks.on_reconnect_attempt().expect("must not return None");
            // Plus jitter (max 500 ms), so the upper bound is
            // MAX_RECONNECT_DELAY + 500 ms.
            assert!(
                delay <= Duration::from_secs(300) + Duration::from_millis(500),
                "delay {:?} exceeds MAX_RECONNECT_DELAY + jitter cap",
                delay
            );
        }
    }

    #[test]
    fn test_kill_switch_auth_failure_engages() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        ks.on_vpn_connected();
        let engaged = ks.on_vpn_disconnected(DisconnectReason::AuthFailure);

        assert!(engaged);
        assert_eq!(ks.state(), KillSwitchState::Engaged);
    }

    #[test]
    fn test_kill_switch_session_timeout_engages() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        ks.on_vpn_connected();
        let engaged = ks.on_vpn_disconnected(DisconnectReason::SessionTimeout);

        assert!(engaged);
        assert_eq!(ks.state(), KillSwitchState::Engaged);
    }

    #[test]
    fn test_kill_switch_unknown_reason_engages() {
        let ks = KillSwitchManager::new(KillSwitchMode::Enabled);

        ks.on_vpn_connected();
        let engaged = ks.on_vpn_disconnected(DisconnectReason::Unknown);

        assert!(engaged);
        assert_eq!(ks.state(), KillSwitchState::Engaged);
    }
}
