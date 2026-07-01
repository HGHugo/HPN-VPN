//! macOS power management integration for sleep/wake handling.
//!
//! Monitors system power state to properly handle VPN connection during:
//! - Sleep: Pause keepalives, prepare for network loss
//! - Wake: Immediate reconnection, resume keepalives
//!
//! Uses IOKit's IOPMLib for power notifications via CFRunLoop.

// Allow unsafe code for IOKit FFI bindings - required for power management
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, error, info, warn};

// IOKit power management FFI bindings
// These are from <IOKit/pwr_mgt/IOPMLib.h> which is not in io-kit-sys
#[allow(non_camel_case_types)]
mod ffi {
    use std::ffi::c_void;

    // IOKit types - use Apple's naming convention
    pub type io_connect_t = u32;
    pub type io_object_t = u32;
    pub type IOReturn = i32;

    // Mach types (not currently used but kept for reference)
    #[allow(dead_code)]
    pub type mach_port_t = u32;
    #[allow(dead_code)]
    pub type natural_t = u32;

    // CoreFoundation types
    #[repr(C)]
    pub struct __CFRunLoop(c_void);
    pub type CFRunLoopRef = *mut __CFRunLoop;

    #[repr(C)]
    pub struct __CFRunLoopSource(c_void);
    pub type CFRunLoopSourceRef = *mut __CFRunLoopSource;

    #[repr(C)]
    pub struct __CFString(c_void);
    pub type CFStringRef = *const __CFString;

    // IONotificationPort (opaque)
    #[repr(C)]
    pub struct IONotificationPort(c_void);
    pub type IONotificationPortRef = *mut IONotificationPort;

    // Power management message types from IOMessage.h
    pub const K_IO_MESSAGE_CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
    pub const K_IO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
    pub const K_IO_MESSAGE_SYSTEM_WILL_POWER_ON: u32 = 0xE000_0500;
    pub const K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON: u32 = 0xE000_0300;

    // Callback type for IORegisterForSystemPower
    pub type IOServiceInterestCallback = unsafe extern "C" fn(
        refcon: *mut c_void,
        service: io_object_t,
        message_type: u32,
        message_argument: *mut c_void,
    );

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        /// Register for system power notifications.
        /// Returns an io_connect_t for IODeregisterForSystemPower.
        pub fn IORegisterForSystemPower(
            refcon: *mut c_void,
            notify_port_ref: *mut IONotificationPortRef,
            callback: IOServiceInterestCallback,
            notifier: *mut io_object_t,
        ) -> io_connect_t;

        /// Deregister from system power notifications.
        pub fn IODeregisterForSystemPower(notifier: *mut io_object_t) -> IOReturn;

        /// Acknowledge a power change notification.
        pub fn IOAllowPowerChange(kernelPort: io_connect_t, notification_id: isize) -> IOReturn;

        /// Get run loop source from notification port.
        pub fn IONotificationPortGetRunLoopSource(
            notify: IONotificationPortRef,
        ) -> CFRunLoopSourceRef;

        /// Destroy notification port.
        pub fn IONotificationPortDestroy(notify: IONotificationPortRef);

        /// Release IOKit object.
        pub fn IOObjectRelease(object: io_object_t) -> IOReturn;

        /// Service close.
        pub fn IOServiceClose(connect: io_connect_t) -> IOReturn;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        /// Get the current thread's run loop.
        pub fn CFRunLoopGetCurrent() -> CFRunLoopRef;

        /// Add a source to the run loop.
        pub fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);

        /// Remove a source from the run loop.
        pub fn CFRunLoopRemoveSource(
            rl: CFRunLoopRef,
            source: CFRunLoopSourceRef,
            mode: CFStringRef,
        );

        /// Run the run loop with a timeout.
        /// Returns reason for returning (timeout, stopped, etc.)
        pub fn CFRunLoopRunInMode(
            mode: CFStringRef,
            seconds: f64,
            return_after_source_handled: bool,
        ) -> i32;

        /// Common run loop modes.
        pub static kCFRunLoopCommonModes: CFStringRef;
        pub static kCFRunLoopDefaultMode: CFStringRef;
    }
}

/// Power state change callback.
pub type PowerCallback = Arc<dyn Fn(PowerEvent) + Send + Sync>;

/// Power management events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerEvent {
    /// System is about to sleep.
    WillSleep,
    /// System has woken from sleep.
    DidWake,
}

/// Context passed to the IOKit callback.
struct PowerContext {
    callback: PowerCallback,
    root_port: ffi::io_connect_t,
}

/// Power manager for handling sleep/wake events.
pub struct PowerManager {
    /// Whether the manager is running.
    running: Arc<AtomicBool>,
}

impl PowerManager {
    /// Create a new power manager.
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start monitoring power events.
    ///
    /// The callback will be invoked on sleep/wake events.
    /// Returns immediately after starting background monitoring.
    ///
    /// # Errors
    ///
    /// Returns an error if the monitoring thread fails to spawn.
    pub fn start<F>(&self, callback: F) -> Result<(), std::io::Error>
    where
        F: Fn(PowerEvent) + Send + Sync + 'static,
    {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Power manager already running");
            return Ok(());
        }

        // Convert to trait object Arc
        let callback: PowerCallback = Arc::new(callback);
        let running = Arc::clone(&self.running);
        let running_on_error = Arc::clone(&self.running);

        std::thread::Builder::new()
            .name("power-monitor".into())
            .spawn(move || {
                info!("Power monitoring thread started");

                // Safety: All IOKit calls are properly paired (register/deregister, etc.)
                // and we handle cleanup on all exit paths.
                unsafe {
                    let mut notify_port: ffi::IONotificationPortRef = std::ptr::null_mut();
                    let mut notifier: ffi::io_object_t = 0;

                    // Create context with callback
                    let context = Box::new(PowerContext {
                        callback: Arc::clone(&callback),
                        root_port: 0, // Will be set after registration
                    });
                    let context_ptr = Box::into_raw(context);

                    // Register for power notifications
                    let root_port = ffi::IORegisterForSystemPower(
                        context_ptr.cast::<c_void>(),
                        std::ptr::addr_of_mut!(notify_port),
                        power_callback,
                        std::ptr::addr_of_mut!(notifier),
                    );

                    if root_port == 0 {
                        error!("IORegisterForSystemPower failed");
                        let _ = Box::from_raw(context_ptr);
                        running.store(false, Ordering::SeqCst);
                        return;
                    }

                    // Update context with root_port for IOAllowPowerChange
                    (*context_ptr).root_port = root_port;

                    debug!(
                        "Registered for power notifications, root_port={}, notifier={}",
                        root_port, notifier
                    );

                    // Get run loop source from notification port
                    let run_loop_source = ffi::IONotificationPortGetRunLoopSource(notify_port);
                    if run_loop_source.is_null() {
                        error!("IONotificationPortGetRunLoopSource failed");
                        ffi::IODeregisterForSystemPower(std::ptr::addr_of_mut!(notifier));
                        ffi::IOServiceClose(root_port);
                        ffi::IONotificationPortDestroy(notify_port);
                        let _ = Box::from_raw(context_ptr);
                        running.store(false, Ordering::SeqCst);
                        return;
                    }

                    // Get current run loop
                    let current_run_loop = ffi::CFRunLoopGetCurrent();

                    // Add source to run loop
                    ffi::CFRunLoopAddSource(
                        current_run_loop,
                        run_loop_source,
                        ffi::kCFRunLoopCommonModes,
                    );

                    info!("Power monitoring active via CFRunLoop");

                    // Run the run loop until stopped
                    // Use CFRunLoopRunInMode with timeout so we can check the running flag
                    while running.load(Ordering::Relaxed) {
                        // Run for 0.5 seconds then check if we should stop
                        ffi::CFRunLoopRunInMode(ffi::kCFRunLoopDefaultMode, 0.5, false);
                    }

                    info!("Power monitoring stopping, cleaning up...");

                    // Cleanup
                    ffi::CFRunLoopRemoveSource(
                        current_run_loop,
                        run_loop_source,
                        ffi::kCFRunLoopCommonModes,
                    );
                    ffi::IODeregisterForSystemPower(std::ptr::addr_of_mut!(notifier));
                    ffi::IOServiceClose(root_port);
                    ffi::IONotificationPortDestroy(notify_port);
                    ffi::IOObjectRelease(notifier);

                    // Free context
                    let _ = Box::from_raw(context_ptr);
                }

                info!("Power monitoring thread stopped");
            })
            .inspect_err(|_| {
                running_on_error.store(false, Ordering::SeqCst);
            })?;

        Ok(())
    }

    /// Stop monitoring power events.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        // The thread will exit on next CFRunLoopRunInMode timeout
    }

    /// Check if monitoring is active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PowerManager {
    fn drop(&mut self) {
        self.stop();
    }
}

/// IOKit power notification callback.
///
/// # Safety
/// Called by IOKit framework, must handle all message types gracefully.
unsafe extern "C" fn power_callback(
    refcon: *mut c_void,
    _service: ffi::io_object_t,
    message_type: u32,
    message_argument: *mut c_void,
) {
    if refcon.is_null() {
        return;
    }

    // SAFETY: refcon is a valid pointer to PowerContext created in PowerMonitor::new
    let context = unsafe { &*(refcon as *const PowerContext) };

    match message_type {
        ffi::K_IO_MESSAGE_CAN_SYSTEM_SLEEP => {
            // System is asking if we can sleep (idle sleep).
            // We always allow it and prepare for sleep.
            debug!("Power: kIOMessageCanSystemSleep - allowing idle sleep");
            // SAFETY: context.root_port is valid IOKit port
            unsafe { ffi::IOAllowPowerChange(context.root_port, message_argument as isize) };
        }
        ffi::K_IO_MESSAGE_SYSTEM_WILL_SLEEP => {
            // System is definitely going to sleep.
            // This is our chance to prepare (close connections, etc.)
            info!("Power: kIOMessageSystemWillSleep - system sleeping");
            (context.callback)(PowerEvent::WillSleep);

            // Must acknowledge to allow sleep to proceed
            // SAFETY: context.root_port is valid IOKit port
            unsafe { ffi::IOAllowPowerChange(context.root_port, message_argument as isize) };
        }
        ffi::K_IO_MESSAGE_SYSTEM_WILL_POWER_ON => {
            // System is beginning to power on (hardware waking).
            // Too early to do network operations.
            debug!("Power: kIOMessageSystemWillPowerOn - hardware waking");
        }
        ffi::K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON => {
            // System has fully woken up. Safe to reconnect.
            info!("Power: kIOMessageSystemHasPoweredOn - system awake");
            (context.callback)(PowerEvent::DidWake);
        }
        _ => {
            debug!("Power: unknown message type 0x{:08X}", message_type);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_manager_creation() {
        let pm = PowerManager::new();
        assert!(!pm.is_running());
    }

    #[test]
    fn test_power_manager_start_stop() {
        let pm = PowerManager::new();
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&events);

        pm.start(move |event| {
            events_clone.lock().unwrap().push(event);
        })
        .expect("failed to start power manager");

        // Give the thread time to start
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(pm.is_running());

        pm.stop();
        // Wait for thread to exit (max 1 second due to 0.5s run loop timeout)
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(!pm.is_running());
    }

    #[test]
    fn test_power_event_equality() {
        assert_eq!(PowerEvent::WillSleep, PowerEvent::WillSleep);
        assert_eq!(PowerEvent::DidWake, PowerEvent::DidWake);
        assert_ne!(PowerEvent::WillSleep, PowerEvent::DidWake);
    }

    #[test]
    fn test_double_start() {
        let pm = PowerManager::new();

        let _ = pm.start(|_| {});
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Second start should be no-op
        let _ = pm.start(|_| {});
        assert!(pm.is_running());

        pm.stop();
    }

    #[test]
    fn test_double_stop() {
        let pm = PowerManager::new();

        let _ = pm.start(|_| {});
        std::thread::sleep(std::time::Duration::from_millis(100));

        pm.stop();
        pm.stop(); // Should be safe
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(!pm.is_running());
    }
}
