//! HPN Relay server binary.
//!
//! A relay server for multi-hop VPN routing.

// `mimalloc` global allocator — see the matching block in
// `crates/hpn-server/src/main.rs` for the full rationale. Short version:
// the relay's data plane (per-handshake response buffers, tokio
// `Bytes::copy_from_slice` calls, dashmap entry allocations on session
// creation) is allocator-bound under high handshake-burst load, and
// mimalloc's per-thread arenas remove the glibc malloc serialisation
// for ~+15 % throughput at 256 handshakes/s.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use hpn_relay::{RelayConfig, RelayServer};

#[derive(Parser)]
#[command(name = "hpn-relay")]
#[command(about = "HPN VPN relay server for multi-hop routing")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the relay server.
    Run {
        /// Path to configuration file.
        #[arg(short, long, default_value = "/etc/hpn/relay.toml")]
        config: PathBuf,
        /// Log level (trace, debug, info, warn, error).
        #[arg(long, default_value = "info")]
        log_level: String,
    },
    /// Generate an example configuration file.
    GenConfig {
        /// Output path for the configuration file.
        #[arg(short, long, default_value = "relay.toml")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (logging_enabled, log_level, log_file_config) = resolve_relay_logging_config(&cli);
    let filter = if logging_enabled {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level))
    } else {
        EnvFilter::new("off")
    };

    if let Some((path, max_size_mb, max_files)) = log_file_config {
        match hpn_relay::log_file::RollingFileWriter::new(&path, max_size_mb, max_files) {
            Ok(file_writer) => {
                let stdout_layer = fmt::layer()
                    .with_target(false)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime);
                let file_layer = fmt::layer()
                    .with_target(false)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime)
                    .with_ansi(false)
                    .with_writer(file_writer);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(stdout_layer)
                    .with(file_layer)
                    .init();
            }
            Err(e) => {
                eprintln!(
                    "WARNING: Failed to open log file {}: {}. Stdout only.",
                    path, e
                );
                tracing_subscriber::registry()
                    .with(
                        fmt::layer()
                            .with_target(false)
                            .with_timer(tracing_subscriber::fmt::time::SystemTime),
                    )
                    .with(filter)
                    .init();
            }
        }
    } else {
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_target(false)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime),
            )
            .with(filter)
            .init();
    };

    match cli.command {
        Commands::Run { config, .. } => {
            run_relay(config).await;
        }
        Commands::GenConfig { output } => {
            gen_config(output);
        }
    }
}

/// Returns (`log_enabled`, `log_level`, `log_file_config`).
fn resolve_relay_logging_config(cli: &Cli) -> (bool, String, Option<(String, u64, u32)>) {
    match &cli.command {
        Commands::Run { config, log_level } => match RelayConfig::load_from_file(config) {
            Ok(c) => {
                let file_config = c
                    .log_file
                    .as_ref()
                    .map(|p| (p.clone(), c.log_max_size_mb, c.log_max_files));
                (c.log_enabled, log_level.clone(), file_config)
            }
            Err(_) => (true, log_level.clone(), None),
        },
        Commands::GenConfig { .. } => (true, "info".to_string(), None),
    }
}

async fn run_relay(config_path: PathBuf) {
    info!("Loading configuration from {:?}", config_path);

    let config = match RelayConfig::load_from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    info!(
        "Relay configuration: listen={}, upstream={}",
        config.listen_addr, config.upstream_addr
    );

    // Create shared shutdown flag (atomic for lock-free checking)
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = Arc::clone(&shutdown);

    let mut relay = match RelayServer::with_shutdown(config, shutdown) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create relay server: {}", e);
            std::process::exit(1);
        }
    };

    // Handle shutdown signals
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(
                "Failed to install CTRL+C handler: {}. Graceful shutdown may not work.",
                e
            );
            return;
        }
        info!("Received shutdown signal");
        shutdown_signal.store(true, Ordering::SeqCst);
    });

    if let Err(e) = relay.run().await {
        error!("Relay server error: {}", e);
        std::process::exit(1);
    }
}

fn gen_config(output: PathBuf) {
    // SAFETY: All address strings are compile-time constants that are valid
    let config = RelayConfig {
        listen_addr: "0.0.0.0:51821".parse().expect("valid listen address"),
        upstream_addr: "198.51.100.1:51820"
            .parse()
            .expect("valid upstream address"),
        max_sessions: 10000,
        session_timeout_secs: 180,
        buffer_size: 65535,
        log_enabled: true,
        log_file: None,
        log_max_size_mb: 100,
        log_max_files: 5,
        enable_stats: true,
        stats_interval_secs: 60,
        relay_id: Some("relay-1".into()),
        rate_limit_pps: None,
        rate_limit_bps: None,
        max_concurrent_handshakes: Some(256),
        handshake_rate_limit_pps: Some(64),
        handshake_global_rate_limit_pps: Some(256),
        enable_metrics: true,
        metrics_addr: "127.0.0.1:9101".parse().expect("valid metrics address"),
        metrics_auth_token: None,
        no_log: true,
        license_key: None,
    };

    match config.save_to_file(&output) {
        Ok(()) => {
            info!("Generated example configuration at {:?}", output);
        }
        Err(e) => {
            error!("Failed to write configuration: {}", e);
            std::process::exit(1);
        }
    }
}
