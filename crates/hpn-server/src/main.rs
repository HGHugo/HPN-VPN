//! HPN Server entry point.
//!
//! Linux server for the HPN post-quantum VPN.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::uninlined_format_args)]

// `mimalloc` as the global allocator on Linux/macOS. Default glibc/macOS
// malloc serialises through a single arena lock under our multi-threaded
// data plane (one allocator call per `Bytes::copy_from_slice` for control
// messages, per `Vec` reused across the AF_XDP fallback, per session
// rate-limit token snapshot, etc.). mimalloc's per-thread arenas remove
// that contention; measurements on the production server show
// +10-25 % steady-state throughput at 50 K active sessions vs. baseline.
//
// Scoped to platforms that ship a relevant binary so a developer
// cross-compile build on Windows (which is not a supported deployment
// target for this binary anyway) does not pull in the C compiler that
// `mimalloc-sys` requires on MSVC. The `default-features = false` in
// `Cargo.toml` keeps mimalloc from monkey-patching the system malloc;
// only this `#[global_allocator]` opt-in routes Rust allocations
// through it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use hpn_core::crypto::MlDsaKeypair;
#[cfg(unix)]
use hpn_server::PrivilegeDropper;
use hpn_server::{ServerConfig, UserStore, VpnServer};

/// HPN VPN Server
#[derive(Parser)]
#[command(name = "hpn-server")]
#[command(about = "Post-quantum VPN server")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/hpn/server.toml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new server keypair
    Genkey {
        /// Output file for the keypair (TOML format)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show the server's public key
    Pubkey {
        /// Keypair file to read from
        #[arg(short, long)]
        keyfile: PathBuf,
    },
    /// User management commands
    User {
        #[command(subcommand)]
        command: UserCommands,
    },
    /// Export a client profile (.hpn file)
    ExportProfile {
        /// Server address (hostname or IP)
        #[arg(short, long)]
        server: String,
        /// Server port
        #[arg(short, long, default_value = "51820")]
        port: u16,
        /// Profile name
        #[arg(short, long)]
        name: String,
        /// Require authentication for this profile
        #[arg(long)]
        requires_auth: bool,
        /// Security level (standard or high)
        #[arg(long, default_value = "standard")]
        level: String,
        /// Keypair file to read public keys from
        #[arg(short, long)]
        keyfile: PathBuf,
        /// Output file (default: <name>.hpn)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run the VPN server
    Run,
}

#[derive(Subcommand)]
enum UserCommands {
    /// Add a new user
    Add {
        /// Username
        username: String,
        /// Password (if not provided, will prompt securely)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Remove a user
    Remove {
        /// Username to remove
        username: String,
    },
    /// List all users
    List,
    /// Disable a user (prevent login)
    Disable {
        /// Username to disable
        username: String,
    },
    /// Enable a user (allow login)
    Enable {
        /// Username to enable
        username: String,
    },
    /// Change a user's password
    Passwd {
        /// Username
        username: String,
        /// New password (if not provided, will prompt securely)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Unlock a user (reset failed login attempts)
    Unlock {
        /// Username to unlock
        username: String,
    },
}

#[derive(Debug, Deserialize)]
struct ServerConfigWrapper {
    server: ServerConfig,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging (supports config-level no-logs mode for server runtime).
    let (logging_enabled, no_log, log_file_config) = resolve_server_logging_config(&cli);
    let filter = if logging_enabled {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level))
    } else {
        EnvFilter::new("off")
    };

    // Set up tracing with optional file output
    if let Some((path, max_size_mb, max_files)) = log_file_config {
        match hpn_server::log_file::RollingFileWriter::new(&path, max_size_mb, max_files) {
            Ok(file_writer) => {
                use tracing_subscriber::layer::SubscriberExt;
                use tracing_subscriber::util::SubscriberInitExt;
                // Dual output: stdout + file
                let stdout_layer = fmt::layer()
                    .with_target(false)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime);
                let file_layer = fmt::layer()
                    .with_target(false)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime)
                    .with_ansi(false) // No ANSI colors in file
                    .with_writer(file_writer);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(stdout_layer)
                    .with(file_layer)
                    .init();
                eprintln!("Logging to stdout + {}", path);
            }
            Err(e) => {
                // Fall back to stdout-only
                eprintln!(
                    "WARNING: Failed to open log file {}: {}. Using stdout only.",
                    path, e
                );
                fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime)
                    .init();
            }
        }
    } else {
        fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_timer(tracing_subscriber::fmt::time::SystemTime)
            .init();
    }

    // Initialize privacy/no-log IP redaction
    hpn_server::privacy::init(no_log);

    let result = match cli.command {
        Some(Commands::Genkey { output }) => generate_keypair(output),
        Some(Commands::Pubkey { keyfile }) => show_pubkey(keyfile),
        Some(Commands::User { command }) => handle_user_command(command, &cli.config),
        Some(Commands::ExportProfile {
            server,
            port,
            name,
            requires_auth,
            level,
            keyfile,
            output,
        }) => export_profile(
            &server,
            port,
            &name,
            requires_auth,
            &level,
            &keyfile,
            output,
        ),
        Some(Commands::Run) | None => run_server(&cli.config),
    };

    if let Err(e) = result {
        error!("Fatal error: {}", e);
        process::exit(1);
    }
}

/// Resolve logging and no-log settings from the config file before full init.
/// Returns (`log_enabled`, `no_log`, `log_file_config`).
/// `log_file_config` is `Some((path, max_size_mb, max_files))` if file logging is configured.
fn resolve_server_logging_config(cli: &Cli) -> (bool, bool, Option<(String, u64, u32)>) {
    if !matches!(cli.command, Some(Commands::Run) | None) {
        return (true, false, None);
    }

    let Ok(content) = std::fs::read_to_string(&cli.config) else {
        return (true, false, None);
    };

    let extract = |config: &ServerConfig| {
        let log_file = config
            .log_file
            .as_ref()
            .map(|p| (p.clone(), config.log_max_size_mb, config.log_max_files));
        (config.log_enabled, config.no_log, log_file)
    };

    if let Ok(config) = toml::from_str::<ServerConfig>(&content) {
        return extract(&config);
    }

    if let Ok(wrapper) = toml::from_str::<ServerConfigWrapper>(&content) {
        return extract(&wrapper.server);
    }

    (true, false, None)
}

fn write_secret_file_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output path has no file name",
        )
    })?;

    let tmp_path = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        process::id()
    ));

    let write_result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);

        let mut tmp_file = options.open(&tmp_path)?;
        tmp_file.write_all(content.as_bytes())?;
        tmp_file.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    write_result
}

/// Generate server keypairs for both security levels.
///
/// Generates keypairs for:
/// - Signing: ML-DSA-65 (Level 3) and ML-DSA-87 (Level 5)
/// - Identity Hiding (KEM): Hybrid X25519+ML-KEM (Level 3 and Level 5)
fn generate_keypair(output: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hpn_core::crypto::{HybridKem, SecurityLevel};

    info!("Generating server keypairs for both security levels...");

    // Generate Level 3 signing keypair (ML-DSA-65)
    info!("  Generating ML-DSA-65 signing keypair (Level 3 / Standard)...");
    let keypair_l3 = MlDsaKeypair::generate_with_level(SecurityLevel::Level3);
    let secret_l3_b64 = STANDARD.encode(keypair_l3.secret_key.as_bytes());
    let public_l3_b64 = STANDARD.encode(keypair_l3.public_key.as_bytes());

    // Generate Level 5 signing keypair (ML-DSA-87)
    info!("  Generating ML-DSA-87 signing keypair (Level 5 / High)...");
    let keypair_l5 = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
    let secret_l5_b64 = STANDARD.encode(keypair_l5.secret_key.as_bytes());
    let public_l5_b64 = STANDARD.encode(keypair_l5.public_key.as_bytes());

    // Generate Level 3 KEM keypair for identity hiding (X25519 + ML-KEM-768)
    info!("  Generating hybrid KEM keypair (Level 3 / Standard) for identity hiding...");
    let (kem_secret_key_l3, kem_public_key_l3) =
        HybridKem::generate_keypair_with_level(SecurityLevel::Level3)?;
    let kem_secret_l3_b64 = STANDARD.encode(kem_secret_key_l3.to_bytes());
    let kem_public_l3_b64 = STANDARD.encode(kem_public_key_l3.to_bytes());

    // Generate Level 5 KEM keypair for identity hiding (X25519 + ML-KEM-1024)
    info!("  Generating hybrid KEM keypair (Level 5 / High) for identity hiding...");
    let (kem_secret_key_l5, kem_public_key_l5) =
        HybridKem::generate_keypair_with_level(SecurityLevel::Level5)?;
    let kem_secret_l5_b64 = STANDARD.encode(kem_secret_key_l5.to_bytes());
    let kem_public_l5_b64 = STANDARD.encode(kem_public_key_l5.to_bytes());

    let content = format!(
        "\
# HPN Server Keypairs
# Generated by hpn-server genkey
# KEEP THE SECRET KEYS SECURE!
#
# Four keypairs are generated:
# - Signing (ML-DSA): For authenticating the server in handshakes
# - KEM: For identity hiding (encrypting client's ephemeral public key)
#
# Clients need both public keys for full identity hiding support.

# Level 3 / Standard security (ML-DSA-65 + ML-KEM-768, ~AES-192 equivalent)
[keypair_level3]
secret_key = \"{secret_l3_b64}\"
public_key = \"{public_l3_b64}\"

[kem_keypair_level3]
secret_key = \"{kem_secret_l3_b64}\"
public_key = \"{kem_public_l3_b64}\"

# Level 5 / High security (ML-DSA-87 + ML-KEM-1024, ~AES-256 equivalent)
[keypair_level5]
secret_key = \"{secret_l5_b64}\"
public_key = \"{public_l5_b64}\"

[kem_keypair_level5]
secret_key = \"{kem_secret_l5_b64}\"
public_key = \"{kem_public_l5_b64}\"
"
    );

    if let Some(path) = output {
        write_secret_file_atomic(&path, &content)?;
        info!("Keypairs written to {}", path.display());

        // Print public keys for convenience
        println!("\n=== Server Public Keys (share with clients) ===\n");
        println!("Standard security (Level 3):");
        println!("  Signing (ML-DSA-65):  {}", public_l3_b64);
        println!("  KEM (ML-KEM-768):     {}\n", kem_public_l3_b64);
        println!("High security (Level 5):");
        println!("  Signing (ML-DSA-87):  {}", public_l5_b64);
        println!("  KEM (ML-KEM-1024):    {}", kem_public_l5_b64);
    } else {
        // Print to stdout
        println!("{}", content);
        println!("\n# Public keys for clients:");
        println!("# Standard (Level 3) Signing: {}", public_l3_b64);
        println!("# Standard (Level 3) KEM:     {}", kem_public_l3_b64);
        println!("# High (Level 5) Signing:     {}", public_l5_b64);
        println!("# High (Level 5) KEM:         {}", kem_public_l5_b64);
    }

    Ok(())
}

/// Show the server's public keys from a keypair file.
fn show_pubkey(keyfile: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::Deserialize;

    // Support both old (single keypair) and new (dual keypair) formats
    #[derive(Deserialize)]
    struct KeypairFile {
        // Old format (single keypair)
        keypair: Option<KeypairSection>,
        // New format (dual keypairs)
        keypair_level3: Option<KeypairSection>,
        keypair_level5: Option<KeypairSection>,
        // KEM keypairs for identity hiding
        kem_keypair_level3: Option<KeypairSection>,
        kem_keypair_level5: Option<KeypairSection>,
    }

    #[derive(Deserialize)]
    struct KeypairSection {
        public_key: String,
        #[allow(dead_code)]
        secret_key: String,
    }

    let content = std::fs::read_to_string(&keyfile)?;
    let kf: KeypairFile = toml::from_str(&content)?;

    // Check for new dual-keypair format first
    if let (Some(l3), Some(l5)) = (&kf.keypair_level3, &kf.keypair_level5) {
        // Validate Level 3 key
        let pk_l3_bytes = STANDARD.decode(&l3.public_key)?;
        if pk_l3_bytes.len() != hpn_core::crypto::MlDsaPublicKey::SIZE {
            return Err(format!(
                "Invalid Level 3 public key size: expected {}, got {}",
                hpn_core::crypto::MlDsaPublicKey::SIZE,
                pk_l3_bytes.len()
            )
            .into());
        }

        // Validate Level 5 key
        let pk_l5_bytes = STANDARD.decode(&l5.public_key)?;
        if pk_l5_bytes.len() != hpn_core::crypto::MlDsaPublicKey::SIZE_87 {
            return Err(format!(
                "Invalid Level 5 public key size: expected {}, got {}",
                hpn_core::crypto::MlDsaPublicKey::SIZE_87,
                pk_l5_bytes.len()
            )
            .into());
        }

        println!("\n=== Server Public Keys (share with clients) ===\n");
        println!("Standard security (Level 3):");
        println!("  Signing (ML-DSA-65):  {}", l3.public_key);
        if let Some(kem_l3) = &kf.kem_keypair_level3 {
            println!("  KEM (ML-KEM-768):     {}", kem_l3.public_key);
        } else {
            println!("  KEM (ML-KEM-768):     (not configured)");
        }
        println!();
        println!("High security (Level 5):");
        println!("  Signing (ML-DSA-87):  {}", l5.public_key);
        if let Some(kem_l5) = &kf.kem_keypair_level5 {
            println!("  KEM (ML-KEM-1024):    {}", kem_l5.public_key);
        } else {
            println!("  KEM (ML-KEM-1024):    (not configured)");
        }
        println!();
        println!("Client configuration:");
        println!("  \"Server Public Key\"     = Signing key (ML-DSA) for your security level");
        println!("  \"Server KEM Public Key\" = KEM key (optional, enables identity hiding)");
    } else if let Some(kp) = &kf.keypair {
        // Old single-keypair format
        let pk_bytes = STANDARD.decode(&kp.public_key)?;
        if pk_bytes.len() != hpn_core::crypto::MlDsaPublicKey::SIZE {
            return Err(format!(
                "Invalid public key size: expected {}, got {}",
                hpn_core::crypto::MlDsaPublicKey::SIZE,
                pk_bytes.len()
            )
            .into());
        }
        println!("{}", kp.public_key);
        eprintln!(
            "WARNING: Legacy single-keypair format. Regenerate with 'hpn-server genkey' for dual-level + identity hiding support."
        );
    } else {
        return Err("No keypair found in file".into());
    }

    Ok(())
}

/// Partial config for reading just the `users_db_path`.
#[derive(serde::Deserialize)]
struct UserDbConfig {
    server: UserDbServerConfig,
}

#[derive(serde::Deserialize)]
struct UserDbServerConfig {
    #[serde(alias = "user_db_path")]
    users_db_path: Option<PathBuf>,
}

/// Prompt for password with confirmation, or use provided password.
fn get_password_with_confirm(
    password: Option<String>,
    prompt: &str,
    confirm_prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(p) = password {
        return Ok(p);
    }
    let pass1 = rpassword::prompt_password(prompt)?;
    let pass2 = rpassword::prompt_password(confirm_prompt)?;
    if pass1 != pass2 {
        return Err("Passwords do not match".into());
    }
    Ok(pass1)
}

/// Handle user management commands.
fn handle_user_command(
    command: UserCommands,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = load_user_db_path_from_config(config_path)?;
    let store = UserStore::open(&db_path)?;

    match command {
        UserCommands::Add { username, password } => {
            let password =
                get_password_with_confirm(password, "Enter password: ", "Confirm password: ")?;
            store.add_user(&username, &password)?;
            println!("User '{}' added successfully", username);
        }
        UserCommands::Remove { username } => {
            if store.remove_user(&username)? {
                println!("User '{}' removed", username);
            } else {
                println!("User '{}' not found", username);
            }
        }
        UserCommands::List => {
            print_user_list(&store)?;
        }
        UserCommands::Disable { username } => {
            if store.set_enabled(&username, false)? {
                println!("User '{}' disabled", username);
            } else {
                println!("User '{}' not found", username);
            }
        }
        UserCommands::Enable { username } => {
            if store.set_enabled(&username, true)? {
                println!("User '{}' enabled", username);
            } else {
                println!("User '{}' not found", username);
            }
        }
        UserCommands::Passwd { username, password } => {
            if store.get_user(&username)?.is_none() {
                return Err(format!("User '{}' not found", username).into());
            }
            let password = get_password_with_confirm(
                password,
                "Enter new password: ",
                "Confirm new password: ",
            )?;
            store.change_password(&username, &password)?;
            println!("Password changed for user '{}'", username);
        }
        UserCommands::Unlock { username } => {
            if store.reset_failed_attempts(&username)? {
                println!("User '{}' unlocked (failed attempts reset)", username);
            } else {
                println!("User '{}' not found", username);
            }
        }
    }
    Ok(())
}

fn parse_user_db_path_from_content(content: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let config: UserDbConfig = toml::from_str(content)?;
    Ok(config
        .server
        .users_db_path
        .unwrap_or_else(|| PathBuf::from(ServerConfig::DEFAULT_USERS_DB_PATH)))
}

fn load_user_db_path_from_config(
    config_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(config_path)?;
    parse_user_db_path_from_content(&content)
}

/// Print the list of users in a formatted table.
fn print_user_list(store: &UserStore) -> Result<(), Box<dyn std::error::Error>> {
    let users = store.list_users()?;
    if users.is_empty() {
        println!("No users configured");
    } else {
        println!(
            "{:<20} {:<10} {:<20} {:<8} {:<20}",
            "Username", "Status", "Last Login", "Failed", "Locked Until"
        );
        println!("{}", "-".repeat(84));
        for user in users {
            let status = if user.enabled { "enabled" } else { "disabled" };
            let last_login = user
                .last_login
                .map_or_else(|| "never".to_string(), chrono_format_timestamp);
            let locked_until = user
                .locked_until
                .map_or_else(|| "-".to_string(), chrono_format_timestamp);
            println!(
                "{:<20} {:<10} {:<20} {:<8} {:<20}",
                user.username, status, last_login, user.failed_attempts, locked_until
            );
        }
    }
    Ok(())
}

/// Format a Unix timestamp as a human-readable string.
fn chrono_format_timestamp(ts: i64) -> String {
    use std::time::UNIX_EPOCH;
    // Simple formatting without chrono dependency
    #[allow(clippy::cast_possible_wrap)]
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let diff = now - ts;

    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{} min ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
}

/// Keypair file structure for profile export.
#[derive(serde::Deserialize)]
struct KeypairFile {
    keypair_level3: Option<KeypairSection>,
    keypair_level5: Option<KeypairSection>,
    kem_keypair_level3: Option<KeypairSection>,
    kem_keypair_level5: Option<KeypairSection>,
}

/// Individual keypair section in the keypair file.
#[derive(serde::Deserialize)]
struct KeypairSection {
    public_key: String,
    #[allow(dead_code)]
    secret_key: String,
}

/// Export a client profile to a .hpn file.
#[allow(clippy::too_many_arguments)]
fn export_profile(
    server: &str,
    port: u16,
    name: &str,
    requires_auth: bool,
    level: &str,
    keyfile: &PathBuf,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate security level
    let security_level = match level.to_lowercase().as_str() {
        "standard" | "level3" | "3" => "standard",
        "high" | "level5" | "5" => "high",
        _ => {
            return Err(format!(
                "Invalid security level: {}. Use 'standard' or 'high'",
                level
            )
            .into());
        }
    };

    // Load keypair file to get public keys
    let content = std::fs::read_to_string(keyfile)?;
    let kf: KeypairFile = toml::from_str(&content)?;

    // Get the appropriate keys based on security level
    let (server_public_key, server_kem_public_key) = if security_level == "standard" {
        let signing_pk = kf
            .keypair_level3
            .as_ref()
            .ok_or("keypair_level3 not found in keyfile")?
            .public_key
            .clone();
        let kem_pk = kf.kem_keypair_level3.as_ref().map(|k| k.public_key.clone());
        (signing_pk, kem_pk)
    } else {
        let signing_pk = kf
            .keypair_level5
            .as_ref()
            .ok_or("keypair_level5 not found in keyfile")?
            .public_key
            .clone();
        let kem_pk = kf.kem_keypair_level5.as_ref().map(|k| k.public_key.clone());
        (signing_pk, kem_pk)
    };

    // Build the profile JSON
    let profile = serde_json::json!({
        "version": 1,
        "profile": {
            "name": name,
            "server": server,
            "port": port,
            "serverPublicKey": server_public_key,
            "serverKemPublicKey": server_kem_public_key,
            "securityLevel": security_level,
            "requiresAuth": requires_auth,
            "splitTunnel": null
        }
    });

    let json = serde_json::to_string_pretty(&profile)?;

    // Determine output path
    let output_path = output.unwrap_or_else(|| {
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        PathBuf::from(format!("{}.hpn", safe_name))
    });

    std::fs::write(&output_path, &json)?;

    println!("Profile exported to: {}", output_path.display());
    println!();
    println!("Profile details:");
    println!("  Name:           {}", name);
    println!("  Server:         {}:{}", server, port);
    println!("  Security Level: {}", security_level);
    println!("  Requires Auth:  {}", requires_auth);
    println!(
        "  Identity Hiding: {}",
        if server_kem_public_key.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    );

    Ok(())
}

/// Run the VPN server.
#[allow(clippy::too_many_lines)]
fn run_server(config_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hpn_core::crypto::{HybridPublicKey, HybridSecretKey, SecurityLevel};
    use serde::Deserialize;

    // Support both old (single keypair) and new (dual keypair) config formats
    #[derive(Deserialize)]
    struct FullConfig {
        server: ServerConfig,
        // Old format (single keypair) - for backward compatibility
        keypair: Option<KeypairSection>,
        // New format (dual signing keypairs)
        keypair_level3: Option<KeypairSection>,
        keypair_level5: Option<KeypairSection>,
        // KEM keypairs for identity hiding (optional)
        kem_keypair_level3: Option<KeypairSection>,
        kem_keypair_level5: Option<KeypairSection>,
    }

    #[derive(Deserialize)]
    struct KeypairSection {
        secret_key: String,
        public_key: String,
    }

    /// Load a KEM keypair from config section.
    fn load_kem_keypair(
        section: &KeypairSection,
        level: SecurityLevel,
    ) -> Result<(HybridSecretKey, HybridPublicKey), Box<dyn std::error::Error>> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let sk_bytes = STANDARD.decode(&section.secret_key)?;
        let pk_bytes = STANDARD.decode(&section.public_key)?;

        let secret_key = HybridSecretKey::from_bytes(&sk_bytes)
            .map_err(|e| format!("Invalid KEM secret key for {:?}: {:?}", level, e))?;
        let public_key = HybridPublicKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("Invalid KEM public key for {:?}: {:?}", level, e))?;

        Ok((secret_key, public_key))
    }

    info!("Loading configuration from {}", config_path.display());

    let content = std::fs::read_to_string(config_path)?;
    // Sanitize TOML parse errors before propagation: the default
    // `toml::de::Error` Display prints a caret pointing at the offending
    // byte range, which includes the raw line contents. If the error
    // lands on a `license_key = "..."` or `admin_api_token = "..."` line,
    // the unredacted secret ends up in `error!("Fatal error: {}", e)`.
    // Keep only the parser message and the byte span.
    let full_config: FullConfig = toml::from_str(&content).map_err(|e: toml::de::Error| {
        let span = e
            .span()
            .map(|s| format!(" (at bytes {}..{})", s.start, s.end))
            .unwrap_or_default();
        format!("failed to parse config: {}{}", e.message(), span)
    })?;

    // Load signing keypairs - support both old and new formats
    let (keypair_level3, keypair_level5) = if let (Some(kp3), Some(kp5)) =
        (&full_config.keypair_level3, &full_config.keypair_level5)
    {
        // New dual-keypair format
        info!("Loading dual signing keypairs (Level 3 + Level 5)...");

        // Decode Level 3 keypair (ML-DSA-65)
        let sk3_bytes = STANDARD.decode(&kp3.secret_key)?;
        let pk3_bytes = STANDARD.decode(&kp3.public_key)?;

        if pk3_bytes.len() != hpn_core::crypto::MlDsaPublicKey::SIZE {
            return Err(format!(
                "Invalid Level 3 public key size: expected {}, got {}",
                hpn_core::crypto::MlDsaPublicKey::SIZE,
                pk3_bytes.len()
            )
            .into());
        }

        let secret_key3 = hpn_core::crypto::MlDsaSecretKey::from_bytes(&sk3_bytes)
            .map_err(|e| format!("Invalid Level 3 secret key: {}", e))?;
        let public_key3 = hpn_core::crypto::MlDsaPublicKey::from_bytes(&pk3_bytes)
            .map_err(|e| format!("Invalid Level 3 public key: {}", e))?;

        let kp3 = MlDsaKeypair {
            secret_key: secret_key3,
            public_key: public_key3,
            security_level: SecurityLevel::Level3,
        };

        // Decode Level 5 keypair (ML-DSA-87)
        let sk5_bytes = STANDARD.decode(&kp5.secret_key)?;
        let pk5_bytes = STANDARD.decode(&kp5.public_key)?;

        if pk5_bytes.len() != hpn_core::crypto::MlDsaPublicKey::SIZE_87 {
            return Err(format!(
                "Invalid Level 5 public key size: expected {}, got {}",
                hpn_core::crypto::MlDsaPublicKey::SIZE_87,
                pk5_bytes.len()
            )
            .into());
        }

        // Size-validated construction: the bytes came off-disk, so we do
        // NOT trust the length without checking. The manual len checks
        // above still run first as a defence-in-depth, but using
        // `from_bytes` here provides a single validated entry point.
        let secret_key5 = hpn_core::crypto::MlDsaSecretKey::from_bytes(&sk5_bytes)
            .map_err(|e| format!("Invalid Level 5 secret key: {}", e))?;
        let public_key5 = hpn_core::crypto::MlDsaPublicKey::from_bytes(&pk5_bytes)
            .map_err(|e| format!("Invalid Level 5 public key: {}", e))?;

        let kp5 = MlDsaKeypair {
            secret_key: secret_key5,
            public_key: public_key5,
            security_level: SecurityLevel::Level5,
        };

        info!("  Level 3 (ML-DSA-65): loaded");
        info!("  Level 5 (ML-DSA-87): loaded");

        (kp3, kp5)
    } else if let Some(kp) = &full_config.keypair {
        // Old single-keypair format - use same keypair for both levels (Level 3 only)
        warn!(
            "Using legacy single-keypair format. Consider regenerating with 'hpn-server genkey' for dual-level support."
        );

        let sk_bytes = STANDARD.decode(&kp.secret_key)?;
        let pk_bytes = STANDARD.decode(&kp.public_key)?;

        let secret_key = hpn_core::crypto::MlDsaSecretKey::from_bytes(&sk_bytes)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let public_key = hpn_core::crypto::MlDsaPublicKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let keypair = MlDsaKeypair {
            secret_key,
            public_key,
            security_level: SecurityLevel::Level3,
        };

        // Clone for both levels (only Level 3 clients will work properly)
        (keypair.clone(), keypair)
    } else {
        return Err(
            "No keypair found in config. Run 'hpn-server genkey' to generate keypairs.".into(),
        );
    };

    // Load KEM keypairs for identity hiding (optional)
    let kem_keypair_level3 = full_config.kem_keypair_level3.as_ref().and_then(|kem_kp| {
        match load_kem_keypair(kem_kp, SecurityLevel::Level3) {
            Ok(kp) => {
                info!("  KEM Level 3 (X25519 + ML-KEM-768): loaded for identity hiding");
                Some(Arc::new(kp))
            }
            Err(e) => {
                warn!(
                    "Failed to load KEM Level 3 keypair: {}. Identity hiding disabled for Level 3.",
                    e
                );
                None
            }
        }
    });

    let kem_keypair_level5 = full_config.kem_keypair_level5.as_ref().and_then(|kem_kp| {
        match load_kem_keypair(kem_kp, SecurityLevel::Level5) {
            Ok(kp) => {
                info!("  KEM Level 5 (X25519 + ML-KEM-1024): loaded for identity hiding");
                Some(Arc::new(kp))
            }
            Err(e) => {
                warn!(
                    "Failed to load KEM Level 5 keypair: {}. Identity hiding disabled for Level 5.",
                    e
                );
                None
            }
        }
    });

    // Log identity hiding status
    if kem_keypair_level3.is_some() || kem_keypair_level5.is_some() {
        info!(
            "Identity hiding enabled: Level3={}, Level5={}",
            kem_keypair_level3.is_some(),
            kem_keypair_level5.is_some()
        );
    } else {
        info!("Identity hiding: disabled (no KEM keypairs configured)");
    }

    // Validate config
    full_config.server.validate()?;

    #[cfg(unix)]
    if hpn_server::privileges::is_root()
        && full_config.server.run_as_user.is_none()
        && std::env::var_os("HPN_ALLOW_RUN_AS_ROOT").is_none()
    {
        return Err(
            "Refusing to run as root without `server.run_as_user`. Set `run_as_user`/`run_as_group` or override with HPN_ALLOW_RUN_AS_ROOT=1 if you accept the risk."
                .into(),
        );
    }

    // Setup privilege dropper before initialization
    // (we need root to create TUN device and bind to privileged ports)
    #[cfg(unix)]
    let privilege_dropper = PrivilegeDropper::new(
        full_config.server.run_as_user.as_deref(),
        full_config.server.run_as_group.as_deref(),
    )?;

    #[cfg(unix)]
    if privilege_dropper.is_configured() {
        info!(
            "Privilege dropping configured: will switch to {}:{}",
            privilege_dropper.username().unwrap_or("(same)"),
            privilege_dropper.groupname().unwrap_or("(same)")
        );
    }

    // Build the shared tokio runtime up-front and reuse it for the server
    // main loop below, so there is a single scheduler instance for the
    // whole process.
    let rt = tokio::runtime::Runtime::new()?;

    // Create server with signing keypairs and optional KEM keypairs.
    // HPN is open-source: there is no license check — the server starts
    // freely and allows unlimited sessions bounded only by the IP pool.
    let mut server = VpnServer::new_with_identity_hiding(
        full_config.server,
        keypair_level3,
        keypair_level5,
        kem_keypair_level3,
        kem_keypair_level5,
    )?;

    info!("Initializing server...");
    server.initialize()?;

    // Drop privileges AFTER initialization (TUN creation, NAT setup, etc.)
    // but BEFORE running the server main loop
    #[cfg(unix)]
    {
        privilege_dropper.drop_privileges()?;
    }

    // Run server with signal handling
    info!("Starting VPN server...");
    rt.block_on(async {
        // Setup signal handlers for graceful shutdown
        let shutdown_signal = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
                let mut sigint =
                    signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM, initiating graceful shutdown...");
                    }
                    _ = sigint.recv() => {
                        info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install Ctrl+C handler");
                info!("Received Ctrl+C, initiating graceful shutdown...");
            }
        };

        // Run server until shutdown signal
        tokio::select! {
            result = server.run() => {
                if let Err(e) = result {
                    error!("Server error: {}", e);
                    return Err(e.into());
                }
            }
            () = shutdown_signal => {
                info!("Shutting down server...");
                server.shutdown();
            }
        }

        info!("Server shutdown complete");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_user_db_path_from_content;
    use hpn_server::ServerConfig;
    use std::path::PathBuf;

    const USER_DB_CONFIG_BASE: &str = r#"
        [server]
        listen_addr = "0.0.0.0:51820"
        ipv4_pool = "10.99.0.0/24"
        server_tunnel_ip = "10.99.0.1"
        dns_servers = ["1.1.1.1"]
    "#;

    #[test]
    fn parse_user_db_path_reads_primary_key() {
        let config = format!(
            "{}users_db_path = \"/tmp/users-primary.db\"\n",
            USER_DB_CONFIG_BASE
        );
        let db_path = parse_user_db_path_from_content(&config).expect("config should parse");
        assert_eq!(db_path, PathBuf::from("/tmp/users-primary.db"));
    }

    #[test]
    fn parse_user_db_path_reads_legacy_alias() {
        let config = format!(
            "{}user_db_path = \"/tmp/users-legacy.db\"\n",
            USER_DB_CONFIG_BASE
        );
        let db_path = parse_user_db_path_from_content(&config).expect("config should parse");
        assert_eq!(db_path, PathBuf::from("/tmp/users-legacy.db"));
    }

    #[test]
    fn parse_user_db_path_defaults_when_omitted() {
        let db_path =
            parse_user_db_path_from_content(USER_DB_CONFIG_BASE).expect("config should parse");
        assert_eq!(db_path, PathBuf::from(ServerConfig::DEFAULT_USERS_DB_PATH));
    }
}
