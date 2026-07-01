use std::io::Read;
use std::path::PathBuf;

/// Compute the SHA-256 of `resources/wintun.dll` and emit it as a
/// `cargo:rustc-env=HPN_WINTUN_SHA256` variable so the runtime loader can
/// refuse to load a swapped-in DLL.
///
/// Background: `find_wintun_dll` searches several disk locations to load
/// `wintun.dll`. Without an integrity check, an attacker who can write
/// to the install directory (typical privilege-escalation finding on
/// Windows) can drop a malicious DLL of the same name and have it
/// loaded by HPN with administrator privileges, since the host process
/// is `requireAdministrator` per the manifest above. Embedding the
/// expected hash at build time and verifying at load time closes that
/// gap end-to-end:
///
/// - Build host: the CI pipeline downloads the official Wintun ZIP
///   (verified against the Wintun publisher's published SHA-256), then
///   extracts `bin/amd64/wintun.dll` into `resources/`. This `build.rs`
///   then hashes it and bakes the value into the executable.
/// - Install: the executable is signed with Azure Trusted Signing, so
///   the embedded hash cannot be tampered with without breaking the
///   signature.
/// - Runtime: the loader compares the file on disk against the
///   embedded hash and refuses to load it on mismatch.
///
/// During local development on non-Windows hosts the file may not yet
/// exist (the CI fetches it). In that case we still emit the env var,
/// but with a sentinel value (`""`) that the runtime check treats as
/// "skip verification, log a loud warning". This keeps `cargo check`
/// and unit tests on macOS/Linux working without requiring the dev to
/// fetch the DLL by hand.
fn embed_wintun_sha256() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let dll_path = manifest_dir.join("resources").join("wintun.dll");

    println!("cargo:rerun-if-changed={}", dll_path.display());

    let hex = match std::fs::File::open(&dll_path) {
        Ok(mut file) => {
            let mut data = Vec::with_capacity(256 * 1024);
            if let Err(e) = file.read_to_end(&mut data) {
                println!(
                    "cargo:warning=Failed to read {} ({}); SHA-256 verification will be disabled",
                    dll_path.display(),
                    e
                );
                String::new()
            } else if data.is_empty() {
                println!(
                    "cargo:warning={} is empty (placeholder); SHA-256 verification will be disabled. \
                     CI must fetch the real Wintun DLL before bundling.",
                    dll_path.display()
                );
                String::new()
            } else {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let digest = hasher.finalize();
                let mut s = String::with_capacity(64);
                for b in digest.iter() {
                    s.push_str(&format!("{:02x}", b));
                }
                s
            }
        }
        Err(_) => {
            println!(
                "cargo:warning={} not found; SHA-256 verification will be disabled. \
                 CI must fetch the real Wintun DLL before bundling.",
                dll_path.display()
            );
            String::new()
        }
    };

    println!("cargo:rustc-env=HPN_WINTUN_SHA256={}", hex);
}

fn main() {
    embed_wintun_sha256();

    // Request administrator privileges on Windows via UAC manifest
    #[cfg(target_os = "windows")]
    {
        let mut windows = tauri_build::WindowsAttributes::new();
        // requireAdministrator - always request admin rights
        // This is needed for:
        // - Creating Wintun TUN adapter
        // - Configuring network routes
        // - Modifying DNS settings
        windows = windows.app_manifest(
            r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 and Windows 11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>
"#,
        );
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
            .expect("failed to run tauri build");
    }

    #[cfg(not(target_os = "windows"))]
    {
        tauri_build::build();
    }
}
