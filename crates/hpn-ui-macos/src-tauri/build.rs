use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let native_dir = manifest_dir.parent().unwrap().join("native");
    let swift_src = native_dir.join("VPNManager.swift");
    let lib_out = native_dir.join("libHPNVPNManager.a");

    println!("cargo:rerun-if-changed={}", swift_src.display());
    println!("cargo:rerun-if-changed=build.rs");
    // Watch the OUTPUT `.a` too. Without this, cargo's incremental
    // build only re-runs build.rs when one of the watched files
    // changes — but if the operator deletes `libHPNVPNManager.a`
    // manually (as the clean-rebuild instructions suggest), cargo
    // thinks "no input change" and skips build.rs. The cached link
    // directives are still passed to the linker (`-lHPNVPNManager`
    // + `-L native/`), which then fails with "library 'HPNVPNManager'
    // not found". Listing the output here makes its absence count
    // as a watched-file change, forcing build.rs to re-run and
    // regenerate the `.a`.
    println!("cargo:rerun-if-changed={}", lib_out.display());

    // Compile Swift when (a) the source changed, (b) the .a is
    // missing, or (c) this is the first build of the crate. swiftc
    // is fast enough that we don't bother trying to skip it when
    // the source-and-output mtimes line up — cargo already gates
    // re-runs of build.rs itself via the rerun-if-changed pragmas
    // above.
    if swift_src.exists() {
        let status = Command::new("swiftc")
            .args([
                "-emit-library",
                "-static",
                "-parse-as-library",
                "-module-name",
                "HPNVPNManager",
                "-target",
                "arm64-apple-macos14.0",
                "-O",
                "-o",
            ])
            .arg(&lib_out)
            .arg(&swift_src)
            .args(["-framework", "NetworkExtension", "-framework", "Foundation"])
            .status()
            .expect("failed to invoke swiftc");

        assert!(status.success(), "swiftc compilation failed");
    } else {
        // Defensive: the source MUST exist. If it doesn't, something is
        // structurally wrong with the checkout — fail the build loudly
        // rather than silently produce a binary that's missing the FFI.
        panic!(
            "VPNManager.swift not found at {}; the checkout is broken",
            swift_src.display()
        );
    }

    // INCREMENTAL-BUILD BUG WORKAROUND (May 2026):
    //
    // Cargo's `rerun-if-changed=VPNManager.swift` makes build.rs re-run
    // when the Swift source changes — but that alone is NOT enough to
    // force the final Rust binary to be re-linked. Cargo's incremental
    // compiler tracks Rust source mtimes and the dependency graph; the
    // produced static library file `libHPNVPNManager.a` is NOT part of
    // that graph. After a swiftc recompile the new `.a` sits on disk,
    // but cargo sees "no Rust source change → skip link", and the
    // already-built Tauri binary keeps the OLD Swift code embedded.
    //
    // The user-visible symptom was: every code change to VPNManager
    // .swift had to be paired with `cargo clean -p hpn-ui-macos` to
    // actually ship. The first two split-tunnel kill-switch iterations
    // (commits b3911e7 and 59c41dc) both shipped this way without the
    // clean step, so the host app continued running the original
    // pre-leak-fix logic for the field tester even after they pulled
    // and rebuilt. The persisted plist showed `IncludeAllNetworks
    // = false` (the old default) — definitive proof that the new
    // VPNManager.swift code never executed.
    //
    // Fix: emit a `cargo:rustc-env=` whose value is a hash of the
    // Swift source. When the hash changes, cargo treats the env input
    // as changed and re-compiles + re-links the host crate, picking
    // up the freshly-built `.a`. The env var is intentionally not
    // read by any Rust code — its only role is to be part of cargo's
    // dependency-tracking input set.
    if let Ok(swift_content) = std::fs::read_to_string(&swift_src) {
        let mut hasher = DefaultHasher::new();
        swift_content.hash(&mut hasher);
        let hash = hasher.finish();
        println!("cargo:rustc-env=HPN_VPN_MANAGER_SWIFT_HASH={:016x}", hash);
    }

    if lib_out.exists() {
        println!("cargo:rustc-link-search=native={}", native_dir.display());
        println!("cargo:rustc-link-lib=static=HPNVPNManager");
        println!("cargo:rustc-link-lib=framework=NetworkExtension");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-search=native=/usr/lib/swift");
    }

    tauri_build::build();
}
