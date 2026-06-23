//! Build script: generates tonic + prost types from `proto/*.proto`.
//!
//! Uses `protoc-bin-vendored` so the build is hermetic (no system
//! `protoc` required). Skipped when the `grpc` feature is off, so
//! default builds don't pay for codegen.

// `std::env::set_var` is unsafe under the 2024 edition; the workspace
// lints `forbid(unsafe_code)` but build scripts run on the host with
// no concurrency invariants, so it's safe here.
#![allow(unsafe_code)]

fn main() {
    println!("cargo:rerun-if-changed=proto/glassbox.proto");
    if std::env::var_os("CARGO_FEATURE_GRPC").is_none() {
        return;
    }
    // SAFETY: env mutation in a single-threaded build.rs main.
    unsafe {
        std::env::set_var(
            "PROTOC",
            protoc_bin_vendored::protoc_bin_path().expect("vendored protoc"),
        );
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/glassbox.proto"], &["proto"])
        .expect("compile_protos");
}
