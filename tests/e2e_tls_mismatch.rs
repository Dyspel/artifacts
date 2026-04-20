//! `serve()` must refuse to start when exactly one of `--tls-cert` /
//! `--tls-key` is set (a config error). Own test binary because the
//! check runs after the once-per-process tracing init.

use clap::Parser as _;

#[test]
fn serve_bails_on_half_configured_tls() {
    #[derive(clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: artifacts::app::ServeArgs,
    }

    let dir = tempfile::tempdir().unwrap();
    // Only --tls-cert, no --tls-key → mismatched config.
    let cert = dir.path().join("cert.pem");
    std::fs::write(&cert, "not a real cert").unwrap();
    let args = Wrapper::parse_from([
        "artifacts",
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--bind",
        "127.0.0.1:0",
        "--public-base-url",
        "http://127.0.0.1:0",
        "--admin-token",
        "x",
        "--tls-cert",
        cert.to_str().unwrap(),
    ])
    .args;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(artifacts::app::serve(args))
        .expect_err("serve must bail when only one of cert/key is set");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("tls-cert") && msg.contains("tls-key"),
        "error should name both TLS flags: {msg}"
    );
}
