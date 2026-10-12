//! Compiles GoBGP's API from the `.proto` files vendored in `proto/`
//! (GoBGP v4.9.0, ADR 0048). `protox` parses them in Rust, so no `protoc`
//! is needed. Only the client is generated: WetechiNetMon never serves
//! GoBGP's API.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let descriptors = protox::compile(["api/gobgp.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_server(false)
        .build_transport(true)
        // The upstream comments hold indented text rustdoc would run as
        // doctests.
        .disable_comments(["."])
        .compile_fds(descriptors)?;
    Ok(())
}
