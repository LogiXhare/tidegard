//! The mitigator (Phase 7, ADR 0048): the only code in WetechiNetMon that
//! speaks to GoBGP.

/// GoBGP's API, generated from the vendored `.proto` files.
#[allow(clippy::all, clippy::pedantic, missing_docs, rustdoc::all)]
pub mod api {
    tonic::include_proto!("api");
}

pub mod gobgp;
pub mod route;
