# GoBGP API (vendored)

The `.proto` files in `api/` are GoBGP's gRPC API, copied unmodified from
[osrg/gobgp](https://github.com/osrg/gobgp) at tag **v4.9.0** (commit
`96ef11aedd066031f1bacb2c587baaa769ba07eb`), path `proto/api/`. GoBGP is
licensed under the Apache License 2.0; its licence is in `LICENSE` here.
See [ADR 0048](../../../docs/architecture/decisions/0048-phase7c-gobgp-adapter.md).

| File | SHA-256 |
|---|---|
| `attribute.proto` | `ea06559c374539ca9580f3ff758099c0698b0d60eca5f81196c88189768eb432` |
| `capability.proto` | `74470c26cafca108d2a6ee1e78afaf8201afc3c1e26714303e2edbdcd845d79c` |
| `common.proto` | `87cb2ebc674d55654b2668f2daec23a0f6f72fa48c9248a5b99f51ac5e52bc99` |
| `extcom.proto` | `6201fa27b12d5e3d8caa95dea4adea28a64c795614b847bace6607176e088779` |
| `gobgp.proto` | `a41dad4f0f6feb6b75b0d56da491e5b0145335bde9ce8d38d4e81624c621012f` |
| `nlri.proto` | `164a3cbffa9f93a947cd7e0b4f180b6425df64dd852dd683c75c5ba2d09fec1e` |

To upgrade, replace all six files and this table, and the `gobgpd`
version and checksum in `.github/workflows/validate.yml`, in one change.
