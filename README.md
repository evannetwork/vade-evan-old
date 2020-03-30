# Vade - evan.network Plugins

[![crates.io](https://img.shields.io/crates/v/vade-evan.svg)](https://crates.io/crates/vade-evan)
[![Documentation](https://docs.rs/vade-evan/badge.svg)](https://docs.rs/vade-evan)
[![Apache-2 licensed](https://img.shields.io/crates/l/vade-evan.svg)](./LICENSE.txt)

## About

This project is providing two plugins to be used with the ['vade'] library. These plugins offer functionalities to work with VCs and DIDs on [evan.network](https://evan.network/).

## Usage

Plugins from this project can be used within the ['vade'] library as described in its own documentation. To give you a jump start, here is how you can retrieve VC documents:

```rust
extern crate vade;
extern crate vade_evan;

use vade::Vade;
use vade_evan::plugin::rust_vcresolver_evan::RustVcResolverEvan;

const EXAMPLE_VC_NAME_REMOTE: &str = "vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3";

#[tokio::test]
async fn can_fetch_a_vc_document() {
    let rde = RustVcResolverEvan::new();
    let mut vade = Vade::new();
    vade.register_vc_resolver(Box::from(rde));

    let _vc = vade.get_vc_document(&EXAMPLE_VC_NAME_REMOTE).await.unwrap();
}
```

## Plugins

Plugins are described below shotly, for more details see respective [API documentation](https://docs.rs/vade-evan)

### VC Resolver

Allows to work with VCs on [evan.network](https://evan.network/), currently includes:

- retrieving VCs
- validating VCs, which will
  - check `proof` (if attached)
  - check `credentialStatus` online (if attached)

### DID Resolver

Allows to work with DIDs on [evan.network](https://evan.network/), currently includes:

- retrieving DIDs

[`vade`]: https://docs.rs/vade
