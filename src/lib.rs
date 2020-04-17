/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

//! This project is providing two plugins to be used with the [`vade`] library. These plugins offer functionalities to work with VCs and DIDs on [evan.network].
//!
//! ## Usage
//!
//! Plugins from this project can be used within the [`vade`] library as described in its own documentation. To give you a jump start, here is how you can retrieve VC documents:
//!
//! ```rust
//! extern crate vade;
//! extern crate vade_evan;
//!
//! use vade::Vade;
//! use vade_evan::plugin::rust_vcresolver_evan::RustVcResolverEvan;
//!
//! const EXAMPLE_VC_NAME_REMOTE: &str = "vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3";
//!
//! #[tokio::test]
//! async fn can_fetch_a_vc_document() {
//!     let rde = RustVcResolverEvan::new();
//!     let mut vade = Vade::new();
//!     vade.register_vc_resolver(Box::from(rde));
//!
//!     let _vc = vade.get_vc_document(&EXAMPLE_VC_NAME_REMOTE).await.unwrap();
//! }
//! ```
//!
//! ## Plugins
//!
//! Plugins are described below shotly, for more details see respective [API documentation].
//!
//! ### VC Resolver
//!
//! Allows to work with VCs on [evan.network], currently includes:
//!
//! - retrieving VCs
//! - validating VCs, which will
//!   - check `proof` (if attached)
//!   - check `credentialStatus` online (if attached)
//!
//! ### DID Resolver
//!
//! Allows to work with DIDs on [evan.network], currently includes:
//!
//! - retrieving DIDs
//!
//! [`vade`]: https://docs.rs/vade
//! [API documentation]: https://docs.rs/vade-evan
//! [evan.network]: https://evan.network

extern crate chrono;
extern crate env_logger;
extern crate hex;
#[macro_use]
extern crate log;
extern crate secp256k1;
extern crate sha3;
extern crate vade;

pub mod platform;
pub mod plugin;
