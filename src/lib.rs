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
//! - creating VCs
//!
//! #### Retrieving VCs
//!
//! Existing VCs from [evan.network] can be retrieved with vade's [`get_vc_document`] function:
//!
//! ```rust
//! use vade::Vade;
//! use vade_evan::plugin::rust_vcresolver_evan::RustVcResolverEvan;
//! 
//! async fn example() {
//!     let vcr = RustVcResolverEvan::new();
//!     let mut vade = Vade::new();
//!     vade.register_vc_resolver(Box::from(vcr));
//!
//!     let vc = vade.get_vc_document("vc:evan:testcore:0x75956ef9b3ea7d7230cf007b8ee042bcaa2a4dad8c043fa77ecf51262ee4f7a9").await.unwrap();
//! }
//! ```
//!
//! Result is returned as a JSON `String` and can easily be parsed with libraries like [`serde_json`] for further processing, e.g.:
//!
//! ```rust
//! # use serde_json::Value;
//! # let vc = "{}";
//! let parsed: Value = serde_json::from_str(&vc).unwrap();
//! ```
//!
//! ##### Validating VCs
//!
//! Taken from our tests:
//!
//! ```rust
//! use vade::Vade;
//! use vade::plugin::rust_storage_cache::RustStorageCache;
//! use vade_evan::plugin::rust_vcresolver_evan::RustVcResolverEvan;
//!
//! async fn example() -> std::result::Result<(), Box<dyn std::error::Error>> {
//!     // create a vc resolver with attached did resolver in a vade
//!     let vcr_didr = RustStorageCache::new();
//!     let mut vcr_vade = Vade::new();
//!     vcr_vade.register_did_resolver(Box::from(vcr_didr));
//!     // add did document to vcr's did resolver
//!     let did_id = "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f";
//!     let did_document = "{...}";
//!     vcr_vade.set_did_document(&did_id, &did_document).await?;
//!     let mut vcr = RustVcResolverEvan::new();
//!     vcr.vade = Some(Box::from(vcr_vade));
//!
//!     // create vade to work with, attach 
//!     let mut vade = Vade::new();
//!     vade.register_vc_resolver(Box::from(vcr));
//!
//!     // test VC document
//!     let vc_name = "vc:evan:testcore:0x8b078ee6cfb208dca52bf89ab7178e0f11323f4363c1a6ad18321275e6d07fcb";
//!     let vc_document = "{...}";
//!     let vc_result = vade.check_vc(&vc_name, &vc_document).await;
//!     match vc_result {
//!         Ok(_) => (),
//!         Err(e) => panic!(format!("{}", e)),
//!     };
//!     Ok(())
//! }
//! ```
//!
//! Note that the setup for the [`RustVcResolver`] instance differs a bit, as we
//! - create a separate [`Vade`] instance
//! - configure a [`DidResolver`] for it in this case an in-memory resolver for our test DID
//! - register it as `vade` in our [`RustVcResolver`] instance
//!
//! This allows us to validate the `proof` property in our VC document.
//!
//!
//! ##### Creating VCs
//!
//! Creating a VC currently has three requirements:
//!
//! - and [evan.network] identity for the VC issuer, which means, we also have
//!   - an DID document for for the issuer of our VC
//!   - a 64B private key as `str`, used to create the `proof` property (of course not IN the DID document ;)) 
//!   - a way to identify this key, as the `ethereumAddress` of it is IN the DID document
//! - an `id` for the VC - as the VCs created with `vade-evan` are currently not stored onchain, we cannot rely on automatic ID generation (`id` can currently be anything, but you should try to avoid reusing IDs to avoid overriding your documents locally)
//!
//! As an example take this test function:
//!
//! ```rust
//! use serde_json::Value;
//! use vade_evan::plugin::rust_vcresolver_evan::{
//!     RustVcResolverEvan,
//!     VC_DEFAULT_TYPE,
//!     VC_W3C_MANDATORY_CONTEXT,
//! };
//!
//! async fn vc_resolver_can_create_new_vcs() -> std::result::Result<(), Box<dyn std::error::Error>> {
//!     // issuer of the new VC
//!     let veri_issuer = "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f";
//!     // verification method of the VC (can be considered "key id" for the key used to create proof)
//!     let veri_method = "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f#key-1";
//!     // Ethereum private key used to create proof
//!     let veri_pkey = "01734663843202e2245e5796cb120510506343c67915eb4f9348ac0d8c2cf22a";
//!     // sample data, `id` is required, `credentialSubject` is optional and holds tests data
//!     let partial_vc_data =r###"
//!     {
//!         "id": "foo-bar-vc",
//!         "credentialSubject": {
//!             "foo": "bar"
//!         }
//!     } 
//! "###;
//!
//!     let vcr = RustVcResolverEvan::new();
//!
//!     let vc: String = vcr.create_vc(partial_vc_data, &veri_method, &veri_pkey).await.unwrap();
//!
//!     let parsed: Value = serde_json::from_str(&vc).unwrap();
//!
//!     assert!(parsed["credentialSubject"]["foo"].as_str() == Some("bar"));
//!     assert!(parsed["@context"].as_array().unwrap().len() == 1);
//!     assert!(parsed["@context"].as_array().unwrap().iter().any(|v| v == VC_W3C_MANDATORY_CONTEXT));
//!     assert!(parsed["type"].as_str() == Some(VC_DEFAULT_TYPE));
//!     assert!(parsed["issuer"].as_str() == Some(veri_issuer));
//!     assert!(parsed["validFrom"].as_str() != None);
//!     assert!(parsed["proof"].as_object() != None);
//!
//!     Ok(())
//! }
//! ```
//!
//! Have a look at the assert block at the end of the test. Here you can see the properties, that are added automatically:
//! -  @context
//! -  type
//! -  issuer
//! -  validFrom
//! -  proof
//!
//! These are added automatically if not provided in `partial_vc_data`.
//!
//! ### DID Resolver
//!
//! Allows to work with DIDs on [evan.network], currently includes:
//!
//! - retrieving DIDs
//!
//! #### Retrieving DIDs
//!
//! Fetching DIDs via [`RustDidResolver`] fetches them from [evan.network] and returns them as `str`, e.g.:
//!
//! ```rust
//! use vade::Vade;
//! use vade_evan::plugin::rust_didresolver_evan::RustDidResolverEvan;
//! # async fn example() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! let rde = RustDidResolverEvan::new();
//! let mut vade = Vade::new();
//! vade.register_did_resolver(Box::from(rde));
//!
//! let did = vade.get_did_document("did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f").await.unwrap();
//! # Ok(())
//! # }
//! ```
//!
//! [`DidResolver`]: https://docs.rs/vade/*/vade/traits/trait.DidResolver.html
//! [`get_vc_document`]: https://docs.rs/vade/*/vade/traits/trait.VcResolver.html#tymethod.get_vc_document
//! [`RustDidResolver`]: https://docs.rs/vade-evan/*/vade_evan/plugin/rust_didresolver_evan/struct.RustDidResolverEvan.html
//! [`RustVcResolver`]: https://docs.rs/vade-evan/*/vade_evan/plugin/rust_vcresolver_evan/struct.RustVcResolverEvan.html
//! [`serde_json`]: https://docs.rs/serde_json/*/serde_json
//! [`vade`]: https://docs.rs/vade
//! [`Vade`]: https://docs.rs/vade/*/vade/struct.Vade.html
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
