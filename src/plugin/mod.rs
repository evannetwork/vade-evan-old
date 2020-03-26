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

//! [`vade`] plugins for working VCs and DIDs on [evan.network](https://evan.network/)
//!
//! ### VC Resolver
//!
//! Allows to work with VCs on [evan.network](https://evan.network/), currently includes:
//!
//! - retrieving VCs
//! - validating VCs, which will
//!   - check `proof` (if attached)
//!   - check `credentialStatus` online (if attached)
//!
//! ### DID Resolver
//!
//! Allows to work with DIDs on [evan.network](https://evan.network/), currently includes:
//!
//! - retrieving DIDs
//!
//! [`vade`]: https://docs.rs/vade

pub mod rust_didresolver_evan;
pub mod rust_vcresolver_evan;