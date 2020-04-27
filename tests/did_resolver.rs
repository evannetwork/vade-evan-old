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

extern crate vade_evan;

use vade::Vade;
use vade::plugin::rust_storage_cache::RustStorageCache;
use vade_evan::plugin::rust_didresolver_evan::RustDidResolverEvan;
use serde_json::Value;

const EXAMPLE_DID: &str = "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906";
const EXAMPLE_DID_DOCUMENT_STR: &str = r###"
{
    "@context": "https://w3id.org/did/v1",
    "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
    "publicKey": [
      {
        "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
        "type": "Secp256k1VerificationKey2018",
        "controller": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
        "ethereumAddress": "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c"
      }
    ],
    "authentication": [
      "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1"
    ],
    "created": "2020-04-16T06:51:48.344Z",
    "updated": "2020-04-16T06:51:48.344Z",
    "proof": {
      "type": "EcdsaPublicKeySecp256k1",
      "created": "2020-04-16T06:51:48.352Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
      "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODcwMTk5MDgsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYiLCJldGhlcmV1bUFkZHJlc3MiOiIweGNkNWUxZGJiNTU1MmMyYmFhMTk0M2U2YjVmNjZkMjIxMDdlOWMwNWMifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wNC0xNlQwNjo1MTo0OC4zNDRaIiwidXBkYXRlZCI6IjIwMjAtMDQtMTZUMDY6NTE6NDguMzQ0WiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYifQ.GvsVegB_bEFi_XIde0LD2Et_kJ9qeaEw5NSS7Ye8FBqgR_am1QWsnEY2vU4tJDyjPSo_AXB6gtRDdRNXwDb3fwA"
    }
  }
"###;

#[tokio::test]
async fn can_fetch_a_did_document() {
    let rde = RustDidResolverEvan::new();
    let mut vade = Vade::new();
    vade.register_did_resolver(Box::from(rde));

    let did = vade.get_did_document(&EXAMPLE_DID).await.unwrap();
    let parsed: Value = serde_json::from_str(&did).unwrap();
    assert!(&EXAMPLE_DID == &parsed["id"]);
}

#[tokio::test]
async fn returns_an_error_for_invalid_did_ids() {
    let rde = RustDidResolverEvan::new();
    let mut vade = Vade::new();
    vade.register_did_resolver(Box::from(rde));

    let did_name = "did:evan:testcore:invalid";
    let did_result = vade.get_did_document(&did_name).await;
    match did_result {
        Ok(_did) => panic!("unexpected did document"),
        Err(e) => assert!(format!("{}", e) == "could not get did document"),
    }
}

// race
#[tokio::test]
async fn can_handle_racing_resolvers_1() {
    let mut vade = Vade::new();
    let rde = RustDidResolverEvan::new();
    vade.register_did_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    vade.register_did_resolver(Box::from(storage));
    let did = vade.get_did_document(&EXAMPLE_DID).await.unwrap();
    assert!(did == EXAMPLE_DID_DOCUMENT_STR);
}

#[tokio::test]
async fn can_handle_racing_resolvers_2() {
    let mut vade = Vade::new();
    let rde = RustDidResolverEvan::new();
    vade.register_did_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_DID, "qwer").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    let did_result = vade.get_did_document("something different").await;
    match did_result {
        Ok(_did) => panic!("unexpected did document"),
        Err(e) => assert!(format!("{}", e) == "could not get did document"),
    }
}

#[allow(dead_code)]
// currently diabled as `RustDidResolverEvan` does not implement `set_vc_document` atm
// #[tokio::test]
async fn can_handle_racing_resolvers_3() {
    let mut vade = Vade::new();
    let rde = RustDidResolverEvan::new();
    vade.register_did_resolver(Box::from(rde));
    let storage = RustStorageCache::new();

    match vade.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    vade.register_did_resolver(Box::from(storage));
    let did = vade.get_did_document(&EXAMPLE_DID).await.unwrap();
    println!("{:?}", &did);
    assert!(did == String::from(EXAMPLE_DID_DOCUMENT_STR));
}