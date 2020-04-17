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

extern crate secp256k1;
extern crate sha3;
extern crate vade;
extern crate vade_evan;

use serde_json::Value;
use vade::Vade;
use vade::plugin::rust_storage_cache::RustStorageCache;
use vade::traits::DidResolver;
use vade_evan::plugin::rust_vcresolver_evan::{
    RustVcResolverEvan,
    VC_DEFAULT_TYPE,
    VC_W3C_MANDATORY_CONTEXT,
};

const EXAMPLE_VC_NAME_REMOTE: &str = "vc:evan:testcore:0x75956ef9b3ea7d7230cf007b8ee042bcaa2a4dad8c043fa77ecf51262ee4f7a9";
const EXAMPLE_VC_DOCUMENT_STR_REMOTE: &str = r###"
{
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiableCredential"
    ],
    "issuer": {
      "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906"
    },
    "credentialSubject": {
      "id": "did:evan:testcore:0xc88d707c2436fa3ce4a1e52d751469acae689fdb",
      "data": [
        {
          "name": "isTrustedSupplier",
          "value": "true"
        }
      ]
    },
    "validFrom": "2020-04-16T06:54:32.805Z",
    "id": "vc:evan:testcore:0x75956ef9b3ea7d7230cf007b8ee042bcaa2a4dad8c043fa77ecf51262ee4f7a9",
    "credentialStatus": {
      "id": "https://testcore.evan.network/vc/status/vc:evan:testcore:0x75956ef9b3ea7d7230cf007b8ee042bcaa2a4dad8c043fa77ecf51262ee4f7a9",
      "type": "evan:evanCredential"
    },
    "proof": {
      "type": "EcdsaPublicKeySecp256k1",
      "created": "2020-04-16T06:54:36.663Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
      "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODcwMjAwNzYsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZDg3MjA0YzM5NTdkNzNiNjhhZTI4ZDBhZjk2MWQzYzcyNDAzOTA2In0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHhjODhkNzA3YzI0MzZmYTNjZTRhMWU1MmQ3NTE0NjlhY2FlNjg5ZmRiIiwiZGF0YSI6W3sibmFtZSI6ImlzVHJ1c3RlZFN1cHBsaWVyIiwidmFsdWUiOiJ0cnVlIn1dfSwidmFsaWRGcm9tIjoiMjAyMC0wNC0xNlQwNjo1NDozMi44MDVaIiwiaWQiOiJ2YzpldmFuOnRlc3Rjb3JlOjB4NzU5NTZlZjliM2VhN2Q3MjMwY2YwMDdiOGVlMDQyYmNhYTJhNGRhZDhjMDQzZmE3N2VjZjUxMjYyZWU0ZjdhOSIsImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL3Rlc3Rjb3JlLmV2YW4ubmV0d29yay92Yy9zdGF0dXMvdmM6ZXZhbjp0ZXN0Y29yZToweDc1OTU2ZWY5YjNlYTdkNzIzMGNmMDA3YjhlZTA0MmJjYWEyYTRkYWQ4YzA0M2ZhNzdlY2Y1MTI2MmVlNGY3YTkiLCJ0eXBlIjoiZXZhbjpldmFuQ3JlZGVudGlhbCJ9fSwiaXNzIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZDg3MjA0YzM5NTdkNzNiNjhhZTI4ZDBhZjk2MWQzYzcyNDAzOTA2In0.DASfiCeTpWmE5xnrlB0CPiGrk_zyf05I2k9B5_FtyLH4mMlJqK4_hCWYv_j7OH6S79Q5ES_Am30ib9zAGnhPGAE"
    }
}
"###;

const EXAMPLE_VC_NAME: &str = "vc:evan:testcore:0x8b078ee6cfb208dca52bf89ab7178e0f11323f4363c1a6ad18321275e6d07fcb";
const EXAMPLE_VC_DOCUMENT_STR: &str = r###"
{ "@context": [ "https://www.w3.org/2018/credentials/v1" ],
  "type": [ "VerifiableCredential" ],
  "issuer":
   { "id":
      "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f" },
  "credentialSubject":
   { "id":
      "did:evan:testcore:0x67ced07dd4f37aa2319bedd97d040b64888c57bc",
     "data": [ { "name": "isTrustedSupplier", "value": "true" } ] },
  "validFrom": "2020-03-19T08:30:30.536Z",
  "id":
   "vc:evan:testcore:0x8b078ee6cfb208dca52bf89ab7178e0f11323f4363c1a6ad18321275e6d07fcb",
  "credentialStatus":
   { "id":
      "https://testcore.evan.network/vc/status/vc:evan:testcore:0x8b078ee6cfb208dca52bf89ab7178e0f11323f4363c1a6ad18321275e6d07fcb",
     "type": "evan:evanCredential" },
  "proof":
   { "type": "EcdsaPublicKeySecp256k1",
     "created": "2020-03-19T08:30:31.667Z",
     "proofPurpose": "assertionMethod",
     "verificationMethod":
      "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f#key-1",
     "jws":
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODQ2MDY2MzEsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZWYwZTU4NGM3MTQ1NjRhNGZjMGM2YzM2N2VkY2NiMGMxY2JmNjVmIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2N2NlZDA3ZGQ0ZjM3YWEyMzE5YmVkZDk3ZDA0MGI2NDg4OGM1N2JjIiwiZGF0YSI6W3sibmFtZSI6ImlzVHJ1c3RlZFN1cHBsaWVyIiwidmFsdWUiOiJ0cnVlIn1dfSwidmFsaWRGcm9tIjoiMjAyMC0wMy0xOVQwODozMDozMC41MzZaIiwiaWQiOiJ2YzpldmFuOnRlc3Rjb3JlOjB4OGIwNzhlZTZjZmIyMDhkY2E1MmJmODlhYjcxNzhlMGYxMTMyM2Y0MzYzYzFhNmFkMTgzMjEyNzVlNmQwN2ZjYiIsImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL3Rlc3Rjb3JlLmV2YW4ubmV0d29yay92Yy9zdGF0dXMvdmM6ZXZhbjp0ZXN0Y29yZToweDhiMDc4ZWU2Y2ZiMjA4ZGNhNTJiZjg5YWI3MTc4ZTBmMTEzMjNmNDM2M2MxYTZhZDE4MzIxMjc1ZTZkMDdmY2IiLCJ0eXBlIjoiZXZhbjpldmFuQ3JlZGVudGlhbCJ9fSwiaXNzIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZWYwZTU4NGM3MTQ1NjRhNGZjMGM2YzM2N2VkY2NiMGMxY2JmNjVmIn0.IMPiWh1fEeVN8n7FlhFzG8bEzPafX7-H04OwLSTi4Wh7wxpanoq_4nUcsC9LlrxNALSKf8cUJUb03xir4uGBpAE" } }
"###;
const EXAMPLE_VC_DOCUMENT_MANIPULATED_STR: &str = r###"
{ "@context": [ "https://www.w3.org/2018/credentials/v1" ],
  "type": [ "VerifiableCredential" ],
  "issuer":
   { "id":
      "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f" },
  "credentialSubject":
   { "id":
      "did:evan:testcore:0x67ced07dd4f37aa2319bedd97d040b64888c57bc",
     "data": [ { "name": "isTrustedSupplier", "value": "false" } ] },
  "validFrom": "2020-03-19T08:30:30.536Z",
  "id":
   "vc:evan:testcore:0x8b078ee6cfb208dca52bf89ab7178e0f11323f4363c1a6ad18321275e6d07fcb",
  "credentialStatus":
   { "id":
      "https://testcore.evan.network/vc/status/vc:evan:testcore:0x8b078ee6cfb208dca52bf89ab7178e0f11323f4363c1a6ad18321275e6d07fcb",
     "type": "evan:evanCredential" },
  "proof":
   { "type": "EcdsaPublicKeySecp256k1",
     "created": "2020-03-19T08:30:31.667Z",
     "proofPurpose": "assertionMethod",
     "verificationMethod":
      "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f#key-1",
     "jws":
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODQ2MDY2MzEsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZWYwZTU4NGM3MTQ1NjRhNGZjMGM2YzM2N2VkY2NiMGMxY2JmNjVmIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2N2NlZDA3ZGQ0ZjM3YWEyMzE5YmVkZDk3ZDA0MGI2NDg4OGM1N2JjIiwiZGF0YSI6W3sibmFtZSI6ImlzVHJ1c3RlZFN1cHBsaWVyIiwidmFsdWUiOiJ0cnVlIn1dfSwidmFsaWRGcm9tIjoiMjAyMC0wMy0xOVQwODozMDozMC41MzZaIiwiaWQiOiJ2YzpldmFuOnRlc3Rjb3JlOjB4OGIwNzhlZTZjZmIyMDhkY2E1MmJmODlhYjcxNzhlMGYxMTMyM2Y0MzYzYzFhNmFkMTgzMjEyNzVlNmQwN2ZjYiIsImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL3Rlc3Rjb3JlLmV2YW4ubmV0d29yay92Yy9zdGF0dXMvdmM6ZXZhbjp0ZXN0Y29yZToweDhiMDc4ZWU2Y2ZiMjA4ZGNhNTJiZjg5YWI3MTc4ZTBmMTEzMjNmNDM2M2MxYTZhZDE4MzIxMjc1ZTZkMDdmY2IiLCJ0eXBlIjoiZXZhbjpldmFuQ3JlZGVudGlhbCJ9fSwiaXNzIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZWYwZTU4NGM3MTQ1NjRhNGZjMGM2YzM2N2VkY2NiMGMxY2JmNjVmIn0.IMPiWh1fEeVN8n7FlhFzG8bEzPafX7-H04OwLSTi4Wh7wxpanoq_4nUcsC9LlrxNALSKf8cUJUb03xir4uGBpAE" } }
"###;

const EXAMPLE_DID: &str = "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f";
const EXAMPLE_DID_DOCUMENT_STR: &str = r###"
{ "@context": "https://w3id.org/did/v1",
  "id":
   "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f",
  "publicKey":
   [ { "id":
        "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f#key-1",
       "type": "Secp256k1VerificationKey2018",
       "controller":
        "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f",
       "ethereumAddress": "0x001de828935e8c7e4cb56fe610495cae63fb2612" } ],
  "authentication":
   [ "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f#key-1" ] }
"###;

#[tokio::test]
async fn can_fetch_a_vc_document() {
    let rde = RustVcResolverEvan::new();
    let mut vade = Vade::new();
    vade.register_vc_resolver(Box::from(rde));

    let vc = vade.get_vc_document(&EXAMPLE_VC_NAME_REMOTE).await.unwrap();
    let parsed: Value = serde_json::from_str(&vc).unwrap();
    assert!(&EXAMPLE_VC_NAME_REMOTE == &parsed["id"]);

    let parsed_example: Value = serde_json::from_str(&EXAMPLE_VC_DOCUMENT_STR_REMOTE).unwrap();
    assert!(parsed_example == parsed);
}

#[tokio::test]
async fn returns_an_error_for_invalid_vc_ids() {
    let rde = RustVcResolverEvan::new();
    let mut vade = Vade::new();
    vade.register_vc_resolver(Box::from(rde));

    let vc_name = "vc:evan:testcore:invalid";
    let vc_result = vade.get_vc_document(&vc_name).await;
    match vc_result {
        Ok(_vc) => panic!("unexpected vc document"),
        Err(e) => assert!(format!("{}", e) == "could not get vc document"),
    }
}

// race
#[tokio::test]
async fn can_handle_racing_resolvers_1() {
    let mut vade = Vade::new();
    let rde = RustVcResolverEvan::new();
    vade.register_vc_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    vade.register_vc_resolver(Box::from(storage));
    let vc = vade.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    assert!(vc == EXAMPLE_VC_DOCUMENT_STR);
}

#[tokio::test]
async fn can_handle_racing_resolvers_2() {
    let mut vade = Vade::new();
    let rde = RustVcResolverEvan::new();
    vade.register_vc_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_VC_NAME, "qwer").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    let vc_result = vade.get_vc_document("something different").await;
    match vc_result {
        Ok(_vc) => panic!("unexpected vc document"),
        Err(e) => assert!(format!("{}", e) == "could not get vc document"),
    }
}

#[allow(dead_code)]
// currently diabled as `RustVcResolverEvan` does not implement `set_did_document` atm
// #[tokio::test]
async fn can_handle_racing_resolvers_3() {
    let mut vade = Vade::new();

    let mut rde = RustVcResolverEvan::new();
    let mut rde_did_resolver = RustStorageCache::new();
    match rde_did_resolver.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };
    let mut rde_vade = Vade::new();
    rde_vade.register_did_resolver(Box::from(rde_did_resolver));
    rde.vade = Some(Box::from(rde_vade));
    vade.register_vc_resolver(Box::from(rde));

    let storage = RustStorageCache::new();

    match vade.set_did_document(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    vade.register_vc_resolver(Box::from(storage));
    let vc = vade.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    println!("{:?}", &vc);
    println!("{:?}", &EXAMPLE_VC_DOCUMENT_STR);
    assert!(vc == EXAMPLE_VC_DOCUMENT_STR);
}

#[tokio::test]
async fn can_validate_valid_vcs() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // create a vc resolver with attached did resolver in a vade
    let vcr_didr = RustStorageCache::new();
    let mut vcr_vade = Vade::new();
    vcr_vade.register_did_resolver(Box::from(vcr_didr));
    // add did document to vcr's did resolver
    vcr_vade.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await?;
    let mut vcr = RustVcResolverEvan::new();
    vcr.vade = Some(Box::from(vcr_vade));

    // create vade to work with, attach 
    let mut vade = Vade::new();
    vade.register_vc_resolver(Box::from(vcr));

    // test VC document
    let vc_result = vade.check_vc(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_STR).await;
    match vc_result {
        Ok(_) => (),
        Err(e) => panic!(format!("{}", e)),
    }

    Ok(())
}

#[tokio::test]
async fn cannot_validate_invalid_vcs() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // create a vc resolver with attached did resolver in a vade
    let vcr_didr = RustStorageCache::new();
    let mut vcr_vade = Vade::new();
    vcr_vade.register_did_resolver(Box::from(vcr_didr));
    // add did document to vcr's did resolver
    vcr_vade.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await?;
    let mut vcr = RustVcResolverEvan::new();
    vcr.vade = Some(Box::from(vcr_vade));

    // create vade to work with, attach 
    let mut vade = Vade::new();
    vade.register_vc_resolver(Box::from(vcr));

    // test invalid VC document
    let vc_result = vade.check_vc(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_MANIPULATED_STR).await;
    match vc_result {
        Ok(_) => panic!("manipulated VC document recocnized as valid"),
        Err(_) => (),
    }

    Ok(())
}

#[tokio::test]
async fn can_create_new_vcs() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let veri_issuer = "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f";
    let veri_method = "did:evan:testcore:0x0ef0e584c714564a4fc0c6c367edccb0c1cbf65f#key-1";
    let veri_pkey = "01734663843202e2245e5796cb120510506343c67915eb4f9348ac0d8c2cf22a";
    let partial_vc_data =r###"
    {
        "id": "foo-bar-vc",
        "credentialSubject": {
            "foo": "bar"
        }
    } 
"###;

    let mut vcr = RustVcResolverEvan::new();

    let vc: String = vcr.create_vc(partial_vc_data, &veri_method, &veri_pkey).await.unwrap();

    let parsed: Value = serde_json::from_str(&vc).unwrap();

    assert!(parsed["credentialSubject"]["foo"].as_str() == Some("bar"));
    assert!(parsed["@context"].as_array().unwrap().len() == 1);
    assert!(parsed["@context"].as_array().unwrap().iter().any(|v| v == VC_W3C_MANDATORY_CONTEXT));
    assert!(parsed["type"].as_str() == Some(VC_DEFAULT_TYPE));
    assert!(parsed["issuer"].as_str() == Some(veri_issuer));
    assert!(parsed["validFrom"].as_str() != None);

    // test VC document
    let vcr_didr = RustStorageCache::new();
    let mut vcr_vade = Vade::new();
    vcr_vade.register_did_resolver(Box::from(vcr_didr));
    // add did document to vcr's did resolver
    vcr_vade.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await?;
    vcr.vade = Some(Box::from(vcr_vade));

    // create vade to work with, attach 
    let mut vade = Vade::new();
    vade.register_vc_resolver(Box::from(vcr));

    // test VC document
    let vc_result = vade.check_vc("foo-bar-vc", &vc).await;
    match vc_result {
        Ok(_) => (),
        Err(e) => panic!(format!("{}", e)),
    }

    Ok(())
}

