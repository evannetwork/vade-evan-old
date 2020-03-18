extern crate secp256k1;
extern crate sha3;
extern crate ssi_evan;

use serde_json::Value;
use ssi_evan::plugin::rust_vcresolver_evan::RustVcResolverEvan;
use ssi::library::Library;
use ssi::library::traits::DidResolver;
use ssi::plugin::rust_storage_cache::RustStorageCache;

const EXAMPLE_VC_NAME: &str = "vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3";
const EXAMPLE_VC_DOCUMENT_STR: &str = r###"
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1"
    ],
    "credentialStatus": {
        "id": "https://testcore.evan.network/vc/vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3",
        "type": "evan:evanCredential"
    },
    "credentialSubject": {
        "data": [
            {
                "name": "isTrustedSupplier",
                "value": "true"
            }
        ],
        "id": "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f"
    },
    "id": "vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3",
    "issuer": {
        "id": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad"
    },
    "proof": {
        "created": "2020-02-25T09:48:58.451Z",
        "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI2MjQxMzgsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg5NmRhODU0ZGYzNGY1ZGNkMjU3OTNiNzVlMTcwYjNkOGM2M2E5NWFkIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2N2NlOGIwMWIzYjc1YTliYTRhMTQ2MjEzOWExZWRhYTBkMmY1MzlmIiwiZGF0YSI6W3sibmFtZSI6ImlzVHJ1c3RlZFN1cHBsaWVyIiwidmFsdWUiOiJ0cnVlIn1dfSwidmFsaWRGcm9tIjoiMjAyMC0wMi0yNVQwOTo0ODo1Ny42NjBaIiwiaWQiOiJ2YzpldmFuOnRlc3Rjb3JlOjB4NmU5MGEzZTJiZjM4MjNlNTJlY2ViMGY4MTM3M2ViNThiMWEwYTIzODk2NWYwZDQzODhhYjljZTljZWVkZGZkMyIsImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL3Rlc3Rjb3JlLmV2YW4ubmV0d29yay92Yy92YzpldmFuOnRlc3Rjb3JlOjB4NmU5MGEzZTJiZjM4MjNlNTJlY2ViMGY4MTM3M2ViNThiMWEwYTIzODk2NWYwZDQzODhhYjljZTljZWVkZGZkMyIsInR5cGUiOiJldmFuOmV2YW5DcmVkZW50aWFsIn19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2ZGE4NTRkZjM0ZjVkY2QyNTc5M2I3NWUxNzBiM2Q4YzYzYTk1YWQifQ.IC8Zb8a1o3OVRh113DX8OSlZuan8jBo_jOWrD_cxovKZs374KKiSTqZD1Uo-Y4jxxCS3dp845nKKeEtPUO6OQQE",
        "proofPurpose": "assertionMethod",
        "type": "EcdsaPublicKeySecp256k1",
        "verificationMethod": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad#key-1"
    },
    "type": [
        "VerifiableCredential"
    ],
    "validFrom": "2020-02-25T09:48:57.660Z"
}
"###;
const EXAMPLE_VC_DOCUMENT_MANIPULATED_STR: &str = r###"
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1"
    ],
    "credentialStatus": {
        "id": "https://testcore.evan.network/vc/vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3",
        "type": "evan:evanCredential"
    },
    "credentialSubject": {
        "data": [
            {
                "name": "isTrustedSupplier",
                "value": "false"
            }
        ],
        "id": "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f"
    },
    "id": "vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3",
    "issuer": {
        "id": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad"
    },
    "proof": {
        "created": "2020-02-25T09:48:58.451Z",
        "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI2MjQxMzgsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg5NmRhODU0ZGYzNGY1ZGNkMjU3OTNiNzVlMTcwYjNkOGM2M2E5NWFkIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2N2NlOGIwMWIzYjc1YTliYTRhMTQ2MjEzOWExZWRhYTBkMmY1MzlmIiwiZGF0YSI6W3sibmFtZSI6ImlzVHJ1c3RlZFN1cHBsaWVyIiwidmFsdWUiOiJ0cnVlIn1dfSwidmFsaWRGcm9tIjoiMjAyMC0wMi0yNVQwOTo0ODo1Ny42NjBaIiwiaWQiOiJ2YzpldmFuOnRlc3Rjb3JlOjB4NmU5MGEzZTJiZjM4MjNlNTJlY2ViMGY4MTM3M2ViNThiMWEwYTIzODk2NWYwZDQzODhhYjljZTljZWVkZGZkMyIsImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL3Rlc3Rjb3JlLmV2YW4ubmV0d29yay92Yy92YzpldmFuOnRlc3Rjb3JlOjB4NmU5MGEzZTJiZjM4MjNlNTJlY2ViMGY4MTM3M2ViNThiMWEwYTIzODk2NWYwZDQzODhhYjljZTljZWVkZGZkMyIsInR5cGUiOiJldmFuOmV2YW5DcmVkZW50aWFsIn19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2ZGE4NTRkZjM0ZjVkY2QyNTc5M2I3NWUxNzBiM2Q4YzYzYTk1YWQifQ.IC8Zb8a1o3OVRh113DX8OSlZuan8jBo_jOWrD_cxovKZs374KKiSTqZD1Uo-Y4jxxCS3dp845nKKeEtPUO6OQQE",
        "proofPurpose": "assertionMethod",
        "type": "EcdsaPublicKeySecp256k1",
        "verificationMethod": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad#key-1"
    },
    "type": [
        "VerifiableCredential"
    ],
    "validFrom": "2020-02-25T09:48:57.660Z"
}
"###;

const EXAMPLE_DID: &str = "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad";
const EXAMPLE_DID_DOCUMENT_STR: &str = r###"
{
    "@context": "https://w3id.org/did/v1",
    "id": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad",
    "publicKey": [
        {
            "id": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad#key-1",
            "type": "Secp256k1VerificationKey2018",
            "owner": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad",
            "ethereumAddress": "0x001de828935e8c7e4cb56fe610495cae63fb2612"
        }
    ],
    "authentication": [
        "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad#key-1"
    ],
    "created": "2020-02-17T09:14:25.915Z",
    "updated": "2020-02-17T09:14:25.915Z",
    "proof": {
        "type": "EcdsaPublicKeySecp256k1",
        "created": "2020-02-17T09:14:25.933Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad#key-1",
        "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODE5MzA4NjUsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4OTZkYTg1NGRmMzRmNWRjZDI1NzkzYjc1ZTE3MGIzZDhjNjNhOTVhZCIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2ZGE4NTRkZjM0ZjVkY2QyNTc5M2I3NWUxNzBiM2Q4YzYzYTk1YWQja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsIm93bmVyIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg5NmRhODU0ZGYzNGY1ZGNkMjU3OTNiNzVlMTcwYjNkOGM2M2E5NWFkIiwiZXRoZXJldW1BZGRyZXNzIjoiMHgwMDFkZTgyODkzNWU4YzdlNGNiNTZmZTYxMDQ5NWNhZTYzZmIyNjEyIn1dLCJhdXRoZW50aWNhdGlvbiI6WyJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2ZGE4NTRkZjM0ZjVkY2QyNTc5M2I3NWUxNzBiM2Q4YzYzYTk1YWQja2V5LTEiXSwiY3JlYXRlZCI6IjIwMjAtMDItMTdUMDk6MTQ6MjUuOTE1WiIsInVwZGF0ZWQiOiIyMDIwLTAyLTE3VDA5OjE0OjI1LjkxNVoifSwiaXNzIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg5NmRhODU0ZGYzNGY1ZGNkMjU3OTNiNzVlMTcwYjNkOGM2M2E5NWFkIn0.yBMpk9cQikhHv3MEEXr4w3po9AZWLRtqhbW7iQ0L0e0Ylxkg5R4z9niOXuVpwueVjNP-tCNOa5HBCIJqnDts6wA"
    }
}
"###;

#[tokio::test]
async fn can_fetch_a_vc_document() {
    let rde = RustVcResolverEvan::new();
    let mut library = Library::new();
    library.register_vc_resolver(Box::from(rde));

    let vc = library.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    let parsed: Value = serde_json::from_str(&vc).unwrap();
    assert!(&EXAMPLE_VC_NAME == &parsed["id"]);
}

#[tokio::test]
async fn returns_an_error_for_invalid_vc_ids() {
    let rde = RustVcResolverEvan::new();
    let mut library = Library::new();
    library.register_vc_resolver(Box::from(rde));

    let vc_name = "vc:evan:testcore:invalid";
    let vc_result = library.get_vc_document(&vc_name).await;
    match vc_result {
        Ok(_vc) => panic!("unexpected vc document"),
        Err(e) => assert!(format!("{}", e) == "could not get vc document"),
    }
}

// race
#[tokio::test]
async fn can_handle_racing_resolvers_1() {
    let mut library = Library::new();
    let rde = RustVcResolverEvan::new();
    library.register_vc_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    library.register_vc_resolver(Box::from(storage));
    let vc = library.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    assert!(vc == EXAMPLE_VC_DOCUMENT_STR);
}

#[tokio::test]
async fn can_handle_racing_resolvers_2() {
    let mut library = Library::new();
    let rde = RustVcResolverEvan::new();
    library.register_vc_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_VC_NAME, "qwer").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    let vc_result = library.get_vc_document("something different").await;
    match vc_result {
        Ok(_vc) => panic!("unexpected vc document"),
        Err(e) => assert!(format!("{}", e) == "could not get vc document"),
    }
}

#[allow(dead_code)]
// currently diabled as `RustVcResolverEvan` does not implement `set_did_document` atm
// #[tokio::test]
async fn can_handle_racing_resolvers_3() {
    let mut library = Library::new();

    let mut rde = RustVcResolverEvan::new();
    let mut rde_did_resolver = RustStorageCache::new();
    match rde_did_resolver.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };
    let mut rde_library = Library::new();
    rde_library.register_did_resolver(Box::from(rde_did_resolver));
    rde.library = Some(Box::from(rde_library));
    library.register_vc_resolver(Box::from(rde));

    let storage = RustStorageCache::new();

    match library.set_did_document(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_STR).await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    library.register_vc_resolver(Box::from(storage));
    let vc = library.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    println!("{:?}", &vc);
    println!("{:?}", &EXAMPLE_VC_DOCUMENT_STR);
    assert!(vc == EXAMPLE_VC_DOCUMENT_STR);
}

#[tokio::test]
async fn can_validate_vcs() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // create a vc resolver with attached did resolver in a library
    let vcr_didr = RustStorageCache::new();
    let mut vcr_library = Library::new();
    vcr_library.register_did_resolver(Box::from(vcr_didr));
    // add did document to vcr's did resolver
    vcr_library.set_did_document(EXAMPLE_DID, EXAMPLE_DID_DOCUMENT_STR).await?;
    let mut vcr = RustVcResolverEvan::new();
    vcr.library = Some(Box::from(vcr_library));

    // create library to work with, attach 
    let mut library = Library::new();
    library.register_vc_resolver(Box::from(vcr));

    // test VC document
    let vc_result = library.check_vc(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_STR).await;
    match vc_result {
        Ok(_) => (),
        Err(e) => panic!(format!("{}", e)),
    }

    // test invalid VC document
    let vc_result = library.check_vc(EXAMPLE_VC_NAME, EXAMPLE_VC_DOCUMENT_MANIPULATED_STR).await;
    match vc_result {
        Ok(_) => panic!("manipulated VC document recocnized as valid"),
        Err(_) => (),
    }

    Ok(())
}
