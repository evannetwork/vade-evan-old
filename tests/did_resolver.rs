extern crate vade_evan;

use vade::Vade;
use vade::plugin::rust_storage_cache::RustStorageCache;
use vade_evan::plugin::rust_didresolver_evan::RustDidResolverEvan;
use serde_json::Value;

const EXAMPLE_DID: &str = "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad";
const EXAMPLE_DID_DOCUMENT_STR: &str = r###"
{
    "did": {
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
    },
    "status": "success",
    "serverInformation": {
        "serverName": "edge-server",
        "apiVersion": "1.2.1",
        "requestDuration": 49,
        "currentTime": 1584086999487
    },
    "requesterInformation": {
        "id": "d928491de5455f96f54a26fc9e6f65ff94f39653-2c093c7f-85be-4bbf-bf02-46a1a1745308",
        "fingerprint": "d928491de5455f96f54a26fc9e6f65ff94f39653",
        "messageId": "2c093c7f-85be-4bbf-bf02-46a1a1745308",
        "remoteIP": "79.232.30.142",
        "receivedParams": {
        "did": "did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad",
        "action": "smart-agents/smart-agent-did-resolver/did/get/:did"
        }
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