extern crate ssi_evan;

use ssi::library::Library;
use ssi::plugin::rust_storage_cache::RustStorageCache;
use ssi_evan::plugin::rust_didresolver_evan::RustDidResolverEvan;
use serde_json::Value;

const EXAMPLE_DID: &str = "did:evan:testcore:0x126E901F6F408f5E260d95c62E7c73D9B60fd734";
const EXAMPLE_DID_DOCUMENT_STR: &str = "{\"@context\":\"https://w3id.org/did/v1\",\"authentication\":[\"did:evan:testcore:0x126E901F6F408f5E260d95c62E7c73D9B60fd734#key-1\"],\"id\":\"did:evan:testcore:0x126E901F6F408f5E260d95c62E7c73D9B60fd734\",\"publicKey\":[{\"id\":\"did:evan:testcore:0x126E901F6F408f5E260d95c62E7c73D9B60fd734#key-1\",\"publicKeyHex\":\"045adfd502c0bc55f4fcb90eea36368d7e19c5b3045aa6f51dfa3699046e9751251d21bc6bdd06c1ff0014fcbbf9f1d83c714434f2b33d713aaf46760f2d53f10d\",\"type\":\"Secp256k1SignatureVerificationKey2018\"}],\"service\":[{\"id\":\"did:evan:testcore:0x126E901F6F408f5E260d95c62E7c73D9B60fd734#randomService\",\"serviceEndpoint\":\"https://openid.example.com/770853367\",\"type\":\"randomService-770853367\"}]}";

#[tokio::test]
async fn can_fetch_a_did_document() {
    let rde = RustDidResolverEvan::new();
    let mut library = Library::new();
    library.register_did_resolver(Box::from(rde));

    let did = library.get_did_document(&EXAMPLE_DID).await.unwrap();
    let parsed: Value = serde_json::from_str(&did).unwrap();
    assert!(&EXAMPLE_DID == &parsed["id"]);
}

#[tokio::test]
async fn returns_an_error_for_invalid_did_ids() {
    let rde = RustDidResolverEvan::new();
    let mut library = Library::new();
    library.register_did_resolver(Box::from(rde));

    let did_name = "did:evan:testcore:invalid";
    let did_result = library.get_did_document(&did_name).await;
    match did_result {
        Ok(_did) => panic!("unexpected did document"),
        Err(e) => assert!(format!("{}", e) == "could not get did document"),
    }
}

// race
#[tokio::test]
async fn can_handle_racing_resolvers_1() {
    let mut library = Library::new();
    let rde = RustDidResolverEvan::new();
    library.register_did_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_DID, "local value").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    library.register_did_resolver(Box::from(storage));
    let did = library.get_did_document(&EXAMPLE_DID).await.unwrap();
    assert!(did == "local value");
}

#[tokio::test]
async fn can_handle_racing_resolvers_2() {
    let mut library = Library::new();
    let rde = RustDidResolverEvan::new();
    library.register_did_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set("something different", "local value").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    library.register_did_resolver(Box::from(storage));
    let did = library.get_did_document(&EXAMPLE_DID).await.unwrap();
    println!("{:?}", &did);
    assert!(did == String::from(EXAMPLE_DID_DOCUMENT_STR));
}

#[tokio::test]
async fn can_handle_racing_resolvers_3() {
    let mut library = Library::new();
    let rde = RustDidResolverEvan::new();
    library.register_did_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set(EXAMPLE_DID, "qwer").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    let did_result = library.get_did_document("something different").await;
    match did_result {
        Ok(_did) => panic!("unexpected did document"),
        Err(e) => assert!(format!("{}", e) == "could not get did document"),
    }
}
