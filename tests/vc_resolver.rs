extern crate ssi_evan;

use ssi::library::Library;
use ssi::plugin::rust_storage_cache::RustStorageCache;
use ssi_evan::plugin::rust_vcresolver_evan::RustVcResolverEvan;
use serde_json::Value;

const EXAMPLE_VC_NAME: &str = "vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3";
const EXAMPLE_VC_DOCUMENT_STR: &str = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialStatus\":{\"id\":\"https://testcore.evan.network/vc/vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3\",\"type\":\"evan:evanCredential\"},\"credentialSubject\":{\"data\":[{\"name\":\"isTrustedSupplier\",\"value\":\"true\"}],\"id\":\"did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f\"},\"id\":\"vc:evan:testcore:0x6e90a3e2bf3823e52eceb0f81373eb58b1a0a238965f0d4388ab9ce9ceeddfd3\",\"issuer\":{\"id\":\"did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad\"},\"proof\":{\"created\":\"2020-02-25T09:48:58.451Z\",\"jws\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODI2MjQxMzgsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg5NmRhODU0ZGYzNGY1ZGNkMjU3OTNiNzVlMTcwYjNkOGM2M2E5NWFkIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2N2NlOGIwMWIzYjc1YTliYTRhMTQ2MjEzOWExZWRhYTBkMmY1MzlmIiwiZGF0YSI6W3sibmFtZSI6ImlzVHJ1c3RlZFN1cHBsaWVyIiwidmFsdWUiOiJ0cnVlIn1dfSwidmFsaWRGcm9tIjoiMjAyMC0wMi0yNVQwOTo0ODo1Ny42NjBaIiwiaWQiOiJ2YzpldmFuOnRlc3Rjb3JlOjB4NmU5MGEzZTJiZjM4MjNlNTJlY2ViMGY4MTM3M2ViNThiMWEwYTIzODk2NWYwZDQzODhhYjljZTljZWVkZGZkMyIsImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL3Rlc3Rjb3JlLmV2YW4ubmV0d29yay92Yy92YzpldmFuOnRlc3Rjb3JlOjB4NmU5MGEzZTJiZjM4MjNlNTJlY2ViMGY4MTM3M2ViNThiMWEwYTIzODk2NWYwZDQzODhhYjljZTljZWVkZGZkMyIsInR5cGUiOiJldmFuOmV2YW5DcmVkZW50aWFsIn19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2ZGE4NTRkZjM0ZjVkY2QyNTc5M2I3NWUxNzBiM2Q4YzYzYTk1YWQifQ.IC8Zb8a1o3OVRh113DX8OSlZuan8jBo_jOWrD_cxovKZs374KKiSTqZD1Uo-Y4jxxCS3dp845nKKeEtPUO6OQQE\",\"proofPurpose\":\"assertionMethod\",\"type\":\"EcdsaPublicKeySecp256k1\",\"verificationMethod\":\"did:evan:testcore:0x96da854df34f5dcd25793b75e170b3d8c63a95ad#key-1\"},\"type\":[\"VerifiableCredential\"],\"validFrom\":\"2020-02-25T09:48:57.660Z\"}";

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

    match storage.set(EXAMPLE_VC_NAME, "local value").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    library.register_vc_resolver(Box::from(storage));
    let vc = library.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    assert!(vc == "local value");
}

#[tokio::test]
async fn can_handle_racing_resolvers_2() {
    let mut library = Library::new();
    let rde = RustVcResolverEvan::new();
    library.register_vc_resolver(Box::from(rde));
    let mut storage = RustStorageCache::new();

    match storage.set("something different", "local value").await {
        Ok(()) => (),
        Err(e) => panic!(format!("{}", e)),
    };

    library.register_vc_resolver(Box::from(storage));
    let vc = library.get_vc_document(&EXAMPLE_VC_NAME).await.unwrap();
    println!("{:?}", &vc);
    assert!(vc == String::from(EXAMPLE_VC_DOCUMENT_STR));
}

#[tokio::test]
async fn can_handle_racing_resolvers_3() {
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
