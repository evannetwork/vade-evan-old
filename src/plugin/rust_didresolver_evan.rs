use reqwest;
use async_trait::async_trait;
use vade::traits::{ DidResolver };
use serde_json::Value;
use simple_error::SimpleError;

/// Resolver for DIDs on evan.network (currently on testnet)
pub struct RustDidResolverEvan {
}

impl RustDidResolverEvan {
    /// Creates new instance of `RustDidResolverEvan`.
    pub fn new() -> RustDidResolverEvan {
        RustDidResolverEvan { }
    }
}

#[async_trait]
impl DidResolver for RustDidResolverEvan {
    /// Checks given DID document.
    /// A DID document is considered as valid if returning ().
    /// Resolver may throw to indicate
    /// - that it is not responsible for this DID
    /// - that it considers this DID as invalid
    /// 
    /// Currently the test `did_name` `"test"` is accepted as valid.
    ///
    /// # Arguments
    ///
    /// * `did_name` - did_name to check document for
    /// * `value` - value to check
    async fn check_did(&self, _did_name: &str, _value: &str) -> Result<(), Box<dyn std::error::Error>> {
        unimplemented!();
    }

    /// Gets document for given did name.
    ///
    /// # Arguments
    ///
    /// * `did_name` - did_name to fetch
    async fn get_did_document(&self, did_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        let body = reqwest::get(&format!("https://testcore.evan.network/did/{}", did_id))
            .await?
            .text()
            .await?;
        let parsed: Value = serde_json::from_str(&body).unwrap();
        if parsed["status"] == "error" {
            Err(Box::new(SimpleError::new(format!("could not get did document, {:?}", parsed["error"].as_str().unwrap()))))
        } else {
            Ok(serde_json::to_string(&parsed["did"]).unwrap())
        }
    }

    /// Sets document for given did name.
    ///
    /// # Arguments
    ///
    /// * `did_name` - did_name to set value for
    /// * `value` - value to set
    async fn set_did_document(&mut self, _did_id: &str, _value: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
        unimplemented!();
    }
}
