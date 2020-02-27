use reqwest;
use async_trait::async_trait;
use ssi::library::traits::{ VcResolver };
use serde_json::Value;
use simple_error::SimpleError;

/// Resolver for DIDs on evan.network (currently on testnet)
pub struct RustVcResolverEvan {
}

impl RustVcResolverEvan {
    /// Creates new instance of `RustVcResolverEvan`.
    pub fn new() -> RustVcResolverEvan {
        RustVcResolverEvan { }
    }

    /// Sets document for given vc name.
    ///
    /// # Arguments
    ///
    /// * `vc_id` - vc_id to set value for
    /// * `value` - value to set
    #[allow(dead_code)]
    async fn set_vc_document(&mut self, _vc_id: &str, _value: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
        unimplemented!();
    }
}

#[async_trait]
impl VcResolver for RustVcResolverEvan {
    /// Gets document for given vc name.
    ///
    /// # Arguments
    ///
    /// * `vc_id` - vc_id to fetch
    async fn get_vc_document(&self, vc_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        let body = reqwest::get(&format!("https://testcore.evan.network/vc/{}", vc_id))
            .await?
            .text()
            .await?;
        let parsed: Value = serde_json::from_str(&body).unwrap();
        if parsed["status"] == "error" {
            Err(Box::new(SimpleError::new(format!("could not get vc document, {:?}", parsed["error"].as_str().unwrap()))))
        } else {
            Ok(serde_json::to_string(&parsed["vc"]).unwrap())
        }
    }
    
    /// Sets document for given vc name.
    ///
    /// # Arguments
    ///
    /// * `vc_name` - vc_name to set value for
    /// * `value` - value to set
    async fn set_vc_document(&mut self, _vc_name: &str, _value: &str) -> Result<(), Box<dyn std::error::Error>> {
        unimplemented!();
    }
}
