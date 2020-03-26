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

use async_trait::async_trait;
use data_encoding::BASE64URL;
use regex::Regex;
use reqwest;
use secp256k1::{Message, Signature, recover, RecoveryId};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use simple_error::SimpleError;
use vade::traits::VcResolver;
use vade::Vade;
use std::str;

const JWT_REGEX: &'static str = r#"^\{"iat":[^,]+,"vc":(.*),"iss":"[^"]+?"\}$"#;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
/// type to cover required fields in evan.network DID documents for key handling,
/// does NOT reflect a full evan.network DID document
struct EvanDid {
    pub publicKey: Vec<EvanDidPublicKey>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
/// type to cover required fields in evan.network DID documents for key handling,
/// does NOT reflect a full evan.network DID document
struct EvanDidPublicKey {
    pub ethereumAddress: String,
    pub id: String,
}

/// Resolver for DIDs on evan.network (currently on testnet)
pub struct RustVcResolverEvan {
    pub vade: Option<Box<Vade>>,
}

impl RustVcResolverEvan {
    /// Creates new instance of `RustVcResolverEvan`.
    pub fn new() -> RustVcResolverEvan {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        RustVcResolverEvan {
            vade: None,
        }
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

    /// Gets all keys from given DID. `self.vade` will be queried for DID, then public keys are checked for keys.
    ///
    /// # Arguments
    /// 
    /// * `key_from_did` - key reference to a DID document like "$DID#key-1"
    async fn get_key_from_did(&self, key_from_did: &str) -> Result<String, Box<dyn std::error::Error>> {
        let did = key_from_did.splitn(2, '#').next().unwrap();
        debug!("getting keys for did {:?}", &did);
        let did_document_string = self.vade.as_ref().unwrap().get_did_document(did).await.unwrap();
        let did_document: EvanDid = serde_json::from_str(&did_document_string)?;

        let key_objects: Vec<EvanDidPublicKey> = did_document.publicKey;
        let matches: Vec<String> = key_objects
            .into_iter()
            .filter(|key| key.id == key_from_did)
            .map(|key| key.ethereumAddress)
            .collect();
 
        match matches.len() {
            1 => Ok(format!("{}", matches[0])),
            0 => Err(Box::from(format!("key {} not found in DID {}", key_from_did, did))),
            _ => Err(Box::from(format!("multiple matches found for key {} in DID {}", key_from_did, did))),
        }
    }
}


#[async_trait]
impl VcResolver for RustVcResolverEvan {
    /// Checks given Vc document.
    /// A Vc document is considered as valid if returning ().
    /// Resolver may throw to indicate
    /// - that it is not responsible for this Vc
    /// - that it considers this Vc as invalid
    /// 
    /// Currently the test `vc_id` `"test"` is accepted as valid.
    ///
    /// # Arguments
    ///
    /// * `vc_id` - vc_id to check document for
    /// * `value` - value to check
    async fn check_vc(&self, vc_id: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: add some pre-flight checks (key type, etc)
        let mut vc: Value = serde_json::from_str(value)?;
        if vc["proof"].is_null() {
            debug!("vcs without a proof are considered as valid");
            Ok(())
        } else {
            debug!("checking vc document");

            // separate proof and vc document (vc document will be a Map after this)
            let vc_without_proof = vc.as_object_mut().unwrap();
            let vc_proof =  vc_without_proof.remove("proof").unwrap();

            // recover address and payload text (pure jwt format)
            let (address, decoded_payload_text) = recover_address_and_data(vc_proof["jws"].as_str().unwrap())?;

            debug!("checking if document given and document from jws are equal");
            // fetch recovered vc document (without proof from jwt)
            let re = Regex::new(JWT_REGEX).unwrap();
            let caps = re.captures(&decoded_payload_text).unwrap();
            // parse recovered vc document into serde Map
            let parsed_caps1: Value = serde_json::from_str(&caps[1])?;
            let parsed_caps1_map = parsed_caps1.as_object().unwrap();
            // compare documents
            if vc_without_proof != parsed_caps1_map {
                return Err(Box::from("recovered VC document and given VC document do not match"));
            }

            debug!("checking proof of vc document");
            let address = format!("0x{}", address);
            let key_to_use = vc_proof["verificationMethod"].as_str().unwrap();
            debug!("recovered address: {}", &address);
            debug!("key to use for verification: {}", &key_to_use);
            let key_from_did = self.get_key_from_did(key_to_use).await?;
            if address != key_from_did {
                return Err(Box::from(format!("could not verify signature of \"{}\"", vc_id)));
            }

            debug!("checking if credential status is present, query it");
            if !vc["credentialStatus"].is_null()
                    && vc["credentialStatus"]["type"] == "evan:evanCredential" {
                debug!("credential status is present, query it");
                let vc_status = get_vc_status_valid(vc["credentialStatus"]["id"].as_str().unwrap()).await?;
                if !vc_status {
                  return Err(Box::from(format!("vc \"{}\" is not active", &vc_id)));
                }
            }
            
            debug!("vc document is valid");
            Ok(())
        }
    }

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

/// Fetches revokation status for VCs. VCs can be active or revoked (-> true/false)
/// missing VC documents or other errors are indicated as Errors.
///
/// # Arguments
///
/// * `vc_status_id` - vc status id / url to query
async fn get_vc_status_valid(vc_status_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let body = reqwest::get(vc_status_id)
        .await?
        .text()
        .await?;
    let parsed: Value = serde_json::from_str(&body).unwrap();
    if parsed["status"] == "error" {
        Err(Box::new(SimpleError::new(format!("vc status error, {:?}", parsed["error"].as_str().unwrap()))))
    } else {
        let is_active = match parsed["vcStatus"].as_str().unwrap() {
            "active" => true,
            _ => false,
        };
        Ok(is_active)
    }
}

/// Recovers Ethereum address of signer and data part of a jwt.
///
/// # Arguments
///
/// * `jwt` - jwt as str&
fn recover_address_and_data(jwt: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    // jwt text parsing
    let split: Vec<&str> = jwt.split('.').collect();
    let (header, data, signature) = (split[0], split[1], split[2]);
    let header_and_data = format!("{}.{}", header, data);
    
    // recover data for later checks
    let data_decoded = match BASE64URL.decode(data.as_bytes()) {
        Ok(decoded) => decoded,
        Err(_) => match BASE64URL.decode(format!("{}=", data).as_bytes()) {
            Ok(decoded) => decoded,
            Err(_) => match BASE64URL.decode(format!("{}==", data).as_bytes()) {
                Ok(decoded) => decoded,
                Err(_) => BASE64URL.decode(format!("{}===", data).as_bytes()).unwrap(),
            },
        },
    };
    let data_string = String::from_utf8(data_decoded)?;

    // decode signature for validation
    let signature_decoded = match BASE64URL.decode(signature.as_bytes()) {
        Ok(decoded) => decoded,
        Err(_) => BASE64URL.decode(format!("{}=", signature).as_bytes()).unwrap(),
    };
    debug!("signature_decoded {:?}", &signature_decoded);
    debug!("signature_decoded.len {:?}", signature_decoded.len());

    // create hash of data (including header)
    let mut hasher = Sha256::new();
    hasher.input(&header_and_data);
    let hash = hasher.result();
    debug!("header_and_data hash {:?}", hash);

    // prepare arguments for public key recovery
    let mut hash_array = [0u8; 32];
    for i in 0..32 {
        hash_array[i] = hash[i];
    }
    let ctx_msg = Message::parse(&hash_array);
    let mut signature_array = [0u8; 64];
    for i in 0..64 {
        signature_array[i] = signature_decoded[i];
    }
    let ctx_sig = Signature::parse(&signature_array);
    let recovery_id = RecoveryId::parse(1).unwrap();

    // recover public key, build ethereum address from it
    let recovered_key = recover(&ctx_msg, &ctx_sig, &recovery_id).unwrap();
    let mut hasher = Keccak256::new();
    hasher.input(&recovered_key.serialize()[1..65]);
    let hash = hasher.result();
    debug!("recovered_key hash {:?}", hash);
    let address = hex::encode(&hash[12..32]);
    debug!("address 0x{}", &address);

    Ok((address, data_string))
}
