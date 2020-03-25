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

use vade::traits::{ Logger };
use std::any::Any;

pub struct RustLogger {

}

impl RustLogger {
    pub fn new() -> RustLogger {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        RustLogger { }
    }
}

impl Logger for RustLogger {
    /// Cast to `Any` for downcasting.
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    fn log(&self, message: &str, level: Option<&str>) {
        match level {
            Some("error") => error!("{}", message),
            Some("warn")  => warn!("{}", message),
            Some("debug") => debug!("{}", message),
            Some("info") | Some(_) | None => info!("{}", message),
        }
    }
}
