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
use vade::traits::{ Logger };
use vade_evan::platform::rust_logger::RustLogger;
use std::any::Any;

// example logger, that follows same trait for testing
pub struct RustLogger1 {
}

impl RustLogger1 {
    pub fn new() -> RustLogger1 {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        RustLogger1 { }
    }
}

impl Logger for RustLogger1 {
    /// Cast to `Any` for downcasting.
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn log(&self, _message: &str, _level: Option<&str>) {
    }
}


#[test]
fn logs_messages() {
    let logger = RustLogger::new();
    let mut vade = Vade::new();
    vade.register_logger(Box::from(logger));

    vade.log("vade_evan: roku", Some("debug"));
}

#[test]
fn handles_specific_logger_types() {
    let mut vade = Vade::new();
    let logger = RustLogger::new();
    vade.register_logger(Box::from(logger));
    let logger1 = RustLogger1::new();
    vade.register_logger(Box::from(logger1));

    vade.log("vade_evan: test log", Some("debug"));
    vade.loggers[0].log("logger", Some("debug"));
    vade.loggers[1].log("logger", Some("debug"));

    match vade.loggers[0].as_any().downcast_ref::<RustLogger>() {
        Some(_) => (),
        None => panic!("unexpected casting error"),
    };

    match vade.loggers[1].as_any().downcast_ref::<RustLogger1>() {
        Some(_) => (),
        None => panic!("unexpected casting error"),
    };

    match vade.loggers[0].as_any().downcast_ref::<RustLogger1>() {
        Some(_) => panic!("unexpected casting success"),
        None => (),
    };

    match vade.loggers[1].as_any().downcast_ref::<RustLogger>() {
        Some(_) => panic!("unexpected casting success"),
        None => (),
    };
}
