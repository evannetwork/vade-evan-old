extern crate ssi_evan;

use ssi::library::Library;
use ssi::library::traits::{ Logger };
use ssi_evan::platform::rust_logger::RustLogger;
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
    let mut library = Library::new();
    library.register_logger(Box::from(logger));

    library.log("ssi_evan: roku", Some("debug"));
}

#[test]
fn handles_specific_logger_types() {
    let mut library = Library::new();
    let logger = RustLogger::new();
    library.register_logger(Box::from(logger));
    let logger1 = RustLogger1::new();
    library.register_logger(Box::from(logger1));

    library.log("ssi_evan: test log", Some("debug"));
    library.loggers[0].log("logger", Some("debug"));
    library.loggers[1].log("logger", Some("debug"));

    match library.loggers[0].as_any().downcast_ref::<RustLogger>() {
        Some(_) => (),
        None => panic!("unexpected casting error"),
    };

    match library.loggers[1].as_any().downcast_ref::<RustLogger1>() {
        Some(_) => (),
        None => panic!("unexpected casting error"),
    };

    match library.loggers[0].as_any().downcast_ref::<RustLogger1>() {
        Some(_) => panic!("unexpected casting success"),
        None => (),
    };

    match library.loggers[1].as_any().downcast_ref::<RustLogger>() {
        Some(_) => panic!("unexpected casting success"),
        None => (),
    };
}
