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
