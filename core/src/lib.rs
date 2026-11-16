//! PERSEUS core: autenticazione e cifratura cartelle.
pub mod camera;
pub mod dpapi;
pub mod error;
pub mod ffi;
pub mod vault;

pub use error::{Error, Result};
