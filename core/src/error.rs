#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("dati non autentici o chiave errata")]
    Crypto,
    #[error("password errata")]
    BadPassword,
    #[error("troppi tentativi: attendi {0} s")]
    LockedOut(u64),
    #[error("vault bloccato: autenticazione richiesta")]
    Locked,
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}
