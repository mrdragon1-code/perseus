//! Journal di un'operazione in corso: permette di riprendere dopo un crash/spegnimento.
use super::write_atomic;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Op {
    /// src = file in chiaro, tmp = .prs.tmp, dst = .prs finale
    Encrypt { src: PathBuf, tmp: PathBuf, dst: PathBuf },
    /// src = .prs, tmp = .dec.tmp, dst = file in chiaro finale
    Decrypt { src: PathBuf, tmp: PathBuf, dst: PathBuf },
}

pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn begin(&self, op: &Op) -> Result<()> {
        write_atomic(&self.path, &serde_json::to_vec(op)?)
    }

    pub fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    pub fn pending(&self) -> Result<Option<Op>> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
