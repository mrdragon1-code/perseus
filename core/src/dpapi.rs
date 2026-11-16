//! Windows DPAPI (ambito utente): protegge la copia "biometrica" della chiave master
//! e il dataset degli autorizzati.
use crate::{error::msg, Result};

const ENTROPY: &[u8] = b"perseus/dpapi/v1";

#[cfg(windows)]
pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::*;
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let ent = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&input, PCWSTR::null(), Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| msg(format!("DPAPI protect: {e}")))?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as _));
        Ok(v)
    }
}

#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::*;
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let ent = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| msg(format!("DPAPI unprotect: {e}")))?;
        let s = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let v = zeroize::Zeroizing::new(s.to_vec());
        zeroize::Zeroize::zeroize(s);
        let _ = LocalFree(HLOCAL(out.pbData as _));
        Ok(v)
    }
}

#[cfg(not(windows))]
pub fn protect(_: &[u8]) -> Result<Vec<u8>> {
    Err(msg("DPAPI disponibile solo su Windows"))
}
#[cfg(not(windows))]
pub fn unprotect(_: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Err(msg("DPAPI disponibile solo su Windows"))
}
