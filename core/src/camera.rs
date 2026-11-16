//! Camere: enumerazione Media Foundation, filtro iVCam (ammessa) / OBS (bloccata), acquisizione.
use crate::{error::msg, Result};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", content = "reason")]
pub enum Verdict {
    /// in allowlist e non in denylist
    Trusted,
    /// denylist (OBS e simili): sempre rifiutata
    Blocked(String),
    /// non in allowlist
    Untrusted,
}

fn tokens(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).map(str::to_lowercase)
}

/// La denylist ha sempre la precedenza sull'allowlist.
pub fn classify(name: &str, misc: &str, allow: &[String]) -> Verdict {
    let all = format!("{name} {misc}").to_lowercase();
    let deny_token = tokens(name).chain(tokens(misc)).any(|t| t == "obs" || t.starts_with("obsvirtual"));
    if deny_token || all.contains("obs-camera") || all.contains("obs virtual") || all.contains("obs-virtualcam") {
        return Verdict::Blocked(format!("camera virtuale OBS rifiutata: {name}"));
    }
    if allow.iter().any(|a| !a.trim().is_empty() && name.to_lowercase().contains(&a.trim().to_lowercase())) {
        Verdict::Trusted
    } else {
        Verdict::Untrusted
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct CameraDesc {
    pub index: u32,
    pub name: String,
    pub misc: String,
    pub verdict: Verdict,
}

pub fn list(allow: &[String]) -> Result<Vec<CameraDesc>> {
    use nokhwa::utils::ApiBackend;
    let cams = nokhwa::query(ApiBackend::MediaFoundation).map_err(|e| msg(format!("enumerazione camere: {e}")))?;
    Ok(cams
        .into_iter()
        .filter_map(|c| {
            let index = c.index().as_index().ok()?;
            let (name, misc) = (c.human_name(), c.misc());
            let verdict = classify(&name, &misc, allow);
            Some(CameraDesc { index, name, misc, verdict })
        })
        .collect())
}

pub struct Frame {
    pub width: u32,
    pub height: u32,
    /// BGRA 8 bit, righe contigue (stride = width*4)
    pub bgra: Vec<u8>,
    pub seq: u64,
}

#[derive(Default)]
struct Shared {
    frame: Option<Frame>,
    error: Option<String>,
}

pub struct CameraStream {
    pub desc: CameraDesc,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CameraStream {
    /// Apre la camera solo se è `Trusted` (controllo ripetuto a ogni apertura).
    pub fn open(index: u32, allow: &[String]) -> Result<Self> {
        let desc = list(allow)?
            .into_iter()
            .find(|c| c.index == index)
            .ok_or_else(|| msg("camera non trovata"))?;
        match &desc.verdict {
            Verdict::Trusted => {}
            Verdict::Blocked(r) => return Err(msg(r.clone())),
            Verdict::Untrusted => {
                return Err(msg(format!("SENSORE NON ATTENDIBILE: '{}' non è in allowlist", desc.name)))
            }
        }
        let shared = Arc::new(Mutex::new(Shared::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, st2) = (shared.clone(), stop.clone());
        let handle = std::thread::Builder::new()
            .name("perseus-camera".into())
            .spawn(move || capture_loop(index, s2, st2))
            .map_err(|e| msg(format!("thread camera: {e}")))?;
        Ok(Self { desc, shared, stop, handle: Some(handle) })
    }

    /// Copia l'ultimo frame se più nuovo di `after_seq`.
    pub fn latest<R>(&self, after_seq: u64, f: impl FnOnce(&Frame) -> R) -> Result<Option<R>> {
        let g = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = &g.error {
            return Err(msg(e.clone()));
        }
        Ok(g.frame.as_ref().filter(|fr| fr.seq > after_seq).map(f))
    }
}

impl Drop for CameraStream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn capture_loop(index: u32, shared: Arc<Mutex<Shared>>, stop: Arc<AtomicBool>) {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
    let set_err = |e: String| shared.lock().unwrap_or_else(|p| p.into_inner()).error = Some(e);

    let req = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    let mut cam = match nokhwa::Camera::new(CameraIndex::Index(index), req) {
        Ok(c) => c,
        Err(e) => return set_err(format!("apertura camera: {e}")),
    };
    if let Err(e) = cam.open_stream() {
        return set_err(format!("avvio stream: {e}"));
    }
    let mut seq = 0u64;
    let mut errors = 0;
    while !stop.load(Ordering::SeqCst) {
        let img = cam.frame().and_then(|b| b.decode_image::<RgbFormat>());
        match img {
            Ok(img) => {
                errors = 0;
                let (w, h) = img.dimensions();
                let mut bgra = Vec::with_capacity((w * h * 4) as usize);
                for px in img.as_raw().chunks_exact(3) {
                    bgra.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
                seq += 1;
                shared.lock().unwrap_or_else(|p| p.into_inner()).frame =
                    Some(Frame { width: w, height: h, bgra, seq });
            }
            Err(e) => {
                errors += 1;
                if errors > 30 {
                    set_err(format!("lettura frame: {e}"));
                    break;
                }
            }
        }
    }
    let _ = cam.stop_stream();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter() {
        let allow = vec!["iVCam".to_string()];
        assert_eq!(classify("e2eSoft iVCam", "", &allow), Verdict::Trusted);
        assert!(matches!(classify("OBS Virtual Camera", "", &allow), Verdict::Blocked(_)));
        assert!(matches!(classify("OBS-Camera", "", &allow), Verdict::Blocked(_)));
        // anche se rinominata, il symbolic link la tradisce
        assert!(matches!(classify("iVCam", r"\\?\root#obsvirtualcam#0000", &allow), Verdict::Blocked(_)));
        assert_eq!(classify("Integrated Webcam", "", &allow), Verdict::Untrusted);
        assert_eq!(classify("Jobs Camera", "", &allow), Verdict::Untrusted); // "obs" solo come parola intera
    }
}

#[cfg(test)]
mod hw {
    /// `cargo test -p perseus-core -- --ignored --nocapture list_real_cameras`
    #[test]
    #[ignore]
    fn list_real_cameras() {
        for c in super::list(&["iVCam".to_string()]).unwrap() {
            println!("[{}] {:<30} {:?}  misc={}", c.index, c.name, c.verdict, c.misc);
        }
    }
}
