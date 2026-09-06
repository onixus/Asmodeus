//! Synthetic canary injector — the T1486 imitation (FTT §4.1). It creates
//! decoy files, then "encrypts" them with a reversible XOR stream. This is a
//! marker to trip the detector (Ferrum eBPF), NOT real encryption: INV-0.
//!
//! Every path is checked against the canary scope before any write; the
//! injector refuses to touch anything outside `/tmp|/var/tmp/asmodeus-canary`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use asmodeus_dsl::path_in_scope;

/// XOR keystream byte. Reversible and harmless — applying twice restores the
/// original, which is exactly what a synthetic marker needs.
const XOR_KEY: u8 = 0xA5;

#[derive(Debug)]
pub enum InjectError {
    /// The target directory is outside the canary blast radius.
    OutOfScope(String),
    Io(io::Error),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectError::OutOfScope(p) => write!(f, "path out of canary scope: {p}"),
            InjectError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for InjectError {}

impl From<io::Error> for InjectError {
    fn from(e: io::Error) -> Self {
        InjectError::Io(e)
    }
}

/// What an injection did — feeds MTTD measurement and the run report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub files_created: usize,
    pub bytes_written: u64,
}

/// A scoped, self-cleaning canary injector.
#[derive(Debug)]
pub struct CanaryInjector {
    dir: PathBuf,
    file_count: usize,
    chunk_size_kb: usize,
}

impl CanaryInjector {
    /// Construct an injector for `dir`. Fails immediately if `dir` is not a
    /// canary path — nothing is created.
    pub fn new(
        dir: impl AsRef<Path>,
        file_count: usize,
        chunk_size_kb: usize,
    ) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(CanaryInjector {
            dir,
            file_count,
            chunk_size_kb,
        })
    }

    /// Create the decoy files and apply the reversible XOR "encryption" pass.
    pub fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let chunk = vec![b'C'; self.chunk_size_kb * 1024];
        let mut bytes_written = 0u64;

        for i in 0..self.file_count {
            let path = self.dir.join(format!("canary_{i:03}.docx"));
            // 1. write plaintext decoy
            let mut f = fs::File::create(&path)?;
            f.write_all(&chunk)?;
            bytes_written += chunk.len() as u64;

            // 2. synthetic pseudo-encryption pass (reversible XOR — INV-0)
            let mut data = fs::read(&path)?;
            for b in data.iter_mut() {
                *b ^= XOR_KEY;
            }
            fs::write(&path, &data)?;
            bytes_written += data.len() as u64;
        }

        Ok(Report {
            files_created: self.file_count,
            bytes_written,
        })
    }

    /// Mandatory rollback: remove every canary artifact and the directory.
    pub fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(tag: &str) -> String {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/tmp/asmodeus-canary/test-{tag}-{n}")
    }

    #[test]
    fn refuses_out_of_scope_dir() {
        let err = CanaryInjector::new("/etc/asmodeus", 3, 1).unwrap_err();
        assert!(matches!(err, InjectError::OutOfScope(_)));
    }

    #[test]
    fn injects_and_cleans_up() {
        let dir = unique_dir("inject");
        let inj = CanaryInjector::new(&dir, 5, 2).unwrap();

        let report = inj.inject().unwrap();
        assert_eq!(report.files_created, 5);
        assert!(Path::new(&dir).join("canary_000.docx").exists());
        // plaintext + xor pass => 2 writes of 2KB each * 5 files
        assert_eq!(report.bytes_written, 5 * 2 * 2 * 1024);

        inj.cleanup().unwrap();
        assert!(!Path::new(&dir).exists());
    }

    #[test]
    fn xor_pass_is_reversible() {
        let dir = unique_dir("xor");
        let inj = CanaryInjector::new(&dir, 1, 1).unwrap();
        inj.inject().unwrap();

        // Re-applying XOR restores the original 'C' plaintext — proving the
        // "encryption" carries no operational capability.
        let path = Path::new(&dir).join("canary_000.docx");
        let mut data = fs::read(&path).unwrap();
        for b in data.iter_mut() {
            *b ^= XOR_KEY;
        }
        assert!(data.iter().all(|&b| b == b'C'));

        inj.cleanup().unwrap();
    }
}
