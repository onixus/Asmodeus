//! asmodeus-testkit — reusable fixtures for exercising the platform on a
//! synthetic polygon: a self-cleaning canary sandbox and signed-scenario
//! fixtures. Consolidates the keypair/manifest/signature boilerplate that the
//! runner and control-plane tests would otherwise hand-roll.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_compact::KeyPair;

pub mod tls;
pub use tls::{TestMtls, TestMtlsPaths};

/// A unique, self-cleaning canary directory under the INV-0 scope. Dropping a
/// `Polygon` removes the directory tree — tests never leave residue.
#[derive(Debug)]
pub struct Polygon {
    dir: PathBuf,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl Polygon {
    /// Create a unique sandbox `/tmp/asmodeus-canary/<tag>-<n>` (not yet on disk).
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        Polygon {
            dir: PathBuf::from(format!("/tmp/asmodeus-canary/{tag}-{pid}-{n}")),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path as a string, e.g. to feed an `ExecuteRequest.target_dir`.
    pub fn path(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }

    /// Assert the sandbox is within the canary blast radius (it always is).
    pub fn in_scope(&self) -> bool {
        asmodeus_dsl::path_in_scope(&self.path())
    }
}

impl Drop for Polygon {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A manifest signed by a throwaway keypair — everything a verify path needs.
#[derive(Debug, Clone)]
pub struct SignedScenario {
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Build a signed synthetic scenario manifest for `id`.
pub fn signed_scenario(id: &str) -> SignedScenario {
    let kp = KeyPair::generate();
    let manifest =
        format!("apiVersion: asmodeus.io/v1alpha1\nkind: AttackScenario\nid: {id}\n").into_bytes();
    let signature = kp.sk.sign(&manifest, None).as_ref().to_vec();
    SignedScenario {
        manifest,
        signature,
        public_key: kp.pk.as_ref().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polygon_is_unique_and_in_scope() {
        let a = Polygon::new("t");
        let b = Polygon::new("t");
        assert_ne!(a.path(), b.path());
        assert!(a.in_scope());
    }

    #[test]
    fn polygon_cleans_up_on_drop() {
        let path;
        {
            let p = Polygon::new("cleanup");
            path = p.path();
            std::fs::create_dir_all(p.dir()).unwrap();
            std::fs::write(p.dir().join("canary_000.docx"), b"x").unwrap();
            assert!(Path::new(&path).exists());
        }
        assert!(!Path::new(&path).exists());
    }

    #[test]
    fn signed_scenario_verifies() {
        let s = signed_scenario("SCN-RT-001");
        assert!(asmodeus_crypto::is_valid(
            &s.manifest,
            &s.signature,
            &s.public_key
        ));
    }
}
