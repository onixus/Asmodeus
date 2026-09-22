//! Per-run ownership: cleanup can never remove the shared canary root.
use std::{
    io,
    path::{Path, PathBuf},
};

pub struct Sandbox {
    path: PathBuf,
}
impl Sandbox {
    pub fn create(target: &str, run_id: &str) -> io::Result<Self> {
        if !asmodeus_dsl::path_in_scope(target)
            || run_id.is_empty()
            || run_id.len() > 96
            || !run_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sandbox target or run ID",
            ));
        }
        let base = Path::new(target);
        // /tmp itself is a platform symlink on macOS; every component at or
        // below asmodeus-canary must be a real directory, never a symlink.
        let mut below_scope = false;
        for ancestor in base.ancestors().collect::<Vec<_>>().into_iter().rev() {
            if ancestor.file_name().is_some_and(|s| s == "asmodeus-canary") {
                below_scope = true;
            }
            if !below_scope {
                continue;
            }
            match std::fs::symlink_metadata(ancestor) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "sandbox path contains symlink or non-directory",
                    ))
                }
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    match std::fs::create_dir(ancestor) {
                        Ok(()) => (),
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            let meta = std::fs::symlink_metadata(ancestor)?;
                            if !meta.is_dir() || meta.file_type().is_symlink() {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "unsafe sandbox parent",
                                ));
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let path = base.join(run_id);
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?; // Exclusive ownership, no reuse of an existing run directory.
        Ok(Self { path })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn cleanup(&self) -> io::Result<()> {
        match std::fs::remove_dir_all(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn refuses_existing_directories_and_symlink_targets() {
        let poly = asmodeus_testkit::Polygon::new("sandbox-links");
        std::fs::create_dir_all(poly.dir()).unwrap();
        let existing = poly.dir().join("existing");
        std::fs::create_dir(&existing).unwrap();
        assert!(Sandbox::create(&poly.path(), "existing").is_err());
        let link = poly.dir().join("link");
        std::os::unix::fs::symlink(&existing, &link).unwrap();
        assert!(Sandbox::create(&link.to_string_lossy(), "run").is_err());
        assert!(existing.exists());
        assert!(Sandbox::create(&poly.path(), "../escape").is_err());
    }
}
