//! Versioned configuration snapshots; heartbeat observations are never durable.
use std::{collections::HashSet, io, io::Write, path::Path, sync::Arc};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::registry::{RegisteredRunner, RegistryData, RunnerRecord, RunnerStatus};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistrySnapshot {
    version: u32,
    require_runner: bool,
    runners: Vec<RunnerConfig>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerConfig {
    id: String,
    name: String,
    endpoint: String,
    tags: Vec<String>,
    draining: bool,
    registered_at_utc: u64,
}

pub(super) fn validate_identity(id: &str, endpoint: &str) -> io::Result<()> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid runner endpoint URL"))?;
    // URL parsing normalizes spaces and control characters; gRPC consumes the
    // original URI and rejects them. Validate against the actual transport too.
    tonic::transport::Channel::from_shared(endpoint.to_string()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid gRPC runner endpoint URI",
        )
    })?;
    if id.is_empty()
        || id.trim() != id
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "runner requires a nonempty trimmed id and an HTTP(S) endpoint without credentials or fragment"));
    }
    Ok(())
}

impl RegistrySnapshot {
    pub(super) fn from_data(data: &RegistryData) -> Self {
        let mut runners: Vec<_> = data
            .runners
            .values()
            .map(|entry| {
                let r = &entry.record;
                RunnerConfig {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    endpoint: r.endpoint.clone(),
                    tags: r.tags.clone(),
                    draining: r.status == RunnerStatus::Draining,
                    registered_at_utc: r.registered_at_utc,
                }
            })
            .collect();
        runners.sort_by(|a, b| a.id.cmp(&b.id));
        Self {
            version: 1,
            require_runner: data.require_runner,
            runners,
        }
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        if self.version != 1 || (!self.require_runner && !self.runners.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported or inconsistent runner snapshot",
            ));
        }
        let mut ids = HashSet::new();
        for runner in &self.runners {
            validate_identity(&runner.id, &runner.endpoint)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if !ids.insert(&runner.id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate runner id in snapshot",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let snapshot: Self = serde_json::from_slice(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(super) fn into_data(self) -> RegistryData {
        RegistryData {
            require_runner: self.require_runner,
            runners: self
                .runners
                .into_iter()
                .map(|r| {
                    let record = RunnerRecord {
                        id: r.id.clone(),
                        name: r.name,
                        endpoint: r.endpoint,
                        tags: r.tags,
                        status: if r.draining {
                            RunnerStatus::Draining
                        } else {
                            RunnerStatus::Unresponsive
                        },
                        last_heartbeat_utc: None,
                        cpu_usage_pct: 0,
                        version: String::new(),
                        registered_at_utc: r.registered_at_utc,
                    };
                    (
                        r.id,
                        RegisteredRunner {
                            record,
                            epoch: Arc::new(()),
                        },
                    )
                })
                .collect(),
        }
    }

    /// One writer process per file, in a directory controlled by the operator.
    /// File sync + atomic rename: no power-loss guarantee for the directory entry.
    pub(super) fn write(&self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut nonce = [0u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("snapshot entropy unavailable"))?;
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = parent.join(format!(".runners-{suffix}.tmp"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        let result = (|| {
            let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}
