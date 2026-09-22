//! Single-process, transactional JSON snapshots for configuration catalogs.
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, LockResult, Mutex, RwLock, RwLockReadGuard},
};

#[derive(Clone)]
pub struct Persistent<T> {
    value: Arc<RwLock<T>>,
    writer: Arc<Mutex<()>>,
    path: Option<PathBuf>,
}

impl<T: Clone + Serialize + DeserializeOwned + Send + Sync + 'static> Persistent<T> {
    pub fn load(path: Option<PathBuf>, default: impl FnOnce() -> T) -> io::Result<Self> {
        let value = match path.as_ref().map(std::fs::read) {
            Some(Ok(bytes)) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            Some(Err(e)) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => default(),
        };
        Ok(Self {
            value: Arc::new(RwLock::new(value)),
            writer: Arc::new(Mutex::new(())),
            path,
        })
    }

    pub fn read(&self) -> LockResult<RwLockReadGuard<'_, T>> {
        self.value.read()
    }

    pub async fn update<R: Send + 'static>(
        &self,
        update: impl FnOnce(&mut T) -> io::Result<R> + Send + 'static,
    ) -> io::Result<R> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = store.writer.lock().unwrap();
            let mut next = store.value.read().unwrap().clone();
            let result = update(&mut next)?;
            if let Some(path) = &store.path {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| std::path::Path::new("."));
                std::fs::create_dir_all(parent)?;
                let tmp = path.with_extension("json.tmp");
                let write = || -> io::Result<()> {
                    use std::io::Write;
                    let bytes = serde_json::to_vec_pretty(&next).map_err(io::Error::other)?;
                    let previous = serde_json::to_vec_pretty(&*store.value.read().unwrap())
                        .map_err(io::Error::other)?;
                    if bytes == previous && path.exists() {
                        return Ok(());
                    }
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&tmp, path)?;
                    Ok(())
                };
                if let Err(err) = write() {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(err);
                }
            }
            *store.value.write().unwrap() = next;
            Ok(result)
        })
        .await
        .map_err(io::Error::other)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_testkit::Polygon;
    #[tokio::test]
    async fn campaign_and_schedule_changes_survive_restart() {
        use crate::{campaign::CampaignCatalog, scheduler::ScheduleCatalog};
        let polygon = Polygon::new("catalog-restart");
        let campaigns_path = polygon.dir().join("campaigns.json");
        let schedules_path = polygon.dir().join("schedules.json");
        let campaigns =
            Persistent::load(Some(campaigns_path.clone()), CampaignCatalog::seeded).unwrap();
        campaigns
            .update(|c| {
                c.deregister("CAMP-RANSOMWARE-CHAIN");
                Ok(())
            })
            .await
            .unwrap();
        let campaigns = Persistent::load(Some(campaigns_path), CampaignCatalog::seeded).unwrap();
        assert!(campaigns
            .read()
            .unwrap()
            .get("CAMP-RANSOMWARE-CHAIN")
            .is_none());
        let schedules =
            Persistent::load(Some(schedules_path.clone()), ScheduleCatalog::seeded).unwrap();
        let due = schedules
            .update(|c| {
                c.set_enabled("SCHED-BASE-RANSOMWARE", true);
                Ok(c.claim_due(1000))
            })
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        let schedules =
            Persistent::load(Some(schedules_path.clone()), ScheduleCatalog::seeded).unwrap();
        schedules
            .update(|c| {
                c.recover_interrupted();
                assert!(c.claim_due(1001).is_empty());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            schedules
                .read()
                .unwrap()
                .get("SCHED-BASE-RANSOMWARE")
                .unwrap()
                .last_status
                .as_deref(),
            Some("INTERRUPTED")
        );
        schedules
            .update(|c| {
                c.set_enabled("SCHED-BASE-RANSOMWARE", false);
                c.deregister("SCHED-BASE-C2-BEACON");
                Ok(())
            })
            .await
            .unwrap();
        let schedules = Persistent::load(Some(schedules_path), ScheduleCatalog::seeded).unwrap();
        assert!(schedules
            .update(|c| Ok(c.claim_due(2000)))
            .await
            .unwrap()
            .is_empty());
        assert!(schedules
            .read()
            .unwrap()
            .get("SCHED-BASE-C2-BEACON")
            .is_none());
    }
    #[tokio::test]
    async fn updates_survive_reload_and_failed_write_does_not_publish() {
        let polygon = Polygon::new("persistent");
        let path = polygon.dir().join("state.json");
        let store = Persistent::load(Some(path.clone()), Vec::<String>::new).unwrap();
        store
            .update(|v| {
                v.push("saved".into());
                Ok(())
            })
            .await
            .unwrap();
        let loaded = Persistent::load(Some(path.clone()), Vec::<String>::new).unwrap();
        assert_eq!(*loaded.read().unwrap(), vec!["saved"]);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store
            .update(|v| {
                v.clear();
                Ok(())
            })
            .await
            .is_err());
        assert_eq!(*store.read().unwrap(), vec!["saved"]);
    }
}
