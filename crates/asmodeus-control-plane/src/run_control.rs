use asmodeus_common::Category;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[derive(Clone)]
pub struct ActiveRun {
    pub category: Category,
    pub cancel: Arc<AtomicBool>,
    pub status: Arc<Mutex<String>>,
}
impl ActiveRun {
    pub fn new(category: Category) -> Self {
        Self {
            category,
            cancel: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new("QUEUED".into())),
        }
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        *self.status.lock().unwrap() = "CANCELLING".into();
    }
}

/// Live control handle for a campaign worker. `current` is the admitted
/// scenario run of the active stage; both fields are guarded by one lock so a
/// cancel request and stage admission cannot miss each other.
#[derive(Clone, Default)]
pub struct CampaignControl {
    inner: Arc<Mutex<CampaignControlState>>,
}

#[derive(Default)]
struct CampaignControlState {
    cancelled: bool,
    current: Option<asmodeus_common::RunId>,
}

impl CampaignControl {
    pub fn is_cancelled(&self) -> bool {
        self.inner.lock().unwrap().cancelled
    }

    /// Request cancellation; returns the active stage run to cancel, if any.
    pub fn cancel(&self) -> Option<asmodeus_common::RunId> {
        let mut state = self.inner.lock().unwrap();
        state.cancelled = true;
        state.current.clone()
    }

    /// Record the admitted stage run; returns true if a cancel already arrived
    /// and the caller must cancel that run itself.
    pub fn set_current(&self, run: Option<asmodeus_common::RunId>) -> bool {
        let mut state = self.inner.lock().unwrap();
        state.current = run;
        state.cancelled && state.current.is_some()
    }
}
