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
