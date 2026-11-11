//! Durable shutdown deadlines; execution and signal delivery remain with their hosts.
use serde::{Deserialize, Serialize};

pub const SHUTDOWN_GRACE: u64 = 35;

#[derive(Clone, Serialize, Deserialize)]
pub struct Shutdown {
    pub requested: u64,
    pub deadline: u64,
    pub complete: bool,
}
impl Shutdown {
    pub fn new(now: u64) -> Self {
        Self {
            requested: now,
            deadline: now.saturating_add(SHUTDOWN_GRACE),
            complete: false,
        }
    }
    pub fn due(&self, now: u64) -> bool {
        !self.complete && now >= self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shutdown_deadline_survives_serialization_and_completion_is_final() {
        let mut s: Shutdown =
            serde_json::from_str(&serde_json::to_string(&Shutdown::new(100)).unwrap()).unwrap();
        assert!(!s.due(134));
        assert!(s.due(135));
        s.complete = true;
        assert!(!s.due(1000));
        assert_eq!(Shutdown::new(u64::MAX).deadline, u64::MAX);
    }
}
