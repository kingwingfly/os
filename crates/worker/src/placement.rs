//! Placement policy is separate from executable authorization. These identifiers are labels,
//! never capabilities. Remote executors remain disabled until registration and consent exist.
use abi::Placement;

pub fn browser(ns: &str, uid: u32, seat: Option<&str>, cgroup: &str) -> Placement {
    Placement {
        cluster: format!("account:{uid}"),
        executor: format!("browser:{ns}:{}", seat.unwrap_or("unassigned")),
        cgroup: cgroup.into(),
    }
}

pub fn container(uid: u32, job: &str) -> Placement {
    Placement {
        cluster: format!("account:{uid}"),
        executor: format!("container:{job}"),
        cgroup: "/system".into(),
    }
}
