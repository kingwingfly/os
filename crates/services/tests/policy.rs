use os_services::{Action, Manifest, State, Supervisor};
use serde_json::{Value, json};

fn unit(name: &str) -> Value {
    json!({ "name": name, "argv": ["/usr/bin/sleep", "1"] })
}
fn manifest(units: Vec<Value>) -> Manifest {
    Manifest::parse(&serde_json::to_vec(&json!({"version":1,"units":units})).unwrap()).unwrap()
}
#[test]
fn invalid_policy_fails_before_launch() {
    let mut bad = Vec::new();
    for (key, value) in [
        ("identity", json!("root")),
        ("readiness", json!("health-check")),
        ("limits", json!({"cpu":1})),
        ("max_restarts", json!(17)),
        ("restart_delay_ms", json!(0)),
        ("stop_timeout_ms", json!(30001)),
        ("startup_timeout_ms", json!(99)),
        ("startup_timeout_ms", json!(60001)),
        ("cwd", json!("relative")),
        ("environment", json!({"X=Y":"z"})),
        ("environment", json!({"OS_READY_FD":"1"})),
        ("argv", json!([])),
    ] {
        let mut u = unit("a");
        u[key] = value;
        bad.push(json!({"version":1,"units":[u]}));
    }
    bad.extend([
        json!({"version":2,"units":[unit("a")]}),
        json!({"version":1,"units":[unit("a"),unit("a")]}),
        json!({"version":1,"units":[]}),
    ]);
    for value in bad {
        assert!(
            Manifest::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{value}"
        );
    }
    assert!(Manifest::parse(&vec![b' '; 65537]).is_err());
}

fn notifying(name: &str) -> Value {
    let mut u = unit(name);
    u["readiness"] = json!("notify");
    u["startup_timeout_ms"] = json!(1000);
    u["stop_timeout_ms"] = json!(100);
    u
}

#[test]
fn notification_gates_requirements_but_not_ordering() {
    let mut required = unit("required");
    required["requires"] = json!(["provider"]);
    let mut ordered = unit("ordered");
    ordered["after"] = json!(["provider"]);
    let mut s = Supervisor::new(manifest(vec![notifying("provider"), required, ordered]));
    assert_eq!(s.tick(0, false), vec![Action::Start(0)]);
    s.started(0, 10, 1);
    assert_eq!(s.services[0].state, State::Starting);
    assert_eq!(s.tick(2, false), vec![Action::Start(2)]);
    s.started(2, 12, 3);
    assert!(!s.ready(0, 99, 4));
    assert!(s.tick(500, false).is_empty());
    assert!(s.ready(0, 10, 501));
    assert!(!s.ready(0, 10, 502));
    assert_eq!(s.tick(502, false), vec![Action::Start(1)]);
    s.started(1, 11, 503);
    // The startup deadline no longer applies after successful notification.
    assert!(s.tick(2000, false).is_empty());
}

#[test]
fn clean_exit_before_notification_is_failure_even_for_oneshots() {
    let mut s = Supervisor::new(manifest(vec![notifying("provider")]));
    s.tick(0, false);
    s.started(0, 10, 1);
    s.exited(0, true, 2);
    assert!(s.done() && s.failed());
    let mut s = Supervisor::new(manifest(vec![notifying("provider")]));
    s.tick(0, false);
    s.started(0, 10, 1);
    assert!(s.ready(0, 10, 2));
    s.exited(0, true, 3);
    assert!(s.done() && !s.failed());
}

#[test]
fn deadline_stops_then_kills_each_attempt_and_retries_only_after_reap() {
    let mut u = notifying("provider");
    u["restart"] = json!("on-failure");
    u["max_restarts"] = json!(1);
    u["restart_delay_ms"] = json!(100);
    let mut s = Supervisor::new(manifest(vec![u]));
    s.tick(0, false);
    for (pid, start) in [(10, 0), (11, 1201)] {
        s.started(0, pid, start + 1);
        assert!(!s.ready(0, pid, start + 1000));
        let actions = s.tick(start + 1000, false);
        assert_eq!(
            actions,
            vec![
                Action::StartupTimeout(0),
                Action::Signal {
                    index: 0,
                    pid,
                    signal: 15
                },
                Action::Signal {
                    index: 0,
                    pid,
                    signal: 18
                }
            ]
        );
        assert!(s.tick(start + 1099, false).is_empty());
        assert_eq!(
            s.tick(start + 1100, false),
            vec![Action::Signal {
                index: 0,
                pid,
                signal: 9
            }]
        );
        assert!(s.tick(start + 1101, false).is_empty());
        // Even a cleanup handler returning 0 cannot turn a startup timeout into success.
        s.exited(0, true, start + 1101);
        if pid == 10 {
            assert_eq!(s.services[0].state, State::Backoff);
            assert!(s.tick(1200, false).is_empty());
            assert_eq!(s.tick(1201, false), vec![Action::Start(0)]);
        }
    }
    assert!(s.done() && s.failed());
}

#[test]
fn invalid_notification_cannot_be_repaired_or_reused_on_another_attempt() {
    let mut u = notifying("provider");
    u["restart"] = json!("on-failure");
    u["max_restarts"] = json!(1);
    u["restart_delay_ms"] = json!(100);
    let mut s = Supervisor::new(manifest(vec![u]));
    s.tick(0, false);
    s.started(0, 10, 1);
    s.readiness_failed(0, 10);
    assert!(!s.ready(0, 10, 2));
    assert_eq!(s.tick(2, false).len(), 2);
    s.exited(0, true, 3);
    assert!(s.tick(102, false).is_empty());
    assert_eq!(s.tick(103, false), vec![Action::Start(0)]);
    s.started(0, 11, 104);
    s.readiness_failed(0, 10);
    assert!(!s.ready(0, 10, 105));
    assert!(s.ready(0, 11, 106));
    s.exited(0, true, 107);
    assert!(s.done() && !s.failed());
}

#[test]
fn shutdown_during_startup_cleanup_cancels_retry() {
    let mut u = notifying("provider");
    u["restart"] = json!("always");
    u["max_restarts"] = json!(2);
    let mut s = Supervisor::new(manifest(vec![u]));
    s.tick(0, false);
    s.started(0, 10, 1);
    s.readiness_failed(0, 10);
    s.tick(2, false);
    assert!(s.tick(3, true).is_empty());
    assert!(!s.ready(0, 10, 4));
    s.exited(0, false, 5);
    assert!(s.done());
    assert!(s.tick(10000, false).is_empty());
}

#[test]
fn dependency_failure_during_startup_cleanup_cancels_retry() {
    let mut u = notifying("dependent");
    u["requires"] = json!(["provider"]);
    u["restart"] = json!("always");
    u["max_restarts"] = json!(2);
    let mut s = Supervisor::new(manifest(vec![unit("provider"), u]));
    s.tick(0, false);
    s.started(0, 10, 1);
    s.tick(2, false);
    s.started(1, 11, 3);
    s.readiness_failed(1, 11);
    s.tick(4, false);
    s.exited(0, false, 5);
    s.tick(6, false);
    s.exited(1, true, 7);
    assert!(s.done() && s.failed());
    assert!(s.tick(10000, false).is_empty());
}

#[test]
fn late_spawn_acceptance_cannot_bypass_startup_deadline() {
    let mut u = unit("slow-image");
    u["startup_timeout_ms"] = json!(100);
    let mut s = Supervisor::new(manifest(vec![u]));
    s.tick(0, false);
    s.started(0, 10, 100);
    assert_eq!(s.services[0].state, State::Starting);
    assert_eq!(s.tick(101, false)[0], Action::StartupTimeout(0));
}

#[test]
fn independent_launch_queue_time_is_not_charged_to_startup() {
    let mut s = Supervisor::new(manifest(vec![notifying("first"), notifying("second")]));
    assert_eq!(s.tick(0, false), vec![Action::Start(0), Action::Start(1)]);
    s.started(0, 10, 500);
    s.launching(1, 900);
    s.started(1, 11, 1100);
    assert!(s.ready(1, 11, 1500));
    assert!(!s.ready(0, 10, 1500));
}
#[test]
fn cycles_and_unknown_dependencies_are_rejected() {
    for units in [
        json!([{"name":"a","argv":["true"],"requires":["missing"]}]),
        json!([{"name":"a","argv":["true"],"requires":["b"]},{"name":"b","argv":["true"],"after":["a"]}]),
    ] {
        assert!(
            Manifest::parse(&serde_json::to_vec(&json!({"version":1,"units":units})).unwrap())
                .is_err()
        );
    }
}
#[test]
fn required_readiness_and_ordering_only_failure_are_different() {
    let mut required = unit("required");
    required["requires"] = json!(["provider"]);
    let mut ordered = unit("ordered");
    ordered["after"] = json!(["provider"]);
    let mut s = Supervisor::new(manifest(vec![required, ordered, unit("provider")]));
    assert_eq!(s.tick(0, false), vec![Action::Start(2)]);
    s.exited(2, false, 1);
    assert_eq!(s.tick(1, false), vec![Action::Start(1)]);
    assert_eq!(s.services[0].state, State::Failed);
    s.started(1, 10, 0);
    s.exited(1, true, 2);
    assert!(s.done() && s.failed());
}
#[test]
fn restarts_have_delay_and_a_lifetime_budget() {
    let mut u = unit("a");
    u["restart"] = json!("on-failure");
    u["max_restarts"] = json!(2);
    u["restart_delay_ms"] = json!(100);
    let mut s = Supervisor::new(manifest(vec![u]));
    assert_eq!(s.tick(0, false), vec![Action::Start(0)]);
    for (i, now) in [1, 101].into_iter().enumerate() {
        s.started(0, 10 + i as u32, now - 1);
        s.exited(0, false, now);
        assert_eq!(s.services[0].state, State::Backoff);
        assert!(s.tick(now + 99, false).is_empty());
        assert_eq!(s.tick(now + 100, false), vec![Action::Start(0)]);
    }
    s.started(0, 12, 201);
    s.exited(0, false, 202);
    assert!(s.done() && s.failed());
}
#[test]
fn stop_cancels_backoff_and_escalates_once_in_reverse_dependency_order() {
    let mut dependent = unit("dependent");
    dependent["requires"] = json!(["provider"]);
    let mut s = Supervisor::new(manifest(vec![dependent, unit("provider")]));
    s.tick(0, false);
    s.started(1, 10, 0);
    s.tick(0, false);
    s.started(0, 11, 1);
    let actions = s.tick(100, true);
    assert_eq!(
        actions,
        vec![
            Action::Signal {
                index: 0,
                pid: 11,
                signal: 15
            },
            Action::Signal {
                index: 0,
                pid: 11,
                signal: 18
            },
            Action::Signal {
                index: 1,
                pid: 10,
                signal: 15
            },
            Action::Signal {
                index: 1,
                pid: 10,
                signal: 18
            }
        ]
    );
    assert!(s.tick(5099, false).is_empty());
    assert_eq!(s.tick(5100, false).len(), 2);
    assert!(s.tick(5200, false).is_empty());
    s.exited(0, false, 5201);
    s.exited(1, false, 5201);
    assert!(s.done());
    let mut u = unit("retry");
    u["restart"] = json!("always");
    u["max_restarts"] = json!(2);
    let mut s = Supervisor::new(manifest(vec![u]));
    s.tick(0, false);
    s.exited(0, false, 1);
    assert!(s.tick(2, true).is_empty());
    assert!(s.done());
    assert!(s.tick(10000, false).is_empty());
}
#[test]
fn failed_requirement_stops_a_live_dependent_and_prevents_restart() {
    let mut u = unit("dependent");
    u["requires"] = json!(["provider"]);
    u["restart"] = json!("always");
    u["max_restarts"] = json!(2);
    let mut s = Supervisor::new(manifest(vec![u, unit("provider")]));
    s.tick(0, false);
    s.started(1, 10, 0);
    s.tick(1, false);
    s.started(0, 11, 1);
    s.exited(1, false, 2);
    assert_eq!(s.tick(2, false).len(), 2);
    s.exited(0, false, 3);
    assert!(s.done() && s.failed());
    assert!(s.tick(10000, false).is_empty());
}

#[test]
fn pid_limits_accept_zero_and_reject_unsupported_contracts() {
    for pids in [0u32, 1, 32, u32::MAX] {
        let body = serde_json::json!({"version":1,"units":[{"name":"limited","argv":["sleep","1"],"limits":{"pids":pids}}]});
        let manifest = os_services::Manifest::parse(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(manifest.units[0].limits.as_ref().unwrap().pids, Some(pids));
    }
    for limits in [
        serde_json::json!({"pids":-1}),
        serde_json::json!({"pids":1.5}),
        serde_json::json!({"pids":1,"cpu":1024}),
        serde_json::json!({}),
    ] {
        let body = serde_json::json!({"version":1,"units":[{"name":"limited","argv":["sleep","1"],"limits":limits}]});
        assert!(os_services::Manifest::parse(&serde_json::to_vec(&body).unwrap()).is_err());
    }
}
