//! Exhaustive tests for Service Manager v2: unit schema, DAG ordering, cycle detection,
//! `OS_READY_FD` / `NOTIFY_SOCKET` readiness, `Optional` failure handling, restart backoff,
//! `SO_PEERCRED` spoofing refusal, per-user manager attenuation, and strict reverse shutdown.

use abi::Errno;
use abi::auth_v2::RemoteScope;
use os_services::control::{
    ControlRequest, ControlResponse, NotifyMessage, PeerCred, decode_request_frame,
    decode_response_frame, encode_request_frame, encode_response_frame, user_manager_socket,
};
use os_services::graph::{GraphError, UnitGraph, default_boot_graph};
use os_services::manager::{ManagerAction, ServiceManager, UnitState};
use os_services::unit::{
    CapabilityGrant, FailurePolicy, MountNsPolicy, Readiness, RestartPolicy, UNIT_MANIFEST_VERSION,
    UnitKind, UnitSpec,
};
use std::collections::BTreeMap;

fn simple_service(name: &str, after: Vec<&str>, requires: Vec<&str>) -> UnitSpec {
    UnitSpec {
        version: UNIT_MANIFEST_VERSION,
        name: name.into(),
        kind: UnitKind::Service,
        description: String::new(),
        after: after.into_iter().map(String::from).collect(),
        wants: Vec::new(),
        requires: requires.into_iter().map(String::from).collect(),
        wanted_by: Vec::new(),
        failure_policy: FailurePolicy::Required,
        readiness: Readiness::NotifySocket,
        ready_timeout_ms: 5_000,
        stop_timeout_ms: 2_000,
        restart: RestartPolicy::Never,
        exec_start: Some(vec![format!("/usr/bin/{name}")]),
        exec_stop: None,
        cwd: Some("/".into()),
        environment: BTreeMap::new(),
        mount: None,
        grant: CapabilityGrant::default(),
        enabled: true,
    }
}

#[test]
fn unit_spec_json_round_trip_defaults_to_empty_cloud_scope_and_rejects_bad_inputs() {
    let raw = serde_json::to_vec(&serde_json::json!({
        "version": 2,
        "name": "worker.service",
        "kind": "service",
        "exec_start": ["/usr/bin/worker", "--local"],
        "readiness": "notify_socket",
        "restart": { "policy": "on_failure", "max_attempts": 3, "backoff_ms": 250 }
    }))
    .unwrap();
    let spec = UnitSpec::parse_json(&raw).unwrap();
    assert_eq!(spec.version, UNIT_MANIFEST_VERSION);
    assert!(
        spec.grant.cloud_scope.is_empty(),
        "default cloud_scope MUST be empty (100% offline)"
    );
    assert_eq!(spec.failure_policy, FailurePolicy::Required);

    // Reject v1 manifests, mismatched suffix, reserved env vars, and invalid bind mounts.
    for bad in [
        serde_json::json!({
            "version": 1,
            "name": "old.service",
            "kind": "service",
            "exec_start": ["/usr/bin/true"]
        }),
        serde_json::json!({
            "version": 2,
            "name": "wrong.target",
            "kind": "service",
            "exec_start": ["/usr/bin/true"]
        }),
        serde_json::json!({
            "version": 2,
            "name": "spoof-env.service",
            "kind": "service",
            "exec_start": ["/usr/bin/true"],
            "environment": { "NOTIFY_SOCKET": "/tmp/fake.sock" }
        }),
        serde_json::json!({
            "version": 2,
            "name": "bad-bind.service",
            "kind": "service",
            "exec_start": ["/usr/bin/true"],
            "grant": {
                "mount_namespace": "system",
                "bind_mounts": [{ "source": "/srv", "target": "/mnt" }]
            }
        }),
    ] {
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert!(
            UnitSpec::parse_json(&bytes).is_err(),
            "expected validation error for {bad}"
        );
    }
}

#[test]
fn dag_topological_order_cycle_detection_and_reverse_shutdown_order() {
    // Cycle A -> B -> A is rejected explicitly with GraphError::Cycle.
    let a = simple_service("a.service", vec!["b.service"], vec!["b.service"]);
    let b = simple_service("b.service", vec!["a.service"], vec!["a.service"]);
    match UnitGraph::build(vec![a, b]) {
        Err(GraphError::Cycle(nodes)) => assert!(nodes.len() >= 3),
        other => panic!("expected Cycle error, got {other:?}"),
    }

    // Unknown required dependency fails closed.
    let orphan = simple_service("orphan.service", vec![], vec!["missing.service"]);
    assert!(matches!(
        UnitGraph::build(vec![orphan]),
        Err(GraphError::UnknownDependency { .. })
    ));

    // Built-in default boot graph orders local-fs -> user-session -> multi-user -> cloud.mount -> devattach -> cloud-online.
    let graph = default_boot_graph(1000).unwrap();
    let order = graph.start_order();
    let pos = |name: &str| order.iter().position(|u| u == name).unwrap();
    assert!(pos("local-fs.target") < pos("user-session@1000.service"));
    assert!(pos("user-session@1000.service") < pos("multi-user.target"));
    assert!(pos("multi-user.target") < pos("cloud.mount"));
    assert!(pos("cloud.mount") < pos("devattach@snd.service"));
    assert!(pos("devattach@snd.service") < pos("cloud-online.target"));

    // Booting `multi-user.target` does NOT pull in `cloud-online.target` or `cloud.mount`.
    let boot_plan = graph.start_plan_for("multi-user.target").unwrap();
    assert!(boot_plan.contains(&"local-fs.target".to_owned()));
    assert!(boot_plan.contains(&"multi-user.target".to_owned()));
    assert!(boot_plan.contains(&"user-session@1000.service".to_owned()));
    assert!(!boot_plan.contains(&"cloud.mount".to_owned()));
    assert!(!boot_plan.contains(&"cloud-online.target".to_owned()));

    // Reverse shutdown order is exact reverse of start order.
    let rev = graph.shutdown_order();
    let rpos = |name: &str| rev.iter().position(|u| u == name).unwrap();
    assert!(rpos("cloud-online.target") < rpos("devattach@snd.service"));
    assert!(rpos("devattach@snd.service") < rpos("cloud.mount"));
    assert!(rpos("cloud.mount") < rpos("multi-user.target"));
    assert!(rpos("multi-user.target") < rpos("user-session@1000.service"));
    assert!(rpos("user-session@1000.service") < rpos("local-fs.target"));
}

#[test]
fn readiness_gates_dependent_units_and_so_peercred_blocks_notify_spoofing() {
    let mut a = simple_service("a.service", vec![], vec![]);
    a.readiness = Readiness::NotifySocket;
    let mut b = simple_service("b.service", vec!["a.service"], vec!["a.service"]);
    b.readiness = Readiness::PipeFd;

    let graph = UnitGraph::build(vec![a, b]).unwrap();
    let mut mgr = ServiceManager::new_system(graph).unwrap();
    mgr.boot_target("b.service").unwrap();

    // Tick 1: ONLY `a.service` spawns; `b.service` waits for `a.service` READY=1!
    let actions = mgr.tick(100);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        ManagerAction::SpawnService {
            unit,
            use_ready_fd: false,
            notify_socket: Some(_),
            ..
        } if unit == "a.service"
    ));
    mgr.on_spawned("a.service", 200, 100).unwrap();
    assert_eq!(mgr.unit_state("a.service"), Some(UnitState::Starting));
    assert_eq!(mgr.unit_state("b.service"), Some(UnitState::Inactive));

    // SECURITY (S-06): Process X (pid 999) tries to spoof READY=1 for `a.service` (pid 200)!
    let spoof = mgr.on_notify(
        PeerCred {
            pid: 999,
            uid: 0,
            gid: 0,
        },
        b"READY=1\nMAINPID=200\n",
        150,
    );
    assert_eq!(spoof.unwrap_err().errno, Errno::EPERM);
    assert_eq!(mgr.spoofed_notify_count(), 1);
    assert_eq!(
        mgr.unit_state("a.service"),
        Some(UnitState::Starting),
        "spoofed notify MUST NOT mark unit Active"
    );
    assert!(mgr.tick(160).is_empty());

    // Genuine `a.service` (pid 200) sends READY=1 + STATUS=...
    let notified = mgr
        .on_notify(
            PeerCred {
                pid: 200,
                uid: 0,
                gid: 0,
            },
            b"READY=1\nSTATUS=listening on /run/a.sock\n",
            200,
        )
        .unwrap();
    assert_eq!(notified, "a.service");
    assert_eq!(mgr.unit_state("a.service"), Some(UnitState::Active));
    assert_eq!(
        mgr.unit_status("a.service").unwrap().status_text.as_deref(),
        Some("listening on /run/a.sock")
    );

    // Now `b.service` spawns with `OS_READY_FD` (`use_ready_fd = true`).
    let actions = mgr.tick(210);
    assert!(matches!(
        &actions[0],
        ManagerAction::SpawnService {
            unit,
            use_ready_fd: true,
            notify_socket: None,
            ..
        } if unit == "b.service"
    ));
    mgr.on_spawned("b.service", 201, 210).unwrap();

    // Wrong PID cannot complete PipeFd readiness either.
    assert!(!mgr.on_ready_fd("b.service", 999, 220).unwrap());
    assert!(mgr.on_ready_fd("b.service", 201, 220).unwrap());
    assert_eq!(mgr.unit_state("b.service"), Some(UnitState::Active));
}

#[test]
fn optional_cloud_mount_failure_never_blocks_boot_health_or_targets() {
    let graph = default_boot_graph(1000).unwrap();
    let mut mgr = ServiceManager::new_system(graph).unwrap();
    mgr.boot_target("multi-user.target").unwrap();

    // Offline boot MUST wait for `user-session@1000.service` `READY=1` BEFORE activating
    // `multi-user.target` or emitting `MarkBootHealthy` (Finding #10), with zero cloud units.
    let actions = mgr.tick(0);
    assert!(!actions.contains(&ManagerAction::MarkBootHealthy));
    assert!(!mgr.is_boot_healthy());
    assert_eq!(mgr.unit_state("local-fs.target"), Some(UnitState::Active));
    assert_eq!(
        mgr.unit_state("multi-user.target"),
        Some(UnitState::Inactive)
    );
    assert_eq!(mgr.unit_state("cloud.mount"), Some(UnitState::Inactive));
    mgr.on_spawned("user-session@1000.service", 10, 5).unwrap();
    mgr.on_notify(
        PeerCred {
            pid: 10,
            uid: 1000,
            gid: 1000,
        },
        b"READY=1\n",
        10,
    )
    .unwrap();
    assert_eq!(
        mgr.unit_state("user-session@1000.service"),
        Some(UnitState::Active)
    );
    let actions = mgr.tick(15);
    assert!(actions.contains(&ManagerAction::MarkBootHealthy));
    assert!(mgr.is_boot_healthy());
    assert_eq!(mgr.unit_state("multi-user.target"), Some(UnitState::Active));

    // User triggers `cloud-online.target` while offline: `cloud.mount` fails ENOTCONN (`Optional`).
    let root = PeerCred {
        pid: 1,
        uid: 0,
        gid: 0,
    };
    let (resp, actions) = mgr.handle_control(
        root,
        ControlRequest::Start {
            unit: "cloud-online.target".into(),
        },
        100,
    );
    assert!(matches!(resp, ControlResponse::Ok { .. }));
    assert!(actions.iter().any(|a| matches!(
        a,
        ManagerAction::MountFs { unit, .. } if unit == "cloud.mount"
    )));

    // Mount fails offline -> Optional failure logged, `multi-user.target` stays Active!
    let _ = mgr.on_mount_result("cloud.mount", Err("ENOTCONN: offline".into()), 120);
    assert_eq!(mgr.unit_state("cloud.mount"), Some(UnitState::Failed));
    assert_eq!(mgr.unit_state("multi-user.target"), Some(UnitState::Active));

    // Dependent optional `devattach@*` units are NOT deadlocked by optional `cloud.mount` failure.
    let actions = mgr.tick(130);
    assert!(actions.iter().any(|a| matches!(
        a,
        ManagerAction::SpawnService { unit, .. } if unit == "devattach@snd.service"
    )));
}

#[test]
fn restart_backoff_policy_retries_with_exponential_delay_up_to_limit() {
    let mut svc = simple_service("flaky.service", vec![], vec![]);
    svc.readiness = Readiness::Immediate;
    svc.restart = RestartPolicy::OnFailure {
        max_attempts: 2,
        backoff_ms: 100,
    };
    let graph = UnitGraph::build(vec![svc]).unwrap();
    let mut mgr = ServiceManager::new_system(graph).unwrap();
    mgr.boot_target("flaky.service").unwrap();

    // Initial spawn -> exits non-zero -> Backoff #1 (100ms).
    let actions = mgr.tick(0);
    assert!(matches!(actions[0], ManagerAction::SpawnService { .. }));
    mgr.on_spawned("flaky.service", 50, 0).unwrap();
    let _ = mgr.on_exited(50, 1, 10);
    assert_eq!(mgr.unit_state("flaky.service"), Some(UnitState::Backoff));
    assert!(mgr.tick(109).is_empty());

    // At t=110 (10 + 100): Retry #1 spawns -> crashes -> Backoff #2 (200ms).
    let actions = mgr.tick(110);
    assert!(matches!(actions[0], ManagerAction::SpawnService { .. }));
    mgr.on_spawned("flaky.service", 51, 110).unwrap();
    let _ = mgr.on_exited(51, 2, 120);
    assert_eq!(mgr.unit_state("flaky.service"), Some(UnitState::Backoff));
    assert!(mgr.tick(319).is_empty());

    // At t=320 (120 + 200): Retry #2 spawns -> crashes -> limit reached -> Failed!
    let actions = mgr.tick(320);
    assert!(matches!(actions[0], ManagerAction::SpawnService { .. }));
    mgr.on_spawned("flaky.service", 52, 320).unwrap();
    let _ = mgr.on_exited(52, 3, 330);
    assert_eq!(mgr.unit_state("flaky.service"), Some(UnitState::Failed));
    assert!(mgr.tick(10_000).is_empty());
}

#[test]
fn control_socket_so_peercred_and_per_user_manager_refuse_privilege_escalation() {
    let graph = default_boot_graph(1000).unwrap();
    let mut sys_mgr = ServiceManager::new_system(graph).unwrap();
    let unpriv = PeerCred {
        pid: 42,
        uid: 1000,
        gid: 1000,
    };

    // Unprivileged user may query `List` and `Status` on system control socket...
    let (resp, _) = sys_mgr.handle_control(unpriv, ControlRequest::List, 0);
    assert!(matches!(resp, ControlResponse::Units { .. }));

    // ...but EVERY mutating operation on system control socket is refused with EPERM!
    for req in [
        ControlRequest::Start {
            unit: "cloud.mount".into(),
        },
        ControlRequest::Stop {
            unit: "multi-user.target".into(),
        },
        ControlRequest::Restart {
            unit: "user-session@1000.service".into(),
        },
        ControlRequest::Enable {
            unit: "cloud.mount".into(),
        },
        ControlRequest::Disable {
            unit: "cloud.mount".into(),
        },
        ControlRequest::Poweroff,
        ControlRequest::Reboot,
    ] {
        let (resp, actions) = sys_mgr.handle_control(unpriv, req, 0);
        assert!(
            matches!(
                resp,
                ControlResponse::Error {
                    errno: Errno::EPERM,
                    ..
                }
            ),
            "expected EPERM for unprivileged mutating op, got {resp:?}"
        );
        assert!(actions.is_empty());
    }

    // Per-user service manager (uid 1000) socket path & strict peer/grant boundaries.
    assert_eq!(user_manager_socket(1000), "/run/user/1000/manager.sock");
    let mut user_unit = simple_service("my-daemon.service", vec![], vec![]);
    user_unit.grant.mount_namespace = MountNsPolicy::Session;
    let user_graph = UnitGraph::build(vec![user_unit]).unwrap();
    let mut user_mgr = ServiceManager::new_user(1000, user_graph).unwrap();

    // Another user (uid 1001) is rejected even for read-only `List`.
    let other_user = PeerCred {
        pid: 77,
        uid: 1001,
        gid: 1001,
    };
    let (resp, _) = user_mgr.handle_control(other_user, ControlRequest::List, 0);
    assert!(matches!(
        resp,
        ControlResponse::Error {
            errno: Errno::EPERM,
            ..
        }
    ));

    // Owner (uid 1000) CANNOT poweroff/reboot or register a unit with `grant.user = "root"`.
    let (resp, _) = user_mgr.handle_control(unpriv, ControlRequest::Poweroff, 0);
    assert!(matches!(
        resp,
        ControlResponse::Error {
            errno: Errno::EPERM,
            ..
        }
    ));

    let mut priv_esc = simple_service("evil.service", vec![], vec![]);
    priv_esc.grant.mount_namespace = MountNsPolicy::Isolated;
    priv_esc.grant.user = Some("root".into());
    let (resp, _) = user_mgr.handle_control(
        unpriv,
        ControlRequest::RegisterUnit {
            spec: Box::new(priv_esc),
        },
        0,
    );
    assert!(matches!(
        resp,
        ControlResponse::Error {
            errno: Errno::EPERM,
            ..
        }
    ));

    // Owner CAN register and start a properly scoped user unit with empty `cloud_scope`.
    let mut good = simple_service("helper.service", vec![], vec![]);
    good.grant.mount_namespace = MountNsPolicy::Session;
    good.grant.cloud_scope = RemoteScope::default();
    let (resp, _) = user_mgr.handle_control(
        unpriv,
        ControlRequest::RegisterUnit {
            spec: Box::new(good),
        },
        0,
    );
    assert!(matches!(resp, ControlResponse::Ok { .. }));

    // Framing round-trip sanity.
    let encoded_req = encode_request_frame(&ControlRequest::Start {
        unit: "helper.service".into(),
    })
    .unwrap();
    assert_eq!(
        decode_request_frame(&encoded_req).unwrap(),
        ControlRequest::Start {
            unit: "helper.service".into()
        }
    );
    let encoded_resp = encode_response_frame(&ControlResponse::Ok {
        message: Some("ok".into()),
    })
    .unwrap();
    assert_eq!(
        decode_response_frame(&encoded_resp).unwrap(),
        ControlResponse::Ok {
            message: Some("ok".into())
        }
    );
    assert!(NotifyMessage::parse(b"READY=1\nSTATUS=up\n").unwrap().ready);
}

#[test]
fn ordered_reverse_shutdown_unmounts_cloud_escalates_sigkill_and_closes_root() {
    let graph = default_boot_graph(1000).unwrap();
    let mut mgr = ServiceManager::new_system(graph).unwrap();
    let root = PeerCred {
        pid: 1,
        uid: 0,
        gid: 0,
    };

    // Bring up local boot + cloud-online.target (`cloud.mount` + `devattach@*`).
    mgr.boot_target("multi-user.target").unwrap();
    let _ = mgr.tick(0);
    mgr.on_spawned("user-session@1000.service", 10, 0).unwrap();
    mgr.on_notify(
        PeerCred {
            pid: 10,
            uid: 1000,
            gid: 1000,
        },
        b"READY=1\n",
        1,
    )
    .unwrap();
    let actions = mgr.tick(2);
    assert!(actions.contains(&ManagerAction::MarkBootHealthy));
    assert_eq!(mgr.unit_state("multi-user.target"), Some(UnitState::Active));

    let (_, _) = mgr.handle_control(
        root,
        ControlRequest::Start {
            unit: "cloud-online.target".into(),
        },
        10,
    );
    mgr.on_mount_result("cloud.mount", Ok(()), 15);
    let actions = mgr.tick(20);
    let mut next_pid = 20u32;
    for action in actions {
        if let ManagerAction::SpawnService { unit, .. } = action {
            mgr.on_spawned(&unit, next_pid, 20).unwrap();
            mgr.on_notify(
                PeerCred {
                    pid: next_pid,
                    uid: 0,
                    gid: 0,
                },
                b"READY=1\n",
                25,
            )
            .unwrap();
            next_pid += 1;
        }
    }
    let _ = mgr.tick(30);
    assert_eq!(
        mgr.unit_state("cloud-online.target"),
        Some(UnitState::Active)
    );

    // Initiate `Poweroff`: MUST stop `cloud-online.target` and `devattach@*` FIRST, BEFORE `cloud.mount`!
    let (resp, actions) = mgr.handle_control(root, ControlRequest::Poweroff, 1000);
    assert!(matches!(resp, ControlResponse::Ok { .. }));
    assert_eq!(
        mgr.unit_state("cloud-online.target"),
        Some(UnitState::Inactive)
    );
    // `devattach@*` receive SIGTERM; `cloud.mount` MUST NOT unmount yet while devattach is stopping!
    let dev_pids: Vec<u32> = actions
        .iter()
        .filter_map(|a| match a {
            ManagerAction::SignalUnit { unit, pid, signal }
                if unit.starts_with("devattach@") && *signal == abi::SIGTERM =>
            {
                Some(*pid)
            }
            _ => None,
        })
        .collect();
    assert_eq!(dev_pids.len(), 4);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, ManagerAction::UmountFs { .. })),
        "cloud.mount must wait for devattach@* to stop first"
    );

    // All 4 devattach services exit cleanly.
    for pid in dev_pids {
        let _ = mgr.on_exited(pid, 0, 1050);
    }

    // Next tick: `cloud.mount` unmounts AND `user-session@1000.service` receives SIGTERM!
    let actions = mgr.tick(1100);
    assert!(actions.iter().any(|a| matches!(
        a,
        ManagerAction::UmountFs { unit, target } if unit == "cloud.mount" && target == "/mnt/cloud"
    )));
    assert!(actions.iter().any(|a| matches!(
        a,
        ManagerAction::SignalUnit { unit, pid: 10, signal }
            if unit == "user-session@1000.service" && *signal == abi::SIGTERM
    )));
    assert!(!mgr.is_shutdown_complete());

    // Simulate `user-session@1000.service` ignoring SIGTERM past `stop_timeout_ms` (3000ms) -> SIGKILL!
    let actions = mgr.tick(1100 + 3000);
    assert!(actions.iter().any(|a| matches!(
        a,
        ManagerAction::SignalUnit { unit, pid: 10, signal }
            if unit == "user-session@1000.service" && *signal == abi::SIGKILL
    )));
    let _ = mgr.on_exited(10, 137, 4200);

    // Final tick tears down `multi-user.target` & `local-fs.target` and emits `CloseCleanRoot`!
    let actions = mgr.tick(4300);
    assert!(actions.contains(&ManagerAction::CloseCleanRoot { reboot: false }));
    assert!(mgr.is_shutdown_complete());
}

#[test]
fn template_authorization_and_shutdown_restart_guards_prevent_desync_or_escalation() {
    // 1. Per-user manager MUST reject a graph containing a template with `grant.user` elevation.
    let mut bad_tmpl = simple_service("elevate@.service", vec![], vec![]);
    bad_tmpl.grant.mount_namespace = MountNsPolicy::Session;
    bad_tmpl.grant.user = Some("%i".into());
    let bad_graph = UnitGraph::build(vec![bad_tmpl]).unwrap();
    assert_eq!(
        ServiceManager::new_user(1000, bad_graph)
            .err()
            .unwrap()
            .errno,
        Errno::EPERM
    );

    // 2. Dynamic registration of a forbidden template on a per-user manager fails EPERM without
    // mutating graph or desyncing runtime state; subsequent ticks never panic.
    let mut ok_tmpl = simple_service("worker@.service", vec![], vec![]);
    ok_tmpl.grant.mount_namespace = MountNsPolicy::Session;
    let mut user_mgr =
        ServiceManager::new_user(1000, UnitGraph::build(vec![ok_tmpl]).unwrap()).unwrap();
    let owner = PeerCred {
        pid: 88,
        uid: 1000,
        gid: 1000,
    };
    let mut sys_tmpl = simple_service("escape@.service", vec![], vec![]);
    sys_tmpl.grant.mount_namespace = MountNsPolicy::System;
    let (resp, _) = user_mgr.handle_control(
        owner,
        ControlRequest::RegisterUnit {
            spec: Box::new(sys_tmpl),
        },
        0,
    );
    assert!(matches!(
        resp,
        ControlResponse::Error {
            errno: Errno::EPERM,
            ..
        }
    ));
    // Starting an allowed template instance works cleanly and stays in sync with `tick()`.
    let (resp, actions) = user_mgr.handle_control(
        owner,
        ControlRequest::Start {
            unit: "worker@alpha.service".into(),
        },
        10,
    );
    assert!(matches!(resp, ControlResponse::Ok { .. }));
    assert_eq!(actions.len(), 1);
    assert!(user_mgr.graph().unit("worker@alpha.service").is_some());
    assert_eq!(
        user_mgr.unit_state("worker@alpha.service"),
        Some(UnitState::Starting)
    );
    let _ = user_mgr.tick(20);

    // 3. `ControlRequest::Restart` during active shutdown returns `EBUSY` (matching `Start`).
    let graph = default_boot_graph(1000).unwrap();
    let mut sys_mgr = ServiceManager::new_system(graph).unwrap();
    let root = PeerCred {
        pid: 1,
        uid: 0,
        gid: 0,
    };
    sys_mgr.boot_target("multi-user.target").unwrap();
    let _ = sys_mgr.tick(0);
    sys_mgr
        .on_spawned("user-session@1000.service", 10, 0)
        .unwrap();
    let (resp, _) = sys_mgr.handle_control(root, ControlRequest::Poweroff, 100);
    assert!(matches!(resp, ControlResponse::Ok { .. }));
    let (resp, actions) = sys_mgr.handle_control(
        root,
        ControlRequest::Restart {
            unit: "user-session@1000.service".into(),
        },
        110,
    );
    assert!(matches!(
        resp,
        ControlResponse::Error {
            errno: Errno::EBUSY,
            ..
        }
    ));
    assert!(actions.is_empty());
}
