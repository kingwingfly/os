//! Portable conformance tests CS-01..CS-07 exercising `MemoryClusterStore`, `authz`, and `fencing`.
use abi::Errno;
use abi::auth_v2::RemoteScope;
use abi::cluster_state::{
    AttemptRecord, CLUSTER_MAX_KEYS_PER_LEASE, CLUSTER_TXN_MAX_COMPARES, CLUSTER_TXN_MAX_OPS,
    CLUSTER_VALUE_MAX_BYTES, ClusterCall, ClusterReply, Compare, CompareOp, CompareTarget,
    NodeMetaRecord, NodeRecord, OutboxRecord, RangeEnd, ResultRecord, TxnOp, TxnOpReply,
    WatchEventType, WorkloadRecord, encode_value_b64,
};
use abi::contract::Boundary;
use os_cluster_state::fencing::{
    FencedPublishFailure, FencedPublishOutcome, build_admit_workload_txn,
    build_cancel_workload_txn, build_claim_attempt_txn, build_publish_result_txn,
    build_register_node_txn, classify_fenced_publish_result, decode_record, node_key,
    node_meta_key, result_key, workload_key,
};
use os_cluster_state::memory::MemoryClusterStore;
use os_cluster_state::{ClusterGrant, ClusterStore, WatchCursor};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn block_on<F: Future>(fut: F) -> F::Output {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    match Pin::as_mut(&mut fut).poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("MemoryClusterStore future unexpectedly returned Pending"),
    }
}

fn admin_grant(tenant: &str) -> ClusterGrant {
    ClusterGrant {
        tenant: tenant.into(),
        owner: format!("owner-{tenant}"),
        admin: tenant == "u0",
        scope: RemoteScope::full(),
    }
}

fn b64(s: &str) -> String {
    encode_value_b64(s.as_bytes()).unwrap()
}

fn put(
    store: &MemoryClusterStore,
    grant: &ClusterGrant,
    key: &str,
    val: &str,
    lease_id: u64,
    now: u64,
) -> u64 {
    let reply = block_on(store.rpc(
        grant,
        ClusterCall::Txn {
            compare: vec![],
            success: vec![TxnOp::Put {
                key: key.into(),
                value_b64: b64(val),
                lease_id,
                prev_kv: false,
            }],
            failure: vec![],
        },
        now,
    ))
    .unwrap();
    match reply {
        ClusterReply::Txn {
            revision,
            succeeded,
            ..
        } => {
            assert!(succeeded);
            revision
        }
        other => panic!("unexpected reply: {other:?}"),
    }
}

#[test]
fn cs01_revisioned_kv_and_historical_range() {
    let store = MemoryClusterStore::new("default");
    let root = admin_grant("u0");

    // Hello negotiation
    let welcome = block_on(store.rpc(
        &root,
        ClusterCall::Hello {
            versions: vec![99, 1],
        },
        100,
    ))
    .unwrap();
    assert!(matches!(
        welcome,
        ClusterReply::Welcome {
            boundary: Boundary::ClusterState,
            version: 1,
            revision: 0,
            compacted_floor: 0,
            ..
        }
    ));
    let bad_ver =
        block_on(store.rpc(&root, ClusterCall::Hello { versions: vec![99] }, 100)).unwrap_err();
    assert_eq!(bad_ver.errno, Errno::EPROTONOSUPPORT);

    // Put create, overwrite, delete, re-create
    let r1 = put(&store, &root, "/t/u0/kv/a", "v1", 0, 100);
    assert_eq!(r1, 1);
    let r2 = put(&store, &root, "/t/u0/kv/a", "v2", 0, 101);
    assert_eq!(r2, 2);
    let r3 = put(&store, &root, "/t/u0/kv/b", "vb", 0, 102);
    assert_eq!(r3, 3);

    // Historical range at r1 still returns v1 with version=1
    let hist = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/kv/a".into(),
            range_end: RangeEnd::Exact,
            revision: r1,
            limit: None,
            keys_only: false,
            count_only: false,
        },
        102,
    ))
    .unwrap();
    match hist {
        ClusterReply::Range {
            revision,
            kvs,
            count,
            ..
        } => {
            assert_eq!(revision, r3);
            assert_eq!(count, 1);
            assert_eq!(kvs[0].value_b64, b64("v1"));
            assert_eq!(kvs[0].create_revision, r1);
            assert_eq!(kvs[0].mod_revision, r1);
            assert_eq!(kvs[0].version, 1);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Current read shows create_revision preserved, version=2
    let cur = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/kv/".into(),
            range_end: RangeEnd::Prefix,
            revision: 0,
            limit: Some(1),
            keys_only: false,
            count_only: false,
        },
        102,
    ))
    .unwrap();
    match cur {
        ClusterReply::Range {
            kvs, more, count, ..
        } => {
            assert_eq!(count, 2);
            assert!(more);
            assert_eq!(kvs.len(), 1);
            assert_eq!(kvs[0].key, "/t/u0/kv/a");
            assert_eq!(kvs[0].create_revision, r1);
            assert_eq!(kvs[0].mod_revision, r2);
            assert_eq!(kvs[0].version, 2);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // keys_only and count_only
    let ko = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/kv/".into(),
            range_end: RangeEnd::Prefix,
            revision: 0,
            limit: None,
            keys_only: true,
            count_only: false,
        },
        102,
    ))
    .unwrap();
    match ko {
        ClusterReply::Range { kvs, .. } => {
            assert_eq!(kvs.len(), 2);
            assert!(kvs.iter().all(|k| k.value_b64.is_empty()));
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Future revision rejected
    let fut_err = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/kv/a".into(),
            range_end: RangeEnd::Exact,
            revision: 99,
            limit: None,
            keys_only: false,
            count_only: false,
        },
        102,
    ))
    .unwrap_err();
    assert_eq!(fut_err.errno, Errno::ERANGE);
}

#[test]
fn cs02_atomic_txn_compares_and_pre_compare_authz() {
    let store = MemoryClusterStore::new("default");
    let root = admin_grant("u0");

    // Atomic multi-op CAS on absent key (Version == 0)
    let r1 = block_on(store.rpc(
        &root,
        ClusterCall::Txn {
            compare: vec![Compare {
                key: "/t/u0/lock/x".into(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            }],
            success: vec![
                TxnOp::Put {
                    key: "/t/u0/lock/x".into(),
                    value_b64: b64("holder-1"),
                    lease_id: 0,
                    prev_kv: true,
                },
                TxnOp::Put {
                    key: "/t/u0/lock/meta".into(),
                    value_b64: b64("m1"),
                    lease_id: 0,
                    prev_kv: false,
                },
            ],
            failure: vec![],
        },
        100,
    ))
    .unwrap();
    match r1 {
        ClusterReply::Txn {
            revision,
            succeeded,
            responses,
            ..
        } => {
            assert!(succeeded);
            assert_eq!(revision, 1);
            assert_eq!(responses.len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Failed compare runs only failure branch and does not advance revision
    let r2 = block_on(store.rpc(
        &root,
        ClusterCall::Txn {
            compare: vec![Compare {
                key: "/t/u0/lock/x".into(),
                op: CompareOp::Equal,
                target: CompareTarget::Value(b64("holder-2")),
            }],
            success: vec![TxnOp::Put {
                key: "/t/u0/lock/x".into(),
                value_b64: b64("should-not-write"),
                lease_id: 0,
                prev_kv: false,
            }],
            failure: vec![TxnOp::Range {
                key: "/t/u0/lock/x".into(),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                keys_only: false,
                count_only: false,
            }],
        },
        101,
    ))
    .unwrap();
    match r2 {
        ClusterReply::Txn {
            revision,
            succeeded,
            responses,
            ..
        } => {
            assert!(!succeeded);
            assert_eq!(revision, 1);
            assert!(
                matches!(&responses[0], TxnOpReply::Range { kvs, .. } if kvs[0].value_b64 == b64("holder-1"))
            );
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Pre-compare authz: read-only grant cannot smuggle a Put in the UNTAKEN failure branch
    let ro = ClusterGrant {
        tenant: "u0".into(),
        owner: "ro".into(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            ..Default::default()
        },
    };
    let denied = block_on(store.rpc(
        &ro,
        ClusterCall::Txn {
            compare: vec![Compare {
                key: "/t/u0/lock/x".into(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(1),
            }],
            success: vec![TxnOp::Range {
                key: "/t/u0/lock/x".into(),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                keys_only: false,
                count_only: false,
            }],
            failure: vec![TxnOp::Put {
                key: "/t/u0/lock/x".into(),
                value_b64: b64("smuggled"),
                lease_id: 0,
                prev_kv: false,
            }],
        },
        101,
    ))
    .unwrap_err();
    assert_eq!(denied.errno, Errno::EACCES);

    // Duplicate key put in one Txn fails EINVAL atomically
    let dup = block_on(store.rpc(
        &root,
        ClusterCall::Txn {
            compare: vec![],
            success: vec![
                TxnOp::Put {
                    key: "/t/u0/dup/a".into(),
                    value_b64: b64("1"),
                    lease_id: 0,
                    prev_kv: false,
                },
                TxnOp::Put {
                    key: "/t/u0/dup/a".into(),
                    value_b64: b64("2"),
                    lease_id: 0,
                    prev_kv: false,
                },
            ],
            failure: vec![],
        },
        101,
    ))
    .unwrap_err();
    assert_eq!(dup.errno, Errno::EINVAL);
}

#[test]
fn cs03_cs04_cs05_watch_catchup_leases_and_compaction() {
    let store = MemoryClusterStore::new("default");
    let root = admin_grant("u0");

    // Grant lease, attach node key, verify keepalive & TTL
    let lease_id = match block_on(store.rpc(
        &root,
        ClusterCall::LeaseGrant {
            ttl_secs: 10,
            node_id: Some("node-a".into()),
        },
        1000,
    ))
    .unwrap()
    {
        ClusterReply::LeaseGranted {
            lease_id,
            expires_at,
            ..
        } => {
            assert_eq!(expires_at, 1010);
            lease_id
        }
        other => panic!("unexpected: {other:?}"),
    };

    put(&store, &root, "/t/u0/node-meta/node-a", "meta", 0, 1000);
    put(&store, &root, "/t/u0/nodes/node-a", "alive", lease_id, 1000);
    let kept = block_on(store.rpc(&root, ClusterCall::LeaseKeepAlive { lease_id }, 1005)).unwrap();
    assert!(matches!(
        kept,
        ClusterReply::LeaseKeptAlive {
            expires_at: 1015,
            ..
        }
    ));

    let ttl = block_on(store.rpc(
        &root,
        ClusterCall::LeaseTimeToLive {
            lease_id,
            keys: true,
        },
        1007,
    ))
    .unwrap();
    match ttl {
        ClusterReply::LeaseTtl {
            remaining_ttl_secs,
            keys,
            ..
        } => {
            assert_eq!(remaining_ttl_secs, 8);
            assert_eq!(keys, vec!["/t/u0/nodes/node-a"]);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Expire lease at t=1016 -> nodes/node-a deleted, node-meta/node-a preserved!
    assert_eq!(store.expire_due_leases(1016), 1);

    // Watch from revision 1 sees Put then Delete with prev_kv
    let mut cursor = WatchCursor::new("/t/u0/nodes/", RangeEnd::Prefix, 1, true);
    let batch = block_on(store.poll_watch(&root, &mut cursor, 16, 1016)).unwrap();
    assert_eq!(batch.events.len(), 2);
    assert_eq!(batch.events[0].event_type, WatchEventType::Put);
    assert_eq!(batch.events[1].event_type, WatchEventType::Delete);
    assert_eq!(
        batch.events[1].prev_kv.as_ref().unwrap().value_b64,
        b64("alive")
    );

    // Durable node-meta survives lease expiry
    let meta_range = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/node-meta/node-a".into(),
            range_end: RangeEnd::Exact,
            revision: 0,
            limit: None,
            keys_only: false,
            count_only: false,
        },
        1016,
    ))
    .unwrap();
    assert!(matches!(meta_range, ClusterReply::Range { count: 1, .. }));

    // Generate 150 mutations to test paginated watch catch-up (> 128 batch)
    let start_rev = store.current_revision() + 1;
    for i in 0..150u32 {
        put(
            &store,
            &root,
            &format!("/t/u0/stream/k{i:03}"),
            &format!("v{i}"),
            0,
            1020,
        );
    }
    let mut c2 = WatchCursor::new("/t/u0/stream/", RangeEnd::Prefix, start_rev, false);
    let b1 = block_on(store.poll_watch(&root, &mut c2, 128, 1020)).unwrap();
    assert_eq!(b1.events.len(), 128);
    assert!(b1.more);
    let b2 = block_on(store.poll_watch(&root, &mut c2, 128, 1020)).unwrap();
    assert_eq!(b2.events.len(), 22);
    assert!(!b2.more);

    // Compact at current_revision - 5 -> older historical range and older watch get Compacted{floor}
    let floor = store.current_revision() - 5;
    let compacted =
        block_on(store.rpc(&root, ClusterCall::Compact { revision: floor }, 1020)).unwrap();
    assert!(matches!(
        compacted,
        ClusterReply::Compacted {
            compacted_floor,
            ..
        } if compacted_floor == floor
    ));

    let stale_range = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/stream/".into(),
            range_end: RangeEnd::Prefix,
            revision: floor - 1,
            limit: None,
            keys_only: false,
            count_only: false,
        },
        1020,
    ))
    .unwrap_err();
    assert_eq!(stale_range.errno, Errno::ESTALE);
    assert_eq!(stale_range.compacted.unwrap().floor, floor);

    let mut lagged = WatchCursor::new("/t/u0/stream/", RangeEnd::Prefix, 1, false);
    let stale_watch = block_on(store.poll_watch(&root, &mut lagged, 16, 1020)).unwrap_err();
    assert_eq!(stale_watch.errno, Errno::ESTALE);
    assert_eq!(stale_watch.compacted.unwrap().floor, floor);
}

#[test]
fn cs06_fenced_node_attempt_cancel_and_publish_lifecycle() {
    let store = MemoryClusterStore::new("default");
    let root = admin_grant("u0");
    let tenant = "u0";

    let grant_lease = |node_id: &str, now: u64| -> u64 {
        match block_on(store.rpc(
            &root,
            ClusterCall::LeaseGrant {
                ttl_secs: 30,
                node_id: Some(node_id.into()),
            },
            now,
        ))
        .unwrap()
        {
            ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
            other => panic!("unexpected: {other:?}"),
        }
    };

    // 1. Register node-a (gen 1, lease l1) and node-b (gen 1, lease l2)
    let l1 = grant_lease("node-a", 100);
    let meta_a = NodeMetaRecord {
        node_id: "node-a".into(),
        host_kind: "os-native".into(),
        labels: BTreeMap::new(),
        capabilities: vec!["wasix".into()],
        enrolled_at: 100,
    };
    let node_a1 = NodeRecord {
        node_id: "node-a".into(),
        node_generation: 1,
        instance_id: "inst-a1".into(),
        lease_id: l1,
        status: "ready".into(),
        heartbeat_at: 100,
    };
    let reg_a1 = block_on(store.rpc(
        &root,
        build_register_node_txn(tenant, &meta_a, &node_a1, None).unwrap(),
        100,
    ))
    .unwrap();
    let node_a1_rev = match reg_a1 {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected node-a register: {other:?}"),
    };

    let l2 = grant_lease("node-b", 100);
    let meta_b = NodeMetaRecord {
        node_id: "node-b".into(),
        host_kind: "container".into(),
        labels: BTreeMap::new(),
        capabilities: vec!["wasix".into()],
        enrolled_at: 100,
    };
    let node_b1 = NodeRecord {
        node_id: "node-b".into(),
        node_generation: 1,
        instance_id: "inst-b1".into(),
        lease_id: l2,
        status: "ready".into(),
        heartbeat_at: 100,
    };
    let node_b1_rev = match block_on(store.rpc(
        &root,
        build_register_node_txn(tenant, &meta_b, &node_b1, None).unwrap(),
        100,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected node-b register: {other:?}"),
    };

    // 2. Admit workload wl-1 with notice-only outbox
    let wl1 = WorkloadRecord {
        workload_id: "wl-1".into(),
        image_ref: "oci:team/app@sha256:00".into(),
        input_snapshot_ref: None,
        labels: BTreeMap::new(),
        desired_state: "pending".into(),
        current_attempt: 0,
        created_at: 101,
    };
    let ob1 = OutboxRecord {
        outbox_id: "ob-wl1-1".into(),
        workload_id: "wl-1".into(),
        attempt_generation: 0,
        kind: "attempt_ready".into(),
        created_at: 101,
    };
    let wl1_rev = match block_on(store.rpc(
        &root,
        build_admit_workload_txn(tenant, &wl1, Some(&ob1)).unwrap(),
        101,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected admit: {other:?}"),
    };

    // 3. Node A claims attempt 1
    let mut wl1_att1 = wl1.clone();
    wl1_att1.desired_state = "running".into();
    wl1_att1.current_attempt = 1;
    let att1 = AttemptRecord {
        workload_id: "wl-1".into(),
        attempt_generation: 1,
        node_id: "node-a".into(),
        node_generation: 1,
        node_lease_id: l1,
        state: "claimed".into(),
        claimed_at: 102,
        finished_at: None,
    };
    let att1_rev = match block_on(store.rpc(
        &root,
        build_claim_attempt_txn(tenant, wl1_rev, node_a1_rev, l1, &wl1_att1, &att1).unwrap(),
        102,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected claim 1: {other:?}"),
    };

    // 4. Node A loses its lease (e.g. network partition / crash -> lease l1 expires at t=131)
    assert_eq!(store.expire_due_leases(131), 2); // l1 and l2 both expired; re-register node-b!
    let l2_new = grant_lease("node-b", 132);
    let node_b2 = NodeRecord {
        node_id: "node-b".into(),
        node_generation: 2,
        instance_id: "inst-b2".into(),
        lease_id: l2_new,
        status: "ready".into(),
        heartbeat_at: 132,
    };
    let node_b2_rev = match block_on(store.rpc(
        &root,
        build_register_node_txn(tenant, &meta_b, &node_b2, None).unwrap(),
        132,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected node-b2: {other:?}"),
    };
    let _ = node_b1_rev;

    // 5. Stale Node A tries to publish attempt 1 after lease expiry -> NodeFenced (ESTALE)!
    let mut wl1_done_a = wl1_att1.clone();
    wl1_done_a.desired_state = "succeeded".into();
    let mut att1_done = att1.clone();
    att1_done.state = "succeeded".into();
    att1_done.finished_at = Some(133);
    let res_a = ResultRecord {
        workload_id: "wl-1".into(),
        attempt_generation: 1,
        node_id: "node-a".into(),
        node_generation: 1,
        exit_code: 0,
        output_ref: Some("remote:snapshot:vol@stale".into()),
        summary: None,
        published_at: 133,
    };
    let stale_pub = block_on(
        store.rpc(
            &root,
            build_publish_result_txn(
                tenant,
                att1_rev,
                node_a1_rev,
                l1,
                att1_rev,
                &wl1_done_a,
                &att1_done,
                &res_a,
                None,
            )
            .unwrap(),
            133,
        ),
    )
    .unwrap();
    let classified =
        classify_fenced_publish_result(&stale_pub, att1_rev, node_a1_rev, l1, att1_rev).unwrap();
    assert_eq!(
        classified,
        FencedPublishOutcome::Rejected(FencedPublishFailure::NodeFenced)
    );
    assert_eq!(FencedPublishFailure::NodeFenced.errno(), Errno::ESTALE);

    // 6. Node B claims attempt 2 and publishes cleanly -> Published!
    let mut wl1_att2 = wl1.clone();
    wl1_att2.desired_state = "running".into();
    wl1_att2.current_attempt = 2;
    let att2 = AttemptRecord {
        workload_id: "wl-1".into(),
        attempt_generation: 2,
        node_id: "node-b".into(),
        node_generation: 2,
        node_lease_id: l2_new,
        state: "claimed".into(),
        claimed_at: 134,
        finished_at: None,
    };
    let att2_rev = match block_on(store.rpc(
        &root,
        build_claim_attempt_txn(tenant, att1_rev, node_b2_rev, l2_new, &wl1_att2, &att2).unwrap(),
        134,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected claim 2: {other:?}"),
    };

    let mut wl1_done_b = wl1_att2.clone();
    wl1_done_b.desired_state = "succeeded".into();
    let mut att2_done = att2.clone();
    att2_done.state = "succeeded".into();
    att2_done.finished_at = Some(135);
    let res_b = ResultRecord {
        workload_id: "wl-1".into(),
        attempt_generation: 2,
        node_id: "node-b".into(),
        node_generation: 2,
        exit_code: 0,
        output_ref: Some("remote:snapshot:vol@good".into()),
        summary: Some("ok".into()),
        published_at: 135,
    };
    let ok_pub = block_on(
        store.rpc(
            &root,
            build_publish_result_txn(
                tenant,
                att2_rev,
                node_b2_rev,
                l2_new,
                att2_rev,
                &wl1_done_b,
                &att2_done,
                &res_b,
                None,
            )
            .unwrap(),
            135,
        ),
    )
    .unwrap();
    assert!(matches!(
        classify_fenced_publish_result(&ok_pub, att2_rev, node_b2_rev, l2_new, att2_rev).unwrap(),
        FencedPublishOutcome::Published { .. }
    ));

    // Duplicate publish attempt -> AlreadyPublished (EEXIST)
    let dup_pub = block_on(
        store.rpc(
            &root,
            build_publish_result_txn(
                tenant,
                att2_rev,
                node_b2_rev,
                l2_new,
                att2_rev,
                &wl1_done_b,
                &att2_done,
                &res_b,
                None,
            )
            .unwrap(),
            136,
        ),
    )
    .unwrap();
    assert_eq!(
        classify_fenced_publish_result(&dup_pub, att2_rev, node_b2_rev, l2_new, att2_rev).unwrap(),
        FencedPublishOutcome::Rejected(FencedPublishFailure::AlreadyPublished)
    );

    // Stored result decodes cleanly to res_b
    let stored = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: result_key(tenant, "wl-1").unwrap(),
            range_end: RangeEnd::Exact,
            revision: 0,
            limit: None,
            keys_only: false,
            count_only: false,
        },
        136,
    ))
    .unwrap();
    match stored {
        ClusterReply::Range { kvs, .. } => {
            let decoded: ResultRecord = decode_record(&kvs[0]).unwrap();
            assert_eq!(decoded, res_b);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // 7. Canceled workload prevents late publish -> Canceled (ECANCELED)
    let wl2 = WorkloadRecord {
        workload_id: "wl-2".into(),
        image_ref: "oci:team/app@sha256:00".into(),
        input_snapshot_ref: None,
        labels: BTreeMap::new(),
        desired_state: "pending".into(),
        current_attempt: 0,
        created_at: 137,
    };
    let wl2_rev = match block_on(store.rpc(
        &root,
        build_admit_workload_txn(tenant, &wl2, None).unwrap(),
        137,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected wl2 admit: {other:?}"),
    };
    let mut wl2_att1 = wl2.clone();
    wl2_att1.desired_state = "running".into();
    wl2_att1.current_attempt = 1;
    let att_wl2 = AttemptRecord {
        workload_id: "wl-2".into(),
        attempt_generation: 1,
        node_id: "node-b".into(),
        node_generation: 2,
        node_lease_id: l2_new,
        state: "claimed".into(),
        claimed_at: 138,
        finished_at: None,
    };
    let att_wl2_rev = match block_on(store.rpc(
        &root,
        build_claim_attempt_txn(tenant, wl2_rev, node_b2_rev, l2_new, &wl2_att1, &att_wl2).unwrap(),
        138,
    ))
    .unwrap()
    {
        ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } => revision,
        other => panic!("expected wl2 claim: {other:?}"),
    };
    let cancel_reply = block_on(store.rpc(
        &root,
        build_cancel_workload_txn(tenant, "wl-2", "user canceled", 139, None).unwrap(),
        139,
    ))
    .unwrap();
    assert!(matches!(
        cancel_reply,
        ClusterReply::Txn {
            succeeded: true,
            ..
        }
    ));

    let mut wl2_done = wl2_att1.clone();
    wl2_done.desired_state = "succeeded".into();
    let mut att_wl2_done = att_wl2.clone();
    att_wl2_done.state = "succeeded".into();
    let res_wl2 = ResultRecord {
        workload_id: "wl-2".into(),
        attempt_generation: 1,
        node_id: "node-b".into(),
        node_generation: 2,
        exit_code: 0,
        output_ref: None,
        summary: None,
        published_at: 140,
    };
    let late_pub = block_on(
        store.rpc(
            &root,
            build_publish_result_txn(
                tenant,
                att_wl2_rev,
                node_b2_rev,
                l2_new,
                att_wl2_rev,
                &wl2_done,
                &att_wl2_done,
                &res_wl2,
                None,
            )
            .unwrap(),
            140,
        ),
    )
    .unwrap();
    assert_eq!(
        classify_fenced_publish_result(&late_pub, att_wl2_rev, node_b2_rev, l2_new, att_wl2_rev)
            .unwrap(),
        FencedPublishOutcome::Rejected(FencedPublishFailure::Canceled)
    );
    assert_eq!(FencedPublishFailure::Canceled.errno(), Errno::ECANCELED);

    // Also verify helper keys match expected canonical layout
    assert_eq!(node_key("u0", "node-a").unwrap(), "/t/u0/nodes/node-a");
    assert_eq!(
        node_meta_key("u0", "node-a").unwrap(),
        "/t/u0/node-meta/node-a"
    );
    assert_eq!(workload_key("u0", "wl-1").unwrap(), "/t/u0/workloads/wl-1");
}

#[test]
fn cs07_tenant_isolation_prefix_node_binding_and_quotas() {
    let store = MemoryClusterStore::new("default");
    let root = admin_grant("u0");
    let alice = admin_grant("u1000");

    put(&store, &root, "/t/u0/secret/k", "root-secret", 0, 100);
    put(&store, &alice, "/t/u1000/data/k", "alice-data", 0, 100);

    // Tenant clamping: OpenEnded on u0 never sees u1000
    let u0_all = block_on(store.rpc(
        &root,
        ClusterCall::Range {
            key: "/t/u0/".into(),
            range_end: RangeEnd::OpenEnded,
            revision: 0,
            limit: None,
            keys_only: false,
            count_only: false,
        },
        100,
    ))
    .unwrap();
    match u0_all {
        ClusterReply::Range { kvs, .. } => {
            assert_eq!(kvs.len(), 1);
            assert_eq!(kvs[0].key, "/t/u0/secret/k");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Cross-tenant key access fails EACCES
    assert_eq!(
        block_on(store.rpc(
            &alice,
            ClusterCall::Range {
                key: "/t/u0/secret/k".into(),
                range_end: RangeEnd::Exact,
                revision: 0,
                limit: None,
                keys_only: false,
                count_only: false,
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );

    // Non-admin compact fails EACCES
    assert_eq!(
        block_on(store.rpc(&alice, ClusterCall::Compact { revision: 1 }, 100))
            .unwrap_err()
            .errno,
        Errno::EACCES
    );

    // Prefix-scoped grant blocks OpenEnded escape and out-of-prefix prefix scan
    let scoped = ClusterGrant {
        tenant: "u0".into(),
        owner: "scoped".into(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_watch: true,
            cluster_prefixes: vec!["workloads/*".into()],
            ..Default::default()
        },
    };
    put(&store, &scoped, "/t/u0/workloads/w1", "ok", 0, 100);
    assert_eq!(
        block_on(store.rpc(
            &scoped,
            ClusterCall::Range {
                key: "/t/u0/workloads/".into(),
                range_end: RangeEnd::OpenEnded,
                revision: 0,
                limit: None,
                keys_only: false,
                count_only: false,
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );
    assert_eq!(
        block_on(store.rpc(
            &scoped,
            ClusterCall::Range {
                key: "/t/u0/workloads".into(),
                range_end: RangeEnd::Prefix,
                revision: 0,
                limit: None,
                keys_only: false,
                count_only: false,
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );

    // Node-bound grant cannot write another node's record or lease
    let node1 = ClusterGrant {
        tenant: "u0".into(),
        owner: "n1".into(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_lease: true,
            cluster_node_id: Some("node-1".into()),
            ..Default::default()
        },
    };
    let n1_lease = match block_on(store.rpc(
        &node1,
        ClusterCall::LeaseGrant {
            ttl_secs: 30,
            node_id: Some("node-1".into()),
        },
        100,
    ))
    .unwrap()
    {
        ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(
        block_on(store.rpc(
            &node1,
            ClusterCall::LeaseGrant {
                ttl_secs: 30,
                node_id: Some("node-2".into()),
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );
    assert_eq!(
        block_on(store.rpc(
            &node1,
            ClusterCall::Txn {
                compare: vec![],
                success: vec![TxnOp::Put {
                    key: "/t/u0/nodes/node-2".into(),
                    value_b64: b64("hijack"),
                    lease_id: n1_lease,
                    prev_kv: false,
                }],
                failure: vec![],
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );
    put(
        &store,
        &node1,
        "/t/u0/nodes/node-1",
        "self-ok",
        n1_lease,
        100,
    );

    // Bounds: > 64 compares -> E2BIG, > 64 ops -> E2BIG, > 256 KiB value -> EFBIG, > 256 keys/lease -> EDQUOT
    let too_many_compares: Vec<Compare> = (0..=CLUSTER_TXN_MAX_COMPARES)
        .map(|i| Compare {
            key: format!("/t/u0/c/k{i}"),
            op: CompareOp::Equal,
            target: CompareTarget::Version(0),
        })
        .collect();
    assert_eq!(
        block_on(store.rpc(
            &root,
            ClusterCall::Txn {
                compare: too_many_compares,
                success: vec![],
                failure: vec![],
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::E2BIG
    );

    let too_many_ops: Vec<TxnOp> = (0..=CLUSTER_TXN_MAX_OPS)
        .map(|i| TxnOp::Range {
            key: format!("/t/u0/c/k{i}"),
            range_end: RangeEnd::Exact,
            limit: None,
            keys_only: false,
            count_only: false,
        })
        .collect();
    assert_eq!(
        block_on(store.rpc(
            &root,
            ClusterCall::Txn {
                compare: vec![],
                success: too_many_ops,
                failure: vec![],
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::E2BIG
    );

    let big = encode_value_b64(&vec![b'x'; CLUSTER_VALUE_MAX_BYTES]);
    assert!(big.is_ok());
    assert_eq!(
        encode_value_b64(&vec![b'x'; CLUSTER_VALUE_MAX_BYTES + 1])
            .unwrap_err()
            .errno,
        Errno::EFBIG
    );

    let cap_lease = match block_on(store.rpc(
        &root,
        ClusterCall::LeaseGrant {
            ttl_secs: 60,
            node_id: None,
        },
        100,
    ))
    .unwrap()
    {
        ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
        other => panic!("unexpected: {other:?}"),
    };
    for i in 0..CLUSTER_MAX_KEYS_PER_LEASE {
        put(
            &store,
            &root,
            &format!("/t/u0/lcap/k{i}"),
            "v",
            cap_lease,
            100,
        );
    }
    let over_lease = block_on(store.rpc(
        &root,
        ClusterCall::Txn {
            compare: vec![],
            success: vec![TxnOp::Put {
                key: "/t/u0/lcap/overflow".into(),
                value_b64: b64("v"),
                lease_id: cap_lease,
                prev_kv: false,
            }],
            failure: vec![],
        },
        100,
    ))
    .unwrap_err();
    assert_eq!(over_lease.errno, Errno::EDQUOT);
}

#[test]
fn security_regressions_delete_quota_lease_scope_oracle_and_bounds() {
    let store = MemoryClusterStore::new("default");
    let root = admin_grant("u0");
    let alice = admin_grant("u1000");

    // 1. Duplicate/overlapping DeleteRange in one Txn branch rejected with EINVAL (no quota bypass).
    put(&store, &root, "/t/u0/del/a", "va", 0, 100);
    put(&store, &root, "/t/u0/del/b", "vb", 0, 100);
    let dup_del = block_on(store.rpc(
        &root,
        ClusterCall::Txn {
            compare: vec![],
            success: vec![
                TxnOp::DeleteRange {
                    key: "/t/u0/del/a".into(),
                    range_end: RangeEnd::Exact,
                    prev_kv: false,
                },
                TxnOp::DeleteRange {
                    key: "/t/u0/del/a".into(),
                    range_end: RangeEnd::Exact,
                    prev_kv: false,
                },
            ],
            failure: vec![],
        },
        100,
    ))
    .unwrap_err();
    assert_eq!(dup_del.errno, Errno::EINVAL);

    let overlap_del = block_on(store.rpc(
        &root,
        ClusterCall::Txn {
            compare: vec![],
            success: vec![
                TxnOp::DeleteRange {
                    key: "/t/u0/del/".into(),
                    range_end: RangeEnd::Prefix,
                    prev_kv: false,
                },
                TxnOp::DeleteRange {
                    key: "/t/u0/del/b".into(),
                    range_end: RangeEnd::Exact,
                    prev_kv: false,
                },
            ],
            failure: vec![],
        },
        100,
    ))
    .unwrap_err();
    assert_eq!(overlap_del.errno, Errno::EINVAL);

    // 2. Prefix-restricted credential denied on LeaseGrant{node_id}, LeaseRevoke, LeaseKeepAlive,
    //    LeaseTimeToLive, and Put(lease_id) when lease holds keys/node outside cluster_prefixes.
    let node_lease = match block_on(store.rpc(
        &root,
        ClusterCall::LeaseGrant {
            ttl_secs: 60,
            node_id: Some("node-1".into()),
        },
        100,
    ))
    .unwrap()
    {
        ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
        other => panic!("unexpected: {other:?}"),
    };
    put(&store, &root, "/t/u0/nodes/node-1", "live", node_lease, 100);

    let secret_lease = match block_on(store.rpc(
        &root,
        ClusterCall::LeaseGrant {
            ttl_secs: 60,
            node_id: None,
        },
        100,
    ))
    .unwrap()
    {
        ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
        other => panic!("unexpected: {other:?}"),
    };
    put(
        &store,
        &root,
        "/t/u0/secret/item",
        "top-secret",
        secret_lease,
        100,
    );

    let wl_scoped = ClusterGrant {
        tenant: "u0".into(),
        owner: "wl-worker".into(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_lease: true,
            cluster_prefixes: vec!["workloads/*".into()],
            ..Default::default()
        },
    };
    assert_eq!(
        block_on(store.rpc(
            &wl_scoped,
            ClusterCall::LeaseGrant {
                ttl_secs: 30,
                node_id: Some("node-1".into()),
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );
    for forbidden_lease in [node_lease, secret_lease] {
        assert_eq!(
            block_on(store.rpc(
                &wl_scoped,
                ClusterCall::LeaseKeepAlive {
                    lease_id: forbidden_lease,
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
        assert_eq!(
            block_on(store.rpc(
                &wl_scoped,
                ClusterCall::LeaseRevoke {
                    lease_id: forbidden_lease,
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
        assert_eq!(
            block_on(store.rpc(
                &wl_scoped,
                ClusterCall::LeaseTimeToLive {
                    lease_id: forbidden_lease,
                    keys: true,
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
        assert_eq!(
            block_on(store.rpc(
                &wl_scoped,
                ClusterCall::LeaseTimeToLive {
                    lease_id: forbidden_lease,
                    keys: false,
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
        assert_eq!(
            block_on(store.rpc(
                &wl_scoped,
                ClusterCall::Txn {
                    compare: vec![],
                    success: vec![TxnOp::Put {
                        key: "/t/u0/workloads/attach".into(),
                        value_b64: b64("x"),
                        lease_id: forbidden_lease,
                        prev_kv: false,
                    }],
                    failure: vec![],
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
    }

    // Prefix-scoped grant CAN still create, attach, keepalive, inspect, and revoke its own in-prefix lease.
    let own_lease = match block_on(store.rpc(
        &wl_scoped,
        ClusterCall::LeaseGrant {
            ttl_secs: 30,
            node_id: None,
        },
        100,
    ))
    .unwrap()
    {
        ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
        other => panic!("unexpected: {other:?}"),
    };
    put(
        &store,
        &wl_scoped,
        "/t/u0/workloads/own",
        "ok",
        own_lease,
        100,
    );
    block_on(store.rpc(
        &wl_scoped,
        ClusterCall::LeaseKeepAlive {
            lease_id: own_lease,
        },
        105,
    ))
    .unwrap();
    block_on(store.rpc(
        &wl_scoped,
        ClusterCall::LeaseTimeToLive {
            lease_id: own_lease,
            keys: true,
        },
        105,
    ))
    .unwrap();
    block_on(store.rpc(
        &wl_scoped,
        ClusterCall::LeaseRevoke {
            lease_id: own_lease,
        },
        106,
    ))
    .unwrap();

    // 3. Cross-tenant lease_id existence oracle eliminated:
    //    cluster_read-only u1000 gets uniform EACCES for existing u0 lease AND missing lease.
    let alice_ro = ClusterGrant {
        tenant: "u1000".into(),
        owner: "alice-ro".into(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            ..Default::default()
        },
    };
    for probe_id in [node_lease, 999_999] {
        assert_eq!(
            block_on(store.rpc(
                &alice_ro,
                ClusterCall::LeaseKeepAlive { lease_id: probe_id },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
        assert_eq!(
            block_on(store.rpc(
                &alice_ro,
                ClusterCall::LeaseRevoke { lease_id: probe_id },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
    }
    //    cluster_lease u1000 gets uniform ENOENT for existing u0 lease AND missing lease.
    for probe_id in [node_lease, 999_999, (i64::MAX as u64) + 1] {
        assert_eq!(
            block_on(store.rpc(
                &alice,
                ClusterCall::LeaseKeepAlive { lease_id: probe_id },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::ENOENT
        );
        assert_eq!(
            block_on(store.rpc(&alice, ClusterCall::LeaseRevoke { lease_id: probe_id }, 100,))
                .unwrap_err()
                .errno,
            Errno::ENOENT
        );
        assert_eq!(
            block_on(store.rpc(
                &alice,
                ClusterCall::LeaseTimeToLive {
                    lease_id: probe_id,
                    keys: true,
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::ENOENT
        );
    }

    // 4. Node-bound credential cannot mutate another node's node-meta, DeleteRange over nodes/ or node-meta/,
    //    or revoke a lease attached to another node's record.
    let node1 = ClusterGrant {
        tenant: "u0".into(),
        owner: "n1".into(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_lease: true,
            cluster_node_id: Some("node-1".into()),
            ..Default::default()
        },
    };
    put(
        &store,
        &node1,
        "/t/u0/node-meta/node-1",
        "self-meta",
        0,
        100,
    );
    assert_eq!(
        block_on(store.rpc(
            &node1,
            ClusterCall::Txn {
                compare: vec![],
                success: vec![TxnOp::Put {
                    key: "/t/u0/node-meta/node-2".into(),
                    value_b64: b64("spoof"),
                    lease_id: 0,
                    prev_kv: false,
                }],
                failure: vec![],
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );
    for dir in ["/t/u0/nodes/", "/t/u0/node-meta/"] {
        assert_eq!(
            block_on(store.rpc(
                &node1,
                ClusterCall::Txn {
                    compare: vec![],
                    success: vec![TxnOp::DeleteRange {
                        key: dir.into(),
                        range_end: RangeEnd::Prefix,
                        prev_kv: false,
                    }],
                    failure: vec![],
                },
                100,
            ))
            .unwrap_err()
            .errno,
            Errno::EACCES
        );
    }
    // Admin attaches node-2 key to node-1's lease -> node-1 cannot revoke it via LeaseRevoke!
    put(
        &store,
        &root,
        "/t/u0/node-meta/node-2",
        "real-n2",
        node_lease,
        100,
    );
    assert_eq!(
        block_on(store.rpc(
            &node1,
            ClusterCall::LeaseRevoke {
                lease_id: node_lease,
            },
            100,
        ))
        .unwrap_err()
        .errno,
        Errno::EACCES
    );

    // 5. Watch from_revision > i64::MAX rejected with EINVAL.
    let mut bad_cur = WatchCursor::new("/t/u0/", RangeEnd::Prefix, (i64::MAX as u64) + 1, false);
    assert_eq!(
        block_on(store.poll_watch(&root, &mut bad_cur, 16, 100))
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );

    // 6. Fencing builders reject zero expected revisions / lease IDs and mismatched current_attempt.
    let wl = WorkloadRecord {
        workload_id: "wl-z".into(),
        image_ref: "oci:team/app@sha256:00".into(),
        input_snapshot_ref: None,
        labels: BTreeMap::new(),
        desired_state: "running".into(),
        current_attempt: 1,
        created_at: 100,
    };
    let att = AttemptRecord {
        workload_id: "wl-z".into(),
        attempt_generation: 1,
        node_id: "node-1".into(),
        node_generation: 1,
        node_lease_id: 1,
        state: "claimed".into(),
        claimed_at: 100,
        finished_at: None,
    };
    let res = ResultRecord {
        workload_id: "wl-z".into(),
        attempt_generation: 1,
        node_id: "node-1".into(),
        node_generation: 1,
        exit_code: 0,
        output_ref: None,
        summary: None,
        published_at: 101,
    };
    assert_eq!(
        build_claim_attempt_txn("u0", 0, 1, 1, &wl, &att)
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
    assert_eq!(
        build_claim_attempt_txn("u0", 1, 0, 1, &wl, &att)
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
    assert_eq!(
        build_publish_result_txn("u0", 0, 1, 1, 1, &wl, &att, &res, None)
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
    assert_eq!(
        build_publish_result_txn("u0", 1, 1, 1, 0, &wl, &att, &res, None)
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
    let mut mismatched_wl = wl.clone();
    mismatched_wl.current_attempt = 2;
    assert_eq!(
        build_publish_result_txn("u0", 1, 1, 1, 1, &mismatched_wl, &att, &res, None)
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
}
