//! SQLite-backed `OverlayRelay` Durable Object (`Boundary::Network` v1, Phase 10b `#87`).
//!
//! Sharded strictly per `overlay:{cluster}:{tenant}:{network}`:
//! - Hibernatable WebSockets (`state.accept_web_socket`) with compact `< 512 B` attachment.
//! - Binary frames `[0x01][raw L3 IPv4/IPv6 packet]` validated through shared `OverlayFirewall`:
//!   strict source-IP anti-spoofing, cross-tenant denial, MTU & bogon checks, `Machine` `io.max`
//!   batch charging (`32 KiB` / `250ms` + teardown flush), and periodic live credential revocation.
//! - Text JSON control & intra-tenant WebRTC `Signal` frames (`<= 16 KiB`, `#[serde(deny_unknown_fields)]`).
//! - Alarm-driven ticket & lease expiration cleanup.

use crate::auth;
use crate::db::{self, Db, int, text};
use crate::overlay_gateway::{
    self, OverlayErr, OverlayIssueTicket, OverlaySessionCheck, OverlayTicketCreated,
};
use crate::resources::{self, IoRequest};
use abi::Errno;
use abi::cluster_state::ClusterCall;
use abi::overlay::{
    DropReason, IpCidr, Ipv4Cidr, OVERLAY_MAX_SOCKETS_PER_DO, OVERLAY_SIGNAL_MAX_BYTES,
    OVERLAY_TICKET_TTL_SECS, OVERLAY_VERSION, OverlayClientFrame, OverlayEndpointPolicy,
    OverlayFirewall, OverlayServerFrame, OverlayStats, PeerInfo, decode_overlay_l3_frame,
    derive_tenant_v6_cidr,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use worker::*;

const CHARGE_BATCH_BYTES: u64 = 32 * 1024;
const CHARGE_BATCH_INTERVAL_MS: u64 = 250;
const REVOCATION_POLL_INTERVAL_MS: u64 = 2_000;
const DROP_NOTICE_MIN_INTERVAL_MS: u64 = 250;
const RATE_WINDOW_MS: u64 = 1_000;

const OVERLAY_SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS overlay_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    cluster TEXT NOT NULL,
    tenant TEXT NOT NULL,
    network TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS overlay_tickets (
    ticket_hash TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    network TEXT NOT NULL,
    ip TEXT NOT NULL,
    prefix_len INTEGER NOT NULL,
    gateway TEXT NOT NULL,
    cidr TEXT NOT NULL,
    ipv6 TEXT,
    mtu INTEGER NOT NULL,
    lease_id INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    host_kind TEXT NOT NULL,
    ns TEXT NOT NULL,
    cred_hash TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    allowed_peer_cidrs_json TEXT NOT NULL,
    max_bytes_per_sec INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_overlay_tickets_exp ON overlay_tickets(expires_at);
CREATE TABLE IF NOT EXISTS overlay_endpoints (
    endpoint_id TEXT PRIMARY KEY,
    conn_id TEXT NOT NULL DEFAULT '',
    tenant TEXT NOT NULL,
    network TEXT NOT NULL,
    ip TEXT NOT NULL,
    prefix_len INTEGER NOT NULL,
    gateway TEXT NOT NULL,
    cidr TEXT NOT NULL,
    ipv6 TEXT,
    mtu INTEGER NOT NULL,
    lease_id INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    host_kind TEXT NOT NULL,
    ns TEXT NOT NULL,
    cred_hash TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    allowed_peer_cidrs_json TEXT NOT NULL,
    max_bytes_per_sec INTEGER NOT NULL,
    unbilled_tx INTEGER NOT NULL DEFAULT 0,
    unbilled_rx INTEGER NOT NULL DEFAULT 0,
    last_charge_ms INTEGER NOT NULL DEFAULT 0,
    last_rx_charge_ms INTEGER NOT NULL DEFAULT 0,
    last_revocation_check_ms INTEGER NOT NULL DEFAULT 0,
    rate_window_ms INTEGER NOT NULL DEFAULT 0,
    rate_window_bytes INTEGER NOT NULL DEFAULT 0,
    last_drop_notice_ms INTEGER NOT NULL DEFAULT 0,
    connected_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS overlay_stats (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    rx_packets INTEGER NOT NULL DEFAULT 0,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_packets INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0,
    dropped_spoofed_src INTEGER NOT NULL DEFAULT 0,
    dropped_cross_tenant INTEGER NOT NULL DEFAULT 0,
    dropped_outside_cidr INTEGER NOT NULL DEFAULT 0,
    dropped_malformed INTEGER NOT NULL DEFAULT 0,
    dropped_no_route INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO overlay_stats(singleton) VALUES(1);
";

/// Compact Hibernatable WebSocket attachment (`< 512 B`, well below the 2 KiB DO cap).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RelayWsAttachment {
    endpoint_id: String,
    #[serde(default)]
    conn_id: String,
    tenant: String,
    network: String,
    ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv6: Option<String>,
    cidr: String,
    mtu: u16,
    lease_id: u64,
    ns: String,
    cred_hash: String,
    instance_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct MetaRow {
    cluster: String,
    tenant: String,
    network: String,
}

#[derive(Clone, Debug, Deserialize)]
struct TicketRow {
    endpoint_id: String,
    tenant: String,
    network: String,
    ip: String,
    prefix_len: u8,
    gateway: String,
    cidr: String,
    ipv6: Option<String>,
    mtu: u16,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_id: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_expires_at: u64,
    host_kind: String,
    ns: String,
    cred_hash: String,
    instance_id: String,
    allowed_peer_cidrs_json: String,
    #[serde(deserialize_with = "db::exact_u64")]
    max_bytes_per_sec: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    expires_at: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct EndpointRow {
    endpoint_id: String,
    conn_id: String,
    tenant: String,
    network: String,
    ip: String,
    #[allow(dead_code)]
    prefix_len: u8,
    gateway: String,
    cidr: String,
    ipv6: Option<String>,
    mtu: u16,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_id: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_expires_at: u64,
    host_kind: String,
    ns: String,
    cred_hash: String,
    instance_id: String,
    allowed_peer_cidrs_json: String,
    #[serde(deserialize_with = "db::exact_u64")]
    max_bytes_per_sec: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    unbilled_tx: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    unbilled_rx: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    last_charge_ms: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    last_rx_charge_ms: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    last_revocation_check_ms: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    rate_window_ms: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    rate_window_bytes: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    last_drop_notice_ms: u64,
}

impl EndpointRow {
    fn to_peer_info(&self) -> PeerInfo {
        PeerInfo {
            endpoint_id: self.endpoint_id.clone(),
            ip: self.ip.clone(),
            ipv6: self.ipv6.clone(),
            host_kind: self.host_kind.clone(),
            mtu: self.mtu,
        }
    }

    fn to_policy(&self) -> std::result::Result<OverlayEndpointPolicy, OverlayErr> {
        let leased_ip: Ipv4Addr = self
            .ip
            .parse()
            .map_err(|_| OverlayErr::new(Errno::EIO, "corrupt endpoint ip"))?;
        let tenant_cidr_v4 = Ipv4Cidr::parse(&self.cidr)
            .ok_or_else(|| OverlayErr::new(Errno::EIO, "corrupt endpoint cidr"))?;
        let leased_ipv6 = self
            .ipv6
            .as_deref()
            .and_then(|s| s.parse::<Ipv6Addr>().ok());
        let tenant_cidr_v6 = leased_ipv6.map(|_| derive_tenant_v6_cidr(&self.tenant));
        let raw_cidrs: Vec<String> =
            serde_json::from_str(&self.allowed_peer_cidrs_json).unwrap_or_default();
        let allowed_peer_cidrs: Vec<IpCidr> =
            raw_cidrs.iter().filter_map(|s| IpCidr::parse(s)).collect();
        Ok(OverlayEndpointPolicy {
            tenant: self.tenant.clone(),
            leased_ip,
            tenant_cidr_v4,
            leased_ipv6,
            tenant_cidr_v6,
            mtu: self.mtu,
            allowed_peer_cidrs,
        })
    }

    fn to_check(&self) -> OverlaySessionCheck {
        OverlaySessionCheck {
            endpoint_id: self.endpoint_id.clone(),
            tenant: self.tenant.clone(),
            ns: self.ns.clone(),
            cred_hash: self.cred_hash.clone(),
            instance_id: self.instance_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct StatsRow {
    #[serde(deserialize_with = "db::exact_u64")]
    rx_packets: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    rx_bytes: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    tx_packets: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    tx_bytes: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    dropped_spoofed_src: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    dropped_cross_tenant: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    dropped_outside_cidr: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    dropped_malformed: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    dropped_no_route: u64,
}

#[derive(Deserialize)]
struct OptNumRow {
    n: Option<String>,
}

fn now_ms() -> u64 {
    js_sys::Date::now().max(0.0) as u64
}

fn tx<T: 'static>(
    state: &State,
    f: impl FnOnce(&mut Db) -> std::result::Result<T, OverlayErr> + 'static,
) -> std::result::Result<T, OverlayErr> {
    db::transact(state, move |db| {
        let r = f(db);
        let commit = r.is_ok();
        (r, commit)
    })
    .map_err(|_| OverlayErr::new(Errno::EIO, "overlay storage transaction failed"))?
}

fn send_server_frame(ws: &WebSocket, frame: &OverlayServerFrame) {
    if let Ok(text) = serde_json::to_string(frame) {
        let _ = ws.send_with_str(text);
    }
}

fn read_attachment(ws: &WebSocket) -> Option<RelayWsAttachment> {
    ws.deserialize_attachment::<RelayWsAttachment>()
        .ok()
        .flatten()
}

const ENDPOINT_SELECT_COLS: &str =
    "endpoint_id, conn_id, tenant, network, ip, prefix_len, gateway, cidr, ipv6, mtu,
                CAST(lease_id AS TEXT) AS lease_id,
                CAST(lease_expires_at AS TEXT) AS lease_expires_at,
                host_kind, ns, cred_hash, instance_id, allowed_peer_cidrs_json,
                CAST(max_bytes_per_sec AS TEXT) AS max_bytes_per_sec,
                CAST(unbilled_tx AS TEXT) AS unbilled_tx,
                CAST(unbilled_rx AS TEXT) AS unbilled_rx,
                CAST(last_charge_ms AS TEXT) AS last_charge_ms,
                CAST(last_rx_charge_ms AS TEXT) AS last_rx_charge_ms,
                CAST(last_revocation_check_ms AS TEXT) AS last_revocation_check_ms,
                CAST(rate_window_ms AS TEXT) AS rate_window_ms,
                CAST(rate_window_bytes AS TEXT) AS rate_window_bytes,
                CAST(last_drop_notice_ms AS TEXT) AS last_drop_notice_ms";

fn load_endpoint(db: &Db, endpoint_id: &str) -> Option<EndpointRow> {
    let sql =
        format!("SELECT {ENDPOINT_SELECT_COLS} FROM overlay_endpoints WHERE endpoint_id = ?1");
    db.rows::<EndpointRow>(&sql, vec![text(endpoint_id)]).pop()
}

fn load_all_endpoints(db: &Db) -> Vec<EndpointRow> {
    let sql =
        format!("SELECT {ENDPOINT_SELECT_COLS} FROM overlay_endpoints ORDER BY connected_at ASC");
    db.rows::<EndpointRow>(&sql, vec![])
}

fn load_expired_endpoints(db: &Db, now: u64) -> Vec<EndpointRow> {
    let sql = format!(
        "SELECT {ENDPOINT_SELECT_COLS} FROM overlay_endpoints WHERE lease_expires_at <= ?1"
    );
    db.rows::<EndpointRow>(&sql, vec![int(now)])
}

fn load_endpoint_by_ip(
    db: &Db,
    tenant: &str,
    network: &str,
    dst: IpAddr,
    exclude_endpoint_id: &str,
) -> Option<EndpointRow> {
    let col = match dst {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ipv6",
    };
    let dst_s = dst.to_string();
    let sql = format!(
        "SELECT {ENDPOINT_SELECT_COLS}
         FROM overlay_endpoints
         WHERE tenant = ?1 AND network = ?2 AND {col} = ?3 AND endpoint_id != ?4
         LIMIT 1"
    );
    db.rows::<EndpointRow>(
        &sql,
        vec![
            text(tenant),
            text(network),
            text(&dst_s),
            text(exclude_endpoint_id),
        ],
    )
    .pop()
}

#[durable_object]
pub struct OverlayRelay {
    state: State,
    env: Env,
    ready: Cell<bool>,
}

impl DurableObject for OverlayRelay {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ready: Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();
        match (req.method(), path.as_str()) {
            (Method::Post, "/internal/ticket") => self.handle_issue_ticket(&mut req).await,
            (Method::Post, "/internal/renew") => self.handle_renew(&mut req).await,
            (Method::Post, "/internal/detach") => self.handle_detach(&mut req).await,
            (Method::Get, "/internal/connect") => self.handle_connect(&req).await,
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if self.ensure_ready(None).is_err() {
            let _ = ws.close(Some(1011), Some("storage error"));
            return Ok(());
        }
        let Some(att) = read_attachment(&ws) else {
            let _ = ws.close(Some(1008), Some("missing attachment"));
            return Ok(());
        };
        let ep_id = att.endpoint_id.clone();
        let row = match tx(&self.state, move |db| Ok(load_endpoint(db, &ep_id))) {
            Ok(Some(r)) if r.conn_id == att.conn_id => r,
            Ok(Some(_)) => {
                // Stale replaced WebSocket — close without touching the active connection's row.
                let _ = ws.close(Some(1000), Some("replaced"));
                return Ok(());
            }
            _ => {
                send_server_frame(
                    &ws,
                    &OverlayServerFrame::Error {
                        errno: Errno::ESTALE,
                        message: "overlay endpoint closed or expired".into(),
                    },
                );
                let _ = ws.close(Some(1008), Some("endpoint gone"));
                return Ok(());
            }
        };

        let now = auth::now();
        if row.lease_expires_at <= now {
            self.disconnect_endpoint(&ws, &row, "lease expired", true)
                .await;
            return Ok(());
        }

        let cur_ms = now_ms();
        let is_text = matches!(message, WebSocketIncomingMessage::String(_));
        if is_text
            || cur_ms.saturating_sub(row.last_revocation_check_ms) >= REVOCATION_POLL_INTERVAL_MS
        {
            let check = row.to_check();
            match overlay_gateway::revalidate_overlay_sessions(&self.env, &[check]).await {
                Ok(revoked) if !revoked.contains(&row.endpoint_id) => {
                    let eid = row.endpoint_id.clone();
                    let _ = tx(&self.state, move |db| {
                        db.run(
                            "UPDATE overlay_endpoints SET last_revocation_check_ms = ?1 WHERE endpoint_id = ?2",
                            vec![int(cur_ms), text(&eid)],
                        );
                        Ok(())
                    });
                }
                _ => {
                    send_server_frame(
                        &ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "overlay credential revoked or expired".into(),
                        },
                    );
                    self.disconnect_endpoint(&ws, &row, "credential revoked", true)
                        .await;
                    return Ok(());
                }
            }
        }

        match message {
            WebSocketIncomingMessage::String(raw) => {
                self.handle_text_frame(&ws, &att, &row, &raw).await;
            }
            WebSocketIncomingMessage::Binary(raw) => {
                self.handle_binary_frame(&ws, &att, &row, &raw).await;
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.cleanup_closed_ws(&ws).await;
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        self.cleanup_closed_ws(&ws).await;
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        if self.ensure_ready(None).is_ok() {
            let now = auth::now();
            let expired: Vec<EndpointRow> = tx(&self.state, move |db| {
                db.run(
                    "DELETE FROM overlay_tickets WHERE expires_at <= ?1",
                    vec![int(now)],
                );
                Ok(load_expired_endpoints(db, now))
            })
            .unwrap_or_default();

            for row in expired {
                let target_ws = self.find_ws_by_endpoint_conn(&row.endpoint_id, &row.conn_id);
                if let Some(ws) = target_ws {
                    self.disconnect_endpoint(&ws, &row, "lease expired", false)
                        .await;
                } else {
                    self.flush_unbilled_io(&row).await;
                    let eid = row.endpoint_id.clone();
                    let cid = row.conn_id.clone();
                    let deleted = tx(&self.state, move |db| {
                        let existed =
                            load_endpoint(db, &eid).is_some_and(|cur| cur.conn_id == cid);
                        if existed {
                            db.run(
                                "DELETE FROM overlay_endpoints WHERE endpoint_id = ?1 AND conn_id = ?2",
                                vec![text(&eid), text(&cid)],
                            );
                        }
                        Ok(existed)
                    })
                    .unwrap_or(false);
                    if deleted {
                        self.broadcast_peer_left(&row.endpoint_id, &row.ip, None);
                    }
                }
            }
            let _ = self.reschedule_alarm().await;
        }
        Response::ok("ok")
    }
}

impl OverlayRelay {
    fn ensure_ready(
        &self,
        init_meta: Option<(&str, &str, &str)>,
    ) -> std::result::Result<(), OverlayErr> {
        if !self.ready.get() {
            tx(&self.state, |db| {
                for stmt in OVERLAY_SCHEMA_SQL.split(';') {
                    let s = stmt.trim();
                    if !s.is_empty() {
                        db.run(s, vec![]);
                    }
                }
                Ok(())
            })?;
            self.ready.set(true);
        }
        if let Some((cluster, tenant, network)) = init_meta {
            let c = cluster.to_string();
            let t = tenant.to_string();
            let n = network.to_string();
            tx(&self.state, move |db| {
                if let Some(existing) = db
                    .rows::<MetaRow>(
                        "SELECT cluster, tenant, network FROM overlay_meta WHERE singleton = 1",
                        vec![],
                    )
                    .pop()
                {
                    if existing.cluster != c || existing.tenant != t || existing.network != n {
                        return Err(OverlayErr::new(
                            Errno::EACCES,
                            "overlay relay shard identity mismatch",
                        ));
                    }
                } else {
                    db.run(
                        "INSERT INTO overlay_meta(singleton, cluster, tenant, network) VALUES(1, ?1, ?2, ?3)",
                        vec![text(&c), text(&t), text(&n)],
                    );
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    async fn reschedule_alarm(&self) -> Result<()> {
        let next_exp = tx(&self.state, |db| {
            let t1 = db
                .rows::<OptNumRow>(
                    "SELECT CAST(MIN(expires_at) AS TEXT) AS n FROM overlay_tickets",
                    vec![],
                )
                .pop()
                .and_then(|r| r.n)
                .and_then(|s| s.parse::<u64>().ok());
            let t2 = db
                .rows::<OptNumRow>(
                    "SELECT CAST(MIN(lease_expires_at) AS TEXT) AS n FROM overlay_endpoints",
                    vec![],
                )
                .pop()
                .and_then(|r| r.n)
                .and_then(|s| s.parse::<u64>().ok());
            let next = match (t1, t2) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            };
            Ok(next)
        })
        .ok()
        .flatten();
        if let Some(ts_secs) = next_exp {
            let now = auth::now();
            let delta_ms = ts_secs.saturating_sub(now).max(1).saturating_mul(1000);
            let _ = self
                .state
                .storage()
                .set_alarm(std::time::Duration::from_millis(delta_ms))
                .await;
        }
        Ok(())
    }

    fn find_ws_by_endpoint_conn(&self, endpoint_id: &str, conn_id: &str) -> Option<WebSocket> {
        self.state.get_websockets().into_iter().find(|ws| {
            read_attachment(ws)
                .is_some_and(|a| a.endpoint_id == endpoint_id && a.conn_id == conn_id)
        })
    }

    fn broadcast_peer_joined(&self, peer: &PeerInfo, skip_ep: &str) {
        let frame = OverlayServerFrame::PeerJoined(peer.clone());
        for ws in self.state.get_websockets() {
            if let Some(att) = read_attachment(&ws)
                && att.endpoint_id != skip_ep
            {
                send_server_frame(&ws, &frame);
            }
        }
    }

    fn broadcast_peer_left(&self, endpoint_id: &str, ip: &str, skip_ep: Option<&str>) {
        let frame = OverlayServerFrame::PeerLeft {
            endpoint_id: endpoint_id.to_string(),
            ip: ip.to_string(),
        };
        for ws in self.state.get_websockets() {
            if let Some(att) = read_attachment(&ws)
                && skip_ep != Some(att.endpoint_id.as_str())
            {
                send_server_frame(&ws, &frame);
            }
        }
    }

    async fn flush_unbilled_io(&self, row: &EndpointRow) {
        if row.unbilled_tx > 0 {
            let _ = resources::checked_io(
                &self.env,
                IoRequest {
                    ns: row.ns.clone(),
                    token: row.cred_hash.clone(),
                    token_is_hash: true,
                    pid: None,
                    write: true,
                    bytes: row.unbilled_tx,
                },
            )
            .await;
        }
        if row.unbilled_rx > 0 {
            let _ = resources::checked_io(
                &self.env,
                IoRequest {
                    ns: row.ns.clone(),
                    token: row.cred_hash.clone(),
                    token_is_hash: true,
                    pid: None,
                    write: false,
                    bytes: row.unbilled_rx,
                },
            )
            .await;
        }
    }

    async fn disconnect_endpoint(
        &self,
        ws: &WebSocket,
        row: &EndpointRow,
        reason: &str,
        revoke_cluster_lease: bool,
    ) {
        self.flush_unbilled_io(row).await;
        let eid = row.endpoint_id.clone();
        let cid = row.conn_id.clone();
        let (deleted, meta) = tx(&self.state, move |db| {
            let existed = load_endpoint(db, &eid).is_some_and(|r| r.conn_id == cid);
            if existed {
                db.run(
                    "DELETE FROM overlay_endpoints WHERE endpoint_id = ?1 AND conn_id = ?2",
                    vec![text(&eid), text(&cid)],
                );
            }
            let m = db
                .rows::<MetaRow>(
                    "SELECT cluster, tenant, network FROM overlay_meta WHERE singleton = 1",
                    vec![],
                )
                .pop();
            Ok((existed, m))
        })
        .unwrap_or((false, None));
        let _ = ws.close(Some(1008), Some(reason));
        if deleted {
            self.broadcast_peer_left(&row.endpoint_id, &row.ip, Some(&row.endpoint_id));
            if revoke_cluster_lease
                && row.lease_id != 0
                && let Some(m) = meta
            {
                let _ = overlay_gateway::cluster_overlay_rpc(
                    &self.env,
                    &m.cluster,
                    &row.tenant,
                    &row.cred_hash,
                    ClusterCall::LeaseRevoke {
                        lease_id: row.lease_id,
                    },
                )
                .await;
            }
        }
    }

    async fn cleanup_closed_ws(&self, ws: &WebSocket) {
        if self.ensure_ready(None).is_err() {
            return;
        }
        let Some(att) = read_attachment(ws) else {
            return;
        };
        let ep_id = att.endpoint_id.clone();
        let cid = att.conn_id.clone();
        let row = tx(&self.state, move |db| {
            let r = load_endpoint(db, &ep_id).filter(|cur| cur.conn_id == cid);
            if r.is_some() {
                db.run(
                    "DELETE FROM overlay_endpoints WHERE endpoint_id = ?1 AND conn_id = ?2",
                    vec![text(&ep_id), text(&cid)],
                );
            }
            Ok(r)
        })
        .ok()
        .flatten();
        if let Some(row) = row {
            self.flush_unbilled_io(&row).await;
            self.broadcast_peer_left(&row.endpoint_id, &row.ip, Some(&row.endpoint_id));
        }
    }

    async fn handle_issue_ticket(&self, req: &mut Request) -> Result<Response> {
        let cmd: OverlayIssueTicket = match serde_json::from_str(&req.text().await?) {
            Ok(c) => c,
            Err(_) => {
                return overlay_gateway::error_response(&OverlayErr::new(
                    Errno::EINVAL,
                    "invalid issue ticket request",
                ));
            }
        };
        if let Err(err) = self.ensure_ready(Some((&cmd.cluster, &cmd.tenant, &cmd.network))) {
            return overlay_gateway::error_response(&err);
        }
        let now = auth::now();
        let secret = auth::random_token();
        let ticket_hash = auth::token_hash(&secret);
        let expires_at = now.saturating_add(OVERLAY_TICKET_TTL_SECS);
        let cidrs_json =
            serde_json::to_string(&cmd.allowed_peer_cidrs).unwrap_or_else(|_| "[]".into());
        let max_bps = cmd.max_bytes_per_sec.unwrap_or(0);
        let inserted = tx(&self.state, move |db| {
            db.run(
                "DELETE FROM overlay_tickets WHERE expires_at <= ?1",
                vec![int(now)],
            );
            db.run(
                "INSERT INTO overlay_tickets(
                   ticket_hash, endpoint_id, tenant, network, ip, prefix_len, gateway, cidr, ipv6,
                   mtu, lease_id, lease_expires_at, host_kind, ns, cred_hash, instance_id,
                   allowed_peer_cidrs_json, max_bytes_per_sec, expires_at
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                vec![
                    text(&ticket_hash),
                    text(&cmd.endpoint_id),
                    text(&cmd.tenant),
                    text(&cmd.network),
                    text(&cmd.ip),
                    int(cmd.prefix_len),
                    text(&cmd.gateway),
                    text(&cmd.cidr),
                    cmd.ipv6.as_deref().into(),
                    int(cmd.mtu),
                    int(cmd.lease_id),
                    int(cmd.lease_expires_at),
                    text(&cmd.host_kind),
                    text(&cmd.ns),
                    text(&cmd.cred_hash),
                    text(&cmd.instance_id),
                    text(&cidrs_json),
                    int(max_bps),
                    int(expires_at),
                ],
            );
            Ok(())
        });
        if let Err(err) = inserted {
            return overlay_gateway::error_response(&err);
        }
        let _ = self.reschedule_alarm().await;
        Response::from_json(&OverlayTicketCreated { secret, expires_at })
    }

    async fn handle_renew(&self, req: &mut Request) -> Result<Response> {
        #[derive(Deserialize)]
        struct RenewCmd {
            endpoint_id: String,
            lease_id: u64,
            lease_expires_at: u64,
        }
        let Ok(cmd) = req.json::<RenewCmd>().await else {
            return Response::error("bad renew", 400);
        };
        if self.ensure_ready(None).is_ok() {
            let _ = tx(&self.state, move |db| {
                db.run(
                    "UPDATE overlay_endpoints SET lease_expires_at = ?1 WHERE endpoint_id = ?2 AND lease_id = ?3",
                    vec![int(cmd.lease_expires_at), text(&cmd.endpoint_id), int(cmd.lease_id)],
                );
                Ok(())
            });
            let _ = self.reschedule_alarm().await;
        }
        Response::from_json(&json!({ "ok": true }))
    }

    async fn handle_detach(&self, req: &mut Request) -> Result<Response> {
        #[derive(Deserialize)]
        struct DetachCmd {
            endpoint_id: String,
        }
        let Ok(cmd) = req.json::<DetachCmd>().await else {
            return Response::error("bad detach", 400);
        };
        if self.ensure_ready(None).is_ok() {
            let ep_id = cmd.endpoint_id.clone();
            let row = tx(&self.state, move |db| Ok(load_endpoint(db, &ep_id)))
                .ok()
                .flatten();
            if let Some(r) = row {
                // Close any lingering stale sockets for this endpoint_id first.
                for ws in self.state.get_websockets() {
                    if read_attachment(&ws)
                        .is_some_and(|a| a.endpoint_id == r.endpoint_id && a.conn_id != r.conn_id)
                    {
                        let _ = ws.close(Some(1000), Some("detached"));
                    }
                }
                if let Some(ws) = self.find_ws_by_endpoint_conn(&r.endpoint_id, &r.conn_id) {
                    self.disconnect_endpoint(&ws, &r, "detached", false).await;
                } else {
                    self.flush_unbilled_io(&r).await;
                    let eid = r.endpoint_id.clone();
                    let cid = r.conn_id.clone();
                    let deleted = tx(&self.state, move |db| {
                        let existed =
                            load_endpoint(db, &eid).is_some_and(|cur| cur.conn_id == cid);
                        if existed {
                            db.run(
                                "DELETE FROM overlay_endpoints WHERE endpoint_id = ?1 AND conn_id = ?2",
                                vec![text(&eid), text(&cid)],
                            );
                        }
                        Ok(existed)
                    })
                    .unwrap_or(false);
                    if deleted {
                        self.broadcast_peer_left(&r.endpoint_id, &r.ip, None);
                    }
                }
            } else {
                for ws in self.state.get_websockets() {
                    if read_attachment(&ws).is_some_and(|a| a.endpoint_id == cmd.endpoint_id) {
                        let _ = ws.close(Some(1000), Some("detached"));
                    }
                }
            }
        }
        Response::from_json(&json!({ "ok": true }))
    }

    async fn handle_connect(&self, req: &Request) -> Result<Response> {
        if !req
            .headers()
            .get("Upgrade")?
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        {
            return Response::error("Expected WebSocket", 426);
        }
        let url = req.url()?;
        let qp = |k: &str| {
            url.query_pairs()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default()
        };
        let ticket_hash = qp("ticket_hash");
        let cluster = qp("cluster");
        let tenant = qp("tenant");
        let network = qp("network");
        if let Err(err) = self.ensure_ready(Some((&cluster, &tenant, &network))) {
            return overlay_gateway::error_response(&err);
        }
        if ticket_hash.is_empty() {
            return overlay_gateway::error_response(&OverlayErr::new(
                Errno::EACCES,
                "missing overlay ticket",
            ));
        }
        if self.state.get_websockets().len() >= OVERLAY_MAX_SOCKETS_PER_DO {
            return overlay_gateway::error_response(&OverlayErr::new(
                Errno::EAGAIN,
                "too many active overlay peers",
            ));
        }

        // 1. Atomically consume single-use upgrade ticket.
        let now = auth::now();
        let th = ticket_hash.clone();
        let consumed = tx(&self.state, move |db| {
            let row = db
                .rows::<TicketRow>(
                    "DELETE FROM overlay_tickets
                     WHERE ticket_hash = ?1
                     RETURNING endpoint_id, tenant, network, ip, prefix_len, gateway, cidr, ipv6, mtu,
                               CAST(lease_id AS TEXT) AS lease_id,
                               CAST(lease_expires_at AS TEXT) AS lease_expires_at,
                               host_kind, ns, cred_hash, instance_id, allowed_peer_cidrs_json,
                               CAST(max_bytes_per_sec AS TEXT) AS max_bytes_per_sec,
                               CAST(expires_at AS TEXT) AS expires_at",
                    vec![text(&th)],
                )
                .pop();
            Ok(row)
        });
        let ticket = match consumed {
            Ok(Some(t))
                if t.expires_at > now
                    && t.lease_expires_at > now
                    && t.tenant == tenant
                    && t.network == network =>
            {
                t
            }
            Ok(_) => {
                return overlay_gateway::error_response(&OverlayErr::new(
                    Errno::EACCES,
                    "invalid, expired, or already used overlay ticket",
                ));
            }
            Err(err) => return overlay_gateway::error_response(&err),
        };

        // 2. Live-revalidate credential BEFORE accepting WebSocket.
        let check = OverlaySessionCheck {
            endpoint_id: ticket.endpoint_id.clone(),
            tenant: ticket.tenant.clone(),
            ns: ticket.ns.clone(),
            cred_hash: ticket.cred_hash.clone(),
            instance_id: ticket.instance_id.clone(),
        };
        match overlay_gateway::revalidate_overlay_sessions(&self.env, &[check]).await {
            Ok(revoked) if !revoked.contains(&ticket.endpoint_id) => {}
            _ => {
                return overlay_gateway::error_response(&OverlayErr::new(
                    Errno::EACCES,
                    "overlay credential revoked or expired",
                ));
            }
        }

        // Re-check socket cap synchronously before inserting & accepting.
        if self.state.get_websockets().len() >= OVERLAY_MAX_SOCKETS_PER_DO {
            return overlay_gateway::error_response(&OverlayErr::new(
                Errno::EAGAIN,
                "too many active overlay peers",
            ));
        }

        // Close EVERY stale socket with the same `endpoint_id` (preventing stale socket shadowing).
        for old_ws in self.state.get_websockets() {
            if read_attachment(&old_ws).is_some_and(|a| a.endpoint_id == ticket.endpoint_id) {
                let _ = old_ws.close(Some(1000), Some("replaced"));
            }
        }

        let cur_ms = now_ms();
        let conn_id = {
            let raw = auth::random_token();
            raw[..raw.len().min(16)].to_string()
        };
        let peer_info = PeerInfo {
            endpoint_id: ticket.endpoint_id.clone(),
            ip: ticket.ip.clone(),
            ipv6: ticket.ipv6.clone(),
            host_kind: ticket.host_kind.clone(),
            mtu: ticket.mtu,
        };
        let attachment = RelayWsAttachment {
            endpoint_id: ticket.endpoint_id.clone(),
            conn_id: conn_id.clone(),
            tenant: ticket.tenant.clone(),
            network: ticket.network.clone(),
            ip: ticket.ip.clone(),
            ipv6: ticket.ipv6.clone(),
            cidr: ticket.cidr.clone(),
            mtu: ticket.mtu,
            lease_id: ticket.lease_id,
            ns: ticket.ns.clone(),
            cred_hash: ticket.cred_hash.clone(),
            instance_id: ticket.instance_id.clone(),
        };

        let inserted = tx(&self.state, move |db| {
            db.run(
                "INSERT OR REPLACE INTO overlay_endpoints(
                   endpoint_id, conn_id, tenant, network, ip, prefix_len, gateway, cidr, ipv6, mtu,
                   lease_id, lease_expires_at, host_kind, ns, cred_hash, instance_id,
                   allowed_peer_cidrs_json, max_bytes_per_sec,
                   unbilled_tx, unbilled_rx, last_charge_ms, last_rx_charge_ms,
                   last_revocation_check_ms, rate_window_ms, rate_window_bytes,
                   last_drop_notice_ms, connected_at
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,0,0,?19,?19,?19,?19,0,0,?20)",
                vec![
                    text(&ticket.endpoint_id),
                    text(&conn_id),
                    text(&ticket.tenant),
                    text(&ticket.network),
                    text(&ticket.ip),
                    int(ticket.prefix_len),
                    text(&ticket.gateway),
                    text(&ticket.cidr),
                    ticket.ipv6.as_deref().into(),
                    int(ticket.mtu),
                    int(ticket.lease_id),
                    int(ticket.lease_expires_at),
                    text(&ticket.host_kind),
                    text(&ticket.ns),
                    text(&ticket.cred_hash),
                    text(&ticket.instance_id),
                    text(&ticket.allowed_peer_cidrs_json),
                    int(ticket.max_bytes_per_sec),
                    int(cur_ms),
                    int(now),
                ],
            );
            Ok(())
        });
        if let Err(err) = inserted {
            return overlay_gateway::error_response(&err);
        }

        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        if let Err(err) = pair.server.serialize_attachment(&attachment) {
            let eid = attachment.endpoint_id.clone();
            let cid = attachment.conn_id.clone();
            let _ = tx(&self.state, move |db| {
                db.run(
                    "DELETE FROM overlay_endpoints WHERE endpoint_id = ?1 AND conn_id = ?2",
                    vec![text(&eid), text(&cid)],
                );
                Ok(())
            });
            let _ = pair.server.close(Some(1011), Some("attachment error"));
            return Err(err);
        }

        self.broadcast_peer_joined(&peer_info, &attachment.endpoint_id);
        let _ = self.reschedule_alarm().await;
        Response::from_websocket(pair.client)
    }

    async fn handle_text_frame(
        &self,
        ws: &WebSocket,
        att: &RelayWsAttachment,
        row: &EndpointRow,
        raw: &str,
    ) {
        if raw.len() > OVERLAY_SIGNAL_MAX_BYTES + 1024 {
            send_server_frame(
                ws,
                &OverlayServerFrame::Error {
                    errno: Errno::E2BIG,
                    message: "control frame exceeds maximum size".into(),
                },
            );
            return;
        }
        let frame: OverlayClientFrame = match serde_json::from_str(raw) {
            Ok(f) => f,
            Err(e) => {
                send_server_frame(
                    ws,
                    &OverlayServerFrame::Error {
                        errno: Errno::EINVAL,
                        message: format!("invalid overlay control frame: {e}"),
                    },
                );
                return;
            }
        };

        match frame {
            OverlayClientFrame::Hello { versions } => {
                if !versions.contains(&OVERLAY_VERSION) {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EPROTONOSUPPORT,
                            message: format!("overlay protocol v{OVERLAY_VERSION} required"),
                        },
                    );
                    let _ = ws.close(Some(1002), Some("unsupported version"));
                    return;
                }
                let live_ids: std::collections::HashSet<String> = self
                    .state
                    .get_websockets()
                    .into_iter()
                    .filter_map(|s| read_attachment(&s).map(|a| a.endpoint_id))
                    .collect();
                let my_id = row.endpoint_id.clone();
                let peers: Vec<PeerInfo> = tx(&self.state, move |db| {
                    Ok(load_all_endpoints(db)
                        .into_iter()
                        .filter(|e| e.endpoint_id != my_id && live_ids.contains(&e.endpoint_id))
                        .map(|e| e.to_peer_info())
                        .collect())
                })
                .unwrap_or_default();
                send_server_frame(
                    ws,
                    &OverlayServerFrame::Welcome {
                        version: OVERLAY_VERSION,
                        tenant: row.tenant.clone(),
                        network: row.network.clone(),
                        endpoint_id: row.endpoint_id.clone(),
                        ip: row.ip.clone(),
                        cidr: row.cidr.clone(),
                        gateway: row.gateway.clone(),
                        mtu: row.mtu,
                        lease_id: row.lease_id,
                        peers,
                    },
                );
            }
            OverlayClientFrame::KeepAlive { seq } => {
                send_server_frame(
                    ws,
                    &OverlayServerFrame::KeepAliveAck {
                        seq,
                        lease_expires_at: row.lease_expires_at,
                    },
                );
            }
            OverlayClientFrame::Stats {} => {
                let active_peers = self.state.get_websockets().len() as u32;
                let stats = tx(&self.state, move |db| {
                    let s = db
                        .rows::<StatsRow>(
                            "SELECT CAST(rx_packets AS TEXT) AS rx_packets,
                                    CAST(rx_bytes AS TEXT) AS rx_bytes,
                                    CAST(tx_packets AS TEXT) AS tx_packets,
                                    CAST(tx_bytes AS TEXT) AS tx_bytes,
                                    CAST(dropped_spoofed_src AS TEXT) AS dropped_spoofed_src,
                                    CAST(dropped_cross_tenant AS TEXT) AS dropped_cross_tenant,
                                    CAST(dropped_outside_cidr AS TEXT) AS dropped_outside_cidr,
                                    CAST(dropped_malformed AS TEXT) AS dropped_malformed,
                                    CAST(dropped_no_route AS TEXT) AS dropped_no_route
                             FROM overlay_stats WHERE singleton = 1",
                            vec![],
                        )
                        .pop()
                        .unwrap_or(StatsRow {
                            rx_packets: 0,
                            rx_bytes: 0,
                            tx_packets: 0,
                            tx_bytes: 0,
                            dropped_spoofed_src: 0,
                            dropped_cross_tenant: 0,
                            dropped_outside_cidr: 0,
                            dropped_malformed: 0,
                            dropped_no_route: 0,
                        });
                    Ok(OverlayStats {
                        rx_packets: s.rx_packets,
                        rx_bytes: s.rx_bytes,
                        tx_packets: s.tx_packets,
                        tx_bytes: s.tx_bytes,
                        dropped_spoofed_src: s.dropped_spoofed_src,
                        dropped_cross_tenant: s.dropped_cross_tenant,
                        dropped_outside_cidr: s.dropped_outside_cidr,
                        dropped_malformed: s.dropped_malformed,
                        dropped_no_route: s.dropped_no_route,
                        active_peers,
                    })
                })
                .unwrap_or_default();
                send_server_frame(ws, &OverlayServerFrame::StatsReply(stats));
            }
            OverlayClientFrame::Signal {
                to_endpoint_id,
                payload,
            } => {
                let payload_len = serde_json::to_vec(&payload)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX);
                if payload_len > OVERLAY_SIGNAL_MAX_BYTES {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::E2BIG,
                            message: "signal payload exceeds 16 KiB".into(),
                        },
                    );
                    return;
                }
                if to_endpoint_id == att.endpoint_id {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EINVAL,
                            message: "cannot signal self".into(),
                        },
                    );
                    return;
                }
                // Strictly intra-tenant lookup within this DO shard + mutual `allowed_peer_cidrs` check!
                let dst_eid = to_endpoint_id.clone();
                let dst_row = tx(&self.state, move |db| Ok(load_endpoint(db, &dst_eid)))
                    .ok()
                    .flatten();
                let now = auth::now();
                let target = dst_row.as_ref().and_then(|dr| {
                    if dr.lease_expires_at <= now {
                        return None;
                    }
                    self.state.get_websockets().into_iter().find(|candidate| {
                        read_attachment(candidate).is_some_and(|ca| {
                            ca.endpoint_id == to_endpoint_id
                                && ca.conn_id == dr.conn_id
                                && ca.tenant == att.tenant
                                && ca.network == att.network
                        })
                    })
                });
                let (Some(dst_ws), Some(dst_row)) = (target, dst_row) else {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "target peer not present in this tenant overlay".into(),
                        },
                    );
                    return;
                };
                let (Ok(sp), Ok(dp)) = (row.to_policy(), dst_row.to_policy()) else {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "invalid overlay endpoint policy".into(),
                        },
                    );
                    return;
                };
                let sender_allows_dst = sp.allowed_peer_cidrs.is_empty()
                    || sp.allowed_peer_cidrs.iter().any(|c| {
                        c.contains(IpAddr::V4(dp.leased_ip))
                            || dp.leased_ipv6.is_some_and(|v6| c.contains(IpAddr::V6(v6)))
                    });
                let dst_allows_sender = dp.allowed_peer_cidrs.is_empty()
                    || dp.allowed_peer_cidrs.iter().any(|c| {
                        c.contains(IpAddr::V4(sp.leased_ip))
                            || sp.leased_ipv6.is_some_and(|v6| c.contains(IpAddr::V6(v6)))
                    });
                if !sender_allows_dst || !dst_allows_sender {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "signaling target denied by allowed_peer_cidrs".into(),
                        },
                    );
                    return;
                }
                send_server_frame(
                    &dst_ws,
                    &OverlayServerFrame::Signal {
                        from_endpoint_id: att.endpoint_id.clone(),
                        payload,
                    },
                );
            }
        }
    }

    fn send_rate_limited_frame(
        &self,
        ws: &WebSocket,
        row: &EndpointRow,
        cur_ms: u64,
        frame: &OverlayServerFrame,
    ) {
        let eid = row.endpoint_id.clone();
        let cid = row.conn_id.clone();
        let should_send = tx(&self.state, move |db| {
            let Some(cur) = load_endpoint(db, &eid).filter(|r| r.conn_id == cid) else {
                return Ok(false);
            };
            if cur_ms.saturating_sub(cur.last_drop_notice_ms) < DROP_NOTICE_MIN_INTERVAL_MS {
                return Ok(false);
            }
            db.run(
                "UPDATE overlay_endpoints SET last_drop_notice_ms = ?1 WHERE endpoint_id = ?2 AND conn_id = ?3",
                vec![int(cur_ms), text(&eid), text(&cid)],
            );
            Ok(true)
        })
        .unwrap_or(false);
        if should_send {
            send_server_frame(ws, frame);
        }
    }

    fn send_drop_notice_rate_limited(
        &self,
        ws: &WebSocket,
        row: &EndpointRow,
        reason: DropReason,
        src: Option<String>,
        dst: Option<String>,
    ) {
        self.send_rate_limited_frame(
            ws,
            row,
            now_ms(),
            &OverlayServerFrame::DropNotice { reason, src, dst },
        );
    }

    async fn handle_binary_frame(
        &self,
        ws: &WebSocket,
        att: &RelayWsAttachment,
        row: &EndpointRow,
        raw: &[u8],
    ) {
        let pkt = match decode_overlay_l3_frame(raw) {
            Ok(p) => p,
            Err(reason) => {
                self.bump_drop_stat(reason);
                self.send_drop_notice_rate_limited(ws, row, reason, None, None);
                return;
            }
        };

        let Ok(policy) = row.to_policy() else {
            return;
        };
        let meta = match OverlayFirewall::check_tx(&policy, pkt) {
            Ok(m) => m,
            Err(reason) => {
                self.bump_drop_stat(reason);
                let (src_s, dst_s) = abi::overlay::parse_l3_packet(pkt, row.mtu)
                    .map(|m| (Some(m.src.to_string()), Some(m.dst.to_string())))
                    .unwrap_or((None, None));
                self.send_drop_notice_rate_limited(ws, row, reason, src_s, dst_s);
                return;
            }
        };

        let pkt_len = pkt.len() as u64;
        let cur_ms = now_ms();

        // Enforce per-endpoint `max_bytes_per_sec` fixed-window rate cap atomically inside one `tx`.
        if row.max_bytes_per_sec > 0 {
            let eid = row.endpoint_id.clone();
            let cid = row.conn_id.clone();
            let limit = row.max_bytes_per_sec;
            let rate_ok = tx(&self.state, move |db| {
                let Some(cur) = load_endpoint(db, &eid).filter(|r| r.conn_id == cid) else {
                    return Ok(false);
                };
                let in_same_window = cur_ms.saturating_sub(cur.rate_window_ms) < RATE_WINDOW_MS;
                let next_window_bytes = if in_same_window {
                    cur.rate_window_bytes.saturating_add(pkt_len)
                } else {
                    pkt_len
                };
                if next_window_bytes > limit {
                    return Ok(false);
                }
                let next_win_ms = if in_same_window {
                    cur.rate_window_ms
                } else {
                    cur_ms
                };
                db.run(
                    "UPDATE overlay_endpoints
                     SET rate_window_ms = ?1, rate_window_bytes = ?2
                     WHERE endpoint_id = ?3 AND conn_id = ?4",
                    vec![
                        int(next_win_ms),
                        int(next_window_bytes),
                        text(&eid),
                        text(&cid),
                    ],
                );
                Ok(true)
            })
            .unwrap_or(false);
            if !rate_ok {
                self.send_rate_limited_frame(
                    ws,
                    row,
                    cur_ms,
                    &OverlayServerFrame::Error {
                        errno: Errno::EAGAIN,
                        message: "overlay max_bytes_per_sec exceeded".into(),
                    },
                );
                return;
            }
        }

        // Atomic SQL increment of `unbilled_tx` + batched `Machine` DO `io.max` charging (32 KiB / 250ms).
        let eid_inc = row.endpoint_id.clone();
        let cid_inc = row.conn_id.clone();
        let current_unbilled_tx = tx(&self.state, move |db| {
            db.run(
                "UPDATE overlay_endpoints
                 SET unbilled_tx = unbilled_tx + ?1
                 WHERE endpoint_id = ?2 AND conn_id = ?3",
                vec![int(pkt_len), text(&eid_inc), text(&cid_inc)],
            );
            Ok(load_endpoint(db, &eid_inc).map_or(pkt_len, |r| r.unbilled_tx))
        })
        .unwrap_or(pkt_len);

        let due_charge = current_unbilled_tx >= CHARGE_BATCH_BYTES
            || cur_ms.saturating_sub(row.last_charge_ms) >= CHARGE_BATCH_INTERVAL_MS;
        if due_charge && current_unbilled_tx > 0 {
            let batch_tx = current_unbilled_tx;
            match resources::checked_io(
                &self.env,
                IoRequest {
                    ns: row.ns.clone(),
                    token: row.cred_hash.clone(),
                    token_is_hash: true,
                    pid: None,
                    write: true,
                    bytes: batch_tx,
                },
            )
            .await
            {
                Ok(()) => {
                    let eid = row.endpoint_id.clone();
                    let cid = row.conn_id.clone();
                    let _ = tx(&self.state, move |db| {
                        db.run(
                            "UPDATE overlay_endpoints
                             SET unbilled_tx = MAX(0, unbilled_tx - ?1), last_charge_ms = ?2
                             WHERE endpoint_id = ?3 AND conn_id = ?4",
                            vec![int(batch_tx), int(cur_ms), text(&eid), text(&cid)],
                        );
                        Ok(())
                    });
                }
                Err(err) if matches!(err.errno, Errno::EACCES | Errno::EPERM | Errno::ESTALE) => {
                    send_server_frame(
                        ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "overlay credential revoked".into(),
                        },
                    );
                    self.disconnect_endpoint(ws, row, "credential revoked", true)
                        .await;
                    return;
                }
                Err(err) if matches!(err.errno, Errno::EAGAIN | Errno::EDQUOT) => {
                    // Roll back only this dropped packet's contribution; preserve remaining unbilled batch.
                    let eid = row.endpoint_id.clone();
                    let cid = row.conn_id.clone();
                    let _ = tx(&self.state, move |db| {
                        db.run(
                            "UPDATE overlay_endpoints
                             SET unbilled_tx = MAX(0, unbilled_tx - ?1)
                             WHERE endpoint_id = ?2 AND conn_id = ?3",
                            vec![int(pkt_len), text(&eid), text(&cid)],
                        );
                        Ok(())
                    });
                    self.send_rate_limited_frame(
                        ws,
                        row,
                        cur_ms,
                        &OverlayServerFrame::Error {
                            errno: err.errno,
                            message: "overlay io.max write quota exceeded".into(),
                        },
                    );
                    return;
                }
                Err(_) => {}
            }
        }

        // Route strictly within `(tenant, network)` by authoritative SQLite row + `(endpoint_id, conn_id)`
        // so a stale closing socket can never shadow a replaced live connection.
        let dst_tenant = att.tenant.clone();
        let dst_net = att.network.clone();
        let dst_ip = meta.dst;
        let sender_eid = att.endpoint_id.clone();
        let dst_row = tx(&self.state, move |db| {
            Ok(load_endpoint_by_ip(
                db,
                &dst_tenant,
                &dst_net,
                dst_ip,
                &sender_eid,
            ))
        })
        .ok()
        .flatten();
        let dst_target = dst_row.and_then(|dr| {
            let ws = self.find_ws_by_endpoint_conn(&dr.endpoint_id, &dr.conn_id)?;
            Some((dr, ws))
        });

        let Some((dst_row, dst_ws)) = dst_target else {
            let _ = tx(&self.state, move |db| {
                db.run(
                    "UPDATE overlay_stats SET dropped_no_route = dropped_no_route + 1 WHERE singleton = 1",
                    vec![],
                );
                Ok(())
            });
            return;
        };

        let now = auth::now();
        if dst_row.lease_expires_at <= now {
            self.disconnect_endpoint(&dst_ws, &dst_row, "lease expired", true)
                .await;
            return;
        }
        if cur_ms.saturating_sub(dst_row.last_revocation_check_ms) >= REVOCATION_POLL_INTERVAL_MS {
            let check = dst_row.to_check();
            match overlay_gateway::revalidate_overlay_sessions(&self.env, &[check]).await {
                Ok(revoked) if !revoked.contains(&dst_row.endpoint_id) => {
                    let deid = dst_row.endpoint_id.clone();
                    let dcid = dst_row.conn_id.clone();
                    let _ = tx(&self.state, move |db| {
                        db.run(
                            "UPDATE overlay_endpoints SET last_revocation_check_ms = ?1 WHERE endpoint_id = ?2 AND conn_id = ?3",
                            vec![int(cur_ms), text(&deid), text(&dcid)],
                        );
                        Ok(())
                    });
                }
                _ => {
                    send_server_frame(
                        &dst_ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "overlay credential revoked or expired".into(),
                        },
                    );
                    self.disconnect_endpoint(&dst_ws, &dst_row, "credential revoked", true)
                        .await;
                    return;
                }
            }
        }

        let Ok(dst_policy) = dst_row.to_policy() else {
            return;
        };
        if OverlayFirewall::check_rx(&dst_policy, pkt).is_err() {
            self.bump_drop_stat(DropReason::RxPolicyDenied);
            return;
        }

        // Atomic SQL increment of `unbilled_rx` + batched `Machine` DO `io.max` read charging.
        let deid_inc = dst_row.endpoint_id.clone();
        let dcid_inc = dst_row.conn_id.clone();
        let current_unbilled_rx = tx(&self.state, move |db| {
            db.run(
                "UPDATE overlay_endpoints
                 SET unbilled_rx = unbilled_rx + ?1
                 WHERE endpoint_id = ?2 AND conn_id = ?3",
                vec![int(pkt_len), text(&deid_inc), text(&dcid_inc)],
            );
            Ok(load_endpoint(db, &deid_inc).map_or(pkt_len, |r| r.unbilled_rx))
        })
        .unwrap_or(pkt_len);

        let due_rx = current_unbilled_rx >= CHARGE_BATCH_BYTES
            || cur_ms.saturating_sub(dst_row.last_rx_charge_ms) >= CHARGE_BATCH_INTERVAL_MS;
        if due_rx && current_unbilled_rx > 0 {
            let batch_rx = current_unbilled_rx;
            match resources::checked_io(
                &self.env,
                IoRequest {
                    ns: dst_row.ns.clone(),
                    token: dst_row.cred_hash.clone(),
                    token_is_hash: true,
                    pid: None,
                    write: false,
                    bytes: batch_rx,
                },
            )
            .await
            {
                Ok(()) => {
                    let deid = dst_row.endpoint_id.clone();
                    let dcid = dst_row.conn_id.clone();
                    let _ = tx(&self.state, move |db| {
                        db.run(
                            "UPDATE overlay_endpoints
                             SET unbilled_rx = MAX(0, unbilled_rx - ?1), last_rx_charge_ms = ?2
                             WHERE endpoint_id = ?3 AND conn_id = ?4",
                            vec![int(batch_rx), int(cur_ms), text(&deid), text(&dcid)],
                        );
                        Ok(())
                    });
                }
                Err(err) if matches!(err.errno, Errno::EACCES | Errno::EPERM | Errno::ESTALE) => {
                    send_server_frame(
                        &dst_ws,
                        &OverlayServerFrame::Error {
                            errno: Errno::EACCES,
                            message: "overlay credential revoked".into(),
                        },
                    );
                    self.disconnect_endpoint(&dst_ws, &dst_row, "credential revoked", true)
                        .await;
                    return;
                }
                Err(err) if matches!(err.errno, Errno::EAGAIN | Errno::EDQUOT) => {
                    let deid = dst_row.endpoint_id.clone();
                    let dcid = dst_row.conn_id.clone();
                    let _ = tx(&self.state, move |db| {
                        db.run(
                            "UPDATE overlay_endpoints
                             SET unbilled_rx = MAX(0, unbilled_rx - ?1)
                             WHERE endpoint_id = ?2 AND conn_id = ?3",
                            vec![int(pkt_len), text(&deid), text(&dcid)],
                        );
                        Ok(())
                    });
                    return;
                }
                Err(_) => {}
            }
        }

        if dst_ws.send_with_bytes(raw).is_ok() {
            let _ = tx(&self.state, move |db| {
                db.run(
                    "UPDATE overlay_stats
                     SET tx_packets = tx_packets + 1, tx_bytes = tx_bytes + ?1,
                         rx_packets = rx_packets + 1, rx_bytes = rx_bytes + ?1
                     WHERE singleton = 1",
                    vec![int(pkt_len)],
                );
                Ok(())
            });
        }
    }

    fn bump_drop_stat(&self, reason: DropReason) {
        let col = match reason {
            DropReason::SpoofedSource => "dropped_spoofed_src",
            DropReason::CrossTenant => "dropped_cross_tenant",
            DropReason::OutsideCidr
            | DropReason::ForbiddenAddress
            | DropReason::SelfLoop
            | DropReason::RxPolicyDenied => "dropped_outside_cidr",
            DropReason::MalformedHeader
            | DropReason::UnsupportedIpVersion
            | DropReason::ExceedsMtu => "dropped_malformed",
        };
        let sql = format!("UPDATE overlay_stats SET {col} = {col} + 1 WHERE singleton = 1");
        let _ = tx(&self.state, move |db| {
            db.run(&sql, vec![]);
            Ok(())
        });
    }
}
