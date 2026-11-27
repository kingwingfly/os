//! CNI Spec v1.0.0 plugin (`os-cni`) for tenant L3 overlay networking backed by `ClusterState`.
//!
//! Supports `VERSION`, `ADD`, `CHECK`, and strictly idempotent, host-loss-safe `DEL` with
//! CAS-guarded IPAM release and atomic `0600` attachment descriptors.

pub mod http;
pub mod ipam;
pub mod netns;
pub mod spec;

use crate::ipam::{
    ClockFn, IpamAllocRequest, allocate_ipam, check_ipam, release_ipam, system_clock_secs,
};
use crate::netns::{LinuxTunNetnsDriver, NetnsDriver, UserspaceNetnsDriver};
use crate::spec::{
    CNI_ERR_INTERNAL, CNI_SPEC_VERSION, CniAttachmentDescriptor, CniCommand, CniDns, CniEnv,
    CniError, CniInterface, CniIpConfig, CniNetConfig, CniResult, CniRoute, CniVersionResult,
    DriverMode, load_cni_attachment, remove_cni_attachment,
};
use os_cluster_state::{ClusterGrant, ClusterStore};
use std::sync::Arc;

pub struct OsCniPlugin<C: ClusterStore> {
    store: Arc<C>,
    grant: ClusterGrant,
    clock: ClockFn,
}

impl<C: ClusterStore> OsCniPlugin<C> {
    pub fn new(store: Arc<C>, grant: ClusterGrant) -> Self {
        Self {
            store,
            grant,
            clock: system_clock_secs(),
        }
    }

    pub fn with_clock(mut self, clock: ClockFn) -> Self {
        self.clock = clock;
        self
    }

    fn now_secs(&self) -> u64 {
        (self.clock)()
    }

    fn driver_for(mode: DriverMode) -> Box<dyn NetnsDriver> {
        match mode {
            DriverMode::Userspace => Box::new(UserspaceNetnsDriver),
            DriverMode::Auto | DriverMode::Linux => Box::new(LinuxTunNetnsDriver { mode }),
        }
    }

    /// Execute a CNI v1.0.0 command and return optional stdout JSON.
    pub async fn execute(
        &self,
        env: &CniEnv,
        stdin_bytes: &[u8],
    ) -> Result<Option<String>, CniError> {
        let cmd = env.validate()?;
        if cmd == CniCommand::Version {
            let out = serde_json::to_string(&CniVersionResult::default()).map_err(|e| {
                CniError::new(CNI_ERR_INTERNAL, "encode version result", e.to_string())
            })?;
            return Ok(Some(out));
        }

        let cfg = CniNetConfig::parse_json(stdin_bytes)?;
        let driver = Self::driver_for(cfg.driver);
        let now = self.now_secs();

        match cmd {
            CniCommand::Version => unreachable!(),
            CniCommand::Add => {
                let static_ip = cfg.requested_static_ip(env)?;
                let alloc = allocate_ipam(
                    self.store.as_ref(),
                    &self.grant,
                    &IpamAllocRequest {
                        tenant: cfg.tenant.clone(),
                        network: cfg.name.clone(),
                        endpoint_id: env.container_id.clone(),
                        node_id: cfg.node_id.clone(),
                        ifname: env.ifname.clone(),
                        host_kind: "cni".to_string(),
                        mtu: cfg.effective_mtu(),
                        lease_ttl_secs: cfg.effective_lease_ttl(),
                        static_ip,
                        requested_cidr: cfg.cidr.clone(),
                    },
                    now,
                )
                .await?;

                let desc = CniAttachmentDescriptor {
                    version: 1,
                    container_id: env.container_id.clone(),
                    ifname: env.ifname.clone(),
                    netns: env.netns.clone(),
                    tenant: alloc.tenant.clone(),
                    cluster: cfg.cluster.clone(),
                    network: alloc.network.clone(),
                    node_id: alloc.node_id.clone(),
                    ip: alloc.ip.to_string(),
                    prefix_len: alloc.prefix_len,
                    gateway: alloc.gateway.to_string(),
                    cidr: alloc.cidr.to_string(),
                    ipv6: alloc.ipv6.clone(),
                    mtu: alloc.mtu,
                    lease_id: alloc.lease_id,
                    fence_epoch: alloc.fence_epoch,
                    driver: driver.driver_name().to_string(),
                    created_at: alloc.allocated_at,
                };

                if let Err(setup_err) = driver.setup_interface(&cfg.state_dir, &desc) {
                    // Roll back IPAM lease cleanly on interface setup failure.
                    let _ = release_ipam(
                        self.store.as_ref(),
                        &self.grant,
                        &cfg.tenant,
                        &cfg.node_id,
                        &env.container_id,
                        Some(&desc),
                        now,
                    )
                    .await;
                    return Err(setup_err);
                }

                let result = CniResult {
                    cni_version: CNI_SPEC_VERSION.to_string(),
                    interfaces: vec![CniInterface {
                        name: env.ifname.clone(),
                        mac: None,
                        sandbox: Some(env.netns.clone()),
                    }],
                    ips: vec![CniIpConfig {
                        interface: 0,
                        address: format!("{}/{}", alloc.ip, alloc.prefix_len),
                        gateway: Some(alloc.gateway.to_string()),
                    }],
                    routes: vec![CniRoute {
                        dst: alloc.cidr.to_string(),
                        gw: Some(alloc.gateway.to_string()),
                    }],
                    dns: cfg.dns.clone().unwrap_or_else(CniDns::default),
                };
                let out = serde_json::to_string(&result).map_err(|e| {
                    CniError::new(CNI_ERR_INTERNAL, "encode CNI ADD result", e.to_string())
                })?;
                Ok(Some(out))
            }
            CniCommand::Check => {
                let Some(desc) = load_cni_attachment(&cfg.state_dir, &env.container_id)? else {
                    return Err(CniError::new(
                        CNI_ERR_INTERNAL,
                        "CNI attachment not found",
                        format!(
                            "no local attachment descriptor for container '{}'",
                            env.container_id
                        ),
                    ));
                };
                if desc.ifname != env.ifname || desc.netns != env.netns || desc.tenant != cfg.tenant
                {
                    return Err(CniError::new(
                        CNI_ERR_INTERNAL,
                        "CNI attachment metadata mismatch",
                        format!(
                            "expected (ifname={}, netns={}, tenant={}) got ({}, {}, {})",
                            env.ifname, env.netns, cfg.tenant, desc.ifname, desc.netns, desc.tenant
                        ),
                    ));
                }
                check_ipam(self.store.as_ref(), &self.grant, &desc, now).await?;
                driver.check_interface(&cfg.state_dir, &desc)?;
                Ok(None)
            }
            CniCommand::Del => {
                // Missing local attachment is NEVER an error (survives wiped $stateDir / host loss).
                let local_hint = load_cni_attachment(&cfg.state_dir, &env.container_id)
                    .ok()
                    .flatten();
                let _ = driver.delete_interface(
                    &cfg.state_dir,
                    &env.container_id,
                    &env.netns,
                    &env.ifname,
                );
                release_ipam(
                    self.store.as_ref(),
                    &self.grant,
                    &cfg.tenant,
                    &cfg.node_id,
                    &env.container_id,
                    local_hint.as_ref(),
                    now,
                )
                .await?;
                let _ = remove_cni_attachment(&cfg.state_dir, &env.container_id);
                Ok(None)
            }
        }
    }
}
