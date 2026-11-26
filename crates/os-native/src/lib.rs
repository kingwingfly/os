//! `os-native` — Standalone headless native host for the portable Rust/Wasm/WASIX OS (#82).
//!
//! Boots the exact same cryptographically signed Release v2 bundle completely offline through
//! Stage 0 -> Stage 1 (`early_init.wasm`) -> Stage 2 (`init.wasm`), persists state in native
//! `CowFs<NativeSqliteHeadStore, NativePackStore>`, runs Wasm/WASIX processes on Wasmtime 51,
//! and serves authenticated `HostAdapter v2` remote seats over Unix sockets, TCP, and WebSocket.

pub mod accounts;
pub mod attach_cli;
pub mod boot;
pub mod cluster_http;
pub mod dev_backend;
pub mod errno;
pub mod export_host;
pub mod http_client;
pub mod kernel_actor;
pub mod kernel_rpc;
pub mod kubelet;
pub mod mount_host;
pub mod pipes;
pub mod proc_runner;
pub mod pty;
pub mod release;
pub mod sandbox;
pub mod seat_proto;
pub mod seat_server;
pub mod signals;
pub mod wasi_host;

pub use attach_cli::{SeatClient, send_control_request};
pub use boot::{ExecOutput, NativeBootConfig, NativeOsHost};
pub use kernel_actor::{NativeBootProfile, NativeRootSpec, NativeWriterMode};
pub use kernel_rpc::HostInspect;
pub use seat_proto::{
    ClientFrame, ControlReply, ControlRequest, ServerFrame, TokenRecord, TokenStore,
};
pub use seat_server::{SeatServerConfig, SeatServerHandle};
