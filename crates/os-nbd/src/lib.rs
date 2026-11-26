//! Standard NBD Fixed Newstyle server & client over Unix domain sockets (`0600`) backed by
//! fenced `os_cowfs::raw_lba::RawBlockVolume` (`Phase 9.5 #85`).

pub mod client;
pub mod proto;
pub mod server;

pub use client::{NbdClient, NbdClientError, NbdExportInfo};
pub use proto::{
    DEFAULT_HANDSHAKE_TIMEOUT, IHAVEOPT, MAX_HANDSHAKE_OPTIONS, MAX_NBD_IO_BYTES, MAX_OPTION_LEN,
    NBD_CMD_DISC, NBD_CMD_FLAG_FUA, NBD_CMD_FLAG_NO_HOLE, NBD_CMD_FLUSH, NBD_CMD_READ,
    NBD_CMD_TRIM, NBD_CMD_WRITE, NBD_CMD_WRITE_ZEROES, NBD_EINVAL, NBD_EIO, NBD_ENOMEM, NBD_ENOSPC,
    NBD_EOVERFLOW, NBD_EPERM, NBD_ESHUTDOWN, NBD_FLAG_C_FIXED_NEWSTYLE, NBD_FLAG_C_NO_ZEROES,
    NBD_FLAG_FIXED_NEWSTYLE, NBD_FLAG_HAS_FLAGS, NBD_FLAG_NO_ZEROES, NBD_FLAG_READ_ONLY,
    NBD_FLAG_SEND_FLUSH, NBD_FLAG_SEND_FUA, NBD_FLAG_SEND_TRIM, NBD_FLAG_SEND_WRITE_ZEROES,
    NBD_INFO_BLOCK_SIZE, NBD_INFO_EXPORT, NBD_INFO_NAME, NBD_OK, NBD_OPT_ABORT,
    NBD_OPT_EXPORT_NAME, NBD_OPT_GO, NBD_OPT_INFO, NBD_OPT_LIST, NBD_REP_ACK, NBD_REP_ERR_INVALID,
    NBD_REP_ERR_POLICY, NBD_REP_ERR_UNKNOWN, NBD_REP_ERR_UNSUP, NBD_REP_INFO, NBD_REP_MAGIC,
    NBD_REP_SERVER, NBD_REQUEST_MAGIC, NBD_SIMPLE_REPLY_MAGIC, NBDMAGIC,
};
pub use server::{
    NbdExportConfig, NbdServerHandle, NbdVolumeActorHandle, OnFencedCallback,
    bind_unix_socket_0600, ensure_private_runtime_dir, serve_unix_on_local_set,
    spawn_raw_volume_actor_on_local, spawn_raw_volume_actor_on_local_with_fence,
    validate_safe_unix_socket_path,
};
