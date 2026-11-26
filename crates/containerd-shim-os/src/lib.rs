//! `containerd-shim-os-v1` — containerd shim v2 runtime for Wasm/WASIX OCI bundles (#85).
//!
//! Speaks containerd's TTRPC v1 (`containerd.task.v2.Task` and `containerd.task.v3.Task`) over a
//! `0600` Unix domain socket, boots isolated per-container `os-native` kernels with CSI `cowfs`
//! and raw `/dev/vdN` volume mounts, enforces Wasmtime 51 epoch preemption on `Kill(SIGKILL)`,
//! and explicitly rejects Linux ELF (`\x7fELF`) binaries with `ENOEXEC`.

pub mod oci_spec;
pub mod shim;
pub mod task_proto;
pub mod ttrpc;

pub const SHIM_VERSION: &str = "0.1.0";
pub const RUNTIME_NAME: &str = "io.containerd.os.v1";
