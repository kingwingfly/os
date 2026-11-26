//! Zero-dependency Protobuf v3 wire codecs for containerd `Task` v2 and v3 RPC messages
//! (`containerd.task.v2.Task` and `containerd.task.v3.Task`).

use crate::ttrpc::{
    decode_tag, decode_varint, encode_bool_field, encode_bytes_field, encode_i32_field,
    encode_i64_field, encode_message_field, encode_string_field, encode_u32_field,
    read_len_delimited, skip_field,
};

pub const TASK_V2_SERVICE: &str = "containerd.task.v2.Task";
pub const TASK_V3_SERVICE: &str = "containerd.task.v3.Task";

fn decode_u32_varint(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    u32::try_from(decode_varint(data, pos)?).map_err(|_| "protobuf uint32 overflow".into())
}

/// `containerd.v1.types.Status` enum values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum TaskStatus {
    #[default]
    Unknown = 0,
    Created = 1,
    Running = 2,
    Stopped = 3,
    Paused = 4,
    Pausing = 5,
}

impl TaskStatus {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Created,
            2 => Self::Running,
            3 => Self::Stopped,
            4 => Self::Paused,
            5 => Self::Pausing,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

impl Timestamp {
    pub fn from_unix_nanos(ns: u64) -> Self {
        Self {
            seconds: (ns / 1_000_000_000) as i64,
            nanos: (ns % 1_000_000_000) as i32,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_i64_field(&mut out, 1, self.seconds);
        encode_i32_field(&mut out, 2, self.nanos);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut ts = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => ts.seconds = decode_varint(data, &mut pos)? as i64,
                (2, 0) => ts.nanos = decode_varint(data, &mut pos)? as i32,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(ts)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtoAny {
    pub type_url: String,
    pub value: Vec<u8>,
}

impl ProtoAny {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.type_url);
        encode_bytes_field(&mut out, 2, &self.value);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut a = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    a.type_url =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => a.value = read_len_delimited(data, &mut pos)?.to_vec(),
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(a)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mount {
    pub mount_type: String,
    pub source: String,
    pub target: String,
    pub options: Vec<String>,
}

impl Mount {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.mount_type);
        encode_string_field(&mut out, 2, &self.source);
        encode_string_field(&mut out, 3, &self.target);
        for opt in &self.options {
            encode_string_field(&mut out, 4, opt);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut m = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    m.mount_type =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    m.source =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 2) => {
                    m.target =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (4, 2) => m.options.push(
                    String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned(),
                ),
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateTaskRequest {
    pub id: String,
    pub bundle: String,
    pub rootfs: Vec<Mount>,
    pub terminal: bool,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub checkpoint: String,
    pub parent_checkpoint: String,
    pub options: Option<ProtoAny>,
}

impl CreateTaskRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.bundle);
        for m in &self.rootfs {
            encode_message_field(&mut out, 3, &m.encode());
        }
        encode_bool_field(&mut out, 4, self.terminal);
        encode_string_field(&mut out, 5, &self.stdin);
        encode_string_field(&mut out, 6, &self.stdout);
        encode_string_field(&mut out, 7, &self.stderr);
        encode_string_field(&mut out, 8, &self.checkpoint);
        encode_string_field(&mut out, 9, &self.parent_checkpoint);
        if let Some(opt) = &self.options {
            encode_message_field(&mut out, 10, &opt.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.bundle =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 2) => r
                    .rootfs
                    .push(Mount::decode(read_len_delimited(data, &mut pos)?)?),
                (4, 0) => r.terminal = decode_varint(data, &mut pos)? != 0,
                (5, 2) => {
                    r.stdin =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (6, 2) => {
                    r.stdout =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (7, 2) => {
                    r.stderr =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (8, 2) => {
                    r.checkpoint =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (9, 2) => {
                    r.parent_checkpoint =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (10, 2) => {
                    r.options = Some(ProtoAny::decode(read_len_delimited(data, &mut pos)?)?);
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateTaskResponse {
    pub pid: u32,
}

impl CreateTaskResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32_field(&mut out, 1, self.pid);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => r.pid = decode_u32_varint(data, &mut pos)?,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartRequest {
    pub id: String,
    pub exec_id: String,
}

impl StartRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.exec_id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.exec_id =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartResponse {
    pub pid: u32,
}

impl StartResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32_field(&mut out, 1, self.pid);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => r.pid = decode_u32_varint(data, &mut pos)?,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateRequest {
    pub id: String,
    pub exec_id: String,
}

impl StateRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.exec_id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let s = StartRequest::decode(data)?;
        Ok(Self {
            id: s.id,
            exec_id: s.exec_id,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateResponse {
    pub id: String,
    pub bundle: String,
    pub pid: u32,
    pub status: TaskStatus,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub terminal: bool,
    pub exit_status: u32,
    pub exited_at: Option<Timestamp>,
    pub exec_id: String,
}

impl StateResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.bundle);
        encode_u32_field(&mut out, 3, self.pid);
        encode_u32_field(&mut out, 4, self.status as u32);
        encode_string_field(&mut out, 5, &self.stdin);
        encode_string_field(&mut out, 6, &self.stdout);
        encode_string_field(&mut out, 7, &self.stderr);
        encode_bool_field(&mut out, 8, self.terminal);
        encode_u32_field(&mut out, 9, self.exit_status);
        if let Some(ts) = &self.exited_at {
            encode_message_field(&mut out, 10, &ts.encode());
        }
        encode_string_field(&mut out, 11, &self.exec_id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.bundle =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 0) => r.pid = decode_u32_varint(data, &mut pos)?,
                (4, 0) => r.status = TaskStatus::from_u32(decode_u32_varint(data, &mut pos)?),
                (5, 2) => {
                    r.stdin =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (6, 2) => {
                    r.stdout =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (7, 2) => {
                    r.stderr =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (8, 0) => r.terminal = decode_varint(data, &mut pos)? != 0,
                (9, 0) => r.exit_status = decode_u32_varint(data, &mut pos)?,
                (10, 2) => {
                    r.exited_at = Some(Timestamp::decode(read_len_delimited(data, &mut pos)?)?)
                }
                (11, 2) => {
                    r.exec_id =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteRequest {
    pub id: String,
    pub exec_id: String,
}

impl DeleteRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.exec_id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let s = StartRequest::decode(data)?;
        Ok(Self {
            id: s.id,
            exec_id: s.exec_id,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteResponse {
    pub pid: u32,
    pub exit_status: u32,
    pub exited_at: Option<Timestamp>,
}

impl DeleteResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32_field(&mut out, 1, self.pid);
        encode_u32_field(&mut out, 2, self.exit_status);
        if let Some(ts) = &self.exited_at {
            encode_message_field(&mut out, 3, &ts.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => r.pid = decode_u32_varint(data, &mut pos)?,
                (2, 0) => r.exit_status = decode_u32_varint(data, &mut pos)?,
                (3, 2) => {
                    r.exited_at = Some(Timestamp::decode(read_len_delimited(data, &mut pos)?)?)
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KillRequest {
    pub id: String,
    pub exec_id: String,
    pub signal: u32,
    pub all: bool,
}

impl KillRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.exec_id);
        encode_u32_field(&mut out, 3, self.signal);
        encode_bool_field(&mut out, 4, self.all);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.exec_id =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 0) => r.signal = decode_u32_varint(data, &mut pos)?,
                (4, 0) => r.all = decode_varint(data, &mut pos)? != 0,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WaitRequest {
    pub id: String,
    pub exec_id: String,
}

impl WaitRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.exec_id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let s = StartRequest::decode(data)?;
        Ok(Self {
            id: s.id,
            exec_id: s.exec_id,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WaitResponse {
    pub exit_status: u32,
    pub exited_at: Option<Timestamp>,
}

impl WaitResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32_field(&mut out, 1, self.exit_status);
        if let Some(ts) = &self.exited_at {
            encode_message_field(&mut out, 2, &ts.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => r.exit_status = decode_u32_varint(data, &mut pos)?,
                (2, 2) => {
                    r.exited_at = Some(Timestamp::decode(read_len_delimited(data, &mut pos)?)?)
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecProcessRequest {
    pub id: String,
    pub exec_id: String,
    pub terminal: bool,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub spec: Option<ProtoAny>,
}

impl ExecProcessRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_string_field(&mut out, 2, &self.exec_id);
        encode_bool_field(&mut out, 3, self.terminal);
        encode_string_field(&mut out, 4, &self.stdin);
        encode_string_field(&mut out, 5, &self.stdout);
        encode_string_field(&mut out, 6, &self.stderr);
        if let Some(s) = &self.spec {
            encode_message_field(&mut out, 7, &s.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.exec_id =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 0) => r.terminal = decode_varint(data, &mut pos)? != 0,
                (4, 2) => {
                    r.stdin =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (5, 2) => {
                    r.stdout =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (6, 2) => {
                    r.stderr =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (7, 2) => r.spec = Some(ProtoAny::decode(read_len_delimited(data, &mut pos)?)?),
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PidsRequest {
    pub id: String,
}

impl PidsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
}

impl ProcessInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32_field(&mut out, 1, self.pid);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => r.pid = decode_u32_varint(data, &mut pos)?,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PidsResponse {
    pub processes: Vec<ProcessInfo>,
}

impl PidsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for p in &self.processes {
            encode_message_field(&mut out, 1, &p.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => r
                    .processes
                    .push(ProcessInfo::decode(read_len_delimited(data, &mut pos)?)?),
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectRequest {
    pub id: String,
}

impl ConnectRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let p = PidsRequest::decode(data)?;
        Ok(Self { id: p.id })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectResponse {
    pub shim_pid: u32,
    pub task_pid: u32,
    pub version: String,
}

impl ConnectResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32_field(&mut out, 1, self.shim_pid);
        encode_u32_field(&mut out, 2, self.task_pid);
        encode_string_field(&mut out, 3, &self.version);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 0) => r.shim_pid = decode_u32_varint(data, &mut pos)?,
                (2, 0) => r.task_pid = decode_u32_varint(data, &mut pos)?,
                (3, 2) => {
                    r.version =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShutdownRequest {
    pub id: String,
    pub now: bool,
}

impl ShutdownRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(&mut out, 1, &self.id);
        encode_bool_field(&mut out, 2, self.now);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 0) => r.now = decode_varint(data, &mut pos)? != 0,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloseIORequest {
    pub id: String,
    pub exec_id: String,
    pub stdin: bool,
}

impl CloseIORequest {
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.exec_id =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 0) => r.stdin = decode_varint(data, &mut pos)? != 0,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResizePtyRequest {
    pub id: String,
    pub exec_id: String,
    pub width: u32,
    pub height: u32,
}

impl ResizePtyRequest {
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut r = Self::default();
        let mut pos = 0;
        while pos < data.len() {
            match decode_tag(data, &mut pos)? {
                (1, 2) => {
                    r.id = String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (2, 2) => {
                    r.exec_id =
                        String::from_utf8_lossy(read_len_delimited(data, &mut pos)?).into_owned()
                }
                (3, 0) => r.width = decode_u32_varint(data, &mut pos)?,
                (4, 0) => r.height = decode_u32_varint(data, &mut pos)?,
                (_, w) => skip_field(data, &mut pos, w)?,
            }
        }
        Ok(r)
    }
}
