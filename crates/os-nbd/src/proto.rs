//! NBD Fixed Newstyle wire protocol constants and bounded async framing.

use abi::Errno;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NBDMAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
pub const IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
pub const NBD_REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
pub const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
pub const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

// Handshake flags (server -> client, u16)
pub const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
pub const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;

// Client flags (client -> server, u32)
pub const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
pub const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

// Transmission flags (u16)
pub const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
pub const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
pub const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
pub const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
pub const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;
pub const NBD_FLAG_SEND_WRITE_ZEROES: u16 = 1 << 6;

// Option codes (u32)
pub const NBD_OPT_EXPORT_NAME: u32 = 1;
pub const NBD_OPT_ABORT: u32 = 2;
pub const NBD_OPT_LIST: u32 = 3;
pub const NBD_OPT_INFO: u32 = 6;
pub const NBD_OPT_GO: u32 = 7;

// Option reply types (u32)
pub const NBD_REP_ACK: u32 = 1;
pub const NBD_REP_SERVER: u32 = 2;
pub const NBD_REP_INFO: u32 = 3;
pub const NBD_REP_ERR_UNSUP: u32 = (1 << 31) | 1;
pub const NBD_REP_ERR_POLICY: u32 = (1 << 31) | 2;
pub const NBD_REP_ERR_INVALID: u32 = (1 << 31) | 3;
pub const NBD_REP_ERR_UNKNOWN: u32 = (1 << 31) | 6;

// NBD_REP_INFO sub-types (u16)
pub const NBD_INFO_EXPORT: u16 = 0;
pub const NBD_INFO_NAME: u16 = 1;
pub const NBD_INFO_BLOCK_SIZE: u16 = 3;

// Transmission commands (u16)
pub const NBD_CMD_READ: u16 = 0;
pub const NBD_CMD_WRITE: u16 = 1;
pub const NBD_CMD_DISC: u16 = 2;
pub const NBD_CMD_FLUSH: u16 = 3;
pub const NBD_CMD_TRIM: u16 = 4;
pub const NBD_CMD_WRITE_ZEROES: u16 = 6;

// Command flags (u16)
pub const NBD_CMD_FLAG_FUA: u16 = 1 << 0;
pub const NBD_CMD_FLAG_NO_HOLE: u16 = 1 << 1;

// Standard NBD wire error numbers (u32)
pub const NBD_OK: u32 = 0;
pub const NBD_EPERM: u32 = 1;
pub const NBD_EIO: u32 = 5;
pub const NBD_ENOMEM: u32 = 12;
pub const NBD_EINVAL: u32 = 22;
pub const NBD_ENOSPC: u32 = 28;
pub const NBD_EOVERFLOW: u32 = 75;
pub const NBD_ESHUTDOWN: u32 = 108;

/// Maximum single NBD `READ`/`WRITE` payload (`4 MiB`).
pub const MAX_NBD_IO_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum handshake option data payload (`4 KiB`).
pub const MAX_OPTION_LEN: u32 = 4 * 1024;
/// Maximum option exchanges allowed in a single handshake.
pub const MAX_HANDSHAKE_OPTIONS: usize = 64;
/// Default timeout for completing the Fixed Newstyle handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Map an `os-abi` `Errno` to the closest standard NBD wire error number.
pub const fn errno_to_nbd_error(err: Errno) -> u32 {
    match err {
        Errno::EROFS | Errno::EPERM | Errno::EACCES => NBD_EPERM,
        Errno::ENOSPC | Errno::EDQUOT => NBD_ENOSPC,
        Errno::EINVAL | Errno::EOPNOTSUPP => NBD_EINVAL,
        Errno::EFBIG | Errno::E2BIG => NBD_EOVERFLOW,
        Errno::ESTALE | Errno::EIO | Errno::EBADF => NBD_EIO,
        _ => NBD_EIO,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientOption {
    pub code: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionReply {
    pub option: u32,
    pub reply_type: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NbdRequest {
    pub flags: u16,
    pub cmd: u16,
    pub handle: u64,
    pub offset: u64,
    pub length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NbdReply {
    pub error: u32,
    pub handle: u64,
}

pub async fn write_newstyle_greeting<W: AsyncWrite + Unpin>(
    w: &mut W,
    handshake_flags: u16,
) -> io::Result<()> {
    let mut buf = [0u8; 18];
    buf[0..8].copy_from_slice(&NBDMAGIC.to_be_bytes());
    buf[8..16].copy_from_slice(&IHAVEOPT.to_be_bytes());
    buf[16..18].copy_from_slice(&handshake_flags.to_be_bytes());
    w.write_all(&buf).await?;
    w.flush().await
}

pub async fn read_newstyle_greeting<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 18];
    r.read_exact(&mut buf).await?;
    let magic = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let opt_magic = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    if magic != NBDMAGIC || opt_magic != IHAVEOPT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NBD Fixed Newstyle greeting magic",
        ));
    }
    Ok(u16::from_be_bytes([buf[16], buf[17]]))
}

pub async fn read_client_option<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(u32, u32)> {
    let mut hdr = [0u8; 16];
    r.read_exact(&mut hdr).await?;
    let magic = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
    if magic != IHAVEOPT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NBD client option magic",
        ));
    }
    let code = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
    let len = u32::from_be_bytes(hdr[12..16].try_into().unwrap());
    Ok((code, len))
}

pub async fn write_client_option<W: AsyncWrite + Unpin>(
    w: &mut W,
    code: u32,
    data: &[u8],
) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "option payload overflow"))?;
    let mut hdr = [0u8; 16];
    hdr[0..8].copy_from_slice(&IHAVEOPT.to_be_bytes());
    hdr[8..12].copy_from_slice(&code.to_be_bytes());
    hdr[12..16].copy_from_slice(&len.to_be_bytes());
    w.write_all(&hdr).await?;
    if !data.is_empty() {
        w.write_all(data).await?;
    }
    w.flush().await
}

pub async fn write_option_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    option: u32,
    reply_type: u32,
    data: &[u8],
) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "reply payload overflow"))?;
    let mut hdr = [0u8; 20];
    hdr[0..8].copy_from_slice(&NBD_REP_MAGIC.to_be_bytes());
    hdr[8..12].copy_from_slice(&option.to_be_bytes());
    hdr[12..16].copy_from_slice(&reply_type.to_be_bytes());
    hdr[16..20].copy_from_slice(&len.to_be_bytes());
    w.write_all(&hdr).await?;
    if !data.is_empty() {
        w.write_all(data).await?;
    }
    w.flush().await
}

pub async fn read_option_reply<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<OptionReply> {
    let mut hdr = [0u8; 20];
    r.read_exact(&mut hdr).await?;
    let magic = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
    if magic != NBD_REP_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NBD option reply magic",
        ));
    }
    let option = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
    let reply_type = u32::from_be_bytes(hdr[12..16].try_into().unwrap());
    let len = u32::from_be_bytes(hdr[16..20].try_into().unwrap());
    if len > MAX_OPTION_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NBD option reply exceeds MAX_OPTION_LEN",
        ));
    }
    let mut data = vec![0u8; len as usize];
    if !data.is_empty() {
        r.read_exact(&mut data).await?;
    }
    Ok(OptionReply {
        option,
        reply_type,
        data,
    })
}

pub fn encode_info_export(size_bytes: u64, transmission_flags: u16) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..2].copy_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
    out[2..10].copy_from_slice(&size_bytes.to_be_bytes());
    out[10..12].copy_from_slice(&transmission_flags.to_be_bytes());
    out
}

pub fn encode_info_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + name.len());
    out.extend_from_slice(&NBD_INFO_NAME.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out
}

pub fn encode_info_block_size(min_block: u32, preferred_block: u32, max_block: u32) -> [u8; 14] {
    let mut out = [0u8; 14];
    out[0..2].copy_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
    out[2..6].copy_from_slice(&min_block.to_be_bytes());
    out[6..10].copy_from_slice(&preferred_block.to_be_bytes());
    out[10..14].copy_from_slice(&max_block.to_be_bytes());
    out
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<NbdRequest>> {
    let mut buf = [0u8; 28];
    match r.read_exact(&mut buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if magic != NBD_REQUEST_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NBD request magic",
        ));
    }
    Ok(Some(NbdRequest {
        flags: u16::from_be_bytes([buf[4], buf[5]]),
        cmd: u16::from_be_bytes([buf[6], buf[7]]),
        handle: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        offset: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
        length: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
    }))
}

pub async fn write_request<W: AsyncWrite + Unpin>(w: &mut W, req: &NbdRequest) -> io::Result<()> {
    let mut buf = [0u8; 28];
    buf[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
    buf[4..6].copy_from_slice(&req.flags.to_be_bytes());
    buf[6..8].copy_from_slice(&req.cmd.to_be_bytes());
    buf[8..16].copy_from_slice(&req.handle.to_be_bytes());
    buf[16..24].copy_from_slice(&req.offset.to_be_bytes());
    buf[24..28].copy_from_slice(&req.length.to_be_bytes());
    w.write_all(&buf).await
}

pub async fn write_simple_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    error: u32,
    handle: u64,
    payload: Option<&[u8]>,
) -> io::Result<()> {
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
    buf[4..8].copy_from_slice(&error.to_be_bytes());
    buf[8..16].copy_from_slice(&handle.to_be_bytes());
    w.write_all(&buf).await?;
    if let Some(bytes) = payload
        && !bytes.is_empty()
    {
        w.write_all(bytes).await?;
    }
    w.flush().await
}

pub async fn read_simple_reply<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<NbdReply> {
    let mut buf = [0u8; 16];
    r.read_exact(&mut buf).await?;
    let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if magic != NBD_SIMPLE_REPLY_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NBD simple reply magic",
        ));
    }
    Ok(NbdReply {
        error: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
        handle: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
    })
}
