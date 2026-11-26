//! Async NBD Fixed Newstyle client over Unix sockets (and generic `AsyncRead + AsyncWrite`).

use crate::proto::{
    NBD_CMD_DISC, NBD_CMD_FLAG_FUA, NBD_CMD_FLUSH, NBD_CMD_READ, NBD_CMD_TRIM, NBD_CMD_WRITE,
    NBD_CMD_WRITE_ZEROES, NBD_FLAG_C_FIXED_NEWSTYLE, NBD_FLAG_C_NO_ZEROES, NBD_FLAG_FIXED_NEWSTYLE,
    NBD_INFO_BLOCK_SIZE, NBD_INFO_EXPORT, NBD_INFO_NAME, NBD_OK, NBD_OPT_ABORT, NBD_OPT_GO,
    NBD_OPT_INFO, NBD_OPT_LIST, NBD_REP_ACK, NBD_REP_INFO, NBD_REP_SERVER, NbdRequest,
    read_newstyle_greeting, read_option_reply, read_simple_reply, write_client_option,
    write_request,
};
use std::fmt;
use std::io;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbdExportInfo {
    pub name: String,
    pub size_bytes: u64,
    pub transmission_flags: u16,
    pub min_block_size: Option<u32>,
    pub preferred_block_size: Option<u32>,
    pub max_block_size: Option<u32>,
}

#[derive(Debug)]
pub enum NbdClientError {
    Io(io::Error),
    Protocol(String),
    OptionError(u32),
    ServerError(u32),
}

impl fmt::Display for NbdClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "NBD I/O error: {e}"),
            Self::Protocol(s) => write!(f, "NBD protocol error: {s}"),
            Self::OptionError(code) => write!(f, "NBD option error: 0x{code:08x}"),
            Self::ServerError(code) => write!(f, "NBD server error: {code}"),
        }
    }
}

impl std::error::Error for NbdClientError {}

impl From<io::Error> for NbdClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct NbdClient<S> {
    stream: S,
    next_handle: u64,
    in_transmission: bool,
}

impl NbdClient<UnixStream> {
    pub async fn connect_unix(path: &Path) -> Result<Self, NbdClientError> {
        let stream = UnixStream::connect(path).await?;
        Self::from_stream(stream).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> NbdClient<S> {
    pub async fn from_stream(mut stream: S) -> Result<Self, NbdClientError> {
        let hflags = read_newstyle_greeting(&mut stream).await?;
        if (hflags & NBD_FLAG_FIXED_NEWSTYLE) == 0 {
            return Err(NbdClientError::Protocol(
                "server does not advertise NBD_FLAG_FIXED_NEWSTYLE".into(),
            ));
        }
        let cflags = NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES;
        stream.write_all(&cflags.to_be_bytes()).await?;
        stream.flush().await?;
        Ok(Self {
            stream,
            next_handle: 1,
            in_transmission: false,
        })
    }

    pub async fn list_exports(&mut self) -> Result<Vec<String>, NbdClientError> {
        if self.in_transmission {
            return Err(NbdClientError::Protocol("already in transmission".into()));
        }
        write_client_option(&mut self.stream, NBD_OPT_LIST, &[]).await?;
        let mut names = Vec::new();
        for _ in 0..crate::proto::MAX_HANDSHAKE_OPTIONS {
            let rep = read_option_reply(&mut self.stream).await?;
            match rep.reply_type {
                NBD_REP_SERVER => {
                    if rep.data.len() < 4 {
                        return Err(NbdClientError::Protocol("short NBD_REP_SERVER".into()));
                    }
                    let nlen = u32::from_be_bytes(rep.data[0..4].try_into().unwrap()) as usize;
                    let end = 4usize.checked_add(nlen).ok_or_else(|| {
                        NbdClientError::Protocol("export name length overflow".into())
                    })?;
                    if rep.data.len() < end {
                        return Err(NbdClientError::Protocol("truncated export name".into()));
                    }
                    let name = std::str::from_utf8(&rep.data[4..end])
                        .map_err(|_| NbdClientError::Protocol("non-UTF8 export name".into()))?
                        .to_string();
                    names.push(name);
                }
                NBD_REP_ACK => return Ok(names),
                err if (err & (1 << 31)) != 0 => return Err(NbdClientError::OptionError(err)),
                other => {
                    return Err(NbdClientError::Protocol(format!(
                        "unexpected NBD_OPT_LIST reply 0x{other:08x}"
                    )));
                }
            }
        }
        Err(NbdClientError::Protocol(
            "too many NBD_OPT_LIST replies without ACK".into(),
        ))
    }

    async fn info_or_go(
        &mut self,
        opt: u32,
        export_name: &str,
    ) -> Result<NbdExportInfo, NbdClientError> {
        if self.in_transmission {
            return Err(NbdClientError::Protocol("already in transmission".into()));
        }
        let nb = export_name.as_bytes();
        let mut req = Vec::with_capacity(4 + nb.len() + 2);
        req.extend_from_slice(&(nb.len() as u32).to_be_bytes());
        req.extend_from_slice(nb);
        req.extend_from_slice(&0u16.to_be_bytes()); // request default info items
        write_client_option(&mut self.stream, opt, &req).await?;

        let mut info = NbdExportInfo {
            name: export_name.to_string(),
            size_bytes: 0,
            transmission_flags: 0,
            min_block_size: None,
            preferred_block_size: None,
            max_block_size: None,
        };
        let mut saw_export = false;
        for _ in 0..crate::proto::MAX_HANDSHAKE_OPTIONS {
            let rep = read_option_reply(&mut self.stream).await?;
            match rep.reply_type {
                NBD_REP_INFO => {
                    if rep.data.len() < 2 {
                        return Err(NbdClientError::Protocol("short NBD_REP_INFO".into()));
                    }
                    let kind = u16::from_be_bytes([rep.data[0], rep.data[1]]);
                    match kind {
                        NBD_INFO_EXPORT => {
                            if rep.data.len() != 12 {
                                return Err(NbdClientError::Protocol("bad NBD_INFO_EXPORT".into()));
                            }
                            info.size_bytes =
                                u64::from_be_bytes(rep.data[2..10].try_into().unwrap());
                            info.transmission_flags =
                                u16::from_be_bytes([rep.data[10], rep.data[11]]);
                            saw_export = true;
                        }
                        NBD_INFO_NAME => {
                            info.name = std::str::from_utf8(&rep.data[2..])
                                .map_err(|_| NbdClientError::Protocol("non-UTF8 info name".into()))?
                                .to_string();
                        }
                        NBD_INFO_BLOCK_SIZE if rep.data.len() == 14 => {
                            info.min_block_size =
                                Some(u32::from_be_bytes(rep.data[2..6].try_into().unwrap()));
                            info.preferred_block_size =
                                Some(u32::from_be_bytes(rep.data[6..10].try_into().unwrap()));
                            info.max_block_size =
                                Some(u32::from_be_bytes(rep.data[10..14].try_into().unwrap()));
                        }
                        _ => {}
                    }
                }
                NBD_REP_ACK => {
                    if !saw_export {
                        return Err(NbdClientError::Protocol("missing NBD_INFO_EXPORT".into()));
                    }
                    if opt == NBD_OPT_GO {
                        self.in_transmission = true;
                    }
                    return Ok(info);
                }
                err if (err & (1 << 31)) != 0 => return Err(NbdClientError::OptionError(err)),
                other => {
                    return Err(NbdClientError::Protocol(format!(
                        "unexpected INFO/GO reply 0x{other:08x}"
                    )));
                }
            }
        }
        Err(NbdClientError::Protocol(
            "too many INFO/GO replies without ACK".into(),
        ))
    }

    pub async fn info(&mut self, export_name: &str) -> Result<NbdExportInfo, NbdClientError> {
        self.info_or_go(NBD_OPT_INFO, export_name).await
    }

    pub async fn go(&mut self, export_name: &str) -> Result<NbdExportInfo, NbdClientError> {
        self.info_or_go(NBD_OPT_GO, export_name).await
    }

    pub async fn abort(mut self) -> Result<(), NbdClientError> {
        write_client_option(&mut self.stream, NBD_OPT_ABORT, &[]).await?;
        let rep = read_option_reply(&mut self.stream).await?;
        if rep.reply_type != NBD_REP_ACK {
            return Err(NbdClientError::OptionError(rep.reply_type));
        }
        Ok(())
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }

    pub async fn read(&mut self, offset: u64, len: u32) -> Result<Vec<u8>, NbdClientError> {
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags: 0,
                cmd: NBD_CMD_READ,
                handle,
                offset,
                length: len,
            },
        )
        .await?;
        self.stream.flush().await?;
        let rep = read_simple_reply(&mut self.stream).await?;
        if rep.handle != handle {
            return Err(NbdClientError::Protocol("mismatched reply handle".into()));
        }
        if rep.error != NBD_OK {
            return Err(NbdClientError::ServerError(rep.error));
        }
        let mut buf = vec![0u8; len as usize];
        if !buf.is_empty() {
            self.stream.read_exact(&mut buf).await?;
        }
        Ok(buf)
    }

    pub async fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        fua: bool,
    ) -> Result<(), NbdClientError> {
        let len = u32::try_from(data.len())
            .map_err(|_| NbdClientError::Protocol("write length overflow".into()))?;
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags: if fua { NBD_CMD_FLAG_FUA } else { 0 },
                cmd: NBD_CMD_WRITE,
                handle,
                offset,
                length: len,
            },
        )
        .await?;
        if !data.is_empty() {
            self.stream.write_all(data).await?;
        }
        self.stream.flush().await?;
        let rep = read_simple_reply(&mut self.stream).await?;
        if rep.handle != handle {
            return Err(NbdClientError::Protocol("mismatched reply handle".into()));
        }
        if rep.error != NBD_OK {
            return Err(NbdClientError::ServerError(rep.error));
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), NbdClientError> {
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags: 0,
                cmd: NBD_CMD_FLUSH,
                handle,
                offset: 0,
                length: 0,
            },
        )
        .await?;
        self.stream.flush().await?;
        let rep = read_simple_reply(&mut self.stream).await?;
        if rep.handle != handle {
            return Err(NbdClientError::Protocol("mismatched reply handle".into()));
        }
        if rep.error != NBD_OK {
            return Err(NbdClientError::ServerError(rep.error));
        }
        Ok(())
    }

    pub async fn trim(&mut self, offset: u64, len: u32, fua: bool) -> Result<(), NbdClientError> {
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags: if fua { NBD_CMD_FLAG_FUA } else { 0 },
                cmd: NBD_CMD_TRIM,
                handle,
                offset,
                length: len,
            },
        )
        .await?;
        self.stream.flush().await?;
        let rep = read_simple_reply(&mut self.stream).await?;
        if rep.handle != handle {
            return Err(NbdClientError::Protocol("mismatched reply handle".into()));
        }
        if rep.error != NBD_OK {
            return Err(NbdClientError::ServerError(rep.error));
        }
        Ok(())
    }

    pub async fn write_zeroes(
        &mut self,
        offset: u64,
        len: u32,
        fua: bool,
    ) -> Result<(), NbdClientError> {
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags: if fua { NBD_CMD_FLAG_FUA } else { 0 },
                cmd: NBD_CMD_WRITE_ZEROES,
                handle,
                offset,
                length: len,
            },
        )
        .await?;
        self.stream.flush().await?;
        let rep = read_simple_reply(&mut self.stream).await?;
        if rep.handle != handle {
            return Err(NbdClientError::Protocol("mismatched reply handle".into()));
        }
        if rep.error != NBD_OK {
            return Err(NbdClientError::ServerError(rep.error));
        }
        Ok(())
    }

    pub async fn disconnect(mut self) -> Result<(), NbdClientError> {
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags: 0,
                cmd: NBD_CMD_DISC,
                handle,
                offset: 0,
                length: 0,
            },
        )
        .await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Raw request helper for testing oversize / malformed server error paths.
    pub async fn send_raw_header_and_read_reply(
        &mut self,
        cmd: u16,
        flags: u16,
        offset: u64,
        length: u32,
    ) -> Result<u32, NbdClientError> {
        let handle = self.alloc_handle();
        write_request(
            &mut self.stream,
            &NbdRequest {
                flags,
                cmd,
                handle,
                offset,
                length,
            },
        )
        .await?;
        self.stream.flush().await?;
        let rep = read_simple_reply(&mut self.stream).await?;
        if rep.handle != handle {
            return Err(NbdClientError::Protocol("mismatched reply handle".into()));
        }
        Ok(rep.error)
    }
}
