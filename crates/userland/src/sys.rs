//! System calls, as user space makes them (libc's part): a batch of calls at a time, each
//! answered on its own, and typed helpers for one.
use abi::{BATCH_MAX, Call, Dirent, Errno, Error, Stat};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The kernel, as a process reaches it: the calls, as one batch, each answered on its own (a
/// batch that cannot be sent at all answers each with EIO); and a file's bytes, as pread(2)
/// reads them, which go apart from the calls, as bytes do.
#[allow(async_fn_in_trait)]
pub trait Sys {
    async fn batch(&self, calls: Vec<Call>) -> Vec<Result<Value, Error>>;
    async fn read(&self, path: &str) -> Result<Vec<u8>, Error>;
    /// Replace an existing file's bytes. Byte-I/O adapters can handle transfers larger
    /// than the inline syscall limit without changing the programs using this trait.
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() as u64 > abi::INLINE_MAX {
            return Err(Errno::EFBIG.into());
        }
        let fd = abi::FdRef::Ref { call: 0 };
        let mut writing = vec![Call::Open {
            path: path.into(),
            flags: abi::O_WRONLY | abi::O_TRUNC,
            mode: 0,
            size: None,
            sha256: None,
            version: None,
        }];
        if !bytes.is_empty() {
            writing.push(Call::Pwrite {
                fd,
                index: 0,
                data: bytes.to_vec().into(),
            });
        }
        writing.push(Call::Close { fd });
        for result in self.batch(writing).await {
            result?;
        }
        Ok(())
    }
}

/// Make `calls`, as many batches as they take: each one's value, as `T`, or its error.
pub async fn calls<T: DeserializeOwned>(sys: &impl Sys, calls: Vec<Call>) -> Vec<Result<T, Error>> {
    let mut out = Vec::with_capacity(calls.len());
    let mut calls = calls.into_iter().peekable();
    while calls.peek().is_some() {
        let batch: Vec<Call> = calls.by_ref().take(BATCH_MAX).collect();
        for result in sys.batch(batch).await {
            out.push(result.and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|e| Error::because(Errno::EIO, format!("bad reply: {e}")))
            }));
        }
    }
    out
}

/// Make one call: its value, as `T`, or its error.
pub async fn call<T: DeserializeOwned>(sys: &impl Sys, call: Call) -> Result<T, Error> {
    calls(sys, vec![call])
        .await
        .pop()
        .unwrap_or_else(|| Err(Errno::EIO.into()))
}

/// A call that gives nothing back: whether it was done.
pub async fn done(sys: &impl Sys, call: Call) -> Result<(), Error> {
    self::call::<Value>(sys, call).await.map(|_| ())
}

pub async fn stat(sys: &impl Sys, path: &str) -> Result<Stat, Error> {
    call(sys, Call::Stat { path: path.into() }).await
}

pub async fn lstat(sys: &impl Sys, path: &str) -> Result<Stat, Error> {
    call(sys, Call::Lstat { path: path.into() }).await
}

pub async fn getdents(sys: &impl Sys, path: &str) -> Result<Vec<Dirent>, Error> {
    call(
        sys,
        Call::Getdents {
            path: path.into(),
            cookie: 0,
            count: None,
        },
    )
    .await
}
