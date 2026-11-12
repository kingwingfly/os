//! Bounded per-unit journals over ordinary pipes and files. No logging syscall or service.
use crate::forward::Forward;
use os_posix::pipe::{close_on_exec, pipe, readable};
use serde_json::json;
#[cfg(not(target_os = "wasi"))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::AsRawFd;
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

const BUDGET: usize = 65536 - 512;
#[derive(Default)]
pub struct Ring {
    records: VecDeque<Vec<u8>>,
    bytes: usize,
    sequence: u64,
    dropped: u64,
    dirty: bool,
}
impl Ring {
    pub fn push(&mut self, mut value: serde_json::Value) {
        self.sequence += 1;
        value["sequence"] = json!(self.sequence);
        let mut record = serde_json::to_vec(&value).expect("journal JSON");
        record.push(b'\n');
        if record.len() > BUDGET {
            self.dropped += 1;
            self.dirty = true;
            return;
        }
        while self.bytes + record.len() > BUDGET {
            self.bytes -= self.records.pop_front().unwrap().len();
            self.dropped += 1;
        }
        self.bytes += record.len();
        self.records.push_back(record);
        self.dirty = true;
    }
    fn write(
        &self,
        out: &mut impl Write,
        name: &str,
        forwarding_dropped: [u64; 2],
    ) -> io::Result<()> {
        serde_json::to_writer(
            &mut *out,
            &json!({"format":"os.service-journal", "version":1, "unit":name, "dropped":self.dropped, "forwarding_dropped_bytes":forwarding_dropped}),
        )?;
        out.write_all(b"\n")?;
        for record in &self.records {
            out.write_all(record)?;
        }
        Ok(())
    }
}
pub struct Journals {
    rings: Vec<Ring>,
    names: Vec<String>,
    directory: Option<PathBuf>,
    flushed: u64,
    forward: Forward,
}
impl Journals {
    pub fn open(names: Vec<String>, directory: Option<&str>) -> io::Result<Self> {
        let directory = directory.map(PathBuf::from);
        if let Some(path) = &directory {
            os_posix::mkdir(path, 0o700)?;
        }
        Ok(Self {
            rings: names.iter().map(|_| Ring::default()).collect(),
            names,
            directory,
            flushed: 0,
            forward: Forward::new()?,
        })
    }
    pub fn event(&mut self, index: usize, attempt: u32, now: u64, text: &str) {
        self.forward.push(
            2,
            format!("supervise: {}: {text}\n", self.names[index]).as_bytes(),
        );
        self.rings[index]
            .push(json!({"elapsed_ms":now,"attempt":attempt,"stream":"event","text":text}));
    }
    fn output(&mut self, index: usize, attempt: u32, now: u64, fd: u32, bytes: &[u8]) {
        self.forward.pump(false);
        self.forward.push(fd, bytes);
        // Exact bytes survive split UTF-8, NULs and arbitrary binary output.
        self.rings[index].push(json!({"elapsed_ms":now,"attempt":attempt,"stream":if fd == 1 {"stdout"} else {"stderr"},"data":abi::Bytes(bytes.to_vec())}));
    }
    pub fn flush(&mut self, now: u64, force: bool) -> io::Result<()> {
        self.forward.pump(force);
        if !force && now.saturating_sub(self.flushed) < 1000 {
            return Ok(());
        }
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        self.flushed = now;
        for (i, ring) in self
            .rings
            .iter_mut()
            .enumerate()
            .filter(|(_, ring)| ring.dirty)
        {
            let path = directory.join(format!("{i}-{}.jsonl", self.names[i]));
            let temporary = directory.join(format!("{i}-{}.tmp", self.names[i]));
            // A fresh private directory prevents accidentally replacing old journals.
            // Closing commits the bounded snapshot before rename publishes it.
            let mut bytes = Vec::with_capacity(65536);
            ring.write(&mut bytes, &self.names[i], self.forward.dropped())?;
            if bytes.len() > 65536 {
                return Err(io::Error::other("journal exceeds its bound"));
            }
            write_snapshot(&temporary, &bytes)?;
            std::fs::rename(temporary, path)?;
            ring.dirty = false;
        }
        Ok(())
    }
}
fn write_snapshot(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    let written = file.write_all(bytes);
    // WASI close commits a growing remote file and can fail. Drop would hide that error.
    #[cfg(target_os = "wasi")]
    {
        use std::os::wasi::io::IntoRawFd;
        #[link(wasm_import_module = "wasi_snapshot_preview1")]
        unsafe extern "C" {
            fn fd_close(fd: u32) -> u32;
        }
        // SAFETY: consume the file exactly once; no Rust owner retains this descriptor.
        let code = unsafe { fd_close(file.into_raw_fd() as u32) };
        written?;
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        written?;
        file.sync_all()?;
    }
    Ok(())
}

pub struct Output {
    readers: [(File, bool); 2],
    writers: Option<[File; 2]>,
}
impl Output {
    pub fn open() -> io::Result<Self> {
        let (out, out_write) = pipe()?;
        let (err, err_write) = pipe()?;
        close_on_exec(&out_write)?;
        close_on_exec(&err_write)?;
        Ok(Self {
            readers: [(out, false), (err, false)],
            writers: Some([out_write, err_write]),
        })
    }
    pub fn actions(&self) -> [(u32, u32); 2] {
        let writers = self.writers.as_ref().expect("before spawn");
        [
            (writers[0].as_raw_fd() as u32, 1),
            (writers[1].as_raw_fd() as u32, 2),
        ]
    }
    pub fn spawned(&mut self) {
        self.writers.take();
    }
    pub fn drain(
        &mut self,
        journal: &mut Journals,
        index: usize,
        attempt: u32,
        now: u64,
    ) -> io::Result<()> {
        // Fair bounded draining keeps a noisy unit from starving deadlines or its siblings.
        for (n, (reader, ended)) in self.readers.iter_mut().enumerate() {
            for _ in 0..4 {
                if *ended || !readable(reader)? {
                    break;
                }
                let mut bytes = [0; 4096];
                let count = reader.read(&mut bytes)?;
                if count == 0 {
                    *ended = true;
                    break;
                }
                journal.output(index, attempt, now, n as u32 + 1, &bytes[..count]);
            }
        }
        Ok(())
    }
    pub fn ended(&self) -> bool {
        self.readers.iter().all(|(_, ended)| *ended)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_bounds_storage_and_keeps_complete_sequenced_records() {
        let mut ring = Ring::default();
        for i in 0..1000 {
            ring.push(json!({"text":"x".repeat(4096),"attempt":i}));
        }
        let mut bytes = Vec::new();
        ring.write(&mut bytes, "bounded", [0, 0]).unwrap();
        assert!(bytes.len() <= 65536);
        assert!(ring.dropped > 0);
        let lines: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.last().unwrap()["sequence"], 1000);
        assert_eq!(lines.len() as u64 - 1 + ring.dropped, 1000);
    }
    #[test]
    fn journal_preserves_binary_data_without_utf8_replacement() {
        let mut logs = Journals::open(vec!["bytes".into()], None).unwrap();
        let source = [0, 255, 240, 159, 166, 128];
        logs.output(0, 2, 9, 2, &source);
        let record: serde_json::Value =
            serde_json::from_slice(logs.rings[0].records.front().unwrap()).unwrap();
        let bytes: abi::Bytes = serde_json::from_value(record["data"].clone()).unwrap();
        assert_eq!(bytes.0, source);
        assert_eq!(record["stream"], "stderr");
    }
}
