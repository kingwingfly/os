use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::fs::{self, AtFlags, Dir, Mode, OFlags, ResolveFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
    time::{Duration, Instant},
};
use tiny_http::{Header, Method, Response, Server};

const CHUNK: usize = 256 * 1024;
const IMAGE_MAX: usize = 128 * 1024 * 1024;
type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
struct Failure(&'static str, String);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}
impl std::error::Error for Failure {}
fn bad(code: &'static str) -> Failure {
    Failure(code, code.into())
}
impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        let code = match error.raw_os_error() {
            Some(1) => "EPERM",
            Some(2) => "ENOENT",
            Some(9) => "EBADF",
            Some(11) => "EAGAIN",
            Some(13) => "EACCES",
            Some(17) => "EEXIST",
            Some(18) => "EXDEV",
            Some(20) => "ENOTDIR",
            Some(21) => "EISDIR",
            Some(22) => "EINVAL",
            Some(28) => "ENOSPC",
            Some(38) => "EOPNOTSUPP",
            Some(39) => "ENOTEMPTY",
            Some(40) => "ELOOP",
            _ => "EIO",
        };
        Self(code, error.to_string())
    }
}
impl From<rustix::io::Errno> for Failure {
    fn from(error: rustix::io::Errno) -> Self {
        std::io::Error::from(error).into()
    }
}
fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key].as_str().ok_or_else(|| bad("EINVAL"))
}
fn number(args: &Value, key: &str, default: u64) -> Result<u64> {
    if args[key].is_null() {
        Ok(default)
    } else {
        args[key]
            .as_u64()
            .filter(|n| *n < (1u64 << 53))
            .ok_or_else(|| bad("EINVAL"))
    }
}
fn secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn relative(path: &str) -> Result<&str> {
    if path.len() > 4096
        || path.starts_with('/')
        || path.contains(['\0', '\\'])
        || path.split('/').any(|part| part == ".." || part.len() > 255)
    {
        return Err(bad("EACCES"));
    }
    Ok(if path.is_empty() { "." } else { path })
}
fn open(root: &File, path: &str, flags: OFlags, mode: Mode) -> Result<File> {
    Ok(fs::openat2(
        root,
        relative(path)?,
        flags | OFlags::CLOEXEC,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )?
    .into())
}
fn parent(root: &File, path: &str) -> Result<(File, String)> {
    relative(path)?;
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name.is_empty() || name == "." || name == ".." {
        return Err(bad("EBUSY"));
    }
    Ok((
        open(
            root,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?,
        name.into(),
    ))
}
struct Held {
    file: File,
    read: bool,
    write: bool,
    append: bool,
}
struct Session {
    writable: bool,
    executable: bool,
    touched: Instant,
    handles: HashMap<String, Held>,
    images: HashMap<String, Vec<u8>>,
}
struct Adapter {
    root: File,
    writable: bool,
    executable: bool,
    master: String,
    sessions: HashMap<String, Session>,
}
impl Adapter {
    fn sweep(&mut self) {
        self.sessions
            .retain(|_, session| session.touched.elapsed() < Duration::from_secs(60));
    }
    fn metadata(&self, file: &File) -> Result<Value> {
        let meta = file.metadata()?;
        let kind = if meta.is_dir() {
            "directory"
        } else if meta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_file() {
            "file"
        } else {
            return Err(bad("EOPNOTSUPP"));
        };
        Ok(
            json!({"kind": kind, "identity": format!("{}:{}", meta.dev(), meta.ino()), "size": meta.len(), "lastModified": meta.mtime().max(0) as u64 * 1000 + meta.mtime_nsec().max(0) as u64 / 1_000_000, "readOnly": !self.writable, "executable": self.executable && meta.is_file()}),
        )
    }
    fn handle(&mut self, token: &str, args: Value) -> Result<Value> {
        self.sweep();
        let op = text(&args, "op")?;
        if op == "mount" {
            if token != self.master {
                return Err(bad("EACCES"));
            }
            if self.sessions.len() >= 16 {
                return Err(bad("ENOSPC"));
            }
            let writable = self.writable && args["write"].as_bool() == Some(true);
            let executable = self.executable && args["execute"].as_bool() == Some(true);
            if args["write"].as_bool() == Some(true) && !writable
                || args["execute"].as_bool() == Some(true) && !executable
            {
                return Err(bad("EACCES"));
            }
            let proof = secret()?;
            self.sessions.insert(
                proof.clone(),
                Session {
                    writable,
                    executable,
                    touched: Instant::now(),
                    handles: HashMap::new(),
                    images: HashMap::new(),
                },
            );
            return Ok(
                json!({"proof": proof, "write": writable, "execute": executable, "protocol": 1}),
            );
        }
        let session = self.sessions.get_mut(token).ok_or_else(|| bad("EACCES"))?;
        session.touched = Instant::now();
        let writable = session.writable;
        let executable = session.executable;
        match op {
            "keep" => return Ok(Value::Null),
            "unmount" => {
                self.sessions.remove(token);
                return Ok(Value::Null);
            }
            "release" => {
                session
                    .handles
                    .remove(text(&args, "handle")?)
                    .ok_or_else(|| bad("EBADF"))?;
                return Ok(Value::Null);
            }
            "unpin" => {
                session.images.remove(text(&args, "id")?);
                return Ok(Value::Null);
            }
            "image" => {
                let bytes = session
                    .images
                    .get(text(&args, "id")?)
                    .ok_or_else(|| bad("ESTALE"))?;
                let offset = number(&args, "offset", 0)? as usize;
                return Ok(json!(STANDARD.encode(
                    &bytes[offset.min(bytes.len())..offset.saturating_add(CHUNK).min(bytes.len())]
                )));
            }
            _ => {}
        }
        if ["mkdir", "remove", "rename", "write"].contains(&op) && !writable {
            return Err(bad("EROFS"));
        }
        if op == "open" || op == "hold" {
            if session.handles.len() >= 128 {
                return Err(bad("EMFILE"));
            }
            let flags = u32::try_from(number(&args, "flags", 0)?).map_err(|_| bad("EINVAL"))?;
            let allowed = 3 | 0o100 | 0o200 | 0o1000 | 0o2000 | 0o200000 | 0o400000 | 0o2000000;
            if flags & !allowed != 0 || flags & 3 == 3 {
                return Err(bad("EOPNOTSUPP"));
            }
            let write = flags & 3 != 0;
            if (write || flags & (0o100 | 0o1000) != 0) && !writable {
                return Err(bad("EROFS"));
            }
            if flags & 0o1000 != 0 && !write {
                return Err(bad("EACCES"));
            }
            let path = text(&args, "path")?;
            // Exported subdirectories use a separately opened root for descriptor admission.
            let boundary = text(&args, "root").unwrap_or("");
            let boundary_file = open(
                &self.root,
                boundary,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )?;
            let scoped = if boundary.is_empty() {
                path
            } else {
                path.strip_prefix(&(boundary.to_owned() + "/"))
                    .ok_or_else(|| bad("EACCES"))?
            };
            let file = open(
                &boundary_file,
                scoped,
                OFlags::from_bits_retain(flags),
                if flags & 0o100 != 0 {
                    Mode::RUSR | Mode::WUSR
                } else {
                    Mode::empty()
                },
            )?;
            if !file.metadata()?.is_file() {
                return Err(bad("EISDIR"));
            }
            let handle = secret()?;
            session.handles.insert(
                handle.clone(),
                Held {
                    file,
                    read: flags & 3 != 1,
                    write,
                    append: flags & 0o2000 != 0,
                },
            );
            return Ok(json!(handle));
        }
        if ["mkdir", "remove", "rename"].contains(&op) {
            let path = text(&args, "path")?;
            let (directory, name) = parent(&self.root, path)?;
            match op {
                "mkdir" => fs::mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?,
                "remove" => fs::unlinkat(
                    &directory,
                    name,
                    if args["directory"].as_bool() == Some(true) {
                        AtFlags::REMOVEDIR
                    } else {
                        AtFlags::empty()
                    },
                )?,
                _ => {
                    let (target, target_name) = parent(&self.root, text(&args, "to")?)?;
                    fs::renameat(&directory, name, &target, target_name)?;
                }
            }
            return Ok(Value::Null);
        }
        if op == "pin" {
            if !executable {
                return Err(bad("EACCES"));
            }
            if session.images.len() >= 2 {
                return Err(bad("EAGAIN"));
            }
            let reserved: usize = self
                .sessions
                .values()
                .flat_map(|s| s.images.values())
                .map(Vec::len)
                .sum();
            let mut file = open(
                &self.root,
                text(&args, "path")?,
                OFlags::RDONLY,
                Mode::empty(),
            )?;
            let before = file.metadata()?;
            if !before.is_file()
                || before.len() > IMAGE_MAX as u64
                || reserved as u64 + before.len() > IMAGE_MAX as u64
            {
                return Err(bad("EFBIG"));
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(IMAGE_MAX as u64 + 1)
                .read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            if bytes.len() != before.len() as usize
                || before.mtime_nsec() != after.mtime_nsec()
                || before.mtime() != after.mtime()
                || before.ctime_nsec() != after.ctime_nsec()
                || before.ctime() != after.ctime()
                || before.len() != after.len()
            {
                return Err(bad("ESTALE"));
            }
            let id = secret()?;
            let digest = hex(&Sha256::digest(&bytes));
            let value = json!({"id": id, "size": bytes.len(), "digest": digest});
            self.sessions
                .get_mut(token)
                .unwrap()
                .images
                .insert(id, bytes);
            return Ok(value);
        }
        let (file, read, write, append) = if let Some(handle) = args["handle"].as_str() {
            let held = session.handles.get(handle).ok_or_else(|| bad("EBADF"))?;
            (held.file.try_clone()?, held.read, held.write, held.append)
        } else {
            let flags = if op == "write" {
                OFlags::RDWR
                    | if args["create"].as_bool() == Some(true) {
                        OFlags::CREATE
                    } else {
                        OFlags::empty()
                    }
            } else if op == "stat" && args["follow"].as_bool() == Some(false) {
                OFlags::PATH | OFlags::NOFOLLOW
            } else {
                OFlags::RDONLY
            };
            (
                open(
                    &self.root,
                    text(&args, "path")?,
                    flags,
                    if flags.contains(OFlags::CREATE) {
                        Mode::RUSR | Mode::WUSR
                    } else {
                        Mode::empty()
                    },
                )?,
                true,
                writable,
                false,
            )
        };
        match op {
            "stat" => self.metadata(&file),
            "list" => {
                let offset = number(&args, "offset", 0)? as usize;
                let limit = number(&args, "limit", 256)? as usize;
                if offset > 100000 || limit == 0 || limit > 256 {
                    return Err(bad("EINVAL"));
                }
                let mut entries = Vec::new();
                let mut at = 0;
                for entry in Dir::read_from(&file)? {
                    let entry = entry?;
                    let name = entry.file_name().to_str().map_err(|_| bad("EILSEQ"))?;
                    if name == "." || name == ".." {
                        continue;
                    }
                    at += 1;
                    if at <= offset {
                        continue;
                    }
                    if entries.len() == limit {
                        return Ok(json!({"entries": entries, "next": offset + entries.len()}));
                    }
                    let kind = match entry.file_type() {
                        fs::FileType::Directory => "directory",
                        fs::FileType::Symlink => "symlink",
                        _ => "file",
                    };
                    entries.push(json!({"name": name, "kind": kind}));
                }
                Ok(json!({"entries": entries, "next": null}))
            }
            "read" => {
                if !read || !file.metadata()?.is_file() {
                    return Err(bad("EBADF"));
                }
                let count = number(&args, "count", CHUNK as u64)? as usize;
                if count > CHUNK {
                    return Err(bad("E2BIG"));
                }
                let mut bytes = vec![0; count];
                let n = file.read_at(&mut bytes, number(&args, "offset", 0)?)?;
                Ok(json!(STANDARD.encode(&bytes[..n])))
            }
            "write" => {
                if !write {
                    return Err(bad("EBADF"));
                }
                let bytes = STANDARD
                    .decode(text(&args, "data")?)
                    .map_err(|_| bad("EINVAL"))?;
                if bytes.len() > CHUNK {
                    return Err(bad("E2BIG"));
                }
                if !args["truncate"].is_null() {
                    file.set_len(number(&args, "truncate", 0)?)?;
                }
                let at = number(&args, "offset", 0)?;
                let append = args["append"].as_bool().unwrap_or(append);
                let flags = fs::fcntl_getfl(&file)?;
                fs::fcntl_setfl(
                    &file,
                    if append {
                        flags | OFlags::APPEND
                    } else {
                        flags & !OFlags::APPEND
                    },
                )?;
                let written = if append {
                    (&file).write(&bytes)?
                } else {
                    file.write_at(&bytes, at)?
                };
                file.sync_data()?;
                Ok(json!({"written": written, "offset": at, "size": file.metadata()?.len()}))
            }
            _ => Err(bad("EOPNOTSUPP")),
        }
    }
}

pub fn run() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let option = |name: &str| {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let root = option("--root").ok_or("usage: os-local-helper --root DIRECTORY --origin https://your-os.example [--port 0] [--write] [--execute]")?;
    let origin = option("--origin").ok_or("--origin is required")?;
    if !(origin.starts_with("https://")
        || origin.starts_with("http://127.0.0.1:")
        || origin.starts_with("http://localhost:"))
        || origin.ends_with('/')
        || origin.contains(['\r', '\n', '\0', '?', '#', '@'])
    {
        return Err("--origin must be one exact HTTPS origin or local development origin".into());
    }
    let root = std::fs::canonicalize(Path::new(root))?;
    let root_file = File::open(&root)?;
    if !root_file.metadata()?.is_dir() {
        return Err("--root must be a directory".into());
    }
    // Refuse older kernels; never replace containment with a lexical fallback.
    open(
        &root_file,
        "",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    let server = Server::http(("127.0.0.1", option("--port").unwrap_or("0").parse::<u16>()?))?;
    let mut adapter = Adapter {
        root: root_file,
        writable: args.iter().any(|a| a == "--write"),
        executable: args.iter().any(|a| a == "--execute"),
        master: secret()?,
        sessions: HashMap::new(),
    };
    println!(
        "{}",
        json!({"url": format!("http://{}", server.server_addr()), "token": adapter.master, "root": root, "write": adapter.writable, "execute": adapter.executable})
    );
    std::io::stdout().flush()?;
    loop {
        adapter.sweep();
        let Some(mut request) = server.recv_timeout(Duration::from_secs(1))? else {
            continue;
        };
        let header = |name: &'static str| {
            request
                .headers()
                .iter()
                .find(|h| h.field.equiv(name))
                .map(|h| h.value.as_str().to_owned())
        };
        let allowed = header("Origin").as_deref() == Some(origin)
            && request
                .remote_addr()
                .is_some_and(|addr| addr.ip().is_loopback())
            && request.url() == "/";
        let authorization = header("Authorization").unwrap_or_default();
        let content_type = header("Content-Type");
        let response = if !allowed {
            Response::from_string("origin denied").with_status_code(403)
        } else if request.method() == &Method::Options {
            Response::from_string("").with_status_code(204)
        } else {
            let result = (|| -> Result<Value> {
                if request.method() != &Method::Post
                    || content_type.as_deref() != Some("application/json")
                {
                    return Err(bad("EINVAL"));
                }
                let token = authorization
                    .strip_prefix("Bearer ")
                    .ok_or_else(|| bad("EACCES"))?;
                let mut bytes = Vec::new();
                request
                    .as_reader()
                    .take((CHUNK * 2 + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > CHUNK * 2 {
                    return Err(bad("E2BIG"));
                }
                let args = serde_json::from_slice(&bytes).map_err(|_| bad("EINVAL"))?;
                adapter.handle(token, args)
            })();
            match result {
                Ok(value) => Response::from_string(json!({"ok": value}).to_string()),
                Err(error) => Response::from_string(
                    json!({"err": {"errno": error.0, "detail": error.1}}).to_string(),
                )
                .with_status_code(400),
            }
        };
        let response = response
            .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
            .with_header(
                Header::from_bytes(
                    "Access-Control-Allow-Origin",
                    if allowed { origin } else { "null" },
                )
                .unwrap(),
            )
            .with_header(
                Header::from_bytes("Access-Control-Allow-Methods", "POST, OPTIONS").unwrap(),
            )
            .with_header(
                Header::from_bytes(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization",
                )
                .unwrap(),
            )
            .with_header(
                Header::from_bytes("Access-Control-Allow-Private-Network", "true").unwrap(),
            )
            .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
            .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap());
        let _ = request.respond(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Fixture, Adapter, String) {
        let path = std::env::temp_dir().join(format!("os-local-helper-{}", secret().unwrap()));
        std::fs::create_dir_all(path.join("root")).unwrap();
        std::fs::create_dir(path.join("outside")).unwrap();
        std::fs::write(path.join("root/file"), b"original").unwrap();
        std::fs::write(path.join("outside/secret"), b"outside").unwrap();
        let mut adapter = Adapter {
            root: File::open(path.join("root")).unwrap(),
            writable: true,
            executable: true,
            master: "master".into(),
            sessions: HashMap::new(),
        };
        let token = adapter
            .handle(
                "master",
                json!({"op":"mount", "write":true, "execute":true}),
            )
            .unwrap()["proof"]
            .as_str()
            .unwrap()
            .to_owned();
        (Fixture(path), adapter, token)
    }
    #[test]
    fn kernel_contains_symlinks_parent_traversal_and_rebound_directories() {
        let (fixture, mut adapter, token) = fixture();
        symlink("../outside", fixture.0.join("root/link")).unwrap();
        for path in ["../outside/secret", "/etc/passwd", "link/secret"] {
            assert!(
                adapter
                    .handle(&token, json!({"op":"read","path":path,"count":10}))
                    .is_err()
            );
        }
        std::fs::create_dir(fixture.0.join("root/nested")).unwrap();
        std::fs::rename(fixture.0.join("root/nested"), fixture.0.join("root/moved")).unwrap();
        symlink("../outside", fixture.0.join("root/nested")).unwrap();
        assert_eq!(
            adapter
                .handle(
                    &token,
                    json!({"op":"read","path":"nested/secret","count":10})
                )
                .unwrap_err()
                .0,
            "ELOOP"
        );
        assert!(
            adapter
                .handle(
                    &token,
                    json!({"op":"write","path":"nested/secret","data":STANDARD.encode(b"bad")})
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.0.join("outside/secret")).unwrap(),
            b"outside"
        );
    }
    #[test]
    fn descriptors_retain_inodes_and_exclusive_creation_is_atomic() {
        let (fixture, mut adapter, token) = fixture();
        let handle = adapter
            .handle(&token, json!({"op":"open","path":"file","flags":2}))
            .unwrap();
        std::fs::rename(fixture.0.join("root/file"), fixture.0.join("root/old")).unwrap();
        std::fs::write(fixture.0.join("root/file"), b"replacement").unwrap();
        let read = adapter
            .handle(&token, json!({"op":"read","handle":handle,"count":100}))
            .unwrap();
        assert_eq!(
            STANDARD.decode(read.as_str().unwrap()).unwrap(),
            b"original"
        );
        adapter.handle(&token, json!({"op":"write","handle":handle,"data":STANDARD.encode(b"changed!"),"offset":0})).unwrap();
        assert_eq!(
            std::fs::read(fixture.0.join("root/file")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            std::fs::read(fixture.0.join("root/old")).unwrap(),
            b"changed!"
        );
        assert_eq!(
            adapter
                .handle(&token, json!({"op":"open","path":"file","flags":0o301}))
                .unwrap_err()
                .0,
            "EEXIST"
        );
    }
    #[test]
    fn proofs_expiry_and_read_only_delegation_are_enforced_by_adapter() {
        let (_fixture, mut adapter, token) = fixture();
        assert_eq!(
            adapter
                .handle("forged", json!({"op":"read","path":"file"}))
                .unwrap_err()
                .0,
            "EACCES"
        );
        let ro = adapter.handle("master", json!({"op":"mount"})).unwrap()["proof"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            adapter
                .handle(
                    &ro,
                    json!({"op":"open","path":"file","flags":2,"write":true})
                )
                .unwrap_err()
                .0,
            "EROFS"
        );
        assert_eq!(
            adapter
                .handle(&ro, json!({"op":"pin","path":"file","execute":true}))
                .unwrap_err()
                .0,
            "EACCES"
        );
        adapter.sessions.get_mut(&token).unwrap().touched =
            Instant::now() - Duration::from_secs(61);
        assert_eq!(
            adapter.handle(&token, json!({"op":"keep"})).unwrap_err().0,
            "EACCES"
        );
        adapter.handle(&ro, json!({"op":"unmount"})).unwrap();
        assert_eq!(
            adapter.handle(&ro, json!({"op":"keep"})).unwrap_err().0,
            "EACCES"
        );
    }
}
