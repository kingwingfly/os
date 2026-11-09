//! The job container's HTTP server, for the JobRunner Durable Object, which
//! sends it one job's files and takes back what it makes, a request at a time:
//!
//! - `PUT /archive`: the archive to read; `POST /list[?unpack=1]`: its members, and their
//!   content unpacked to disk; `GET /entry?index=&offset=&length=`: part of one member.
//! - `PUT /input?index=`: a file to archive; `POST /build`: build the archive, returning its
//!   size and the SHA-256 of each chunk; `GET /output?offset=&length=`: part of it.
//! - `POST /faststart`: input 0, an MP4, made faststart as the output, sized and hashed as an
//!   archive is; or `already`, if its index already comes first.
//! - `GET /status`, and `DELETE /job` to forget everything.
//!
//! Every request names its job (`?job=`); a request for another job starts again from nothing.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use os_core::archive::Format;
use os_jobs::faststart::{Outcome, faststart};
use os_jobs::{Input, VERSION, build, chunk_hashes, list};
use serde::Deserialize;
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

type Reply = Response<Box<dyn Read + Send>>;

fn json_reply(status: u16, value: Value) -> Reply {
    let body = value.to_string().into_bytes();
    let length = body.len();
    Response::new(
        StatusCode(status),
        vec![Header::from_bytes("Content-Type", "application/json").unwrap()],
        Box::new(io::Cursor::new(body)),
        Some(length),
        None,
    )
}
fn error(status: u16, message: impl std::fmt::Display) -> Reply {
    json_reply(status, json!({"error": message.to_string()}))
}

struct Jobs {
    root: PathBuf,
    job: Option<String>,
}
impl Jobs {
    fn dir(&self) -> PathBuf {
        self.root.join("job")
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir().join(name)
    }
    /// Make `job` the one this container holds, forgetting another's files.
    fn select(&mut self, job: &str) -> io::Result<()> {
        if self.job.as_deref() != Some(job) {
            let _ = fs::remove_dir_all(self.dir());
            fs::create_dir_all(self.dir().join("in"))?;
            self.job = Some(job.to_string());
        }
        Ok(())
    }
    fn handle(&mut self, request: &mut Request) -> Reply {
        let url = request.url().to_string();
        let (path, query) = url.split_once('?').unwrap_or((&url, ""));
        let param = |name: &str| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        };
        let number = |name: &str| param(name).and_then(|v| v.parse::<u64>().ok());
        let method = request.method().clone();
        if (method.clone(), path) == (Method::Get, "/status") {
            let inputs: Vec<String> = fs::read_dir(self.path("in"))
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            return json_reply(
                200,
                json!({
                    "job": self.job, "version": VERSION, "archive": self.path("archive").exists(),
                    "listed": self.path("unpacked").exists(), "inputs": inputs,
                    "output": fs::metadata(self.path("output")).ok().map(|m| m.len()),
                }),
            );
        }
        let Some(job) =
            param("job").filter(|j| !j.is_empty() && j.bytes().all(|b| b.is_ascii_alphanumeric()))
        else {
            return error(400, "name the job with ?job=");
        };
        if let Err(e) = self.select(&job) {
            return error(500, e);
        }
        match (method, path) {
            (Method::Put, "/archive") => {
                let _ = fs::remove_dir_all(self.path("unpacked"));
                receive(request, &self.path("archive"))
            }
            (Method::Post, "/list") => {
                let unpack = param("unpack").is_some_and(|v| v == "1");
                // Unpacked aside, and named `unpacked` only once whole, as status says it is.
                let target = self.path("unpacked");
                let staging = self.path("unpacking");
                let _ = fs::remove_dir_all(&target);
                let _ = fs::remove_dir_all(&staging);
                match list(&self.path("archive"), unpack.then_some(staging.as_path())) {
                    Ok((format, members)) => {
                        if unpack && let Err(e) = fs::rename(&staging, &target) {
                            return error(500, e);
                        }
                        json_reply(200, json!({"format": format, "members": members}))
                    }
                    Err(e) => {
                        let _ = fs::remove_dir_all(&staging);
                        error(422, e)
                    }
                }
            }
            (Method::Get, "/entry") => match number("index") {
                Some(index) => send(
                    &self.path(&format!("unpacked/{index}")),
                    number("offset").unwrap_or(0),
                    number("length"),
                ),
                None => error(400, "name the member with ?index="),
            },
            (Method::Put, "/input") => match number("index") {
                Some(index) => receive(request, &self.path(&format!("in/{index}"))),
                None => error(400, "name the input with ?index="),
            },
            (Method::Post, "/build") => {
                #[derive(Deserialize)]
                struct Build {
                    format: Format,
                    mtime: u64,
                    chunk_size: u64,
                    inputs: Vec<Input>,
                }
                let mut body = String::new();
                if let Err(e) = request.as_reader().read_to_string(&mut body) {
                    return error(400, e);
                }
                let build_request: Build = match serde_json::from_str(&body) {
                    Ok(b) => b,
                    Err(e) => return error(400, e),
                };
                let output = self.path("output");
                let built = build(
                    build_request.format,
                    build_request.mtime,
                    &build_request.inputs,
                    &self.path("in"),
                    &output,
                )
                .and_then(|size| {
                    Ok((
                        size,
                        chunk_hashes(&output, build_request.chunk_size.max(1))?,
                    ))
                });
                match built {
                    Ok((size, chunks)) => json_reply(
                        200,
                        json!({"size": size, "chunks": chunks, "version": VERSION}),
                    ),
                    Err(e) => error(422, e),
                }
            }
            (Method::Post, "/faststart") => {
                #[derive(Deserialize)]
                struct Faststart {
                    chunk_size: u64,
                }
                let mut body = String::new();
                if let Err(e) = request.as_reader().read_to_string(&mut body) {
                    return error(400, e);
                }
                let wanted: Faststart = match serde_json::from_str(&body) {
                    Ok(w) => w,
                    Err(e) => return error(400, e),
                };
                // Made aside, and named the output only once whole, as status says it is.
                let output = self.path("output");
                let making = self.path("output.partial");
                let _ = fs::remove_file(&output);
                match faststart(&self.path("in/0"), &making) {
                    Ok(Outcome::Already) => {
                        json_reply(200, json!({"already": true, "version": VERSION}))
                    }
                    Ok(Outcome::Moved(moov)) => {
                        let made = fs::rename(&making, &output).map_err(|e| e.to_string());
                        match made.and_then(|()| chunk_hashes(&output, wanted.chunk_size.max(1))) {
                            Ok(chunks) => json_reply(
                                200,
                                json!({
                                    "size": fs::metadata(&output).map(|m| m.len()).unwrap_or(0),
                                    "chunks": chunks, "moov": moov, "version": VERSION,
                                }),
                            ),
                            Err(e) => error(500, e),
                        }
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&making);
                        error(422, e)
                    }
                }
            }
            (Method::Get, "/output") => send(
                &self.path("output"),
                number("offset").unwrap_or(0),
                number("length"),
            ),
            (Method::Delete, "/job") => {
                let _ = fs::remove_dir_all(self.dir());
                self.job = None;
                json_reply(200, json!({"cleared": true}))
            }
            _ => error(404, "unknown endpoint"),
        }
    }
}

/// Write the request's body to `path`, which appears only once all of it has arrived: a body
/// cut short reads as ended, and status would take what it left for the whole file.
fn receive(request: &mut Request, path: &Path) -> Reply {
    let expected = request.body_length().map(|n| n as u64);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let partial = path.with_file_name(format!(".{name}.partial"));
    let written =
        File::create(&partial).and_then(|mut file| io::copy(request.as_reader(), &mut file));
    let reply = match written {
        Ok(size) if expected.is_some_and(|expected| expected != size) => error(
            400,
            format!("received {size} of {} bytes", expected.unwrap_or_default()),
        ),
        Ok(size) => match fs::rename(&partial, path) {
            Ok(()) => return json_reply(200, json!({"size": size})),
            Err(e) => error(500, e),
        },
        Err(e) => error(500, e),
    };
    let _ = fs::remove_file(&partial);
    reply
}
/// `length` bytes of the file at `path` from `offset`, or the rest of it.
fn send(path: &Path, offset: u64, length: Option<u64>) -> Reply {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return error(404, "no such content; send or build it first"),
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if offset > size {
        return error(416, "offset beyond the end");
    }
    let length = length.unwrap_or(size - offset).min(size - offset);
    if let Err(e) = file.seek(SeekFrom::Start(offset)) {
        return error(500, e);
    }
    Response::new(
        StatusCode(200),
        vec![Header::from_bytes("Content-Type", "application/octet-stream").unwrap()],
        Box::new(file.take(length)),
        Some(length as usize),
        None,
    )
}

fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let root = PathBuf::from(std::env::var("JOBS_DATA").unwrap_or_else(|_| "/tmp/jobs".into()));
    let server = Server::http(format!("0.0.0.0:{port}")).expect("listen");
    let mut jobs = Jobs { root, job: None };
    eprintln!("jobs {VERSION} listening on {port}");
    // One job at a time, a request at a time: the runner sends them in order.
    for mut request in server.incoming_requests() {
        let reply = jobs.handle(&mut request);
        let _ = request.respond(reply);
    }
}
