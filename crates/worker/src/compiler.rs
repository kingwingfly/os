//! Content-addressed compilation outside the filesystem authority. Every request reaches
//! this internal binding only after files.rs has authorized access to the original image.
use std::cell::Cell;
use std::time::Duration;
use worker::*;

pub const VERSION: &str = "fork-v4";
const CACHE_LIFETIME: i64 = 7 * 24 * 60 * 60 * 1000;

pub fn prefix(content: &str) -> String {
    format!("compiled/{}/", crate::auth::token_hash(content))
}

#[durable_object]
pub struct ModuleCompiler {
    state: State,
    env: Env,
    busy: Cell<bool>,
}

impl DurableObject for ModuleCompiler {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            busy: Cell::new(false),
        }
    }
    async fn fetch(&self, req: Request) -> Result<Response> {
        let key = req.path().trim_start_matches('/').to_string();
        let bucket = self.env.bucket("FILES")?;
        // One object id per content/version: concurrent requests wait for that same output.
        for _ in 0..140 {
            if let Some(object) = bucket.get(&key).execute().await? {
                let headers = Headers::new();
                headers.set("Content-Type", "application/wasm")?;
                return Ok(Response::from_body(
                    object
                        .body()
                        .ok_or_else(|| Error::RustError("missing compiler output".into()))?
                        .response_body()?,
                )?
                .with_headers(headers));
            }
            if !self.busy.get() {
                break;
            }
            Delay::from(Duration::from_millis(500)).await;
        }
        if self.busy.replace(true) {
            return Response::error("Compiler busy", 503);
        }
        let result = self.compile(req, &key).await;
        self.busy.set(false);
        result
    }
    async fn alarm(&self) -> Result<Response> {
        if let Some(container) = self.state.container() {
            container.destroy(None).await?;
        }
        // This also bounds orphan outputs if the original file was deleted while compiling.
        if let Some(key) = self.state.storage().get::<String>("cached").await? {
            self.env.bucket("FILES")?.delete(&key).await?;
            self.state.storage().delete("cached").await?;
        }
        Response::ok("")
    }
}

impl ModuleCompiler {
    async fn compile(&self, req: Request, key: &str) -> Result<Response> {
        let container = self
            .state
            .container()
            .ok_or_else(|| Error::RustError("Compiler container unavailable".into()))?;
        // An alarm also bounds a stalled compiler. No executable or account token enters it.
        self.state.storage().set_alarm(120_000).await?;
        if !container.running() {
            let mut options = ContainerStartupOptions::new();
            options.enable_internet(false);
            container.start(Some(options))?;
        }
        let fetcher = container.get_tcp_port(8080)?;
        let mut ready = false;
        for _ in 0..100 {
            if let Ok(response) = fetcher.fetch("http://compiler/status", None).await
                && response.status_code() == 200
            {
                ready = true;
                break;
            }
            Delay::from(Duration::from_millis(500)).await;
        }
        if !ready {
            return Response::error("Compiler did not start", 503);
        }
        let mut init = RequestInit::new();
        let Some(stream) = req.inner().body() else {
            return Response::error("Missing image", 400);
        };
        init.with_method(Method::Post)
            .with_body(Some(stream.into()));
        let compiled = fetcher
            .fetch_request(Request::new_with_init("http://compiler/compile", &init)?)
            .await?;
        if compiled.status_code() != 200 {
            return Ok(compiled);
        }
        let length = compiled
            .headers()
            .get("Content-Length")?
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|length| (8..=abi::EXEC_MAX).contains(length));
        let Some(length) = length else {
            return Response::error("Invalid compiler output length", 502);
        };
        let ResponseBody::Stream(stream) = compiled.body() else {
            return Response::error("Missing output", 502);
        };
        // R2 requires a stream with a known length. Keep bytes in native streams, as the
        // archive runner does, and reject a truncated or oversized compiler response.
        let output = Data::ReadableStream(crate::streams::fixed_length(stream, length as f64));
        self.env.bucket("FILES")?.put(key, output).execute().await?;
        container.destroy(None).await?;
        self.state.storage().put("cached", key).await?;
        self.state.storage().set_alarm(CACHE_LIFETIME).await?;
        let object = self
            .env
            .bucket("FILES")?
            .get(key)
            .execute()
            .await?
            .ok_or_else(|| Error::RustError("Missing compiler output".into()))?;
        let headers = Headers::new();
        headers.set("Content-Type", "application/wasm")?;
        Ok(Response::from_body(
            object
                .body()
                .ok_or_else(|| Error::RustError("Missing compiler output".into()))?
                .response_body()?,
        )?
        .with_headers(headers))
    }
}

pub async fn image(env: &Env, content: &str, body: Response) -> Result<Response> {
    let key = format!("{}{VERSION}", prefix(content));
    let ResponseBody::Stream(stream) = body.body() else {
        return Response::error("Missing image", 400);
    };
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(stream.clone().into()));
    env.durable_object("COMPILER")?
        .id_from_name(&key)?
        .get_stub()?
        .fetch_with_request(Request::new_with_init(
            &format!("https://compiler/{key}"),
            &init,
        )?)
        .await
}
