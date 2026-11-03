//! Cloudflare Realtime (owner's choice, 2026-10-28), which carries live sound: a speaker's page
//! sends its microphone to the Realtime SFU over WebRTC, as the track `voice` of a session of
//! its own; a listener's page gets a session of its own that pulls it. Pages never see the
//! app's secret: the drivers (snd.rs, present.rs) speak to Realtime for them, once the kernel
//! has decided that they may.
//!
//! The app is the site's: REALTIME_APP_ID and the secret REALTIME_APP_TOKEN. Without them, a
//! recording is only recorded.
use serde_json::{Value, json};
use worker::*;

/// Realtime's API.
const REALTIME: &str = "https://rtc.live.cloudflare.com/v1";
/// The track a speaker sends.
pub const TRACK: &str = "voice";
/// The longest description of a session (SDP) taken, in bytes.
pub const SDP_MAX: usize = 64 * 1024;
/// A listener's Realtime session, as `listen` made it: the deadline (kind) by which its page
/// answers it, once, and the seconds it has to.
pub const LISTENER: &str = "listener";
pub const ANSWER_TTL: u64 = 60;
/// How a listener's deadline names it: the session that listened and its Realtime session,
/// which that session alone answers.
pub fn listener(sid: &str, session: &str) -> String {
    format!("{sid} {session}")
}

/// The site's Realtime app: its id and secret.
pub fn app(env: &Env) -> std::result::Result<(String, String), String> {
    let text = |name: &str| {
        env.var(name)
            .map(|v| v.to_string())
            .or_else(|_| env.secret(name).map(|v| v.to_string()))
            .ok()
            .filter(|value| !value.is_empty())
    };
    match (text("REALTIME_APP_ID"), text("REALTIME_APP_TOKEN")) {
        (Some(id), Some(token)) => Ok((id, token)),
        _ => Err("Live sound needs the site's Cloudflare Realtime app (REALTIME_APP_ID and REALTIME_APP_TOKEN); this one has none".into()),
    }
}

/// Ask Realtime, at `path` of the app, with `body`; its answer, or why not.
pub async fn realtime(
    env: &Env,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> std::result::Result<Value, String> {
    let (id, token) = app(env)?;
    let failed = |e: Error| format!("Realtime could not be reached: {e}");
    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(failed)?;
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(body) = body {
        headers
            .set("Content-Type", "application/json")
            .map_err(failed)?;
        init.with_body(Some(body.to_string().into()));
    }
    init.with_headers(headers);
    let url = format!("{REALTIME}/apps/{id}/{path}");
    let request = Request::new_with_init(&url, &init).map_err(failed)?;
    let mut response = Fetch::Request(request).send().await.map_err(failed)?;
    let value: Value = response.json().await.unwrap_or_default();
    // A track refused is said in its entry, the request's other errors at the top.
    let refused = value["tracks"]
        .as_array()
        .and_then(|tracks| tracks.iter().find(|track| track["errorCode"].is_string()))
        .unwrap_or(&value);
    if response.status_code() >= 400 || refused["errorCode"].is_string() {
        let why = refused["errorDescription"]
            .as_str()
            .or(refused["errorCode"].as_str())
            .map_or_else(
                || format!("status {}", response.status_code()),
                str::to_string,
            );
        return Err(format!("Realtime refused: {why}"));
    }
    Ok(value)
}

/// A new Realtime session's id.
pub async fn session(env: &Env) -> std::result::Result<String, String> {
    let made = realtime(env, Method::Post, "sessions/new", None).await?;
    made["sessionId"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "Realtime made no session".into())
}

/// Send the track a page offers (`sdp`, its transceiver `mid`) as a new session's `voice`: the
/// session, and Realtime's answer.
pub async fn publish(
    env: &Env,
    sdp: &str,
    mid: &str,
) -> std::result::Result<(String, String), String> {
    let session = session(env).await?;
    let tracks = json!({
        "sessionDescription": { "type": "offer", "sdp": sdp },
        "tracks": [{ "location": "local", "mid": mid, "trackName": TRACK }],
    });
    let answered = realtime(
        env,
        Method::Post,
        &format!("sessions/{session}/tracks/new"),
        Some(tracks),
    )
    .await?;
    let sdp = answered["sessionDescription"]["sdp"]
        .as_str()
        .ok_or("Realtime gave no answer")?
        .to_string();
    Ok((session, sdp))
}

/// A new session that pulls the track `track` of the speaker's session `speaker`: the session,
/// and Realtime's offer, which the listener answers (`answer`).
pub async fn pull(
    env: &Env,
    speaker: &str,
    track: &str,
) -> std::result::Result<(String, String), String> {
    let session = session(env).await?;
    let tracks = json!({
        "tracks": [{ "location": "remote", "sessionId": speaker, "trackName": track }],
    });
    let offered = realtime(
        env,
        Method::Post,
        &format!("sessions/{session}/tracks/new"),
        Some(tracks),
    )
    .await?;
    let sdp = offered["sessionDescription"]["sdp"]
        .as_str()
        .ok_or("Realtime offered nothing")?
        .to_string();
    Ok((session, sdp))
}

/// A listener's answer to what Realtime offered for `session`.
pub async fn answer(env: &Env, session: &str, sdp: &str) -> std::result::Result<(), String> {
    realtime(
        env,
        Method::Put,
        &format!("sessions/{session}/renegotiate"),
        Some(json!({ "sessionDescription": { "type": "answer", "sdp": sdp } })),
    )
    .await
    .map(|_| ())
}
