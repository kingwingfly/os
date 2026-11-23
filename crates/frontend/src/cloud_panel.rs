//! Zero-friction Local OS Identity + explicit Cloud / Cluster Sign-In top-bar panel (`#57` `L3d`,
//! Contract v2 §1, §2.1, §2.4).
//!
//! Strictly separates:
//! - **Local OS Identity** (`/etc/passwd` on the instance's local `os-cowfs` root volume — never
//!   mutated by cloud authentication, zero OS-level `issuer`, zero `(issuer, subject)` UID mapping).
//! - **Cloud / Cluster Service Credentials** (explicit userspace `ServiceAuth v2` grants activating
//!   optional `/mnt/cloud` and remote device attachments `devattach@{archive,media,present,snd}`).

use abi::auth_v2::RemoteScope;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;

/// Read-only summary of the instance's local OS account and mounted `os-cowfs` root volume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentityInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    #[serde(default)]
    pub root_volume_uuid: Option<String>,
    #[serde(default)]
    pub forked_from: Option<String>,
    #[serde(default)]
    pub ephemeral_if_unmodified: bool,
}

impl Default for LocalIdentityInfo {
    fn default() -> Self {
        Self {
            username: "user".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/user".into(),
            root_volume_uuid: None,
            forked_from: None,
            ephemeral_if_unmodified: false,
        }
    }
}

impl LocalIdentityInfo {
    pub fn is_fork(&self) -> bool {
        self.forked_from.is_some()
    }
}

/// Explicit userspace `ServiceAuth v2` cloud credential state (100% decoupled from `/etc/passwd`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudAuthState {
    pub signed_in: bool,
    #[serde(default)]
    pub cloud_user: Option<String>,
    #[serde(default)]
    pub scope: RemoteScope,
    #[serde(default)]
    pub cloud_mount_active: bool,
    #[serde(default)]
    pub busy: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub notice: Option<String>,
}

/// Explicit credentials and requested `ServiceAuth v2` scope submitted by the Cloud Sign-In form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudSignInRequest {
    pub username: String,
    pub password: String,
    pub scope: RemoteScope,
}

/// Format the compact top-bar pill text: `Local: <user> · Cloud: Signed out` or `<cloud-user>`.
pub fn format_pill_label(local_user: &str, cloud_user: Option<&str>) -> String {
    let local = if local_user.is_empty() {
        "user"
    } else {
        local_user
    };
    match cloud_user.filter(|u| !u.is_empty()) {
        Some(cloud) => format!("Local: {local} · Cloud: {cloud}"),
        None => format!("Local: {local} · Cloud: Signed out"),
    }
}

/// Format a compact 8-character prefix for displaying a local `os-cowfs` volume UUID.
pub fn short_volume_id(uuid: &str) -> &str {
    uuid.get(..8).unwrap_or(uuid)
}

/// Build a `RemoteScope` from the popover's individual capability checkboxes.
pub fn build_requested_scope(
    cloud_fs: bool,
    dev_archive: bool,
    dev_media: bool,
    dev_present: bool,
    dev_snd: bool,
    containers: bool,
    relay: bool,
) -> RemoteScope {
    let mut devices = Vec::new();
    if dev_archive {
        devices.push("archive".into());
    }
    if dev_media {
        devices.push("media".into());
    }
    if dev_present {
        devices.push("present".into());
    }
    if dev_snd {
        devices.push("snd".into());
    }
    RemoteScope {
        cloud_fs,
        devices,
        containers,
        relay,
        ..RemoteScope::default()
    }
}

/// Top-bar Local Identity & Cloud / Cluster Sign-In popover component.
///
/// Ready for direct wiring in `crates/frontend/src/lib.rs` (Wave 4B) via reactive signals and
/// explicit callbacks (`on_sign_in`, `on_sign_out`, optional `on_switch_local_user` and
/// `on_open_boot_profile`).
#[component]
pub fn CloudSignInPanel(
    local: Signal<LocalIdentityInfo>,
    cloud: Signal<CloudAuthState>,
    on_sign_in: Callback<CloudSignInRequest>,
    on_sign_out: Callback<()>,
    #[prop(optional)] on_switch_local_user: Option<Callback<()>>,
    #[prop(optional)] on_open_boot_profile: Option<Callback<()>>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());

    // Explicit opt-in ServiceAuth v2 scope toggles.
    let scope_cloud_fs = RwSignal::new(true);
    let scope_archive = RwSignal::new(true);
    let scope_media = RwSignal::new(true);
    let scope_present = RwSignal::new(true);
    let scope_snd = RwSignal::new(true);
    let scope_containers = RwSignal::new(true);
    let scope_relay = RwSignal::new(false);

    let pill_label = move || {
        let local_info = local.get();
        let cloud_info = cloud.get();
        let cloud_name = cloud_info
            .signed_in
            .then_some(cloud_info.cloud_user)
            .flatten();
        format_pill_label(&local_info.username, cloud_name.as_deref())
    };

    let submit_sign_in = move || {
        if cloud.with_untracked(|c| c.busy) {
            return;
        }
        let user = username.get_untracked().trim().to_owned();
        let secret = password.get_untracked();
        if user.is_empty() || secret.is_empty() {
            return;
        }
        password.set(String::new());
        let scope = build_requested_scope(
            scope_cloud_fs.get_untracked(),
            scope_archive.get_untracked(),
            scope_media.get_untracked(),
            scope_present.get_untracked(),
            scope_snd.get_untracked(),
            scope_containers.get_untracked(),
            scope_relay.get_untracked(),
        );
        on_sign_in.run(CloudSignInRequest {
            username: user,
            password: secret,
            scope,
        });
    };

    view! {
        <div
            class="cloud-panel"
            on:keydown=move |event: web_sys::KeyboardEvent| {
                if event.key() == "Escape" {
                    open.set(false);
                }
            }
            on:focusout=move |event: web_sys::FocusEvent| {
                let inside = event
                    .current_target()
                    .and_then(|node| node.dyn_into::<web_sys::Node>().ok())
                    .zip(
                        event
                            .related_target()
                            .and_then(|node| node.dyn_into::<web_sys::Node>().ok()),
                    )
                    .is_some_and(|(panel, target)| panel.contains(Some(&target)));
                if !inside {
                    open.set(false);
                }
            }
        >
            <button
                type="button"
                class="lock cloud-panel-trigger"
                class:cloud-connected=move || cloud.get().signed_in
                aria-haspopup="dialog"
                aria-expanded=move || open.get().to_string()
                on:click=move |_| open.update(|v| *v = !*v)
            >
                <span class="cloud-indicator" aria-hidden="true">
                    {move || if cloud.get().signed_in { "●" } else { "○" }}
                </span>
                <span class="cloud-pill-text">{pill_label}</span>
            </button>

            <Show when=move || open.get()>
                <section
                    class="cloud-panel-popover"
                    role="dialog"
                    aria-label="Local identity and Cloud sign-in"
                >
                    <div class="cloud-panel-section cloud-panel-local">
                        <header class="cloud-panel-heading">
                            <strong>"Local OS Identity"</strong>
                            <Show when=move || local.get().is_fork()>
                                <span
                                    class="cloud-badge cloud-badge-fork"
                                    title=move || {
                                        let info = local.get();
                                        let base = info.forked_from.unwrap_or_default();
                                        if info.ephemeral_if_unmodified {
                                            format!("O(1) fork of {base} (pruned on clean shutdown if unmodified)")
                                        } else {
                                            format!("Modified O(1) fork of {base} (retained)")
                                        }
                                    }
                                >
                                    "O(1) Fork"
                                </span>
                            </Show>
                        </header>
                        <dl class="cloud-meta-list">
                            <div>
                                <dt>"Account"</dt>
                                <dd>{move || {
                                    let info = local.get();
                                    format!("{} (uid={}, gid={})", info.username, info.uid, info.gid)
                                }}</dd>
                            </div>
                            <div>
                                <dt>"Home"</dt>
                                <dd>{move || local.get().home}</dd>
                            </div>
                            <Show when=move || local.get().root_volume_uuid.is_some()>
                                <div>
                                    <dt>"Root volume"</dt>
                                    <dd title=move || local.get().root_volume_uuid.unwrap_or_default()>
                                        {move || {
                                            local
                                                .get()
                                                .root_volume_uuid
                                                .as_deref()
                                                .map(|id| short_volume_id(id).to_owned())
                                                .unwrap_or_default()
                                        }}
                                    </dd>
                                </div>
                            </Show>
                        </dl>
                        <p class="cloud-panel-note">
                            "Local accounts live in /etc/passwd on this instance's root volume. Cloud sign-in never changes your local UID or /etc/passwd."
                        </p>
                        <div class="cloud-panel-actions">
                            {on_switch_local_user.map(|cb| {
                                view! {
                                    <button
                                        type="button"
                                        class="cloud-btn-secondary"
                                        on:click=move |_| {
                                            open.set(false);
                                            cb.run(());
                                        }
                                    >
                                        "Switch local user"
                                    </button>
                                }
                            })}
                            {on_open_boot_profile.map(|cb| {
                                view! {
                                    <button
                                        type="button"
                                        class="cloud-btn-secondary"
                                        on:click=move |_| {
                                            open.set(false);
                                            cb.run(());
                                        }
                                    >
                                        "Volumes & boot profile"
                                    </button>
                                }
                            })}
                        </div>
                    </div>

                    <div class="cloud-panel-section cloud-panel-remote">
                        <header class="cloud-panel-heading">
                            <strong>"Cloud / Cluster Credentials"</strong>
                            <span class="cloud-badge">
                                {move || if cloud.get().signed_in { "ServiceAuth v2" } else { "Offline / Signed out" }}
                            </span>
                        </header>

                        <Show
                            when=move || cloud.get().signed_in
                            fallback=move || {
                                view! {
                                    <form
                                        class="cloud-signin-form"
                                        on:submit=move |event| {
                                            event.prevent_default();
                                            submit_sign_in();
                                        }
                                    >
                                        <label for="cloud-auth-user">"Cloud username"</label>
                                        <input
                                            id="cloud-auth-user"
                                            name="cloud_username"
                                            autocomplete="username"
                                            required
                                            maxlength="64"
                                            disabled=move || cloud.get().busy
                                            prop:value=move || username.get()
                                            on:input=move |e| username.set(event_target_value(&e))
                                        />
                                        <label for="cloud-auth-pass">"Cloud password"</label>
                                        <input
                                            id="cloud-auth-pass"
                                            name="cloud_password"
                                            type="password"
                                            autocomplete="current-password"
                                            required
                                            disabled=move || cloud.get().busy
                                            prop:value=move || password.get()
                                            on:input=move |e| password.set(event_target_value(&e))
                                        />
                                        <fieldset class="cloud-scope-toggles" disabled=move || cloud.get().busy>
                                            <legend>"Requested scopes"</legend>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_cloud_fs.get()
                                                    on:change=move |e| scope_cloud_fs.set(event_target_checked(&e))
                                                />
                                                "Cloud filesystem (/mnt/cloud)"
                                            </label>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_archive.get()
                                                    on:change=move |e| scope_archive.set(event_target_checked(&e))
                                                />
                                                "Device: /dev/archive"
                                            </label>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_media.get()
                                                    on:change=move |e| scope_media.set(event_target_checked(&e))
                                                />
                                                "Device: /dev/media"
                                            </label>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_present.get()
                                                    on:change=move |e| scope_present.set(event_target_checked(&e))
                                                />
                                                "Device: /dev/present"
                                            </label>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_snd.get()
                                                    on:change=move |e| scope_snd.set(event_target_checked(&e))
                                                />
                                                "Device: /dev/snd"
                                            </label>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_containers.get()
                                                    on:change=move |e| scope_containers.set(event_target_checked(&e))
                                                />
                                                "Remote containers"
                                            </label>
                                            <label>
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || scope_relay.get()
                                                    on:change=move |e| scope_relay.set(event_target_checked(&e))
                                                />
                                                "Shared-mount relay"
                                            </label>
                                        </fieldset>
                                        <button
                                            type="submit"
                                            class="primary cloud-btn-signin"
                                            disabled=move || cloud.get().busy
                                        >
                                            {move || if cloud.get().busy { "Signing in…" } else { "Sign in to Cloud" }}
                                        </button>
                                    </form>
                                }
                            }
                        >
                            <div class="cloud-connected-summary">
                                <p>
                                    "Signed in as "
                                    <strong>{move || cloud.get().cloud_user.unwrap_or_else(|| "cloud".into())}</strong>
                                </p>
                                <p class="cloud-scope-summary">
                                    {move || {
                                        let state = cloud.get();
                                        let mut parts = Vec::new();
                                        if state.scope.cloud_fs {
                                            parts.push(if state.cloud_mount_active {
                                                "/mnt/cloud (mounted)".to_owned()
                                            } else {
                                                "cloud_fs".to_owned()
                                            });
                                        }
                                        if !state.scope.devices.is_empty() {
                                            parts.push(format!("devices: {}", state.scope.devices.join(", ")));
                                        }
                                        if state.scope.containers {
                                            parts.push("containers".to_owned());
                                        }
                                        if state.scope.relay {
                                            parts.push("relay".to_owned());
                                        }
                                        if parts.is_empty() {
                                            "No active remote scopes".to_owned()
                                        } else {
                                            parts.join(" · ")
                                        }
                                    }}
                                </p>
                                <p class="cloud-panel-note">
                                    "Signing out unmounts /mnt/cloud and revokes ServiceAuth v2 tokens without stopping local processes."
                                </p>
                                <button
                                    type="button"
                                    class="cloud-btn-signout"
                                    disabled=move || cloud.get().busy
                                    on:click=move |_| on_sign_out.run(())
                                >
                                    {move || if cloud.get().busy { "Signing out…" } else { "Sign out of Cloud" }}
                                </button>
                            </div>
                        </Show>

                        <Show when=move || cloud.get().error.as_deref().is_some_and(|e| !e.is_empty())>
                            <p class="cloud-panel-error" role="alert">
                                {move || cloud.get().error.unwrap_or_default()}
                            </p>
                        </Show>
                        <Show when=move || cloud.get().notice.as_deref().is_some_and(|n| !n.is_empty())>
                            <p class="cloud-panel-status" role="status">
                                {move || cloud.get().notice.unwrap_or_default()}
                            </p>
                        </Show>
                    </div>
                </section>
            </Show>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pill_label_keeps_local_and_cloud_identity_distinct() {
        assert_eq!(
            format_pill_label("user", None),
            "Local: user · Cloud: Signed out"
        );
        assert_eq!(
            format_pill_label("user", Some("")),
            "Local: user · Cloud: Signed out"
        );
        assert_eq!(
            format_pill_label("user", Some("alice@cloud")),
            "Local: user · Cloud: alice@cloud"
        );
        assert_eq!(short_volume_id("12345678-9abc-def0"), "12345678");
    }

    #[test]
    fn requested_scope_builder_maps_checkboxes_faithfully() {
        let scope = build_requested_scope(true, true, false, true, false, true, false);
        assert!(scope.cloud_fs);
        assert_eq!(scope.devices, vec!["archive", "present"]);
        assert!(scope.containers);
        assert!(!scope.relay);

        let empty = build_requested_scope(false, false, false, false, false, false, false);
        assert!(empty.is_empty());
    }
}
