//! DOM rendering and keyboard encoding for the client kernel's terminal device.
use leptos::prelude::*;
use terminal_worker_core::ansi::screen::Screen;

pub fn view(screen: RwSignal<Screen>, live: RwSignal<bool>) -> impl IntoView {
    view! {
        <pre class="output-line terminal-screen" data-live=move || live.get().to_string() data-alternate=move || (live.get() && screen.with(Screen::alternate)).to_string()>
            {move || screen.with(|screen| screen.runs(live.get()).into_iter().map(|run| {
                let style = run.style.css();
                match run.link {
                    Some(link) => view! { <a href=link target="_blank" rel="noopener noreferrer" style=style>{run.text}</a> }.into_any(),
                    None => view! { <span style=style>{run.text}</span> }.into_any(),
                }
            }).collect_view())}
            <span class="terminal-cursor" aria-hidden="true" hidden=move || !live.get() || !screen.with(|s| s.cursor)
                style=move || screen.with(|screen| {
                    let (row, col) = screen.cursor_position();
                    format!("left:{col}ch;top:{}em", row as f64 * 1.7)
                })></span>
        </pre>
    }
}

pub fn key(event: &web_sys::KeyboardEvent, application: bool) -> Option<String> {
    if event.meta_key() || event.is_composing() {
        return None;
    }
    let key = event.key();
    if event.ctrl_key() && (event.shift_key() || key.eq_ignore_ascii_case("v")) {
        return None;
    }
    if event.ctrl_key() && !event.alt_key() && key.len() == 1 {
        let byte = key.as_bytes()[0].to_ascii_uppercase();
        if (b'@'..=b'_').contains(&byte) {
            return Some(char::from(byte & 31).to_string());
        }
        if byte == b'?' {
            return Some("\x7f".into());
        }
    }
    let prefix = if application { "\x1bO" } else { "\x1b[" };
    let encoded = match key.as_str() {
        "Enter" => "\r".into(),
        "Backspace" => "\x7f".into(),
        "Tab" if event.shift_key() => "\x1b[Z".into(),
        "Tab" => "\t".into(),
        "Escape" => "\x1b".into(),
        "ArrowUp" => format!("{prefix}A"),
        "ArrowDown" => format!("{prefix}B"),
        "ArrowRight" => format!("{prefix}C"),
        "ArrowLeft" => format!("{prefix}D"),
        "Home" => format!("{prefix}H"),
        "End" => format!("{prefix}F"),
        "Insert" => "\x1b[2~".into(),
        "Delete" => "\x1b[3~".into(),
        "PageUp" => "\x1b[5~".into(),
        "PageDown" => "\x1b[6~".into(),
        "F1" => "\x1bOP".into(),
        "F2" => "\x1bOQ".into(),
        "F3" => "\x1bOR".into(),
        "F4" => "\x1bOS".into(),
        _ => return None,
    };
    Some(encoded)
}
