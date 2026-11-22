//! Shared permission-error classifier for worker API replies.
//! Local OS account mutations (`useradd`/`usermod`/`userdel`/`groupadd`/`groupmod`/`groupdel`)
//! were retired in Wave 4B (`#57` L3d; Contract v2 §2.12) and now live 100% locally on `os-cowfs`.

pub fn is_permission_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("current account is not in the wheel group")
        || message.contains("sudo requires reauthentication")
        || message.contains("permission denied")
        || message.contains("only root")
        || message.contains("only the owner")
        || message.contains("root permission required")
        || message.contains("cannot traverse")
        || message.contains("operation not permitted")
}
