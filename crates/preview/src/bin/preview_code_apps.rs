//! The worker that highlights [`Group::Apps`](os_preview::language::Group)'s languages.

fn main() {
    os_preview::worker::serve_code(os_preview::code::apps());
}
