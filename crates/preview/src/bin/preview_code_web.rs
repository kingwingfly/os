//! The worker that highlights [`Group::Web`](os_preview::language::Group)'s languages.

fn main() {
    os_preview::worker::serve_code(os_preview::code::web());
}
