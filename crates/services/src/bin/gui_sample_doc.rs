#[unsafe(no_mangle)]
pub extern "C" fn gui_client_tick() -> i32 {
    os_services::gui_client::client_tick::<false>()
}
fn main() {
    os_services::gui_client::sample::<false>();
}
