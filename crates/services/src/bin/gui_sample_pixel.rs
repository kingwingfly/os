#[unsafe(no_mangle)]
pub extern "C" fn gui_client_tick() -> i32 {
    os_services::gui_client::client_tick::<true>()
}
fn main() {
    os_services::gui_client::sample::<true>();
}
