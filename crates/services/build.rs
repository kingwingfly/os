fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("wasi") {
        println!("cargo:rustc-link-arg-bin=supervise=--export=__os_service_signal");
        println!("cargo:rustc-link-arg-bin=init=--export=__os_init_signal");
    }
}
