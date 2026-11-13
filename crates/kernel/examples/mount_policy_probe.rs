//! Line-oriented adapter used by the Node provider tests. Uses the production
//! Rust permission bridge without requiring prebuilt browser assets.
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        match line {
            Ok(input) => println!("{}", os_kernel::mount_policy::json_request(&input)),
            Err(_) => break,
        }
    }
}
