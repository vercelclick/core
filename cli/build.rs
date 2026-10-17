use std::process::Command;

fn main() {
    // Only bundle for release builds
    if cfg!(debug_assertions) {
        return;
    }

    let status = Command::new("make")
        .arg("bundle")
        .current_dir("../")
        .status()
        .expect("UI Bundle failed");

    if !status.success() {
        panic!("UI Bundle failed");
    }
}
