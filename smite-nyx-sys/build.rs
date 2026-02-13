use std::{path::Path, process::Command};

// Get the afl coverage map size of the given binary
fn get_map_size(binary: &Path) -> Option<String> {
    let output = String::from_utf8_lossy(
        &Command::new(binary)
            .env("AFL_DUMP_MAP_SIZE", "1")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {}", binary.display()))
            .stdout,
    )
    .trim()
    .to_string();

    (!output.is_empty()).then_some(output)
}

fn main() {
    let mut build = cc::Build::new();
    build.file("src/nyx-agent.c").define("NO_PT_NYX", None);

    // TARGET_MAP_SIZE can be set directly (e.g., for CLN LTO where the total
    // map size spans multiple binaries), or computed from TARGET_PATH by
    // querying a single binary via AFL_DUMP_MAP_SIZE.
    let map_size = std::env::var("TARGET_MAP_SIZE").ok().or_else(|| {
        std::env::var("TARGET_PATH")
            .ok()
            .and_then(|path| get_map_size(Path::new(&path)))
    });

    if let Some(ref size) = map_size {
        build.define("TARGET_MAP_SIZE", size.as_str());
    }

    build.compile("nyx_agent");

    println!("cargo:rerun-if-changed=src/nyx-agent.c");
    println!("cargo:rerun-if-env-changed=TARGET_MAP_SIZE");
    println!("cargo:rerun-if-env-changed=TARGET_PATH");
}
