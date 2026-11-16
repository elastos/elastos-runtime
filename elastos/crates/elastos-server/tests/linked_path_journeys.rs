//! The unit gate needs only the path helper. Cargo runs the native journeys here,
//! after compiling the candidate library and after the ordinary unit suite.

fn cargo_journeys() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "test",
            "--manifest-path",
            "Cargo.toml",
            "-p",
            "elastos-server",
            "--lib",
            "linked_start_journey_",
            "--",
            "--ignored",
            "--test-threads=1",
        ])
        .env_remove("CARGO_MAKEFLAGS");
    command
}

#[test]
fn linked_path_native_journeys_use_cargo_builds() {
    let listed = cargo_journeys().arg("--list").output().unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let names = String::from_utf8(listed.stdout).unwrap();
    assert_eq!(
        names
            .lines()
            .filter(|line| line.ends_with(": test"))
            .count(),
        7,
        "{names}"
    );
    let status = cargo_journeys().arg("--nocapture").status().unwrap();
    assert!(
        status.success(),
        "Cargo-built native startup journeys failed"
    );
}
