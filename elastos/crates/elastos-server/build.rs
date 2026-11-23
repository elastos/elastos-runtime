use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=ELASTOS_RELEASE_RELAY_URL");
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    let pin_file =
        std::path::Path::new(&manifest_dir).join("../../../carrier-relay-spki-sha256.txt");
    println!("cargo:rerun-if-changed={}", pin_file.display());
    let pins = std::fs::read_to_string(pin_file).expect("repository meeting point pins");
    let pins: Vec<_> = pins
        .lines()
        .map(|line| line.split('#').next().unwrap().trim())
        .filter(|line| !line.is_empty())
        .collect();
    assert!(
        pins.len() <= 2
            && pins
                .iter()
                .all(|pin| pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit())),
        "meeting point accepts one primary and at most one backup SPKI SHA-256 pin"
    );
    if let Ok(raw) = env::var("ELASTOS_RELEASE_RELAY_URL") {
        let relay = url::Url::parse(&raw).expect("invalid release meeting point origin");
        assert!(
            !raw.chars().any(char::is_whitespace)
                && relay.scheme() == "https"
                && relay.host().is_some()
                && relay.username().is_empty()
                && relay.password().is_none()
                && relay.path() == "/"
                && relay.query().is_none()
                && relay.fragment().is_none(),
            "release meeting point must be an HTTPS origin"
        );
        assert!(
            !pins.is_empty(),
            "release meeting point requires a repository SPKI pin"
        );
        println!("cargo:rustc-env=ELASTOS_RELEASE_RELAY_URL={raw}");
        println!(
            "cargo:rustc-env=ELASTOS_RELEASE_RELAY_SPKI_SHA256={}",
            pins.join(",")
        );
    }
    println!("cargo:rerun-if-env-changed=ELASTOS_RELEASE_VERSION");

    let version = env::var("ELASTOS_RELEASE_VERSION").unwrap_or_else(|_| {
        let pkg = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
        format!("{pkg}-dev")
    });

    println!("cargo:rustc-env=ELASTOS_VERSION={version}");
}
