use std::env;

fn main() {
    for key in [
        "ELASTOS_RELEASE_RELAY_URL",
        "ELASTOS_RELEASE_RELAY_CERT_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
        if let Ok(value) = env::var(key) {
            assert!(
                !value.contains(['\n', '\r']),
                "invalid release meeting point"
            );
            println!("cargo:rustc-env={key}={value}");
        }
    }
    assert_eq!(
        env::var_os("ELASTOS_RELEASE_RELAY_URL").is_some(),
        env::var_os("ELASTOS_RELEASE_RELAY_CERT_SHA256").is_some(),
        "release meeting point needs address and identity"
    );
    if let Ok(raw) = env::var("ELASTOS_RELEASE_RELAY_URL") {
        let relay = url::Url::parse(&raw).expect("invalid release meeting point origin");
        assert!(
            relay.scheme() == "https"
                && relay.host().is_some()
                && relay.username().is_empty()
                && relay.password().is_none()
                && relay.path() == "/"
                && relay.query().is_none()
                && relay.fragment().is_none(),
            "release meeting point must be an HTTPS origin"
        );
        let pin =
            env::var("ELASTOS_RELEASE_RELAY_CERT_SHA256").expect("release meeting point identity");
        assert!(
            pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid release meeting point certificate identity"
        );
    }
    println!("cargo:rerun-if-env-changed=ELASTOS_RELEASE_VERSION");

    let version = env::var("ELASTOS_RELEASE_VERSION").unwrap_or_else(|_| {
        let pkg = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
        format!("{pkg}-dev")
    });

    println!("cargo:rustc-env=ELASTOS_VERSION={version}");
}
