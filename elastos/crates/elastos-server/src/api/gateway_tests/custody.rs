use super::*;
use crate::custody_node_card::tests::labelled_card;
use crate::custody_surface::{
    STEP_UP_KNOWN_POOL_ADD as KNOWN_POOL_ADD_OPERATION,
    STEP_UP_LOCAL_NODE_INCLUDE as INCLUDE_OPERATION, STEP_UP_LOCAL_NODE_REMOVE as REMOVE_OPERATION,
    STEP_UP_MESSAGES_ENABLE as MESSAGES_ENABLE_OPERATION,
    STEP_UP_NODE_REQUEST_APPROVE as APPROVE_REQUEST_OPERATION,
    STEP_UP_POOL_INSTALL as INSTALL_OPERATION,
};
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::protected_content_config::{CUSTODY_THRESHOLD_REQUIRED, CUSTODY_THRESHOLD_TOTAL};

const STORAGE: &[&str] = &["chain", "custody", "ipfs"];
const CUSTODY_ONLY: &[&str] = &["chain", "custody"];

/// Every Custody route with a body its handler accepts, so a refusal is about
/// who calls, never about what they sent.
fn custody_routes() -> Vec<(&'static str, &'static str, Option<Value>)> {
    vec![
        ("GET", "/api/apps/custody/summary", None),
        ("POST", "/api/apps/custody/signing-key", None),
        (
            "POST",
            "/api/apps/custody/node-cards/read",
            Some(json!({ "card": "hello" })),
        ),
        (
            "POST",
            "/api/apps/custody/node-cards/fetch",
            Some(json!({ "address": "hello" })),
        ),
        (
            "POST",
            "/api/apps/custody/local-node",
            Some(json!({ "run_by": "Alice", "location": "Lisbon", "step_up_token": "" })),
        ),
        (
            "DELETE",
            "/api/apps/custody/local-node",
            Some(json!({ "step_up_token": "" })),
        ),
        (
            "POST",
            "/api/apps/custody/pool/check",
            Some(json!({ "slots": [] })),
        ),
        (
            "POST",
            "/api/apps/custody/pool",
            Some(json!({ "slots": [], "term_days": 365, "step_up_token": "" })),
        ),
        ("POST", "/api/apps/custody/pool/verify", None),
        ("POST", "/api/apps/custody/pool/notify", Some(json!({}))),
        ("GET", "/api/apps/custody/pool", None),
        ("GET", "/api/apps/custody/pool/health", None),
        ("POST", "/api/apps/custody/pool/members/1/register", None),
        ("GET", "/api/apps/custody/offer", None),
        (
            "POST",
            "/api/apps/custody/offer",
            Some(json!({ "enabled": false, "run_by": "Alice", "location": "Lisbon" })),
        ),
        (
            "POST",
            "/api/apps/custody/messages/enable",
            Some(json!({ "step_up_token": "" })),
        ),
        ("POST", "/api/apps/custody/nodes/find", Some(json!({}))),
        (
            "POST",
            "/api/apps/custody/node-requests",
            Some(json!({ "profile_did": "did:key:z6MkNode", "term_days": 365 })),
        ),
        ("GET", "/api/apps/custody/pools/known", None),
        (
            "POST",
            "/api/apps/custody/pools/known",
            Some(json!({ "address": "elastos-pool:x", "step_up_token": "" })),
        ),
    ]
}

struct CustodyFixture {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    app: Router,
    admin: TestPasskeyAuthority,
    token: String,
}

/// An admin with a Custody launch token, on a Home with protected content on.
fn custody_fixture() -> CustodyFixture {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    owner_only_dir(&data_dir);
    std::fs::write(data_dir.join("config.toml"), "protected_content = true\n").unwrap();
    // #388 A1: the Custody app's Hosting runs on a WCI-operated host.
    crate::host_trust::seed_for_test(&data_dir, true);
    let admin = passkey_authority_with_profile(&data_dir, "Owner");
    let token = app_token_for_authority(&data_dir, "custody", &admin);
    CustodyFixture {
        app: gateway_router(test_state(&data_dir)),
        _dir: dir,
        data_dir,
        admin,
        token,
    }
}

async fn custody_call(
    app: &Router,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = test_browser_request("localhost:61180", "null")
        .method(method)
        .uri(uri)
        .header("x-elastos-home-token", token);
    let request = match body {
        Some(body) => request
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

fn three_remote_slots() -> Value {
    json!([
        { "card": labelled_card("Alice", "Lisbon", STORAGE) },
        { "card": labelled_card("Bob", "Oslo", STORAGE) },
        { "card": labelled_card("Carol", "Kyiv", CUSTODY_ONLY) },
    ])
}

fn pool_path(data_dir: &std::path::Path) -> PathBuf {
    crate::protected_content_runtime::runtime_custody_composition_config_path(data_dir)
}

#[tokio::test]
async fn custody_routes_refuse_guest_and_other_apps() {
    let fixture = custody_fixture();
    let guest = passkey_authority_with_profile_role_credential(
        &fixture.data_dir,
        "Guest",
        crate::auth::RuntimePrincipalRole::Guest,
        "custody-guest",
    );
    let guest_token = app_token_for_authority(&fixture.data_dir, "custody", &guest);
    for token in [&guest_token, &fixture.admin.people_token] {
        for (method, uri, body) in custody_routes() {
            let (status, answer) = custody_call(&fixture.app, token, method, uri, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {answer}");
        }
    }
    let key_path = crate::custody_pool_setup::policy_authority_key_path(&fixture.data_dir);
    assert!(!key_path.exists());
}

#[tokio::test]
async fn custody_summary_reports_threshold_from_runtime_constants() {
    let fixture = custody_fixture();
    let (status, summary) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/summary",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(
        summary["threshold"],
        json!({ "required": CUSTODY_THRESHOLD_REQUIRED, "total": CUSTODY_THRESHOLD_TOTAL })
    );
    assert_eq!(summary["term_presets_days"], json!([182, 365, 730]));
    assert_eq!(summary["signing_key"]["present"], false);
    assert_eq!(summary["local_node"]["provisioned"], false);
    assert_eq!(summary["local_node"]["running"], false);
    assert_eq!(summary["local_node"].get("address"), Some(&Value::Null));
    assert_eq!(summary["pool_installed"], false);
    assert_eq!(summary["pool"], Value::Null);
    // Plan B T2.3: `serving` is a list.
    assert_eq!(summary["serving"], json!([]));
    // The signed-in admin's own Profile name.
    assert_eq!(summary["local_profile_name"], "Owner");
    assert_eq!(summary["node_requests"], json!([]));
    assert_eq!(summary.get("pool_notices"), Some(&Value::Null));

    let (status, card) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/node-cards/read",
        Some(json!({ "card": labelled_card("Alice", "Lisbon", STORAGE) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{card}");
    assert_eq!(card["run_by"], "Alice");
    assert_eq!(card["local"], false);
    let (status, card) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/node-cards/read",
        Some(json!({ "card": "hello" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{card}");
    assert_eq!(card, json!({ "refused": "not_a_card" }));

    for slots in [
        json!([{ "card": "hello", "this_home": true }]),
        json!([{ "this_home": false }]),
        json!([{}]),
    ] {
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/pool/check",
            Some(json!({ "slots": slots })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{slots}: {answer}");
        assert_eq!(answer, json!({ "code": "bad_slot", "detail": null }));
    }
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool/check",
        Some(json!({ "slots": [], "extra": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer, json!({ "code": "bad_request", "detail": null }));
}

#[tokio::test]
async fn custody_fetch_maps_bad_address() {
    let fixture = custody_fixture();
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/node-cards/fetch",
        Some(json!({ "address": "not a ticket" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer, json!({ "code": "bad_address", "detail": null }));

    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/node-cards/fetch",
        Some(json!({ "address": "x", "card": "y" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer, json!({ "code": "bad_request", "detail": null }));
}

#[tokio::test]
async fn custody_install_requires_step_up() {
    let fixture = custody_fixture();
    let (status, _) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let slots = three_remote_slots();
    let request = json!({ "slots": slots, "term_days": 365 });

    let mut missing = request.clone();
    missing["step_up_token"] = json!("");
    let wrong_operation = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INCLUDE_OPERATION,
        &request,
    );
    let other_request = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &json!({ "slots": slots, "term_days": 730 }),
    );
    for token in [wrong_operation, other_request] {
        let mut body = request.clone();
        body["step_up_token"] = json!(token);
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/pool",
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool",
        Some(missing),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert!(!pool_path(&fixture.data_dir).exists());

    // A term outside the offered three is refused before any step-up is spent.
    let mut body = json!({ "slots": slots, "term_days": 100 });
    body["step_up_token"] = json!("unused");
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer, json!({ "code": "bad_term", "detail": null }));
    assert!(!pool_path(&fixture.data_dir).exists());
}

#[tokio::test]
async fn custody_include_requires_step_up() {
    let fixture = custody_fixture();
    let request = json!({ "run_by": "Owner", "location": "Lisbon" });
    let wrong_operation = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let other_labels = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INCLUDE_OPERATION,
        &json!({ "run_by": "Owner", "location": "Oslo" }),
    );
    for token in [String::new(), wrong_operation, other_labels] {
        let mut body = request.clone();
        body["step_up_token"] = json!(token);
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/local-node",
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    let local_node = crate::protected_content_runtime::protected_content_root(&fixture.data_dir)
        .join("custody-local-node.descriptor.json");
    assert!(!local_node.exists());

    // With a fresh step-up the service runs: this Home has no custody provider
    // binary, so it refuses with the code and the Runtime's reason apart.
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INCLUDE_OPERATION,
        &request,
    );
    let mut body = request.clone();
    body["step_up_token"] = json!(token);
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/local-node",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "provision_failed");
    assert!(answer["detail"]
        .as_str()
        .is_some_and(|detail| !detail.is_empty()));
    assert!(!local_node.exists());
}

#[tokio::test]
async fn custody_remove_local_node_needs_step_up_and_keeps_an_installed_pools_node() {
    let fixture = custody_fixture();
    crate::custody_pool_setup::tests::write_local_node(&fixture.data_dir, "Owner", "Lisbon");
    let local_node = crate::protected_content_runtime::protected_content_root(&fixture.data_dir)
        .join("custody-local-node.descriptor.json");
    let remove = |token: String| {
        custody_call(
            &fixture.app,
            &fixture.token,
            "DELETE",
            "/api/apps/custody/local-node",
            Some(json!({ "step_up_token": token })),
        )
    };
    let wrong_operation = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INCLUDE_OPERATION,
        &json!({}),
    );
    for token in [String::new(), wrong_operation] {
        let (status, answer) = remove(token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    assert!(local_node.exists());

    // Once a pool is installed the node stays, and the passkey approval is
    // not spent on the refusal.
    let pool = crate::protected_content_runtime::runtime_custody_composition_config_path(
        &fixture.data_dir,
    );
    std::fs::write(&pool, b"{}").unwrap();
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        REMOVE_OPERATION,
        &json!({}),
    );
    let (status, answer) = remove(token.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "pool_installed");
    assert!(local_node.exists());
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        0
    );

    std::fs::remove_file(&pool).unwrap();
    let (status, answer) = remove(token).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["provisioned"], false);
    assert!(!local_node.exists());
    assert!(!crate::custody_pool_setup::holds_custody_state(&fixture.data_dir).unwrap());
}

/// A Remove Runtime refuses leaves the passkey approval unspent: with no
/// node to remove, and on a Home that serves another owner.
#[tokio::test]
async fn custody_remove_local_node_refusals_spend_no_passkey_approval() {
    let fixture = custody_fixture();
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        REMOVE_OPERATION,
        &json!({}),
    );
    let remove = || {
        custody_call(
            &fixture.app,
            &fixture.token,
            "DELETE",
            "/api/apps/custody/local-node",
            Some(json!({ "step_up_token": token })),
        )
    };
    // A tombstone a stopped removal left holds no node, and the refusal
    // deletes it.
    let protected = crate::protected_content_runtime::protected_content_root(&fixture.data_dir);
    let tombstone =
        crate::protected_content_runtime::inactive_custody_state_root(&fixture.data_dir)
            .with_file_name("inactive.removing");
    for dir in [
        &protected,
        &tombstone.parent().unwrap().to_path_buf(),
        &tombstone,
    ] {
        crate::protected_content_config::ensure_owner_only_dir(dir, "test dir").unwrap();
    }
    let (status, answer) = remove().await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "no_local_node");
    assert!(!tombstone.exists());

    // Plan B T2.2 (removal approved 2026-11-12 10:35): a served node is not
    // this Home's own; with no own node there is nothing to remove.
    crate::collaboration_config::create_owner_only_file(
        &crate::protected_content_config::custody_node_descriptor_path(&fixture.data_dir),
        b"{}",
        "test served node",
    )
    .unwrap();
    let (status, answer) = remove().await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "no_local_node");
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        0
    );
}

#[tokio::test]
async fn custody_routes_hidden_when_protected_content_off() {
    let fixture = custody_fixture();
    std::fs::write(
        fixture.data_dir.join("config.toml"),
        "protected_content = false\n",
    )
    .unwrap();
    for (method, uri, body) in custody_routes() {
        let (status, answer) = custody_call(&fixture.app, &fixture.token, method, uri, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {answer}");
        assert_eq!(answer["code"], "protected_content_off", "{method} {uri}");
    }
    let key_path = crate::custody_pool_setup::policy_authority_key_path(&fixture.data_dir);
    assert!(!key_path.exists());
}

async fn install_pool(fixture: &CustodyFixture, slots: &Value) -> (StatusCode, Value) {
    let request = json!({ "slots": slots, "term_days": 365 });
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let mut body = request;
    body["step_up_token"] = json!(token);
    custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool",
        Some(body),
    )
    .await
}

#[tokio::test]
async fn custody_install_refuses_second_pool() {
    let fixture = custody_fixture();
    let (status, created) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert!(created["fingerprint"].as_str().is_some());
    assert!(created["fingerprint_full"]
        .as_str()
        .is_some_and(|full| full.starts_with("sha256:") && full.len() == 71));
    let (status, again) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(again, json!({ "code": "key_exists", "detail": null }));

    let (status, installed) = install_pool(&fixture, &three_remote_slots()).await;
    assert_eq!(status, StatusCode::OK, "{installed}");
    assert_eq!(installed["verified"], true);
    let pool = std::fs::read(pool_path(&fixture.data_dir)).unwrap();

    let (status, answer) = install_pool(&fixture, &three_remote_slots()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer,
        json!({ "code": "already_installed", "detail": null })
    );
    assert_eq!(std::fs::read(pool_path(&fixture.data_dir)).unwrap(), pool);
}

/// A refusal the server knows without the passkey leaves the step-up unspent:
/// the same token installs once the cause is gone.
#[tokio::test]
async fn custody_install_refuses_known_refusals_before_spending_step_up() {
    let fixture = custody_fixture();
    let request = json!({ "slots": three_remote_slots(), "term_days": 365 });
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let mut body = request;
    body["step_up_token"] = json!(token);
    let install = || {
        custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/pool",
            Some(body.clone()),
        )
    };

    let (status, answer) = install().await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer, json!({ "code": "no_signing_key", "detail": null }));

    let (status, _) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, installed) = install().await;
    assert_eq!(status, StatusCode::OK, "{installed}");

    // A second pool, as a second window would ask for it.
    let request = json!({ "slots": three_remote_slots(), "term_days": 730 });
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let mut body = request;
    body["step_up_token"] = json!(token);
    let install = || {
        custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/pool",
            Some(body.clone()),
        )
    };
    let pool = std::fs::read(pool_path(&fixture.data_dir)).unwrap();
    let (status, answer) = install().await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer,
        json!({ "code": "already_installed", "detail": null })
    );
    assert_eq!(std::fs::read(pool_path(&fixture.data_dir)).unwrap(), pool);

    std::fs::remove_file(pool_path(&fixture.data_dir)).unwrap();
    let (status, installed) = install().await;
    assert_eq!(status, StatusCode::OK, "{installed}");
}

/// A node that approved a request consented to its term: Install with that
/// node's card and another term is refused before the passkey is spent.
#[tokio::test]
async fn custody_install_keeps_the_term_a_node_consented_to() {
    let fixture = custody_fixture();
    let (status, _) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let consented = labelled_card("Alice", "Lisbon", STORAGE);
    crate::custody_owner_requests::tests::plant_approved(&fixture.data_dir, &consented, 182);
    let slots = json!([
        { "card": consented },
        { "card": labelled_card("Bob", "Oslo", STORAGE) },
        { "card": labelled_card("Carol", "Kyiv", CUSTODY_ONLY) },
    ]);

    let request = json!({ "slots": slots, "term_days": 365 });
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let mut body = request;
    body["step_up_token"] = json!(token);
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer, json!({ "code": "term_changed", "detail": null }));
    assert!(!pool_path(&fixture.data_dir).exists());

    let request = json!({ "slots": slots, "term_days": 182 });
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let mut body = request;
    body["step_up_token"] = json!(token);
    let (status, installed) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{installed}");
}

/// Install records whom this Home tells about the pool; Notify members
/// again answers through the custody message plane.
#[tokio::test]
async fn custody_install_records_pool_notices_and_notify_needs_a_pool() {
    let fixture = custody_fixture();
    let notify = || {
        custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/pool/notify",
            Some(json!({})),
        )
    };
    let (status, answer) = notify().await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer, json!({ "code": "no_pool", "detail": null }));
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool/notify",
        Some(json!({ "extra": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");

    let (status, _) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, installed) = install_pool(&fixture, &three_remote_slots()).await;
    assert_eq!(status, StatusCode::OK, "{installed}");
    let (status, summary) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/summary",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    // Without the message plane this Home has no contacts to tell.
    assert_eq!(
        summary["pool_notices"],
        json!({
            "fingerprint_full": installed["fingerprint_full"],
            "members": [
                { "share": 1, "state": "skipped", "code": "not_contact" },
                { "share": 2, "state": "skipped", "code": "not_contact" },
                { "share": 3, "state": "skipped", "code": "not_contact" },
            ],
        })
    );
    let (status, answer) = notify().await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "messages_unavailable");
}

#[tokio::test]
async fn custody_pool_health_reports_no_pool_then_each_member() {
    let fixture = custody_fixture();
    let health = || {
        custody_call(
            &fixture.app,
            &fixture.token,
            "GET",
            "/api/apps/custody/pool/health",
            None,
        )
    };
    let (status, answer) = health().await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer, json!({ "code": "no_pool", "detail": null }));

    custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    let (status, installed) = install_pool(&fixture, &three_remote_slots()).await;
    assert_eq!(status, StatusCode::OK, "{installed}");

    // The cards' tickets reach no node, so every member is not answering.
    let (status, answer) = health().await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "down");
    assert_eq!(answer["online"], 0);
    assert_eq!(answer["required"], CUSTODY_THRESHOLD_REQUIRED);
    assert_eq!(answer["total"], CUSTODY_THRESHOLD_TOTAL);
    assert!(answer["checked_at"].as_u64().is_some_and(|at| at > 0));
    let members = answer["members"].as_array().unwrap();
    assert_eq!(members.len(), usize::from(CUSTODY_THRESHOLD_TOTAL));
    for (share, member) in (1..).zip(members) {
        assert_eq!(member["share"], share, "{member}");
        assert_eq!(member["state"], "not_answering", "{member}");
        assert!(member["detail"].is_string(), "{member}");
    }
}

#[tokio::test]
async fn custody_register_reports_unknown_share() {
    let fixture = custody_fixture();
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool/members/1/register",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "no_pool");

    custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    let slots = three_remote_slots();
    let (status, checked) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool/check",
        Some(json!({ "slots": slots })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{checked}");
    assert!(checked["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|check| check["result"] != "fail"));
    let (status, installed) = install_pool(&fixture, &slots).await;
    assert_eq!(status, StatusCode::OK, "{installed}");

    let (status, pool) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/pool",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pool}");
    let share = pool["members"][0]["share"].as_u64().unwrap();
    let (status, registered) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        &format!("/api/apps/custody/pool/members/{share}/register"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    assert_eq!(registered, json!({ "share": share, "registered": true }));

    for share in ["99", "first"] {
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            &format!("/api/apps/custody/pool/members/{share}/register"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{share}: {answer}");
        assert_eq!(answer, json!({ "code": "unknown_share", "detail": null }));
    }

    let (status, verified) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pool/verify",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["fingerprint"], pool["fingerprint"]);
    assert!(verified["fingerprint_full"].is_string(), "{verified}");
    assert_eq!(verified["fingerprint_full"], pool["fingerprint_full"]);
}

fn admin_profile_did(data_dir: &std::path::Path, authority: &TestPasskeyAuthority) -> String {
    crate::collaboration_profile_authority::load_profile_authority(
        data_dir,
        &authority.principal_id,
        &crate::auth::principal_localhost_root(&authority.principal_id),
    )
    .unwrap()
    .unwrap()
    .document()
    .profile_did
    .clone()
}

#[tokio::test]
async fn custody_offer_starts_from_the_profile_name_and_saves() {
    let fixture = custody_fixture();
    let (status, offer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/offer",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{offer}");
    assert_eq!(
        offer,
        json!({
            "enabled": false,
            "run_by": "Owner",
            "location": "",
            "provides": CUSTODY_ONLY,
            "holds_custody_state": false,
            "messages_enabled": false,
        })
    );

    for body in [
        json!({ "enabled": true, "run_by": "Owner", "location": "" }),
        json!({ "enabled": true, "run_by": " Owner", "location": "Lisbon" }),
    ] {
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/offer",
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert_eq!(answer, json!({ "code": "bad_labels", "detail": null }));
    }
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/offer",
        Some(json!({ "enabled": true, "run_by": "Owner", "location": "Lisbon", "extra": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");

    let (status, saved) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/offer",
        Some(json!({ "enabled": true, "run_by": "Owner", "location": "Lisbon" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["enabled"], true);
    assert_eq!(saved["location"], "Lisbon");
    let (_, offer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/offer",
        None,
    )
    .await;
    assert_eq!(offer, saved);
}

#[tokio::test]
async fn custody_messages_enable_requires_step_up() {
    let fixture = custody_fixture();
    let request = json!({});
    let wrong_operation = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INCLUDE_OPERATION,
        &request,
    );
    for token in [String::new(), wrong_operation] {
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/messages/enable",
            Some(json!({ "step_up_token": token })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        MESSAGES_ENABLE_OPERATION,
        &request,
    );
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/messages/enable",
        Some(json!({ "step_up_token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer, json!({ "messages_enabled": true }));
    let (_, offer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/offer",
        None,
    )
    .await;
    assert_eq!(offer["messages_enabled"], true);
}

/// A Home whose custody message plane runs, so an Inbox approval reaches
/// provisioning; it has no custody provider binary, so provisioning refuses.
async fn custody_inbox_fixture() -> (CustodyFixture, Router) {
    let fixture = custody_fixture();
    let (device, _) = elastos_identity::load_or_create_did(&fixture.data_dir).unwrap();
    let (trusted, _) = elastos_runtime::signature::generate_keypair();
    let mut state = test_state(&fixture.data_dir);
    state.collaboration_discovery_service = Some(
        crate::collaboration_discovery_runtime::CollaborationDiscoveryService::new(
            ed25519_dalek::SigningKey::from_bytes(&device.to_bytes()),
            super::home_system::configured_discovery_network_profile_for_test(
                &trusted,
                "custody-inbox-network",
            ),
            Arc::new(ProviderRegistry::new()),
        )
        .await
        .unwrap(),
    );
    (fixture, gateway_router(state))
}

/// Find nodes and node requests answer through the custody message plane.
#[tokio::test]
async fn custody_find_and_request_refuse_until_this_home_can_ask() {
    let fixture = custody_fixture();
    for (uri, body) in [
        ("/api/apps/custody/nodes/find", json!({})),
        (
            "/api/apps/custody/node-requests",
            json!({ "profile_did": "did:key:z6MkNode", "term_days": 365 }),
        ),
    ] {
        let (status, answer) =
            custody_call(&fixture.app, &fixture.token, "POST", uri, Some(body)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{uri}: {answer}");
        assert_eq!(answer["code"], "messages_unavailable", "{uri}");
    }

    let (fixture, app) = custody_inbox_fixture().await;
    let send = |body: Value| {
        custody_call(
            &app,
            &fixture.token,
            "POST",
            "/api/apps/custody/node-requests",
            Some(body),
        )
    };
    for body in [
        json!({ "term_days": 365 }),
        json!({ "profile_did": "x", "term_days": 365, "extra": 1 }),
    ] {
        let (status, answer) = send(body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert_eq!(answer["code"], "bad_request");
    }
    let (status, answer) = custody_call(
        &app,
        &fixture.token,
        "POST",
        "/api/apps/custody/nodes/find",
        Some(json!({ "extra": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");

    let (status, answer) =
        send(json!({ "profile_did": "did:key:z6MkNode", "term_days": 30 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "bad_term");
    let (status, answer) =
        send(json!({ "profile_did": "did:key:z6MkNode", "term_days": 365 })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "no_signing_key");
    let (status, _) = custody_call(
        &app,
        &fixture.token,
        "POST",
        "/api/apps/custody/signing-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, answer) =
        send(json!({ "profile_did": "did:key:z6MkNode", "term_days": 365 })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "not_contact");

    // The admin's own Profile has not enabled custody messages yet.
    let (status, answer) = custody_call(
        &app,
        &fixture.token,
        "POST",
        "/api/apps/custody/nodes/find",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "messages_not_enabled");
}

fn custody_entry(summary: &Value) -> Option<&Value> {
    summary["notifications"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "custody_node_request")
}

#[tokio::test]
async fn inbox_custody_request_is_admin_only_and_approved_with_its_exact_step_up() {
    let (fixture, app) = custody_inbox_fixture().await;
    let now = crate::auth::now_ts();
    let (owner_key, _) = elastos_runtime::signature::generate_keypair();
    let owner_home = crate::crypto::encode_signing_key_did(&owner_key);
    let profile_did = admin_profile_did(&fixture.data_dir, &fixture.admin);
    let request_id = hex::encode([0x11; 16]);
    let expected = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &profile_did,
        &request_id,
        &owner_home,
        now - 5,
        now + 3_600,
    );
    let approve_id = format!("custody-approve-request:{request_id}");

    // A guest of this Home sees no card and approves nothing.
    let guest = passkey_authority_with_profile_role_credential(
        &fixture.data_dir,
        "Guest",
        crate::auth::RuntimePrincipalRole::Guest,
        "custody-inbox-guest",
    );
    let guest_inbox = app_token_for_authority(&fixture.data_dir, "inbox", &guest);
    // Not even a request addressed to the guest's own Profile.
    let guest_request = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &admin_profile_did(&fixture.data_dir, &guest),
        &hex::encode([0x33; 16]),
        &owner_home,
        now - 5,
        now + 3_600,
    );
    let (status, summary) =
        custody_call(&app, &guest_inbox, "GET", "/api/apps/inbox/summary", None).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert!(custody_entry(&summary).is_none(), "{summary}");
    let guest_token = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &guest_inbox,
        APPROVE_REQUEST_OPERATION,
        &expected,
    );
    for (action_id, shown) in [
        (approve_id.clone(), &expected),
        (format!("custody-decline-request:{request_id}"), &expected),
        (
            format!("custody-approve-request:{}", hex::encode([0x33; 16])),
            &guest_request,
        ),
    ] {
        let (status, answer) = custody_call(
            &app,
            &guest_inbox,
            "POST",
            "/api/apps/inbox/actions",
            Some(json!({
                "action_id": action_id,
                "step_up_token": guest_token,
                "step_up_request": shown,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }

    // The admin's card carries exactly the request its passkey approves.
    let inbox = app_token_for_authority(&fixture.data_dir, "inbox", &fixture.admin);
    let (status, summary) =
        custody_call(&app, &inbox, "GET", "/api/apps/inbox/summary", None).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    let entry = custody_entry(&summary).expect("the admin sees the custody request");
    assert_eq!(entry["id"], format!("custody-node-request:{request_id}"));
    assert_eq!(entry["action_ref"]["action_id"], approve_id);
    assert_eq!(entry["passkey_approval"], true);
    assert_eq!(entry["step_up_request"], expected);
    assert_eq!(
        expected,
        json!({
            "request_id": request_id,
            "request_sha256": format!("sha256:{}", hex::encode([0x5e; 32])),
            "owner_name": "Olivia",
            "owner_home": owner_home,
            "term_days": 365,
            "run_by": "Nadia",
            "location": "Porto",
            "expires_at": now + 3_600,
        })
    );

    let post = |body: Value| {
        let app = app.clone();
        let inbox = inbox.clone();
        async move { custody_call(&app, &inbox, "POST", "/api/apps/inbox/actions", Some(body)).await }
    };
    // Without a passkey step there is no approval.
    let (status, answer) =
        post(json!({ "action_id": approve_id, "step_up_request": expected })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");

    // A step-up for other fields is refused as changed, and the token the
    // admin signed for the real request stays unspent.
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &inbox,
        APPROVE_REQUEST_OPERATION,
        &expected,
    );
    for (field, value) in [("term_days", json!(730)), ("run_by", json!("Mallory"))] {
        let mut shown = expected.clone();
        shown[field] = value;
        let other_token = step_up_token_for_app_context(
            &fixture.data_dir,
            "inbox",
            &inbox,
            APPROVE_REQUEST_OPERATION,
            &shown,
        );
        for step_up_token in [&token, &other_token] {
            let (status, answer) = post(json!({
                "action_id": approve_id,
                "step_up_token": step_up_token,
                "step_up_request": shown,
            }))
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{field}: {answer}");
            assert_eq!(answer["code"], "changed", "{field}");
        }
    }
    // The real request is checked before its approval is spent: this Home has
    // no Carrier address to put in a card, so it refuses and keeps the token.
    let body = json!({
        "action_id": approve_id,
        "step_up_token": token,
        "step_up_request": expected,
    });
    for _ in 0..2 {
        let (status, answer) = post(body.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert_eq!(answer["code"], "no_address");
    }
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        0,
        "no refusal spent a passkey approval"
    );
    assert!(!crate::custody_pool_setup::holds_custody_state(&fixture.data_dir).unwrap());
    let (_, summary) = custody_call(&app, &inbox, "GET", "/api/apps/inbox/summary", None).await;
    assert_eq!(
        custody_entry(&summary).unwrap()["step_up_request"],
        expected
    );
    // The count does see a spent approval.
    let enable = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        MESSAGES_ENABLE_OPERATION,
        &json!({}),
    );
    let (status, answer) = custody_call(
        &app,
        &fixture.token,
        "POST",
        "/api/apps/custody/messages/enable",
        Some(json!({ "step_up_token": enable })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        1
    );

    let (status, answer) = post(json!({ "action_id": "custody-decline-request:00" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "unknown_request");
}

/// With protected content off, Inbox approves nothing; Decline still works.
#[tokio::test]
async fn inbox_custody_approval_needs_protected_content_on() {
    let (fixture, app) = custody_inbox_fixture().await;
    let now = crate::auth::now_ts();
    let profile_did = admin_profile_did(&fixture.data_dir, &fixture.admin);
    let request_id = hex::encode([0x44; 16]);
    let expected = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &profile_did,
        &request_id,
        "did:key:z6MkOwner",
        now - 5,
        now + 3_600,
    );
    std::fs::write(
        fixture.data_dir.join("config.toml"),
        "protected_content = false\n",
    )
    .unwrap();
    let inbox = app_token_for_authority(&fixture.data_dir, "inbox", &fixture.admin);
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &inbox,
        APPROVE_REQUEST_OPERATION,
        &expected,
    );
    let (status, answer) = custody_call(
        &app,
        &inbox,
        "POST",
        "/api/apps/inbox/actions",
        Some(json!({
            "action_id": format!("custody-approve-request:{request_id}"),
            "step_up_token": token,
            "step_up_request": expected,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "protected_content_off");
    let (status, answer) = custody_call(
        &app,
        &inbox,
        "POST",
        "/api/apps/inbox/actions",
        Some(json!({ "action_id": format!("custody-decline-request:{request_id}") })),
    )
    .await;
    // Decline is not held back by the protected-content switch; this Home's
    // message plane has no Profile context here, so signing the answer is
    // what refuses it, with no custody code.
    assert_ne!(status, StatusCode::NOT_FOUND, "{answer}");
    assert!(!status.is_success(), "{answer}");
    assert!(answer.get("code").is_none(), "{status}: {answer}");
}

#[tokio::test]
async fn inbox_custody_approval_after_expiry_is_refused_before_the_step_up() {
    let (fixture, app) = custody_inbox_fixture().await;
    let now = crate::auth::now_ts();
    let profile_did = admin_profile_did(&fixture.data_dir, &fixture.admin);
    let request_id = hex::encode([0x22; 16]);
    let expected = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &profile_did,
        &request_id,
        "did:key:z6MkOwner",
        now - 120,
        now - 1,
    );
    let inbox = app_token_for_authority(&fixture.data_dir, "inbox", &fixture.admin);
    let (_, summary) = custody_call(&app, &inbox, "GET", "/api/apps/inbox/summary", None).await;
    assert!(custody_entry(&summary).is_none(), "{summary}");
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &inbox,
        APPROVE_REQUEST_OPERATION,
        &expected,
    );
    let (status, answer) = custody_call(
        &app,
        &inbox,
        "POST",
        "/api/apps/inbox/actions",
        Some(json!({
            "action_id": format!("custody-approve-request:{request_id}"),
            "step_up_token": token,
            "step_up_request": expected,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "expired");
    assert!(!crate::custody_pool_setup::holds_custody_state(&fixture.data_dir).unwrap());
}

#[tokio::test]
async fn inbox_custody_approval_left_unfinished_stays_until_approved_again() {
    let (fixture, app) = custody_inbox_fixture().await;
    let now = crate::auth::now_ts();
    let profile_did = admin_profile_did(&fixture.data_dir, &fixture.admin);
    let request_id = hex::encode([0x44; 16]);
    let expected = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &profile_did,
        &request_id,
        "did:key:z6MkOwner",
        now - 120,
        now - 1,
    );
    crate::custody_consent::tests::mark_approving(&fixture.data_dir, &request_id);
    let inbox = app_token_for_authority(&fixture.data_dir, "inbox", &fixture.admin);

    // Past its expiry, the unfinished approval is still there to finish. It
    // set nothing up yet, so it may be declined too.
    let (status, summary) =
        custody_call(&app, &inbox, "GET", "/api/apps/inbox/summary", None).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    let entry = summary["notifications"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "custody_node_resumable")
        .unwrap_or_else(|| panic!("the approving card is gone: {summary}"));
    assert_eq!(entry["id"], format!("custody-node-request:{request_id}"));
    assert_eq!(
        entry["action_ref"]["action_id"],
        format!("custody-approve-request:{request_id}")
    );
    assert_eq!(entry["passkey_approval"], true);
    assert_eq!(entry["step_up_request"], expected);
    assert_eq!(entry["title"], "Finish approving Olivia's custody request");
}

#[tokio::test]
async fn inbox_custody_approval_stopped_part_way_is_declined_not_approved() {
    let (fixture, app) = custody_inbox_fixture().await;
    let now = crate::auth::now_ts();
    let profile_did = admin_profile_did(&fixture.data_dir, &fixture.admin);
    let request_id = hex::encode([0x66; 16]);
    let expected = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &profile_did,
        &request_id,
        "did:key:z6MkOwner",
        now - 120,
        now - 1,
    );
    crate::custody_consent::tests::mark_approving(&fixture.data_dir, &request_id);
    // R3-D5 = B: the approval reserved `inactive` before it provisioned.
    crate::custody_consent::tests::reserve_for_approval(
        &fixture.data_dir,
        &request_id,
        "inactive",
        &profile_did,
    );
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(
                crate::protected_content_runtime::inactive_custody_state_root(&fixture.data_dir),
            )
            .unwrap();
    }
    let inbox = app_token_for_authority(&fixture.data_dir, "inbox", &fixture.admin);
    let (_, summary) = custody_call(&app, &inbox, "GET", "/api/apps/inbox/summary", None).await;
    let entry = summary["notifications"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "custody_node_incomplete")
        .unwrap_or_else(|| panic!("the stopped approval is not shown: {summary}"));
    assert_eq!(
        entry["action_ref"]["action_id"],
        format!("custody-decline-request:{request_id}")
    );
    assert_eq!(entry["step_up_request"], expected);
    assert_eq!(
        entry["title"],
        "Approving Olivia's custody request could not finish"
    );
    assert_eq!(
        entry.get("passkey_approval"),
        None,
        "it is declined without a passkey"
    );

    // Approving is refused before the passkey approval is spent.
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &inbox,
        APPROVE_REQUEST_OPERATION,
        &expected,
    );
    let (status, answer) = custody_call(
        &app,
        &inbox,
        "POST",
        "/api/apps/inbox/actions",
        Some(json!({
            "action_id": format!("custody-approve-request:{request_id}"),
            "step_up_token": token,
            "step_up_request": expected,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer,
        json!({
            "code": "provision_failed",
            "detail": "custody_state_incomplete",
        })
    );
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        0
    );
}

#[tokio::test]
async fn inbox_custody_approval_for_a_full_home_spends_no_passkey_approval() {
    let (fixture, app) = custody_inbox_fixture().await;
    let now = crate::auth::now_ts();
    let profile_did = admin_profile_did(&fixture.data_dir, &fixture.admin);
    let request_id = hex::encode([0x55; 16]);
    let expected = crate::custody_consent::tests::plant_request(
        &fixture.data_dir,
        &profile_did,
        &request_id,
        "did:key:z6MkOwner",
        now - 5,
        now + 3_600,
    );
    // Plan B T2.2: this Home holds eight custody roots, the most it can.
    let base = crate::protected_content_runtime::custody_provider_base(&fixture.data_dir);
    for fill in 1u8..=8 {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(base.join(format!("pools/{}", hex::encode([fill; 32]))))
            .unwrap();
    }
    let inbox = app_token_for_authority(&fixture.data_dir, "inbox", &fixture.admin);
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &inbox,
        APPROVE_REQUEST_OPERATION,
        &expected,
    );
    let (status, answer) = custody_call(
        &app,
        &inbox,
        "POST",
        "/api/apps/inbox/actions",
        Some(json!({
            "action_id": format!("custody-approve-request:{request_id}"),
            "step_up_token": token,
            "step_up_request": expected,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "too_many_pools");
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        0
    );
}

/// Plan B T4.3: Add a pool needs the admin's passkey for exactly this
/// address; a bad address is refused before any approval is spent.
#[tokio::test]
async fn known_pool_add_needs_step_up() {
    use elastos_protected_content_contracts::{PoolAddressV2, PoolMemberRouteV2};
    let fixture = custody_fixture();
    let address = crate::custody_pool_descriptor::encode_pool_address(
        &PoolAddressV2::new(
            elastos_protected_content_contracts::test_fixtures::pool_did(),
            PoolMemberRouteV2::new("did:key:z6MkPoolNode01".to_string()).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let request = json!({ "address": address });
    let wrong_operation = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        INSTALL_OPERATION,
        &request,
    );
    let other_address = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        KNOWN_POOL_ADD_OPERATION,
        &json!({ "address": format!("{address}A") }),
    );
    for token in [String::new(), wrong_operation, other_address] {
        let (status, answer) = custody_call(
            &fixture.app,
            &fixture.token,
            "POST",
            "/api/apps/custody/pools/known",
            Some(json!({ "address": address, "step_up_token": token })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        "/api/apps/custody/pools/known",
        Some(json!({ "address": "elastos-pool:not-an-address", "step_up_token": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "bad_address");
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/pools/known",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer, json!({ "pools": [] }));
}

// Plan B T2.3: Hosting lists every served pool, and Stop serving one.

/// A served pool `fill` on this Home: its root folder and its entry.
fn plant_served_pool(data_dir: &std::path::Path, fill: u8) -> (String, PathBuf) {
    use std::os::unix::fs::DirBuilderExt as _;
    let hex = hex::encode([fill; 32]);
    let root_path = format!("pools/{hex}");
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, &root_path);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)
        .unwrap();
    crate::collaboration_config::create_owner_only_file(
        &root.join("trusted-runtime-issuer"),
        format!("0x{}", hex::encode([fill; 32])).as_bytes(),
        "test issuer",
    )
    .unwrap();
    crate::custody_consent::update_served_pools(data_dir, |pools| {
        pools.entries.insert(
            format!("sha256:{hex}"),
            crate::custody_consent::ServedPoolEntryV2 {
                owner_home: format!("did:key:z6MkOwner{fill}"),
                consent: crate::custody_consent::ServedConsentV2 {
                    term_days: 365,
                    signing_key_fingerprint_full: format!("sha256:{hex}"),
                },
                root_path: root_path.clone(),
                admin_profile_did: Some("did:key:z6MkAdmin".to_string()),
                pool_did: None,
                served_pool: None,
                descriptor: None,
            },
        );
        Ok(())
    })
    .unwrap();
    (hex, root)
}

#[tokio::test]
async fn served_pools_lists_every_root() {
    let fixture = custody_fixture();
    let (first, _) = plant_served_pool(&fixture.data_dir, 0x0a);
    let (second, _) = plant_served_pool(&fixture.data_dir, 0x0b);
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        crate::custody_surface::ROUTE_POOLS_SERVED,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let items = answer.as_array().unwrap();
    assert_eq!(items.len(), 2);
    let prints: Vec<&str> = items
        .iter()
        .map(|item| item["pool_fingerprint"].as_str().unwrap())
        .collect();
    assert_eq!(prints, vec![first.as_str(), second.as_str()]);
    for item in items {
        // No People name here: the owner's DID stands in.
        assert!(item["owner_name"].as_str().unwrap().starts_with("did:key:"));
        // No provider runs in this test Runtime: the root is not loaded.
        assert_eq!(item["status"], "needs_restart");
        assert!(item["term_end"].is_null());
        assert!(item["shares_held"].is_null());
        assert!(item.get("sessions_24h").is_none());
        assert!(item.get("seals_24h").is_none());
    }
}

#[tokio::test]
async fn stop_serving_needs_step_up_and_keeps_other_pools() {
    let fixture = custody_fixture();
    let (stopped, _) = plant_served_pool(&fixture.data_dir, 0x0c);
    let (kept, kept_root) = plant_served_pool(&fixture.data_dir, 0x0d);
    let uri = |pool: &str| format!("{}/{pool}", crate::custody_surface::ROUTE_POOLS_SERVED);
    let stop = |pool: String, token: String| {
        let uri = uri(&pool);
        let app = fixture.app.clone();
        let launch = fixture.token.clone();
        async move {
            custody_call(
                &app,
                &launch,
                "DELETE",
                &uri,
                Some(json!({ "pool": pool, "step_up_token": token })),
            )
            .await
        }
    };
    // A pool this Home does not serve, or a malformed one, spends nothing.
    let unknown = hex::encode([0x0e; 32]);
    let (status, answer) = stop(unknown.clone(), String::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "unknown_pool");
    let (status, answer) = stop("sha256:abc".to_string(), String::new()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "bad_pool");
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        0
    );
    // Without the passkey step-up nothing changes.
    let (status, answer) = stop(stopped.clone(), String::new()).await;
    assert_ne!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        crate::custody_consent::served_pools(&fixture.data_dir)
            .unwrap()
            .entries
            .len(),
        2
    );
    // A step-up for another pool does not stop this one.
    let for_kept = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        crate::custody_surface::STEP_UP_SERVED_POOL_REMOVE,
        &json!({ "pool": kept }),
    );
    let (status, answer) = stop(stopped.clone(), for_kept).await;
    assert_ne!(status, StatusCode::OK, "{answer}");

    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        crate::custody_surface::STEP_UP_SERVED_POOL_REMOVE,
        &json!({ "pool": stopped }),
    );
    let (status, answer) = stop(stopped.clone(), token).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let pools = crate::custody_consent::served_pools(&fixture.data_dir).unwrap();
    assert_eq!(
        pools.entries.keys().cloned().collect::<Vec<_>>(),
        vec![format!("sha256:{kept}")]
    );
    assert!(kept_root.join("trusted-runtime-issuer").exists());
}

#[tokio::test]
async fn stop_serving_leaves_a_tombstone() {
    let fixture = custody_fixture();
    let (stopped, root) = plant_served_pool(&fixture.data_dir, 0x0f);
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        crate::custody_surface::STEP_UP_SERVED_POOL_REMOVE,
        &json!({ "pool": stopped }),
    );
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "DELETE",
        &format!("{}/{stopped}", crate::custody_surface::ROUTE_POOLS_SERVED),
        Some(json!({ "pool": stopped, "step_up_token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(!root.exists());
    let pools_dir = root.parent().unwrap();
    let tombstones: Vec<PathBuf> = std::fs::read_dir(pools_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("{stopped}.stopped-")))
        })
        .collect();
    assert_eq!(tombstones.len(), 1);
    // The shares stay on disk, set aside; the root is no longer one.
    assert!(tombstones[0].join("trusted-runtime-issuer").exists());
    assert!(
        crate::protected_content_runtime::custody_provider_root_paths(&fixture.data_dir)
            .unwrap()
            .is_empty()
    );
    assert!(crate::custody_consent::served_pools(&fixture.data_dir)
        .unwrap()
        .entries
        .is_empty());
}

#[tokio::test]
async fn unconfigured_root_shows_needs_restart() {
    let fixture = custody_fixture();
    let (pool, _) = plant_served_pool(&fixture.data_dir, 0x21);
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        crate::custody_surface::ROUTE_POOLS_SERVED,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer[0]["pool_fingerprint"], pool);
    // No running provider lists this root configured.
    assert_eq!(answer[0]["status"], "needs_restart");
}

#[test]
fn status_order_is_restart_waiting_ending_serving() {
    use crate::custody_pool_setup::{served_pool_status, ServedPoolStatus, CONSENT_ENDING_SECS};
    let now = 2_000_000_000;
    let far = now + CONSENT_ENDING_SECS * 4;
    let near = now + CONSENT_ENDING_SECS - 1;
    // Not loaded comes first, whatever else holds.
    for term_end in [None, Some(near), Some(far)] {
        assert_eq!(
            served_pool_status(false, term_end, now),
            ServedPoolStatus::NeedsRestart
        );
    }
    assert_eq!(
        served_pool_status(true, None, now),
        ServedPoolStatus::WaitingForPool
    );
    assert_eq!(
        served_pool_status(true, Some(near), now),
        ServedPoolStatus::ConsentEnding
    );
    // The 7-day boundary: exactly seven days left is still serving.
    assert_eq!(
        served_pool_status(true, Some(now + CONSENT_ENDING_SECS), now),
        ServedPoolStatus::Serving
    );
    assert_eq!(
        served_pool_status(true, Some(far), now),
        ServedPoolStatus::Serving
    );
}

#[tokio::test]
async fn node_without_pool_key_has_no_stop_serving() {
    let fixture = custody_fixture();
    // A served node with no entry has no pool key: the summary card carries
    // none, so the app shows no Stop serving, and the route has nothing to
    // name.
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "DELETE",
        &format!(
            "{}/{}",
            crate::custody_surface::ROUTE_POOLS_SERVED,
            "0".repeat(64)
        ),
        Some(json!({ "pool": "0".repeat(64), "step_up_token": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "unknown_pool");
}

/// Stops `pool` with its passkey step-up.
async fn stop_with_step_up(fixture: &CustodyFixture, pool: &str) -> (StatusCode, Value) {
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        crate::custody_surface::STEP_UP_SERVED_POOL_REMOVE,
        &json!({ "pool": pool }),
    );
    custody_call(
        &fixture.app,
        &fixture.token,
        "DELETE",
        &format!("{}/{pool}", crate::custody_surface::ROUTE_POOLS_SERVED),
        Some(json!({ "pool": pool, "step_up_token": token })),
    )
    .await
}

#[tokio::test]
async fn stop_serving_inactive_does_not_free_inactive() {
    let fixture = custody_fixture();
    let (stopped, _) = plant_served_pool(&fixture.data_dir, 0x22);
    // The served pool sits on `inactive`, the first root ever.
    crate::custody_consent::update_served_pools(&fixture.data_dir, |pools| {
        pools
            .entries
            .get_mut(&format!("sha256:{stopped}"))
            .unwrap()
            .root_path = "inactive".to_string();
        Ok(())
    })
    .unwrap();
    let base = crate::protected_content_runtime::custody_provider_base(&fixture.data_dir);
    std::fs::rename(base.join(format!("pools/{stopped}")), base.join("inactive")).unwrap();
    let (status, answer) = stop_with_step_up(&fixture, &stopped).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(!base.join("inactive").exists());
    // The `pools` folder stays, so `inactive` is never given out again.
    assert!(base.join("pools").is_dir());
    let next = format!("sha256:{}", hex::encode([0x23; 32]));
    assert_eq!(
        crate::custody_pool_setup::reserve_custody_root_for_new_pool(&fixture.data_dir, &next)
            .unwrap(),
        format!("pools/{}", hex::encode([0x23; 32]))
    );
}

#[tokio::test]
async fn stop_serving_the_last_root_stops_the_provider() {
    let fixture = custody_fixture();
    let (stopped, _) = plant_served_pool(&fixture.data_dir, 0x24);
    let (status, answer) = stop_with_step_up(&fixture, &stopped).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(
        crate::protected_content_runtime::custody_provider_root_paths(&fixture.data_dir)
            .unwrap()
            .is_empty()
    );
    // The provider stops before the root is set aside, as Remove does.
    let source = include_str!("../../custody_pool_setup.rs");
    let stop = &source[source
        .find("pub(crate) async fn stop_serving_pool(")
        .unwrap()..];
    let unregister = stop.find("unregister_runtime_provider_target").unwrap();
    let rename = stop.find("std::fs::rename(&root, &tombstone)").unwrap();
    assert!(unregister < rename);
}

#[tokio::test]
async fn hosting_shows_the_offer_after_the_last_root() {
    let fixture = custody_fixture();
    let (stopped, _) = plant_served_pool(&fixture.data_dir, 0x25);
    let (status, _) = stop_with_step_up(&fixture, &stopped).await;
    assert_eq!(status, StatusCode::OK);
    let (status, summary) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/summary",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["serving"], json!([]));
    let (status, offer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        "/api/apps/custody/offer",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{offer}");
}

#[tokio::test]
async fn re_enrollment_after_the_last_root_starts_the_provider_on_a_pools_root() {
    let fixture = custody_fixture();
    let (stopped, _) = plant_served_pool(&fixture.data_dir, 0x26);
    let (status, _) = stop_with_step_up(&fixture, &stopped).await;
    assert_eq!(status, StatusCode::OK);
    // The next pool takes a `pools/<hex>` root, never `inactive`.
    let next = format!("sha256:{}", hex::encode([0x27; 32]));
    assert_eq!(
        crate::custody_pool_setup::reserve_custody_root_for_new_pool(&fixture.data_dir, &next)
            .unwrap(),
        format!("pools/{}", hex::encode([0x27; 32]))
    );
    // Approve starts the provider again through the local registration.
    let source = include_str!("../../custody_pool_setup.rs");
    assert!(source.contains("register_local_custody_provider("));
}

#[tokio::test]
async fn restart_with_no_root_registers_nothing() {
    let fixture = custody_fixture();
    let (stopped, _) = plant_served_pool(&fixture.data_dir, 0x28);
    let (status, _) = stop_with_step_up(&fixture, &stopped).await;
    assert_eq!(status, StatusCode::OK);
    // Boot builds the root list from disk; with none it registers nothing.
    assert!(
        crate::protected_content_runtime::custody_provider_root_paths(&fixture.data_dir)
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::protected_content_runtime::custody_provider_roots_config(&fixture.data_dir).is_err()
    );
}

#[tokio::test]
async fn tombstones_are_kept() {
    let fixture = custody_fixture();
    let (first, _) = plant_served_pool(&fixture.data_dir, 0x29);
    let (second, _) = plant_served_pool(&fixture.data_dir, 0x2a);
    for pool in [&first, &second] {
        let (status, _) = stop_with_step_up(&fixture, pool).await;
        assert_eq!(status, StatusCode::OK);
    }
    let pools_dir =
        crate::protected_content_runtime::custody_provider_base(&fixture.data_dir).join("pools");
    let tombstones = std::fs::read_dir(&pools_dir)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.contains(".stopped-"))
        .count();
    assert_eq!(tombstones, 2, "no tombstone is deleted");
}

/// Confirm publisher for `pool` with a step-up for `approved`.
async fn confirm_publisher(
    fixture: &CustodyFixture,
    pool: &str,
    approved: &str,
) -> (StatusCode, Value) {
    let token = step_up_token_for_app_context(
        &fixture.data_dir,
        "custody",
        &fixture.token,
        crate::custody_surface::STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER,
        &json!({ "pool": approved }),
    );
    custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        &format!(
            "{}/{pool}/publisher",
            crate::custody_surface::ROUTE_POOLS_SERVED
        ),
        Some(json!({ "pool": pool, "step_up_token": token })),
    )
    .await
}

fn entry_profile(data_dir: &std::path::Path, pool: &str) -> Option<String> {
    crate::custody_consent::served_pools(data_dir)
        .unwrap()
        .entries[&format!("sha256:{pool}")]
        .admin_profile_did
        .clone()
}

#[tokio::test]
async fn confirm_publisher_needs_step_up_and_records_the_admin_profile() {
    let fixture = custody_fixture();
    let (pool, _) = plant_served_pool(&fixture.data_dir, 0x2b);
    crate::custody_consent::update_served_pools(&fixture.data_dir, |pools| {
        pools
            .entries
            .get_mut(&format!("sha256:{pool}"))
            .unwrap()
            .admin_profile_did = None;
        Ok(())
    })
    .unwrap();
    // Without a step-up nothing is kept.
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        &format!(
            "{}/{pool}/publisher",
            crate::custody_surface::ROUTE_POOLS_SERVED
        ),
        Some(json!({ "pool": pool, "step_up_token": "" })),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{answer}");
    assert_eq!(entry_profile(&fixture.data_dir, &pool), None);
    // The body must name the path's pool.
    let other = hex::encode([0x2c; 32]);
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "POST",
        &format!(
            "{}/{pool}/publisher",
            crate::custody_surface::ROUTE_POOLS_SERVED
        ),
        Some(json!({ "pool": other, "step_up_token": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "bad_pool");
    // A pool this Home neither serves nor owns spends nothing.
    let (status, answer) = confirm_publisher(&fixture, &other, &other).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer["code"], "unknown_pool");

    let (status, answer) = confirm_publisher(&fixture, &pool, &pool).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    // The calling admin's profile DID is kept for this pool.
    let kept = entry_profile(&fixture.data_dir, &pool).expect("the admin profile is kept");
    assert!(kept.starts_with("did:"), "{kept}");
}

#[tokio::test]
async fn confirm_publisher_is_offered_only_when_missing() {
    let fixture = custody_fixture();
    let (confirmed, _) = plant_served_pool(&fixture.data_dir, 0x2d);
    let (missing, _) = plant_served_pool(&fixture.data_dir, 0x2e);
    crate::custody_consent::update_served_pools(&fixture.data_dir, |pools| {
        pools
            .entries
            .get_mut(&format!("sha256:{missing}"))
            .unwrap()
            .admin_profile_did = None;
        Ok(())
    })
    .unwrap();
    let (status, answer) = custody_call(
        &fixture.app,
        &fixture.token,
        "GET",
        crate::custody_surface::ROUTE_POOLS_SERVED,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    for item in answer.as_array().unwrap() {
        let expected = item["pool_fingerprint"] == confirmed.as_str();
        assert_eq!(item["publisher_confirmed"], expected, "{item}");
    }
    assert!(answer
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["pool_fingerprint"] == missing.as_str()));
}

/// This Home's own pool: an own root trusting this Home and its pool key.
fn plant_own_pool(fixture: &CustodyFixture) -> String {
    use std::os::unix::fs::DirBuilderExt as _;
    let fingerprint = crate::custody_pool_setup::signing_key_fingerprint(&fixture.data_dir)
        .unwrap()
        .unwrap_or_else(|| {
            crate::custody_pool_setup::create_signing_key(&fixture.data_dir).unwrap()
        });
    let hex = fingerprint.full.trim_start_matches("sha256:").to_string();
    let root = crate::protected_content_runtime::custody_root_dir(
        &fixture.data_dir,
        &format!("pools/{hex}"),
    );
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)
        .unwrap();
    let own_issuer =
        crate::protected_content_config::runtime_issuer_hex(&fixture.data_dir).unwrap();
    crate::collaboration_config::create_owner_only_file(
        &root.join("trusted-runtime-issuer"),
        own_issuer.as_bytes(),
        "test issuer",
    )
    .unwrap();
    hex
}

/// A served root's issuer as a real Ed25519 key, so every root on disk reads
/// and this Home's own root can be found beside it.
fn give_real_issuer(root: &std::path::Path, seed: u8) {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    let path = root.join("trusted-runtime-issuer");
    std::fs::remove_file(&path).unwrap();
    crate::collaboration_config::create_owner_only_file(
        &path,
        format!("0x{}", hex::encode(issuer.as_bytes())).as_bytes(),
        "test issuer",
    )
    .unwrap();
}

#[tokio::test]
async fn own_root_confirm_publisher_needs_step_up_writes_only_the_own_root_profile() {
    let fixture = custody_fixture();
    let (served, served_root) = plant_served_pool(&fixture.data_dir, 0x2f);
    give_real_issuer(&served_root, 0x2f);
    crate::custody_consent::update_served_pools(&fixture.data_dir, |pools| {
        pools
            .entries
            .get_mut(&format!("sha256:{served}"))
            .unwrap()
            .admin_profile_did = None;
        Ok(())
    })
    .unwrap();
    let own = plant_own_pool(&fixture);
    let before = crate::custody_consent::served_pools(&fixture.data_dir).unwrap();
    assert_eq!(before.own_root_admin_profile_did, None);
    let (status, answer) = confirm_publisher(&fixture, &own, &own).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let after = crate::custody_consent::served_pools(&fixture.data_dir).unwrap();
    assert!(after.own_root_admin_profile_did.is_some());
    // No entry and no other root changes.
    assert_eq!(after.entries, before.entries);
    assert_eq!(entry_profile(&fixture.data_dir, &served), None);
}

#[tokio::test]
async fn own_root_confirm_publisher_step_up_for_another_pool_is_refused() {
    let fixture = custody_fixture();
    let (served, served_root) = plant_served_pool(&fixture.data_dir, 0x30);
    give_real_issuer(&served_root, 0x30);
    let own = plant_own_pool(&fixture);
    // A passkey approval for the served pool does not confirm the own one.
    let (status, answer) = confirm_publisher(&fixture, &own, &served).await;
    assert_ne!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        crate::custody_consent::served_pools(&fixture.data_dir)
            .unwrap()
            .own_root_admin_profile_did,
        None
    );
}
