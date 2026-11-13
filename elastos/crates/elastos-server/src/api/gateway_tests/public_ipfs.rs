//! Public metadata sharing (META-PUBLIC A4/A5): the Creator's read-only
//! status, the admin's consent and "Stop sharing metadata" in Inbox (exact
//! passkey step-up, the durable withdrawal and its repair), the Inbox card,
//! its Home events signature, and the A5 gate.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::public_ipfs_store::tests::{no_configure, FakeBridge, FakeStore};
use crate::public_ipfs_store::{PublicIpfsStore, PUBLIC_IPFS_TARGET};
use crate::public_metadata_consent::tests::{
    close_public_metadata_gate, open_public_metadata_gate, set_config_flags,
};
use crate::public_metadata_consent::{
    acquire_public_state_lock, consent_enabled, consent_wording_sha256, create_withdrawal_marker,
    enable_step_up_request, phase_allowed, read_consent, read_withdrawal_marker,
    remove_withdrawal_marker, write_consent, ConsentState, PublicMetadataErrorCode,
    CONSENT_WORDING, CONSENT_WORDING_VERSION, ENABLE_OPERATION, STATE_LOCK_BUDGET,
};

const READ: &str = "/api/apps/creator/public-ipfs";
const ACTION: &str = "/api/apps/inbox/actions";
const SUMMARY: &str = "/api/apps/inbox/summary";
const ENABLE_ACTION: &str = crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_ENABLE;
const STOP_ACTION: &str = crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_STOP;

struct PublicIpfsFixture {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    registry: Arc<ProviderRegistry>,
    state: GatewayState,
    app: Router,
    admin: TestPasskeyAuthority,
    /// The admin's Creator launch token (read-only status).
    token: String,
    /// The admin's Inbox launch token (consent and Stop).
    inbox: String,
}

/// An admin with Creator and Inbox launch tokens, on a Home that offers
/// public metadata sharing (A5 gate open) and runs a provider registry.
fn public_ipfs_fixture() -> PublicIpfsFixture {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    owner_only_dir(&data_dir);
    open_public_metadata_gate(&data_dir);
    let admin = passkey_authority_with_profile(&data_dir, "Owner");
    let token = app_token_for_authority(&data_dir, "creator", &admin);
    let inbox = app_token_for_authority(&data_dir, "inbox", &admin);
    let registry = Arc::new(ProviderRegistry::new());
    let state = GatewayState {
        provider_registry: Some(registry.clone()),
        ..test_state(&data_dir)
    };
    PublicIpfsFixture {
        app: gateway_router(state.clone()),
        state,
        _dir: dir,
        registry,
        data_dir,
        admin,
        token,
        inbox,
    }
}

fn guest(data_dir: &std::path::Path) -> TestPasskeyAuthority {
    passkey_authority_with_profile_role_credential(
        data_dir,
        "Guest",
        crate::auth::RuntimePrincipalRole::Guest,
        "public-metadata-guest",
    )
}

fn context_of(authority: &TestPasskeyAuthority) -> HomeLaunchTokenContext {
    HomeLaunchTokenContext {
        principal_id: authority.principal_id.clone(),
        session_id: authority.session_id.clone(),
        proof_binding_id: Some(authority.proof_binding_id.clone()),
        grant_id: authority.grant_id.clone(),
    }
}

async fn public_ipfs_call(
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

/// A passkey step-up of the Inbox launch over `request`.
fn enable_token(fixture: &PublicIpfsFixture, operation: &str, request: &Value) -> String {
    step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &fixture.inbox,
        operation,
        request,
    )
}

/// Inbox Agree: the token and the request the card showed.
async fn enable_with(
    fixture: &PublicIpfsFixture,
    launch: &str,
    step_up_token: Option<String>,
    shown: Value,
) -> (StatusCode, Value) {
    let mut body = json!({ "action_id": ENABLE_ACTION, "step_up_request": shown });
    if let Some(token) = step_up_token {
        body["step_up_token"] = json!(token);
    }
    public_ipfs_call(&fixture.app, launch, "POST", ACTION, Some(body)).await
}

async fn enable(fixture: &PublicIpfsFixture, step_up_token: String) -> (StatusCode, Value) {
    enable_with(
        fixture,
        &fixture.inbox,
        Some(step_up_token),
        enable_step_up_request(),
    )
    .await
}

/// Inbox Stop sharing (and Try again): no step-up.
async fn stop_with(fixture: &PublicIpfsFixture, launch: &str) -> (StatusCode, Value) {
    public_ipfs_call(
        &fixture.app,
        launch,
        "POST",
        ACTION,
        Some(json!({ "action_id": STOP_ACTION })),
    )
    .await
}

async fn stop(fixture: &PublicIpfsFixture) -> (StatusCode, Value) {
    stop_with(fixture, &fixture.inbox).await
}

/// The public metadata card of `launch`'s Inbox, if it has one.
async fn card_for(fixture: &PublicIpfsFixture, launch: &str) -> Option<Value> {
    let (status, summary) = public_ipfs_call(&fixture.app, launch, "GET", SUMMARY, None).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    summary["notifications"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            entry["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("public_metadata_"))
        })
        .cloned()
}

async fn card(fixture: &PublicIpfsFixture) -> Option<Value> {
    card_for(fixture, &fixture.inbox).await
}

async fn enable_consent_directly(data_dir: &std::path::Path) {
    let guard = acquire_public_state_lock(data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    write_consent(data_dir, ConsentState::Enabled, "principal:earlier", &guard).unwrap();
}

fn marker_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("public-ipfs").join("withdraw-requested")
}

fn consent_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("public-ipfs").join("consent.json")
}

/// A marker the Runtime cannot read: malformed, owner-only.
fn plant_unreadable_marker(data_dir: &std::path::Path) {
    crate::protected_content_runtime::write_owner_only_bytes(&marker_path(data_dir), b"not json")
        .unwrap();
    assert!(read_withdrawal_marker(data_dir).is_err());
}

/// Start the store as Enable does, through the fake launcher.
async fn start_store(fixture: &PublicIpfsFixture) {
    let guard = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    PublicIpfsStore::start(&fixture.registry, &fixture.data_dir, &guard)
        .await
        .unwrap();
}

/// The withdrawal ends: the marker gone, the store stopped and unregistered.
async fn wait_withdrawn(fixture: &PublicIpfsFixture) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::fs::symlink_metadata(marker_path(&fixture.data_dir)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "the withdrawal never completed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !fixture
            .registry
            .has_ready_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
    );
}

// ── Enable in Inbox (re-pointed from the Creator routes; names kept) ─

#[tokio::test]
async fn enable_without_step_up_is_refused() {
    let fixture = public_ipfs_fixture();
    for token in [None, Some(String::new())] {
        let (status, answer) =
            enable_with(&fixture, &fixture.inbox, token, enable_step_up_request()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
}

#[tokio::test]
async fn enable_with_step_up_for_other_wording_is_refused() {
    let fixture = public_ipfs_fixture();
    let other_wording = json!({
        "wording_version": CONSENT_WORDING_VERSION,
        "wording_sha256": "0".repeat(64),
    });
    let older_version = json!({ "wording_version": 0, "wording_sha256": consent_wording_sha256() });
    // A token over other wording, shown as the current request, does not
    // match what the passkey approved.
    for approved in [&other_wording, &older_version] {
        let token = enable_token(&fixture, ENABLE_OPERATION, approved);
        let (status, answer) = enable(&fixture, token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    }
    let other_operation = enable_token(
        &fixture,
        "custody.messages.enable",
        &enable_step_up_request(),
    );
    let (status, answer) = enable(&fixture, other_operation).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
}

#[tokio::test]
async fn enable_with_exact_step_up_writes_enabled() {
    let fixture = public_ipfs_fixture();
    let token = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
    let (status, answer) = enable(&fixture, token.clone()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer["message"].is_string(), "{answer}");

    let record = read_consent(&fixture.data_dir).unwrap().unwrap();
    assert_eq!(record.state, ConsentState::Enabled);
    assert_eq!(record.principal, fixture.admin.principal_id);
    assert_eq!(record.wording_version, CONSENT_WORDING_VERSION);
    assert_eq!(record.wording_sha256, consent_wording_sha256());
    assert!(consent_enabled(&fixture.data_dir).unwrap());

    // Readiness is GET's to report; until the store runs it reads not ready.
    let (status, read) = public_ipfs_call(&fixture.app, &fixture.token, "GET", READ, None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["gate_open"], true);
    assert_eq!(read["consent_enabled"], true);
    assert_eq!(read["withdrawing"], false);
    assert_eq!(read["stop_pending"], Value::Null);
    assert_eq!(read["store"]["ready"], false);
    assert_eq!(read["store"]["liveness"], "down");
    assert_eq!(read["store"]["peers"], 0);

    // One approval enables once.
    let (status, answer) = enable(&fixture, token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
}

/// R4: the Creator's GET no longer carries the wording or a step-up request,
/// for anyone; it says whether the gate is open.
#[tokio::test]
async fn non_admin_read_has_no_step_up_request() {
    let fixture = public_ipfs_fixture();
    let (status, admin_read) =
        public_ipfs_call(&fixture.app, &fixture.token, "GET", READ, None).await;
    assert_eq!(status, StatusCode::OK, "{admin_read}");
    assert_eq!(admin_read["admin"], true);
    assert_eq!(admin_read["gate_open"], true);
    assert_eq!(admin_read["consent_enabled"], false);
    assert_eq!(admin_read["withdrawing"], false);
    assert_eq!(admin_read["stop_pending"], Value::Null);
    for removed in ["wording", "wording_version", "step_up_request"] {
        assert!(admin_read.get(removed).is_none(), "{removed}: {admin_read}");
    }
    assert_eq!(
        admin_read["store"],
        json!({ "liveness": "down", "ready": false, "peers": 0 })
    );

    let guest_token =
        app_token_for_authority(&fixture.data_dir, "creator", &guest(&fixture.data_dir));
    let (status, guest_read) =
        public_ipfs_call(&fixture.app, &guest_token, "GET", READ, None).await;
    assert_eq!(status, StatusCode::OK, "{guest_read}");
    assert_eq!(guest_read["admin"], false);
    assert!(guest_read.get("step_up_request").is_none());
    assert_eq!(guest_read["consent_enabled"], false);
}

#[tokio::test]
async fn non_admin_enable_is_refused() {
    let fixture = public_ipfs_fixture();
    let guest_inbox =
        app_token_for_authority(&fixture.data_dir, "inbox", &guest(&fixture.data_dir));
    let step_up = step_up_token_for_app_context(
        &fixture.data_dir,
        "inbox",
        &guest_inbox,
        ENABLE_OPERATION,
        &enable_step_up_request(),
    );
    let (status, answer) = enable_with(
        &fixture,
        &guest_inbox,
        Some(step_up),
        enable_step_up_request(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let (status, answer) = stop_with(&fixture, &guest_inbox).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
    assert_eq!(read_withdrawal_marker(&fixture.data_dir).unwrap(), None);
    assert!(card_for(&fixture, &guest_inbox).await.is_none());
}

#[tokio::test]
async fn public_disable_returns_before_completion_and_marks() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    enable_consent_directly(&fixture.data_dir).await;
    start_store(&fixture).await;
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();

    let (status, answer) = tokio::time::timeout(Duration::from_secs(5), stop(&fixture))
        .await
        .expect("Stop answers without waiting for the state lock");
    assert_eq!(status, StatusCode::OK, "{answer}");

    let marker = read_withdrawal_marker(&fixture.data_dir).unwrap().unwrap();
    assert_eq!(marker.principal, fixture.admin.principal_id);
    // The completion waits for the lock, so nothing past the marker yet.
    assert!(consent_enabled(&fixture.data_dir).unwrap());
    assert_eq!(store.last().shutdown_calls.load(Ordering::SeqCst), 0);
    let (_, read) = public_ipfs_call(&fixture.app, &fixture.token, "GET", READ, None).await;
    assert_eq!(read["withdrawing"], true);
    assert_eq!(read["stop_pending"], Value::Null);
    assert_eq!(
        card(&fixture).await.unwrap()["kind"],
        "public_metadata_stopping"
    );
    // Stop again is idempotent: the first request stands.
    let (status, _) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        read_withdrawal_marker(&fixture.data_dir)
            .unwrap()
            .unwrap()
            .withdrawal_id,
        marker.withdrawal_id
    );

    // Released, the detached completion persists Disabled, stops the store
    // and only then removes the marker.
    drop(held);
    wait_withdrawn(&fixture).await;
    let record = read_consent(&fixture.data_dir).unwrap().unwrap();
    assert_eq!(record.state, ConsentState::Disabled);
    assert_eq!(record.principal, fixture.admin.principal_id);
    assert_eq!(store.last().shutdown_calls.load(Ordering::SeqCst), 1);
    let (_, read) = public_ipfs_call(&fixture.app, &fixture.token, "GET", READ, None).await;
    assert_eq!(read["withdrawing"], false);
    assert_eq!(read["consent_enabled"], false);
    assert_eq!(read["stop_pending"], Value::Null);
    assert_eq!(read["store"]["liveness"], "down");
}

#[tokio::test]
async fn public_withdrawal_survives_caller_cancel() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    enable_consent_directly(&fixture.data_dir).await;
    start_store(&fixture).await;
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();

    // The caller goes away right after the answer, body unread.
    let request = test_browser_request("localhost:61180", "null")
        .method("POST")
        .uri(ACTION)
        .header("x-elastos-home-token", &fixture.inbox)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "action_id": STOP_ACTION }).to_string()))
        .unwrap();
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);

    drop(held);
    wait_withdrawn(&fixture).await;
    assert_eq!(
        read_consent(&fixture.data_dir).unwrap().unwrap().state,
        ConsentState::Disabled
    );
    assert_eq!(store.last().shutdown_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn public_concurrent_enable_disable_ends_disabled() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    for round in 0..4 {
        let token = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
        let enabled = enable(&fixture, token);
        let disabled = stop(&fixture);
        let ((enabled, enable_answer), (disabled, disable_answer)) = if round % 2 == 0 {
            tokio::join!(enabled, disabled)
        } else {
            let (disabled, enabled) = tokio::join!(disabled, enabled);
            (enabled, disabled)
        };
        // Either Enable is refused, or it finished before the marker existed
        // and the withdrawal then wins.
        assert!(
            enabled == StatusCode::OK
                || (enabled == StatusCode::CONFLICT
                    && enable_answer["code"] == "withdrawal_in_progress"),
            "round {round}: {enabled} {enable_answer}"
        );
        assert_eq!(disabled, StatusCode::OK, "{disable_answer}");
        wait_withdrawn(&fixture).await;
        assert_eq!(
            read_consent(&fixture.data_dir).unwrap().unwrap().state,
            ConsentState::Disabled,
            "round {round}"
        );
        for fake in store.launched.lock().unwrap().iter() {
            assert!(
                fake.shutdown_calls.load(Ordering::SeqCst) >= 1
                    || !fake.ops().contains(&"ensure_started".to_string()),
                "round {round}: a started store was left running"
            );
        }
    }
}

/// Review T3-F1 at the Inbox route: while another Stop has linked the marker
/// but not yet made it durable, a Stop whose durability barrier fails gets
/// no acknowledgement.
#[tokio::test]
async fn public_disable_is_not_acknowledged_before_the_marker_is_durable() {
    use crate::public_metadata_consent::test_seams;
    use std::sync::{mpsc, Mutex};

    let fixture = public_ipfs_fixture();
    let (paused_tx, paused_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (paused_tx, release_rx) = (Mutex::new(paused_tx), Mutex::new(release_rx));
    let calls = Arc::new(AtomicUsize::new(0));
    let hook_calls = calls.clone();
    let _hook = test_seams::set_sync_hook(
        &fixture.data_dir,
        Arc::new(move |_dir| {
            if hook_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                paused_tx.lock().unwrap().send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                Ok(())
            } else {
                Err(std::io::Error::other("injected sync failure"))
            }
        }),
    );
    let stop_a = std::thread::spawn({
        let data_dir = fixture.data_dir.clone();
        move || create_withdrawal_marker(&data_dir, "principal:a")
    });
    paused_rx.recv().unwrap();

    let (status, answer) = stop(&fixture).await;
    assert_ne!(status, StatusCode::OK, "{answer}");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{answer}");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    release_tx.send(()).unwrap();
    stop_a.join().unwrap().unwrap();
}

#[tokio::test]
async fn public_enable_refused_while_withdrawing() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    let marker = create_withdrawal_marker(&fixture.data_dir, "principal:earlier").unwrap();
    let record = read_consent(&fixture.data_dir).unwrap();
    let spent = consumed_passkey_step_up_count_for_test(&fixture.data_dir);

    let token = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
    let (status, answer) = enable(&fixture, token).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "withdrawal_in_progress");
    assert_eq!(
        read_withdrawal_marker(&fixture.data_dir).unwrap(),
        Some(marker)
    );
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), record);
    // Refused before the approval is spent.
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        spent
    );
}

#[tokio::test(flavor = "current_thread")]
async fn public_lock_acquisition_never_blocks_the_runtime() {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    owner_only_dir(&data_dir);
    let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let ticks = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let holder = tokio::spawn({
        let ticks = ticks.clone();
        let release = release.clone();
        async move {
            let _guard = guard;
            while !release.load(Ordering::SeqCst) {
                ticks.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });

    let before = ticks.load(Ordering::SeqCst);
    let refused = acquire_public_state_lock(&data_dir, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), PublicMetadataErrorCode::NotReady);
    // The one runtime thread kept running the holder while the second
    // acquisition waited.
    assert!(
        ticks.load(Ordering::SeqCst) >= before + 10,
        "the holder did not run while the lock was polled"
    );

    release.store(true, Ordering::SeqCst);
    holder.await.unwrap();
    acquire_public_state_lock(&data_dir, Duration::from_millis(300))
        .await
        .unwrap();
}

#[tokio::test]
async fn public_marker_makes_next_phase_disabled() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    phase_allowed(&fixture.data_dir).unwrap();

    create_withdrawal_marker(&fixture.data_dir, "principal:earlier").unwrap();
    let refused = phase_allowed(&fixture.data_dir).unwrap_err();
    assert_eq!(refused.code(), PublicMetadataErrorCode::Disabled);
    // The record itself still says enabled: the marker alone disables.
    assert!(consent_enabled(&fixture.data_dir).unwrap());
}

/// Another capsule's launch (here People) reaches neither the Creator's
/// status nor the Inbox actions as an Inbox.
#[tokio::test]
async fn other_capsule_token_is_refused() {
    let fixture = public_ipfs_fixture();
    let other = fixture.admin.people_token.clone();
    let (status, answer) = public_ipfs_call(&fixture.app, &other, "GET", READ, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let step_up = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
    let (status, answer) =
        enable_with(&fixture, &other, Some(step_up), enable_step_up_request()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let (status, answer) = stop_with(&fixture, &other).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
    assert_eq!(read_withdrawal_marker(&fixture.data_dir).unwrap(), None);
}

/// An Enable that passed its marker check and then waited for the lock while
/// a whole withdrawal completed must not re-enable: the withdrawal wins.
#[tokio::test]
async fn public_enable_after_a_withdrawal_completed_while_it_waited_is_refused() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    enable_consent_directly(&fixture.data_dir).await;
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let spent = consumed_passkey_step_up_count_for_test(&fixture.data_dir);
    let token = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
    let waiting = {
        let (app, launch) = (fixture.app.clone(), fixture.inbox.clone());
        tokio::spawn(async move {
            public_ipfs_call(
                &app,
                &launch,
                "POST",
                ACTION,
                Some(json!({
                    "action_id": ENABLE_ACTION,
                    "step_up_token": token,
                    "step_up_request": enable_step_up_request(),
                })),
            )
            .await
        })
    };
    // The Enable has spent its step-up and now waits for the lock.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while consumed_passkey_step_up_count_for_test(&fixture.data_dir) == spent {
        assert!(std::time::Instant::now() < deadline, "the Enable never ran");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // A whole withdrawal completes meanwhile, under the held lock.
    create_withdrawal_marker(&fixture.data_dir, "principal:earlier").unwrap();
    write_consent(
        &fixture.data_dir,
        ConsentState::Disabled,
        "principal:earlier",
        &held,
    )
    .unwrap();
    remove_withdrawal_marker(&fixture.data_dir, &held).unwrap();
    drop(held);

    let (status, answer) = waiting.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "withdrawal_in_progress");
    assert_eq!(
        read_consent(&fixture.data_dir).unwrap().unwrap().state,
        ConsentState::Disabled
    );
    assert_eq!(store.launches(), 0);
}

// ── A4 §1.7: the Inbox request check and the launch restriction ─────

/// The request the card showed is compared with the one the Runtime
/// rebuilds before the passkey approval is spent.
#[tokio::test]
async fn public_inbox_enable_with_changed_request_is_refused_before_spending() {
    let fixture = public_ipfs_fixture();
    let shown =
        json!({ "wording_version": CONSENT_WORDING_VERSION, "wording_sha256": "f".repeat(64) });
    let token = enable_token(&fixture, ENABLE_OPERATION, &shown);
    let spent = consumed_passkey_step_up_count_for_test(&fixture.data_dir);
    for shown in [shown, json!(null), json!({})] {
        let (status, answer) =
            enable_with(&fixture, &fixture.inbox, Some(token.clone()), shown).await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert_eq!(answer["code"], "changed");
    }
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        spent,
        "no approval was spent"
    );
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
}

/// The Creator only reads: it can neither enable nor stop, and its old
/// routes are gone (R1).
#[tokio::test]
async fn public_creator_token_cannot_enable_or_stop() {
    let fixture = public_ipfs_fixture();
    let step_up = step_up_token_for_app_context(
        &fixture.data_dir,
        "creator",
        &fixture.token,
        ENABLE_OPERATION,
        &enable_step_up_request(),
    );
    let (status, answer) = enable_with(
        &fixture,
        &fixture.token,
        Some(step_up),
        enable_step_up_request(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let (status, answer) = stop_with(&fixture, &fixture.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    for (uri, body) in [
        (
            "/api/apps/creator/public-ipfs/enable",
            json!({ "step_up_token": "" }),
        ),
        ("/api/apps/creator/public-ipfs/disable", json!({})),
    ] {
        let (status, answer) =
            public_ipfs_call(&fixture.app, &fixture.token, "POST", uri, Some(body)).await;
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "{uri}: {status} {answer}"
        );
    }
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
    assert_eq!(read_withdrawal_marker(&fixture.data_dir).unwrap(), None);
}

// ── A4 §1.3: Stop needs neither flag; card states and recovery ─────

/// A started store, consent Enabled, then `flag` turned off: Stop from the
/// Inbox still records the marker, persists Disabled and stops the store;
/// the launch restriction is kept.
async fn stop_with_flag_off(flag: &str) {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    enable_consent_directly(&fixture.data_dir).await;
    start_store(&fixture).await;
    set_config_flags(&fixture.data_dir, &[(flag, false)]);

    let (status, answer) = stop_with(&fixture, &fixture.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "Creator: {answer}");
    let (status, answer) = stop_with(&fixture, &fixture.admin.people_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "People: {answer}");
    assert_eq!(read_withdrawal_marker(&fixture.data_dir).unwrap(), None);

    let (status, answer) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    wait_withdrawn(&fixture).await;
    assert_eq!(
        read_consent(&fixture.data_dir).unwrap().unwrap().state,
        ConsentState::Disabled
    );
    assert_eq!(store.last().shutdown_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn public_stop_with_public_metadata_off() {
    stop_with_flag_off(crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY).await;
}

#[tokio::test]
async fn public_stop_with_protected_content_off() {
    stop_with_flag_off("protected_content").await;
}

/// "Try again" posts the same action: one withdrawal, one id.
#[tokio::test]
async fn public_retry_stop_is_idempotent() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let (status, _) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK);
    let first = read_withdrawal_marker(&fixture.data_dir).unwrap().unwrap();
    let entry = card(&fixture).await.unwrap();
    assert_eq!(entry["kind"], "public_metadata_stopping");
    assert_eq!(entry["action_ref"]["action_id"], STOP_ACTION);
    for _ in 0..3 {
        let (status, answer) = stop(&fixture).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            read_withdrawal_marker(&fixture.data_dir).unwrap().unwrap(),
            first
        );
    }
    drop(held);
    wait_withdrawn(&fixture).await;
}

#[tokio::test]
async fn public_paused_card_when_not_offered() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    assert_eq!(
        card(&fixture).await.unwrap()["kind"],
        "public_metadata_sharing"
    );
    for (flag, reason) in [
        (
            crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY,
            "sharing is not offered",
        ),
        ("protected_content", "protected content is off"),
    ] {
        open_public_metadata_gate(&fixture.data_dir);
        set_config_flags(&fixture.data_dir, &[(flag, false)]);
        let entry = card(&fixture).await.unwrap();
        assert_eq!(entry["kind"], "public_metadata_paused", "{entry}");
        assert_eq!(
            entry["body"],
            format!("Metadata sharing is paused on this Home ({reason}). Your consent is kept.")
        );
        assert_eq!(entry["action_ref"]["action_id"], STOP_ACTION);
        assert_eq!(entry["passkey_approval"], Value::Null);
        // Paused, not withdrawn.
        assert!(consent_enabled(&fixture.data_dir).unwrap());
    }
}

#[tokio::test]
async fn public_no_offer_after_stop_when_not_offered() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    close_public_metadata_gate(&fixture.data_dir);
    let (status, _) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK);
    wait_withdrawn(&fixture).await;
    assert!(card(&fixture).await.is_none());
    // And Agree is refused before any approval is spent.
    let spent = consumed_passkey_step_up_count_for_test(&fixture.data_dir);
    let token = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
    let (status, answer) = enable(&fixture, token).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "public_metadata_off");
    assert_eq!(
        consumed_passkey_step_up_count_for_test(&fixture.data_dir),
        spent
    );
}

#[tokio::test]
async fn public_offer_after_stop_when_offered() {
    let fixture = public_ipfs_fixture();
    // No record yet: the quiet standing offer.
    let entry = card(&fixture).await.unwrap();
    assert_eq!(entry["kind"], "public_metadata_consent");
    assert_eq!(entry["body"], CONSENT_WORDING);
    assert_eq!(entry["severity"], "info");
    assert_eq!(entry["read"], true);
    assert_eq!(entry["passkey_approval"], true);
    assert_eq!(entry["step_up_request"], enable_step_up_request());
    assert_eq!(entry["action_ref"]["action_id"], ENABLE_ACTION);
    // The standing card adds nothing unread.
    let (_, summary) = public_ipfs_call(&fixture.app, &fixture.inbox, "GET", SUMMARY, None).await;
    let unread = summary["notifications"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["read"] == false)
        .count();
    assert_eq!(summary["notifications"]["unread_count"], unread);

    enable_consent_directly(&fixture.data_dir).await;
    let (status, _) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK);
    wait_withdrawn(&fixture).await;
    let entry = card(&fixture).await.unwrap();
    assert_eq!(entry["kind"], "public_metadata_consent");
    assert_eq!(entry["read"], true);
}

#[tokio::test]
async fn public_unreadable_consent_stop_recovers() {
    let fixture = public_ipfs_fixture();
    crate::protected_content_runtime::write_owner_only_bytes(
        &consent_path(&fixture.data_dir),
        b"{ not a record",
    )
    .unwrap();
    let entry = card(&fixture).await.unwrap();
    assert_eq!(entry["kind"], "public_metadata_unreadable");
    assert_eq!(
        entry["body"],
        "Metadata sharing state can't be read. Stop sharing to reset it."
    );
    assert_eq!(entry["action_ref"]["action_id"], STOP_ACTION);

    let (status, answer) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    wait_withdrawn(&fixture).await;
    assert_eq!(
        read_consent(&fixture.data_dir).unwrap().unwrap().state,
        ConsentState::Disabled
    );
    assert_eq!(
        card(&fixture).await.unwrap()["kind"],
        "public_metadata_consent"
    );
}

#[tokio::test]
async fn public_unreadable_marker_stop_recovers() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    plant_unreadable_marker(&fixture.data_dir);
    let entry = card(&fixture).await.unwrap();
    assert_eq!(entry["kind"], "public_metadata_stopping");
    assert_eq!(
        entry["body"],
        "Still stopping: the withdrawal state is unreadable. Your Home keeps trying."
    );
    // The supervisor keeps treating it as a withdrawal: no phase passes.
    assert_eq!(
        phase_allowed(&fixture.data_dir).unwrap_err().code(),
        PublicMetadataErrorCode::Disabled
    );

    let (status, answer) = stop(&fixture).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    wait_withdrawn(&fixture).await;
    let record = read_consent(&fixture.data_dir).unwrap().unwrap();
    assert_eq!(record.state, ConsentState::Disabled);
    assert_eq!(record.principal, fixture.admin.principal_id);
}

#[tokio::test]
async fn public_marker_wins_over_enabled_consent() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    create_withdrawal_marker(&fixture.data_dir, "principal:earlier").unwrap();
    let entry = card(&fixture).await.unwrap();
    assert_eq!(entry["kind"], "public_metadata_stopping");
    assert_eq!(entry["body"], "Stopping…");
    drop(held);
}

// ── A45-F5: repairing an unreadable marker ──────────────────────────

/// Polls the marker until `done`, recording every valid withdrawal id seen.
async fn ids_seen_until(
    data_dir: &std::path::Path,
    done: impl Fn() -> bool,
) -> std::collections::BTreeSet<String> {
    let mut seen = std::collections::BTreeSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "never done");
        if let Ok(Some(marker)) = read_withdrawal_marker(data_dir) {
            seen.insert(marker.withdrawal_id);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if let Ok(Some(marker)) = read_withdrawal_marker(data_dir) {
        seen.insert(marker.withdrawal_id);
    }
    seen
}

/// Two Stops repair the same unreadable marker: exactly one fresh marker is
/// installed, and the other Stop keeps it.
#[tokio::test]
async fn public_marker_repairs_race_keep_one_withdrawal_id() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    // The completion's Stop blocks inside the store's shutdown, so the
    // repaired marker stays observable.
    let gates = Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = gates.clone();
    let _store = FakeStore::install(
        &fixture.data_dir,
        Arc::new(move |fake: &FakeBridge| {
            kept.lock().unwrap().push(fake.hold_shutdown());
        }),
    );
    start_store(&fixture).await;
    plant_unreadable_marker(&fixture.data_dir);
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let spawn_stop = || {
        let (app, launch) = (fixture.app.clone(), fixture.inbox.clone());
        tokio::spawn(async move {
            public_ipfs_call(
                &app,
                &launch,
                "POST",
                ACTION,
                Some(json!({ "action_id": STOP_ACTION })),
            )
            .await
        })
    };
    let (first, second) = (spawn_stop(), spawn_stop());
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(held);
    let both = Arc::new(AtomicUsize::new(0));
    let (first, second) = {
        let both_a = both.clone();
        let both_b = both.clone();
        (
            tokio::spawn(async move {
                let answer = first.await.unwrap();
                both_a.fetch_add(1, Ordering::SeqCst);
                answer
            }),
            tokio::spawn(async move {
                let answer = second.await.unwrap();
                both_b.fetch_add(1, Ordering::SeqCst);
                answer
            }),
        )
    };
    let done = both.clone();
    let seen = ids_seen_until(&fixture.data_dir, move || done.load(Ordering::SeqCst) >= 1).await;
    assert_eq!(seen.len(), 1, "one repaired marker: {seen:?}");
    // Let the completion finish.
    for gate in gates.lock().unwrap().iter() {
        gate.open();
    }
    let (a, b) = (first.await.unwrap(), second.await.unwrap());
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    wait_withdrawn(&fixture).await;
    assert_eq!(
        read_consent(&fixture.data_dir).unwrap().unwrap().state,
        ConsentState::Disabled
    );
}

/// Another Stop installs a valid marker while the repair waits for the
/// guard: the repair keeps it, its id and principal included.
#[tokio::test]
async fn public_marker_repair_races_stop_keeps_valid_marker() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    plant_unreadable_marker(&fixture.data_dir);
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let repair = {
        let (app, launch) = (fixture.app.clone(), fixture.inbox.clone());
        tokio::spawn(async move {
            public_ipfs_call(
                &app,
                &launch,
                "POST",
                ACTION,
                Some(json!({ "action_id": STOP_ACTION })),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The other Stop's marker, written whole.
    let other = crate::public_metadata_consent::WithdrawalMarker {
        withdrawal_id: format!("withdrawal:{}", "ab".repeat(16)),
        principal: "principal:other-stop".to_string(),
        created_at: 7,
        stop_pending: None,
    };
    crate::protected_content_runtime::write_owner_only_bytes(
        &marker_path(&fixture.data_dir),
        &serde_json::to_vec(&other).unwrap(),
    )
    .unwrap();
    drop(held);
    let (status, answer) = repair.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{answer}");
    // Either still pending with that marker, or completed: never another id.
    if let Some(kept) = read_withdrawal_marker(&fixture.data_dir).unwrap() {
        assert_eq!(kept.withdrawal_id, other.withdrawal_id);
        assert_eq!(kept.principal, other.principal);
    }
    wait_withdrawn(&fixture).await;
    let record = read_consent(&fixture.data_dir).unwrap().unwrap();
    assert_eq!(record.state, ConsentState::Disabled);
    assert_eq!(record.principal, "principal:other-stop");
}

/// A completion removed the marker while the repair waited: the withdrawal
/// is complete, and the repair touches neither marker nor consent.
#[tokio::test]
async fn public_marker_repair_after_completion_touches_nothing() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    plant_unreadable_marker(&fixture.data_dir);
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let repair = {
        let (app, launch) = (fixture.app.clone(), fixture.inbox.clone());
        tokio::spawn(async move {
            public_ipfs_call(
                &app,
                &launch,
                "POST",
                ACTION,
                Some(json!({ "action_id": STOP_ACTION })),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    write_consent(
        &fixture.data_dir,
        ConsentState::Disabled,
        "principal:completion",
        &held,
    )
    .unwrap();
    remove_withdrawal_marker(&fixture.data_dir, &held).unwrap();
    let after = read_consent(&fixture.data_dir).unwrap();
    drop(held);
    let (status, answer) = repair.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{answer}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(read_withdrawal_marker(&fixture.data_dir).unwrap(), None);
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), after);
}

/// A completion and then a later Enable ran while the repair waited: the
/// Enable stands.
#[tokio::test]
async fn public_marker_repair_never_clobbers_later_enable() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    plant_unreadable_marker(&fixture.data_dir);
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let repair = {
        let (app, launch) = (fixture.app.clone(), fixture.inbox.clone());
        tokio::spawn(async move {
            public_ipfs_call(
                &app,
                &launch,
                "POST",
                ACTION,
                Some(json!({ "action_id": STOP_ACTION })),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    write_consent(
        &fixture.data_dir,
        ConsentState::Disabled,
        "principal:completion",
        &held,
    )
    .unwrap();
    remove_withdrawal_marker(&fixture.data_dir, &held).unwrap();
    let later = write_consent(
        &fixture.data_dir,
        ConsentState::Enabled,
        "principal:later-enable",
        &held,
    )
    .unwrap();
    drop(held);
    let (status, answer) = repair.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{answer}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(read_withdrawal_marker(&fixture.data_dir).unwrap(), None);
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), Some(later));
}

/// The caller goes away while the repair waits for the guard: the detached
/// task still repairs and completes the withdrawal.
#[tokio::test]
async fn public_marker_repair_survives_cancel_before_guard() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    plant_unreadable_marker(&fixture.data_dir);
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let cancelled = tokio::time::timeout(Duration::from_millis(200), stop(&fixture)).await;
    assert!(cancelled.is_err(), "the caller gave up while it waited");
    drop(held);
    wait_withdrawn(&fixture).await;
    let record = read_consent(&fixture.data_dir).unwrap().unwrap();
    assert_eq!(record.state, ConsentState::Disabled);
    assert_eq!(record.principal, fixture.admin.principal_id);
}

/// Each durability step of the replace can fail: the Stop answers 500 with
/// no acknowledgement, and the old marker or a new durable one is on disk,
/// never none.
#[tokio::test]
async fn public_marker_repair_durability_failure_no_ack() {
    use crate::public_metadata_consent::test_seams::{self, ReplaceStage};

    for failing in [
        ReplaceStage::TempSync,
        ReplaceStage::Rename,
        ReplaceStage::DirSync,
    ] {
        let fixture = public_ipfs_fixture();
        enable_consent_directly(&fixture.data_dir).await;
        plant_unreadable_marker(&fixture.data_dir);
        let _hook = test_seams::set_replace_hook(
            &fixture.data_dir,
            Arc::new(move |stage| {
                if stage == failing {
                    Err(std::io::Error::other("injected durability failure"))
                } else {
                    Ok(())
                }
            }),
        );
        let (status, answer) = stop(&fixture).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{failing:?}: {answer}"
        );
        let bytes = std::fs::read(marker_path(&fixture.data_dir))
            .unwrap_or_else(|_| panic!("{failing:?}: the marker is gone"));
        let old = bytes == b"not json";
        let new =
            serde_json::from_slice::<crate::public_metadata_consent::WithdrawalMarker>(&bytes)
                .is_ok_and(|marker| marker.principal == fixture.admin.principal_id);
        assert!(old || new, "{failing:?}: neither the old nor a new marker");
        if failing != ReplaceStage::DirSync {
            assert!(old, "{failing:?}: nothing was renamed yet");
        }
    }
}

/// A crash after the rename and before the directory sync leaves the old or
/// the new marker in place, never none.
#[tokio::test]
async fn public_marker_repair_crash_barrier() {
    use crate::public_metadata_consent::test_seams::{self, ReplaceStage};
    use std::sync::Mutex;

    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    plant_unreadable_marker(&fixture.data_dir);
    let at_barrier = Arc::new(Mutex::new(None::<Option<Vec<u8>>>));
    let seen = at_barrier.clone();
    let marker = marker_path(&fixture.data_dir);
    let _hook = test_seams::set_replace_hook(
        &fixture.data_dir,
        Arc::new(move |stage| {
            if stage == ReplaceStage::DirSync {
                // The "crash": what is on disk at the barrier, then no sync.
                *seen.lock().unwrap() = Some(std::fs::read(&marker).ok());
                return Err(std::io::Error::other("crashed before the directory sync"));
            }
            Ok(())
        }),
    );
    let (status, _) = stop(&fixture).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let on_disk = at_barrier
        .lock()
        .unwrap()
        .clone()
        .expect("the barrier was reached")
        .expect("a marker is on disk at the barrier");
    assert!(
        on_disk == b"not json"
            || serde_json::from_slice::<crate::public_metadata_consent::WithdrawalMarker>(&on_disk)
                .is_ok()
    );
}

// ── A45-F3: Home events see detail-only card changes ────────────────

fn signature(fixture: &PublicIpfsFixture) -> Option<String> {
    public_metadata_realtime_signature(&fixture.state, &context_of(&fixture.admin))
}

/// One status read, after the previous read's task has let the single
/// status slot go.
async fn read_status(fixture: &PublicIpfsFixture) {
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = PublicIpfsStore::status(&fixture.registry).await;
}

#[tokio::test]
async fn public_signature_changes_on_ready_only_change() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    enable_consent_directly(&fixture.data_dir).await;
    start_store(&fixture).await;
    store.last().peers.store(0, Ordering::SeqCst);
    read_status(&fixture).await;
    let not_ready = signature(&fixture).unwrap();
    store.last().peers.store(3, Ordering::SeqCst);
    read_status(&fixture).await;
    let ready = signature(&fixture).unwrap();
    assert_ne!(not_ready, ready);
    assert_eq!(
        card(&fixture).await.unwrap()["kind"],
        "public_metadata_sharing"
    );
}

#[tokio::test]
async fn public_signature_changes_on_liveness_only_change() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    enable_consent_directly(&fixture.data_dir).await;
    read_status(&fixture).await;
    let down = signature(&fixture).unwrap();
    start_store(&fixture).await;
    store.last().peers.store(0, Ordering::SeqCst);
    read_status(&fixture).await;
    let running = signature(&fixture).unwrap();
    assert_ne!(down, running);
}

#[tokio::test]
async fn public_signature_changes_on_stop_pending_text_change() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    create_withdrawal_marker(&fixture.data_dir, "principal:test").unwrap();
    let plain = signature(&fixture).unwrap();
    crate::public_metadata_consent::record_withdrawal_pending(
        &fixture.data_dir,
        "the provider did not stop",
        &held,
    )
    .unwrap();
    let pending = signature(&fixture).unwrap();
    crate::public_metadata_consent::record_withdrawal_pending(
        &fixture.data_dir,
        "the repo lock is still held",
        &held,
    )
    .unwrap();
    let other = signature(&fixture).unwrap();
    assert_ne!(plain, pending);
    assert_ne!(pending, other);
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn public_signature_stable_when_nothing_changes() {
    let fixture = public_ipfs_fixture();
    enable_consent_directly(&fixture.data_dir).await;
    let first = signature(&fixture).unwrap();
    assert_eq!(signature(&fixture).unwrap(), first);
    // A running store; its peer count moves and the slot gets busy.
    let slow = Arc::new(FakeBridge::new());
    fixture
        .registry
        .register_runtime_provider_target(PUBLIC_IPFS_TARGET, slow.clone())
        .await
        .unwrap();
    start_store(&fixture).await;
    read_status(&fixture).await;
    let running = signature(&fixture).unwrap();
    slow.peers.store(9, Ordering::SeqCst);
    read_status(&fixture).await;
    assert_eq!(signature(&fixture).unwrap(), running, "no peer count");
    let _held = slow.hold("status");
    read_status(&fixture).await;
    assert_eq!(
        PublicIpfsStore::status(&fixture.registry).await.liveness,
        crate::public_ipfs_store::StoreLiveness::Unknown
    );
    assert_eq!(signature(&fixture).unwrap(), running, "a busy slot");
}

#[tokio::test]
async fn public_signature_absent_for_non_admin() {
    let fixture = public_ipfs_fixture();
    assert!(signature(&fixture).is_some());
    let guest = guest(&fixture.data_dir);
    assert_eq!(
        public_metadata_realtime_signature(&fixture.state, &context_of(&guest),),
        None
    );
}

// ── A5: Enable meets the gate under the guard ───────────────────────

/// The gate closes while an Enable waits for the guard: no Enabled write
/// and no start.
#[tokio::test]
async fn public_gate_closes_while_enable_waits_for_guard() {
    let fixture = public_ipfs_fixture();
    let store = FakeStore::install(&fixture.data_dir, no_configure());
    let held = acquire_public_state_lock(&fixture.data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    let spent = consumed_passkey_step_up_count_for_test(&fixture.data_dir);
    let token = enable_token(&fixture, ENABLE_OPERATION, &enable_step_up_request());
    let waiting = {
        let (app, launch) = (fixture.app.clone(), fixture.inbox.clone());
        tokio::spawn(async move {
            public_ipfs_call(
                &app,
                &launch,
                "POST",
                ACTION,
                Some(json!({
                    "action_id": ENABLE_ACTION,
                    "step_up_token": token,
                    "step_up_request": enable_step_up_request(),
                })),
            )
            .await
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while consumed_passkey_step_up_count_for_test(&fixture.data_dir) == spent {
        assert!(std::time::Instant::now() < deadline, "the Enable never ran");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    close_public_metadata_gate(&fixture.data_dir);
    drop(held);
    let (status, answer) = waiting.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "public_metadata_off");
    assert_eq!(read_consent(&fixture.data_dir).unwrap(), None);
    assert_eq!(store.launches(), 0);
}

/// With the gate closed the Creator reads `gate_open: false` and opens as on
/// develop; the Home has no card to offer.
#[tokio::test]
async fn public_gate_closed_read_and_card() {
    let fixture = public_ipfs_fixture();
    close_public_metadata_gate(&fixture.data_dir);
    let (status, read) = public_ipfs_call(&fixture.app, &fixture.token, "GET", READ, None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["gate_open"], false);
    assert!(card(&fixture).await.is_none());
    set_config_flags(&fixture.data_dir, &[("protected_content", false)]);
    let (status, read) = public_ipfs_call(&fixture.app, &fixture.token, "GET", READ, None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["gate_open"], false);
}
