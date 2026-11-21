//! `cs_*` rows for the Runtime transaction effect store. The Wallet
//! authority is built as the Wallet routes build it: a verified token whose
//! actor is the Wallet capsule, then `runtime_wallet_authority`.
//!
//! How far the effect lifecycle is driven. A real effect is first stored by
//! `ensure_runtime_transaction_approval`, which needs a Chain provider and a
//! Wallet provider; the rows have neither. So each row (1) calls
//! `complete_runtime_transaction_effect` for an effect that does not exist,
//! (2) calls the private `save_transaction_effect_store` directly with a
//! small store holding one prepared effect bound to the person's authority,
//! and (3) calls `complete_runtime_transaction_effect` for that effect. Step
//! 3 is the route-level function: it records the requested audit event,
//! saves the store itself, and then stops where it asks the Wallet provider,
//! which is not there. Step 2 is one level below the routes.
//!
//! See the fixture's module comment (`gateway_tests/cs_child_saves.rs`) for
//! what stands in for a real child and where it differs.

use super::super::gateway_tests::cs_child_saves::{
    answer, assert_stored_protected, is_envelope, parent_person, person_folders_left, read_written,
    report_person_files, tree, ParentPerson, ENVELOPE_START, KEPT_ELSEWHERE, PERSON, ROOT_DIR,
};
use super::*;

const STORE_FILE: &str = ".AppData/ElastOS/Runtime/transaction-effects.json";
const EFFECT_ID: &str =
    "transaction-effect:sha256:c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
const ADDRESS: &str = "0x00000000000000000000000000000000000000c5";

/// A store with one prepared effect, bound to the authority's person,
/// session, proof binding, grant, actor and launch.
fn small_store(authority: &RuntimeWalletAuthority) -> RuntimeTransactionEffectStore {
    let effect = RuntimeTransactionEffect {
        schema: TRANSACTION_EFFECT_SCHEMA.to_string(),
        effect_id: EFFECT_ID.to_string(),
        source: NATIVE_TRANSACTION_SOURCE.to_string(),
        authority: transaction_authority(authority),
        request_sha256: "11".repeat(32),
        request_binding: json!({"cs": "request binding"}),
        approval_request_id: "cs-approval-request".to_string(),
        wallet_request_sha256: format!("request:sha256:{}", "22".repeat(32)),
        approval_expires_at: 4_102_444_800,
        approval_reason: "cs transaction reason".to_string(),
        account_id: "cs-account".to_string(),
        address: ADDRESS.to_string(),
        chain_namespace: "eip155:20".to_string(),
        network: "esc-mainnet".to_string(),
        intent: json!({"to": ADDRESS, "value": "1000"}),
        state: TransactionEffectState::Prepared,
        approval_snapshot: None,
        signed_transaction: None,
        wallet_binding: None,
        wallet_transaction_hash: None,
        signed_result: None,
        receipt: None,
        requested_audit_completed: false,
        projection_completed: false,
        completion_audit_completed: false,
        completion_error: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    };
    RuntimeTransactionEffectStore {
        schema: TRANSACTION_EFFECT_STORE_SCHEMA.to_string(),
        principal_id: PERSON.to_string(),
        effects: vec![effect],
    }
}

fn shown<T>(result: &Result<T, (StatusCode, String)>) -> String {
    match result {
        Ok(_) => "Ok".to_string(),
        Err((status, text)) => format!("Err {} {text}", status.as_u16()),
    }
}

/// What the three steps answered and what the store held after each save.
struct Outcome {
    unknown: String,
    saved: String,
    plain_after_save: Vec<u8>,
    /// The store file's bytes on disk right after the direct save.
    file_after_save: Vec<u8>,
    completed: String,
    plain_after_complete: Vec<u8>,
    audit_events: Vec<(String, Option<String>)>,
}

/// The three steps in the module comment, in `dir`, with the authority built
/// from `required`.
async fn drive(row: &str, dir: &std::path::Path, required: &RequiredHomeLaunchToken) -> Outcome {
    let authority = runtime_wallet_authority(required).unwrap();
    assert_eq!(authority.verified_context().principal_id(), PERSON);
    assert_eq!(authority.verified_context().actor(), WALLET_CAPSULE_ID);
    let state = ParentPerson::state_on(dir);

    let lookup = RuntimeTransactionLookup::EffectId(EFFECT_ID);
    let unknown =
        shown(&complete_runtime_transaction_effect(&state, &authority, lookup, None, None).await);
    answer(
        row,
        "complete_runtime_transaction_effect, no such effect",
        &unknown,
    );
    assert!(!dir.join(ROOT_DIR).exists(), "the load wrote nothing");

    let mut store = small_store(&authority);
    let saved = shown(&save_transaction_effect_store(&state, &store));
    answer(row, "save_transaction_effect_store", &saved);
    let plain_after_save = serde_json::to_vec_pretty(&store).unwrap();
    report_person_files(row, "after the direct save:", dir);
    let file_after_save = read_written(dir, STORE_FILE);

    let lookup = RuntimeTransactionLookup::EffectId(EFFECT_ID);
    let completed =
        shown(&complete_runtime_transaction_effect(&state, &authority, lookup, None, None).await);
    answer(
        row,
        "complete_runtime_transaction_effect, the stored effect",
        &completed,
    );
    report_person_files(row, "after the route-level call:", dir);
    // What the route-level call's own save wrote: the same store with the
    // requested audit marked done. Its `updated_at` is the time of the call,
    // so it is read back through the store's own load.
    let loaded = load_transaction_effect_store(&state, PERSON).unwrap();
    assert_eq!(loaded.effects.len(), 1);
    answer(
        row,
        "stored effect after the route-level call",
        format!(
            "requested_audit_completed {}, state {:?}",
            loaded.effects[0].requested_audit_completed, loaded.effects[0].state
        ),
    );
    store.effects[0].requested_audit_completed = loaded.effects[0].requested_audit_completed;
    store.effects[0].updated_at = loaded.effects[0].updated_at;
    let plain_after_complete = serde_json::to_vec_pretty(&store).unwrap();
    let audit_events: Vec<(String, Option<String>)> = crate::auth::load_auth_state(dir)
        .unwrap()
        .audit
        .iter()
        .filter(|event| event.event_type.contains("transaction"))
        .map(|event| (event.event_type.clone(), event.principal_id.clone()))
        .collect();
    answer(
        row,
        "transaction audit events in this folder's sign-in state",
        format!("{audit_events:?}"),
    );
    Outcome {
        unknown,
        saved,
        plain_after_save,
        file_after_save,
        completed,
        plain_after_complete,
        audit_events,
    }
}

const UNKNOWN: &str = "Err 404 Runtime transaction effect not found";
const SAVED: &str = "Ok";
const COMPLETED: &str = "Err 503 wallet-provider unavailable: wallet provider unavailable";

/// On the CHILD, with the person's verified Wallet context. The direct save
/// of the store is refused with 403, because the person's record is kept on
/// the parent and the child holds no protection for their root; no file is
/// written. The route-level call then finds no stored effect, so it records
/// no audit event and the child's sign-in state stays empty.
#[tokio::test(flavor = "current_thread")]
async fn cs_child_transaction_effect_save_for_the_parent_person() {
    const ROW: &str = "cs_child_transaction_effect_save_for_the_parent_person";
    let person = parent_person(WALLET_CAPSULE_ID);
    let child = person.child.path();
    person.assert_child_holds_only(ROW, &[]);
    let authority = runtime_wallet_authority(&person.on_child).unwrap();
    assert_eq!(authority.verified_context().principal_id(), PERSON);
    let state = ParentPerson::state_on(child);

    let store = small_store(&authority);
    let saved = shown(&save_transaction_effect_store(&state, &store));
    answer(ROW, "save_transaction_effect_store", &saved);
    report_person_files(ROW, "after the direct save:", child);
    assert_eq!(saved, format!("Err 403 {KEPT_ELSEWHERE}"));

    let lookup = RuntimeTransactionLookup::EffectId(EFFECT_ID);
    let completed =
        shown(&complete_runtime_transaction_effect(&state, &authority, lookup, None, None).await);
    answer(
        ROW,
        "complete_runtime_transaction_effect, after the refused save",
        &completed,
    );
    assert_eq!(completed, UNKNOWN);

    let left = person_folders_left(child);
    let left: Vec<&str> = left.iter().map(String::as_str).collect();
    let audit = person.assert_child_holds_only(ROW, &left);
    assert_eq!(audit, 0);
    assert!(!person.parent.path().join(ROOT_DIR).exists());
}

/// Control. On the PARENT, where the person has root protection, the same
/// three steps answer the same, and the store file on disk is an encrypted
/// envelope after each save.
#[tokio::test(flavor = "current_thread")]
async fn cs_parent_transaction_effect_save_is_stored_protected() {
    const ROW: &str = "cs_parent_transaction_effect_save_is_stored_protected";
    let person = parent_person(WALLET_CAPSULE_ID);
    let parent = person.parent.path();
    let outcome = drive(ROW, parent, &person.on_parent).await;
    assert_eq!(outcome.unknown, UNKNOWN);
    assert_eq!(outcome.saved, SAVED);
    assert_eq!(outcome.completed, COMPLETED);
    assert_eq!(tree(&parent.join(ROOT_DIR)), [STORE_FILE]);
    // The file right after the direct save: an envelope, not the plain store.
    assert!(is_envelope(&outcome.file_after_save));
    assert!(outcome
        .file_after_save
        .starts_with(ENVELOPE_START.as_bytes()));
    assert_ne!(outcome.file_after_save, outcome.plain_after_save);
    // The file as it is now, after the route-level call's own save.
    assert_stored_protected(
        parent,
        STORE_FILE,
        &outcome.plain_after_complete,
        &["effect_id", "cs-account", "session_id", ADDRESS],
    );
    assert_eq!(
        outcome.audit_events,
        [(
            "wallet.transaction.requested".to_string(),
            Some(PERSON.to_string())
        )]
    );
    person.assert_child_holds_only(ROW, &[]);
}
