//! Fixture for the `cs_*` rows. A person signs in on a parent Runtime
//! with a passkey and has root protection there, so the parent stores their
//! data as an encrypted envelope. The rows then call the save functions on a
//! child Runtime's data folder with that person's verified launch context and
//! check what each save does: its result, the files it leaves, and whether
//! each file's bytes are the plain input or an envelope.
//!
//! The rows live beside the private functions they call: `home_rows.rs`,
//! `transaction_rows.rs`, `home_agent_row.rs` and `assistant_row.rs` in the
//! `cs_child_saves` folder, each mounted from its production file as a
//! test-only module.
//!
//! What stands in for a real child, and where it differs:
//!
//! - The child's data folder. A real child's folder is under the parent's
//!   `managed-runtimes/<kind>/home/…` (runtime_control.rs,
//!   `managed_runtime_child_home_dir`). Here it is a second, separate temp
//!   folder, not placed under the parent's.
//! - The parent's sign-in state. A real child is told where it is by the
//!   process environment variable `ELASTOS_HOME_LAUNCH_TRUSTED_AUTH_DATA_DIR`,
//!   which the parent sets when it starts the child (runtime_control.rs) and
//!   `home_launch_auth_data_dir` reads (gateway_home_token.rs). The rows set
//!   no environment variable. They use the test-only thread-local the same
//!   function checks first, which only the thread that set it sees, so every
//!   call a row makes stays on the test thread.
//! - The signer. A real child verifies a launch token against the parent's
//!   DID, read from the process environment variable
//!   `ELASTOS_HOME_LAUNCH_TRUSTED_SIGNER_DID` (gateway.rs,
//!   `load_existing_gateway_runtime_did`). The fixture hands the parent's DID
//!   to the same verifier through its test-only entry.
//! - The person's record. Production enrollment writes it after a WebAuthn
//!   ceremony. The fixture writes it with
//!   `upsert_principal_for_binding_as_role_named` and a made-up public key,
//!   and stores test root protection with
//!   `store_test_principal_root_protection`. The session grant and the token
//!   are made by the production calls.
//! - The routes. The rows call private functions the routes call after they
//!   have verified the token; each row names its entry. No row sends an HTTP
//!   request, so the routes' header, cookie and origin checks are not run.

use super::*;
use crate::api::gateway::gateway_home_token::{
    require_home_launch_token_value_from_expected_did_for_test as verify_with_signer,
    TestHomeLaunchAuthDataDir,
};
use crate::auth::{PasskeySessionPurpose, PasskeySessionRequest};

const RP_ID: &str = "elastos.elacitylabs.com";
const ORIGIN: &str = "https://elastos.elacitylabs.com";
const CREDENTIAL: &str = "cs-parent-passkey";
const PUBLIC_KEY: &str = "cs-parent-public-key";

/// `person:local:` + the first 16 bytes of
/// sha256("passkey-credential:elastos.elacitylabs.com:cs-parent-passkey").
pub(in crate::api) const PERSON: &str = "person:local:fd5069f0960d6bf8473d325abe114cf3";
/// `localhost://Users/` + the first 12 bytes of sha256(PERSON).
pub(in crate::api) const ROOT: &str = "localhost://Users/c2ee6e1b81f244f49fa43ca4";
/// The person's root as a folder under a data folder.
pub(in crate::api) const ROOT_DIR: &str = "Users/c2ee6e1b81f244f49fa43ca4";
/// The `schema` value of the envelope `write_principal_root_object` writes
/// under root protection (auth.rs, `PRINCIPAL_ROOT_OBJECT_SCHEMA`).
pub(in crate::api) const ENVELOPE_SCHEMA: &str = "elastos.principal-root.object/v1";
/// The first bytes of every such envelope for this person: the pretty-printed
/// JSON starts with the schema and the person's id.
pub(in crate::api) const ENVELOPE_START: &str = "{\n  \"schema\": \"elastos.principal-root.object/v1\",\n  \"principal_id\": \"person:local:fd5069f0960d6bf8473d325abe114cf3\",\n  \"lo";

/// The parent's passkey person, their parent, and a child Runtime's folder.
pub(in crate::api) struct ParentPerson {
    pub(in crate::api) parent: tempfile::TempDir,
    pub(in crate::api) child: tempfile::TempDir,
    /// What the child's verifier built from the parent-signed token.
    pub(in crate::api) on_child: RequiredHomeLaunchToken,
    /// What the parent's own verifier built from the same token.
    pub(in crate::api) on_parent: RequiredHomeLaunchToken,
    /// Keeps `home_launch_auth_data_dir` answering the parent's folder on
    /// this thread for the row's body. See the module comment.
    _auth: TestHomeLaunchAuthDataDir,
}

fn owner_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// What the parent stores for the person (a stand-in for enrollment), then
/// the production grant call a passkey sign-in ends in.
fn sign_in_on_parent(parent: &std::path::Path) -> AuthSessionGrantV1 {
    let now = crate::auth::now_ts();
    let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
        credential_id: CREDENTIAL.to_string(),
        public_key: PUBLIC_KEY.to_string(),
        sign_count: 1,
        user_verified: true,
        origin: ORIGIN.to_string(),
        rp_id: RP_ID.to_string(),
        created_at: now,
        last_used_at: now,
        revoked_at: None,
    });
    let id = crate::auth::passkey_credential_principal_id(RP_ID, CREDENTIAL).unwrap();
    let record = crate::auth::upsert_principal_for_binding_as_role_named(
        parent,
        binding,
        id,
        crate::auth::RuntimePrincipalRole::Admin,
        Some("Parent Person"),
        now,
    )
    .unwrap();
    assert_eq!(record.principal_id, PERSON);
    assert_eq!(record.localhost_root, ROOT);
    crate::auth::store_test_principal_root_protection(parent, PERSON);
    let credential = elastos_identity::StoredCredential {
        credential_id: CREDENTIAL.to_string(),
        public_key: PUBLIC_KEY.to_string(),
        sign_count: 2,
        rp_id: RP_ID.to_string(),
    };
    let grant = crate::auth::grant_passkey_session(
        parent,
        PasskeySessionRequest {
            credential: &credential,
            origin: ORIGIN,
            user_verified: true,
            display_name: None,
            profile_display_name: None,
            reason: "cs parent passkey sign-in",
            purpose: PasskeySessionPurpose::SignIn,
        },
    )
    .unwrap();
    assert_eq!(grant.apps, ["home", "system"]);
    assert_eq!(grant.principal_id, PERSON);
    grant
}

/// The person signs in on the parent and opens `app` from the parent's Home:
/// the parent signs a Home projection token for them. The child verifies it
/// against the parent's DID and the parent's sign-in state; the parent
/// verifies the same token against its own.
pub(in crate::api) fn parent_person(app: &str) -> ParentPerson {
    let parent = owner_only_dir();
    let child = owner_only_dir();
    let (_, parent_did) = elastos_identity::load_or_create_did(parent.path()).unwrap();
    let (_, child_did) = elastos_identity::load_or_create_did(child.path()).unwrap();
    assert_ne!(parent_did, child_did);
    let grant = sign_in_on_parent(parent.path());
    let signed_in = HomeLaunchTokenContext {
        principal_id: grant.principal_id.clone(),
        session_id: grant.session_id.clone(),
        proof_binding_id: Some(grant.proof_binding_id.clone()),
        grant_id: grant.grant_id.clone(),
    };
    let token =
        issue_home_projection_launch_token_with_context(parent.path(), app, app, &signed_in)
            .unwrap();
    let auth = set_test_home_launch_auth_data_dir(parent.path());
    // The child: the parent's DID as signer, and the sign-in state its own
    // `home_launch_auth_data_dir` names, which is the parent's.
    let child_auth_dir = home_launch_auth_data_dir(child.path());
    assert_eq!(child_auth_dir, parent.path());
    let on_child = verify_with_signer(&token, &[app], parent_did, &child_auth_dir).unwrap();
    // The same token is refused when the signer expected is the child's own.
    let own = verify_with_signer(&token, &[app], child_did, &child_auth_dir);
    assert!(
        own.is_err(),
        "the child's own DID does not verify the token"
    );
    // The parent: its production verifier for a carried token.
    let on_parent = require_carried_home_launch_token(parent.path(), &token, &[app]).unwrap();
    assert_eq!(on_child.context, on_parent.context);
    assert_eq!(on_child.context, signed_in);
    assert_eq!(on_child.context.principal_id, PERSON);
    assert_eq!(on_child.launch_context.authority_actor, "home");
    assert_eq!(on_child.launch_context.executable_actor, app);
    let proof = on_child.context.proof_binding_id.as_deref().unwrap();
    assert!(proof.starts_with("proof:passkey:"), "{proof}");
    let person = ParentPerson {
        parent,
        child,
        on_child,
        on_parent,
        _auth: auth,
    };
    // The parent stores the person's record, protection and session.
    let state = crate::auth::load_auth_state(person.parent.path()).unwrap();
    assert_eq!(state.principals.len(), 1);
    assert_eq!(state.principal_root_protections.len(), 1);
    assert_eq!(state.sessions.len(), 1);
    assert_eq!(state.principals[0].principal_id, PERSON);
    assert_eq!(state.principal_root_protections[0].principal_id, PERSON);
    assert_eq!(state.sessions[0].grant.principal_id, PERSON);
    person
}

/// Every file under `dir`, and every folder with nothing in it (shown with a
/// trailing `/`), as paths relative to `dir`. A link is listed, not followed.
pub(in crate::api) fn tree(dir: &std::path::Path) -> Vec<String> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        let mut entries = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            entries += 1;
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(base, &path, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().display().to_string());
            }
        }
        if entries == 0 && dir != base {
            out.push(format!("{}/", dir.strip_prefix(base).unwrap().display()));
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// A path under the person's root, as `tree` reports it.
pub(in crate::api) fn under_person(relative: &str) -> String {
    format!("{ROOT_DIR}/{relative}")
}

/// Whether a file's bytes are the envelope `write_principal_root_object`
/// writes under root protection: a JSON object with exactly the envelope's
/// eight fields and its schema value.
pub(in crate::api) fn is_envelope(bytes: &[u8]) -> bool {
    let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(bytes) else {
        return false;
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    keys == [
        "cipher",
        "ciphertext",
        "data_key_id",
        "localhost_root",
        "nonce",
        "object_uri",
        "principal_id",
        "schema",
    ] && object["schema"] == ENVELOPE_SCHEMA
}

/// At most the first 120 bytes of `bytes`, with anything unprintable escaped.
pub(in crate::api) fn first_bytes(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(120)];
    String::from_utf8_lossy(head).escape_default().to_string()
}

/// One line of `answers.log`.
pub(in crate::api) fn answer(row: &str, what: &str, value: impl std::fmt::Display) {
    println!("cs-answer | {row} | {what} | {value}");
}

/// Prints, for `answers.log`, every file under the person's root in `dir`:
/// its size, whether it is an envelope, and its first bytes.
pub(in crate::api) fn report_person_files(row: &str, side: &str, dir: &std::path::Path) {
    let root = dir.join(ROOT_DIR);
    if !root.exists() {
        answer(row, &format!("{side} person root"), "not there");
        return;
    }
    for relative in tree(&root) {
        if relative.ends_with('/') {
            answer(row, &format!("{side} folder {relative}"), "empty");
            continue;
        }
        let bytes = std::fs::read(root.join(&relative)).unwrap();
        let kind = if is_envelope(&bytes) {
            "envelope"
        } else {
            "not an envelope"
        };
        answer(
            row,
            &format!("{side} file {relative}"),
            format!(
                "{} bytes, {kind}, first bytes: {}",
                bytes.len(),
                first_bytes(&bytes)
            ),
        );
    }
}

/// The bytes of one file under the person's root in `dir`.
pub(in crate::api) fn read_written(dir: &std::path::Path, relative: &str) -> Vec<u8> {
    let path = dir.join(under_person(relative));
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A file the row wrote is an envelope for this person and this object, its
/// bytes hold none of `plain_markers`, and the parent's own read opens it to
/// `plain`.
pub(in crate::api) fn assert_stored_protected(
    dir: &std::path::Path,
    relative: &str,
    plain: &[u8],
    plain_markers: &[&str],
) {
    let bytes = read_written(dir, relative);
    assert_ne!(bytes, plain, "{relative} is not the plain input");
    assert!(is_envelope(&bytes), "{relative} is an envelope");
    assert!(
        bytes.starts_with(ENVELOPE_START.as_bytes()),
        "{relative} starts as an envelope for the person: {}",
        first_bytes(&bytes)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let object_uri = format!("{ROOT}/{relative}");
    assert_eq!(envelope["schema"], ENVELOPE_SCHEMA);
    assert_eq!(envelope["principal_id"], PERSON);
    assert_eq!(envelope["localhost_root"], ROOT);
    assert_eq!(envelope["object_uri"], object_uri.as_str());
    assert_eq!(envelope["cipher"], "aes-256-gcm");
    let text = String::from_utf8_lossy(&bytes);
    for marker in plain_markers {
        assert!(!text.contains(marker), "{relative} does not show {marker}");
    }
    let path = dir.join(under_person(relative));
    let opened =
        crate::auth::read_principal_root_object(dir, PERSON, ROOT, &object_uri, &path).unwrap();
    assert_eq!(opened, plain, "{relative} opens to the plain input");
}

/// What a child holds before any row touches it, each with its reason.
pub(in crate::api) const CHILD_OWN: &[&str] = &[
    // The lock file a read of the child's sign-in state leaves; the check
    // below makes such a read itself. It holds no state: no `auth-state.json`
    // is beside it unless a row lists one.
    "ElastOS/System/Auth/audit-chain-required.json.lock",
    // The child's own device key, made by `load_or_create_did`.
    "identity/device.key",
    // The identity store's lock file, made with the key.
    "identity/identity.lock",
];

impl ParentPerson {
    /// The entire child data folder holds exactly `CHILD_OWN` plus `also`, the
    /// child's sign-in state stores no record, no protection and no session
    /// at all (so none for the person), and the child still reads the
    /// parent's sign-in state. Every difference is reported. Returns the
    /// number of audit events the child's sign-in state holds.
    pub(in crate::api) fn assert_child_holds_only(&self, row: &str, also: &[&str]) -> usize {
        let child = self.child.path();
        let mut problems = Vec::new();
        let mut expected: Vec<String> = CHILD_OWN
            .iter()
            .chain(also)
            .map(|s| s.to_string())
            .collect();
        expected.sort();
        let state = crate::auth::load_auth_state(child).unwrap();
        let found = tree(child);
        answer(row, "child data folder holds", format!("{found:?}"));
        answer(
            row,
            "child sign-in state",
            format!(
                "records {}, protections {}, sessions {}, audit events {}",
                state.principals.len(),
                state.principal_root_protections.len(),
                state.sessions.len(),
                state.audit.len()
            ),
        );
        if found != expected {
            problems.push(format!(
                "the child data folder holds {found:#?}, expected exactly {expected:#?}"
            ));
        }
        if !state.principals.is_empty() {
            problems.push("the child's sign-in state stores a record".to_string());
        }
        if !state.principal_root_protections.is_empty() {
            problems.push("the child's sign-in state stores a protection record".to_string());
        }
        if !state.sessions.is_empty() {
            problems.push("the child's sign-in state stores a session".to_string());
        }
        if home_launch_auth_data_dir(child) != self.parent.path() {
            problems.push("the child no longer reads the parent's sign-in state".to_string());
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        state.audit.len()
    }

    /// A gateway state on `dir`. Built by hand so that nothing is written
    /// into the folder.
    pub(in crate::api) fn state_on(dir: &std::path::Path) -> GatewayState {
        GatewayState {
            provider_registry: None,
            collaboration_chat_product_port: None,
            collaboration_presence_product_port: None,
            carrier_endpoint: None,
            collaboration_discovery_service: None,
            browser_internet: Default::default(),
            walletconnect: Default::default(),
            identity_manager: Arc::new(std::sync::OnceLock::new()),
            cache_dir: dir.to_path_buf(),
            data_dir: dir.to_path_buf(),
        }
    }
}

/// The refusal a child gives for a save of a person whose record is kept on
/// the parent (auth.rs, `ProtectedRecordKeptElsewhere`).
pub(in crate::api) const KEPT_ELSEWHERE: &str =
    "protected record is kept only on the Runtime this person signed in on";

/// The result text ends with the kept-elsewhere refusal.
pub(in crate::api) fn assert_kept_elsewhere(what: &str, shown: &str) {
    assert!(
        shown.ends_with(KEPT_ELSEWHERE),
        "{what} is refused as kept elsewhere: {shown}"
    );
}

/// Every entry left under the person's root in `dir`, as `tree` reports it
/// relative to `dir`. The row asserts each one is an empty folder: a refused
/// save writes no file, though a caller may have made the folder first.
pub(in crate::api) fn person_folders_left(dir: &std::path::Path) -> Vec<String> {
    let root = dir.join(ROOT_DIR);
    if !root.exists() {
        return Vec::new();
    }
    let left: Vec<String> = tree(&root).into_iter().map(|r| under_person(&r)).collect();
    for entry in &left {
        assert!(entry.ends_with('/'), "a refused save left the file {entry}");
    }
    left
}

/// The refusal text, with its full cause chain, or None when the call passed.
pub(in crate::api) fn refusal<T>(result: anyhow::Result<T>) -> Option<String> {
    result.err().map(|error| format!("{error:#}"))
}
