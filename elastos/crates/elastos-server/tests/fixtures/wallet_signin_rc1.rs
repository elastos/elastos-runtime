//! Frozen production implementation from 2.0.2-rc.1 source
//! 7c1e32366dce2eab2d209a7e5949784b4080302a, src/auth/wallet_signin.rs.
//! Only its test module is omitted. Kept verbatim to exercise real Undo sign-in.
//! Additive wallet authority. The legacy auth file remains the passkey/account owner.
use super::*;
use elastos_runtime::auth::{bitcoin, wallet_signin::*};
use subtle::ConstantTimeEq;

const FILE: &str = "wallet-signin.json";
const SCHEMA: &str = "elastos.auth.wallet-signin/v1";
const TTL: u64 = 180;
const CONTRACT_VERSION: u32 = 2;
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PENDING: usize = 64;
const MAX_METHODS: usize = 128;
pub(crate) const OPERATION: &str = "auth.wallet.method";
pub(crate) const RELAY_NOTICE: &str =
    "Your wallet connects through a relay that can see this computer's internet address.";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Method {
    pub method_id: String,
    pub account_id: String,
    pub connector: String,
    pub address: String,
    pub chain_id: u64,
    pub network: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    witnesses: Vec<String>,
    root_key: Option<String>,
    generation: String,
    // Read and drop the retired trial field; every other field stays strict.
    #[serde(default, skip_serializing, rename = "sign_in_enabled")]
    _retired_sign_in_enabled: Option<serde::de::IgnoredAny>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    #[serde(default)]
    contract_version: u32,
    id: String,
    action: String,
    method: Method,
    origin: String,
    home: String,
    browser: [u8; 32],
    #[serde(default)]
    peer: Option<std::net::IpAddr>,
    nonce: [u8; 32],
    proof_secret: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    actor: Option<AuthSessionGrantV1>,
    #[serde(default)]
    terminal: Terminal,
    proof_consumed: bool,
    local: bool,
    transport_digest: [u8; 32],
    instance_id: String,
    #[serde(default, skip_serializing, rename = "creates_method")]
    _retired_creates_method: Option<serde::de::IgnoredAny>,
    #[serde(default, skip_serializing, rename = "result")]
    _retired_result: Option<serde::de::IgnoredAny>,
    #[serde(default, skip_serializing, rename = "response_digest")]
    _retired_response_digest: Option<serde::de::IgnoredAny>,
    #[serde(default, skip_serializing, rename = "cancelled")]
    _retired_cancelled: Option<serde::de::IgnoredAny>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Terminal {
    #[default]
    Open,
    Committed {
        result: Value,
        response_digest: String,
    },
    Cancelled,
}
impl Pending {
    fn open(&self) -> bool {
        matches!(self.terminal, Terminal::Open)
    }
    fn cancelled(&self) -> bool {
        matches!(self.terminal, Terminal::Cancelled)
    }
    fn retained(&self, now: u64) -> bool {
        // A sign-in receipt lives as long as its session, so expiry of the
        // signing window cannot erase a committed response or revoke a session.
        self.expires_at > now
            || matches!(&self.terminal, Terminal::Committed { result, .. }
            if self.action == "signin" && result["expires_at"].as_u64().is_some_and(|t| t > now))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyAddApproval {
    ceremony_id: String,
    actor: AuthSessionGrantV1,
    approver: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    schema: String,
    methods: Vec<Method>,
    pending: Vec<Pending>,
    sessions: Vec<StoredAuthSession>,
    audit_sequence: u64,
    audit_hash: String,
    #[serde(default)]
    passkey_add: Vec<PasskeyAddApproval>,
}
impl Default for Store {
    fn default() -> Self {
        Self {
            schema: SCHEMA.into(),
            methods: vec![],
            pending: vec![],
            sessions: vec![],
            audit_sequence: 0,
            audit_hash: String::new(),
            passkey_add: vec![],
        }
    }
}

#[derive(Debug)]
pub(crate) struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet_signin_refused")
    }
}
impl std::error::Error for Refused {}
#[derive(Debug)]
pub(crate) struct Capacity;
impl std::fmt::Display for Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet_attempts_busy")
    }
}
impl std::error::Error for Capacity {}
#[derive(Debug)]
pub(crate) struct Conflict;
impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet_method_conflict")
    }
}
impl std::error::Error for Conflict {}
fn same_grant(a: &AuthSessionGrantV1, b: &AuthSessionGrantV1) -> bool {
    a.session_id == b.session_id
        && a.grant_id == b.grant_id
        && a.principal_id == b.principal_id
        && a.proof_binding_id == b.proof_binding_id
}
fn same_actor(a: Option<&AuthSessionGrantV1>, b: Option<&AuthSessionGrantV1>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => same_grant(a, b),
        _ => false,
    }
}

fn require(value: bool) -> anyhow::Result<()> {
    if value {
        Ok(())
    } else {
        Err(Refused.into())
    }
}
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn secret(value: &str) -> anyhow::Result<[u8; 32]> {
    require(value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))?;
    let bytes: [u8; 32] = hex::decode(value)?.try_into().map_err(|_| Refused)?;
    require(bytes != [0; 32])?;
    Ok(bytes)
}
fn path(data: &Path) -> anyhow::Result<PathBuf> {
    Ok(auth_state_path(data)?.with_file_name(FILE))
}
fn read(data: &Path) -> anyhow::Result<Store> {
    let path = path(data)?;
    if let Some(parent) = path.parent() {
        ensure_regular_auth_parent(data, parent)?;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Store::default()),
        Err(err) => return Err(err.into()),
    };
    require(file.metadata()?.is_file() && file.metadata()?.len() <= MAX_BYTES)?;
    let mut bytes = vec![];
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= MAX_BYTES)?;
    let store: Store = serde_json::from_slice(&bytes)?;
    require(store.schema == SCHEMA)?;
    Ok(store)
}
fn write(data: &Path, store: &Store) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(store)?;
    require(bytes.len() as u64 <= MAX_BYTES)?;
    write_secret_bytes_atomic(&path(data)?, &bytes)?;
    Ok(())
}
fn witnesses(auth: &AuthState, account: &str) -> Vec<String> {
    let mut result: Vec<_> = auth
        .principals
        .iter()
        .filter(|p| p.principal_id == account && active_passkey(p))
        .map(|p| {
            format!(
                "{}:{}",
                p.proof_binding_id,
                hex::encode(digest(
                    &p.proof_binding
                        .passkey
                        .as_ref()
                        .expect("passkey")
                        .public_key
                ))
            )
        })
        .collect();
    result.sort();
    result
}
fn root_key(auth: &AuthState, account: &str) -> Option<String> {
    auth.principal_root_protections
        .iter()
        .find(|p| p.principal_id == account)
        .map(|p| p.data_key_id.clone())
}
fn eligible(auth: &AuthState, method: &Method) -> bool {
    let current = witnesses(auth, &method.account_id);
    method.witnesses.iter().any(|id| current.contains(id))
        && (method.root_key.is_none() || root_key(auth, &method.account_id) == method.root_key)
}
fn live_method<'a>(store: &'a Store, auth: &AuthState, id: &str) -> Option<&'a Method> {
    store
        .methods
        .iter()
        .find(|m| m.method_id == id && eligible(auth, m))
}
fn session_active(store: &Store, auth: &AuthState, session: &StoredAuthSession, now: u64) -> bool {
    session.revoked_at.is_none()
        && session.grant.expires_at > now
        && live_method(store, auth, &session.grant.proof_binding_id)
            .is_some_and(|m| m.account_id == session.grant.principal_id)
}
fn reconcile(store: &mut Store, auth: &AuthState) {
    reconcile_through(store, auth, u64::MAX);
}
fn reconcile_through(store: &mut Store, auth: &AuthState, revocations_through: u64) {
    for pending in &mut store.pending {
        if pending.contract_version != CONTRACT_VERSION
            || !matches!(pending.action.as_str(), "add" | "remove" | "signin")
        {
            pending.terminal = Terminal::Cancelled;
        }
    }
    let last = auth.audit_chain.last();
    if store.audit_sequence > 0 {
        let continuation = auth
            .audit_chain
            .iter()
            .find(|l| l.sequence == store.audit_sequence);
        let continuous = continuation.is_some_and(|l| l.chain_hash == store.audit_hash)
            || auth.audit_chain_anchor.as_ref().is_some_and(|a| {
                a.sequence == store.audit_sequence && a.chain_hash == store.audit_hash
            });
        if !continuous {
            // An old binary may have recovered an account while its bounded audit
            // tail advanced. Missing continuation cannot preserve wallet authority.
            store.methods.clear();
            store.pending.clear();
            store.sessions.clear();
        }
    }
    let reset_accounts: Vec<_> = auth
        .audit_chain
        .iter()
        .filter(|l| l.sequence > store.audit_sequence)
        .filter_map(|l| auth.audit.iter().find(|e| e.event_id == l.event_id))
        .filter(|e| {
            matches!(
                e.event_type.as_str(),
                "auth.owner.recovered"
                    | "auth.principal.recovered"
                    | "auth.recovery_kit.imported"
                    | "auth.recovery_kit.reassigned"
            )
        })
        .filter_map(|e| e.principal_id.as_ref())
        .collect();
    store
        .methods
        .retain(|m| !reset_accounts.contains(&&m.account_id));
    for pending in &mut store.pending {
        if reset_accounts.contains(&&pending.method.account_id)
            || pending
                .actor
                .as_ref()
                .is_some_and(|actor| reset_accounts.contains(&&actor.principal_id))
        {
            pending.terminal = Terminal::Cancelled;
        }
    }
    // A legacy binary cannot see wallet sessions during Undo. Honor its
    // account session revocations when this sidecar next observes the audit.
    let revoked_accounts: Vec<_> = auth
        .audit_chain
        .iter()
        .filter(|l| l.sequence > store.audit_sequence && l.sequence <= revocations_through)
        .filter_map(|l| auth.audit.iter().find(|e| e.event_id == l.event_id))
        .filter(|e| e.event_type == "auth.session.revoked" && e.result == "ok")
        .filter_map(|e| e.principal_id.as_ref())
        .collect();
    store
        .sessions
        .retain(|s| !revoked_accounts.contains(&&s.grant.principal_id));
    let added: Vec<_> = auth
        .audit_chain
        .iter()
        .filter(|l| l.sequence > store.audit_sequence)
        .filter_map(|l| auth.audit.iter().find(|e| e.event_id == l.event_id))
        .filter(|e| e.event_type == "auth.passkey.added" && e.result == "ok")
        .filter_map(|e| Some((e.principal_id.as_deref()?, e.proof_binding_id.as_deref()?)))
        .collect();
    store.methods.retain(|m| {
        eligible(auth, m)
            || ((m.root_key.is_none() || root_key(auth, &m.account_id) == m.root_key)
                && auth.principals.iter().any(|p| {
                    p.principal_id == m.account_id
                        && active_passkey(p)
                        && added.contains(&(p.principal_id.as_str(), p.proof_binding_id.as_str()))
                }))
    });
    for method in &mut store.methods {
        method.witnesses = witnesses(auth, &method.account_id);
        method.root_key = root_key(auth, &method.account_id);
    }
    let live: Vec<_> = store
        .methods
        .iter()
        .map(|m| (m.method_id.clone(), m.generation.clone()))
        .collect();
    let relay_enabled = has_relay_method(store);
    for p in &mut store.pending {
        if p.action == "signin" && p.method.connector == "walletconnect" && !relay_enabled {
            p.terminal = Terminal::Cancelled;
        }
        if p.open()
            && p.action != "add"
            && p.action != "signin"
            && !live
                .iter()
                .any(|(id, g)| *id == p.method.method_id && *g == p.method.generation)
        {
            p.terminal = Terminal::Cancelled;
        }
        if p.action == "signin"
            && !p.method.account_id.is_empty()
            && !p.method.address.is_empty()
            && !live
                .iter()
                .any(|(id, g)| *id == p.method.method_id && *g == p.method.generation)
        {
            p.terminal = Terminal::Cancelled;
        }
    }
    if let Some(last) = last {
        store.audit_sequence = last.sequence;
        store.audit_hash = last.chain_hash.clone();
    }
}
fn mutate<T>(
    data: &Path,
    f: impl FnOnce(&AuthState, &mut Store) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = auth_state_mutation_lock()
        .lock()
        .map_err(|_| anyhow!("auth state mutation lock poisoned"))?;
    let lock = lock_auth_state_file(open_auth_state_lock(data)?)?;
    let auth = load_auth_state_with_identity(data)?.0;
    let mut store = read(data)?;
    let before = serde_json::to_vec(&store)?;
    reconcile(&mut store, &auth);
    let now = now_ts();
    store.pending.retain(|p| p.retained(now));
    store.passkey_add.retain(|p| p.expires_at > now);
    store.sessions.retain(|s| s.grant.expires_at > now);
    let result = f(&auth, &mut store)?;
    if serde_json::to_vec(&store)? != before {
        write(data, &store)?;
    }
    unlock_auth_state_file(lock)?;
    Ok(result)
}
// Called after every current-binary auth commit to keep the bounded legacy audit
// checkpoint current. Reads independently reconcile, including after a crash here.
pub(super) fn observe_auth_commit(
    data: &Path,
    auth: &AuthState,
    previous_audit_sequence: u64,
) -> anyhow::Result<()> {
    if !path(data)?.exists() {
        return Ok(());
    }
    let mut store = read(data)?;
    // Replay missed legacy events, while the current transaction owns the
    // effects of its new events (including targeted single-session revocation).
    reconcile_through(&mut store, auth, previous_audit_sequence);
    write(data, &store)
}
fn loaded(data: &Path) -> anyhow::Result<(AuthState, Store)> {
    let auth = load_auth_state_with_identity(data)?.0;
    let mut store = read(data)?;
    reconcile(&mut store, &auth);
    Ok((auth, store))
}
pub(crate) fn sessions(data: &Path, auth: &AuthState) -> anyhow::Result<Vec<StoredAuthSession>> {
    let mut store = read(data)?;
    reconcile(&mut store, auth);
    Ok(store
        .sessions
        .iter()
        .filter(|s| session_active(&store, auth, s, now_ts()))
        .cloned()
        .collect())
}
pub(crate) fn principal(data: &Path, id: &str) -> anyhow::Result<PrincipalRecord> {
    let (auth, store) = loaded(data)?;
    let m = live_method(&store, &auth, id).ok_or(Refused)?;
    let mut p = auth
        .principals
        .iter()
        .find(|p| p.principal_id == m.account_id && active_passkey(p))
        .cloned()
        .ok_or(Refused)?;
    p.proof_binding_id = m.method_id.clone();
    p.proof_binding = if m.connector == "unisat" {
        ProofBinding {
            kind: elastos_runtime::auth::ProofBindingKind::BtcAddress,
            subject: m.address.clone(),
            chain_id: None,
            verified_at: now_ts(),
            passkey: None,
        }
    } else {
        ProofBinding::evm_account(m.chain_id, &m.address, now_ts())
    };
    Ok(p)
}
pub(crate) fn list(data: &Path, actor: &AuthSessionGrantV1) -> anyhow::Result<Value> {
    mutate(data, |auth, store| {
        require_actor(auth, store, actor, false)?;
        // This snapshot shares completion's lock. An absent open change cannot
        // commit later: expiry/cancellation already retired it on this Home.
        let open_changes: Vec<_> = store
            .pending
            .iter()
            .filter(|p| {
                p.open() && p.action != "signin" && p.method.account_id == actor.principal_id
            })
            .map(|p| &p.id)
            .collect();
        Ok(
            serde_json::json!({"account_id":actor.principal_id,"open_changes":open_changes,"methods":store.methods.iter().filter(|m| m.account_id == actor.principal_id).map(|m| serde_json::json!({"method_id":m.method_id,"connector":m.connector,"address":m.address,"chain_id":m.chain_id,"network":m.network,"sign_in_enabled":true,"created_at":m.created_at,"last_used_at":m.last_used_at})).collect::<Vec<_>>()}),
        )
    })
}
fn require_actor(
    auth: &AuthState,
    store: &Store,
    actor: &AuthSessionGrantV1,
    admin: bool,
) -> anyhow::Result<()> {
    let matches = |s: &StoredAuthSession| {
        s.revoked_at.is_none() && same_grant(&s.grant, actor) && s.grant.expires_at > now_ts()
    };
    require(
        auth.sessions.iter().any(matches)
            || store
                .sessions
                .iter()
                .any(|s| matches(s) && session_active(store, auth, s, now_ts())),
    )?;
    require(auth.principals.iter().any(|p| {
        p.principal_id == actor.principal_id && active_passkey(p) && (!admin || is_admin(p))
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Begin {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub method_id: String,
    #[serde(default)]
    pub connector: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub chain_id: u64,
    #[serde(default)]
    pub network: String,
    pub browser_secret: String,
    #[serde(default)]
    pub allow_temporary_internet: bool,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct BeginResult {
    pub ceremony_id: String,
    pub message: String,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_token: Option<String>,
    pub instance_id: String,
    pub storage_revision: u64,
}
fn normalize(input: &Begin) -> anyhow::Result<(String, String)> {
    require(matches!(
        input.connector.as_str(),
        "walletconnect" | "metamask" | "unisat"
    ))?;
    require(input.address.len() <= 128 && input.network.len() <= 32)?;
    if input.connector == "unisat" {
        require(input.chain_id == 0)?;
        bitcoin::bitcoin_proof_type_for_address(&input.network, &input.address)
            .map_err(|_| Refused)?;
        // Legacy Base58 is case-sensitive. Bech32 validation permits uniform case.
        let address = bitcoin::bitcoin_address(
            &input.address,
            bitcoin::bitcoin_network(&input.network).map_err(|_| Refused)?,
        )
        .map_err(|_| Refused)?
        .to_string();
        Ok((address, "bitcoin".into()))
    } else {
        require(
            input.chain_id > 0
                && (input.connector != "walletconnect" || matches!(input.chain_id, 20 | 8453)),
        )?;
        elastos_runtime::auth::validate_evm_address(&input.address).map_err(|_| Refused)?;
        Ok((
            elastos_runtime::auth::normalize_evm_address(&input.address),
            String::new(),
        ))
    }
}
fn compatible_relay_method(m: &Method) -> bool {
    m.connector == "walletconnect" && matches!(m.chain_id, 20 | 8453)
}
fn has_relay_method(store: &Store) -> bool {
    store.methods.iter().any(compatible_relay_method)
}
fn same_wallet(a: &Method, b: &Method) -> bool {
    a.address == b.address && a.chain_id == b.chain_id && a.network == b.network
}
fn approval(p: &Pending) -> Value {
    serde_json::json!({"ceremony_id":p.id,"account_id":p.method.account_id,"action":p.action,"method_id":p.method.method_id,"connector":p.method.connector,"address":p.method.address,"chain_id":p.method.chain_id,"network":p.method.network,"authorizes_short_public_walletconnect":p.action == "add" && compatible_relay_method(&p.method)})
}
fn purpose(p: &Pending) -> WalletProofPurpose {
    if p.action == "signin" {
        WalletProofPurpose::SignIn
    } else {
        let account_id = p.method.account_id.clone();
        let method_digest = digest(&format!(
            "{}:{}:{}:{}",
            p.id, p.action, p.method.method_id, p.method.generation
        ));
        WalletProofPurpose::AddSignInMethod {
            account_id,
            method_digest,
        }
    }
}
fn challenge(p: &Pending) -> anyhow::Result<WalletProofChallenge> {
    Ok(WalletProofChallenge::new(
        WalletProofInput {
            origin: p.origin.clone(),
            uri: format!("{}/home", p.origin),
            home_id: p.home.clone(),
            ceremony_id: p.id.clone(),
            chain_id: p.method.chain_id,
            address: p.method.address.clone(),
            nonce: p.nonce,
            issued_at: p.issued_at,
            ttl_secs: p.expires_at - p.issued_at,
            purpose: purpose(p),
        },
        &p.proof_secret,
    )?)
}
fn message(p: &Pending) -> anyhow::Result<String> {
    if p.action == "remove" || p.method.address.is_empty() {
        return Ok(String::new());
    }
    if p.method.connector != "unisat" {
        return Ok(challenge(p)?.message().into());
    }
    let purpose = purpose(p);
    let sentence = purpose.statement()?;
    let resources = purpose
        .resources(&p.home, &p.id, &p.proof_secret)?
        .into_iter()
        .map(|r| format!("- {r}"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!("{} wants you to sign with your Bitcoin account:\n{}\n\n{}\n\nURI: {}/home\nNetwork: {}\nNonce: {}\nIssued At: {}\nExpiration Time: {}\nResources:\n{}",p.origin,p.method.address,sentence,p.origin,p.method.network,hex::encode(p.nonce),p.issued_at,p.expires_at,resources))
}
fn begin_result(p: &Pending, token: Option<String>) -> anyhow::Result<BeginResult> {
    Ok(BeginResult {
        ceremony_id: p.id.clone(),
        message: message(p)?,
        expires_at: p.expires_at,
        approval: p
            .actor
            .as_ref()
            .map(|_| serde_json::json!({"operation":OPERATION,"request":approval(p),"notice":if p.action == "add" && compatible_relay_method(&p.method) {RELAY_NOTICE} else {""}})),
        attempt_token: token,
        instance_id: p.instance_id.clone(),
        storage_revision: 0,
    })
}
pub(crate) fn begin(
    data: &Path,
    origin: &str,
    home: &str,
    input: Begin,
    actor: Option<AuthSessionGrantV1>,
) -> anyhow::Result<BeginResult> {
    begin_for_peer(data, origin, home, input, actor, None)
}

pub(crate) fn begin_for_peer(
    data: &Path,
    origin: &str,
    home: &str,
    mut input: Begin,
    actor: Option<AuthSessionGrantV1>,
    peer: Option<std::net::IpAddr>,
) -> anyhow::Result<BeginResult> {
    let peer = elastos_identity::webauthn::signin_peer_network(peer);
    let browser = digest(&hex::encode(secret(&input.browser_secret)?));
    if actor.is_none() {
        input.action = "signin".into();
    } else {
        require(input.action != "signin")?;
    }
    require(matches!(input.action.as_str(), "signin" | "add" | "remove"))?;
    let now = now_ts();
    mutate(data, |auth, store| {
        if let Some(actor) = &actor {
            require_actor(auth, store, actor, input.action == "add")?;
        } else {
            require(auth.principals.iter().any(active_passkey))?;
        }
        store
            .pending
            .retain(|p| !p.cancelled() || p.issued_at.saturating_add(60) > now);
        // Cancel frees active capacity, but keeps the rate debit for one minute.
        // The global bound also covers callers that rotate browser commitments.
        let recent: Vec<_> = store
            .pending
            .iter()
            .filter(|p| p.issued_at.saturating_add(60) > now)
            .collect();
        if recent.len() >= MAX_PENDING
            || recent
                .iter()
                .filter(|p| p.browser == browser && p.actor.is_none() == actor.is_none())
                .count()
                >= 32
        {
            return Err(Capacity.into());
        }
        if actor.is_none()
            && store
                .pending
                .iter()
                .filter(|p| p.actor.is_none() && p.open() && p.expires_at > now && p.peer == peer)
                .count()
                >= 8
        {
            return Err(Capacity.into());
        }
        if store
            .pending
            .iter()
            .filter(|p| p.open() && p.expires_at > now)
            .count()
            >= MAX_PENDING
            || store
                .pending
                .iter()
                .filter(|p| p.expires_at > now && p.open())
                .filter(|p| match (&p.actor, &actor) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.session_id == b.session_id,
                    _ => false,
                })
                .count()
                >= if actor.is_none() { 32 } else { 4 }
        {
            return Err(Capacity.into());
        }
        let mut method = if input.action == "remove" {
            store
                .methods
                .iter()
                .find(|m| {
                    m.method_id == input.method_id
                        && Some(m.account_id.as_str())
                            == actor.as_ref().map(|a| a.principal_id.as_str())
                })
                .cloned()
                .ok_or(Refused)?
        } else {
            let (address, network) = if (actor.is_none() || input.action == "add")
                && input.connector == "walletconnect"
                && input.address.is_empty()
            {
                (String::new(), String::new())
            } else {
                normalize(&input)?
            };
            Method {
                method_id: format!("proof:signin-wallet:{}", random_secret_hex()),
                account_id: actor
                    .as_ref()
                    .map(|a| a.principal_id.clone())
                    .unwrap_or_default(),
                connector: input.connector.clone(),
                address,
                chain_id: input.chain_id,
                network,
                created_at: now,
                last_used_at: None,
                witnesses: vec![],
                root_key: None,
                generation: random_secret_hex(),
                _retired_sign_in_enabled: None,
            }
        };
        if actor.is_none() && !method.address.is_empty() {
            // Unknown addresses receive an indistinguishable challenge.
            if let Some(stored) = store.methods.iter().find(|m| same_wallet(m, &method)) {
                method = stored.clone();
                method.connector = input.connector.clone();
            }
        }
        if input.action == "add" {
            if store.methods.len() >= MAX_METHODS {
                return Err(Capacity.into());
            }
            method.witnesses = witnesses(auth, &method.account_id);
            method.root_key = root_key(auth, &method.account_id);
        }
        if method.connector == "walletconnect" && matches!(input.action.as_str(), "signin" | "add")
        {
            require(input.allow_temporary_internet)?;
            if actor.is_none() {
                require(has_relay_method(store))?;
            }
        }
        let token = random_secret_hex();
        let mut pending = Pending {
            _retired_creates_method: None,
            _retired_result: None,
            _retired_response_digest: None,
            _retired_cancelled: None,
            contract_version: CONTRACT_VERSION,
            id: format!("ceremony:{}", random_secret_hex()),
            action: input.action,
            method,
            origin: origin.into(),
            home: home.into(),
            browser,
            peer,
            nonce: [0; 32],
            proof_secret: [0; 32],
            issued_at: now,
            expires_at: now + TTL,
            actor,
            terminal: Terminal::Open,
            proof_consumed: false,
            local: false,
            transport_digest: digest(&token),
            instance_id: random_secret_hex(),
        };
        rand::rngs::OsRng.fill_bytes(&mut pending.nonce);
        rand::rngs::OsRng.fill_bytes(&mut pending.proof_secret);
        if let Some(actor) = &pending.actor {
            pending.expires_at = pending.expires_at.min(actor.expires_at);
        }
        let result = begin_result(
            &pending,
            (pending.method.connector == "walletconnect"
                && matches!(pending.action.as_str(), "signin" | "add"))
            .then_some(token),
        )?;
        store.pending.push(pending);
        Ok(result)
    })
}
fn pending<'a>(
    store: &'a Store,
    id: &str,
    browser: &str,
    origin: &str,
) -> anyhow::Result<&'a Pending> {
    let candidate = store.pending.iter().find(|p| p.id == id).ok_or(Refused)?;
    let expected = digest(&hex::encode(secret(browser)?));
    require(
        bool::from(candidate.browser.ct_eq(&expected))
            && candidate.origin == origin
            && !candidate.cancelled()
            && candidate.retained(now_ts()),
    )?;
    Ok(candidate)
}
pub(crate) fn intent(
    data: &Path,
    id: &str,
    browser: &str,
    origin: &str,
    actor: &AuthSessionGrantV1,
) -> anyhow::Result<Value> {
    mutate(data, |auth, store| {
        let p = pending(store, id, browser, origin)?;
        require_actor(auth, store, actor, p.action == "add")?;
        require(same_actor(p.actor.as_ref(), Some(actor)))?;
        Ok(approval(p))
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Complete {
    pub ceremony_id: String,
    pub browser_secret: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub signature_type: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub step_up_token: String,
}
impl WalletProofStore for Store {
    type Error = anyhow::Error;
    fn insert_if_absent(
        &mut self,
        key: WalletProofUse,
        _: u64,
        _: &WalletProofResult,
    ) -> anyhow::Result<()> {
        let pending = self
            .pending
            .iter_mut()
            .find(|p| p.home == key.home_id() && &p.nonce == key.nonce())
            .ok_or(Refused)?;
        require(!pending.proof_consumed)?;
        pending.proof_consumed = true;
        Ok(())
    }
}
fn verify(store: &mut Store, p: &Pending, input: &Complete) -> anyhow::Result<()> {
    require(input.signature.len() <= 16384 && input.public_key.len() <= 132)?;
    if p.method.connector == "unisat" {
        let proof_type =
            bitcoin::bitcoin_proof_type_for_address(&p.method.network, &p.method.address)
                .map_err(|_| Refused)?;
        bitcoin::verify_bitcoin_proof_for_type(
            proof_type,
            &input.signature_type,
            &p.method.network,
            &p.method.address,
            &message(p)?,
            &input.signature,
            Some(&input.public_key),
        )
        .map_err(|_| Refused)?;
    } else {
        require(matches!(
            input.signature_type.as_str(),
            "" | "personal_sign"
        ))?;
        let signature = hex::decode(
            input
                .signature
                .strip_prefix("0x")
                .unwrap_or(&input.signature),
        )
        .map_err(|_| Refused)?;
        let proof = challenge(p)?.verify(
            &message(p)?,
            &signature,
            &purpose(p),
            &p.proof_secret,
            now_ts(),
        )?;
        // The surrounding locked file transaction commits this verification's
        // single-use terminal AND authority effect together, or neither.
        proof.consume(store)?;
    }
    Ok(())
}
pub(crate) fn complete(
    data: &Path,
    origin: &str,
    input: &Complete,
    actor: Option<&AuthSessionGrantV1>,
    approve: impl FnOnce(&Value) -> anyhow::Result<()>,
) -> anyhow::Result<Value> {
    let result = mutate(data, |auth, store| {
        let p = pending(store, &input.ceremony_id, &input.browser_secret, origin)?.clone();
        require(same_actor(p.actor.as_ref(), actor))?;
        if let Some(actor) = actor {
            require_actor(auth, store, actor, p.action == "add")?;
        }
        let response_digest = hex::encode(digest(&format!(
            "{}:{}:{}",
            input.signature, input.signature_type, input.public_key
        )));
        if let Terminal::Committed {
            result,
            response_digest: saved_digest,
        } = &p.terminal
        {
            require(p.expires_at > now_ts() && saved_digest == &response_digest)?;
            if p.action == "signin" {
                require(store.sessions.iter().any(|s| {
                    Some(s.grant.session_id.as_str()) == result["session_id"].as_str()
                        && session_active(store, auth, s, now_ts())
                }))?;
            }
            return Ok(result.clone());
        }
        if matches!(p.action.as_str(), "add" | "signin") {
            verify(store, &p, input)?;
        }
        let result = if p.action == "signin" {
            let index = store
                .methods
                .iter()
                .position(|m| {
                    m.method_id == p.method.method_id
                        && m.generation == p.method.generation
                        && eligible(auth, m)
                        && same_wallet(m, &p.method)
                })
                .ok_or(Refused)?;
            let m = &mut store.methods[index];
            m.last_used_at = Some(now_ts());
            let now = now_ts();
            if store.sessions.len() >= 1024 {
                return Err(Capacity.into());
            }
            let grant = AuthSessionGrantV1 {
                schema: AuthSessionGrantV1::SCHEMA.into(),
                session_id: format!("auth:wallet:{}", random_secret_hex()),
                grant_id: format!("grant:{}", random_secret_hex()),
                principal_id: m.account_id.clone(),
                proof_binding_id: m.method_id.clone(),
                issued_at: now,
                expires_at: now + AUTH_SESSION_TTL_SECS,
                apps: vec!["home".into(), "system".into()],
            };
            store.sessions.push(StoredAuthSession {
                grant: grant.clone(),
                revoked_at: None,
            });
            serde_json::to_value(grant)?
        } else {
            // Consume passkey approval only after proof/ownership validation. A
            // failed write leaves authority unchanged; retry needs new approval.
            let creates_method = p.action == "add";
            if creates_method {
                if store.methods.len() >= MAX_METHODS {
                    return Err(Capacity.into());
                }
                if store.methods.iter().any(|m| same_wallet(m, &p.method)) {
                    return Err(Conflict.into());
                }
            } else {
                require(store.methods.iter().any(|m| {
                    m.method_id == p.method.method_id
                        && m.generation == p.method.generation
                        && m.account_id == p.method.account_id
                }))?;
            }
            approve(&approval(&p))?;
            if creates_method {
                let mut method = p.method.clone();
                method.witnesses = witnesses(auth, &method.account_id);
                method.root_key = root_key(auth, &method.account_id);
                store.methods.push(method);
            } else if p.action == "remove" {
                store.methods.retain(|m| m.method_id != p.method.method_id);
            }
            if p.action == "remove" {
                for s in &mut store.sessions {
                    if s.grant.proof_binding_id == p.method.method_id {
                        s.revoked_at = Some(now_ts());
                    }
                }
                for other in &mut store.pending {
                    if (other.method.method_id == p.method.method_id
                        || same_wallet(&other.method, &p.method))
                        && other.id != p.id
                    {
                        other.terminal = Terminal::Cancelled;
                    }
                }
            }
            serde_json::json!({"status":if p.action == "remove" {"removed"} else {"complete"},"method_id":p.method.method_id,"sign_in_enabled":p.action == "add"})
        };
        let saved = store
            .pending
            .iter_mut()
            .find(|q| q.id == p.id)
            .ok_or(Refused)?;
        saved.terminal = Terminal::Committed {
            result: result.clone(),
            response_digest,
        };
        reconcile(store, auth);
        Ok(result)
    })?;
    if result.get("session_id").is_some() {
        let grant: AuthSessionGrantV1 = serde_json::from_value(result.clone())?;
        // The sidecar owns the committed grant. The auth owner signs its audit
        // event before HTTP can issue tokens; a lost audit write is retryable.
        mutate_auth_state(data, |auth| {
            let store = read(data)?;
            require(store.sessions.iter().any(|session| {
                session.grant.session_id == grant.session_id
                    && session_active(&store, auth, session, now_ts())
            }))?;
            if !auth.audit.iter().any(|event| {
                event.event_type == "auth.session.granted"
                    && event.session_id.as_deref() == Some(&grant.session_id)
            }) {
                let event = sign_audit_event(
                    data,
                    RuntimeAuditEventV1 {
                        schema: RuntimeAuditEventV1::SCHEMA.into(),
                        event_id: format!("audit:{}", random_secret_hex()),
                        event_type: "auth.session.granted".into(),
                        principal_id: Some(grant.principal_id.clone()),
                        proof_binding_id: Some(grant.proof_binding_id.clone()),
                        session_id: Some(grant.session_id.clone()),
                        challenge_id: Some(input.ceremony_id.clone()),
                        capsule_id: None,
                        result: "ok".into(),
                        reason: "Wallet sign-in".into(),
                        occurred_at: grant.issued_at,
                        signer_did: None,
                        signature: None,
                    },
                )?;
                push_audit_event(data, auth, event)?;
            }
            Ok(())
        })?;
    }
    Ok(result)
}

pub(crate) fn cancel(data: &Path, id: &str, browser: &str, origin: &str) -> anyhow::Result<()> {
    mutate(data, |_, store| {
        // Check secret on repeats as well; unknown IDs disclose no state.
        let p = store
            .pending
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Refused)?;
        require(
            p.origin == origin
                && bool::from(p.browser.ct_eq(&digest(&hex::encode(secret(browser)?)))),
        )?;
        if let Terminal::Committed { result, .. } = &p.terminal {
            if let Some(id) = result["session_id"].as_str() {
                for s in &mut store.sessions {
                    if s.grant.session_id == id {
                        s.revoked_at = Some(now_ts());
                    }
                }
            }
        } else {
            p.terminal = Terminal::Cancelled;
        }
        Ok(())
    })
}
pub(crate) fn select(
    data: &Path,
    id: &str,
    browser: &str,
    origin: &str,
    address: String,
    chain_id: u64,
) -> anyhow::Result<BeginResult> {
    mutate(data, |_, store| {
        let mut p = pending(store, id, browser, origin)?.clone();
        require(
            matches!(p.action.as_str(), "signin" | "add")
                && p.method.connector == "walletconnect"
                && p.method.address.is_empty()
                && p.open(),
        )?;
        let input = Begin {
            action: String::new(),
            method_id: String::new(),
            connector: "walletconnect".into(),
            address,
            chain_id,
            network: String::new(),
            browser_secret: String::new(),
            allow_temporary_internet: false,
        };
        let (address, _) = normalize(&input)?;
        p.method.address = address;
        p.method.chain_id = chain_id;
        if let Some(m) = store
            .methods
            .iter()
            .find(|m| p.action == "signin" && same_wallet(m, &p.method))
        {
            p.method = m.clone();
            p.method.connector = "walletconnect".into();
        }
        let result = begin_result(&p, None)?;
        *store
            .pending
            .iter_mut()
            .find(|q| q.id == id)
            .ok_or(Refused)? = p;
        Ok(result)
    })
}
pub(crate) fn update_session(
    data: &Path,
    id: &str,
    grant: Option<AuthSessionGrantV1>,
    revoked_at: Option<u64>,
) -> anyhow::Result<()> {
    update_session_approved(data, id, grant, revoked_at, || Ok(()))
}
pub(crate) fn update_session_approved(
    data: &Path,
    id: &str,
    grant: Option<AuthSessionGrantV1>,
    revoked_at: Option<u64>,
    approve: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    mutate(data, |auth, store| {
        let current = store
            .sessions
            .iter()
            .find(|s| s.grant.session_id == id)
            .ok_or(Refused)?;
        require(session_active(store, auth, current, now_ts()))?;
        if let Some(g) = &grant {
            require(
                g.session_id == current.grant.session_id
                    && g.grant_id == current.grant.grant_id
                    && g.principal_id == current.grant.principal_id
                    && g.proof_binding_id == current.grant.proof_binding_id,
            )?;
        }
        approve()?;
        let s = store
            .sessions
            .iter_mut()
            .find(|s| s.grant.session_id == id)
            .ok_or(Refused)?;
        if let Some(g) = grant {
            s.grant = g;
        }
        s.revoked_at = revoked_at;
        Ok(())
    })
}

pub(crate) fn approval_intent(
    data: &Path,
    id: &str,
    actor: &AuthSessionGrantV1,
) -> anyhow::Result<Value> {
    mutate(data, |auth, store| {
        let p = store
            .pending
            .iter()
            .find(|p| p.id == id && !p.cancelled() && p.expires_at > now_ts() && p.open())
            .ok_or(Refused)?;
        require_actor(auth, store, actor, p.action == "add")?;
        require(same_actor(p.actor.as_ref(), Some(actor)))?;
        Ok(approval(p))
    })
}

pub(crate) struct AttemptContext {
    pub ceremony_id: String,
    pub instance_id: String,
    pub storage_revision: u64,
    pub expires_at: u64,
    pub local: bool,
    pub session_id: Option<String>,
}
pub(crate) fn attempt_context(
    data: &Path,
    token: &str,
    instance: &str,
    now: u64,
) -> anyhow::Result<AttemptContext> {
    secret(token)?;
    let (auth, store) = loaded(data)?;
    let p = store
        .pending
        .iter()
        .find(|p| {
            bool::from(p.transport_digest.ct_eq(&digest(token)))
                && p.instance_id == instance
                && p.method.connector == "walletconnect"
                && matches!(p.action.as_str(), "signin" | "add")
                && !p.cancelled()
                && p.open()
                && p.expires_at > now
        })
        .ok_or(Refused)?;
    if let Some(actor) = &p.actor {
        require_actor(&auth, &store, actor, true)?;
    }
    Ok(AttemptContext {
        ceremony_id: p.id.clone(),
        instance_id: p.instance_id.clone(),
        storage_revision: 0,
        expires_at: p.expires_at,
        local: p.local,
        session_id: p.actor.as_ref().map(|a| a.session_id.clone()),
    })
}
pub(crate) fn set_transport_local(data: &Path, id: &str, local: bool) -> anyhow::Result<()> {
    mutate(data, |_, store| {
        let p = store
            .pending
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Refused)?;
        p.local = local;
        Ok(())
    })
}
pub(crate) fn expire_attempt(data: &Path, id: &str, instance: &str) -> anyhow::Result<()> {
    mutate(data, |_, store| {
        if let Some(p) = store
            .pending
            .iter_mut()
            .find(|p| p.id == id && p.instance_id == instance)
        {
            if p.open() {
                p.terminal = Terminal::Cancelled;
            }
        }
        Ok(())
    })
}

pub(crate) fn inactive_attempts(data: &Path) -> anyhow::Result<Vec<String>> {
    let (auth, store) = loaded(data)?;
    Ok(store
        .pending
        .iter()
        .filter(|p| {
            !p.open()
                || p.expires_at <= now_ts()
                || p.actor
                    .as_ref()
                    .is_some_and(|a| require_actor(&auth, &store, a, true).is_err())
        })
        .map(|p| p.id.clone())
        .collect())
}

pub(crate) fn remember_passkey_add(
    data: &Path,
    ceremony: &str,
    actor: &AuthSessionGrantV1,
    approver: &str,
) -> anyhow::Result<()> {
    mutate(data, |auth, store| {
        require_actor(auth, store, actor, true)?;
        require(auth.principals.iter().any(|p| {
            p.principal_id == actor.principal_id
                && p.proof_binding_id == approver
                && active_passkey(p)
        }))?;
        if store.passkey_add.len() >= MAX_PENDING {
            return Err(Capacity.into());
        }
        store.passkey_add.push(PasskeyAddApproval {
            ceremony_id: ceremony.into(),
            actor: actor.clone(),
            approver: approver.into(),
            expires_at: (now_ts() + TTL).min(actor.expires_at),
        });
        Ok(())
    })
}
pub(crate) fn passkey_add_approver(
    data: &Path,
    ceremony: &str,
    actor: &AuthSessionGrantV1,
) -> anyhow::Result<PrincipalRecord> {
    let (auth, store) = loaded(data)?;
    require_actor(&auth, &store, actor, true)?;
    let approval = store
        .passkey_add
        .iter()
        .find(|p| {
            p.ceremony_id == ceremony && p.expires_at > now_ts() && same_grant(&p.actor, actor)
        })
        .ok_or(Refused)?;
    auth.principals
        .into_iter()
        .find(|p| {
            p.proof_binding_id == approval.approver
                && p.principal_id == actor.principal_id
                && active_passkey(p)
        })
        .ok_or_else(|| Refused.into())
}

pub(crate) fn availability(data: &Path) -> anyhow::Result<(bool, bool, Vec<&'static str>)> {
    let (_, store) = loaded(data)?;
    let mut connectors = Vec::new();
    if store.methods.iter().any(|m| m.connector != "unisat") {
        connectors.push("metamask");
    }
    if store.methods.iter().any(|m| m.connector == "unisat") {
        connectors.push("unisat");
    }
    if has_relay_method(&store) {
        connectors.push("walletconnect");
    }
    Ok((!connectors.is_empty(), has_relay_method(&store), connectors))
}

