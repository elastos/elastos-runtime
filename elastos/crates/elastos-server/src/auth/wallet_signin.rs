//! Additive wallet authority. The legacy auth file remains the passkey/account owner.
use super::*;
use elastos_runtime::auth::{bitcoin, wallet_signin::*};
use subtle::ConstantTimeEq;

const FILE: &str = "wallet-signin.json";
const SCHEMA: &str = "elastos.auth.wallet-signin/v1";
const TTL: u64 = 180;
const CONTRACT_VERSION: u32 = 1;
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PENDING: usize = 64;
const MAX_METHODS: usize = 128;
pub(crate) const OPERATION: &str = "auth.wallet.method";
pub(crate) const RELAY_NOTICE: &str =
    "Your phone wallet connects through a relay that can see this computer's internet address.";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Method {
    pub method_id: String,
    pub account_id: String,
    pub connector: String,
    pub address: String,
    pub chain_id: u64,
    pub network: String,
    pub sign_in_enabled: bool,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    witnesses: Vec<String>,
    root_key: Option<String>,
    generation: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    #[serde(default)]
    contract_version: u32,
    id: String,
    action: String,
    // Read saved ceremonies from the older contract without granting authority.
    #[serde(default, rename = "creates_method", skip_serializing)]
    _legacy_creates_method: bool,
    method: Method,
    origin: String,
    home: String,
    browser: [u8; 32],
    nonce: [u8; 32],
    proof_secret: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    actor: Option<AuthSessionGrantV1>,
    result: Option<Value>,
    response_digest: Option<String>,
    cancelled: bool,
    proof_consumed: bool,
    local: bool,
    transport_digest: [u8; 32],
    instance_id: String,
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
        .find(|m| m.method_id == id && m.sign_in_enabled && eligible(auth, m))
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
    let trial_methods = store.methods.iter().filter(|m| !m.sign_in_enabled).count();
    store.methods.retain(|m| m.sign_in_enabled);
    if trial_methods > 0 {
        tracing::warn!(
            count = trial_methods,
            "Deleted disabled trial wallet sign-in methods"
        );
    }
    for pending in &mut store.pending {
        if pending.contract_version != CONTRACT_VERSION
            || !matches!(pending.action.as_str(), "add" | "remove" | "signin")
        {
            pending.cancelled = true;
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
            pending.cancelled = true;
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
        .map(|m| (m.method_id.clone(), m.generation.clone(), m.sign_in_enabled))
        .collect();
    let relay_enabled = has_relay_method(store);
    for p in &mut store.pending {
        if p.action == "signin" && p.method.connector == "walletconnect" && !relay_enabled {
            p.cancelled = true;
        }
        if p.result.is_none()
            && p.action != "add"
            && p.action != "signin"
            && !live
                .iter()
                .any(|(id, g, _)| *id == p.method.method_id && *g == p.method.generation)
        {
            p.cancelled = true;
        }
        if p.action == "signin"
            && !p.method.account_id.is_empty()
            && !p.method.address.is_empty()
            && !live
                .iter()
                .any(|(id, g, on)| *id == p.method.method_id && *g == p.method.generation && *on)
        {
            p.cancelled = true;
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
    store.pending.retain(|p| p.expires_at > now);
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
        Ok(
            serde_json::json!({"account_id":actor.principal_id,"methods":store.methods.iter().filter(|m| m.account_id == actor.principal_id).map(|m| serde_json::json!({"method_id":m.method_id,"connector":m.connector,"address":m.address,"chain_id":m.chain_id,"network":m.network,"sign_in_enabled":m.sign_in_enabled,"created_at":m.created_at,"last_used_at":m.last_used_at})).collect::<Vec<_>>()}),
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
    store
        .methods
        .iter()
        .any(|m| m.sign_in_enabled && compatible_relay_method(m))
}
fn same_wallet(a: &Method, b: &Method) -> bool {
    a.address == b.address && a.chain_id == b.chain_id && a.network == b.network
}
fn approval(p: &Pending) -> Value {
    serde_json::json!({"ceremony_id":p.id,"account_id":p.method.account_id,"action":p.action,"method_id":p.method.method_id,"connector":p.method.connector,"address":p.method.address,"chain_id":p.method.chain_id,"network":p.method.network,"authorizes_short_public_walletconnect":p.action == "add" && compatible_relay_method(&p.method)})
}
fn purpose(p: &Pending) -> WalletProofPurpose {
    if p.action == "signin" {
        WalletProofPurpose::SignIn {
            account_id: p.id.clone(),
        }
    } else {
        let account_id = p.method.account_id.clone();
        let method_digest = digest(&format!(
            "{}:{}:{}:{}",
            p.id, p.action, p.method.method_id, p.method.generation
        ));
        if p.action == "add" {
            WalletProofPurpose::AddSignInMethod {
                account_id,
                method_digest,
            }
        } else {
            WalletProofPurpose::AddMethod {
                account_id,
                method_digest,
            }
        }
    }
}
fn challenge(p: &Pending) -> anyhow::Result<WalletProofChallenge> {
    Ok(WalletProofChallenge::new(
        WalletProofInput {
            origin: p.origin.clone(),
            uri: format!("{}/home", p.origin),
            home_id: p.home.clone(),
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
    Ok(format!("{} wants you to {} with your Bitcoin account:\n{}\n\nHome: {}\nNetwork: {}\nAction: {}\nIntent: {}\nNonce: {}\nBrowser: {}\nIssued At: {}\nExpiration Time: {}",p.origin,if p.action == "signin" {"sign in".into()} else if p.action == "add" {format!("add this wallet so it can sign in to this Home for account {}", p.method.account_id)} else {"add a sign-in method".into()},p.method.address,p.home,p.method.network,p.action,hex::encode(digest(&approval(p).to_string())),hex::encode(p.nonce),hex::encode(digest(&hex::encode(p.proof_secret))),p.issued_at,p.expires_at))
}
fn begin_result(p: &Pending, token: Option<String>) -> anyhow::Result<BeginResult> {
    Ok(BeginResult {
        ceremony_id: p.id.clone(),
        message: message(p)?,
        expires_at: p.expires_at,
        approval: p
            .actor
            .as_ref()
            .map(|_| serde_json::json!({"operation":OPERATION,"request":approval(p),"notice":if p.action == "add" && compatible_relay_method(&p.method) {RELAY_NOTICE} else {"Confirm this wallet sign-in method change with your passkey."}})),
        attempt_token: token,
        instance_id: p.instance_id.clone(),
        storage_revision: 0,
    })
}
pub(crate) fn begin(
    data: &Path,
    origin: &str,
    home: &str,
    mut input: Begin,
    actor: Option<AuthSessionGrantV1>,
) -> anyhow::Result<BeginResult> {
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
        if store.pending.len() >= MAX_PENDING
            || store
                .pending
                .iter()
                .filter(|p| actor.is_none() || p.result.is_none())
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
                sign_in_enabled: false,
                created_at: now,
                last_used_at: None,
                witnesses: vec![],
                root_key: None,
                generation: random_secret_hex(),
            }
        };
        if actor.is_none() && !method.address.is_empty() {
            // Unknown and disabled addresses receive an indistinguishable challenge.
            if let Some(stored) = store
                .methods
                .iter()
                .find(|m| same_wallet(m, &method) && m.sign_in_enabled)
            {
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
            contract_version: CONTRACT_VERSION,
            id: format!("wallet:{}", random_secret_hex()),
            action: input.action,
            _legacy_creates_method: false,
            method,
            origin: origin.into(),
            home: home.into(),
            browser,
            nonce: [0; 32],
            proof_secret: [0; 32],
            issued_at: now,
            expires_at: now + TTL,
            actor,
            result: None,
            response_digest: None,
            cancelled: false,
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
            && !candidate.cancelled
            && candidate.expires_at > now_ts(),
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
    mutate(data, |auth, store| {
        let p = pending(store, &input.ceremony_id, &input.browser_secret, origin)?.clone();
        require(same_actor(p.actor.as_ref(), actor))?;
        if let Some(actor) = actor {
            require_actor(auth, store, actor, p.action == "add")?;
        }
        let response_digest = hex::encode(digest(&format!(
            "{}:{}:{}",
            input.signature, input.signature_type, input.public_key
        )));
        if let Some(result) = &p.result {
            require(p.response_digest.as_ref() == Some(&response_digest))?;
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
                        && m.sign_in_enabled
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
                method.sign_in_enabled = true;
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
                        other.cancelled = true;
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
        saved.result = Some(result.clone());
        saved.response_digest = Some(response_digest);
        reconcile(store, auth);
        Ok(result)
    })
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
        if let Some(result) = &p.result {
            if let Some(id) = result["session_id"].as_str() {
                for s in &mut store.sessions {
                    if s.grant.session_id == id {
                        s.revoked_at = Some(now_ts());
                    }
                }
            }
        }
        p.cancelled = true;
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
                && p.result.is_none(),
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
            .find(|m| p.action == "signin" && same_wallet(m, &p.method) && m.sign_in_enabled)
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
            .find(|p| p.id == id && !p.cancelled && p.expires_at > now_ts() && p.result.is_none())
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
                && !p.cancelled
                && p.result.is_none()
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
            p.cancelled = true;
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
            p.cancelled
                || p.result.is_some()
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
    if store
        .methods
        .iter()
        .any(|m| m.sign_in_enabled && m.connector != "unisat")
    {
        connectors.push("metamask");
    }
    if store
        .methods
        .iter()
        .any(|m| m.sign_in_enabled && m.connector == "unisat")
    {
        connectors.push("unisat");
    }
    if has_relay_method(&store) {
        connectors.push("walletconnect");
    }
    Ok((!connectors.is_empty(), has_relay_method(&store), connectors))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    const ORIGIN: &str = "http://localhost:4100";
    const BROWSER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    pub(crate) struct Fixture {
        pub data: tempfile::TempDir,
        pub actor: AuthSessionGrantV1,
        key: SigningKey,
        pub(crate) address: String,
    }
    pub(crate) fn fixture() -> Fixture {
        let data = tempfile::tempdir().unwrap();
        let actor = add_account(data.path(), "alice", "alice-key");
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let encoded = key.verifying_key().to_encoded_point(false);
        let address = format!(
            "0x{}",
            hex::encode(&sha3::Keccak256::digest(&encoded.as_bytes()[1..])[12..])
        );
        Fixture {
            data,
            actor,
            key,
            address,
        }
    }
    fn add_account(data: &Path, account: &str, credential: &str) -> AuthSessionGrantV1 {
        let now = now_ts();
        let binding =
            ProofBinding::passkey_webauthn(elastos_runtime::auth::PasskeyWebAuthnBinding {
                credential_id: credential.into(),
                public_key: format!("public-{credential}"),
                sign_count: 0,
                user_verified: true,
                origin: ORIGIN.into(),
                rp_id: "localhost".into(),
                created_at: now,
                last_used_at: now,
                revoked_at: None,
            });
        let p = upsert_principal_for_binding_as_role(
            data,
            binding,
            format!("person:local:{account}"),
            RuntimePrincipalRole::Admin,
            now,
        )
        .unwrap();
        let actor = AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.into(),
            grant_id: format!("grant:{credential}"),
            session_id: format!("auth:{credential}"),
            principal_id: p.principal_id,
            proof_binding_id: p.proof_binding_id,
            issued_at: now,
            expires_at: now + 3600,
            apps: vec!["home".into(), "system".into()],
        };
        store_session_grant(data, actor.clone()).unwrap();
        actor
    }
    fn input(action: &str, method: &str, address: &str) -> Begin {
        serde_json::from_value(serde_json::json!({"action":action,"method_id":method,"connector":"metamask","address":address,"chain_id":20,"browser_secret":BROWSER})).unwrap()
    }
    fn signed(key: &SigningKey, message: &str) -> String {
        let hash = elastos_runtime::auth::ethereum_signed_message_hash(message.as_bytes());
        let (sig, id) = key.sign_prehash_recoverable(&hash).unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(id.to_byte() + 27);
        format!("0x{}", hex::encode(bytes))
    }
    pub(crate) fn completion(f: &Fixture, b: &BeginResult) -> Complete {
        Complete {
            ceremony_id: b.ceremony_id.clone(),
            browser_secret: BROWSER.into(),
            signature: if b.message.is_empty() {
                String::new()
            } else {
                signed(&f.key, &b.message)
            },
            signature_type: "personal_sign".into(),
            public_key: String::new(),
            step_up_token: String::new(),
        }
    }
    fn change(f: &Fixture, action: &str, id: &str) -> String {
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input(action, id, &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        let out = complete(
            f.data.path(),
            ORIGIN,
            &completion(f, &b),
            Some(&f.actor),
            |_| Ok(()),
        )
        .unwrap();
        out["method_id"].as_str().unwrap().into()
    }
    pub(crate) fn enabled(f: &Fixture) -> String {
        change(f, "add", "")
    }
    pub(crate) fn enabled_relay(f: &Fixture) -> String {
        let mut req = input("add", "", &f.address);
        req.connector = "walletconnect".into();
        req.allow_temporary_internet = true;
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            req,
            Some(f.actor.clone()),
        )
        .unwrap();
        let out = complete(
            f.data.path(),
            ORIGIN,
            &completion(f, &b),
            Some(&f.actor),
            |_| Ok(()),
        )
        .unwrap();
        out["method_id"].as_str().unwrap().into()
    }
    #[test]
    fn wallet_metamask_does_not_admit_anonymous_phone_pairing() {
        let f = fixture();
        enabled(&f);
        let (available, relay, connectors) = availability(f.data.path()).unwrap();
        assert!(available);
        assert!(!relay);
        assert_eq!(connectors, vec!["metamask"]);
        let mut req = input("signin", "", "");
        req.connector = "walletconnect".into();
        req.chain_id = 0;
        req.allow_temporary_internet = true;
        assert!(begin(f.data.path(), ORIGIN, "home-test", req, None).is_err());
    }
    #[test]
    fn wallet_one_state_add_is_live_and_retired_actions_are_refused() {
        let f = fixture();
        let id = change(&f, "add", "");
        assert!(principal(f.data.path(), &id).is_ok());
        assert_eq!(signin(&f).proof_binding_id, id);
        for action in ["add_signin", "enable", "disable"] {
            assert!(begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input(action, &id, &f.address),
                Some(f.actor.clone())
            )
            .is_err());
        }
    }
    #[test]
    fn wallet_one_state_load_deletes_disabled_trial_methods_and_invalidates_ceremonies() {
        let f = fixture();
        let id = enabled(&f);
        let session = signin(&f);
        let mut req = input("add", "", &f.address);
        req.chain_id = 8453;
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            req,
            Some(f.actor.clone()),
        )
        .unwrap();
        let proof = completion(&f, &b);
        let file = path(f.data.path()).unwrap();
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        saved["methods"][0]["sign_in_enabled"] = false.into();
        for pending in saved["pending"].as_array_mut().unwrap() {
            pending.as_object_mut().unwrap().remove("contract_version");
        }
        write_secret_bytes_atomic(&file, &serde_json::to_vec(&saved).unwrap()).unwrap();
        #[derive(Clone)]
        struct LogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for LogWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = LogWriter(logs.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(list(f.data.path(), &f.actor).unwrap()["methods"]
                .as_array()
                .unwrap()
                .is_empty());
        });
        let log = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("Deleted disabled trial wallet sign-in methods"),
            "{log}"
        );
        assert!(log.contains("count=1"), "{log}");
        assert!(
            !log.contains(&f.address),
            "migration logs counts, not wallet identities"
        );
        assert!(read(f.data.path()).unwrap().methods.is_empty());
        assert!(principal(f.data.path(), &id).is_err());
        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err());
        assert!(
            complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |_| panic!(
                "old ceremony cannot consume approval"
            ))
            .is_err()
        );
    }
    #[test]
    fn wallet_one_state_legacy_pending_and_completed_ceremonies_are_invalid() {
        for action in ["add", "remove", "signin"] {
            for completed in [false, true] {
                let f = fixture();
                let id = enabled(&f);
                let mut req = input(action, &id, &f.address);
                if action == "add" {
                    req.chain_id = 8453;
                }
                let actor = (action != "signin").then_some(&f.actor);
                let b = begin(f.data.path(), ORIGIN, "home-test", req, actor.cloned()).unwrap();
                let proof = completion(&f, &b);
                if completed {
                    complete(f.data.path(), ORIGIN, &proof, actor, |_| Ok(())).unwrap();
                }
                let file = path(f.data.path()).unwrap();
                let mut saved: Value =
                    serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
                for pending in saved["pending"].as_array_mut().unwrap() {
                    pending.as_object_mut().unwrap().remove("contract_version");
                }
                write_secret_bytes_atomic(&file, &serde_json::to_vec(&saved).unwrap()).unwrap();
                assert!(
                    complete(f.data.path(), ORIGIN, &proof, actor, |_| panic!(
                        "legacy ceremony cannot consume approval"
                    ))
                    .is_err(),
                    "{action}, completed={completed}"
                );
                assert!(
                    list(f.data.path(), &f.actor).is_ok(),
                    "passkey account remains available"
                );
            }
        }
    }
    #[test]
    fn wallet_one_state_removing_final_compatible_method_ends_unselected_pairing() {
        let f = fixture();
        let id = enabled_relay(&f);
        let mut second = input("add", "", &f.address);
        second.chain_id = 8453;
        second.connector = "walletconnect".into();
        second.allow_temporary_internet = true;
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            second,
            Some(f.actor.clone()),
        )
        .unwrap();
        let second = complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &b),
            Some(&f.actor),
            |_| Ok(()),
        )
        .unwrap();
        let mut req = input("signin", "", "");
        req.connector = "walletconnect".into();
        req.chain_id = 0;
        req.allow_temporary_internet = true;
        let pair = begin(f.data.path(), ORIGIN, "home-test", req, None).unwrap();
        change(&f, "remove", &id);
        assert!(
            attempt_context(
                f.data.path(),
                pair.attempt_token.as_deref().unwrap(),
                &pair.instance_id,
                now_ts()
            )
            .is_ok(),
            "the remaining compatible method keeps pairing live"
        );
        change(&f, "remove", second["method_id"].as_str().unwrap());
        assert!(attempt_context(
            f.data.path(),
            pair.attempt_token.as_deref().unwrap(),
            &pair.instance_id,
            now_ts()
        )
        .is_err());
        assert!(select(
            f.data.path(),
            &pair.ceremony_id,
            BROWSER,
            ORIGIN,
            f.address.clone(),
            20
        )
        .is_err());
        assert!(inactive_attempts(f.data.path())
            .unwrap()
            .contains(&pair.ceremony_id));
    }
    #[test]
    fn wallet_add_signin_completes_enabled_atomically() {
        let f = fixture();
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        assert!(list(f.data.path(), &f.actor).unwrap()["methods"]
            .as_array()
            .unwrap()
            .is_empty());
        let expected = b.approval.as_ref().unwrap()["request"].clone();
        assert_eq!(expected["action"], "add");
        assert_eq!(expected["authorizes_short_public_walletconnect"], false);
        assert_ne!(b.approval.as_ref().unwrap()["notice"], RELAY_NOTICE);
        assert_eq!(
            approval_intent(f.data.path(), &b.ceremony_id, &f.actor).unwrap(),
            expected
        );
        let proof = completion(&f, &b);
        assert!(
            complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |request| {
                assert_eq!(request, &expected);
                Err(Refused.into())
            })
            .is_err()
        );
        assert!(read(f.data.path()).unwrap().methods.is_empty());
        assert!(!read(f.data.path()).unwrap().pending[0].proof_consumed);
        let out = complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |request| {
            assert_eq!(request, &expected);
            Ok(())
        })
        .unwrap();
        assert_eq!(out["status"], "complete");
        assert_eq!(out["sign_in_enabled"], true);
        let saved = read(f.data.path()).unwrap();
        assert_eq!(saved.methods.len(), 1);
        assert!(saved.methods[0].sign_in_enabled);
        assert!(saved.pending[0].proof_consumed);
        // A lost reply returns the original result without another approval/effect.
        assert_eq!(
            complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |_| {
                panic!("an identical retry returns its committed result")
            })
            .unwrap(),
            out
        );
        assert_eq!(signin(&f).principal_id, f.actor.principal_id);
    }
    #[test]
    fn wallet_add_signin_and_add_proofs_are_disjoint_and_single_use() {
        for (action, other) in [("add", "legacy_add"), ("add", "signin")] {
            let f = fixture();
            let b = begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input(action, "", &f.address),
                Some(f.actor.clone()),
            )
            .unwrap();
            // Keep nonce, wallet, browser and ceremony equal: only the action changes.
            let mut changed = read(f.data.path()).unwrap().pending[0].clone();
            changed.action = other.into();
            let other = begin_result(&changed, None).unwrap();
            assert_ne!(b.message, other.message);
            assert!(complete(
                f.data.path(),
                ORIGIN,
                &completion(&f, &other),
                Some(&f.actor),
                |_| { panic!("a cross-purpose proof cannot consume approval") }
            )
            .is_err());
            let proof = completion(&f, &b);
            complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |_| Ok(())).unwrap();
            let fresh = begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input(action, "", &f.address),
                Some(f.actor.clone()),
            )
            .unwrap();
            let mut replay = proof;
            replay.ceremony_id = fresh.ceremony_id;
            assert!(
                complete(f.data.path(), ORIGIN, &replay, Some(&f.actor), |_| {
                    panic!("a replay cannot consume approval")
                })
                .is_err()
            );
            assert_eq!(read(f.data.path()).unwrap().methods.len(), 1);
        }
    }
    #[test]
    fn wallet_add_signin_requires_live_admin_at_begin_and_completion() {
        for demote_before_begin in [true, false] {
            let f = fixture();
            add_account(f.data.path(), "bob", "bob-key");
            let b = if demote_before_begin {
                None
            } else {
                Some(
                    begin(
                        f.data.path(),
                        ORIGIN,
                        "home-test",
                        input("add", "", &f.address),
                        Some(f.actor.clone()),
                    )
                    .unwrap(),
                )
            };
            demote_passkey_to_guest(f.data.path(), &f.actor.proof_binding_id, now_ts()).unwrap();
            assert!(begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input("add", "", &f.address),
                Some(f.actor.clone()),
            )
            .is_err());
            if let Some(b) = b {
                assert!(intent(f.data.path(), &b.ceremony_id, BROWSER, ORIGIN, &f.actor).is_err());
                assert!(approval_intent(f.data.path(), &b.ceremony_id, &f.actor).is_err());
                assert!(complete(
                    f.data.path(),
                    ORIGIN,
                    &completion(&f, &b),
                    Some(&f.actor),
                    |_| { panic!("a demoted actor cannot consume approval") }
                )
                .is_err());
            }
            assert!(read(f.data.path()).unwrap().methods.is_empty());
        }
    }
    #[test]
    fn wallet_metamask_add_keeps_relay_permission_off_on_every_chain() {
        for chain in [20, 8453, 1] {
            let f = fixture();
            let mut req = input("add", "", &f.address);
            req.chain_id = chain;
            let b = begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                req,
                Some(f.actor.clone()),
            )
            .unwrap();
            assert!(b.message.contains("Add this wallet so it can sign in"));
            assert!(b.message.contains(&f.actor.principal_id));
            let approval = b.approval.as_ref().unwrap();
            assert_eq!(
                approval["request"]["authorizes_short_public_walletconnect"],
                false
            );
            assert_ne!(approval["notice"], RELAY_NOTICE);
            complete(
                f.data.path(),
                ORIGIN,
                &completion(&f, &b),
                Some(&f.actor),
                |_| Ok(()),
            )
            .unwrap();
        }
    }
    #[test]
    fn walletconnect_add_signin_pairs_selects_and_completes_with_consent() {
        let f = fixture();
        let request = |consent| {
            let mut req = input("add", "", "");
            req.connector = "walletconnect".into();
            req.chain_id = 0;
            req.allow_temporary_internet = consent;
            req
        };
        assert!(begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            request(false),
            Some(f.actor.clone())
        )
        .is_err());
        let pair = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            request(true),
            Some(f.actor.clone()),
        )
        .unwrap();
        assert!(pair.message.is_empty());
        let token = pair.attempt_token.as_ref().unwrap();
        assert!(attempt_context(f.data.path(), token, &pair.instance_id, now_ts()).is_ok());
        let selected = select(
            f.data.path(),
            &pair.ceremony_id,
            BROWSER,
            ORIGIN,
            f.address.clone(),
            8453,
        )
        .unwrap();
        let expected = selected.approval.as_ref().unwrap()["request"].clone();
        assert_eq!(expected["action"], "add");
        assert_eq!(expected["chain_id"], 8453);
        assert_eq!(expected["authorizes_short_public_walletconnect"], true);
        assert_eq!(selected.approval.as_ref().unwrap()["notice"], RELAY_NOTICE);
        let out = complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &selected),
            Some(&f.actor),
            |request| {
                assert_eq!(request, &expected);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(out["sign_in_enabled"], true);
        assert!(attempt_context(f.data.path(), token, &pair.instance_id, now_ts()).is_err());
        let mut req = input("signin", "", &f.address);
        req.chain_id = 8453;
        let signin = begin(f.data.path(), ORIGIN, "home-test", req, None).unwrap();
        let session = complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &signin),
            None,
            |_| panic!("sign-in cannot consume approval"),
        )
        .unwrap();
        assert_eq!(session["principal_id"], f.actor.principal_id);
    }
    pub(crate) fn signin(f: &Fixture) -> AuthSessionGrantV1 {
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("signin", "", &f.address),
            None,
        )
        .unwrap();
        serde_json::from_value(
            complete(f.data.path(), ORIGIN, &completion(f, &b), None, |_| {
                panic!("sign-in never consumes approval")
            })
            .unwrap(),
        )
        .unwrap()
    }
    pub(crate) fn enabled_session_for_actor(
        data: &Path,
        actor: &AuthSessionGrantV1,
    ) -> AuthSessionGrantV1 {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let address = format!(
            "0x{}",
            hex::encode(&sha3::Keccak256::digest(&point.as_bytes()[1..])[12..])
        );
        let mut id = String::new();
        for action in ["add", "signin"] {
            let owner = (action != "signin").then_some(actor);
            let b = begin(
                data,
                ORIGIN,
                "home-test",
                input(action, &id, &address),
                owner.cloned(),
            )
            .unwrap();
            let proof = Complete {
                ceremony_id: b.ceremony_id,
                browser_secret: BROWSER.into(),
                signature: signed(&key, &b.message),
                signature_type: "personal_sign".into(),
                public_key: String::new(),
                step_up_token: String::new(),
            };
            let out = complete(data, ORIGIN, &proof, owner, |_| Ok(())).unwrap();
            if action == "signin" {
                return serde_json::from_value(out).unwrap();
            }
            id = out["method_id"].as_str().unwrap().into();
        }
        unreachable!()
    }
    #[test]
    fn wallet_remove_requires_an_owned_method_id() {
        let f = fixture();
        enabled(&f);
        for id in ["", "proof:signin-wallet:unknown"] {
            assert!(begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input("remove", id, &f.address),
                Some(f.actor.clone())
            )
            .is_err());
        }
        let bob = add_account(f.data.path(), "bob", "bob-key");
        let id = list(f.data.path(), &f.actor).unwrap()["methods"][0]["method_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("remove", &id, &f.address),
            Some(bob)
        )
        .is_err());
    }
    #[test]
    fn wallet_legacy_provisional_enable_cannot_create_method() {
        let f = fixture();
        begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        // Model a saved enable-by-identity ceremony from the older contract.
        let file = path(f.data.path()).unwrap();
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        saved["pending"][0]["action"] = "enable".into();
        saved["pending"][0]["creates_method"] = true.into();
        write_secret_bytes_atomic(&file, &serde_json::to_vec(&saved).unwrap()).unwrap();
        let saved = read(f.data.path()).unwrap();
        let b = begin_result(&saved.pending[0], None).unwrap();
        assert!(complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &b),
            Some(&f.actor),
            |_| panic!("a provisional enable cannot consume approval"),
        )
        .is_err());
        assert!(list(f.data.path(), &f.actor).unwrap()["methods"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn wallet_completed_changes_leave_live_approval_capacity_available() {
        let f = fixture();
        let mut id = enabled(&f);
        for _ in 0..4 {
            change(&f, "remove", &id);
            id = change(&f, "add", "");
        }
        for _ in 0..4 {
            begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input("remove", &id, ""),
                Some(f.actor.clone()),
            )
            .unwrap();
        }
        let refused = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("remove", &id, ""),
            Some(f.actor.clone()),
        );
        assert!(matches!(refused, Err(err) if err.is::<Capacity>()));
    }
    #[test]
    fn wallet_cancelled_attempts_cannot_bypass_the_session_quota() {
        let f = fixture();
        for _ in 0..4 {
            let b = begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input("add", "", &f.address),
                Some(f.actor.clone()),
            )
            .unwrap();
            cancel(f.data.path(), &b.ceremony_id, BROWSER, ORIGIN).unwrap();
        }
        assert!(
            matches!(begin(f.data.path(), ORIGIN, "home-test", input("add", "", &f.address), Some(f.actor.clone())), Err(err) if err.is::<Capacity>())
        );
    }
    #[test]
    fn wallet_activation_stamps_current_passkeys_after_rotation_during_approval() {
        let f = fixture();
        enabled(&f);
        let actor = signin(&f);
        let mut request = input("add", "", &f.address);
        request.chain_id = 8453;
        let add = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            request,
            Some(actor.clone()),
        )
        .unwrap();
        let b = add;
        let second = add_account(f.data.path(), "alice", "rotated-approver");
        revoke_passkey_for_actor(
            f.data.path(),
            &second.principal_id,
            &second.proof_binding_id,
            &f.actor.proof_binding_id,
            now_ts(),
        )
        .unwrap();
        let out = complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &b),
            Some(&actor),
            |_| Ok(()),
        )
        .unwrap();
        let method = principal(f.data.path(), out["method_id"].as_str().unwrap()).unwrap();
        assert_eq!(method.principal_id, actor.principal_id);
    }
    #[test]
    fn wallet_add_signs_into_same_account_with_same_root_and_metadata() {
        let f = fixture();
        let old =
            load_principal_for_proof_binding(f.data.path(), &f.actor.proof_binding_id).unwrap();
        set_passkey_added_from(
            f.data.path(),
            &f.actor.proof_binding_id,
            Some("Safari on Mac"),
        )
        .unwrap();
        let id = change(&f, "add", "");
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("signin", "", &f.address),
            None,
        )
        .unwrap();
        assert!(complete(f.data.path(), ORIGIN, &completion(&f, &b), None, |_| Ok(())).is_ok());
        let session = signin(&f);
        assert_eq!(session.principal_id, f.actor.principal_id);
        assert_eq!(
            principal(f.data.path(), &id).unwrap().localhost_root,
            old.localhost_root
        );
        assert_eq!(
            load_principal_for_proof_binding(f.data.path(), &f.actor.proof_binding_id)
                .unwrap()
                .passkey_added_from
                .as_deref(),
            Some("Safari on Mac")
        );
        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_ok());
    }
    #[test]
    fn wallet_ownership_conflict_and_cross_account_completion_refused() {
        let f = fixture();
        enabled(&f);
        let bob = add_account(f.data.path(), "bob", "bob-key");
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(bob.clone()),
        )
        .unwrap();
        assert!(complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &b),
            Some(&bob),
            |_| panic!("ownership is checked before approval")
        )
        .is_err());
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", "0x0000000000000000000000000000000000000001"),
            Some(f.actor.clone()),
        )
        .unwrap();
        assert!(complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &b),
            Some(&bob),
            |_| Ok(())
        )
        .is_err());
    }
    #[test]
    fn wallet_remove_revokes_sessions_pending_and_old_signatures_after_readd() {
        let f = fixture();
        let id = enabled(&f);
        let session = signin(&f);
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("signin", "", &f.address),
            None,
        )
        .unwrap();
        let proof = completion(&f, &b);
        change(&f, "remove", &id);
        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err());
        assert!(renew_session_grant(f.data.path(), session.clone()).is_err());
        let replacement = change(&f, "add", "");
        assert!(complete(f.data.path(), ORIGIN, &proof, None, |_| Ok(())).is_err());
        assert!(principal(f.data.path(), &id).is_err());
        assert!(principal(f.data.path(), &replacement).is_ok());
    }
    #[test]
    fn wallet_remove_revokes_sessions_and_pending_method_approvals() {
        let f = fixture();
        let id = enabled(&f);
        let session = signin(&f);
        let pending = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("remove", &id, &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        change(&f, "remove", &id);
        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err());
        assert!(complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &pending),
            Some(&f.actor),
            |_| panic!("removed method consumes no approval")
        )
        .is_err());
    }
    #[test]
    fn wallet_proofs_require_browser_origin_purpose_and_wallet_signature() {
        let f = fixture();
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        let mut c = completion(&f, &b);
        c.browser_secret = "22".repeat(32);
        assert!(complete(f.data.path(), ORIGIN, &c, Some(&f.actor), |_| Ok(())).is_err());
        c.browser_secret = BROWSER.into();
        assert!(complete(
            f.data.path(),
            "https://elsewhere.test",
            &c,
            Some(&f.actor),
            |_| Ok(())
        )
        .is_err());
        let key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        c.signature = signed(&key, &b.message);
        assert!(complete(f.data.path(), ORIGIN, &c, Some(&f.actor), |_| Ok(())).is_err());
        c = completion(&f, &b);
        assert!(complete(f.data.path(), ORIGIN, &c, None, |_| Ok(())).is_err());
        assert!(
            complete(f.data.path(), ORIGIN, &c, Some(&f.actor), |_| Err(anyhow!(
                "passkey refused"
            )))
            .is_err()
        );
        assert!(list(f.data.path(), &f.actor).unwrap()["methods"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn wallet_lost_completion_response_retries_exact_session_once_and_respects_revocation() {
        let f = fixture();
        let id = enabled(&f);
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("signin", "", &f.address),
            None,
        )
        .unwrap();
        let c = completion(&f, &b);
        let first = complete(f.data.path(), ORIGIN, &c, None, |_| Ok(())).unwrap();
        assert_eq!(
            complete(f.data.path(), ORIGIN, &c, None, |_| Ok(())).unwrap(),
            first
        );
        assert_eq!(read(f.data.path()).unwrap().sessions.len(), 1);
        change(&f, "remove", &id);
        assert!(complete(f.data.path(), ORIGIN, &c, None, |_| Ok(())).is_err());
    }
    #[test]
    fn wallet_interrupted_approval_commits_neither_proof_nor_method() {
        let f = fixture();
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        let c = completion(&f, &b);
        assert!(
            complete(f.data.path(), ORIGIN, &c, Some(&f.actor), |_| Err(anyhow!(
                "approval consumed; write interrupted"
            )))
            .is_err()
        );
        assert!(read(f.data.path()).unwrap().methods.is_empty());
        assert!(!read(f.data.path()).unwrap().pending[0].proof_consumed);
        assert!(complete(f.data.path(), ORIGIN, &c, Some(&f.actor), |_| Ok(())).is_ok());
    }
    #[test]
    fn wallet_cancel_clears_transport_and_denies_completion() {
        let f = fixture();
        enabled_relay(&f);
        let mut request = input("signin", "", "");
        request.connector = "walletconnect".into();
        request.allow_temporary_internet = true;
        request.chain_id = 0;
        let b = begin(f.data.path(), ORIGIN, "home-test", request, None).unwrap();
        assert!(attempt_context(
            f.data.path(),
            b.attempt_token.as_ref().unwrap(),
            &b.instance_id,
            now_ts()
        )
        .is_ok());
        cancel(f.data.path(), &b.ceremony_id, BROWSER, ORIGIN).unwrap();
        cancel(f.data.path(), &b.ceremony_id, BROWSER, ORIGIN).unwrap();
        assert!(attempt_context(
            f.data.path(),
            b.attempt_token.as_ref().unwrap(),
            &b.instance_id,
            now_ts()
        )
        .is_err());
        assert!(select(
            f.data.path(),
            &b.ceremony_id,
            BROWSER,
            ORIGIN,
            f.address.clone(),
            20
        )
        .is_err());
    }
    #[test]
    fn wallet_signed_out_ceremonies_verify_before_method_lookup() {
        for chain in [20, 8453] {
            let f = fixture();
            enabled_relay(&f);
            let mut store = read(f.data.path()).unwrap();
            store.methods[0].chain_id = chain;
            let address_for = |key: &SigningKey| {
                let point = key.verifying_key().to_encoded_point(false);
                format!(
                    "0x{}",
                    hex::encode(&sha3::Keccak256::digest(&point.as_bytes()[1..])[12..])
                )
            };
            let unknown_key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
            let unknown = address_for(&unknown_key);
            let disabled_key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
            let mut disabled = store.methods[0].clone();
            disabled.method_id = format!("proof:signin-wallet:{}", random_secret_hex());
            disabled.address = address_for(&disabled_key);
            disabled.sign_in_enabled = false;
            store.methods.push(disabled.clone());
            write(f.data.path(), &store).unwrap();
            for connector in ["metamask", "walletconnect"] {
                for (address, signing_key) in [
                    (f.address.as_str(), &f.key),
                    (unknown.as_str(), &unknown_key),
                    (disabled.address.as_str(), &disabled_key),
                ] {
                    let b = begin(
                        f.data.path(),
                        ORIGIN,
                        "home-test",
                        serde_json::from_value(serde_json::json!({
                            "connector":connector,
                            "address":if connector == "walletconnect" { "" } else { address },
                            "chain_id":chain,"browser_secret":BROWSER,
                            "allow_temporary_internet":true
                        }))
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                    let challenge = if connector == "walletconnect" {
                        let selected = select(
                            f.data.path(),
                            &b.ceremony_id,
                            BROWSER,
                            ORIGIN,
                            address.into(),
                            chain,
                        )
                        .unwrap();
                        assert!(attempt_context(
                            f.data.path(),
                            b.attempt_token.as_deref().unwrap(),
                            &b.instance_id,
                            now_ts()
                        )
                        .is_ok());
                        selected
                    } else {
                        b
                    };
                    let (_, store) = loaded(f.data.path()).unwrap();
                    assert!(
                        !store
                            .pending
                            .iter()
                            .find(|p| p.id == challenge.ceremony_id)
                            .unwrap()
                            .cancelled
                    );
                    let mut response = completion(&f, &challenge);
                    // A well-sized invalid signature reaches cryptographic verification
                    // for enabled, disabled and unknown wallets alike.
                    response.signature = "00".repeat(65);
                    let err = complete(f.data.path(), ORIGIN, &response, None, |_| {
                        panic!("sign-in cannot approve")
                    })
                    .unwrap_err();
                    assert_eq!(
                        err.downcast_ref::<WalletProofError>(),
                        Some(&WalletProofError::InvalidSignature),
                        "{connector} {chain}: {err}"
                    );
                    response.signature = signed(signing_key, &challenge.message);
                    let result = complete(f.data.path(), ORIGIN, &response, None, |_| {
                        panic!("sign-in cannot approve")
                    });
                    if address == f.address {
                        assert_eq!(result.unwrap()["principal_id"], f.actor.principal_id);
                    } else {
                        assert!(
                            result.unwrap_err().is::<Refused>(),
                            "valid proof still needs an enabled method"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn wallet_unisat_unknown_and_enabled_ceremonies_stay_live() {
        let f = fixture();
        enabled(&f);
        let mut store = read(f.data.path()).unwrap();
        store.methods[0].connector = "unisat".into();
        store.methods[0].network = "bitcoin".into();
        store.methods[0].chain_id = 0;
        store.methods[0].address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".into();
        write(f.data.path(), &store).unwrap();
        for address in [
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
        ] {
            let b = begin(f.data.path(), ORIGIN, "home-test", serde_json::from_value(serde_json::json!({"connector":"unisat","address":address,"network":"bitcoin","browser_secret":BROWSER})).unwrap(), None).unwrap();
            let (_, store) = loaded(f.data.path()).unwrap();
            assert!(
                !store
                    .pending
                    .iter()
                    .find(|p| p.id == b.ceremony_id)
                    .unwrap()
                    .cancelled
            );
        }
    }

    #[test]
    fn wallet_reads_preserve_file_identity_and_real_changes_are_saved() {
        let f = fixture();
        let id = enabled_relay(&f);
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("remove", &id, &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        let file_path = path(f.data.path()).unwrap();
        let held = File::open(&file_path).unwrap();
        let before =
            regular_file_identity_from_metadata(&held.metadata().unwrap(), "wallet state").unwrap();
        for _ in 0..3 {
            list(f.data.path(), &f.actor).unwrap();
            intent(f.data.path(), &b.ceremony_id, BROWSER, ORIGIN, &f.actor).unwrap();
            assert_eq!(
                observe_optional_regular_file_identity(&file_path, "wallet state").unwrap(),
                Some(before)
            );
        }
        let pair = begin(f.data.path(), ORIGIN, "home-test", serde_json::from_value(serde_json::json!({"connector":"walletconnect","address":"","chain_id":0,"browser_secret":BROWSER,"allow_temporary_internet":true})).unwrap(), None).unwrap();
        select(
            f.data.path(),
            &pair.ceremony_id,
            BROWSER,
            ORIGIN,
            f.address.clone(),
            20,
        )
        .unwrap();
        assert_eq!(
            read(f.data.path())
                .unwrap()
                .pending
                .iter()
                .find(|p| p.id == pair.ceremony_id)
                .unwrap()
                .method
                .address,
            f.address
        );
        let selected = File::open(&file_path).unwrap();
        let selected_identity =
            regular_file_identity_from_metadata(&selected.metadata().unwrap(), "wallet state")
                .unwrap();
        assert!(select(
            f.data.path(),
            &pair.ceremony_id,
            BROWSER,
            ORIGIN,
            f.address.clone(),
            20
        )
        .is_err());
        assert_eq!(
            observe_optional_regular_file_identity(&file_path, "wallet state").unwrap(),
            Some(selected_identity)
        );
        // Reconciliation is a real change even on list: expired pending state
        // must be removed and persisted, rather than skipped as a read.
        let mut store = read(f.data.path()).unwrap();
        store.pending[0].expires_at = 0;
        write(f.data.path(), &store).unwrap();
        list(f.data.path(), &f.actor).unwrap();
        assert!(read(f.data.path())
            .unwrap()
            .pending
            .iter()
            .all(|p| p.expires_at > 0));
    }

    #[test]
    fn wallet_undo_session_revocation_clears_only_affected_account_after_checkpoint() {
        for (result, observe_with_commit) in [("ok", false), ("ok", true), ("denied", false)] {
            let f = fixture();
            let id = enabled(&f);
            let old = signin(&f);
            let other = add_account(f.data.path(), "bob", "bob-key");
            let mut store = read(f.data.path()).unwrap();
            let mut other_method = store.methods[0].clone();
            other_method.method_id = format!("proof:signin-wallet:{}", random_secret_hex());
            other_method.address = "0x000000000000000000000000000000000000beef".into();
            other_method.account_id = other.principal_id.clone();
            let auth = load_auth_state_with_identity(f.data.path()).unwrap().0;
            other_method.witnesses = witnesses(&auth, &other.principal_id);
            other_method.root_key = root_key(&auth, &other.principal_id);
            let mut other_session = old.clone();
            other_session.session_id = format!("auth:wallet:{}", random_secret_hex());
            other_session.principal_id = other.principal_id.clone();
            other_session.proof_binding_id = other_method.method_id.clone();
            store.methods.push(other_method);
            store.sessions.push(StoredAuthSession {
                grant: other_session.clone(),
                revoked_at: None,
            });
            write(f.data.path(), &store).unwrap();
            let event = sign_audit_event(
                f.data.path(),
                RuntimeAuditEventV1 {
                    schema: RuntimeAuditEventV1::SCHEMA.into(),
                    event_id: format!("audit:{}", random_secret_hex()),
                    event_type: "auth.session.revoked".into(),
                    principal_id: Some(f.actor.principal_id.clone()),
                    proof_binding_id: Some(f.actor.proof_binding_id.clone()),
                    session_id: Some(f.actor.session_id.clone()),
                    challenge_id: None,
                    capsule_id: None,
                    result: result.into(),
                    reason: "legacy session revocation".into(),
                    occurred_at: now_ts(),
                    signer_did: None,
                    signature: None,
                },
            )
            .unwrap();
            let mut legacy = load_auth_state_with_identity(f.data.path()).unwrap().0;
            push_audit_event(f.data.path(), &mut legacy, event).unwrap();
            save_auth_state(f.data.path(), &legacy, None).unwrap();
            if observe_with_commit {
                // Forward may first write passkey state. Its observer must
                // replay the legacy revocation before advancing the checkpoint.
                store_session_grant(f.data.path(), f.actor.clone()).unwrap();
            }
            assert_eq!(
                load_active_session_grant(f.data.path(), &old.session_id, now_ts()).is_err(),
                result == "ok"
            );
            assert!(
                load_active_session_grant(f.data.path(), &other_session.session_id, now_ts())
                    .is_ok()
            );
            assert!(
                principal(f.data.path(), &id).is_ok(),
                "session revocation keeps the method"
            );
            // Persist the new checkpoint. The same historical event must leave
            // a subsequent wallet sign-in usable.
            list(f.data.path(), &f.actor).unwrap();
            let fresh = signin(&f);
            assert!(load_active_session_grant(f.data.path(), &fresh.session_id, now_ts()).is_ok());
            let store = read(f.data.path()).unwrap();
            assert_eq!(
                store
                    .sessions
                    .iter()
                    .any(|s| s.grant.session_id == old.session_id),
                result != "ok"
            );
        }
    }

    #[test]
    fn wallet_undo_legacy_writer_preserves_additive_records_forward_signin_works() {
        let f = fixture();
        let id = enabled(&f);
        let before = std::fs::read(path(f.data.path()).unwrap()).unwrap();
        // AuthState is byte-for-byte the rc.1 schema: the old writer knows only
        // this file. Exercise its serialization/write without the new observer.
        let mut legacy = load_auth_state_with_identity(f.data.path()).unwrap().0;
        legacy.guest_registration_enabled = true;
        save_auth_state(f.data.path(), &legacy, None).unwrap();
        assert_eq!(std::fs::read(path(f.data.path()).unwrap()).unwrap(), before);
        assert_eq!(signin(&f).proof_binding_id, id);
        let legacy: Value = serde_json::from_slice(
            &std::fs::read(auth_state_path(f.data.path()).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(legacy.get("wallets").is_none());
        assert!(legacy["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| !s["grant"]["session_id"]
                .as_str()
                .unwrap()
                .starts_with("auth:wallet:")));
    }
    #[test]
    fn wallet_undo_recovery_retaining_account_root_and_passkey_invalidates_wallet() {
        let f = fixture();
        let id = enabled(&f);
        let session = signin(&f);
        let event = sign_audit_event(
            f.data.path(),
            RuntimeAuditEventV1 {
                schema: RuntimeAuditEventV1::SCHEMA.into(),
                event_id: format!("audit:{}", random_secret_hex()),
                event_type: "auth.recovery_kit.reassigned".into(),
                principal_id: Some(f.actor.principal_id.clone()),
                proof_binding_id: Some(f.actor.proof_binding_id.clone()),
                session_id: None,
                challenge_id: None,
                capsule_id: None,
                result: "ok".into(),
                reason: "Kit reassignment retaining the importer passkey".into(),
                occurred_at: now_ts(),
                signer_did: None,
                signature: None,
            },
        )
        .unwrap();
        // Simulate rc.1: no new observer, same account/root/key; signed recovery event.
        let pending_add = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        let mut legacy = load_auth_state_with_identity(f.data.path()).unwrap().0;
        push_audit_event(f.data.path(), &mut legacy, event).unwrap();
        save_auth_state(f.data.path(), &legacy, None).unwrap();
        assert!(principal(f.data.path(), &id).is_err());
        assert!(
            complete(
                f.data.path(),
                ORIGIN,
                &completion(&f, &pending_add),
                Some(&f.actor),
                |_| Ok(())
            )
            .is_err(),
            "pre-recovery activation survived"
        );

        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err());
    }
    #[test]
    fn wallet_undo_missing_audit_continuation_fails_closed() {
        let f = fixture();
        let id = enabled(&f);
        let mut store = read(f.data.path()).unwrap();
        store.audit_sequence = u64::MAX;
        store.audit_hash = "sha256:lost-continuation".into();
        write(f.data.path(), &store).unwrap();
        assert!(principal(f.data.path(), &id).is_err());
    }
    #[test]
    fn wallet_last_passkey_removal_clears_only_that_accounts_wallet_access() {
        let f = fixture();
        enabled(&f);
        let session = signin(&f);
        let other = add_account(f.data.path(), "bob", "bob-key");
        revoke_passkey_for_actor_approved(
            f.data.path(),
            &other.principal_id,
            &other.proof_binding_id,
            PasskeyRemovalTarget {
                proof_binding_id: &f.actor.proof_binding_id,
                account_id: &f.actor.principal_id,
                remove_account: true,
            },
            now_ts(),
            || Ok(()),
        )
        .unwrap();
        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err());
        assert!(active_passkey_principals(f.data.path())
            .unwrap()
            .iter()
            .any(|p| p.principal_id == other.principal_id));
    }
    #[test]
    fn wallet_ordinary_removals_race_keeps_each_accounts_last_passkey() {
        let f = fixture();
        enabled(&f);
        let second = add_account(f.data.path(), "alice", "alice-second");
        add_account(f.data.path(), "bob", "bob-key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for key in [&f.actor, &second] {
                let ready = barrier.clone();
                let data = f.data.path();
                workers.push(scope.spawn(move || {
                    ready.wait();
                    revoke_passkey_for_actor(
                        data,
                        &key.principal_id,
                        &key.proof_binding_id,
                        &key.proof_binding_id,
                        now_ts(),
                    )
                    .is_ok()
                }));
            }
            assert_eq!(
                workers
                    .into_iter()
                    .map(|w| w.join().unwrap())
                    .filter(|ok| *ok)
                    .count(),
                1
            );
        });
        assert_eq!(
            active_passkey_principals(f.data.path())
                .unwrap()
                .iter()
                .filter(|p| p.principal_id == f.actor.principal_id)
                .count(),
            1
        );
        assert_eq!(signin(&f).principal_id, f.actor.principal_id);
    }
    #[test]
    fn wallet_guest_can_remove_own_wallet_but_cannot_add_one() {
        for use_wallet_session in [false, true] {
            let mut f = fixture();
            let id = enabled(&f);
            let session = signin(&f);
            add_account(f.data.path(), "bob", "bob-key");
            demote_passkey_to_guest(f.data.path(), &f.actor.proof_binding_id, now_ts()).unwrap();
            if use_wallet_session {
                f.actor = session.clone();
            }
            assert!(begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                input("add", "", &f.address),
                Some(f.actor.clone())
            )
            .is_err());
            change(&f, "remove", &id);
            assert!(
                load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err()
            );
        }
    }
    #[test]
    fn wallet_explicit_account_removals_race_leaves_one_home_admin() {
        let f = fixture();
        let b = add_account(f.data.path(), "bob", "bob-key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let a = f.actor.clone();
            let data = f.data.path();
            let ready = barrier.clone();
            let first = scope.spawn(move || {
                ready.wait();
                revoke_passkey_for_actor_approved(
                    data,
                    &a.principal_id,
                    &a.proof_binding_id,
                    PasskeyRemovalTarget {
                        proof_binding_id: &a.proof_binding_id,
                        account_id: &a.principal_id,
                        remove_account: true,
                    },
                    now_ts(),
                    || Ok(()),
                )
                .is_ok()
            });
            let data = f.data.path();
            let ready = barrier.clone();
            let second = scope.spawn(move || {
                ready.wait();
                revoke_passkey_for_actor_approved(
                    data,
                    &b.principal_id,
                    &b.proof_binding_id,
                    PasskeyRemovalTarget {
                        proof_binding_id: &b.proof_binding_id,
                        account_id: &b.principal_id,
                        remove_account: true,
                    },
                    now_ts(),
                    || Ok(()),
                )
                .is_ok()
            });
            assert_ne!(first.join().unwrap(), second.join().unwrap());
        });
        assert_eq!(
            active_admin_passkey_principal_count(f.data.path()).unwrap(),
            1
        );
    }
    #[test]
    fn wallet_remove_racing_signin_never_leaves_a_live_wallet_session() {
        let f = fixture();
        let id = enabled(&f);
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("signin", "", &f.address),
            None,
        )
        .unwrap();
        let c = completion(&f, &b);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| complete(f.data.path(), ORIGIN, &c, None, |_| Ok(())));
            let second = scope.spawn(|| change(&f, "remove", &id));
            let _ = first.join().unwrap();
            second.join().unwrap();
        });
        let auth = load_auth_state(f.data.path()).unwrap();
        assert!(auth
            .sessions
            .iter()
            .all(|s| !s.grant.session_id.starts_with("auth:wallet:")));
    }
    #[test]
    fn wallet_survives_same_account_passkey_rotation() {
        let f = fixture();
        let id = enabled(&f);
        let second = add_account(f.data.path(), "alice", "alice-second");
        revoke_passkey_for_actor(
            f.data.path(),
            &second.principal_id,
            &second.proof_binding_id,
            &f.actor.proof_binding_id,
            now_ts(),
        )
        .unwrap();
        assert_eq!(signin(&f).proof_binding_id, id);
    }
    #[test]
    fn wallet_survives_first_root_protection_and_kit_export() {
        let f = fixture();
        let id = enabled(&f);
        store_test_principal_root_protection(f.data.path(), &f.actor.principal_id);
        append_audit_event(
            f.data.path(),
            RuntimeAuditEventV1 {
                schema: RuntimeAuditEventV1::SCHEMA.into(),
                event_id: format!("audit:{}", random_secret_hex()),
                event_type: "auth.full_recovery_bundle.exported".into(),
                principal_id: Some(f.actor.principal_id.clone()),
                proof_binding_id: Some(f.actor.proof_binding_id.clone()),
                session_id: None,
                challenge_id: None,
                capsule_id: None,
                result: "ok".into(),
                reason: "ordinary Kit export".into(),
                occurred_at: now_ts(),
                signer_did: None,
                signature: None,
            },
        )
        .unwrap();
        assert_eq!(signin(&f).proof_binding_id, id);
    }
    #[test]
    fn wallet_undo_coalesced_passkey_rotation_retains_ownership() {
        let f = fixture();
        let id = enabled(&f);
        let original = std::fs::read(path(f.data.path()).unwrap()).unwrap();
        let second = add_account(f.data.path(), "alice", "alice-second");
        let mut legacy = load_auth_state_with_identity(f.data.path()).unwrap().0;
        let event = sign_audit_event(
            f.data.path(),
            RuntimeAuditEventV1 {
                schema: RuntimeAuditEventV1::SCHEMA.into(),
                event_id: format!("audit:{}", random_secret_hex()),
                event_type: "auth.passkey.added".into(),
                principal_id: Some(second.principal_id.clone()),
                proof_binding_id: Some(second.proof_binding_id.clone()),
                session_id: None,
                challenge_id: None,
                capsule_id: None,
                result: "ok".into(),
                reason: "legacy passkey add".into(),
                occurred_at: now_ts(),
                signer_did: None,
                signature: None,
            },
        )
        .unwrap();
        push_audit_event(f.data.path(), &mut legacy, event).unwrap();
        revoke_binding_in_state(&mut legacy, &f.actor.proof_binding_id, now_ts()).unwrap();
        save_auth_state(f.data.path(), &legacy, None).unwrap();
        write_secret_bytes_atomic(&path(f.data.path()).unwrap(), &original).unwrap();
        assert_eq!(signin(&f).proof_binding_id, id);
    }
    #[test]
    fn wallet_malformed_sidecar_refuses_wallets_and_preserves_passkey_access() {
        let f = fixture();
        let id = enabled(&f);
        let session = signin(&f);
        write_secret_bytes_atomic(&path(f.data.path()).unwrap(), b"broken-json").unwrap();
        assert!(principal(f.data.path(), &id).is_err());
        assert!(load_active_session_grant(f.data.path(), &session.session_id, now_ts()).is_err());
        assert!(load_active_session_grant(f.data.path(), &f.actor.session_id, now_ts()).is_ok());
        assert!(renew_session_grant(f.data.path(), f.actor.clone()).is_ok());
    }
    #[test]
    fn wallet_unisat_add_signin_binds_account_and_enables_without_relay_permission() {
        let f = fixture();
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let key = SigningKey::from_bytes((&bytes).into()).unwrap();
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            serde_json::from_value(serde_json::json!({
                "action":"add", "connector":"unisat",
                "address":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                "network":"bitcoin", "browser_secret":BROWSER
            }))
            .unwrap(),
            Some(f.actor.clone()),
        )
        .unwrap();
        assert!(b
            .message
            .contains("add this wallet so it can sign in to this Home"));
        assert!(b.message.contains(&f.actor.principal_id));
        assert_eq!(
            b.approval.as_ref().unwrap()["request"]["authorizes_short_public_walletconnect"],
            false
        );
        assert_ne!(b.approval.as_ref().unwrap()["notice"], RELAY_NOTICE);
        let sign = |message: &str| {
            let (sig, id) = key
                .sign_prehash_recoverable(&bitcoin::bitcoin_signed_message_hash(message.as_bytes()))
                .unwrap();
            let mut raw = vec![31 + id.to_byte()];
            raw.extend_from_slice(&sig.to_bytes());
            base64::engine::general_purpose::STANDARD.encode(raw)
        };
        let mut proof = Complete {
            ceremony_id: b.ceremony_id.clone(),
            browser_secret: BROWSER.into(),
            signature: String::new(),
            signature_type: "bitcoin_signed_message".into(),
            public_key: hex::encode(key.verifying_key().to_encoded_point(true).as_bytes()),
            step_up_token: String::new(),
        };
        let mut add = read(f.data.path()).unwrap().pending[0].clone();
        add.action = "legacy_add".into();
        proof.signature = sign(&message(&add).unwrap());
        assert!(
            complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |_| {
                panic!("a Bitcoin add proof cannot enable sign-in")
            })
            .is_err()
        );
        proof.signature = sign(&b.message);
        let out = complete(f.data.path(), ORIGIN, &proof, Some(&f.actor), |_| Ok(())).unwrap();
        assert_eq!(out["sign_in_enabled"], true);
        assert!(principal(f.data.path(), out["method_id"].as_str().unwrap()).is_ok());
    }
    #[test]
    fn wallet_unisat_fresh_bitcoin_proof_add_and_signin() {
        let f = fixture();
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let key = SigningKey::from_bytes((&bytes).into()).unwrap();
        let address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        for network in ["testnet", "signet", "regtest"] {
            let unsupported: Begin = serde_json::from_value(serde_json::json!({"action":"add","connector":"unisat","address":address,"network":network,"browser_secret":BROWSER})).unwrap();
            assert!(begin(
                f.data.path(),
                ORIGIN,
                "home-test",
                unsupported,
                Some(f.actor.clone())
            )
            .is_err());
        }
        let make = |b: &BeginResult| {
            let (sig, id) = key
                .sign_prehash_recoverable(&bitcoin::bitcoin_signed_message_hash(
                    b.message.as_bytes(),
                ))
                .unwrap();
            let mut raw = vec![31 + id.to_byte()];
            raw.extend_from_slice(&sig.to_bytes());
            Complete {
                ceremony_id: b.ceremony_id.clone(),
                browser_secret: BROWSER.into(),
                signature: base64::engine::general_purpose::STANDARD.encode(raw),
                signature_type: "bitcoin_signed_message".into(),
                public_key: hex::encode(key.verifying_key().to_encoded_point(true).as_bytes()),
                step_up_token: String::new(),
            }
        };
        let input: Begin=serde_json::from_value(serde_json::json!({"action":"add","connector":"unisat","address":address,"network":"bitcoin","browser_secret":BROWSER})).unwrap();
        let added = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input,
            Some(f.actor.clone()),
        )
        .unwrap();
        let result = complete(f.data.path(), ORIGIN, &make(&added), Some(&f.actor), |_| {
            Ok(())
        })
        .unwrap();
        assert_eq!(result["sign_in_enabled"], true);
        let signin=begin(f.data.path(),ORIGIN,"home-test",serde_json::from_value(serde_json::json!({"connector":"unisat","address":address,"network":"bitcoin","browser_secret":BROWSER})).unwrap(),None).unwrap();
        let result = complete(f.data.path(), ORIGIN, &make(&signin), None, |_| {
            panic!("Bitcoin signs in, never approves")
        })
        .unwrap();
        assert_eq!(result["principal_id"], f.actor.principal_id);
    }
    #[test]
    fn walletconnect_add_pairs_before_address_selection() {
        let f = fixture();
        let mut request = input("add", "", "");
        request.connector = "walletconnect".into();
        request.allow_temporary_internet = true;
        request.chain_id = 0;
        let pair = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            request,
            Some(f.actor.clone()),
        )
        .unwrap();
        assert!(pair.message.is_empty());
        assert!(pair.attempt_token.is_some());
        let selected = select(
            f.data.path(),
            &pair.ceremony_id,
            BROWSER,
            ORIGIN,
            f.address.clone(),
            20,
        )
        .unwrap();
        assert!(!selected.message.is_empty());
        let result = complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &selected),
            Some(&f.actor),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(result["sign_in_enabled"], true);
        let remove = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("remove", result["method_id"].as_str().unwrap(), ""),
            Some(f.actor.clone()),
        )
        .unwrap();
        assert!(
            remove.attempt_token.is_none(),
            "removal owns no relay authority"
        );
    }
    #[test]
    fn walletconnect_requires_explicit_short_consent_and_enabled_method() {
        let f = fixture();
        let mut req = input("signin", "", "");
        req.connector = "walletconnect".into();
        req.chain_id = 0;
        req.allow_temporary_internet = true;
        assert!(begin(f.data.path(), ORIGIN, "home-test", req, None).is_err());
        let id = enabled_relay(&f);
        let mut req = input("signin", "", "");
        req.connector = "walletconnect".into();
        req.chain_id = 0;
        assert!(begin(f.data.path(), ORIGIN, "home-test", req, None).is_err());
        let mut req = input("signin", "", "");
        req.connector = "walletconnect".into();
        req.chain_id = 0;
        req.allow_temporary_internet = true;
        let attempt = begin(f.data.path(), ORIGIN, "home-test", req, None).unwrap();
        assert!(attempt_context(
            f.data.path(),
            attempt.attempt_token.as_ref().unwrap(),
            &attempt.instance_id,
            now_ts()
        )
        .is_ok());
        change(&f, "remove", &id);
        assert!(attempt_context(
            f.data.path(),
            attempt.attempt_token.as_ref().unwrap(),
            &attempt.instance_id,
            now_ts()
        )
        .is_err());
        assert!(inactive_attempts(f.data.path())
            .unwrap()
            .contains(&attempt.ceremony_id));
    }
    #[test]
    fn wallet_add_approval_discloses_short_public_relay_authority() {
        let f = fixture();
        let mut input = input("add", "", &f.address);
        input.connector = "walletconnect".into();
        input.allow_temporary_internet = true;
        let request = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input,
            Some(f.actor.clone()),
        )
        .unwrap();
        let approval = request.approval.unwrap();
        assert_eq!(
            approval["request"]["authorizes_short_public_walletconnect"],
            true
        );
        assert!(approval["notice"]
            .as_str()
            .unwrap()
            .contains("internet address"));
    }
    #[test]
    fn wallet_session_refresh_keeps_pending_approval_identity() {
        let f = fixture();
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            input("add", "", &f.address),
            Some(f.actor.clone()),
        )
        .unwrap();
        let mut renewed = f.actor.clone();
        renewed.expires_at += 60;
        renew_session_grant(f.data.path(), renewed.clone()).unwrap();
        assert!(complete(
            f.data.path(),
            ORIGIN,
            &completion(&f, &b),
            Some(&renewed),
            |_| Ok(())
        )
        .is_ok());
    }
}

#[cfg(test)]
mod review_probe {
    use super::tests::*;
    use super::*;
    const ORIGIN: &str = "http://localhost:4100";
    const BROWSER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    fn wc_selected_is_live(f: &Fixture, address: &str) -> bool {
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            serde_json::from_value(serde_json::json!({"connector":"walletconnect","address":"","chain_id":0,"browser_secret":BROWSER,"allow_temporary_internet":true})).unwrap(),
            None,
        )
        .unwrap();
        select(
            f.data.path(),
            &b.ceremony_id,
            BROWSER,
            ORIGIN,
            address.into(),
            20,
        )
        .unwrap();
        attempt_context(
            f.data.path(),
            b.attempt_token.as_deref().unwrap(),
            &b.instance_id,
            now_ts(),
        )
        .is_ok()
    }
    fn metamask_pending_cancelled(f: &Fixture, address: &str) -> bool {
        let b = begin(
            f.data.path(),
            ORIGIN,
            "home-test",
            serde_json::from_value(serde_json::json!({"connector":"metamask","address":address,"chain_id":20,"browser_secret":BROWSER})).unwrap(),
            None,
        )
        .unwrap();
        let (_, store) = loaded(f.data.path()).unwrap();
        store
            .pending
            .iter()
            .find(|p| p.id == b.ceremony_id)
            .unwrap()
            .cancelled
    }
    #[test]
    fn review_probe_signed_out_wallet_oracle() {
        let f = fixture();
        enabled_relay(&f);
        let unknown = "0x000000000000000000000000000000000000dead";
        let wc_known = wc_selected_is_live(&f, &f.address);
        let wc_unknown = wc_selected_is_live(&f, unknown);
        let mm_known = metamask_pending_cancelled(&f, &f.address);
        let mm_unknown = metamask_pending_cancelled(&f, unknown);
        println!("PROBE wc_transport_live known={wc_known} unknown={wc_unknown}; metamask_pending_cancelled known={mm_known} unknown={mm_unknown}");
        assert_eq!(wc_known, wc_unknown);
        assert_eq!(mm_known, mm_unknown);
    }
}
