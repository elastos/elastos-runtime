//! Plan B T4.4: the pool open, with fake pool servers, Wallet and release.
//!
//! The fixtures are real contracts: the descriptor, the attestations, the
//! Wallet's V2 signature and the node contributions all verify, so the
//! operation and terminal receipts built here are the ones a server checks.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    key_envelope_for, node_public_key, pool_bundle, pool_descriptor,
    recipient_attestation_statement_for_key, recipient_public_key, signed_node_rights_decision,
    signing_key, wallet_address, wallet_signing_key,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, Digest32, EvmContractAddressV1, EvmFunctionSelectorV1,
    EvmRightsMethodAbiV1, NodeContributionStatementV1, NodePublicKey, PoolEpochBundleV1,
    ProfileIdentityV1, ProtectedContentBindingV1, RecipientSealedContributionV1, RightsActionV1,
    RightsDecisionV1, RightsObservationFinalityV1, RightsPolicyBodyV1, RightsPolicyIdentityV1,
    RightsRequestAnyV1, RightsRequestV2, RightsSubjectSourceV1, RuntimeIssuerPolicyV1,
    RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1, RuntimeSessionBindingV1,
    SignedNodeContributionV1, SignedPoolRecipientAttestationV2, SignedRuntimeReleaseOperationV2,
    TerminalReceiptIssuerKey, WalletSignedRightsRequestV2, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use elastos_protected_content_runtime::{
    resolve_pool_from_candidates, AcceptAnyPool, PoolResolveError, PoolSessionIdV1,
    PoolSessionOpenV1, PoolSessionOpenedV1, PoolSessionPrepareV1, PoolSessionPreparedV1,
    PoolSessionReadV1, PoolTransportError, ResolvedPoolV1, RuntimeReleaseCoordinatorOutcome,
    RuntimeReleaseTerminalResult,
};
use elastos_runtime::provider::{ProviderCarrierRoute, ProviderInvocationTransport};
use x_wing::kem::Decapsulator as _;
use x_wing::KeyExport as _;

use super::*;
use crate::protected_content_runtime::RuntimeCustodyAccessAt;

const NOW: u64 = 2_000_000_000;
const WALLET_SEED: u8 = 7;
const POOL_MODULE_SOURCE: &str = include_str!("../protected_content_pool_open.rs");
const RUNTIME_SOURCE: &str = include_str!("../protected_content_runtime.rs");
const SERVER_INFRA_SOURCE: &str = include_str!("../server_infra.rs");
const LIBRARY_SOURCE: &str = include_str!("../library.rs");
/// The chain the fixture policy names.
const POLICY_CHAIN: u64 = 11155111;

fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

fn device_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x43; 32])
}

fn device_issuer() -> RuntimeOperationIssuerKeyV1 {
    RuntimeOperationIssuerKeyV1::new(device_key().verifying_key().to_bytes()).unwrap()
}

/// The fixture pool (nodes 1, 2, 3, all serving; v3, WCI-operated), one
/// item of it, and the buyer's binding to it.
struct Pool {
    bundle: PoolEpochBundleV1,
    resolved: ResolvedPoolV1,
    binding: ProtectedContentBindingV1,
    policy: RightsPolicyBodyV1,
    content: PoolSessionContentRefV1,
}

fn pool(max_servers_per_session: u8) -> Pool {
    let draft = crate::protected_content_runtime::tests::mint_draft_for_composition_journal_test();
    let encrypted = draft.encrypted_content().clone();
    let bundle = pool_bundle(xwing, NOW);
    let key_envelope = key_envelope_for(&bundle, &encrypted);
    let descriptor = pool_descriptor(&bundle, max_servers_per_session, device_issuer(), NOW);
    let resolved = resolve_pool_from_candidates(
        vec![("known", descriptor.into())],
        &AcceptAnyPool,
        &key_envelope,
        &[],
        NOW,
    )
    .unwrap();
    let policy = RightsPolicyBodyV1::new(
        encrypted.clone(),
        ContentAccessIdV1::new([0x44; 16]).unwrap(),
        RightsActionV1::View,
        RightsSubjectSourceV1::WalletAddress,
        POLICY_CHAIN,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap();
    let binding = ProtectedContentBindingV1::new(
        encrypted,
        key_envelope,
        policy.policy_identity().unwrap(),
        ProfileIdentityV1::from_public_key_bytes(signing_key(0x61).verifying_key().to_bytes())
            .unwrap(),
        wallet_address(WALLET_SEED),
        RuntimeSessionBindingV1::new(Digest32::new([0x66; 32])).unwrap(),
    )
    .unwrap();
    let content = pool_content_ref("bafy-item", &draft);
    Pool {
        bundle,
        resolved,
        binding,
        policy,
        content,
    }
}

fn seed_of(key: NodePublicKey) -> u8 {
    (1..=3)
        .find(|seed| node_public_key(*seed) == key)
        .expect("a fixture node")
}

fn handle() -> PoolViewerHandle {
    [0x5c; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]
}

fn context<'a>(
    pool: &'a Pool,
    own: &'a [NodePublicKey],
    resume: Option<PoolResume>,
) -> PoolOpenContext<'a> {
    PoolOpenContext {
        resolved: &pool.resolved,
        own_node_keys: own,
        binding: pool.binding.clone(),
        action: RightsActionV1::View,
        content: pool.content.clone(),
        audit_request_id: RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap(),
        handle: handle(),
        approval_expires_at: NOW + 290,
        resume,
        now: NOW,
    }
}

// ---------------------------------------------------------------------------
// Fake pool servers
// ---------------------------------------------------------------------------

/// Pool servers that prepare a recipient they vouch for, or refuse as told,
/// and record every call.
struct FakeServers<'a> {
    pool: &'a Pool,
    refusals: HashMap<u8, PoolTransportError>,
    /// OPEN-LOOP F2: how a server answers `session.open`.
    open_refusals: HashMap<u8, PoolTransportError>,
    prepares: Mutex<Vec<(u8, PoolSessionPrepareV1)>>,
    opens: Mutex<Vec<(u8, PoolSessionOpenV1)>>,
    /// T4.5: how a server answers reads, set while the test runs.
    read_refusals: Mutex<HashMap<u8, PoolTransportError>>,
    reads: Mutex<Vec<(u8, PoolSessionReadV1)>>,
    closes: Mutex<Vec<(u8, PoolSessionIdV1)>>,
    /// S4B-F2: each read takes one barrier, if any, and waits on it, so
    /// reads can be held in flight together.
    read_barriers: Mutex<Vec<std::sync::Arc<tokio::sync::Barrier>>>,
}

impl<'a> FakeServers<'a> {
    fn new(pool: &'a Pool) -> Self {
        Self {
            pool,
            refusals: HashMap::new(),
            open_refusals: HashMap::new(),
            prepares: Mutex::default(),
            opens: Mutex::default(),
            read_refusals: Mutex::default(),
            reads: Mutex::default(),
            closes: Mutex::default(),
            read_barriers: Mutex::default(),
        }
    }

    fn refuse_reads(&self, seed: u8, error: PoolTransportError) {
        self.read_refusals.lock().unwrap().insert(seed, error);
    }

    fn answer_reads(&self, seed: u8) {
        self.read_refusals.lock().unwrap().remove(&seed);
    }

    fn read_seeds(&self) -> Vec<u8> {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .map(|(seed, _)| *seed)
            .collect()
    }

    fn refusing(mut self, seed: u8, error: PoolTransportError) -> Self {
        self.refusals.insert(seed, error);
        self
    }

    fn refusing_opens(mut self, seed: u8, error: PoolTransportError) -> Self {
        self.open_refusals.insert(seed, error);
        self
    }

    fn prepared_seeds(&self) -> Vec<u8> {
        self.prepares
            .lock()
            .unwrap()
            .iter()
            .map(|(seed, _)| *seed)
            .collect()
    }

    fn opened(&self) -> Vec<(u8, PoolSessionOpenV1)> {
        self.opens.lock().unwrap().clone()
    }
}

/// The recipient server `seed` prepares, vouched for this binding (v2,
/// WCI-operated, #388 A2).
fn attested_recipient(pool: &Pool, seed: u8) -> PoolSessionPreparedV1 {
    let recipient_key = recipient_public_key(xwing, 0x20 + seed);
    let statement = recipient_attestation_statement_for_key(
        &pool.bundle,
        &pool.binding,
        device_issuer(),
        recipient_key,
        seed,
        NOW,
    );
    let attestation = SignedPoolRecipientAttestationV2::new(
        statement.clone(),
        signing_key(seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    PoolSessionPreparedV1 {
        session_id: [seed; 16],
        recipient_public_key: recipient_key,
        attestation,
    }
}

#[async_trait::async_trait]
impl PoolSessionCalls for FakeServers<'_> {
    async fn prepare(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionPrepareV1,
    ) -> Result<PoolSessionPreparedV1, PoolTransportError> {
        let seed = seed_of(server.node_public_key());
        self.prepares.lock().unwrap().push((seed, req.clone()));
        if let Some(error) = self.refusals.get(&seed) {
            return Err(error.clone());
        }
        Ok(attested_recipient(self.pool, seed))
    }

    async fn open(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionOpenV1,
    ) -> Result<PoolSessionOpenedV1, PoolTransportError> {
        let seed = seed_of(server.node_public_key());
        self.opens.lock().unwrap().push((seed, req.clone()));
        if let Some(error) = self.open_refusals.get(&seed) {
            return Err(error.clone());
        }
        // T3.2 as amended: the session's end, not the operation's.
        Ok(PoolSessionOpenedV1 {
            expires_at: req.operation.statement().session_expires_at(),
        })
    }

    /// Seals the fixture clear part to the delivery key the session opened
    /// with, under the AAD a real server uses.
    async fn read_sealed(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionReadV1,
    ) -> Result<Vec<u8>, PoolTransportError> {
        let seed = seed_of(server.node_public_key());
        self.reads.lock().unwrap().push((seed, *req));
        let barrier = self.read_barriers.lock().unwrap().pop();
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        let refusal = self.read_refusals.lock().unwrap().get(&seed).cloned();
        if let Some(error) = refusal {
            return Err(error);
        }
        let opens = self.opens.lock().unwrap();
        let (_, open) = opens
            .iter()
            .rev()
            .find(|(opened_at, open)| *opened_at == seed && open.session_id == req.session_id)
            .ok_or_else(|| PoolTransportError::Refused("unknown_session".into()))?;
        let operation_hash = open
            .operation
            .verify(RuntimeIssuerPolicyV1::Declared, NOW)
            .unwrap()
            .operation_hash();
        let aad = ViewerPartAadV1 {
            session_id: req.session_id,
            operation_hash,
            part: req.part,
        };
        Ok(elastos_protected_content_custody::seal_viewer_part_v1(
            &open.delivery_public_key,
            &aad,
            &clear_part(req.part),
        )
        .unwrap())
    }

    async fn close(
        &self,
        server: &PoolMemberV2,
        session_id: PoolSessionIdV1,
    ) -> Result<(), PoolTransportError> {
        let seed = seed_of(server.node_public_key());
        self.closes.lock().unwrap().push((seed, session_id));
        Ok(())
    }
}

/// The clear bytes a fixture server returns for `part`.
fn clear_part(part: ViewerPartIndexV1) -> Vec<u8> {
    format!("clear part {part:?};").repeat(3).into_bytes()
}

// ---------------------------------------------------------------------------
// Fake policy, signing, Wallet, release and chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletMode {
    Pending,
    Sign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseMode {
    Contributions,
    RightsDenied,
}

struct FakePorts<'a> {
    pool: &'a Pool,
    wallet: Mutex<VecDeque<WalletMode>>,
    release_mode: ReleaseMode,
    verdict: RightsDeniedClass,
    /// The policy lookup fails (ADV-01 §4B).
    policy_fails: bool,
    policy_calls: AtomicUsize,
    sign_operation_calls: AtomicUsize,
    sign_receipt_calls: AtomicUsize,
    /// Every fresh rights request, and every replayed request's bytes, that
    /// passed the open's check and reached the Wallet.
    fresh: Mutex<Vec<RightsRequestV2>>,
    replays: Mutex<Vec<Vec<u8>>>,
    persisted: Mutex<Vec<PoolPendingRelease>>,
    released: Mutex<Vec<SignedRuntimeReleaseOperationV2>>,
}

impl<'a> FakePorts<'a> {
    fn new(pool: &'a Pool, wallet: &[WalletMode]) -> Self {
        Self {
            pool,
            wallet: Mutex::new(wallet.iter().copied().collect()),
            release_mode: ReleaseMode::Contributions,
            verdict: RightsDeniedClass::Denied,
            policy_fails: false,
            policy_calls: AtomicUsize::new(0),
            sign_operation_calls: AtomicUsize::new(0),
            sign_receipt_calls: AtomicUsize::new(0),
            fresh: Mutex::default(),
            replays: Mutex::default(),
            persisted: Mutex::default(),
            released: Mutex::default(),
        }
    }

    fn wallet_calls(&self) -> usize {
        self.fresh.lock().unwrap().len() + self.replays.lock().unwrap().len()
    }
}

fn wallet_sign(request: &RightsRequestV2) -> WalletSignedRightsRequestV2 {
    let (signature, recovery_id) = wallet_signing_key(WALLET_SEED)
        .sign_prehash_recoverable(&request.signing_hash().unwrap())
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    WalletSignedRightsRequestV2::new(request.clone(), bytes).unwrap()
}

/// A node's contribution to `operation`, sealed to `recipient`.
fn contribution(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    recipient: &RecipientKeyIdentityV1,
    node_seed: u8,
) -> SignedNodeContributionV1 {
    let decision =
        signed_node_rights_decision(operation, node_seed, RightsDecisionV1::Allowed, NOW - 3);
    let statement = NodeContributionStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        decision,
        RecipientSealedContributionV1::new(recipient.clone(), vec![node_seed; 96]).unwrap(),
        NOW,
        NOW + 27,
    )
    .unwrap();
    SignedNodeContributionV1::new(
        statement.clone(),
        signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[async_trait::async_trait]
impl PoolOpenPorts for FakePorts<'_> {
    async fn rights_policy(&self) -> anyhow::Result<(RightsPolicyBodyV1, RightsPolicyIdentityV1)> {
        self.policy_calls.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(
            !self.policy_fails,
            "Runtime custody rights policy is unavailable"
        );
        Ok((
            self.pool.policy.clone(),
            self.pool.policy.policy_identity().unwrap(),
        ))
    }

    fn device_issuer(&self) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
        device_issuer_of(&device_key())
    }

    fn sign_release_operation_v2(
        &self,
        statement: RuntimeReleaseOperationStatementV2,
    ) -> anyhow::Result<SignedRuntimeReleaseOperationV2> {
        self.sign_operation_calls.fetch_add(1, Ordering::SeqCst);
        sign_release_operation_v2_with(&device_key(), statement)
    }

    fn sign_terminal_receipt_v2(
        &self,
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        server_contributions: &[SignedNodeContributionV1],
        recipient: &RecipientKeyIdentityV1,
        now: u64,
    ) -> anyhow::Result<SignedTerminalReceiptV1> {
        self.sign_receipt_calls.fetch_add(1, Ordering::SeqCst);
        // The fixture contributions are issued at NOW; the clock is NOW here.
        sign_terminal_receipt_v2_with(
            &device_key(),
            operation,
            server_contributions,
            recipient,
            now.min(NOW),
        )
    }

    async fn sign_rights(
        &self,
        fresh: Option<&RightsRequestV2>,
        replay: Option<&[u8]>,
        expected: RightsRequestCheck<'_>,
        _now: u64,
    ) -> anyhow::Result<PoolWalletAnswer> {
        // The Wallet is reached only after the open's check passes, as pcr's
        // `runtime_release_wallet_request` does.
        let request = match (fresh, replay) {
            (Some(fresh), None) => {
                anyhow::ensure!(
                    expected(&RightsRequestAnyV1::V2(fresh.clone())),
                    "the fresh request is not this open's"
                );
                self.fresh.lock().unwrap().push(fresh.clone());
                fresh.clone()
            }
            (None, Some(bytes)) => {
                let any = RightsRequestAnyV1::from_canonical_bytes(bytes)
                    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
                anyhow::ensure!(expected(&any), "the replay is not this open's request");
                let RightsRequestAnyV1::V2(request) = any else {
                    anyhow::bail!("a V1 request")
                };
                self.replays.lock().unwrap().push(bytes.to_vec());
                request
            }
            _ => anyhow::bail!("one of fresh and replay"),
        };
        let request_bytes = request.canonical_bytes().unwrap();
        match self
            .wallet
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(WalletMode::Sign)
        {
            WalletMode::Pending => Ok(PoolWalletAnswer::PendingApproval {
                request_bytes,
                approval_request_id: "approval-1".into(),
                external_signer: false,
                connector_id: None,
            }),
            WalletMode::Sign => Ok(PoolWalletAnswer::Signed {
                request_bytes,
                response_bytes: b"wallet-response".to_vec(),
                signed_rights: Box::new(wallet_sign(&request)),
            }),
        }
    }

    async fn release(
        &self,
        _wallet_request: &[u8],
        _wallet_response: &[u8],
        operation: &SignedRuntimeReleaseOperationV2,
        now: u64,
    ) -> anyhow::Result<RuntimeReleaseCoordinatorOutcome> {
        self.released.lock().unwrap().push(operation.clone());
        let authenticated = operation
            .verify(RuntimeIssuerPolicyV1::Expected(device_issuer()), now)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let result = match self.release_mode {
            ReleaseMode::Contributions => RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions: authenticated
                    .recipients()
                    .iter()
                    .flat_map(|recipient| {
                        [1u8, 2]
                            .map(|seed| contribution(&authenticated, recipient.identity(), seed))
                    })
                    .collect(),
            },
            ReleaseMode::RightsDenied => RuntimeReleaseTerminalResult::RightsDenied {
                signed_node_rights_decision: Box::new(signed_node_rights_decision(
                    &authenticated,
                    1,
                    RightsDecisionV1::Allowed,
                    NOW - 3,
                )),
            },
        };
        Ok(RuntimeReleaseCoordinatorOutcome::Terminal(result))
    }

    async fn resume_release(
        &self,
        _operation_hash: Digest32,
        _now: u64,
    ) -> anyhow::Result<RuntimeReleaseCoordinatorOutcome> {
        anyhow::bail!("no resume in these tests")
    }

    async fn rights_denied_verdict(&self, now: u64) -> RightsDeniedVerdict {
        match self.verdict {
            RightsDeniedClass::Finalizing => {
                RightsDeniedVerdict::Finalizing(RuntimeCustodyOpenProgress::finalizing(now + 900))
            }
            RightsDeniedClass::Denied => RightsDeniedVerdict::Denied,
            RightsDeniedClass::Unavailable => RightsDeniedVerdict::Unavailable,
        }
    }

    fn persist_pending(&self, pending: &PoolPendingRelease) -> anyhow::Result<()> {
        self.persisted.lock().unwrap().push(PoolPendingRelease {
            wallet_request: pending.wallet_request.clone(),
            approval_request_id: pending.approval_request_id.clone(),
            sessions: pending.sessions.clone(),
        });
        Ok(())
    }
}

fn opened(outcome: PoolOpenOutcome) -> PoolOpened {
    match outcome {
        PoolOpenOutcome::Opened(opened) => opened,
        PoolOpenOutcome::PendingApproval(_) => panic!("expected an opened viewer"),
    }
}

fn progress_of(error: &anyhow::Error) -> &RuntimeCustodyOpenProgress {
    error
        .downcast_ref::<RuntimeCustodyOpenProgress>()
        .expect("the open answers a typed state")
}

/// The text of `fn <name>` up to its closing brace at column 0.
fn fn_body<'s>(source: &'s str, name: &str) -> &'s str {
    let start = source
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} is missing"));
    let end = source[start..]
        .find("\n}\n")
        .unwrap_or_else(|| panic!("fn {name} has no end"));
    &source[start..start + end]
}

/// The text of `struct <name>` up to its closing brace at column 0.
fn struct_body<'s>(source: &'s str, name: &str) -> &'s str {
    let start = source
        .find(&format!("struct {name}"))
        .unwrap_or_else(|| panic!("struct {name} is missing"));
    let end = source[start..]
        .find("\n}\n")
        .unwrap_or_else(|| panic!("struct {name} has no end"));
    &source[start..start + end]
}

/// A prepared server list of one, for the step tests.
fn one_prepared(pool: &Pool, seed: u8) -> Vec<PoolPreparedServer> {
    vec![PoolPreparedServer {
        member: pool
            .resolved
            .descriptor
            .member(node_public_key(seed))
            .unwrap()
            .clone(),
        prepared: attested_recipient(pool, seed),
    }]
}

fn delivery_key() -> DeliveryPublicKeyBytesV1 {
    elastos_protected_content_custody::DeliverySecretKeyV1::generate()
        .unwrap()
        .public_key()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Route matrix (S4-A1)
// ---------------------------------------------------------------------------

/// The route is chosen once, in pcr, after the unchanged checks and before
/// the composition load and the Wallet; these pin each branch's order.
#[test]
fn pool_route_when_the_pool_resolves() {
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let resolve = open
        .find("home_pool_resolver(data_dir, registry.clone())")
        .expect("the resolve");
    let pool_branch = open
        .find("open_runtime_custody_pool_viewer(RuntimeCustodyPoolOpenInput")
        .expect("the pool branch");
    let composition = open
        .find("load_runtime_custody_composition(data_dir, registry.clone())")
        .expect("the local branch's composition load");
    let wallet = open
        .find("invoke_runtime_release_wallet(")
        .expect("the local Wallet call");
    assert!(resolve < pool_branch && pool_branch < composition && composition < wallet);
    // A resolved pool never asks the local-holder predicate.
    assert!(open.contains("Ok(_) => false,"));
}

#[test]
fn unresolved_pool_and_local_holder_opens_local_v1() {
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    // Only a failed resolve consults the predicate, and only a local holder
    // falls through to the local V1 open below.
    assert!(
        open.contains("runtime_custody_local_holder(data_dir, &registry, draft.key_envelope())")
    );
    assert!(open.contains("Err(error) if !local_holder =>"));
    assert!(open.contains("Err(_) => {}"));
}

#[test]
fn holder_without_a_ready_decrypt_target_is_not_a_local_holder() {
    let predicate = fn_body(RUNTIME_SOURCE, "runtime_custody_local_holder");
    let composition = predicate
        .find("runtime_custody_composition_holds_key_envelope(")
        .expect("the composition check");
    let target = predicate
        .find("has_ready_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)")
        .expect("the decrypt target check");
    // Both must hold: a holder whose decrypt target is not ready is not one.
    assert!(composition < target);
    assert!(predicate.contains("return Ok(false);"));
}

#[test]
fn own_pool_with_no_eligible_remote_server_and_local_holder_opens_local_v1() {
    // The owner's own pool resolves to NoEligibleServer when it is the only
    // server; the local holder then opens through its local V1 path.
    let pool = pool(1);
    let all_own = [node_public_key(1), node_public_key(2), node_public_key(3)];
    assert_eq!(
        resolve_pool_from_candidates(
            vec![("own", pool.resolved.signed.clone())],
            &AcceptAnyPool,
            pool.binding.key_envelope(),
            &all_own,
            NOW,
        )
        .err(),
        Some(PoolResolveError::NoEligibleServer)
    );
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    assert!(open.contains("Err(_) => runtime_custody_local_holder("));
}

#[test]
fn own_pool_with_no_eligible_remote_server_and_no_local_holder_answers_no_eligible_server_before_wallet(
) {
    let answer = pool_unresolved_error(PoolResolveError::NoEligibleServer);
    assert_eq!(
        answer.to_string(),
        crate::protected_content_runtime::RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE
    );
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let refusal = open.find("pool_unresolved_error(").expect("the refusal");
    let wallet = open.find("invoke_runtime_release_wallet(").unwrap();
    assert!(refusal < wallet);
}

#[tokio::test]
async fn unresolved_pool_answers_custody_unresolved_before_wallet() {
    for (error, message) in [
        (
            PoolResolveError::Unresolved,
            crate::protected_content_runtime::RUNTIME_CUSTODY_UNRESOLVED_MESSAGE,
        ),
        (
            PoolResolveError::Invalid,
            crate::protected_content_runtime::RUNTIME_CUSTODY_UNRESOLVED_MESSAGE,
        ),
        (
            PoolResolveError::NoEligibleServer,
            crate::protected_content_runtime::RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE,
        ),
    ] {
        let answer = pool_unresolved_error(error);
        assert_eq!(answer.to_string(), message);
        // Not resumable: a Retry, not a wait (S4-Q16).
        let progress = progress_of(&answer);
        assert!(!progress.awaits_person());
        assert_eq!(
            progress.stage_label(),
            RuntimeCustodyOpenProgress::unavailable().stage_label()
        );
    }
    // pcr answers it right after the resolve, before any Wallet call, and
    // the pool branch never answers it.
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let unresolved = open
        .find("pool_unresolved_error(")
        .expect("the unresolved answer");
    let wallet = open
        .find("invoke_runtime_release_wallet(")
        .expect("the local Wallet call");
    assert!(unresolved < wallet);
    assert!(!fn_body(RUNTIME_SOURCE, "open_runtime_custody_pool_viewer")
        .contains("pool_unresolved_error"));
}

#[tokio::test]
async fn every_server_refusing_prepare_answers_no_eligible_server_without_local_fallback() {
    let pool = pool(1);
    let mut servers = FakeServers::new(&pool);
    for seed in 1..=3 {
        servers = servers.refusing(seed, PoolTransportError::Refused("pool_busy".into()));
    }
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let error = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .err()
        .expect("nobody can prepare");
    assert_eq!(
        error.to_string(),
        crate::protected_content_runtime::RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE
    );
    assert_eq!(ports.wallet_calls(), 0);
    // pcr returns the pool branch's answer as it is: no local fallback.
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let pool_branch = open
        .find("return open_runtime_custody_pool_viewer(")
        .expect("the pool branch returns");
    assert!(open[pool_branch..].contains(".await;"));
}

#[test]
fn pending_resume_keeps_its_route() {
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    // A local pending record skips the pool entirely; a pool pending record
    // never becomes a local holder.
    assert!(open.contains("if resumed_pending_release.is_none() || resumed_is_pool {"));
    assert!(open.contains("Err(_) if resumed_is_pool => false,"));
}

// ---------------------------------------------------------------------------
// The pool branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pool_open_never_calls_the_local_decrypt_target() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let opened = opened(
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .unwrap(),
    );
    // Prepared and opened at one pool server; nothing else was asked.
    assert_eq!(servers.prepared_seeds().len(), 1);
    assert_eq!(servers.opened().len(), 1);
    assert_eq!(opened.sessions.servers_hex().len(), 1);
    // The pool path names no local decrypt call, and the pool entry in pcr
    // neither prepares a local recipient nor opens a local session.
    for local in [
        "RuntimeDecryptRegistryAdapter",
        "prepare_recipient(",
        "open_viewer_session(",
        "DECRYPT_PROVIDER_ID",
    ] {
        assert!(
            !POOL_MODULE_SOURCE.contains(local),
            "the pool module uses {local}"
        );
        for body in [
            fn_body(RUNTIME_SOURCE, "open_runtime_custody_pool_viewer"),
            fn_body(RUNTIME_SOURCE, "runtime_custody_pool_record_has_secret"),
        ] {
            assert!(!body.contains(local), "the pool open uses {local}");
        }
    }
}

#[tokio::test]
async fn prepare_fails_over_to_next_server() {
    for refusal in [
        PoolTransportError::Unreachable,
        PoolTransportError::Refused("server_not_ready".into()),
        PoolTransportError::Refused("pool_busy".into()),
        PoolTransportError::Refused("decrypt_unavailable".into()),
    ] {
        assert!(prepare_fails_over(&refusal), "{refusal:?}");
        let pool = pool(1);
        // Everyone refuses: every server is tried, and no Wallet request
        // is raised.
        let mut servers = FakeServers::new(&pool);
        for seed in 1..=3 {
            servers = servers.refusing(seed, refusal.clone());
        }
        let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
        let keys = PoolDeliveryKeys::default();
        let error = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .err()
            .expect("nobody can prepare");
        assert_eq!(
            ports.wallet_calls(),
            0,
            "no Wallet request without a server"
        );
        assert!(format!("{error:#}").contains(
            crate::protected_content_runtime::RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE
        ));
        let mut tried = servers.prepared_seeds();
        tried.sort_unstable();
        assert_eq!(tried, [1, 2, 3]);

        // Only node 3 answers. The server order is random per open, so the
        // open is repeated until node 3 came after a refusal at least once.
        let mut failed_over = false;
        for _ in 0..32 {
            let servers = FakeServers::new(&pool)
                .refusing(1, refusal.clone())
                .refusing(2, refusal.clone());
            let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
            let keys = PoolDeliveryKeys::default();
            let opened = opened(
                open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
                    .await
                    .unwrap(),
            );
            let tried = servers.prepared_seeds();
            assert_eq!(tried.last(), Some(&3), "{tried:?}");
            assert_eq!(servers.opened()[0].0, 3, "the answering server serves");
            assert_eq!(opened.sessions.session_ids_hex(), [hex::encode([3u8; 16])]);
            failed_over |= tried.len() > 1;
        }
        assert!(failed_over, "the open moved down the order after a refusal");
    }
    // NoExactResult stops: the server may have acted.
    assert!(!prepare_fails_over(&PoolTransportError::NoExactResult));
    assert!(!prepare_fails_over(&PoolTransportError::Refused(
        "binding_mismatch".into()
    )));
    let pool = pool(1);
    let mut servers = FakeServers::new(&pool);
    for seed in 1..=3 {
        servers = servers.refusing(seed, PoolTransportError::NoExactResult);
    }
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    assert!(
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .is_err()
    );
    assert_eq!(
        servers.prepared_seeds().len(),
        1,
        "no second prepare after NoExactResult"
    );
    assert_eq!(ports.wallet_calls(), 0);
}

#[tokio::test]
async fn rights_v2_names_server_recipients_and_delivery_key() {
    let pool = pool(2);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let rights = ports.fresh.lock().unwrap()[0].clone();
    let seeds = servers.prepared_seeds();
    assert_eq!(seeds.len(), 2, "two servers, as the descriptor allows");
    assert_eq!(rights.recipients().len(), 2);
    for seed in seeds {
        let recipient = attested_recipient(&pool, seed);
        assert!(rights
            .recipients()
            .contains(recipient.attestation.statement().recipient_identity()));
    }
    let delivery = keys
        .with_entry(&handle(), |entry| entry.delivery_public_key().unwrap())
        .unwrap();
    assert_eq!(rights.delivery_key(), Some(delivery.identity()));
    assert_eq!(rights.binding(), &pool.binding);
    // ADV-01: the chain of the policy read first.
    assert_eq!(rights.chain_id(), POLICY_CHAIN);
    // T4.4 pre-Wallet cap: no later than the attestations (NOW + 200).
    assert_eq!(rights.expires_at(), NOW + 200);
}

#[tokio::test]
async fn pending_approval_resumes_same_server_session() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Pending, WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let pending = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let PoolOpenOutcome::PendingApproval(progress) = pending else {
        panic!("expected a pending approval");
    };
    assert_eq!(
        progress.stage_label(),
        RuntimeCustodyOpenProgress::awaiting_rights_approval(false, None, "approval-1", NOW + 290)
            .stage_label()
    );
    let persisted = ports
        .persisted
        .lock()
        .unwrap()
        .pop()
        .expect("the pending release is kept");
    assert_eq!(persisted.approval_request_id, "approval-1");
    assert!(
        keys.contains(&handle(), NOW),
        "the delivery secret waits with the approval"
    );
    let prepared_before = servers.prepared_seeds();

    let resume = PoolResume {
        wallet_request: persisted.wallet_request.clone(),
        sessions: persisted.sessions.clone(),
    };
    let opened = opened(
        open_pool_viewer(context(&pool, &[], Some(resume)), &servers, &ports, &keys)
            .await
            .unwrap(),
    );
    // No new prepare: the same server session opens.
    assert_eq!(servers.prepared_seeds(), prepared_before);
    let opens = servers.opened();
    assert_eq!(opens.len(), 1);
    assert_eq!(opens[0].1.session_id, [prepared_before[0]; 16]);
    assert_eq!(
        opened.sessions.session_ids_hex(),
        [hex::encode([prepared_before[0]; 16])]
    );
    // The exact request was replayed, not a new one raised.
    assert_eq!(ports.fresh.lock().unwrap().len(), 1);
    assert_eq!(
        ports.replays.lock().unwrap().as_slice(),
        [persisted.wallet_request]
    );
}

#[tokio::test]
async fn pending_resume_without_delivery_secret_starts_fresh() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Pending]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let persisted = ports.persisted.lock().unwrap().pop().unwrap();
    // A restart loses the secret.
    let restarted = PoolDeliveryKeys::default();
    assert!(!restarted.contains(&handle(), NOW));
    let resume = PoolResume {
        wallet_request: persisted.wallet_request,
        sessions: persisted.sessions,
    };
    let replays_before = ports.replays.lock().unwrap().len();
    assert!(
        open_pool_viewer(
            context(&pool, &[], Some(resume)),
            &servers,
            &ports,
            &restarted
        )
        .await
        .is_err(),
        "a resume never replays without its delivery key"
    );
    assert_eq!(ports.replays.lock().unwrap().len(), replays_before);
    // The open resumes only with the secret; otherwise the record settles
    // and the open starts fresh (pcr's resume guard).
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let resume_arm = open
        .find(
            "RuntimeCustodyViewerLifecycleStatus::OpenPending\n                if record.pending_release.is_some()",
        )
        .expect("the resume arm");
    let resume_end = open[resume_arm..].find("=>").unwrap();
    assert!(open[resume_arm..resume_arm + resume_end]
        .contains("runtime_custody_pool_record_has_secret(&record, viewer_now)"));
}

#[test]
fn active_record_without_delivery_secret_reopens() {
    let keys = PoolDeliveryKeys::default();
    let secret = elastos_protected_content_custody::DeliverySecretKeyV1::generate().unwrap();
    keys.insert(
        handle(),
        PoolDeliveryEntry::pending(secret, Vec::new(), Vec::new(), NOW + 50),
    );
    assert!(keys.contains(&handle(), NOW + 49));
    // At its end the entry is dropped, as on close.
    assert!(!keys.contains(&handle(), NOW + 50));
    assert!(keys.take(&handle()).is_none());
    // The Active shortcut needs the secret; without it the record settles
    // and the open starts fresh.
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let active_arm = open
        .find(
            "RuntimeCustodyViewerLifecycleStatus::Active\n                if record.matches_runtime_session_binding(&runtime_session_binding)",
        )
        .expect("the Active shortcut");
    let active_end = open[active_arm..].find("=>").unwrap();
    assert!(open[active_arm..active_arm + active_end]
        .contains("runtime_custody_pool_record_has_secret(&record, viewer_now)"));
    // And the cleanup of a pool record drops its secret.
    assert!(
        fn_body(RUNTIME_SOURCE, "settle_runtime_custody_viewer_cleanup")
            .contains("runtime_custody_close_pool_viewer(data_dir, &registry, &handle)")
    );
}

#[tokio::test]
async fn owner_opens_own_item_through_another_member() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    // The owner's Home is node 1 of its own pool.
    let own = [node_public_key(1)];
    open_pool_viewer(context(&pool, &own, None), &servers, &ports, &keys)
        .await
        .unwrap();
    let seeds = servers.prepared_seeds();
    assert_eq!(seeds.len(), 1);
    assert_ne!(seeds[0], 1, "the owner never serves itself");
    assert_ne!(servers.opened()[0].0, 1);
    // With every server its own, nothing is asked at all.
    let servers = FakeServers::new(&pool);
    let all_own = [node_public_key(1), node_public_key(2), node_public_key(3)];
    let error = open_pool_viewer(context(&pool, &all_own, None), &servers, &ports, &keys)
        .await
        .err()
        .unwrap();
    assert!(servers.prepared_seeds().is_empty());
    assert!(!progress_of(&error).awaits_person());
}

#[test]
fn own_member_route_is_local() {
    let pool = pool(1);
    let own = [node_public_key(2)];
    let member = pool.resolved.descriptor.member(node_public_key(2)).unwrap();
    assert!(matches!(
        epoch_node_transport(member, &own, &KeptCardTickets::new()),
        ProviderInvocationTransport::Local
    ));
}

/// Item 10: the descriptor carries no tickets, so a buyer reaches every
/// other member by its peer DID through Carrier discovery, with a bounded
/// answer wait.
#[test]
fn servers_are_reached_by_peer_did_with_a_bounded_wait() {
    let pool = pool(1);
    for member in pool.resolved.descriptor.members() {
        match epoch_node_transport(member, &[], &KeptCardTickets::new()) {
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did,
                timeout_ms,
                reply_wait_ms,
            }) => {
                assert_eq!(peer_did, member.route().peer_did());
                assert!(timeout_ms.is_some(), "the connect is bounded");
                assert!(reply_wait_ms.is_some(), "the answer wait is bounded");
            }
            other => panic!("a buyer reaches a member by peer DID, not {other:?}"),
        }
    }
}

/// A pool member reaches the epoch nodes whose cards it kept by their
/// tickets, still with a bounded wait; the others by peer DID.
#[test]
fn pool_member_routes_epoch_nodes_with_its_kept_cards() {
    let pool = pool(1);
    let kept_member = pool.resolved.descriptor.member(node_public_key(3)).unwrap();
    let mut kept = KeptCardTickets::new();
    kept.insert(
        kept_member.route().peer_did().to_string(),
        "kept-ticket-3".to_string(),
    );
    for member in pool.resolved.descriptor.members() {
        let transport = epoch_node_transport(member, &[], &kept);
        if member.node_public_key() == node_public_key(3) {
            match transport {
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::ConnectTicket {
                    connect_ticket,
                    peer_did,
                    reply_wait_ms,
                    ..
                }) => {
                    assert_eq!(connect_ticket, "kept-ticket-3");
                    assert_eq!(peer_did.as_deref(), Some(member.route().peer_did()));
                    assert!(reply_wait_ms.is_some());
                }
                other => panic!("a kept card routes by its ticket, not {other:?}"),
            }
        } else {
            assert!(matches!(
                transport,
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid { .. })
            ));
        }
    }
    // pcr reads the kept cards once per open and routes through them.
    assert!(
        fn_body(RUNTIME_SOURCE, "open_runtime_custody_pool_viewer").contains(
            "kept_card_tickets: crate::custody_pool_setup::kept_card_tickets(input.data_dir)"
        )
    );
}

#[test]
fn operation_expiry_is_bounded_by_attestations() {
    let pool = pool(1);
    let prepared = one_prepared(&pool, 2);
    let delivery = delivery_key();
    let rights = pool_rights_request(
        &pool.binding,
        RightsActionV1::View,
        &prepared,
        &delivery,
        NOW,
        NOW + 290,
        POLICY_CHAIN,
    )
    .unwrap();
    let signed = wallet_sign(&rights);
    let identity = pool.policy.policy_identity().unwrap();
    let input = PoolOperationInput {
        signed_rights: &signed,
        prepared: &prepared,
        policy_body: &pool.policy,
        policy_identity: &identity,
        resolved: &pool.resolved,
        audit_request_id: RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap(),
    };
    // Early in the window: the usual lifetime.
    let early = pool_release_statement(device_issuer(), &input, NOW).unwrap();
    assert_eq!(early.expires_at(), NOW + 50);
    // Late: the attestation and rights (NOW + 200) bound it.
    let late = pool_release_statement(device_issuer(), &input, NOW + 180).unwrap();
    assert_eq!(late.expires_at(), NOW + 200);
    // Past it: the open fails cleanly and starts fresh.
    let error = pool_release_statement(device_issuer(), &input, NOW + 200).unwrap_err();
    assert!(error.downcast_ref::<PoolOperationExpired>().is_some());
    // The early operation verifies as this Runtime's.
    sign_release_operation_v2_with(&device_key(), early)
        .unwrap()
        .verify(RuntimeIssuerPolicyV1::Expected(device_issuer()), NOW)
        .unwrap();
}

#[tokio::test]
async fn prepare_sends_the_drafts_kind_identity_and_commitment() {
    let draft = crate::protected_content_runtime::tests::mint_draft_for_composition_journal_test();
    let content = pool_content_ref("bafy-item", &draft);
    assert_eq!(content.cid, "bafy-item");
    assert_eq!(
        content.content_key_commitment,
        draft.content_key_commitment()
    );
    assert_eq!(content.kind, content.identity.kind());
    match (draft.content_identity(), &content.identity) {
        (RuntimeContentIdentityV1::Media(draft), PoolContentIdentityV1::MediaV1(sent)) => {
            assert_eq!(draft, sent)
        }
        (RuntimeContentIdentityV1::MediaDash(draft), PoolContentIdentityV1::DashV2(sent)) => {
            assert_eq!(draft, sent)
        }
        (RuntimeContentIdentityV1::Object(draft), PoolContentIdentityV1::Object(sent)) => {
            assert_eq!(draft, sent)
        }
        _ => panic!("the kind changed on the way to the server"),
    }
    // The open sends exactly that to every server it prepares.
    let pool = pool(2);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    for (_, request) in servers.prepares.lock().unwrap().iter() {
        assert_eq!(request.content, pool.content);
        assert_eq!(request.binding, pool.binding);
        assert_eq!(request.runtime_operation_issuer, device_issuer());
        assert_eq!(request.expires_at, NOW + 290);
        assert_eq!(&request.pool, pool.resolved.descriptor.pool());
    }
}

#[tokio::test]
async fn open_sends_the_delivery_key_the_wallet_signed() {
    let pool = pool(2);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let operation = ports.released.lock().unwrap()[0].clone();
    let authenticated = operation
        .verify(RuntimeIssuerPolicyV1::Expected(device_issuer()), NOW)
        .unwrap();
    let opens = servers.opened();
    assert_eq!(opens.len(), 2);
    for (seed, open) in opens {
        assert_eq!(open.operation, operation);
        // F3: the key whose identity the Wallet signed.
        assert_eq!(
            open.delivery_public_key.identity(),
            authenticated.delivery_key()
        );
        // Only this server's contributions, under a receipt over the
        // operation hash (L1) that this Runtime signed.
        let recipient = attested_recipient(&pool, seed);
        let recipient = recipient.attestation.statement().recipient_identity();
        assert_eq!(open.contributions.len(), 2);
        let node_set = pool.bundle.signed_epoch().statement().node_set().unwrap();
        let verified = open
            .contributions
            .iter()
            .map(|contribution| {
                assert_eq!(
                    contribution
                        .statement()
                        .recipient_sealed_contribution()
                        .recipient(),
                    recipient
                );
                authenticated
                    .verify_node_contribution(contribution, &node_set, recipient, NOW)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        authenticated
            .verify_terminal_receipt(
                &open.terminal_receipt,
                &verified,
                TerminalReceiptIssuerKey::new(device_key().verifying_key().to_bytes()).unwrap(),
                NOW,
            )
            .unwrap();
    }
}

/// User 2026-11-13 04:45: the delivery entry and the viewer record end at
/// the session's end, the signed rights expiry capped by the attestations,
/// not at the release operation's expiry.
#[tokio::test]
async fn viewer_record_expires_at_rights_expiry_capped_by_attestation() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let opened = opened(
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .unwrap(),
    );
    let operation = ports.released.lock().unwrap()[0].clone();
    let session_end = operation.statement().session_expires_at();
    assert!(session_end > operation.statement().expires_at());
    assert_eq!(
        session_end,
        operation
            .statement()
            .rights_request()
            .request()
            .expires_at()
            .min(NOW + 200)
    );
    assert_eq!(opened.expires_at, session_end);
    assert_eq!(
        keys.with_entry(&handle(), |entry| entry.expires_at()),
        Some(session_end)
    );
    assert!(keys
        .with_entry(&handle(), |entry| entry.operation_hash())
        .flatten()
        .is_some());
    // The record takes it from the opened viewer.
    let record = fn_body(RUNTIME_SOURCE, "from_pool_opened");
    assert!(record.contains("record.expires_at = opened.expires_at;"));
}

#[tokio::test]
async fn open_answer_carries_read_ahead_segments_from_the_verified_descriptor() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let opened = opened(
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .unwrap(),
    );
    assert_eq!(
        opened.read_ahead_segments,
        pool.resolved
            .descriptor
            .serve_policy()
            .bounds
            .read_ahead_segments
    );
    // The reply that carries it is pinned by the shared viewer contract
    // (`protected_content_runtime::tests::every_viewer_reply_matches_the_shared_viewer_contract`).
}

/// S4-R4-F3: the open signs through the typed port, which loads the device
/// key per call; no context, port struct or delivery entry keeps a signer.
#[tokio::test]
async fn open_signs_through_the_typed_port_and_stores_no_signer() {
    let pool = pool(2);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    assert_eq!(ports.sign_operation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ports.sign_receipt_calls.load(Ordering::SeqCst), 2);
    for (source, name) in [
        (POOL_MODULE_SOURCE, "PoolOpenContext<'a>"),
        (POOL_MODULE_SOURCE, "PoolDeliveryEntry"),
        (RUNTIME_SOURCE, "RuntimePoolOpenPorts<'a>"),
    ] {
        assert!(
            !struct_body(source, name).contains("SigningKey"),
            "{name} keeps a signer"
        );
    }
    for port in [
        "fn sign_release_operation_v2(",
        "fn sign_terminal_receipt_v2(",
        "fn device_issuer(",
    ] {
        assert!(RUNTIME_SOURCE.contains(port), "pcr implements {port}");
    }
    assert!(RUNTIME_SOURCE.contains("load_runtime_pool_device_signing_key(self.data_dir)?"));
}

/// The INFO log this thread writes while the guard lives.
fn capture_info_logs() -> (
    std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    tracing::subscriber::DefaultGuard,
) {
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
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = LogWriter(std::sync::Arc::clone(&output));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    (output, tracing::subscriber::set_default(subscriber))
}

fn logged_text(output: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
    String::from_utf8(output.lock().unwrap().clone()).unwrap()
}

/// dkms-reviewer: the delivery key is logged once, when the approval is
/// created; a poll that finds the same approval pending logs nothing new.
#[tokio::test]
async fn polling_a_pending_approval_twice_logs_the_delivery_key_once() {
    let (output, _subscriber) = capture_info_logs();
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(
        &pool,
        &[
            WalletMode::Pending,
            WalletMode::Pending,
            WalletMode::Pending,
        ],
    );
    let keys = PoolDeliveryKeys::default();
    let PoolOpenOutcome::PendingApproval(_) =
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .unwrap()
    else {
        panic!("the first open asks the Wallet");
    };
    let (wallet_request, sessions) = {
        let persisted = ports.persisted.lock().unwrap();
        assert_eq!(persisted.len(), 1);
        (
            persisted[0].wallet_request.clone(),
            persisted[0].sessions.clone(),
        )
    };
    for _ in 0..2 {
        let resume = PoolResume {
            wallet_request: wallet_request.clone(),
            sessions: sessions.clone(),
        };
        let PoolOpenOutcome::PendingApproval(progress) =
            open_pool_viewer(context(&pool, &[], Some(resume)), &servers, &ports, &keys)
                .await
                .unwrap()
        else {
            panic!("the poll finds the approval still pending");
        };
        assert_eq!(progress.as_json()["approval_request_id"], "approval-1");
    }
    let log = logged_text(&output);
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("delivery_key=0x"))
            .count(),
        1,
        "{log}"
    );
    // One approval was created, and no other.
    assert_eq!(ports.persisted.lock().unwrap().len(), 1);
}

/// User decision 2026-11-13 13:05 (reverses item 4's display): the approval
/// progress the viewer reads carries no delivery key fingerprint; the open
/// logs it once at info, with the approval request and the operation's audit
/// id, equal to the Wallet text's `Delivery key:` line.
#[tokio::test]
async fn approval_progress_carries_no_delivery_key_and_the_log_names_it() {
    let (output, _subscriber) = capture_info_logs();

    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Pending]);
    let keys = PoolDeliveryKeys::default();
    let ctx = context(&pool, &[], None);
    let audit = hex::encode(ctx.audit_request_id.digest().as_bytes());
    let PoolOpenOutcome::PendingApproval(progress) = open_pool_viewer(ctx, &servers, &ports, &keys)
        .await
        .unwrap()
    else {
        panic!("expected a pending approval");
    };
    let answer = progress.as_json();
    assert!(answer.get("delivery_key_fingerprint").is_none(), "{answer}");
    assert!(!answer.to_string().contains("Delivery key"), "{answer}");
    let approval = answer["approval_request_id"].as_str().unwrap().to_string();

    let rights = ports.fresh.lock().unwrap()[0].clone();
    let text = rights.signing_message().unwrap();
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("Delivery key: "))
        .expect("the Wallet text names the delivery key")
        .to_string();
    let log = logged_text(&output);
    let logged: Vec<&str> = log
        .lines()
        .filter(|entry| entry.contains(&format!("delivery_key={line}")))
        .collect();
    assert_eq!(logged.len(), 1, "{log}");
    assert!(logged[0].contains("INFO"), "{log}");
    assert!(
        logged[0].contains(&format!("approval_request_id={approval}")),
        "{log}"
    );
    assert!(
        logged[0].contains(&format!("audit_request_id={audit}")),
        "{log}"
    );
    // The direct V1 open shows nothing either.
    let direct =
        RuntimeCustodyOpenProgress::awaiting_rights_approval(false, None, "approval-1", NOW + 290);
    assert!(direct.as_json().get("delivery_key_fingerprint").is_none());
}

// ---------------------------------------------------------------------------
// F9
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rights_denied_maps_to_denied_only_when_finalized_access_is_absent() {
    use RuntimeCustodyAccessAt::{Granted, NotGranted, Unanswered};
    assert_eq!(
        rights_denied_class(NotGranted, NotGranted),
        RightsDeniedClass::Denied
    );
    assert_eq!(
        rights_denied_class(NotGranted, Granted),
        RightsDeniedClass::Finalizing
    );
    for (finalized, latest) in [
        (Granted, Granted),
        (Granted, NotGranted),
        (Granted, Unanswered),
        (Unanswered, Granted),
        (Unanswered, NotGranted),
        (Unanswered, Unanswered),
        (NotGranted, Unanswered),
    ] {
        assert_eq!(
            rights_denied_class(finalized, latest),
            RightsDeniedClass::Unavailable,
            "{finalized:?} {latest:?}"
        );
    }
    // The open answers each class. OPEN-LOOP F2: an unavailable verdict
    // comes after the Wallet signed, so it ends the open (see
    // `assert_final_after_approval`).
    for (verdict, stage) in [
        (
            RightsDeniedClass::Denied,
            Some(RuntimeCustodyOpenProgress::denied().stage_label()),
        ),
        (RightsDeniedClass::Unavailable, None),
    ] {
        let pool = pool(1);
        let servers = FakeServers::new(&pool);
        let mut ports = FakePorts::new(&pool, &[WalletMode::Sign]);
        ports.release_mode = ReleaseMode::RightsDenied;
        ports.verdict = verdict;
        let keys = PoolDeliveryKeys::default();
        let error = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .err()
            .expect("a denied release opens nothing");
        match stage {
            Some(stage) => assert_eq!(progress_of(&error).stage_label(), stage),
            None => assert_final_after_approval(&error),
        }
        assert!(servers.opened().is_empty());
    }
}

/// OPEN-LOOP OP2 (b): finality is read before the Wallet, so a `finalizing`
/// verdict after the approval was spent follows F2: the open ends with
/// Retry, and no second approval request is raised.
#[tokio::test]
async fn rights_denied_while_latest_grants_after_the_approval_raises_no_second_request() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let mut ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    ports.release_mode = ReleaseMode::RightsDenied;
    ports.verdict = RightsDeniedClass::Finalizing;
    let keys = PoolDeliveryKeys::default();
    let error = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .err()
        .unwrap();
    assert_final_after_approval(&error);
    assert_eq!(ports.wallet_calls(), 1);
    assert_eq!(ports.released.lock().unwrap().len(), 1);
    assert!(servers.opened().is_empty());
}

// ---------------------------------------------------------------------------
// ADV-01 §4B: the policy before the Wallet, the chain-aware matcher
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pool_open_policy_lookup_failure_never_reaches_the_wallet() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let mut ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    ports.policy_fails = true;
    let keys = PoolDeliveryKeys::default();
    assert!(
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .is_err()
    );
    assert_eq!(ports.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ports.wallet_calls(), 0);
    // Nothing was built or sent: no server was asked, no key was made.
    assert!(servers.prepared_seeds().is_empty());
    assert!(!keys.contains(&handle(), NOW));
}

/// A pending request this open would replay names another chain than the
/// policy read first: refused before the Wallet.
#[tokio::test]
async fn pool_open_pending_request_for_another_chain_is_refused_before_the_wallet() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Pending]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let persisted = ports.persisted.lock().unwrap().pop().unwrap();
    let held = ports.fresh.lock().unwrap()[0].clone();
    // The same request on another chain, as an older pending record holds.
    let delivery = keys
        .with_entry(&handle(), |entry| entry.delivery_public_key().unwrap())
        .unwrap();
    let prepared = persisted.sessions.restore(&pool.resolved).unwrap();
    let other_chain = pool_rights_request(
        &pool.binding,
        RightsActionV1::View,
        &prepared,
        &delivery,
        NOW,
        held.expires_at(),
        POLICY_CHAIN + 1,
    )
    .unwrap();
    let wallet_before = ports.wallet_calls();
    let resume = PoolResume {
        wallet_request: other_chain.canonical_bytes().unwrap(),
        sessions: persisted.sessions,
    };
    assert!(
        open_pool_viewer(context(&pool, &[], Some(resume)), &servers, &ports, &keys)
            .await
            .is_err()
    );
    assert_eq!(ports.wallet_calls(), wallet_before);
    assert!(servers.opened().is_empty());
}

/// The matcher that gates a replay refuses a request that differs from this
/// open's only in its chain, and pcr hands it to the Wallet path as the
/// replay check.
#[test]
fn pool_open_replayed_request_for_another_chain_is_refused_before_the_wallet() {
    let pool = pool(1);
    let prepared = one_prepared(&pool, 2);
    let delivery = delivery_key();
    let request = |chain| {
        RightsRequestAnyV1::V2(
            pool_rights_request(
                &pool.binding,
                RightsActionV1::View,
                &prepared,
                &delivery,
                NOW,
                NOW + 290,
                chain,
            )
            .unwrap(),
        )
    };
    let matches = |request: &RightsRequestAnyV1| {
        rights_request_matches(
            request,
            &pool.binding,
            RightsActionV1::View,
            &prepared,
            &delivery,
            POLICY_CHAIN,
        )
    };
    assert!(matches(&request(POLICY_CHAIN)));
    assert!(!matches(&request(POLICY_CHAIN + 1)));
    // Another delivery key or a later expiry than the attestations is not
    // this open's either.
    assert!(!rights_request_matches(
        &request(POLICY_CHAIN),
        &pool.binding,
        RightsActionV1::View,
        &prepared,
        &delivery_key(),
        POLICY_CHAIN,
    ));
    let late = pool_rights_request(
        &pool.binding,
        RightsActionV1::View,
        &prepared,
        &delivery,
        NOW,
        NOW + 290,
        POLICY_CHAIN,
    )
    .unwrap();
    assert!(late.expires_at() <= prepared[0].attestation_expires_at());
    // pcr: the open's check is the Wallet path's replay check.
    assert!(fn_body(RUNTIME_SOURCE, "invoke_runtime_release_wallet_any")
        .contains("runtime_release_wallet_request(fresh, replay_matches, invocation, replay_request, now)"));
    assert!(RUNTIME_SOURCE.contains("            |request| expected(request),"));
}

/// R5 (a): bytes that are not a current V2 request (a pre-alignment or
/// truncated layout) never reach the Wallet.
#[tokio::test]
async fn pool_open_resume_with_pre_alignment_pending_bytes_is_refused_before_the_wallet() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Pending]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let persisted = ports.persisted.lock().unwrap().pop().unwrap();
    let mut old_layout = persisted.wallet_request.clone();
    // The current layout without its trailing chain id.
    old_layout.truncate(old_layout.len() - 8);
    assert!(RightsRequestAnyV1::from_canonical_bytes(&old_layout).is_err());
    let wallet_before = ports.wallet_calls();
    let resume = PoolResume {
        wallet_request: old_layout,
        sessions: persisted.sessions,
    };
    assert!(
        open_pool_viewer(context(&pool, &[], Some(resume)), &servers, &ports, &keys)
            .await
            .is_err()
    );
    assert_eq!(ports.wallet_calls(), wallet_before);
}

#[tokio::test]
async fn pool_open_builds_the_operation_with_the_policy_it_signed_against() {
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    assert_eq!(
        ports.policy_calls.load(Ordering::SeqCst),
        1,
        "one policy call"
    );
    let operation = ports.released.lock().unwrap()[0].clone();
    assert_eq!(operation.statement().policy_body(), &pool.policy);
    assert_eq!(
        operation.statement().rights_request().request().chain_id(),
        pool.policy.chain_id()
    );
    // The policy is read before the resume match and before the Wallet.
    let open = fn_body(POOL_MODULE_SOURCE, "open_pool_viewer<S, P>");
    let policy = open.find("ports.rights_policy().await?").unwrap();
    let resume = open.find("match &ctx.resume").unwrap();
    let wallet = open.find(".sign_rights(").unwrap();
    assert!(policy < resume && resume < wallet);
    assert_eq!(open.matches("rights_policy()").count(), 1);
}

#[test]
fn delivery_key_fingerprint_is_eight_bytes_lowercase() {
    let identity = DeliveryKeyIdentityV1::new(Digest32::new([0xab; 32]));
    assert_eq!(delivery_key_fingerprint(identity), "0xabababababababab");
}

// ---------------------------------------------------------------------------
// T4.5: read and close through the pool
// ---------------------------------------------------------------------------

/// An opened viewer on `pool`, its servers, its ports and its keys.
async fn opened_viewer<'a>(
    pool: &'a Pool,
    keys: &PoolDeliveryKeys,
) -> (FakeServers<'a>, FakePorts<'a>, PoolOpened) {
    let servers = FakeServers::new(pool);
    let ports = FakePorts::new(pool, &[WalletMode::Sign]);
    let outcome = open_pool_viewer(context(pool, &[], None), &servers, &ports, keys)
        .await
        .unwrap();
    (servers, ports, opened(outcome))
}

const EVERY_KIND: [ViewerPartIndexV1; 5] = [
    // V1 media: the init (its header may be absent, L12) and a segment.
    ViewerPartIndexV1::MediaV1Init,
    ViewerPartIndexV1::MediaV1Segment(3),
    // DASH v2: an init (it carries its header, L12) and a segment.
    ViewerPartIndexV1::DashInit { rendition: 1 },
    ViewerPartIndexV1::DashSegment {
        rendition: 0,
        index: 2,
    },
    // An object chunk.
    ViewerPartIndexV1::ObjectChunk(5),
];

#[tokio::test]
async fn pool_open_reads_every_kind() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, _, _) = opened_viewer(&pool, &keys).await;
    for part in EVERY_KIND {
        let clear = read_pool_viewer(&handle(), part, &servers, &keys, NOW + 1)
            .await
            .unwrap();
        // Byte-exact: what the server sealed is what the viewer gets.
        assert_eq!(clear.as_slice(), clear_part(part).as_slice(), "{part:?}");
    }
    // The buyer sent only the part index; no ciphertext is fetched here.
    let reads = servers.reads.lock().unwrap().clone();
    assert_eq!(
        reads.iter().map(|(_, read)| read.part).collect::<Vec<_>>(),
        EVERY_KIND
    );
    let read = fn_body(RUNTIME_SOURCE, "read_runtime_custody_pool_part");
    for fetch in [
        "fetch_bytes_via_provider",
        "fetch_content_object_manifest",
        "RuntimeDecryptRegistryAdapter",
    ] {
        assert!(!read.contains(fetch), "the pool read uses {fetch}");
    }
    for mapping in [
        "ViewerPartIndexV1::MediaV1Init",
        "ViewerPartIndexV1::MediaV1Segment(segment_index)",
        "ViewerPartIndexV1::DashInit { rendition }",
        "ViewerPartIndexV1::DashSegment { rendition, index }",
        "ViewerPartIndexV1::ObjectChunk(chunk_index)",
    ] {
        assert!(read.contains(mapping), "{mapping}");
    }
    // The pool branch runs before any local decrypt call.
    let viewer = fn_body(RUNTIME_SOURCE, "read_runtime_custody_viewer");
    let pool_branch = viewer.find("read_runtime_custody_pool_part(").unwrap();
    let local = viewer.find("RuntimeDecryptRegistryAdapter::new").unwrap();
    assert!(pool_branch < local);
}

/// Strict read-ahead (user 11:00): the bound is the verified descriptor's;
/// the open passes it as a hint and the server refuses past it. Its
/// refusal is an unavailable read that keeps the session.
#[tokio::test]
async fn read_ahead_bound_comes_from_the_verified_descriptor_and_is_refused_by_the_server() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, opened) = opened_viewer(&pool, &keys).await;
    assert_eq!(
        opened.read_ahead_segments,
        pool.resolved
            .descriptor
            .serve_policy()
            .bounds
            .read_ahead_segments
    );
    let seed = servers.opened()[0].0;
    servers.refuse_reads(
        seed,
        PoolTransportError::Refused("session_bound_exceeded".into()),
    );
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::DashSegment {
                rendition: 0,
                index: 40
            },
            &servers,
            &keys,
            NOW + 1
        )
        .await
        .unwrap_err(),
        PoolReadError::ServerLost
    );
    assert!(keys.contains(&handle(), NOW + 1), "the session is kept");
    assert_eq!(ports.wallet_calls(), 1, "no new Wallet call");
}

#[tokio::test]
async fn read_reports_server_lost() {
    for lost in [
        PoolTransportError::Unreachable,
        PoolTransportError::NoExactResult,
        PoolTransportError::Refused("content_unavailable".into()),
        PoolTransportError::Refused("unknown_session".into()),
        PoolTransportError::Refused("session_expired".into()),
    ] {
        let pool = pool(1);
        let keys = PoolDeliveryKeys::default();
        let (servers, _, opened) = opened_viewer(&pool, &keys).await;
        let seed = servers.opened()[0].0;
        servers.refuse_reads(seed, lost.clone());
        assert_eq!(
            read_pool_viewer(
                &handle(),
                ViewerPartIndexV1::ObjectChunk(0),
                &servers,
                &keys,
                NOW + 1
            )
            .await
            .unwrap_err(),
            PoolReadError::ServerLost,
            "{lost:?}"
        );
        // Before the session's end the session and its secret stay (C3).
        assert!(keys.contains(&handle(), NOW + 1));
        assert!(servers.closes.lock().unwrap().is_empty());
        assert_eq!(opened.sessions.session_ids_hex().len(), 1);
    }
    // A retryable failure with no stage: a plain sentence, no open progress,
    // and the record is kept.
    let read = fn_body(RUNTIME_SOURCE, "read_runtime_custody_pool_part");
    let lost = read.find("PoolReadError::ServerLost").unwrap();
    let arm = &read[lost..lost + read[lost..].find("let response").unwrap()];
    assert!(arm.contains("RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE"));
    assert!(!arm.contains("RuntimeCustodyOpenProgress"), "no stage");
    assert!(
        !arm.contains("settle_runtime_custody_viewer_cleanup"),
        "the session is kept"
    );
}

/// User 2026-11-13 04:45: a long read continues past the release
/// operation's expiry while the rights are valid.
#[tokio::test]
async fn long_read_continues_past_the_operation_expiry_while_rights_are_valid() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, opened) = opened_viewer(&pool, &keys).await;
    let operation = ports.released.lock().unwrap()[0].clone();
    let operation_expires_at = operation.statement().expires_at();
    assert!(opened.expires_at > operation_expires_at);
    for now in [
        operation_expires_at,
        operation_expires_at + 1,
        opened.expires_at - 1,
    ] {
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::ObjectChunk(1),
            &servers,
            &keys,
            now,
        )
        .await
        .unwrap();
    }
    assert_eq!(ports.wallet_calls(), 1, "one release per Wallet approval");
    assert_eq!(ports.released.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn session_ends_at_rights_expiry_capped_by_attestation_expiry() {
    let pool = pool(2);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, opened) = opened_viewer(&pool, &keys).await;
    let operation = ports.released.lock().unwrap()[0].clone();
    assert_eq!(
        opened.expires_at,
        operation.statement().session_expires_at()
    );
    // At the end: no server is asked, the entry is dropped, and every server
    // session is closed best effort.
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::MediaV1Init,
            &servers,
            &keys,
            opened.expires_at
        )
        .await
        .unwrap_err(),
        PoolReadError::RenewalRequired
    );
    assert!(servers.read_seeds().is_empty());
    assert!(!keys.contains(&handle(), NOW));
    assert_eq!(servers.closes.lock().unwrap().len(), 2);
}

/// C3: at rights expiry the read answers `pool_session_renewal_required`
/// once, and the next open runs the normal path with exactly one Wallet
/// prompt.
#[tokio::test]
async fn rights_expiry_answers_renewal_required_once_and_the_open_prompts_once() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, opened) = opened_viewer(&pool, &keys).await;
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::ObjectChunk(0),
            &servers,
            &keys,
            opened.expires_at
        )
        .await
        .unwrap_err(),
        PoolReadError::RenewalRequired
    );
    // Once: the entry is gone, so a second read is a plain unavailable.
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::ObjectChunk(0),
            &servers,
            &keys,
            opened.expires_at
        )
        .await
        .unwrap_err(),
        PoolReadError::NoSecret
    );
    let wallet_before = ports.wallet_calls();
    // The reopen: its pending approval is the one Wallet prompt.
    let reopen = FakePorts::new(&pool, &[WalletMode::Pending]);
    let PoolOpenOutcome::PendingApproval(progress) =
        open_pool_viewer(context(&pool, &[], None), &servers, &reopen, &keys)
            .await
            .unwrap()
    else {
        panic!("the reopen asks the Wallet");
    };
    assert_eq!(reopen.wallet_calls(), 1);
    assert_eq!(ports.wallet_calls(), wallet_before);
    assert!(progress.as_json().get("delivery_key_fingerprint").is_none());
    // pcr maps the end to the typed code the Player and Reader read.
    let read = fn_body(RUNTIME_SOURCE, "read_runtime_custody_pool_part");
    assert!(read.contains("RuntimeCustodyPoolSessionRenewalRequired::error()"));
    assert!(LIBRARY_SOURCE.contains("RuntimeCustodyPoolSessionRenewalRequired::is(error)"));
    assert_eq!(
        POOL_SESSION_RENEWAL_REQUIRED,
        "pool_session_renewal_required"
    );
}

/// The byte budget is the integrated one, over the whole session: reaching
/// it before the end is an unavailable read, never a renewal.
#[tokio::test]
async fn byte_budget_covers_the_whole_session() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, _) = opened_viewer(&pool, &keys).await;
    let seed = servers.opened()[0].0;
    servers.refuse_reads(
        seed,
        PoolTransportError::Refused("session_bound_exceeded".into()),
    );
    for _ in 0..3 {
        assert_eq!(
            read_pool_viewer(
                &handle(),
                ViewerPartIndexV1::ObjectChunk(0),
                &servers,
                &keys,
                NOW + 1
            )
            .await
            .unwrap_err(),
            PoolReadError::ServerLost
        );
    }
    assert!(keys.contains(&handle(), NOW + 1));
    assert_eq!(ports.wallet_calls(), 1);
    assert_eq!(ports.released.lock().unwrap().len(), 1);
}

/// C3: early exhaustion and early server loss cause no extra Wallet or
/// release call, and no new prepare.
#[tokio::test]
async fn early_exhaustion_and_server_loss_make_no_wallet_or_release_call() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, opened) = opened_viewer(&pool, &keys).await;
    let seed = servers.opened()[0].0;
    let prepares = servers.prepared_seeds().len();
    for lost in [
        PoolTransportError::Refused("session_bound_exceeded".into()),
        PoolTransportError::Refused("unknown_session".into()),
        PoolTransportError::Refused("session_expired".into()),
        PoolTransportError::Unreachable,
        PoolTransportError::NoExactResult,
    ] {
        servers.refuse_reads(seed, lost);
        let _ = read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::ObjectChunk(2),
            &servers,
            &keys,
            opened.expires_at - 1,
        )
        .await;
    }
    assert_eq!(ports.wallet_calls(), 1);
    assert_eq!(ports.released.lock().unwrap().len(), 1);
    assert_eq!(servers.prepared_seeds().len(), prepares);
    assert!(keys.contains(&handle(), opened.expires_at - 1));
}

/// Repeated reads reuse the one session, so nothing here can reset a
/// server's counters: no new session, no new release.
#[tokio::test]
async fn repeated_reads_cannot_reset_the_counters() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, opened) = opened_viewer(&pool, &keys).await;
    let seed = servers.opened()[0].0;
    servers.refuse_reads(
        seed,
        PoolTransportError::Refused("session_bound_exceeded".into()),
    );
    for _ in 0..5 {
        let _ = read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::ObjectChunk(0),
            &servers,
            &keys,
            NOW + 1,
        )
        .await;
    }
    servers.answer_reads(seed);
    read_pool_viewer(
        &handle(),
        ViewerPartIndexV1::ObjectChunk(0),
        &servers,
        &keys,
        NOW + 1,
    )
    .await
    .unwrap();
    let session_ids = servers
        .reads
        .lock()
        .unwrap()
        .iter()
        .map(|(_, read)| read.session_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(session_ids.len(), 1, "every read names the one session");
    assert_eq!(
        hex::encode(session_ids.iter().next().unwrap()),
        opened.sessions.session_ids_hex()[0]
    );
    assert_eq!(servers.opened().len(), 1);
    assert_eq!(ports.released.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn pool_viewer_record_without_delivery_key_answers_unavailable_and_next_open_reopens() {
    let pool = pool(1);
    let keys = PoolDeliveryKeys::default();
    let (servers, _, _) = opened_viewer(&pool, &keys).await;
    // A restart: the record is on disk, the secret is not.
    let restarted = PoolDeliveryKeys::default();
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::MediaV1Init,
            &servers,
            &restarted,
            NOW + 1
        )
        .await
        .unwrap_err(),
        PoolReadError::NoSecret
    );
    assert!(
        servers.read_seeds().is_empty(),
        "no server is asked without the secret"
    );
    // pcr answers the existing unavailable sentence and settles the record.
    let read = fn_body(RUNTIME_SOURCE, "read_runtime_custody_pool_part");
    let no_secret = read.find("PoolReadError::NoSecret").unwrap();
    let answer = read[no_secret..]
        .find("Runtime custody viewer session is unavailable")
        .unwrap();
    assert!(read[no_secret..no_secret + answer].contains("settle_runtime_custody_viewer_cleanup("));
    // The next open starts fresh and reads again.
    let (servers, _, _) = opened_viewer(&pool, &restarted).await;
    read_pool_viewer(
        &handle(),
        ViewerPartIndexV1::MediaV1Init,
        &servers,
        &restarted,
        NOW + 1,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn close_closes_every_server_session_and_drops_the_secret() {
    let pool = pool(2);
    let keys = PoolDeliveryKeys::default();
    let (servers, _, opened) = opened_viewer(&pool, &keys).await;
    assert_eq!(
        close_pool_viewer(&handle(), &servers, &keys).await,
        PoolCloseResult::Closed
    );
    let mut closed = servers
        .closes
        .lock()
        .unwrap()
        .iter()
        .map(|(_, session_id)| hex::encode(session_id))
        .collect::<Vec<_>>();
    closed.sort();
    let mut expected = opened.sessions.session_ids_hex().to_vec();
    expected.sort();
    assert_eq!(closed, expected, "every server session is closed");
    assert!(!keys.contains(&handle(), NOW + 1));
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::MediaV1Init,
            &servers,
            &keys,
            NOW + 1
        )
        .await
        .unwrap_err(),
        PoolReadError::NoSecret
    );
    // A second close finds nothing and asks nobody.
    let before = servers.closes.lock().unwrap().len();
    assert_eq!(
        close_pool_viewer(&handle(), &servers, &keys).await,
        PoolCloseResult::AlreadyAbsent
    );
    assert_eq!(servers.closes.lock().unwrap().len(), before);
    // pcr's close and cleanup both go through it, never the local decrypt.
    assert!(fn_body(RUNTIME_SOURCE, "close_runtime_custody_viewer")
        .contains("RuntimeCustodyViewerLifecycleStatus::Active if record.is_pool() => {"));
    assert!(
        fn_body(RUNTIME_SOURCE, "runtime_custody_close_pool_viewer").contains("close_pool_viewer(")
    );
}

#[test]
fn v1_active_record_is_settled_and_reopened_through_pool() {
    // On a Home with no ready decrypt target, a local record settles as
    // absent before any decrypt call, so it no longer blocks the open...
    let settle = fn_body(RUNTIME_SOURCE, "settle_runtime_custody_viewer_cleanup");
    let no_decrypt = settle
        .find("has_ready_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)")
        .expect("the cleanup checks for a decrypt target");
    let decrypt = settle
        .find("RuntimeDecryptRegistryAdapter::new(registry)")
        .unwrap();
    assert!(no_decrypt < decrypt);
    assert!(settle[no_decrypt..decrypt].contains("RuntimeViewerSessionCloseResult::AlreadyAbsent"));
    // ...and the open settles it before it resolves the pool and opens there.
    let open = fn_body(RUNTIME_SOURCE, "open_runtime_custody_viewer");
    let settled = open.find("settle_runtime_custody_viewer_cleanup(").unwrap();
    let resolve = open.find("home_pool_resolver(").unwrap();
    assert!(settled < resolve);
}

#[tokio::test]
async fn boot_reconcile_drops_pool_records_without_secret() {
    // At boot no secret survives: closing finds no entry, asks no server,
    // and the record settles as absent.
    let pool = pool(1);
    let servers = FakeServers::new(&pool);
    let keys = PoolDeliveryKeys::default();
    assert_eq!(
        close_pool_viewer(&handle(), &servers, &keys).await,
        PoolCloseResult::AlreadyAbsent
    );
    assert!(servers.closes.lock().unwrap().is_empty());
    // The pool reconcile runs at every boot, outside the decrypt branch.
    let boot = SERVER_INFRA_SOURCE
        .find("reconcile_runtime_custody_pool_viewers_at_boot(")
        .expect("boot reconciles pool records");
    let decrypt = SERVER_INFRA_SOURCE
        .find("find_installed_provider_binary(\"protected-content-decrypt-provider\")")
        .unwrap();
    assert!(
        boot < decrypt,
        "the pool reconcile does not wait for a decrypt target"
    );
    assert!(
        fn_body(RUNTIME_SOURCE, "reconcile_runtime_custody_viewer_records")
            .contains("if only_pool && !record.is_pool() {")
    );
}

// ---------------------------------------------------------------------------
// T4.8: several servers per session (the fixtures sign m = 2)
// ---------------------------------------------------------------------------

/// Parts spread over two renditions and an object, enough to reach both
/// servers.
fn striped_parts() -> Vec<ViewerPartIndexV1> {
    let mut parts = Vec::new();
    for rendition in 0..2u8 {
        parts.push(ViewerPartIndexV1::DashInit { rendition });
        for index in 0..4 {
            parts.push(ViewerPartIndexV1::DashSegment { rendition, index });
        }
    }
    parts.extend((0..4).map(ViewerPartIndexV1::ObjectChunk));
    parts
}

#[tokio::test]
async fn two_servers_split_stripes() {
    let pool = pool(2);
    let keys = PoolDeliveryKeys::default();
    let (servers, _, opened) = opened_viewer(&pool, &keys).await;
    // The entry's server order is the open's prepare order.
    let order = servers
        .prepared_seeds()
        .into_iter()
        .take(2)
        .collect::<Vec<_>>();
    assert_eq!(opened.sessions.servers_hex().len(), 2);
    for part in striped_parts() {
        let clear = read_pool_viewer(&handle(), part, &servers, &keys, NOW + 1)
            .await
            .unwrap();
        assert_eq!(clear.as_slice(), clear_part(part).as_slice());
    }
    let expected = striped_parts()
        .iter()
        .map(|part| order[elastos_protected_content_runtime::stripe_index(part, 2)])
        .collect::<Vec<_>>();
    let seeds = servers.read_seeds();
    assert_eq!(seeds, expected, "each part goes to its stripe's server");
    assert!(
        seeds.contains(&order[0]) && seeds.contains(&order[1]),
        "both servers read"
    );
    // A rendition's init goes with its first segment.
    for rendition in 0..2u8 {
        assert_eq!(
            elastos_protected_content_runtime::stripe_index(
                &ViewerPartIndexV1::DashInit { rendition },
                2
            ),
            elastos_protected_content_runtime::stripe_index(
                &ViewerPartIndexV1::DashSegment {
                    rendition,
                    index: 0
                },
                2
            )
        );
    }
}

#[tokio::test]
async fn stripe_moves_when_one_server_stops() {
    let pool = pool(2);
    let keys = PoolDeliveryKeys::default();
    let (servers, ports, _) = opened_viewer(&pool, &keys).await;
    let order = servers
        .prepared_seeds()
        .into_iter()
        .take(2)
        .collect::<Vec<_>>();
    let (stopped, live) = (order[0], order[1]);
    servers.refuse_reads(stopped, PoolTransportError::Unreachable);
    for part in striped_parts() {
        let clear = read_pool_viewer(&handle(), part, &servers, &keys, NOW + 1)
            .await
            .unwrap();
        assert_eq!(clear.as_slice(), clear_part(part).as_slice(), "{part:?}");
    }
    // The stopped server was asked once; every other read went to the live
    // one, under the same release and with no Wallet call.
    let seeds = servers.read_seeds();
    assert_eq!(
        seeds.iter().filter(|seed| **seed == stopped).count(),
        1,
        "{seeds:?}"
    );
    assert!(seeds
        .iter()
        .skip_while(|seed| **seed != stopped)
        .skip(1)
        .all(|seed| *seed == live));
    assert_eq!(ports.released.lock().unwrap().len(), 1, "no new release");
    assert_eq!(ports.wallet_calls(), 1);
    // When the live one stops too, the read is a retryable loss, and the
    // last server is kept for the next try.
    servers.refuse_reads(live, PoolTransportError::Unreachable);
    assert_eq!(
        read_pool_viewer(
            &handle(),
            ViewerPartIndexV1::ObjectChunk(0),
            &servers,
            &keys,
            NOW + 1
        )
        .await
        .unwrap_err(),
        PoolReadError::ServerLost
    );
    assert!(keys.contains(&handle(), NOW + 1));
    servers.answer_reads(live);
    read_pool_viewer(
        &handle(),
        ViewerPartIndexV1::ObjectChunk(0),
        &servers,
        &keys,
        NOW + 1,
    )
    .await
    .unwrap();
}

/// S4B-F2: two reads fail together against both servers. The live count
/// is checked with the loss, so one server stays live (the last live server
/// is never marked lost); and the session's end is checked before a server
/// is picked, so the reopen at rights expiry is never wedged behind a loss.
#[tokio::test]
async fn concurrent_losses_keep_one_server_and_expiry_still_renews() {
    let pool = pool(2);
    let keys = PoolDeliveryKeys::default();
    let (servers, _, opened) = opened_viewer(&pool, &keys).await;
    let order = servers
        .prepared_seeds()
        .into_iter()
        .take(2)
        .collect::<Vec<_>>();
    let on = |stripe: usize| {
        striped_parts()
            .into_iter()
            .find(|part| elastos_protected_content_runtime::stripe_index(part, 2) == stripe)
            .unwrap()
    };
    for seed in &order {
        servers.refuse_reads(*seed, PoolTransportError::Unreachable);
    }
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    *servers.read_barriers.lock().unwrap() = vec![barrier.clone(), barrier];
    let viewer = handle();
    let (first, second) = tokio::join!(
        read_pool_viewer(&viewer, on(0), &servers, &keys, NOW + 1),
        read_pool_viewer(&viewer, on(1), &servers, &keys, NOW + 1),
    );
    assert_eq!(first.unwrap_err(), PoolReadError::ServerLost);
    assert_eq!(second.unwrap_err(), PoolReadError::ServerLost);
    let live = keys
        .with_entry(&handle(), |entry| {
            (0..entry.lost.len())
                .filter(|index| !entry.lost[*index])
                .collect::<Vec<_>>()
        })
        .unwrap();
    assert_eq!(live.len(), 1, "one server stays live");

    // Before the end the kept server reads again once it answers.
    servers.answer_reads(order[live[0]]);
    read_pool_viewer(&handle(), on(0), &servers, &keys, NOW + 1)
        .await
        .unwrap();

    // Whatever the live count, the session's end answers the reopen.
    keys.with_entry(&handle(), |entry| {
        entry.lost.iter_mut().for_each(|lost| *lost = true)
    })
    .unwrap();
    let reads = servers.read_seeds().len();
    assert_eq!(
        read_pool_viewer(&handle(), on(0), &servers, &keys, opened.expires_at)
            .await
            .unwrap_err(),
        PoolReadError::RenewalRequired
    );
    assert_eq!(servers.read_seeds().len(), reads, "no server is asked");
    assert!(!keys.contains(&handle(), NOW));
}

/// C3: a bound refusal (read-ahead or the byte budget) keeps the stripe on
/// its server; moving it would spend another server's budget.
#[tokio::test]
async fn a_bound_refusal_does_not_move_the_stripe() {
    let pool = pool(2);
    let keys = PoolDeliveryKeys::default();
    let (servers, _, _) = opened_viewer(&pool, &keys).await;
    let order = servers
        .prepared_seeds()
        .into_iter()
        .take(2)
        .collect::<Vec<_>>();
    let part = ViewerPartIndexV1::ObjectChunk(0);
    let owner = order[elastos_protected_content_runtime::stripe_index(&part, 2)];
    servers.refuse_reads(
        owner,
        PoolTransportError::Refused("session_bound_exceeded".into()),
    );
    assert_eq!(
        read_pool_viewer(&handle(), part, &servers, &keys, NOW + 1)
            .await
            .unwrap_err(),
        PoolReadError::ServerLost
    );
    assert_eq!(servers.read_seeds(), [owner], "no other server is asked");
    servers.answer_reads(owner);
    read_pool_viewer(&handle(), part, &servers, &keys, NOW + 1)
        .await
        .unwrap();
    assert_eq!(servers.read_seeds(), [owner, owner]);
}

#[tokio::test]
async fn each_server_gets_only_its_contributions() {
    let pool = pool(2);
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .unwrap();
    let operation = ports.released.lock().unwrap()[0].clone();
    let authenticated = operation
        .verify(RuntimeIssuerPolicyV1::Expected(device_issuer()), NOW)
        .unwrap();
    assert_eq!(authenticated.recipients().len(), 2);
    let node_set = pool.bundle.signed_epoch().statement().node_set().unwrap();
    let mut sent = Vec::new();
    for (seed, open) in servers.opened() {
        let recipient = attested_recipient(&pool, seed);
        let recipient = recipient
            .attestation
            .statement()
            .recipient_identity()
            .clone();
        // Only the contributions sealed to this server's recipient...
        assert!(!open.contributions.is_empty());
        let verified = open
            .contributions
            .iter()
            .map(|contribution| {
                assert_eq!(
                    contribution
                        .statement()
                        .recipient_sealed_contribution()
                        .recipient(),
                    &recipient
                );
                authenticated
                    .verify_node_contribution(contribution, &node_set, &recipient, NOW)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        // ...under a receipt over exactly that subset (T3.1 accepts it).
        authenticated
            .verify_terminal_receipt(
                &open.terminal_receipt,
                &verified,
                TerminalReceiptIssuerKey::new(device_key().verifying_key().to_bytes()).unwrap(),
                NOW,
            )
            .unwrap();
        sent.extend(open.contributions.clone());
    }
    // Together they are every contribution of the release, each sent once.
    assert_eq!(sent.len(), 4);
    for (index, contribution) in sent.iter().enumerate() {
        assert!(!sent[index + 1..].contains(contribution));
    }

    // F5: the same two recipients under a descriptor that signs m = 1 is
    // refused with TooMany.
    let narrow = self::pool(1);
    let prepared = [2u8, 3]
        .map(|seed| PoolPreparedServer {
            member: narrow
                .resolved
                .descriptor
                .member(node_public_key(seed))
                .unwrap()
                .clone(),
            prepared: attested_recipient(&narrow, seed),
        })
        .to_vec();
    let rights = pool_rights_request(
        &narrow.binding,
        RightsActionV1::View,
        &prepared,
        &delivery_key(),
        NOW,
        NOW + 290,
        POLICY_CHAIN,
    )
    .unwrap();
    let signed = wallet_sign(&rights);
    let identity = narrow.policy.policy_identity().unwrap();
    let statement = pool_release_statement(
        device_issuer(),
        &PoolOperationInput {
            signed_rights: &signed,
            prepared: &prepared,
            policy_body: &narrow.policy,
            policy_identity: &identity,
            resolved: &narrow.resolved,
            audit_request_id: RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap(),
        },
        NOW,
    )
    .unwrap();
    let refused = sign_release_operation_v2_with(&device_key(), statement)
        .unwrap()
        .verify(RuntimeIssuerPolicyV1::Expected(device_issuer()), NOW)
        .unwrap_err();
    assert!(format!("{refused:?}").contains("TooMany"), "{refused:?}");
    // The open never builds it: it prepares at most m servers.
    assert_eq!(wanted_servers(&narrow.resolved), 1);
}

// ---------------------------------------------------------------------------
// OPEN-LOOP F2: a failure after the Wallet signed never asks it again
// ---------------------------------------------------------------------------

/// The answer to a failure after the Wallet signed: no resumable stage (a
/// viewer re-runs no open on its own), the typed `content_unavailable` code,
/// and the plain words a viewer shows beside Retry.
fn assert_final_after_approval(error: &anyhow::Error) {
    assert!(
        error.downcast_ref::<RuntimeCustodyOpenProgress>().is_none(),
        "a failure after the approval carries no resumable stage: {error:#}"
    );
    assert_eq!(
        error.to_string(),
        "This file isn't available from the pool right now. Try again later."
    );
    let envelope = crate::library::provider_error_from_for_test(error);
    assert_eq!(envelope["code"], "content_unavailable", "{envelope}");
    assert!(envelope.get("open_progress").is_none(), "{envelope}");
}

#[tokio::test]
async fn a_session_open_refusal_after_signing_ends_the_open_without_asking_again() {
    let pool = pool(1);
    let mut servers = FakeServers::new(&pool);
    for seed in 1..=3 {
        servers = servers.refusing_opens(
            seed,
            PoolTransportError::Refused("content_unavailable".into()),
        );
    }
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let error = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .err()
        .expect("no server opens the session");
    assert_final_after_approval(&error);
    // One approval, one release: nothing asked the Wallet again.
    assert_eq!(ports.wallet_calls(), 1);
    assert_eq!(ports.released.lock().unwrap().len(), 1);
    assert_eq!(servers.opened().len(), 1);
}

#[tokio::test]
async fn a_failure_before_the_wallet_keeps_its_resumable_answer() {
    let pool = pool(1);
    let servers =
        FakeServers::new(&pool).refusing(1, PoolTransportError::Refused("binding_mismatch".into()));
    let servers = servers
        .refusing(2, PoolTransportError::Refused("binding_mismatch".into()))
        .refusing(3, PoolTransportError::Refused("binding_mismatch".into()));
    let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let keys = PoolDeliveryKeys::default();
    let error = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
        .await
        .err()
        .expect("no server prepares");
    assert_eq!(ports.wallet_calls(), 0);
    assert_eq!(
        progress_of(&error).stage_label(),
        RuntimeCustodyOpenProgress::unavailable().stage_label()
    );
}

// ---------------------------------------------------------------------------
// OPEN-LOOP F4: this Home's own node never serves its own open
// ---------------------------------------------------------------------------

/// A Home that included itself as node 1 of the pool counts that node among
/// its own node keys, so its own open never asks it to serve (D2 refuses
/// self-serve).
#[tokio::test]
async fn guard_a_home_that_included_itself_never_selects_its_own_node() {
    let dir = crate::protected_content_config::tests::safe_ancestor_tempdir();
    let data_dir = dir.path().join("home");
    crate::custody_pool_setup::tests::write_included_node_seeded(&data_dir, 1, "Home", "Paris");
    let own = crate::protected_content_runtime::own_custody_node_keys(&data_dir).unwrap();
    assert!(
        own.contains(&node_public_key(1)),
        "this Home's included node is one of its node keys"
    );
    let pool = pool(1);
    for _ in 0..32 {
        let servers = FakeServers::new(&pool);
        let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
        let keys = PoolDeliveryKeys::default();
        open_pool_viewer(context(&pool, &own, None), &servers, &ports, &keys)
            .await
            .unwrap();
        assert!(
            !servers.prepared_seeds().contains(&1),
            "{:?}",
            servers.prepared_seeds()
        );
    }
}

/// A server that answers `not_eligible_server` refused before any action, so
/// the next server may answer: an own node first in rank fails over.
#[tokio::test]
async fn an_own_node_first_in_rank_fails_over_to_the_next_server() {
    let refusal = PoolTransportError::Refused("not_eligible_server".into());
    assert!(prepare_fails_over(&refusal));
    let pool = pool(1);
    let mut failed_over = false;
    for _ in 0..32 {
        let servers = FakeServers::new(&pool).refusing(1, refusal.clone());
        let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
        let keys = PoolDeliveryKeys::default();
        let opened = opened(
            open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
                .await
                .unwrap(),
        );
        let tried = servers.prepared_seeds();
        assert_ne!(servers.opened()[0].0, 1, "the refusing node never serves");
        assert_eq!(opened.sessions.session_ids_hex().len(), 1);
        failed_over |= tried.first() == Some(&1) && tried.len() > 1;
    }
    assert!(failed_over, "the open moved past an own node ranked first");
}
