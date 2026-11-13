use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::task::Poll;

use elastos_protected_content_contracts::{
    AuthenticatedRuntimeReleaseOperationAnyV1, AuthenticatedRuntimeReleaseOperationV1,
    AuthenticatedRuntimeReleaseOperationV2, CanonicalContract, ContractError, Digest32,
    NodePublicKey, NodeSetV1, RightsDecisionV1, RightsRequestAnyV1, RightsRequestV2,
    RuntimeIssuerPolicyV1, RuntimeOperationIssuerKeyV1, RuntimeReleaseOperationAnyV1,
    SignedNodeContributionV1, SignedNodeRightsDecisionV1, SignedRuntimeReleaseOperationV1,
    SignedRuntimeReleaseOperationV2, WalletAddress, WalletSignedRightsRequestAnyV1,
    WalletSignedRightsRequestV1, WalletSignedRightsRequestV2,
};
use elastos_protected_content_provider_contracts::{
    CustodyProviderRequestV1, CustodyProviderResponseV1, PoolCustodyRequestV1,
    PoolCustodyResponseV1, RightsProviderRequestV1, RightsProviderResponseV1,
};
use elastos_wallet_contract::{
    ProtectedContentRightsSignatureResultV1, WalletProviderOperationV2, WalletProviderRequestV2,
    WalletProviderResponseV2, WalletResultV2,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    RuntimeReleaseJournal, RuntimeReleaseJournalError, RuntimeReleaseOperationDraft,
    RuntimeReleaseTerminalResult,
};

/// Why a provider call did not yield an exact result, classified by whether the
/// provider can have had a durable effect.
///
/// A caller holding a journal has to decide, on failure, whether to record a
/// terminal abort. That decision turns on one question — could the provider have
/// acted? — and only some failures answer it. A custody node that refuses
/// *before* its durable write and one that fails *after* it can return the same
/// transport-level shape, so a variant here claims "without effect" only where
/// the provider contract guarantees the refusal precedes any write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeProviderCallError {
    /// The call never left this Runtime: the request could not be encoded. No
    /// provider saw it, so none can have acted on it.
    #[error("provider call was not dispatched")]
    NotDispatched,
    /// The provider answered and refused with a code its contract emits only
    /// before any durable write. The effect is provably absent.
    #[error("provider refused the request without acting")]
    RefusedWithoutEffect,
    /// The call left this Runtime and no usable answer came back, or the answer
    /// carries a code that spans both acted and did-not-act paths. The effect is
    /// unknown and must never be assumed absent.
    #[error("provider call did not return an exact result")]
    NoExactResult,
}

impl RuntimeProviderCallError {
    /// Whether this failure proves the provider did not act.
    ///
    /// `false` means unknown, never "it acted". A caller may only skip a
    /// terminal abort when this is `true`.
    #[must_use]
    pub const fn proves_no_effect(self) -> bool {
        match self {
            Self::NotDispatched | Self::RefusedWithoutEffect => true,
            Self::NoExactResult => false,
        }
    }
}

#[async_trait::async_trait]
pub trait RuntimeRightsProvider: Send + Sync {
    async fn evaluate_rights(
        &self,
        request: &RightsProviderRequestV1,
    ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError>;
}

#[async_trait::async_trait]
pub trait RuntimeCustodyProvider: Send + Sync {
    async fn release_contribution(
        &self,
        request: &CustodyProviderRequestV1,
    ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError>;

    async fn provision_node_share(
        &self,
        request: &CustodyProviderRequestV1,
    ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError>;

    /// One node's contributions to a V2 (pool) release, one per signed
    /// recipient (Plan B T4.1, S4-Q3). Required: every custody adapter
    /// answers it, so a V2 release never silently skips a node.
    async fn release_pool_contribution(
        &self,
        request: &PoolCustodyRequestV1,
    ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError>;

    /// Plan B S7-lite T7.6: an admitted minter provisions this node's share
    /// of its pool. Adapters that cannot reach a pool node never send it.
    async fn provision_pool_node_share(
        &self,
        _request: &PoolCustodyRequestV1,
    ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
        Err(RuntimeProviderCallError::NotDispatched)
    }
}

pub struct RuntimeSelectedProvider<'a> {
    node_public_key: NodePublicKey,
    rights: &'a dyn RuntimeRightsProvider,
    custody: &'a dyn RuntimeCustodyProvider,
}

impl<'a> RuntimeSelectedProvider<'a> {
    pub fn new(
        node_public_key: NodePublicKey,
        rights: &'a dyn RuntimeRightsProvider,
        custody: &'a dyn RuntimeCustodyProvider,
    ) -> Self {
        Self {
            node_public_key,
            rights,
            custody,
        }
    }

    pub const fn node_public_key(&self) -> NodePublicKey {
        self.node_public_key
    }
}

impl fmt::Debug for RuntimeSelectedProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSelectedProvider")
            .field("node_public_key", &self.node_public_key)
            .field("rights", &"[redacted]")
            .field("custody", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeReleaseCoordinatorOutcome {
    Terminal(RuntimeReleaseTerminalResult),
    Nonterminal {
        operation_hash: Digest32,
        reason: RuntimeReleaseNonterminalReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeReleaseNonterminalReason {
    ProviderEffectAlreadyStarted,
    ProviderEffectUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartedOperationResolutionMode {
    InitialDispatch,
    ExactResume,
}

#[derive(Debug)]
struct StartedOperationCollection {
    offer: Option<RuntimeReleaseReconcileOffer>,
    replayable_rights_decisions: Vec<SignedNodeRightsDecisionV1>,
}

struct StartedOperationContext<'a, 'b> {
    draft: &'a RuntimeReleaseOperationDraft,
    signed_runtime_release_operation: &'a RuntimeReleaseOperationAnyV1,
    authenticated: &'a AuthenticatedRuntimeReleaseOperationAnyV1,
    ordered_providers: &'a [&'b RuntimeSelectedProvider<'b>],
    replayable_rights_decisions: &'a [SignedNodeRightsDecisionV1],
    now_unix_seconds: u64,
    mode: StartedOperationResolutionMode,
}

impl<'a, 'b> StartedOperationContext<'a, 'b> {
    /// V1: the operation's custody epoch; V2: the item's bundle (F2).
    fn threshold(&self) -> Result<usize, RuntimeReleaseCoordinatorError> {
        self.authenticated
            .node_set()
            .map(|node_set| usize::from(node_set.threshold().required()))
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum RuntimeReleaseReconcileOffer {
    RightsDenied {
        signed_node_rights_decision: Box<SignedNodeRightsDecisionV1>,
    },
    ContributionsReady {
        signed_node_contributions: Vec<SignedNodeContributionV1>,
    },
}

impl fmt::Debug for RuntimeReleaseReconcileOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RightsDenied { .. } => formatter.write_str("RightsDenied"),
            Self::ContributionsReady {
                signed_node_contributions,
            } => formatter
                .debug_struct("ContributionsReady")
                .field("contribution_count", &signed_node_contributions.len())
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeReleaseCoordinatorError {
    #[error("runtime release wallet authority is invalid")]
    WalletAuthority,
    #[error("runtime release operation authority is invalid")]
    OperationAuthority,
    #[error("runtime release provider selection is invalid")]
    ProviderSelection,
    #[error("runtime release provider result is invalid")]
    ProviderResult,
    #[error("runtime release reconciliation is invalid")]
    Reconciliation,
    #[error("runtime release journal failed")]
    Journal,
}

impl From<RuntimeReleaseJournalError> for RuntimeReleaseCoordinatorError {
    fn from(_: RuntimeReleaseJournalError) -> Self {
        Self::Journal
    }
}

impl From<ContractError> for RuntimeReleaseCoordinatorError {
    fn from(_: ContractError) -> Self {
        Self::OperationAuthority
    }
}

pub struct RuntimeReleaseCoordinator<'a> {
    journal: RuntimeReleaseJournal,
    expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
    selected_providers: Vec<RuntimeSelectedProvider<'a>>,
    response_clock: Option<fn() -> u64>,
}

impl<'a> RuntimeReleaseCoordinator<'a> {
    pub fn new(
        journal: RuntimeReleaseJournal,
        expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
        selected_providers: Vec<RuntimeSelectedProvider<'a>>,
    ) -> Result<Self, RuntimeReleaseCoordinatorError> {
        let mut nodes = BTreeSet::new();
        for provider in &selected_providers {
            if !nodes.insert(provider.node_public_key) {
                return Err(RuntimeReleaseCoordinatorError::ProviderSelection);
            }
        }
        Ok(Self {
            journal,
            expected_runtime_issuer,
            selected_providers,
            response_clock: None,
        })
    }

    /// Validate provider responses against a live clock instead of the
    /// operation-start `now`. Providers stamp decisions and contributions with
    /// their own wall clocks while the release call is in flight; with a
    /// frozen `now`, any provider walk longer than the permitted clock skew
    /// fails closed as `ProviderEffectUncertain`. Statement verification of
    /// caller-supplied pre-signed inputs still uses the caller's `now`.
    #[must_use]
    pub fn with_response_clock(mut self, response_clock: fn() -> u64) -> Self {
        self.response_clock = Some(response_clock);
        self
    }

    fn response_validation_now(&self, operation_now_unix_seconds: u64) -> u64 {
        match self.response_clock {
            Some(clock) => clock().max(operation_now_unix_seconds),
            None => operation_now_unix_seconds,
        }
    }

    /// Runs one release, V1 or V2. Only this Runtime's own operations are
    /// accepted (`Expected(own)`), whichever version.
    pub async fn release(
        &self,
        wallet_request_bytes: &[u8],
        wallet_response_bytes: &[u8],
        signed_runtime_release_operation: RuntimeReleaseOperationAnyV1,
        now_unix_seconds: u64,
    ) -> Result<RuntimeReleaseCoordinatorOutcome, RuntimeReleaseCoordinatorError> {
        let wallet_request =
            WalletProviderRequestV2::decode_at(wallet_request_bytes, now_unix_seconds)
                .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
        let wallet_response =
            WalletProviderResponseV2::decode_for_request(wallet_response_bytes, &wallet_request)
                .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
        validate_wallet_release_binding(
            &wallet_request,
            &wallet_response,
            &signed_runtime_release_operation,
        )?;
        let authenticated =
            self.authenticate(&signed_runtime_release_operation, now_unix_seconds)?;
        let draft = RuntimeReleaseOperationDraft::new(
            wallet_request_bytes.to_vec(),
            wallet_response_bytes.to_vec(),
            signed_runtime_release_operation.clone(),
        )?;
        let persisted = self.journal.persist_before_provider_effect(&draft)?;
        if let Some(terminal) = persisted.terminal_result().cloned() {
            return Ok(RuntimeReleaseCoordinatorOutcome::Terminal(terminal));
        }
        if persisted.provider_effect_started() {
            return Ok(RuntimeReleaseCoordinatorOutcome::Nonterminal {
                operation_hash: draft.operation_hash()?,
                reason: RuntimeReleaseNonterminalReason::ProviderEffectAlreadyStarted,
            });
        }
        let ordered_providers = self.selected_ordered_providers(&authenticated)?;
        self.journal.mark_provider_effect_started(&draft)?;
        self.resolve_started_operation(
            draft.operation_hash()?,
            StartedOperationContext {
                draft: &draft,
                signed_runtime_release_operation: &signed_runtime_release_operation,
                authenticated: &authenticated,
                ordered_providers: &ordered_providers,
                replayable_rights_decisions: &[],
                now_unix_seconds,
                mode: StartedOperationResolutionMode::InitialDispatch,
            },
        )
        .await
    }

    pub async fn resume_exact(
        &self,
        operation_hash: Digest32,
        now_unix_seconds: u64,
    ) -> Result<RuntimeReleaseCoordinatorOutcome, RuntimeReleaseCoordinatorError> {
        let persisted = self
            .journal
            .load(operation_hash)
            .map_err(|error| match error {
                RuntimeReleaseJournalError::NotFound => {
                    RuntimeReleaseCoordinatorError::Reconciliation
                }
                _ => RuntimeReleaseCoordinatorError::Journal,
            })?;
        if let Some(terminal) = persisted.terminal_result().cloned() {
            return Ok(RuntimeReleaseCoordinatorOutcome::Terminal(terminal));
        }
        if !persisted.provider_effect_started() {
            return Err(RuntimeReleaseCoordinatorError::Reconciliation);
        }
        let draft = persisted.draft().clone();
        if draft.operation_hash()? != operation_hash {
            return Err(RuntimeReleaseCoordinatorError::Reconciliation);
        }
        let signed_runtime_release_operation = draft.signed_runtime_release_operation().clone();
        let authenticated =
            self.authenticate(&signed_runtime_release_operation, now_unix_seconds)?;
        let ordered_providers = self.selected_ordered_providers(&authenticated)?;
        self.resolve_started_operation(
            operation_hash,
            StartedOperationContext {
                draft: &draft,
                signed_runtime_release_operation: &signed_runtime_release_operation,
                authenticated: &authenticated,
                ordered_providers: &ordered_providers,
                replayable_rights_decisions: persisted.replayable_rights_decisions(),
                now_unix_seconds,
                mode: StartedOperationResolutionMode::ExactResume,
            },
        )
        .await
    }

    /// Whether a custody node may have been asked for a contribution under
    /// this operation.
    ///
    /// Contributions are asked for only once a threshold of rights decisions
    /// is durably persisted, so an unresolved operation below that threshold
    /// has asked no custody node for anything durable: its caller may build a
    /// fresh operation from the same Wallet signature instead of resuming one
    /// that has too little time left. Every case this cannot prove -- an
    /// unknown or unreadable record, a terminal one, a threshold that does not
    /// decode -- answers `true`.
    #[must_use]
    pub fn custody_contribution_possibly_requested(&self, operation_hash: Digest32) -> bool {
        let Ok(persisted) = self.journal.load(operation_hash) else {
            return true;
        };
        if persisted.terminal_result().is_some() {
            return true;
        }
        // The draft-level check reads the node set by decode only (V2: the
        // descriptor bundle the item's key envelope names).
        let Some(node_set) = persisted
            .draft()
            .signed_runtime_release_operation()
            .unverified_node_set()
        else {
            return true;
        };
        persisted.replayable_rights_decisions().len()
            >= usize::from(node_set.threshold().required())
    }

    pub fn reconcile(
        &self,
        operation_hash: Digest32,
        offer: RuntimeReleaseReconcileOffer,
        now_unix_seconds: u64,
    ) -> Result<RuntimeReleaseCoordinatorOutcome, RuntimeReleaseCoordinatorError> {
        let persisted = self
            .journal
            .load(operation_hash)
            .map_err(|error| match error {
                RuntimeReleaseJournalError::NotFound => {
                    RuntimeReleaseCoordinatorError::Reconciliation
                }
                _ => RuntimeReleaseCoordinatorError::Journal,
            })?;
        let draft = persisted.draft().clone();
        if draft.operation_hash()? != operation_hash {
            return Err(RuntimeReleaseCoordinatorError::Reconciliation);
        }
        if let Some(terminal) = persisted.terminal_result() {
            if offer_to_terminal(&offer) != *terminal {
                return Err(RuntimeReleaseCoordinatorError::Reconciliation);
            }
            return Ok(RuntimeReleaseCoordinatorOutcome::Terminal(terminal.clone()));
        }
        if !persisted.provider_effect_started() {
            return Err(RuntimeReleaseCoordinatorError::Reconciliation);
        }
        let signed_runtime_release_operation = draft.signed_runtime_release_operation().clone();
        let authenticated =
            self.authenticate(&signed_runtime_release_operation, now_unix_seconds)?;
        let node_set = authenticated
            .node_set()
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)?;
        let terminal = match offer {
            RuntimeReleaseReconcileOffer::RightsDenied {
                signed_node_rights_decision,
            } => {
                let verified = authenticated
                    .verify_node_rights_decision(
                        &signed_node_rights_decision,
                        &node_set,
                        self.response_validation_now(now_unix_seconds),
                    )
                    .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
                if verified.decision() != RightsDecisionV1::Denied {
                    return Err(RuntimeReleaseCoordinatorError::ProviderResult);
                }
                RuntimeReleaseTerminalResult::RightsDenied {
                    signed_node_rights_decision,
                }
            }
            RuntimeReleaseReconcileOffer::ContributionsReady {
                signed_node_contributions,
            } => RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions: exact_release_contributions(
                    &authenticated,
                    &node_set,
                    &signed_node_contributions,
                    self.response_validation_now(now_unix_seconds),
                )?,
            },
        };
        let persisted = self.journal.mark_terminal(&draft, terminal)?;
        Ok(RuntimeReleaseCoordinatorOutcome::Terminal(
            persisted.into_terminal_result()?,
        ))
    }

    /// Verifies a V1 or V2 operation under this Runtime's own issuer.
    fn authenticate(
        &self,
        operation: &RuntimeReleaseOperationAnyV1,
        now_unix_seconds: u64,
    ) -> Result<AuthenticatedRuntimeReleaseOperationAnyV1, RuntimeReleaseCoordinatorError> {
        operation
            .verify(
                RuntimeIssuerPolicyV1::Expected(self.expected_runtime_issuer),
                now_unix_seconds,
            )
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)
    }

    fn selected_ordered_providers(
        &'a self,
        authenticated: &AuthenticatedRuntimeReleaseOperationAnyV1,
    ) -> Result<Vec<&'a RuntimeSelectedProvider<'a>>, RuntimeReleaseCoordinatorError> {
        let node_set = authenticated
            .node_set()
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)?;
        let mut configured = HashMap::with_capacity(self.selected_providers.len());
        for provider in &self.selected_providers {
            if !node_set.contains(provider.node_public_key) {
                return Err(RuntimeReleaseCoordinatorError::ProviderSelection);
            }
            configured.insert(provider.node_public_key, provider);
        }
        let selected = node_set
            .members()
            .iter()
            .filter_map(|node| configured.get(node).copied())
            .collect::<Vec<_>>();
        if selected.len() < usize::from(node_set.threshold().required()) {
            return Err(RuntimeReleaseCoordinatorError::ProviderSelection);
        }
        Ok(selected)
    }

    async fn resolve_started_operation(
        &self,
        operation_hash: Digest32,
        context: StartedOperationContext<'_, '_>,
    ) -> Result<RuntimeReleaseCoordinatorOutcome, RuntimeReleaseCoordinatorError> {
        let collection = self.collect_rights_decisions(&context).await?;
        let Some(offer) = collection.offer else {
            let persisted_decisions = if collection.replayable_rights_decisions.is_empty() {
                context.replayable_rights_decisions.to_vec()
            } else {
                self.journal
                    .persist_replayable_rights_decisions(
                        context.draft,
                        &collection.replayable_rights_decisions,
                    )
                    .map_err(|_| RuntimeReleaseCoordinatorError::Journal)?
                    .replayable_rights_decisions()
                    .to_vec()
            };
            if persisted_decisions.len() < context.threshold()? {
                return Ok(RuntimeReleaseCoordinatorOutcome::Nonterminal {
                    operation_hash,
                    reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                });
            }
            let offer = self
                .collect_contributions(&StartedOperationContext {
                    replayable_rights_decisions: &persisted_decisions,
                    ..context
                })
                .await?;
            let Some(offer) = offer else {
                return Ok(RuntimeReleaseCoordinatorOutcome::Nonterminal {
                    operation_hash,
                    reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                });
            };
            return self.reconcile(operation_hash, offer, context.now_unix_seconds);
        };
        self.reconcile(operation_hash, offer, context.now_unix_seconds)
    }

    async fn collect_rights_decisions(
        &self,
        context: &StartedOperationContext<'_, '_>,
    ) -> Result<StartedOperationCollection, RuntimeReleaseCoordinatorError> {
        let node_set = context
            .authenticated
            .node_set()
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)?;
        let threshold = context.threshold()?;
        let mut persisted_by_node = self.persisted_rights_decisions_by_node(context, &node_set)?;
        if persisted_by_node.len() >= threshold {
            return Ok(StartedOperationCollection {
                offer: None,
                replayable_rights_decisions: Vec::new(),
            });
        }
        let candidates = context
            .ordered_providers
            .iter()
            .copied()
            .filter(|provider| !persisted_by_node.contains_key(&provider.node_public_key))
            .collect::<Vec<_>>();
        let requests = candidates
            .iter()
            .map(|provider| {
                match context.signed_runtime_release_operation {
                    // V1 requests are built exactly as before.
                    RuntimeReleaseOperationAnyV1::V1(operation) => {
                        RightsProviderRequestV1::new_evaluate(provider.node_public_key, operation)
                    }
                    RuntimeReleaseOperationAnyV1::V2(_) => {
                        RightsProviderRequestV1::new_evaluate_any(
                            provider.node_public_key,
                            context.signed_runtime_release_operation,
                        )
                    }
                }
                .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut calls = ThresholdCalls::new(
            candidates
                .iter()
                .zip(&requests)
                .map(|(provider, request)| provider.rights.evaluate_rights(request))
                .collect(),
        );
        // Kept with each decision's place in node-set order, so what is
        // persisted does not depend on which node answered first.
        let mut collected = Vec::new();
        let newly_replayable = |collected: &mut Vec<(usize, SignedNodeRightsDecisionV1)>| {
            collected.sort_by_key(|(index, _)| *index);
            collected
                .drain(..)
                .map(|(_, decision)| decision)
                .collect::<Vec<_>>()
        };
        while persisted_by_node.len() < threshold {
            calls.launch_up_to(threshold - persisted_by_node.len());
            let Some((index, answer)) = calls.next_answer().await else {
                break;
            };
            let provider = candidates[index];
            let request = &requests[index];
            // A node that gave no answer is passed over and the next node in
            // order is asked in its place; it contributes nothing.
            let Ok(response) = answer else {
                tracing::debug!(
                    node_index = index,
                    "runtime release: rights call gave no exact result, asking the next node"
                );
                continue;
            };
            if response
                .validate_against_request_at(
                    request,
                    self.response_validation_now(context.now_unix_seconds),
                )
                .is_err()
            {
                return match context.mode {
                    StartedOperationResolutionMode::InitialDispatch => {
                        Ok(StartedOperationCollection {
                            offer: None,
                            replayable_rights_decisions: newly_replayable(&mut collected),
                        })
                    }
                    StartedOperationResolutionMode::ExactResume => {
                        Err(RuntimeReleaseCoordinatorError::ProviderResult)
                    }
                };
            }
            let decision = match response.signed_node_rights_decision() {
                Ok(decision) => decision,
                Err(_) => {
                    return match context.mode {
                        StartedOperationResolutionMode::InitialDispatch => {
                            Ok(StartedOperationCollection {
                                offer: None,
                                replayable_rights_decisions: newly_replayable(&mut collected),
                            })
                        }
                        StartedOperationResolutionMode::ExactResume => {
                            Err(RuntimeReleaseCoordinatorError::ProviderResult)
                        }
                    };
                }
            };
            let verified = context
                .authenticated
                .verify_node_rights_decision(
                    &decision,
                    &node_set,
                    self.response_validation_now(context.now_unix_seconds),
                )
                .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
            if verified.node_public_key() != provider.node_public_key {
                return Err(RuntimeReleaseCoordinatorError::ProviderResult);
            }
            if verified.decision() == RightsDecisionV1::Denied {
                return Ok(StartedOperationCollection {
                    offer: Some(RuntimeReleaseReconcileOffer::RightsDenied {
                        signed_node_rights_decision: Box::new(decision),
                    }),
                    replayable_rights_decisions: newly_replayable(&mut collected),
                });
            }
            if persisted_by_node
                .insert(provider.node_public_key, decision.clone())
                .is_some()
            {
                return Err(RuntimeReleaseCoordinatorError::ProviderResult);
            }
            collected.push((index, decision));
        }
        Ok(StartedOperationCollection {
            offer: None,
            replayable_rights_decisions: newly_replayable(&mut collected),
        })
    }

    async fn collect_contributions(
        &self,
        context: &StartedOperationContext<'_, '_>,
    ) -> Result<Option<RuntimeReleaseReconcileOffer>, RuntimeReleaseCoordinatorError> {
        match (
            context.signed_runtime_release_operation,
            context.authenticated,
        ) {
            (
                RuntimeReleaseOperationAnyV1::V1(signed),
                AuthenticatedRuntimeReleaseOperationAnyV1::V1(authenticated),
            ) => {
                self.collect_v1_contributions(context, signed, authenticated)
                    .await
            }
            (
                RuntimeReleaseOperationAnyV1::V2(signed),
                AuthenticatedRuntimeReleaseOperationAnyV1::V2(authenticated),
            ) => {
                self.collect_pool_contributions(context, signed, authenticated)
                    .await
            }
            _ => Err(RuntimeReleaseCoordinatorError::OperationAuthority),
        }
    }

    async fn collect_v1_contributions(
        &self,
        context: &StartedOperationContext<'_, '_>,
        signed: &SignedRuntimeReleaseOperationV1,
        authenticated: &AuthenticatedRuntimeReleaseOperationV1,
    ) -> Result<Option<RuntimeReleaseReconcileOffer>, RuntimeReleaseCoordinatorError> {
        let node_set = context
            .authenticated
            .node_set()
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)?;
        let threshold = context.threshold()?;
        let persisted_by_node = self.persisted_rights_decisions_by_node(context, &node_set)?;
        let candidates = context
            .ordered_providers
            .iter()
            .copied()
            .filter_map(|provider| {
                persisted_by_node
                    .get(&provider.node_public_key)
                    .map(|decision| (provider, decision))
            })
            .collect::<Vec<_>>();
        let requests = candidates
            .iter()
            .map(|(_, decision)| {
                CustodyProviderRequestV1::new_release_contribution(signed, decision)
                    .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut calls = ThresholdCalls::new(
            candidates
                .iter()
                .zip(&requests)
                .map(|((provider, _), request)| provider.custody.release_contribution(request))
                .collect(),
        );
        let mut contributions = Vec::with_capacity(threshold);
        while contributions.len() < threshold {
            calls.launch_up_to(threshold - contributions.len());
            let Some((index, answer)) = calls.next_answer().await else {
                break;
            };
            let (provider, _) = candidates[index];
            let request = &requests[index];
            // As for rights: a node without an exact answer is passed over,
            // and only a node holding a persisted decision is ever asked.
            let Ok(response) = answer else {
                tracing::debug!(
                    node_index = index,
                    "runtime release: contribution call gave no exact result, asking the next node"
                );
                continue;
            };
            if response
                .validate_against_request_at(
                    request,
                    self.expected_runtime_issuer,
                    provider.node_public_key,
                    self.response_validation_now(context.now_unix_seconds),
                )
                .is_err()
            {
                return match context.mode {
                    StartedOperationResolutionMode::InitialDispatch => Ok(None),
                    StartedOperationResolutionMode::ExactResume => {
                        Err(RuntimeReleaseCoordinatorError::ProviderResult)
                    }
                };
            }
            let contribution = response
                .signed_node_contribution()
                .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
            validate_contribution_identity(
                authenticated,
                &node_set,
                &contribution,
                provider.node_public_key,
                self.response_validation_now(context.now_unix_seconds),
            )?;
            contributions.push((index, contribution));
        }
        if contributions.len() < threshold {
            return Ok(None);
        }
        contributions.sort_by_key(|(index, _)| *index);
        Ok(Some(RuntimeReleaseReconcileOffer::ContributionsReady {
            signed_node_contributions: contributions
                .into_iter()
                .map(|(_, contribution)| contribution)
                .collect(),
        }))
    }

    /// V2: each node with a persisted decision is asked for its
    /// contributions, one per wallet-signed recipient (S4-Q5). A node counts
    /// only when it answers for every recipient, each sealed to that
    /// recipient (E7); the offer is node-set order, then recipient order.
    async fn collect_pool_contributions(
        &self,
        context: &StartedOperationContext<'_, '_>,
        signed: &SignedRuntimeReleaseOperationV2,
        authenticated: &AuthenticatedRuntimeReleaseOperationV2,
    ) -> Result<Option<RuntimeReleaseReconcileOffer>, RuntimeReleaseCoordinatorError> {
        let node_set = context
            .authenticated
            .node_set()
            .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)?;
        let threshold = context.threshold()?;
        let persisted_by_node = self.persisted_rights_decisions_by_node(context, &node_set)?;
        let candidates = context
            .ordered_providers
            .iter()
            .copied()
            .filter_map(|provider| {
                persisted_by_node
                    .get(&provider.node_public_key)
                    .map(|decision| (provider, decision))
            })
            .collect::<Vec<_>>();
        let requests = candidates
            .iter()
            .map(|(_, decision)| {
                PoolCustodyRequestV1::new_release_pool_contribution(signed, decision)
                    .map_err(|_| RuntimeReleaseCoordinatorError::OperationAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut calls = ThresholdCalls::new(
            candidates
                .iter()
                .zip(&requests)
                .map(|((provider, _), request)| provider.custody.release_pool_contribution(request))
                .collect(),
        );
        let mut groups = Vec::with_capacity(threshold);
        while groups.len() < threshold {
            calls.launch_up_to(threshold - groups.len());
            let Some((index, answer)) = calls.next_answer().await else {
                break;
            };
            let (provider, _) = candidates[index];
            let Ok(response) = answer else {
                tracing::debug!(
                    node_index = index,
                    "runtime release: pool contribution call gave no exact result, asking the next node"
                );
                continue;
            };
            let now = self.response_validation_now(context.now_unix_seconds);
            if response
                .validate_against_plain_request_at(&requests[index], provider.node_public_key, now)
                .is_err()
            {
                return match context.mode {
                    StartedOperationResolutionMode::InitialDispatch => Ok(None),
                    StartedOperationResolutionMode::ExactResume => {
                        Err(RuntimeReleaseCoordinatorError::ProviderResult)
                    }
                };
            }
            let contributions = response
                .signed_node_contributions()
                .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
            validate_pool_contribution_group(
                authenticated,
                &node_set,
                &contributions,
                Some(provider.node_public_key),
                now,
            )?;
            groups.push((index, contributions));
        }
        if groups.len() < threshold {
            return Ok(None);
        }
        groups.sort_by_key(|(index, _)| *index);
        Ok(Some(RuntimeReleaseReconcileOffer::ContributionsReady {
            signed_node_contributions: groups
                .into_iter()
                .flat_map(|(_, contributions)| contributions)
                .collect(),
        }))
    }

    fn persisted_rights_decisions_by_node(
        &self,
        context: &StartedOperationContext<'_, '_>,
        node_set: &NodeSetV1,
    ) -> Result<HashMap<NodePublicKey, SignedNodeRightsDecisionV1>, RuntimeReleaseCoordinatorError>
    {
        if context.replayable_rights_decisions.len() > context.ordered_providers.len() {
            return Err(RuntimeReleaseCoordinatorError::ProviderResult);
        }
        let selected_nodes = context
            .ordered_providers
            .iter()
            .map(|provider| provider.node_public_key)
            .collect::<BTreeSet<_>>();
        let mut persisted_by_node =
            HashMap::with_capacity(context.replayable_rights_decisions.len());
        for decision in context.replayable_rights_decisions {
            let verified = context
                .authenticated
                .verify_node_rights_decision(
                    decision,
                    node_set,
                    self.response_validation_now(context.now_unix_seconds),
                )
                .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
            if verified.decision() != RightsDecisionV1::Allowed {
                return Err(RuntimeReleaseCoordinatorError::ProviderResult);
            }
            if !selected_nodes.contains(&verified.node_public_key()) {
                return Err(RuntimeReleaseCoordinatorError::ProviderResult);
            }
            if persisted_by_node
                .insert(verified.node_public_key(), decision.clone())
                .is_some()
            {
                return Err(RuntimeReleaseCoordinatorError::ProviderResult);
            }
        }
        Ok(persisted_by_node)
    }
}

/// One provider call, not yet polled: an `async_trait` call does nothing until
/// it is first polled, so a call that is never launched never reaches a node.
type ProviderCall<'f, T> =
    Pin<Box<dyn Future<Output = Result<T, RuntimeProviderCallError>> + Send + 'f>>;

/// Provider calls for the nodes of one release step, in node-set order.
///
/// Nodes are asked together rather than one after another, so a slow node
/// costs its own time instead of adding it to every other node's. No more are
/// in flight than the step still needs, and the next node in order is asked
/// only when one in flight passes, so the nodes asked are the ones the
/// one-after-another walk would ask.
struct ThresholdCalls<'f, T> {
    calls: Vec<Option<ProviderCall<'f, T>>>,
    launched: usize,
    in_flight: Vec<usize>,
}

impl<'f, T> ThresholdCalls<'f, T> {
    fn new(calls: Vec<ProviderCall<'f, T>>) -> Self {
        Self {
            calls: calls.into_iter().map(Some).collect(),
            launched: 0,
            in_flight: Vec::new(),
        }
    }

    /// Asks further nodes, in order, until `wanted` calls are in flight or
    /// every node has been asked.
    fn launch_up_to(&mut self, wanted: usize) {
        while self.in_flight.len() < wanted && self.launched < self.calls.len() {
            self.in_flight.push(self.launched);
            self.launched += 1;
        }
    }

    /// The next call to finish, with its index among the calls; `None` once
    /// nothing is in flight. Calls that finish together are taken in node
    /// order. Calls still in flight when the caller stops are dropped
    /// unanswered, as the walk never asked those nodes at all.
    async fn next_answer(&mut self) -> Option<(usize, Result<T, RuntimeProviderCallError>)> {
        if self.in_flight.is_empty() {
            return None;
        }
        let (slot, answer) = poll_fn(|cx| {
            for (slot, index) in self.in_flight.iter().enumerate() {
                let Some(call) = self.calls[*index].as_mut() else {
                    continue;
                };
                if let Poll::Ready(answer) = call.as_mut().poll(cx) {
                    return Poll::Ready((slot, answer));
                }
            }
            Poll::Pending
        })
        .await;
        let index = self.in_flight.remove(slot);
        self.calls[index] = None;
        Some((index, answer))
    }
}

/// Extracts the canonical rights signature result from a Wallet `ok` payload.
/// The Wallet answers a `RequestProtectedContentRightsSignature` in one of
/// two shapes: the bare result (a signer that completes inline), or the
/// approval envelope it replays for an exact managed request once the
/// principal approved it (`approval_request` + `signed_result`, with
/// `requires_approval` false). Both carry the same result; a still-pending
/// envelope (no `signed_result`) yields nothing.
pub fn wallet_rights_signature_result(
    data: &Value,
) -> Option<ProtectedContentRightsSignatureResultV1> {
    if let Ok(result) =
        serde_json::from_value::<ProtectedContentRightsSignatureResultV1>(data.clone())
    {
        return Some(result);
    }
    if data.get("approval_request").is_none()
        || data.get("requires_approval").and_then(Value::as_bool) != Some(false)
    {
        return None;
    }
    serde_json::from_value::<ProtectedContentRightsSignatureResultV1>(
        data.get("signed_result")?.clone(),
    )
    .ok()
}

/// The asked request's canonical bytes and the Wallet's result of one
/// rights-signature exchange, after the result's account check.
fn wallet_rights_exchange(
    wallet_request: &WalletProviderRequestV2,
    wallet_response: &WalletProviderResponseV2,
) -> Result<(Vec<u8>, ProtectedContentRightsSignatureResultV1), RuntimeReleaseCoordinatorError> {
    let (account_id, canonical_rights_request_hex) = match &wallet_request.operation {
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id,
            canonical_rights_request_hex,
            ..
        } => (account_id, canonical_rights_request_hex),
        _ => return Err(RuntimeReleaseCoordinatorError::WalletAuthority),
    };
    let rights_request_bytes = hex::decode(canonical_rights_request_hex)
        .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    let result = match &wallet_response.result {
        WalletResultV2::Ok { data } => wallet_rights_signature_result(data)
            .ok_or(RuntimeReleaseCoordinatorError::WalletAuthority)?,
        WalletResultV2::Error { .. } => {
            return Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        }
    };
    result
        .validate()
        .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    if &result.account_id != account_id {
        return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
    }
    Ok((rights_request_bytes, result))
}

pub(crate) fn validate_wallet_rights_signature(
    wallet_request: &WalletProviderRequestV2,
    wallet_response: &WalletProviderResponseV2,
    expected_rights_request: &elastos_protected_content_contracts::RightsRequestV1,
) -> Result<WalletSignedRightsRequestV1, RuntimeReleaseCoordinatorError> {
    let (rights_request_bytes, result) = wallet_rights_exchange(wallet_request, wallet_response)?;
    let rights_request =
        elastos_protected_content_contracts::RightsRequestV1::from_canonical_bytes(
            &rights_request_bytes,
        )
        .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    if &rights_request != expected_rights_request {
        return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
    }
    if result.signer != wallet_address_hex(expected_rights_request.binding().wallet()) {
        return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
    }
    let signed_rights_bytes = hex::decode(&result.wallet_signed_rights_request_hex)
        .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    let result_signed_rights =
        WalletSignedRightsRequestV1::from_canonical_bytes(&signed_rights_bytes)
            .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    if result_signed_rights.request() != expected_rights_request {
        return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
    }
    Ok(result_signed_rights)
}

/// The V2 twin of [`validate_wallet_rights_signature`] (Plan B T1.2). The
/// Wallet result keeps schema `/v1`; the signed bytes' canonical domain says
/// V2 (L16). Beyond the V1 checks, the wallet signature itself must recover
/// to the bound wallet. The release coordinator calls it for V2 (T4.1).
pub(crate) fn validate_wallet_rights_signature_v2(
    wallet_request: &WalletProviderRequestV2,
    wallet_response: &WalletProviderResponseV2,
    expected_rights_request: &RightsRequestV2,
) -> Result<WalletSignedRightsRequestV2, RuntimeReleaseCoordinatorError> {
    let (rights_request_bytes, result) = wallet_rights_exchange(wallet_request, wallet_response)?;
    match RightsRequestAnyV1::from_canonical_bytes(&rights_request_bytes) {
        Ok(RightsRequestAnyV1::V2(asked)) if &asked == expected_rights_request => {}
        _ => return Err(RuntimeReleaseCoordinatorError::WalletAuthority),
    }
    if result.signer != wallet_address_hex(expected_rights_request.binding().wallet()) {
        return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
    }
    let signed_rights_bytes = hex::decode(&result.wallet_signed_rights_request_hex)
        .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    let signed = match WalletSignedRightsRequestAnyV1::from_canonical_bytes(&signed_rights_bytes) {
        Ok(WalletSignedRightsRequestAnyV1::V2(signed)) => signed,
        _ => return Err(RuntimeReleaseCoordinatorError::WalletAuthority),
    };
    if signed.request() != expected_rights_request {
        return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
    }
    signed
        .verify_unclaimed_at(expected_rights_request.issued_at())
        .map_err(|_| RuntimeReleaseCoordinatorError::WalletAuthority)?;
    Ok(signed)
}

/// The Wallet answer must be the exact wallet-signed rights request the
/// operation carries, V1 or V2.
fn validate_wallet_release_binding(
    wallet_request: &WalletProviderRequestV2,
    wallet_response: &WalletProviderResponseV2,
    signed_runtime_release_operation: &RuntimeReleaseOperationAnyV1,
) -> Result<(), RuntimeReleaseCoordinatorError> {
    match signed_runtime_release_operation {
        RuntimeReleaseOperationAnyV1::V1(operation) => {
            let signed_rights = operation.statement().rights_request();
            let result_signed_rights = validate_wallet_rights_signature(
                wallet_request,
                wallet_response,
                signed_rights.request(),
            )?;
            if &result_signed_rights != signed_rights {
                return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
            }
        }
        RuntimeReleaseOperationAnyV1::V2(operation) => {
            let signed_rights = operation.statement().rights_request();
            let result_signed_rights = validate_wallet_rights_signature_v2(
                wallet_request,
                wallet_response,
                signed_rights.request(),
            )?;
            if &result_signed_rights != signed_rights {
                return Err(RuntimeReleaseCoordinatorError::WalletAuthority);
            }
        }
    }
    Ok(())
}

fn offer_to_terminal(offer: &RuntimeReleaseReconcileOffer) -> RuntimeReleaseTerminalResult {
    match offer {
        RuntimeReleaseReconcileOffer::RightsDenied {
            signed_node_rights_decision,
        } => RuntimeReleaseTerminalResult::RightsDenied {
            signed_node_rights_decision: signed_node_rights_decision.clone(),
        },
        RuntimeReleaseReconcileOffer::ContributionsReady {
            signed_node_contributions,
        } => RuntimeReleaseTerminalResult::ContributionsReady {
            signed_node_contributions: signed_node_contributions.clone(),
        },
    }
}

/// The terminal contribution set of either version.
fn exact_release_contributions(
    authenticated: &AuthenticatedRuntimeReleaseOperationAnyV1,
    node_set: &NodeSetV1,
    contributions: &[SignedNodeContributionV1],
    now_unix_seconds: u64,
) -> Result<Vec<SignedNodeContributionV1>, RuntimeReleaseCoordinatorError> {
    match authenticated {
        AuthenticatedRuntimeReleaseOperationAnyV1::V1(authenticated) => {
            exact_threshold_contributions(authenticated, node_set, contributions, now_unix_seconds)
        }
        AuthenticatedRuntimeReleaseOperationAnyV1::V2(authenticated) => {
            exact_pool_contributions(authenticated, node_set, contributions, now_unix_seconds)
        }
    }
}

/// V2 (S4-Q5): exactly `required` distinct nodes, each with one
/// contribution per wallet-signed recipient, in node-set order and then
/// recipient order. Each pair appears once.
fn exact_pool_contributions(
    authenticated: &AuthenticatedRuntimeReleaseOperationV2,
    node_set: &NodeSetV1,
    contributions: &[SignedNodeContributionV1],
    now_unix_seconds: u64,
) -> Result<Vec<SignedNodeContributionV1>, RuntimeReleaseCoordinatorError> {
    let required = usize::from(node_set.threshold().required());
    let recipients = authenticated
        .statement()
        .rights_request()
        .request()
        .recipients();
    if recipients.is_empty() || contributions.len() != required.saturating_mul(recipients.len()) {
        return Err(RuntimeReleaseCoordinatorError::ProviderResult);
    }
    let mut seen = BTreeSet::new();
    let mut previous_position = None;
    for group in contributions.chunks(recipients.len()) {
        let node = validate_pool_contribution_group(
            authenticated,
            node_set,
            group,
            None,
            now_unix_seconds,
        )?;
        if !seen.insert(node) {
            return Err(RuntimeReleaseCoordinatorError::ProviderResult);
        }
        let position = node_set
            .members()
            .iter()
            .position(|member| *member == node)
            .ok_or(RuntimeReleaseCoordinatorError::ProviderResult)?;
        if previous_position.is_some_and(|previous| position <= previous) {
            return Err(RuntimeReleaseCoordinatorError::ProviderResult);
        }
        previous_position = Some(position);
    }
    Ok(contributions.to_vec())
}

/// One node's V2 contributions: one per wallet-signed recipient, in the
/// rights request's order, each verified against its own recipient (E7),
/// all from one node (`expected_node` when given). Answers that node.
fn validate_pool_contribution_group(
    authenticated: &AuthenticatedRuntimeReleaseOperationV2,
    node_set: &NodeSetV1,
    contributions: &[SignedNodeContributionV1],
    expected_node: Option<NodePublicKey>,
    now_unix_seconds: u64,
) -> Result<NodePublicKey, RuntimeReleaseCoordinatorError> {
    let recipients = authenticated
        .statement()
        .rights_request()
        .request()
        .recipients();
    if recipients.is_empty() || contributions.len() != recipients.len() {
        return Err(RuntimeReleaseCoordinatorError::ProviderResult);
    }
    let mut node = expected_node;
    for (contribution, recipient) in contributions.iter().zip(recipients) {
        let verified = authenticated
            .verify_node_contribution(contribution, node_set, recipient, now_unix_seconds)
            .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
        if verified.recipient() != recipient {
            return Err(RuntimeReleaseCoordinatorError::ProviderResult);
        }
        match node {
            None => node = Some(verified.node_public_key()),
            Some(expected) if expected != verified.node_public_key() => {
                return Err(RuntimeReleaseCoordinatorError::ProviderResult);
            }
            Some(_) => {}
        }
    }
    node.ok_or(RuntimeReleaseCoordinatorError::ProviderResult)
}

fn exact_threshold_contributions(
    authenticated: &AuthenticatedRuntimeReleaseOperationV1,
    node_set: &NodeSetV1,
    contributions: &[SignedNodeContributionV1],
    now_unix_seconds: u64,
) -> Result<Vec<SignedNodeContributionV1>, RuntimeReleaseCoordinatorError> {
    let required = usize::from(node_set.threshold().required());
    if contributions.len() != required {
        return Err(RuntimeReleaseCoordinatorError::ProviderResult);
    }
    let mut seen = BTreeSet::new();
    let mut verified = Vec::with_capacity(required);
    for contribution in contributions {
        let node = authenticated
            .verify_node_contribution(contribution, node_set, now_unix_seconds)
            .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?
            .node_public_key();
        if !seen.insert(node) {
            return Err(RuntimeReleaseCoordinatorError::ProviderResult);
        }
        verified.push(contribution.clone());
    }
    Ok(verified)
}

fn validate_contribution_identity(
    authenticated: &AuthenticatedRuntimeReleaseOperationV1,
    node_set: &NodeSetV1,
    contribution: &SignedNodeContributionV1,
    expected_node: NodePublicKey,
    now_unix_seconds: u64,
) -> Result<(), RuntimeReleaseCoordinatorError> {
    let verified = authenticated
        .verify_node_contribution(contribution, node_set, now_unix_seconds)
        .map_err(|_| RuntimeReleaseCoordinatorError::ProviderResult)?;
    if verified.node_public_key() != expected_node {
        return Err(RuntimeReleaseCoordinatorError::ProviderResult);
    }
    Ok(())
}

pub(crate) fn wallet_address_hex(wallet: WalletAddress) -> String {
    format!("0x{}", hex::encode(wallet.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use ed25519_dalek::{Signer as _, SigningKey};
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyApprovedSuitesV1, CustodyCommitteeAuthorizationIdentityV1,
        CustodyEnvelopeManifestV1, CustodyEnvelopeV1, CustodyEpochIssuerKeyV1,
        CustodyEpochStatementV1, CustodyNodeIdentityV1, CustodyNodeProvisioningRecordIdentityV1,
        CustodyPoolFailureDomainIdV1, CustodyPoolOperatorIdV1, EncryptedContentIdentityV1,
        EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1, KeyReleaseOutcomeV1,
        KeyReleaseRequestV1, NodeContributionRefV1, NodeContributionStatementV1,
        NodeCustodyPublicKeyV1, PqHybridSealedShareV1, ProfileIdentityV1,
        ProtectedContentBindingV1, RecipientKeyAuthorizationStatementV1, RecipientKeyIdentityV1,
        RecipientPublicKeyBytesV1, RecipientSealedContributionV1, ReplayNonce16, RightsActionV1,
        RightsEvaluationEvidenceRequestV1, RightsObservationFinalityV1, RightsPolicyBodyV1,
        RightsRequestV1, RightsSubjectSourceV1, RuntimeCustodyProvisioningIdV1,
        RuntimeReleaseAuditIdV1, RuntimeReleaseOperationStatementV1, RuntimeSessionBindingV1,
        ShareCoordinateV1, SignedCustodyEpochV1, SignedNodeRightsDecisionV1,
        SignedRecipientKeyAuthorizationV1, SignedTerminalReceiptV1, TerminalReceiptIssuerKey,
        TerminalReceiptStatementV1, ThresholdV1, WalletAddress,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES,
        X_WING_DRAFT06_CIPHERTEXT_BYTES,
    };
    use elastos_protected_content_provider_contracts::{
        CustodyProviderResponseStatusV1, DecryptProviderRequestV1, DecryptProviderResponseV1,
        ProviderFailureCodeV1, ValidatedCustodyProviderRequestV1,
        ValidatedDecryptProviderRequestV1, ValidatedRightsProviderRequestV1,
        ViewerMediaPartSelectorV1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
    };
    use elastos_wallet_contract::{
        ProtectedContentRightsSignatureResultV1, ValidatedChainOutcomeBindingV1,
        VerifiedWalletInvocationContext, WalletProviderOperationV2, WalletProviderRequestV2,
        WalletProviderResponseV2, WalletResultV2,
    };
    use k256::ecdsa::SigningKey as WalletSigningKey;
    use sha3::{Digest as _, Keccak256};
    use tempfile::tempdir;
    use x_wing::kem::{Decapsulator as _, KeyExport as _};
    use x_wing::TryKeyInit as _;

    use serde_json::json;

    use super::*;
    use crate::test_media;
    use crate::{
        bind_buy, close_viewer_session, open_viewer_session, prepare_recipient,
        read_viewer_media_part, RuntimeContentAvailabilityRequirement, RuntimeDecryptProvider,
        RuntimeMintCoordinator, RuntimeMintCoordinatorOutcome, RuntimeMintDraft,
        RuntimeMintJournal, RuntimeMintNodeBinding, RuntimeMintNodeReceipt,
        RuntimeMintSelectedNode, RuntimeOpenError, RuntimeOpenViewerContentV1,
        RuntimeOpenViewerSessionInput, RuntimeProtectedContentPurchaseIntent,
        RuntimePurchaseEffectAuthority, RuntimeVerifiedContentAvailability,
        RuntimeVerifiedContentIdentityRootV1, RuntimeVerifiedPurchaseEffect,
    };

    const NOW: u64 = 2_000_000_000;
    const PQ_HYBRID_AEAD_NONCE_BYTES: usize = 12;
    const PQ_HYBRID_WRAPPED_SHARE_BYTES: usize = 48;

    #[derive(Default)]
    struct FakeRightsProvider {
        responses: Mutex<Vec<Result<RightsProviderResponseV1, RuntimeProviderCallError>>>,
        requests: Mutex<Vec<RightsProviderRequestV1>>,
    }

    impl FakeRightsProvider {
        fn new(responses: Vec<Result<RightsProviderResponseV1, RuntimeProviderCallError>>) -> Self {
            Self {
                responses: Mutex::new(responses),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl RuntimeRightsProvider for FakeRightsProvider {
        async fn evaluate_rights(
            &self,
            request: &RightsProviderRequestV1,
        ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError> {
            self.requests.lock().unwrap().push(request.clone());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            Ok(responses.remove(0)?)
        }
    }

    #[derive(Default)]
    struct FakeCustodyProvider {
        responses: Mutex<Vec<Result<CustodyProviderResponseV1, RuntimeProviderCallError>>>,
        requests: Mutex<Vec<CustodyProviderRequestV1>>,
    }

    impl FakeCustodyProvider {
        fn new(
            responses: Vec<Result<CustodyProviderResponseV1, RuntimeProviderCallError>>,
        ) -> Self {
            Self {
                responses: Mutex::new(responses),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl RuntimeCustodyProvider for FakeCustodyProvider {
        async fn release_contribution(
            &self,
            request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            self.requests.lock().unwrap().push(request.clone());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            Ok(responses.remove(0)?)
        }

        async fn provision_node_share(
            &self,
            _request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }

        async fn release_pool_contribution(
            &self,
            _request: &PoolCustodyRequestV1,
        ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }
    }

    /// A node whose every answer takes `delay`.
    struct SlowProvider<'a> {
        rights: &'a FakeRightsProvider,
        custody: &'a FakeCustodyProvider,
        delay: std::time::Duration,
    }

    #[async_trait::async_trait]
    impl RuntimeRightsProvider for SlowProvider<'_> {
        async fn evaluate_rights(
            &self,
            request: &RightsProviderRequestV1,
        ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError> {
            tokio::time::sleep(self.delay).await;
            self.rights.evaluate_rights(request).await
        }
    }

    #[async_trait::async_trait]
    impl RuntimeCustodyProvider for SlowProvider<'_> {
        async fn release_contribution(
            &self,
            request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            tokio::time::sleep(self.delay).await;
            self.custody.release_contribution(request).await
        }

        async fn provision_node_share(
            &self,
            request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            self.custody.provision_node_share(request).await
        }

        async fn release_pool_contribution(
            &self,
            request: &PoolCustodyRequestV1,
        ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
            tokio::time::sleep(self.delay).await;
            self.custody.release_pool_contribution(request).await
        }
    }

    struct InspectingCustodyProvider {
        journal_root: PathBuf,
        operation_hash: Digest32,
        observed_replayable_rights_counts: Mutex<Vec<usize>>,
        responses: Mutex<Vec<Result<CustodyProviderResponseV1, RuntimeProviderCallError>>>,
        requests: Mutex<Vec<CustodyProviderRequestV1>>,
    }

    impl InspectingCustodyProvider {
        fn new(
            journal_root: PathBuf,
            operation_hash: Digest32,
            responses: Vec<Result<CustodyProviderResponseV1, RuntimeProviderCallError>>,
        ) -> Self {
            Self {
                journal_root,
                operation_hash,
                observed_replayable_rights_counts: Mutex::new(Vec::new()),
                responses: Mutex::new(responses),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn observed_replayable_rights_counts(&self) -> Vec<usize> {
            self.observed_replayable_rights_counts
                .lock()
                .unwrap()
                .clone()
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl RuntimeCustodyProvider for InspectingCustodyProvider {
        async fn release_contribution(
            &self,
            request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            self.requests.lock().unwrap().push(request.clone());
            let persisted = RuntimeReleaseJournal::new(self.journal_root.clone())
                .load(self.operation_hash)
                .unwrap();
            self.observed_replayable_rights_counts
                .lock()
                .unwrap()
                .push(persisted.replayable_rights_decisions().len());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            Ok(responses.remove(0)?)
        }

        async fn provision_node_share(
            &self,
            _request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }

        async fn release_pool_contribution(
            &self,
            _request: &PoolCustodyRequestV1,
        ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn node_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn node_public_key(seed: u8) -> NodePublicKey {
        NodePublicKey::new(node_key(seed).verifying_key().to_bytes()).unwrap()
    }

    fn wallet_key(seed: u8) -> WalletSigningKey {
        WalletSigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn wallet(seed: u8) -> WalletAddress {
        let key = wallet_key(seed);
        let encoded = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
        WalletAddress::new(digest[12..].try_into().unwrap())
    }

    fn recipient_public_key(seed: u8) -> RecipientPublicKeyBytesV1 {
        RecipientPublicKeyBytesV1::new(xwing_public_key_bytes(seed.max(9))).unwrap()
    }

    fn recipient_identity(seed: u8) -> RecipientKeyIdentityV1 {
        recipient_public_key(seed)
            .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
            .unwrap()
    }

    fn xwing_public_key_bytes(
        seed: u8,
    ) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
        secret.encapsulation_key().to_bytes().into()
    }

    fn node_custody_public_key(seed: u8) -> NodeCustodyPublicKeyV1 {
        NodeCustodyPublicKeyV1::new(xwing_public_key_bytes(seed)).unwrap()
    }

    fn sealed_share(seed: u8) -> PqHybridSealedShareV1 {
        let public =
            x_wing::EncapsulationKey::new_from_slice(&xwing_public_key_bytes(seed)).unwrap();
        let (ciphertext, _) =
            public.encapsulate_deterministic(&[seed; x_wing::ENCAPSULATION_RANDOMNESS_SIZE].into());
        let ciphertext: [u8; X_WING_DRAFT06_CIPHERTEXT_BYTES] = ciphertext.into();
        let mut envelope = Vec::with_capacity(PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES);
        envelope.extend_from_slice(&ciphertext);
        envelope.extend_from_slice(&[seed; PQ_HYBRID_AEAD_NONCE_BYTES]);
        envelope.extend_from_slice(&[seed ^ 0x5a; PQ_HYBRID_WRAPPED_SHARE_BYTES]);
        PqHybridSealedShareV1::new(envelope).unwrap()
    }

    fn policy_body() -> RightsPolicyBodyV1 {
        policy_body_with_media(
            media_identity(0x21),
            ContentAccessIdV1::new([0x41; 16]).unwrap(),
        )
    }

    fn policy_body_with_media(
        encrypted_content: EncryptedContentIdentityV1,
        content_access_id: ContentAccessIdV1,
    ) -> RightsPolicyBodyV1 {
        RightsPolicyBodyV1::new(
            encrypted_content,
            content_access_id,
            RightsActionV1::View,
            RightsSubjectSourceV1::WalletAddress,
            11155111,
            EvmContractAddressV1::new([0x11; 20]).unwrap(),
            EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
            EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
            RightsObservationFinalityV1::finalized(),
        )
        .unwrap()
    }

    fn profile_identity(seed: u8) -> ProfileIdentityV1 {
        ProfileIdentityV1::from_public_key_bytes(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    fn media_identity(seed: u8) -> EncryptedContentIdentityV1 {
        test_media::media_identity(seed).encrypted_content().clone()
    }

    fn content_access_id(seed: u8) -> ContentAccessIdV1 {
        ContentAccessIdV1::new([seed; 16]).unwrap()
    }

    fn binding_for_runtime_release(
        envelope: &CustodyEnvelopeV1,
        policy: &RightsPolicyBodyV1,
        profile_seed: u8,
        wallet_seed: u8,
        session_seed: u8,
    ) -> ProtectedContentBindingV1 {
        ProtectedContentBindingV1::new(
            envelope.manifest().encrypted_content().clone(),
            envelope.key_envelope_identity().unwrap(),
            policy.policy_identity().unwrap(),
            profile_identity(profile_seed),
            wallet(wallet_seed),
            RuntimeSessionBindingV1::new(digest(session_seed)).unwrap(),
        )
        .unwrap()
    }

    fn signed_custody_epoch() -> SignedCustodyEpochV1 {
        let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
        let nodes = [1, 2, 3]
            .into_iter()
            .map(|seed| {
                CustodyNodeIdentityV1::new(
                    node_public_key(seed),
                    node_custody_public_key(0x30 + seed),
                    ShareCoordinateV1::new(seed).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let statement = CustodyEpochStatementV1::new(
            CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
            CustodyApprovedSuitesV1::new(
                CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            )
            .unwrap(),
            ThresholdV1::new(2, 3).unwrap(),
            nodes,
        )
        .unwrap();
        SignedCustodyEpochV1::new(
            statement.clone(),
            issuer_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    fn custody_envelope(seed: u8) -> CustodyEnvelopeV1 {
        let epoch = signed_custody_epoch();
        let manifest = CustodyEnvelopeManifestV1::new(
            media_identity(seed),
            elastos_protected_content_contracts::CustodyPoolIdentityV1::new(
                digest(seed ^ 0x34),
                512,
            )
            .unwrap(),
            epoch.epoch_identity().unwrap(),
            CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
            ThresholdV1::new(2, 3).unwrap(),
            digest(seed ^ 0x33),
            epoch.statement().nodes().to_vec(),
        )
        .unwrap();
        let shares = [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
            .into_iter()
            .map(sealed_share)
            .collect();
        CustodyEnvelopeV1::new(manifest, shares).unwrap()
    }

    fn runtime_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn runtime_issuer(seed: u8) -> RuntimeOperationIssuerKeyV1 {
        RuntimeOperationIssuerKeyV1::new(runtime_key(seed).verifying_key().to_bytes()).unwrap()
    }

    fn signed_runtime_release_operation(seed: u8) -> SignedRuntimeReleaseOperationV1 {
        signed_runtime_release_operation_for_envelope(seed, 0x11)
    }

    fn signed_runtime_release_operation_for_envelope(
        seed: u8,
        envelope_seed: u8,
    ) -> SignedRuntimeReleaseOperationV1 {
        signed_runtime_release_operation_for(seed, envelope_seed, 7, 0x30)
    }

    fn signed_runtime_release_operation_for(
        seed: u8,
        envelope_seed: u8,
        wallet_seed: u8,
        recipient_seed: u8,
    ) -> SignedRuntimeReleaseOperationV1 {
        let envelope = custody_envelope(envelope_seed);
        let policy = policy_body();
        let binding =
            binding_for_runtime_release(&envelope, &policy, 0x26, wallet_seed, 0x66 ^ wallet_seed);
        signed_runtime_release_operation_with_binding(
            seed,
            binding,
            policy,
            wallet_seed,
            recipient_seed,
            0x26,
        )
    }

    fn signed_runtime_release_operation_with_binding(
        seed: u8,
        binding: ProtectedContentBindingV1,
        policy: RightsPolicyBodyV1,
        wallet_seed: u8,
        recipient_seed: u8,
        profile_seed: u8,
    ) -> SignedRuntimeReleaseOperationV1 {
        let runtime_key = runtime_key(seed);
        let rights_request = {
            let request = RightsRequestV1::new(
                binding.clone(),
                RightsActionV1::View,
                recipient_identity(recipient_seed),
                NOW,
                NOW + 180,
                ReplayNonce16::new([wallet_seed; 16]),
            )
            .unwrap();
            let (signature, recovery_id) = wallet_key(wallet_seed)
                .sign_prehash_recoverable(&request.signing_hash().unwrap())
                .unwrap();
            let mut signature_bytes = signature.to_bytes().to_vec();
            signature_bytes.push(recovery_id.to_byte());
            WalletSignedRightsRequestV1::new(request, signature_bytes).unwrap()
        };
        let release_request = KeyReleaseRequestV1::new(
            binding.clone(),
            rights_request.request().request_hash().unwrap(),
            RightsActionV1::View,
            rights_request.request().recipient().clone(),
            NOW + 1,
            NOW + 50,
            ReplayNonce16::new([0x66; 16]),
        )
        .unwrap();
        let profile = SigningKey::from_bytes(&[profile_seed; 32]);
        let recipient_public_key = recipient_public_key(recipient_seed);
        let authorization_statement = RecipientKeyAuthorizationStatementV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_public_key,
            rights_request.request().recipient().clone(),
            RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
            NOW,
            NOW + 90,
        )
        .unwrap();
        let authorization = SignedRecipientKeyAuthorizationV1::new(
            authorization_statement.clone(),
            profile
                .sign(&authorization_statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let evidence_request = RightsEvaluationEvidenceRequestV1::new(
            binding.clone(),
            policy.policy_identity().unwrap(),
        )
        .unwrap();
        let statement = RuntimeReleaseOperationStatementV1::new(
            RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
            rights_request,
            release_request,
            recipient_public_key,
            authorization,
            policy,
            evidence_request,
            signed_custody_epoch(),
            RuntimeReleaseAuditIdV1::new(digest(0x91 ^ seed ^ wallet_seed)).unwrap(),
            NOW + 2,
            NOW + 40,
        )
        .unwrap();
        SignedRuntimeReleaseOperationV1::new(
            statement.clone(),
            runtime_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    fn signed_node_rights_decision(
        operation: &SignedRuntimeReleaseOperationV1,
        node_seed: u8,
        decision: RightsDecisionV1,
    ) -> SignedNodeRightsDecisionV1 {
        let authenticated = operation
            .verify(operation.statement().runtime_operation_issuer(), NOW + 3)
            .unwrap();
        let statement = elastos_protected_content_contracts::NodeRightsDecisionStatementV1::new(
            authenticated.release_request_hash(),
            authenticated.rights_request_hash(),
            authenticated.binding().clone(),
            authenticated.action(),
            node_public_key(node_seed),
            decision,
            digest(0x80 ^ node_seed),
            NOW + 4,
            NOW + 35,
        )
        .unwrap();
        SignedNodeRightsDecisionV1::new(
            statement.clone(),
            node_key(node_seed)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    fn signed_node_contribution(
        operation: &SignedRuntimeReleaseOperationV1,
        node_seed: u8,
    ) -> SignedNodeContributionV1 {
        let authenticated = operation
            .verify(operation.statement().runtime_operation_issuer(), NOW + 5)
            .unwrap();
        let decision = signed_node_rights_decision(operation, node_seed, RightsDecisionV1::Allowed);
        let sealed = RecipientSealedContributionV1::new(
            authenticated.recipient().clone(),
            vec![node_seed; 96],
        )
        .unwrap();
        let statement = NodeContributionStatementV1::new(
            authenticated.release_request_hash(),
            authenticated.binding().clone(),
            decision,
            sealed,
            NOW + 5,
            NOW + 35,
        )
        .unwrap();
        SignedNodeContributionV1::new(
            statement.clone(),
            node_key(node_seed)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    fn wallet_request_response(operation: &SignedRuntimeReleaseOperationV1) -> (Vec<u8>, Vec<u8>) {
        wallet_request_response_for(
            operation,
            "profile:alpha",
            "wallet-account-alpha",
            "wallet-request:11111111111111111111111111111111",
        )
    }

    fn wallet_request_response_for(
        operation: &SignedRuntimeReleaseOperationV1,
        profile: &str,
        account_id: &str,
        request_id: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let context = VerifiedWalletInvocationContext::new(
            profile,
            "runtime-session:alpha",
            Some("proof:alpha".to_string()),
            "grant:alpha",
            "runtime",
            "launch:alpha",
        )
        .unwrap();
        let request = WalletProviderRequestV2::new(
            &context,
            request_id,
            NOW,
            NOW + 120,
            WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                account_id: account_id.to_string(),
                canonical_rights_request_hex: hex::encode(
                    operation
                        .statement()
                        .rights_request()
                        .request()
                        .canonical_bytes()
                        .unwrap(),
                ),
                reason: "Open protected content".to_string(),
            },
        )
        .unwrap();
        let result = ProtectedContentRightsSignatureResultV1::new(
            account_id,
            wallet_address_hex(
                operation
                    .statement()
                    .rights_request()
                    .request()
                    .binding()
                    .wallet(),
            ),
            hex::encode(
                operation
                    .statement()
                    .rights_request()
                    .canonical_bytes()
                    .unwrap(),
            ),
        )
        .unwrap();
        let response = WalletProviderResponseV2::for_request(
            &request,
            WalletResultV2::Ok {
                data: serde_json::to_value(result).unwrap(),
            },
        );
        (
            serde_json::to_vec(&request).unwrap(),
            serde_json::to_vec(&response).unwrap(),
        )
    }

    /// Plan B T1.2: the wallet exchange for a V2 rights request.
    fn wallet_request_response_v2(
        asked: &elastos_protected_content_contracts::RightsRequestV2,
        signed: &elastos_protected_content_contracts::WalletSignedRightsRequestV2,
    ) -> (WalletProviderRequestV2, WalletProviderResponseV2) {
        let context = VerifiedWalletInvocationContext::new(
            "profile:alpha",
            "runtime-session:alpha",
            Some("proof:alpha".to_string()),
            "grant:alpha",
            "runtime",
            "launch:alpha",
        )
        .unwrap();
        let account_id = "wallet-account-alpha";
        let request = WalletProviderRequestV2::new(
            &context,
            "wallet-request:22222222222222222222222222222222",
            NOW,
            NOW + 120,
            WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                account_id: account_id.to_string(),
                canonical_rights_request_hex: hex::encode(asked.canonical_bytes().unwrap()),
                reason: "Open protected content".to_string(),
            },
        )
        .unwrap();
        let result = ProtectedContentRightsSignatureResultV1::new(
            account_id,
            wallet_address_hex(asked.binding().wallet()),
            hex::encode(signed.canonical_bytes().unwrap()),
        )
        .unwrap();
        let response = WalletProviderResponseV2::for_request(
            &request,
            WalletResultV2::Ok {
                data: serde_json::to_value(result).unwrap(),
            },
        );
        (request, response)
    }

    #[test]
    fn guard_wallet_v2_signature_for_other_request_is_refused() {
        use elastos_protected_content_contracts::{
            DeliveryKeyIdentityV1, RightsRequestV2, WalletSignedRightsRequestV2,
        };
        let operation = signed_runtime_release_operation(1);
        let binding = operation
            .statement()
            .rights_request()
            .request()
            .binding()
            .clone();
        // ADV-01: the request binds the chain of the fixture's policy.
        let chain_id = operation.statement().policy_body().chain_id();
        let request_v2 = |nonce: u8| {
            RightsRequestV2::new(
                binding.clone(),
                RightsActionV1::View,
                vec![recipient_identity(9), recipient_identity(10)],
                DeliveryKeyIdentityV1::new(Digest32::new([0x5d; 32])),
                NOW,
                NOW + 180,
                ReplayNonce16::new([nonce; 16]),
                chain_id,
            )
            .unwrap()
        };
        // The fixture binding names wallet 7.
        let signed_by = |wallet_seed: u8, request: &RightsRequestV2| {
            let (signature, recovery_id) = wallet_key(wallet_seed)
                .sign_prehash_recoverable(&request.signing_hash().unwrap())
                .unwrap();
            let mut signature_bytes = signature.to_bytes().to_vec();
            signature_bytes.push(recovery_id.to_byte());
            WalletSignedRightsRequestV2::new(request.clone(), signature_bytes).unwrap()
        };
        let expected = request_v2(0x51);
        let other = request_v2(0x52);

        let (request, response) = wallet_request_response_v2(&expected, &signed_by(7, &expected));
        let signed = validate_wallet_rights_signature_v2(&request, &response, &expected).unwrap();
        assert_eq!(signed.request(), &expected);

        // The wallet answered with a signature for another request.
        let (request, response) = wallet_request_response_v2(&expected, &signed_by(7, &other));
        assert_eq!(
            validate_wallet_rights_signature_v2(&request, &response, &expected),
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        // The wallet was asked to sign another request.
        let (request, response) = wallet_request_response_v2(&other, &signed_by(7, &other));
        assert_eq!(
            validate_wallet_rights_signature_v2(&request, &response, &expected),
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        // Another wallet key signed the expected request.
        let (request, response) = wallet_request_response_v2(&expected, &signed_by(8, &expected));
        assert_eq!(
            validate_wallet_rights_signature_v2(&request, &response, &expected),
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
    }

    #[test]
    fn wallet_rights_signature_result_accepts_bare_and_replayed_approval_shapes() {
        let result = json!({
            "schema": "elastos.wallet.protected-content-rights-signature-result/v1",
            "account_id": "wallet:eip155:20:0x00000000000000000000000000000000000000aa",
            "signer": "0x00000000000000000000000000000000000000aa",
            "wallet_signed_rights_request_hex": "00",
        });
        let bare = super::wallet_rights_signature_result(&result);
        let replayed = super::wallet_rights_signature_result(&json!({
            "approval_request": { "request_id": "wallet-request:1", "status": "completed" },
            "requires_approval": false,
            "signature": null,
            "signed_result": result,
            "signature_receipt": { "request_id": "wallet-request:1" },
        }));
        let pending = super::wallet_rights_signature_result(&json!({
            "approval_request": { "request_id": "wallet-request:1", "status": "pending" },
            "requires_approval": true,
            "signature": null,
        }));
        assert!(bare.is_some(), "bare result must decode");
        assert_eq!(
            bare, replayed,
            "replayed approval envelope carries the same result"
        );
        assert!(pending.is_none(), "a pending approval carries no signature");
    }

    fn owner_only_root(temp: &tempfile::TempDir) -> PathBuf {
        let parent = temp.path().join("owner-only-parent");
        create_owner_only_directory(&parent);
        parent.join("runtime-release")
    }

    fn create_owner_only_directory(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn coordinator<'a>(
        root: &Path,
        providers: Vec<RuntimeSelectedProvider<'a>>,
    ) -> RuntimeReleaseCoordinator<'a> {
        RuntimeReleaseCoordinator::new(
            RuntimeReleaseJournal::new(root.to_path_buf()),
            runtime_issuer(0x42),
            providers,
        )
        .unwrap()
    }

    fn selected<'a>(
        rights: &'a FakeRightsProvider,
        custody: &'a FakeCustodyProvider,
        node_seed: u8,
    ) -> RuntimeSelectedProvider<'a> {
        RuntimeSelectedProvider::new(node_public_key(node_seed), rights, custody)
    }

    fn provider_triplet(
        operation: &SignedRuntimeReleaseOperationV1,
    ) -> (
        FakeRightsProvider,
        FakeRightsProvider,
        FakeRightsProvider,
        FakeCustodyProvider,
        FakeCustodyProvider,
        FakeCustodyProvider,
    ) {
        (
            FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
                &signed_node_rights_decision(operation, 1, RightsDecisionV1::Allowed),
            )
            .unwrap())]),
            FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
                &signed_node_rights_decision(operation, 2, RightsDecisionV1::Allowed),
            )
            .unwrap())]),
            FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
                &signed_node_rights_decision(operation, 3, RightsDecisionV1::Allowed),
            )
            .unwrap())]),
            FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
                &signed_node_contribution(operation, 1),
            )
            .unwrap())]),
            FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
                &signed_node_contribution(operation, 2),
            )
            .unwrap())]),
            FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
                &signed_node_contribution(operation, 3),
            )
            .unwrap())]),
        )
    }

    #[tokio::test]
    async fn runtime_coordination_allows_and_collects_threshold_contributions() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let (r1, r2, r3, c1, c2, c3) = provider_triplet(&operation);
        let runtime = coordinator(
            &owner_only_root(&temp),
            vec![
                selected(&r1, &c1, 1),
                selected(&r2, &c2, 2),
                selected(&r3, &c3, 3),
            ],
        );

        let outcome = runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        match outcome {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(r1.request_count(), 1);
        assert_eq!(r2.request_count(), 1);
        assert_eq!(c1.request_count(), 1);
        assert_eq!(c2.request_count(), 1);
        assert_eq!(r3.request_count(), 0);
        assert_eq!(c3.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_denial_is_terminal_and_skips_custody() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Denied),
        )
        .unwrap())]);
        let r2 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Denied),
        )
        .unwrap())]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(
            &owner_only_root(&temp),
            vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)],
        );

        let outcome = runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        match outcome {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::RightsDenied { .. },
            ) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(r1.request_count() + r2.request_count(), 1);
        assert_eq!(c1.request_count(), 0);
        assert_eq!(c2.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_replays_terminal_without_dispatch() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let (r1, r2, r3, c1, c2, c3) = provider_triplet(&operation);
        let runtime = coordinator(
            &root,
            vec![
                selected(&r1, &c1, 1),
                selected(&r2, &c2, 2),
                selected(&r3, &c3, 3),
            ],
        );
        let first = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let r1_replay = FakeRightsProvider::default();
        let r2_replay = FakeRightsProvider::default();
        let c1_replay = FakeCustodyProvider::default();
        let c2_replay = FakeCustodyProvider::default();
        let runtime_replay = coordinator(
            &root,
            vec![
                selected(&r1_replay, &c1_replay, 1),
                selected(&r2_replay, &c2_replay, 2),
            ],
        );

        let replay = runtime_replay
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        assert_eq!(replay, first);
        assert_eq!(r1_replay.request_count(), 0);
        assert_eq!(r2_replay.request_count(), 0);
        assert_eq!(c1_replay.request_count(), 0);
        assert_eq!(c2_replay.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_nonterminal_replay_does_not_redispatch() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let r2 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);

        let first = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        assert!(matches!(
            first,
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                ..
            }
        ));
        // Both nodes were asked, and neither gave an exact answer.
        assert_eq!(r1.request_count(), 1);
        assert_eq!(r2.request_count(), 1);

        let r1_replay = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Denied),
        )
        .unwrap())]);
        let r2_replay = FakeRightsProvider::default();
        let c1_replay = FakeCustodyProvider::default();
        let c2_replay = FakeCustodyProvider::default();
        let runtime_replay = coordinator(
            &root,
            vec![
                selected(&r1_replay, &c1_replay, 1),
                selected(&r2_replay, &c2_replay, 2),
            ],
        );
        let replay = runtime_replay
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        assert!(matches!(
            replay,
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                reason: RuntimeReleaseNonterminalReason::ProviderEffectAlreadyStarted,
                ..
            }
        ));
        assert_eq!(r1_replay.request_count(), 0);
        assert_eq!(r2_replay.request_count(), 0);
        assert_eq!(c1_replay.request_count(), 0);
        assert_eq!(c2_replay.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_resume_exact_settles_uncertain_effect_without_new_operation() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![
            Err(RuntimeProviderCallError::NoExactResult),
            Err(RuntimeProviderCallError::NoExactResult),
        ]);
        let r2 = FakeRightsProvider::new(vec![
            Err(RuntimeProviderCallError::NoExactResult),
            Ok(
                RightsProviderResponseV1::new_decision(&signed_node_rights_decision(
                    &operation,
                    2,
                    RightsDecisionV1::Allowed,
                ))
                .unwrap(),
            ),
        ]);
        let r3 = FakeRightsProvider::new(vec![
            Ok(
                RightsProviderResponseV1::new_decision(&signed_node_rights_decision(
                    &operation,
                    3,
                    RightsDecisionV1::Allowed,
                ))
                .unwrap(),
            ),
            Ok(
                RightsProviderResponseV1::new_decision(&signed_node_rights_decision(
                    &operation,
                    3,
                    RightsDecisionV1::Allowed,
                ))
                .unwrap(),
            ),
        ]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
            &signed_node_contribution(&operation, 2),
        )
        .unwrap())]);
        let c3 = FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
            &signed_node_contribution(&operation, 3),
        )
        .unwrap())]);
        let runtime = coordinator(
            &root,
            vec![
                selected(&r1, &c1, 1),
                selected(&r2, &c2, 2),
                selected(&r3, &c3, 3),
            ],
        );

        let first = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let operation_hash = match first {
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                operation_hash,
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
            } => operation_hash,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let resumed = runtime.resume_exact(operation_hash, NOW + 6).await.unwrap();
        match resumed {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected resumed outcome: {other:?}"),
        }
        let persisted = RuntimeReleaseJournal::new(root)
            .load(operation_hash)
            .unwrap();
        assert!(matches!(
            persisted.terminal_result(),
            Some(RuntimeReleaseTerminalResult::ContributionsReady { .. })
        ));
        assert_eq!(c1.request_count(), 0);
        assert_eq!(c2.request_count(), 1);
        assert_eq!(c3.request_count(), 1);
    }

    #[tokio::test]
    async fn runtime_coordination_persists_replayable_rights_before_contribution_dispatch() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let draft = RuntimeReleaseOperationDraft::new(
            wallet_request.clone(),
            wallet_response.clone(),
            operation.clone().into(),
        )
        .unwrap();
        let operation_hash = draft.operation_hash().unwrap();
        let r1 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let r2 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1 = InspectingCustodyProvider::new(
            root.clone(),
            operation_hash,
            vec![Err(RuntimeProviderCallError::NoExactResult)],
        );
        let c2 = InspectingCustodyProvider::new(
            root.clone(),
            operation_hash,
            vec![Err(RuntimeProviderCallError::NoExactResult)],
        );
        let runtime = coordinator(
            &root,
            vec![
                RuntimeSelectedProvider::new(node_public_key(1), &r1, &c1),
                RuntimeSelectedProvider::new(node_public_key(2), &r2, &c2),
            ],
        );

        let first = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let operation_hash = match first {
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                operation_hash,
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
            } => operation_hash,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let persisted = RuntimeReleaseJournal::new(root.clone())
            .load(operation_hash)
            .unwrap();
        assert_eq!(persisted.replayable_rights_decisions().len(), 2);
        let observed_counts = [
            c1.observed_replayable_rights_counts(),
            c2.observed_replayable_rights_counts(),
        ]
        .concat();
        // Every custody node asked saw both decisions already persisted.
        assert_eq!(observed_counts, vec![2, 2]);
        assert_eq!(c1.request_count(), 1);
        assert_eq!(c2.request_count(), 1);

        let r1_resume = FakeRightsProvider::default();
        let r2_resume = FakeRightsProvider::default();
        let c1_resume = FakeCustodyProvider::new(vec![Ok(
            CustodyProviderResponseV1::new_contribution(&signed_node_contribution(&operation, 1))
                .unwrap(),
        )]);
        let c2_resume = FakeCustodyProvider::new(vec![Ok(
            CustodyProviderResponseV1::new_contribution(&signed_node_contribution(&operation, 2))
                .unwrap(),
        )]);
        let resumed_runtime = coordinator(
            &root,
            vec![
                selected(&r1_resume, &c1_resume, 1),
                selected(&r2_resume, &c2_resume, 2),
            ],
        );
        let resumed = resumed_runtime
            .resume_exact(operation_hash, NOW + 6)
            .await
            .unwrap();
        match resumed {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected resumed outcome: {other:?}"),
        }
        assert_eq!(r1_resume.request_count(), 0);
        assert_eq!(r2_resume.request_count(), 0);
        assert_eq!(c1_resume.request_count(), 1);
        assert_eq!(c2_resume.request_count(), 1);
    }

    #[tokio::test]
    async fn runtime_coordination_resume_exact_reloads_same_unresolved_operation_hash() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let r2 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);

        let first = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let operation_hash = match first {
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                operation_hash,
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
            } => operation_hash,
            other => panic!("unexpected first outcome: {other:?}"),
        };

        let r1_resume = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let r2_resume = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1_resume = FakeCustodyProvider::new(vec![Ok(
            CustodyProviderResponseV1::new_contribution(&signed_node_contribution(&operation, 1))
                .unwrap(),
        )]);
        let c2_resume = FakeCustodyProvider::new(vec![Ok(
            CustodyProviderResponseV1::new_contribution(&signed_node_contribution(&operation, 2))
                .unwrap(),
        )]);
        let resumed_runtime = coordinator(
            &root,
            vec![
                selected(&r1_resume, &c1_resume, 1),
                selected(&r2_resume, &c2_resume, 2),
            ],
        );
        let resumed = resumed_runtime
            .resume_exact(operation_hash, NOW + 6)
            .await
            .unwrap();
        match resumed {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected resumed outcome: {other:?}"),
        }
        assert_eq!(r1.request_count(), 1);
        assert_eq!(r2.request_count(), 1);
        assert_eq!(r1_resume.request_count(), 1);
        assert_eq!(r2_resume.request_count(), 1);
        assert_eq!(c1_resume.request_count(), 1);
        assert_eq!(c2_resume.request_count(), 1);
    }

    #[tokio::test]
    async fn runtime_coordination_resume_exact_rejects_mismatched_replay_and_keeps_obligation() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let other = signed_runtime_release_operation_for(0x43, 0x12, 7, 0x30);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let r2 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);

        let first = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let operation_hash = match first {
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                operation_hash,
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
            } => operation_hash,
            other => panic!("unexpected first outcome: {other:?}"),
        };

        let r1_resume = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let r2_resume = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1_resume = FakeCustodyProvider::new(vec![Ok(
            CustodyProviderResponseV1::new_contribution(&signed_node_contribution(&other, 1))
                .unwrap(),
        )]);
        let c2_resume = FakeCustodyProvider::new(vec![Ok(
            CustodyProviderResponseV1::new_contribution(&signed_node_contribution(&other, 2))
                .unwrap(),
        )]);
        let resumed_runtime = coordinator(
            &root,
            vec![
                selected(&r1_resume, &c1_resume, 1),
                selected(&r2_resume, &c2_resume, 2),
            ],
        );
        assert_eq!(
            resumed_runtime.resume_exact(operation_hash, NOW + 6).await,
            Err(RuntimeReleaseCoordinatorError::ProviderResult)
        );
        let persisted = RuntimeReleaseJournal::new(root)
            .load(operation_hash)
            .unwrap();
        assert!(persisted.provider_effect_started());
        assert!(persisted.terminal_result().is_none());
        assert_eq!(r1_resume.request_count(), 1);
        assert_eq!(r2_resume.request_count(), 1);
        assert_eq!(c1_resume.request_count() + c2_resume.request_count(), 1);
    }

    #[tokio::test]
    async fn runtime_coordination_rejects_wallet_operation_and_result_substitution() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let mut request: WalletProviderRequestV2 = serde_json::from_slice(&wallet_request).unwrap();
        if let WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            canonical_rights_request_hex,
            ..
        } = &mut request.operation
        {
            *canonical_rights_request_hex = hex::encode(
                signed_runtime_release_operation(0x43)
                    .statement()
                    .rights_request()
                    .request()
                    .canonical_bytes()
                    .unwrap(),
            );
        }
        request.request_sha256 = "0x".to_string();
        let other_wallet_request = serde_json::to_vec(&request).unwrap();
        let mut response: WalletProviderResponseV2 =
            serde_json::from_slice(&wallet_response).unwrap();
        response.request_id = "wallet-request:22222222222222222222222222222222".to_string();
        let other_wallet_response = serde_json::to_vec(&response).unwrap();
        let r1 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let runtime = coordinator(&owner_only_root(&temp), vec![selected(&r1, &c1, 1)]);

        assert_eq!(
            runtime
                .release(
                    &other_wallet_request,
                    &wallet_response,
                    operation.clone().into(),
                    NOW + 6
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        assert_eq!(
            runtime
                .release(
                    &wallet_request,
                    &other_wallet_response,
                    operation.into(),
                    NOW + 6
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        assert_eq!(r1.request_count(), 0);
        assert_eq!(c1.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_rejects_wrong_node_set_and_threshold_selection() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let wrong_node_runtime = coordinator(
            &owner_only_root(&temp),
            vec![RuntimeSelectedProvider::new(node_public_key(4), &r1, &c1)],
        );
        assert_eq!(
            wrong_node_runtime
                .release(
                    &wallet_request,
                    &wallet_response,
                    operation.clone().into(),
                    NOW + 6,
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::ProviderSelection)
        );
        let threshold_runtime = coordinator(&owner_only_root(&temp), vec![selected(&r1, &c1, 1)]);
        assert_eq!(
            threshold_runtime
                .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
                .await,
            Err(RuntimeReleaseCoordinatorError::ProviderSelection)
        );
        assert_eq!(r1.request_count(), 0);
        assert_eq!(c1.request_count(), 0);
    }

    #[tokio::test]
    async fn release_completes_with_one_unreachable_node() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        // Node 1 is the unreachable node: it errors on both evaluate_rights and
        // release_contribution.
        let r1 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let r2 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let r3 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 3, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1 = FakeCustodyProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let c2 = FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
            &signed_node_contribution(&operation, 2),
        )
        .unwrap())]);
        let c3 = FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
            &signed_node_contribution(&operation, 3),
        )
        .unwrap())]);
        let runtime = coordinator(
            &root,
            vec![
                selected(&r1, &c1, 1),
                selected(&r2, &c2, 2),
                selected(&r3, &c3, 3),
            ],
        );

        let operation_hash = RuntimeReleaseOperationDraft::new(
            wallet_request.clone(),
            wallet_response.clone(),
            operation.clone().into(),
        )
        .unwrap()
        .operation_hash()
        .unwrap();

        // The first dispatch passes over the dead node, asks the third node
        // in its place, and meets the threshold with nodes 2 and 3.
        let outcome = runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        match outcome {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(r1.request_count(), 1);
        assert_eq!(r2.request_count(), 1);
        assert_eq!(r3.request_count(), 1);
        assert_eq!(c2.request_count(), 1);
        assert_eq!(c3.request_count(), 1);
        // The dead node never contributed: it never obtained a rights
        // decision, so custody was never asked of it at all.
        assert_eq!(c1.request_count(), 0);
        let persisted = RuntimeReleaseJournal::new(root)
            .load(operation_hash)
            .unwrap();
        assert!(matches!(
            persisted.terminal_result(),
            Some(RuntimeReleaseTerminalResult::ContributionsReady { .. })
        ));
    }

    /// The incident this guards: two nodes each spent most of the release
    /// window on a slow read, one after the other, and the operation expired
    /// before the second answered. Asked together, they cost the slower one.
    #[tokio::test(start_paused = true)]
    async fn slow_nodes_are_asked_together_rather_than_one_after_another() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let (r1, r2, r3, c1, c2, c3) = provider_triplet(&operation);
        let delay = std::time::Duration::from_secs(20);
        let slow = [(&r1, &c1), (&r2, &c2), (&r3, &c3)].map(|(rights, custody)| SlowProvider {
            rights,
            custody,
            delay,
        });
        let runtime = coordinator(
            &owner_only_root(&temp),
            slow.iter()
                .zip(1u8..)
                .map(|(node, seed)| RuntimeSelectedProvider::new(node_public_key(seed), node, node))
                .collect(),
        );

        let started = tokio::time::Instant::now();
        let outcome = runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        match outcome {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected outcome: {other:?}"),
        }
        // One rights round and one contribution round, each as long as one
        // slow node; one after the other this took four delays.
        assert!(
            elapsed >= delay * 2 && elapsed < delay * 3,
            "release took {elapsed:?}"
        );
        // Asking together asked no more nodes than the threshold needs.
        assert_eq!(
            r1.request_count() + r2.request_count() + r3.request_count(),
            2
        );
        assert_eq!(
            c1.request_count() + c2.request_count() + c3.request_count(),
            2
        );
    }

    #[tokio::test]
    async fn custody_contribution_is_possibly_requested_only_once_rights_reach_the_threshold() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        // Rights short of the threshold: one node allows, the other is dead.
        let r1 = FakeRightsProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let r2 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);
        let short = match runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap()
        {
            RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } => operation_hash,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert_eq!(c1.request_count() + c2.request_count(), 0);
        assert!(!runtime.custody_contribution_possibly_requested(short));

        // Rights at the threshold, then a contribution without an exact
        // answer: custody may have acted.
        let other_temp = tempdir().unwrap();
        let other_root = owner_only_root(&other_temp);
        let (r1, r2, _, _, _, _) = provider_triplet(&operation);
        let c1 = FakeCustodyProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let c2 = FakeCustodyProvider::new(vec![Err(RuntimeProviderCallError::NoExactResult)]);
        let runtime = coordinator(
            &other_root,
            vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)],
        );
        let asked = match runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap()
        {
            RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } => operation_hash,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert!(c1.request_count() + c2.request_count() > 0);
        assert!(runtime.custody_contribution_possibly_requested(asked));

        // An operation this journal does not hold proves nothing.
        assert!(runtime.custody_contribution_possibly_requested(digest(0x99)));
    }

    #[tokio::test]
    async fn runtime_coordination_wrong_provider_result_stays_nonterminal() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let r2 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(
            &owner_only_root(&temp),
            vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)],
        );

        let outcome = runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                ..
            }
        ));
        assert_eq!(r1.request_count() + r2.request_count(), 1);
        assert_eq!(c1.request_count(), 0);
        assert_eq!(c2.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_rejects_mismatched_contribution_identity() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let r2 = FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
            &signed_node_rights_decision(&operation, 2, RightsDecisionV1::Allowed),
        )
        .unwrap())]);
        let c1 = FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
            &signed_node_contribution(&operation, 3),
        )
        .unwrap())]);
        let c2 = FakeCustodyProvider::new(vec![Ok(CustodyProviderResponseV1::new_contribution(
            &signed_node_contribution(&operation, 2),
        )
        .unwrap())]);
        let runtime = coordinator(
            &owner_only_root(&temp),
            vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)],
        );

        let outcome = runtime
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                ..
            }
        ));
        assert_eq!(c1.request_count(), 1);
        assert_eq!(c1.request_count() + c2.request_count(), 2);
    }

    #[test]
    fn runtime_coordination_uses_typed_requests_without_secret_or_topology_fields() {
        let operation = signed_runtime_release_operation(0x42);
        let rights_request =
            RightsProviderRequestV1::new_evaluate(node_public_key(1), &operation).unwrap();
        let decision = signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed);
        let custody_request =
            CustodyProviderRequestV1::new_release_contribution(&operation, &decision).unwrap();
        let surface = format!(
            "{}{}{:?}{:?}",
            rights_request.to_json_vec().unwrap().escape_ascii(),
            custody_request.to_json_vec().unwrap().escape_ascii(),
            RuntimeSelectedProvider::new(
                node_public_key(1),
                &FakeRightsProvider::default(),
                &FakeCustodyProvider::default(),
            ),
            RuntimeReleaseCoordinatorError::ProviderResult
        );
        for forbidden in [
            "CEK",
            "raw_share",
            "share_bytes",
            "provider_route",
            "endpoint",
            "host",
            "ip",
            "port",
            "Carrier",
            "http://",
            "https://",
        ] {
            assert!(
                !surface.contains(forbidden),
                "unexpected forbidden marker {forbidden}"
            );
        }

        let validated = ValidatedRightsProviderRequestV1::decode_and_validate_at(
            &rights_request.to_json_vec().unwrap(),
            NOW + 6,
        )
        .unwrap();
        assert_eq!(validated.selected_node_public_key(), node_public_key(1));

        let validated_custody = ValidatedCustodyProviderRequestV1::decode_and_validate_at(
            &custody_request.to_json_vec().unwrap(),
            runtime_issuer(0x42),
            node_public_key(1),
            NOW + 6,
        )
        .unwrap();
        assert_eq!(
            validated_custody
                .release_contribution()
                .unwrap()
                .selected_node_public_key(),
            node_public_key(1)
        );
        assert_eq!(
            CustodyProviderResponseV1::new_failure(
                validated_custody.release_contribution().unwrap(),
                ProviderFailureCodeV1::BackendUnavailable,
            )
            .unwrap()
            .status(),
            CustodyProviderResponseStatusV1::Failure
        );
    }

    #[tokio::test]
    async fn runtime_coordination_wallet_error_result_is_not_authority() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, _) = wallet_request_response(&operation);
        let request: WalletProviderRequestV2 = serde_json::from_slice(&wallet_request).unwrap();
        let response = WalletProviderResponseV2::for_request(
            &request,
            WalletResultV2::Error {
                code: "denied".to_string(),
                message: "user denied".to_string(),
            },
        );
        let r1 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let runtime = coordinator(&owner_only_root(&temp), vec![selected(&r1, &c1, 1)]);

        assert_eq!(
            runtime
                .release(
                    &wallet_request,
                    &serde_json::to_vec(&response).unwrap(),
                    operation.into(),
                    NOW + 6,
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        assert_eq!(r1.request_count(), 0);
        assert_eq!(c1.request_count(), 0);
    }

    #[tokio::test]
    async fn runtime_coordination_rejects_operation_substitution_before_dispatch() {
        let temp = tempdir().unwrap();
        let operation = signed_runtime_release_operation(0x42);
        let other = signed_runtime_release_operation(0x43);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let r1 = FakeRightsProvider::default();
        let r2 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(
            &owner_only_root(&temp),
            vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)],
        );

        assert_eq!(
            runtime
                .release(&wallet_request, &wallet_response, other.into(), NOW + 6)
                .await,
            Err(RuntimeReleaseCoordinatorError::OperationAuthority)
        );
        assert_eq!(r1.request_count(), 0);
        assert_eq!(c1.request_count(), 0);
    }

    fn persist_effect_started(
        root: &Path,
        operation: &SignedRuntimeReleaseOperationV1,
        wallet_request: &[u8],
        wallet_response: &[u8],
    ) -> Digest32 {
        let journal = RuntimeReleaseJournal::new(root.to_path_buf());
        let draft = RuntimeReleaseOperationDraft::new(
            wallet_request.to_vec(),
            wallet_response.to_vec(),
            operation.clone().into(),
        )
        .unwrap();
        journal.persist_before_provider_effect(&draft).unwrap();
        journal.mark_provider_effect_started(&draft).unwrap();
        draft.operation_hash().unwrap()
    }

    #[tokio::test]
    async fn runtime_reconcile_settles_exact_contributions_without_redispatch() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let operation_hash =
            persist_effect_started(&root, &operation, &wallet_request, &wallet_response);
        let r1 = FakeRightsProvider::default();
        let r2 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);
        let first = runtime
            .reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            )
            .unwrap();
        match &first {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => assert_eq!(signed_node_contributions.len(), 2),
            other => panic!("unexpected outcome: {other:?}"),
        }
        let replay = runtime
            .reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            )
            .unwrap();
        assert_eq!(replay, first);
        let r1_release = FakeRightsProvider::default();
        let r2_release = FakeRightsProvider::default();
        let c1_release = FakeCustodyProvider::default();
        let c2_release = FakeCustodyProvider::default();
        let runtime_release = coordinator(
            &root,
            vec![
                selected(&r1_release, &c1_release, 1),
                selected(&r2_release, &c2_release, 2),
            ],
        );
        let released = runtime_release
            .release(&wallet_request, &wallet_response, operation.into(), NOW + 6)
            .await
            .unwrap();
        assert_eq!(released, first);
        assert_eq!(r1.request_count(), 0);
        assert_eq!(c1.request_count(), 0);
        assert_eq!(r1_release.request_count(), 0);
        assert_eq!(c1_release.request_count(), 0);
        let record = RuntimeReleaseJournal::new(root)
            .load(operation_hash)
            .unwrap()
            .audit_record()
            .unwrap();
        assert_eq!(
            record.phase(),
            crate::RuntimeReleaseAuditPhase::TerminalContributionsReady {
                contribution_count: 2
            }
        );
        let reason = record.reason();
        for forbidden in [
            "CEK",
            "raw_share",
            "share_bytes",
            "provider_route",
            "endpoint",
            "host",
            "ip",
            "port",
            "127.0.0.1",
        ] {
            assert!(
                !reason.contains(forbidden),
                "unexpected forbidden marker {forbidden}"
            );
        }
    }

    #[test]
    fn runtime_reconcile_settles_rights_denial_without_custody() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let operation_hash =
            persist_effect_started(&root, &operation, &wallet_request, &wallet_response);
        let r1 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r1, &c1, 2)]);
        let outcome = runtime
            .reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::RightsDenied {
                    signed_node_rights_decision: Box::new(signed_node_rights_decision(
                        &operation,
                        1,
                        RightsDecisionV1::Denied,
                    )),
                },
                NOW + 6,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::RightsDenied { .. }
            )
        ));
        assert_eq!(c1.request_count(), 0);
    }

    #[test]
    fn runtime_reconcile_fails_closed_without_effect_and_on_wrong_identity() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let other = signed_runtime_release_operation(0x43);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let journal = RuntimeReleaseJournal::new(root.clone());
        let draft = RuntimeReleaseOperationDraft::new(
            wallet_request.clone(),
            wallet_response.clone(),
            operation.clone().into(),
        )
        .unwrap();
        journal.persist_before_provider_effect(&draft).unwrap();
        let r1 = FakeRightsProvider::default();
        let r2 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);
        let pending_hash = draft.operation_hash().unwrap();
        assert_eq!(
            runtime.reconcile(
                pending_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::Reconciliation)
        );
        assert!(journal
            .load(pending_hash)
            .unwrap()
            .terminal_result()
            .is_none());
        assert!(!journal
            .load(pending_hash)
            .unwrap()
            .provider_effect_started());

        let (other_request, other_response) = wallet_request_response(&other);
        let started_hash = persist_effect_started(&root, &other, &other_request, &other_response);
        let started_runtime =
            coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);
        assert_eq!(
            started_runtime.reconcile(
                started_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::OperationAuthority)
        );
        assert!(journal
            .load(started_hash)
            .unwrap()
            .terminal_result()
            .is_none());

        let operation_hash =
            persist_effect_started(&root, &operation, &wallet_request, &wallet_response);
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);
        assert_eq!(
            runtime.reconcile(
                Digest32::new([0x11; 32]),
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::Reconciliation)
        );
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![signed_node_contribution(&operation, 1)],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::ProviderResult)
        );
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 1),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::ProviderResult)
        );
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 4),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::ProviderResult)
        );
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::RightsDenied {
                    signed_node_rights_decision: Box::new(signed_node_rights_decision(
                        &operation,
                        1,
                        RightsDecisionV1::Allowed,
                    )),
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::ProviderResult)
        );
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 1_000,
            ),
            Err(RuntimeReleaseCoordinatorError::OperationAuthority)
        );
        let wrong_issuer = RuntimeReleaseCoordinator::new(
            RuntimeReleaseJournal::new(root.clone()),
            runtime_issuer(0x43),
            vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)],
        )
        .unwrap();
        assert_eq!(
            wrong_issuer.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::OperationAuthority)
        );
        assert!(journal
            .load(operation_hash)
            .unwrap()
            .terminal_result()
            .is_none());
        assert_eq!(r1.request_count(), 0);
        assert_eq!(c1.request_count(), 0);
    }

    #[test]
    fn runtime_reconcile_rejects_conflicting_terminal_offer() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let operation_hash =
            persist_effect_started(&root, &operation, &wallet_request, &wallet_response);
        let r1 = FakeRightsProvider::default();
        let r2 = FakeRightsProvider::default();
        let c1 = FakeCustodyProvider::default();
        let c2 = FakeCustodyProvider::default();
        let runtime = coordinator(&root, vec![selected(&r1, &c1, 1), selected(&r2, &c2, 2)]);
        runtime
            .reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::RightsDenied {
                    signed_node_rights_decision: Box::new(signed_node_rights_decision(
                        &operation,
                        1,
                        RightsDecisionV1::Denied,
                    )),
                },
                NOW + 6,
            )
            .unwrap();
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::Reconciliation)
        );
    }
    fn mint_nodes() -> Vec<RuntimeMintNodeBinding> {
        [1u8, 2, 3]
            .into_iter()
            .map(|seed| {
                RuntimeMintNodeBinding::new(
                    node_public_key(seed),
                    CustodyPoolOperatorIdV1::new([0x80 + seed; 32]),
                    CustodyPoolFailureDomainIdV1::new([0x90 + seed; 32]),
                    digest(0xa0 + seed),
                )
                .unwrap()
            })
            .collect()
    }

    fn custody_provisioned_mint_matching(
        operation: &SignedRuntimeReleaseOperationV1,
    ) -> (tempfile::TempDir, crate::PersistedRuntimeMint) {
        let temp = tempdir().unwrap();
        let parent = temp.path().join("owner-only-mint-parent");
        create_owner_only_directory(&parent);
        let journal = RuntimeMintJournal::new(parent.join("runtime-mint"));
        let binding = operation.statement().rights_request().request().binding();
        let (init_segment, encrypted_segments, mime_type, codecs) =
            test_media::media_components(0x11);
        let draft = RuntimeMintDraft::new(
            &init_segment,
            &encrypted_segments,
            mime_type,
            codecs,
            content_access_id(0x41),
            binding.key_envelope().clone(),
            binding.rights_policy().clone(),
            digest(0x19),
            ThresholdV1::new(2, 3).unwrap(),
            mint_nodes(),
        )
        .unwrap();
        journal.persist_bound(&draft).unwrap();
        for (index, node) in draft.nodes().iter().enumerate() {
            journal
                .mark_node_effect_started(draft.mint_id(), node.node_public_key())
                .unwrap();
            journal
                .mark_node_receipt(
                    draft.mint_id(),
                    RuntimeMintNodeReceipt::new(
                        node.node_public_key(),
                        RuntimeCustodyProvisioningIdV1::new(digest(0x80 + index as u8)).unwrap(),
                        CustodyNodeProvisioningRecordIdentityV1::new(
                            digest(0xa1 + index as u8),
                            128,
                        )
                        .unwrap(),
                        node.owner_state_root(),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let provisioned = journal.mark_custody_provisioned(draft.mint_id()).unwrap();
        (temp, provisioned)
    }

    fn purchase_effect_for_wallet(
        mint: &crate::PersistedRuntimeMint,
        operation: &SignedRuntimeReleaseOperationV1,
    ) -> RuntimeVerifiedPurchaseEffect {
        purchase_effect_for_account(
            mint,
            operation,
            "profile:alpha",
            "wallet-account-alpha",
            "wallet-request:11111111111111111111111111111111",
            0xaa,
        )
    }

    fn purchase_effect_for_account(
        mint: &crate::PersistedRuntimeMint,
        operation: &SignedRuntimeReleaseOperationV1,
        principal_id: &str,
        account_id: &str,
        approval_request_id: &str,
        tx_byte: u8,
    ) -> RuntimeVerifiedPurchaseEffect {
        let rights_request = operation.statement().rights_request().request();
        RuntimeVerifiedPurchaseEffect::new(
            RuntimeProtectedContentPurchaseIntent::new(
                mint.draft().mint_id(),
                mint.draft().encrypted_content().clone(),
                mint.draft().key_envelope().clone(),
                mint.draft().policy().clone(),
                rights_request.action(),
                "eip155:20",
                "esc-mainnet",
                "0x2222222222222222222222222222222222222222",
                "0x1",
                "0x",
            )
            .unwrap(),
            RuntimePurchaseEffectAuthority::new(
                principal_id,
                account_id,
                wallet_address_hex(rights_request.binding().wallet()),
                approval_request_id,
            )
            .unwrap(),
            ValidatedChainOutcomeBindingV1::ManagedSigned {
                signed_transaction_sha256: format!("sha256:{}", hex::encode([tx_byte ^ 1; 32])),
            },
            format!("0x{}", hex::encode([tx_byte; 32])),
            json!({
                "schema": "elastos.chain.broadcast_receipt/v1",
                "network": "esc-mainnet",
            }),
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn custody_provisioned_mint_rejects_buy_pending_content_availability_receipt() {
        let operation = signed_runtime_release_operation(0x42);
        let (_mint_temp, provisioned) = custody_provisioned_mint_matching(&operation);
        assert_eq!(
            bind_buy(
                &provisioned,
                "profile:alpha",
                profile_identity(0x26),
                &purchase_effect_for_wallet(&provisioned, &operation),
            ),
            Err(RuntimeOpenError::MintSelection)
        );
    }

    struct FakeMintCustody {
        expected_issuer: RuntimeOperationIssuerKeyV1,
        node: NodePublicKey,
        now: u64,
        journal_root: PathBuf,
        mint_id: Digest32,
        requests: Mutex<Vec<CustodyProviderRequestV1>>,
    }

    impl FakeMintCustody {
        fn new(node: NodePublicKey, journal_root: PathBuf, mint_id: Digest32) -> Self {
            Self {
                expected_issuer: runtime_issuer(0x42),
                node,
                now: NOW + 10,
                journal_root,
                mint_id,
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl RuntimeCustodyProvider for FakeMintCustody {
        async fn release_contribution(
            &self,
            _request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }

        async fn provision_node_share(
            &self,
            request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            let record_path = self.journal_root.join(hex::encode(self.mint_id.as_bytes()));
            if !record_path.exists() {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            self.requests.lock().unwrap().push(request.clone());
            let bytes = request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            let validated = ValidatedCustodyProviderRequestV1::decode_and_validate_at(
                &bytes,
                self.expected_issuer,
                self.node,
                self.now,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            let provision = validated
                .provision_node_share()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            CustodyProviderResponseV1::new_provisioned(provision)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)
        }

        async fn release_pool_contribution(
            &self,
            _request: &PoolCustodyRequestV1,
        ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }
    }

    fn sign_mint_statement(bytes: &[u8]) -> [u8; 64] {
        runtime_key(0x42).sign(bytes).to_bytes()
    }

    async fn provision_custody_provisioned_mint(
        operation: &SignedRuntimeReleaseOperationV1,
        envelope: &CustodyEnvelopeV1,
    ) -> (tempfile::TempDir, crate::PersistedRuntimeMint, PathBuf) {
        let temp = tempdir().unwrap();
        let parent = temp.path().join("owner-only-mint-parent");
        create_owner_only_directory(&parent);
        let root = parent.join("runtime-mint");
        let journal = RuntimeMintJournal::new(&root);
        let binding = operation.statement().rights_request().request().binding();
        let (init_segment, encrypted_segments, mime_type, codecs) =
            test_media::media_components(0x11);
        let draft = RuntimeMintDraft::new(
            &init_segment,
            &encrypted_segments,
            mime_type,
            codecs,
            content_access_id(0x41),
            binding.key_envelope().clone(),
            binding.rights_policy().clone(),
            envelope.manifest().content_key_commitment(),
            envelope.manifest().threshold(),
            mint_nodes(),
        )
        .unwrap();
        let c1 = FakeMintCustody::new(node_public_key(1), root.clone(), draft.mint_id());
        let c2 = FakeMintCustody::new(node_public_key(2), root.clone(), draft.mint_id());
        let c3 = FakeMintCustody::new(node_public_key(3), root.clone(), draft.mint_id());
        let mint = RuntimeMintCoordinator::new(
            journal,
            runtime_issuer(0x42),
            sign_mint_statement,
            vec![
                RuntimeMintSelectedNode::new(mint_nodes()[0].clone(), &c1),
                RuntimeMintSelectedNode::new(mint_nodes()[1].clone(), &c2),
                RuntimeMintSelectedNode::new(mint_nodes()[2].clone(), &c3),
            ],
        )
        .unwrap();
        assert_eq!(
            mint.provision(&draft, envelope, NOW + 10).await.unwrap(),
            RuntimeMintCoordinatorOutcome::CustodyProvisioned {
                mint_id: draft.mint_id(),
            }
        );
        assert_eq!(c1.request_count(), 1);
        assert_eq!(c2.request_count(), 1);
        assert_eq!(c3.request_count(), 1);
        let provisioned = RuntimeMintJournal::new(&root)
            .load(draft.mint_id())
            .unwrap();
        assert_eq!(
            provisioned.custody_terminal(),
            Some(crate::RuntimeCustodyTerminalKind::CustodyProvisioned)
        );
        (temp, provisioned, root)
    }

    fn content_availability_requirement() -> RuntimeContentAvailabilityRequirement {
        RuntimeContentAvailabilityRequirement::new(
            "did:elastos:content-provider-alpha",
            "did:elastos:protected-content-object-alpha",
            "did:elastos:protected-content-publisher-alpha",
            "protected-content-replication/v1",
            3,
            300,
            30,
        )
        .unwrap()
    }

    fn verified_content_availability(
        mint: &crate::PersistedRuntimeMint,
    ) -> RuntimeVerifiedContentAvailability {
        RuntimeVerifiedContentAvailability::new(
            "bafybeiprotectedcontentavailability",
            "did:elastos:protected-content-object-alpha",
            "did:elastos:protected-content-publisher-alpha",
            &content_availability_requirement(),
            3,
            NOW + 11,
            digest(0x7e),
            mint.draft().encrypted_content().clone(),
            RuntimeVerifiedContentIdentityRootV1::for_media(mint.draft().media_identity().unwrap()),
        )
        .unwrap()
    }

    fn opaque_handle(seed: u8) -> [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] {
        let mut handle = [0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
        handle[0] = seed.max(1);
        handle[MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1 - 1] = seed ^ 0x5a;
        handle
    }

    fn signed_terminal_receipt(
        operation: &SignedRuntimeReleaseOperationV1,
        contributions: &[SignedNodeContributionV1],
        issuer_seed: u8,
    ) -> SignedTerminalReceiptV1 {
        let authenticated = operation
            .verify(operation.statement().runtime_operation_issuer(), NOW + 6)
            .unwrap();
        let node_set = signed_custody_epoch().statement().node_set().unwrap();
        let verified = contributions
            .iter()
            .map(|contribution| {
                authenticated
                    .verify_node_contribution(contribution, &node_set, NOW + 6)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let refs = verified
            .iter()
            .map(NodeContributionRefV1::from)
            .collect::<Vec<_>>();
        let issuer = SigningKey::from_bytes(&[issuer_seed; 32]);
        let statement = TerminalReceiptStatementV1::new(
            authenticated.release_request_hash(),
            authenticated.binding().clone(),
            TerminalReceiptIssuerKey::new(issuer.verifying_key().to_bytes()).unwrap(),
            KeyReleaseOutcomeV1::Released,
            refs,
            NOW + 6,
            NOW + 35,
        )
        .unwrap();
        SignedTerminalReceiptV1::new(
            statement.clone(),
            issuer
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    struct FakeCompositeDecryptProvider {
        expected_issuer: RuntimeOperationIssuerKeyV1,
        recipient_public_key: RecipientPublicKeyBytesV1,
        recipient_identity: RecipientKeyIdentityV1,
        prepared_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        clear_init: Vec<u8>,
        clear_segment: Vec<u8>,
        requests: Mutex<Vec<DecryptProviderRequestV1>>,
    }

    impl FakeCompositeDecryptProvider {
        fn new(operation: &SignedRuntimeReleaseOperationV1) -> Self {
            Self {
                expected_issuer: operation.statement().runtime_operation_issuer(),
                recipient_public_key: operation.statement().recipient_public_key(),
                recipient_identity: operation
                    .statement()
                    .recipient_authorization()
                    .statement()
                    .recipient_identity()
                    .clone(),
                prepared_handle: opaque_handle(0x41),
                clear_init: b"clear-fmp4-init".to_vec(),
                clear_segment: b"clear-fmp4-segment".to_vec(),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn validate(
            &self,
            request: &DecryptProviderRequestV1,
        ) -> Result<ValidatedDecryptProviderRequestV1, RuntimeProviderCallError> {
            let bytes = request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            let validated = ValidatedDecryptProviderRequestV1::decode_and_validate_at(
                &bytes,
                self.expected_issuer,
                NOW + 10,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            self.requests.lock().unwrap().push(request.clone());
            Ok(validated)
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl RuntimeDecryptProvider for FakeCompositeDecryptProvider {
        async fn prepare_recipient(
            &self,
            request: &DecryptProviderRequestV1,
        ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
            let validated = self.validate(request)?;
            DecryptProviderResponseV1::new_prepared_recipient(
                validated.audit_request_id(),
                self.prepared_handle,
                self.recipient_public_key,
                &self.recipient_identity,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)
        }

        async fn open_viewer_session(
            &self,
            request: &DecryptProviderRequestV1,
        ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
            let validated = self.validate(request)?;
            if validated
                .prepared_recipient_handle()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?
                != &self.prepared_handle
            {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            DecryptProviderResponseV1::new_viewer_session_opened(
                validated.audit_request_id(),
                self.prepared_handle,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)
        }

        async fn read_viewer_media_part(
            &self,
            request: &DecryptProviderRequestV1,
        ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
            let validated = self.validate(request)?;
            if validated
                .viewer_session_handle()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?
                != &self.prepared_handle
            {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            let selector = validated
                .viewer_media_part_selector()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            let clear = if selector.is_init() {
                self.clear_init.clone()
            } else if selector.segment_index() == Some(0) {
                self.clear_segment.clone()
            } else {
                return Err(RuntimeProviderCallError::NoExactResult);
            };
            DecryptProviderResponseV1::new_viewer_media_part(
                validated.audit_request_id(),
                self.prepared_handle,
                selector.clone(),
                clear,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)
        }

        async fn cancel_prepared_recipient(
            &self,
            request: &DecryptProviderRequestV1,
        ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
            let validated = self.validate(request)?;
            DecryptProviderResponseV1::new_prepared_recipient_already_absent(
                validated.audit_request_id(),
                *validated
                    .prepared_recipient_handle()
                    .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)
        }

        async fn close_viewer_session(
            &self,
            request: &DecryptProviderRequestV1,
        ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
            let validated = self.validate(request)?;
            if validated
                .viewer_session_handle()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?
                != &self.prepared_handle
            {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            DecryptProviderResponseV1::new_closed_viewer_session(
                validated.audit_request_id(),
                self.prepared_handle,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)
        }

        // This fake is media-only (see the hardcoded `clear_init`/`clear_segment`
        // fields above); no test in this module exercises the object viewer
        // path, so this arm fails closed rather than fabricating a plaintext
        // chunk response.
        async fn read_viewer_object_chunk(
            &self,
            _request: &DecryptProviderRequestV1,
        ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }
    }

    #[tokio::test]
    async fn inactive_two_principals_mint_verified_availability_buy_open_play_and_close() {
        let envelope = custody_envelope(0x11);
        let allowed = signed_runtime_release_operation_for(0x42, 0x11, 7, 0x30);
        let (_mint_temp, provisioned, mint_root) =
            provision_custody_provisioned_mint(&allowed, &envelope).await;
        let availability = verified_content_availability(&provisioned);
        let available = RuntimeMintJournal::new(&mint_root)
            .mark_content_available(
                provisioned.draft().mint_id(),
                &content_availability_requirement(),
                availability.clone(),
            )
            .unwrap();
        assert_eq!(available.content_availability(), Some(&availability));
        assert_eq!(
            RuntimeMintJournal::new(&mint_root)
                .mark_content_available(
                    provisioned.draft().mint_id(),
                    &content_availability_requirement(),
                    availability,
                )
                .unwrap(),
            available
        );

        let effect_a = purchase_effect_for_account(
            &available,
            &allowed,
            "profile:alpha",
            "wallet-account-alpha",
            "wallet-request:11111111111111111111111111111111",
            0xaa,
        );
        let buy = bind_buy(
            &available,
            "profile:alpha",
            profile_identity(0x26),
            &effect_a,
        )
        .unwrap();
        assert_eq!(
            bind_buy(
                &available,
                "profile:alpha",
                profile_identity(0x26),
                &effect_a
            )
            .unwrap(),
            buy
        );
        assert_eq!(
            bind_buy(
                &available,
                "profile:beta",
                profile_identity(0x26),
                &effect_a,
            ),
            Err(RuntimeOpenError::ChainEvidence)
        );

        let decrypt = FakeCompositeDecryptProvider::new(&allowed);
        let prepared = prepare_recipient(
            &decrypt,
            &buy,
            allowed
                .statement()
                .rights_request()
                .request()
                .binding()
                .runtime_session_binding(),
            allowed.statement().audit_request_id(),
            allowed.statement().runtime_operation_issuer(),
            NOW + 10,
            NOW + 40,
        )
        .await
        .unwrap();
        let (protected_init, encrypted_segments, _, _) = test_media::media_components(0x11);
        let contributions = vec![
            signed_node_contribution(&allowed, 1),
            signed_node_contribution(&allowed, 2),
        ];
        let terminal = signed_terminal_receipt(&allowed, &contributions, 0x63);
        let session = open_viewer_session(
            &decrypt,
            &RuntimeOpenViewerSessionInput {
                buy: &buy,
                prepared_recipient: &prepared,
                signed_runtime_release_operation: &allowed,
                expected_terminal_issuer: terminal.statement().issuer(),
                content_key_commitment: envelope.manifest().content_key_commitment(),
                content: RuntimeOpenViewerContentV1::Media {
                    media_identity: available.draft().media_identity().unwrap(),
                    protected_init_segment: &protected_init,
                },
                signed_node_contributions: &contributions,
                signed_terminal_receipt: &terminal,
                now_unix_seconds: NOW + 10,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            session.viewer_session_handle(),
            prepared.prepared_recipient_handle()
        );
        let init = read_viewer_media_part(
            &decrypt,
            &session,
            ViewerMediaPartSelectorV1::init(),
            NOW + 11,
        )
        .await
        .unwrap();
        let segment_selector =
            ViewerMediaPartSelectorV1::segment(0, encrypted_segments[0].clone()).unwrap();
        let segment =
            read_viewer_media_part(&decrypt, &session, segment_selector.clone(), NOW + 11)
                .await
                .unwrap();
        assert_eq!(init.audit_request_id(), session.audit_request_id());
        assert_eq!(
            init.viewer_session_handle(),
            session.viewer_session_handle()
        );
        assert_eq!(init.part_selector(), &ViewerMediaPartSelectorV1::init());
        assert_eq!(init.clear_media_part(), b"clear-fmp4-init");
        assert_eq!(segment.audit_request_id(), session.audit_request_id());
        assert_eq!(
            segment.viewer_session_handle(),
            session.viewer_session_handle()
        );
        assert_eq!(segment.part_selector(), &segment_selector);
        assert_eq!(segment.clear_media_part(), b"clear-fmp4-segment");
        assert_eq!(
            segment_selector.encrypted_segment(),
            Some(encrypted_segments[0].as_slice())
        );
        close_viewer_session(&decrypt, &session).await.unwrap();
        close_viewer_session(&decrypt, &session).await.unwrap();
        assert_eq!(decrypt.request_count(), 6);
    }

    // -----------------------------------------------------------------
    // Plan B T4.1: V2 (pool) releases through the same coordinator and
    // journal. Fixtures: the contracts' pool release (nodes 1-3, 2-of-3,
    // Runtime 0x43), two recipients served by nodes 1 and 2, a descriptor
    // that allows two servers per session (rev 3 F5).
    // -----------------------------------------------------------------

    use elastos_protected_content_contracts::test_fixtures as pool_fixtures;
    use elastos_protected_content_provider_contracts::ValidatedPoolCustodyRequestV1;

    const POOL_RUNTIME_SEED: u8 = 0x43;

    fn pool_release_with(
        recipients: usize,
        replay_nonce: u8,
    ) -> pool_fixtures::PoolReleaseFixtureV1 {
        let mut spec =
            pool_fixtures::PoolReleaseSpecV1::new(xwing_public_key_bytes, policy_body(), NOW);
        spec.recipients = [(9, 1), (10, 2)][..recipients].to_vec();
        spec.max_servers_per_session = 2;
        spec.replay_nonce = replay_nonce;
        pool_fixtures::pool_release_fixture(&spec)
    }

    fn pool_release() -> pool_fixtures::PoolReleaseFixtureV1 {
        pool_release_with(2, 0x55)
    }

    fn pool_authenticated(
        operation: &SignedRuntimeReleaseOperationV2,
    ) -> AuthenticatedRuntimeReleaseOperationV2 {
        operation
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
            .unwrap()
    }

    fn pool_node_set(operation: &AuthenticatedRuntimeReleaseOperationV2) -> NodeSetV1 {
        operation
            .epoch_bundle()
            .signed_epoch()
            .statement()
            .node_set()
            .unwrap()
    }

    /// Nodes 1 and 2 in node-set order, which sorts by key, not by seed.
    fn pool_node_order(operation: &AuthenticatedRuntimeReleaseOperationV2) -> (u8, u8) {
        let node_set = pool_node_set(operation);
        let position = |seed| {
            node_set
                .members()
                .iter()
                .position(|member| *member == node_public_key(seed))
                .unwrap()
        };
        if position(1) < position(2) {
            (1, 2)
        } else {
            (2, 1)
        }
    }

    fn pool_recipients(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
    ) -> Vec<RecipientKeyIdentityV1> {
        operation
            .statement()
            .rights_request()
            .request()
            .recipients()
            .to_vec()
    }

    fn pool_wallet_bytes(operation: &SignedRuntimeReleaseOperationV2) -> (Vec<u8>, Vec<u8>) {
        let signed = operation.statement().rights_request();
        let (request, response) = wallet_request_response_v2(signed.request(), signed);
        (
            serde_json::to_vec(&request).unwrap(),
            serde_json::to_vec(&response).unwrap(),
        )
    }

    fn pool_decision(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        node_seed: u8,
    ) -> SignedNodeRightsDecisionV1 {
        pool_decision_at(operation, node_seed, NOW)
    }

    /// A node's decision whose window starts at `base + 3`.
    fn pool_decision_at(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        node_seed: u8,
        base: u64,
    ) -> SignedNodeRightsDecisionV1 {
        pool_fixtures::signed_node_rights_decision(
            operation,
            node_seed,
            RightsDecisionV1::Allowed,
            base,
        )
    }

    /// One node's contribution, sealed to `recipient`.
    fn pool_contribution(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        decision: &SignedNodeRightsDecisionV1,
        recipient: &RecipientKeyIdentityV1,
        node_seed: u8,
    ) -> SignedNodeContributionV1 {
        pool_contribution_at(operation, decision, recipient, node_seed, NOW)
    }

    /// One node's contribution whose window is `base + 5 .. base + 30`.
    fn pool_contribution_at(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        decision: &SignedNodeRightsDecisionV1,
        recipient: &RecipientKeyIdentityV1,
        node_seed: u8,
        base: u64,
    ) -> SignedNodeContributionV1 {
        let statement = NodeContributionStatementV1::new(
            operation.operation_hash(),
            operation.binding().clone(),
            decision.clone(),
            RecipientSealedContributionV1::new(recipient.clone(), vec![node_seed; 96]).unwrap(),
            base + 5,
            base + 30,
        )
        .unwrap();
        SignedNodeContributionV1::new(
            statement.clone(),
            node_key(node_seed)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PoolCustodyMode {
        /// One contribution per signed recipient.
        Honest,
        /// No exact answer.
        Unreachable,
        /// Only the first recipient's contribution.
        OneRecipientOnly,
        /// The first contribution is sealed to a recipient nobody signed.
        UnknownRecipient,
    }

    /// A custody node answering `release_pool_contribution` as a real node
    /// would: it validates the request, then signs one contribution per
    /// recipient (or the mode's deviation).
    struct FakePoolCustody {
        node_seed: u8,
        mode: PoolCustodyMode,
        /// The node's clock is `base + 6`; its contributions start at
        /// `base + 5`.
        base: u64,
        requests: Mutex<usize>,
    }

    impl FakePoolCustody {
        fn at(node_seed: u8, mode: PoolCustodyMode, base: u64) -> Self {
            Self {
                node_seed,
                mode,
                base,
                requests: Mutex::new(0),
            }
        }

        fn request_count(&self) -> usize {
            *self.requests.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl RuntimeCustodyProvider for FakePoolCustody {
        async fn release_contribution(
            &self,
            _request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }

        async fn provision_node_share(
            &self,
            _request: &CustodyProviderRequestV1,
        ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
            Err(RuntimeProviderCallError::NoExactResult)
        }

        async fn release_pool_contribution(
            &self,
            request: &PoolCustodyRequestV1,
        ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
            *self.requests.lock().unwrap() += 1;
            if self.mode == PoolCustodyMode::Unreachable {
                return Err(RuntimeProviderCallError::NoExactResult);
            }
            let validated = ValidatedPoolCustodyRequestV1::decode_and_validate_at(
                &request.to_json_vec().unwrap(),
                node_public_key(self.node_seed),
                self.base + 6,
            )
            .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
            let release = validated.release_pool_contribution().unwrap();
            let operation = release.authenticated_runtime_release_operation();
            let decision = release.signed_node_rights_decision();
            let mut recipients = pool_recipients(operation);
            match self.mode {
                PoolCustodyMode::OneRecipientOnly => recipients.truncate(1),
                PoolCustodyMode::UnknownRecipient => recipients[0] = recipient_identity(0x77),
                PoolCustodyMode::Honest | PoolCustodyMode::Unreachable => {}
            }
            let contributions = recipients
                .iter()
                .map(|recipient| {
                    pool_contribution_at(operation, decision, recipient, self.node_seed, self.base)
                })
                .collect::<Vec<_>>();
            Ok(PoolCustodyResponseV1::new_pool_contributions(&validated, &contributions).unwrap())
        }
    }

    /// The three pool nodes: each answers its rights call once.
    struct PoolNodes {
        rights: [FakeRightsProvider; 3],
        custody: [FakePoolCustody; 3],
    }

    fn pool_nodes(operation: &SignedRuntimeReleaseOperationV2, mode: PoolCustodyMode) -> PoolNodes {
        pool_nodes_at(operation, mode, NOW)
    }

    /// The three pool nodes with their clocks at `base` (decisions from
    /// `base + 3`, custody at `base + 6`).
    fn pool_nodes_at(
        operation: &SignedRuntimeReleaseOperationV2,
        mode: PoolCustodyMode,
        base: u64,
    ) -> PoolNodes {
        let authenticated = operation
            .verify(RuntimeIssuerPolicyV1::Declared, base + 3)
            .unwrap();
        let rights = |node: u8| {
            FakeRightsProvider::new(vec![Ok(RightsProviderResponseV1::new_decision(
                &pool_decision_at(&authenticated, node, base),
            )
            .unwrap())])
        };
        PoolNodes {
            rights: [rights(1), rights(2), rights(3)],
            custody: [
                FakePoolCustody::at(1, mode, base),
                FakePoolCustody::at(2, mode, base),
                FakePoolCustody::at(3, mode, base),
            ],
        }
    }

    /// Nodes that must not be asked anything (a resume after restart).
    fn silent_pool_nodes(mode: PoolCustodyMode) -> PoolNodes {
        silent_pool_nodes_at(mode, NOW)
    }

    fn silent_pool_nodes_at(mode: PoolCustodyMode, base: u64) -> PoolNodes {
        PoolNodes {
            rights: [
                FakeRightsProvider::default(),
                FakeRightsProvider::default(),
                FakeRightsProvider::default(),
            ],
            custody: [
                FakePoolCustody::at(1, mode, base),
                FakePoolCustody::at(2, mode, base),
                FakePoolCustody::at(3, mode, base),
            ],
        }
    }

    fn pool_coordinator<'a>(root: &Path, nodes: &'a PoolNodes) -> RuntimeReleaseCoordinator<'a> {
        pool_coordinator_for(
            root,
            nodes,
            pool_fixtures::runtime_issuer(POOL_RUNTIME_SEED),
        )
    }

    fn pool_coordinator_for<'a>(
        root: &Path,
        nodes: &'a PoolNodes,
        own_issuer: RuntimeOperationIssuerKeyV1,
    ) -> RuntimeReleaseCoordinator<'a> {
        RuntimeReleaseCoordinator::new(
            RuntimeReleaseJournal::new(root.to_path_buf()),
            own_issuer,
            (0..3)
                .map(|index| {
                    RuntimeSelectedProvider::new(
                        node_public_key(index as u8 + 1),
                        &nodes.rights[index],
                        &nodes.custody[index],
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    /// The exact V2 terminal set: nodes 1 and 2, each for both recipients.
    fn pool_contribution_set(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        pairs: &[(u8, RecipientKeyIdentityV1)],
    ) -> Vec<SignedNodeContributionV1> {
        pairs
            .iter()
            .map(|(node, recipient)| {
                pool_contribution(
                    operation,
                    &pool_decision(operation, *node),
                    recipient,
                    *node,
                )
            })
            .collect()
    }

    fn contributions_of(
        outcome: RuntimeReleaseCoordinatorOutcome,
    ) -> Vec<SignedNodeContributionV1> {
        match outcome {
            RuntimeReleaseCoordinatorOutcome::Terminal(
                RuntimeReleaseTerminalResult::ContributionsReady {
                    signed_node_contributions,
                },
            ) => signed_node_contributions,
            other => panic!("expected contributions, got {other:?}"),
        }
    }

    fn assert_pool_pairs(
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        contributions: &[SignedNodeContributionV1],
        expected: &[(u8, RecipientKeyIdentityV1)],
    ) {
        let node_set = pool_node_set(operation);
        assert_eq!(contributions.len(), expected.len());
        for (contribution, (node, recipient)) in contributions.iter().zip(expected) {
            let verified = operation
                .verify_node_contribution(contribution, &node_set, recipient, NOW + 6)
                .unwrap();
            assert_eq!(verified.node_public_key(), node_public_key(*node));
            assert_eq!(verified.recipient(), recipient);
        }
    }

    #[tokio::test]
    async fn v2_release_collects_contributions_for_every_recipient() {
        let temp = tempdir().unwrap();
        let fixture = pool_release();
        let authenticated = pool_authenticated(&fixture.operation);
        let recipients = pool_recipients(&authenticated);
        assert_eq!(recipients.len(), 2);
        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Honest);
        let runtime = pool_coordinator(&owner_only_root(&temp), &nodes);
        let (wallet_request, wallet_response) = pool_wallet_bytes(&fixture.operation);

        let contributions = contributions_of(
            runtime
                .release(
                    &wallet_request,
                    &wallet_response,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await
                .unwrap(),
        );
        // `required` (2) distinct nodes x every recipient, node-set order
        // then recipient order (S4-Q5).
        let (a, b) = pool_node_order(&authenticated);
        assert_pool_pairs(
            &authenticated,
            &contributions,
            &[
                (a, recipients[0].clone()),
                (a, recipients[1].clone()),
                (b, recipients[0].clone()),
                (b, recipients[1].clone()),
            ],
        );
        assert_eq!(nodes.rights[0].request_count(), 1);
        assert_eq!(nodes.rights[1].request_count(), 1);
        assert_eq!(nodes.rights[2].request_count(), 0);
        assert_eq!(nodes.custody[0].request_count(), 1);
        assert_eq!(nodes.custody[1].request_count(), 1);
        assert_eq!(nodes.custody[2].request_count(), 0);
    }

    #[tokio::test]
    async fn v2_resume_exact_after_restart() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let fixture = pool_release();
        let journal_key = RuntimeReleaseOperationAnyV1::V2(fixture.operation.clone())
            .journal_key()
            .unwrap();
        let (wallet_request, wallet_response) = pool_wallet_bytes(&fixture.operation);
        {
            // Rights are decided, then every custody call is lost.
            let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Unreachable);
            let runtime = pool_coordinator(&root, &nodes);
            let outcome = runtime
                .release(
                    &wallet_request,
                    &wallet_response,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await
                .unwrap();
            assert_eq!(
                outcome,
                RuntimeReleaseCoordinatorOutcome::Nonterminal {
                    operation_hash: journal_key,
                    reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                }
            );
            assert!(runtime.custody_contribution_possibly_requested(journal_key));
        }

        // A new Runtime over the same journal resumes the exact operation
        // with the persisted decisions: no rights call is made again.
        let nodes = silent_pool_nodes(PoolCustodyMode::Honest);
        let runtime = pool_coordinator(&root, &nodes);
        let contributions =
            contributions_of(runtime.resume_exact(journal_key, NOW + 7).await.unwrap());
        assert_eq!(contributions.len(), 4);
        assert!(nodes
            .rights
            .iter()
            .all(|rights| rights.request_count() == 0));
        let persisted = RuntimeReleaseJournal::new(root).load(journal_key).unwrap();
        assert_eq!(
            persisted.draft().signed_runtime_release_operation(),
            &RuntimeReleaseOperationAnyV1::V2(fixture.operation)
        );
        assert_eq!(persisted.terminal_result().unwrap().contribution_count(), 4);
    }

    #[tokio::test]
    async fn v1_journal_records_still_reconcile() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let operation = signed_runtime_release_operation(0x42);
        let (wallet_request, wallet_response) = wallet_request_response(&operation);
        let (r1, r2, r3, _, _, _) = provider_triplet(&operation);
        let (c1, c2, c3) = (
            FakeCustodyProvider::default(),
            FakeCustodyProvider::default(),
            FakeCustodyProvider::default(),
        );
        let runtime = coordinator(
            &root,
            vec![
                selected(&r1, &c1, 1),
                selected(&r2, &c2, 2),
                selected(&r3, &c3, 3),
            ],
        );
        let outcome = runtime
            .release(
                &wallet_request,
                &wallet_response,
                operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } = outcome else {
            panic!("custody gave no answer, so the release is not terminal");
        };
        // The V1 journal key is unchanged: the signed operation's hash.
        assert_eq!(operation_hash, operation.canonical_hash().unwrap());

        let settled = runtime
            .reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: vec![
                        signed_node_contribution(&operation, 1),
                        signed_node_contribution(&operation, 2),
                    ],
                },
                NOW + 6,
            )
            .unwrap();
        assert_eq!(contributions_of(settled).len(), 2);
        let persisted = RuntimeReleaseJournal::new(root)
            .load(operation_hash)
            .unwrap();
        assert_eq!(
            persisted.draft().signed_runtime_release_operation(),
            &RuntimeReleaseOperationAnyV1::V1(operation)
        );
    }

    #[tokio::test]
    async fn v2_contribution_for_unknown_recipient_is_refused() {
        let temp = tempdir().unwrap();
        let fixture = pool_release();
        let authenticated = pool_authenticated(&fixture.operation);
        let recipients = pool_recipients(&authenticated);
        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::UnknownRecipient);
        let runtime = pool_coordinator(&owner_only_root(&temp), &nodes);
        let (wallet_request, wallet_response) = pool_wallet_bytes(&fixture.operation);

        let outcome = runtime
            .release(
                &wallet_request,
                &wallet_response,
                fixture.operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } = outcome else {
            panic!("a contribution to an unsigned recipient never settles a release: {outcome:?}");
        };
        // Offered directly, the same contribution is refused, and nothing
        // terminal is written.
        let unknown = recipient_identity(0x77);
        let (a, b) = pool_node_order(&authenticated);
        let offer = pool_contribution_set(
            &authenticated,
            &[
                (a, unknown),
                (a, recipients[1].clone()),
                (b, recipients[0].clone()),
                (b, recipients[1].clone()),
            ],
        );
        assert_eq!(
            runtime.reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: offer,
                },
                NOW + 6,
            ),
            Err(RuntimeReleaseCoordinatorError::ProviderResult)
        );
        let persisted = RuntimeReleaseJournal::new(owner_only_root(&temp))
            .load(operation_hash)
            .unwrap();
        assert!(persisted.terminal_result().is_none());
    }

    #[tokio::test]
    async fn v2_missing_recipient_pair_is_refused() {
        let temp = tempdir().unwrap();
        let fixture = pool_release();
        let authenticated = pool_authenticated(&fixture.operation);
        let recipients = pool_recipients(&authenticated);
        let (r0, r1) = (recipients[0].clone(), recipients[1].clone());
        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::OneRecipientOnly);
        let runtime = pool_coordinator(&owner_only_root(&temp), &nodes);
        let (wallet_request, wallet_response) = pool_wallet_bytes(&fixture.operation);

        // Nodes that answer for one recipient only never complete a release.
        let outcome = runtime
            .release(
                &wallet_request,
                &wallet_response,
                fixture.operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap();
        let RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } = outcome else {
            panic!("a node without every recipient's pair does not count: {outcome:?}");
        };

        let (a, b) = pool_node_order(&authenticated);
        let refused = [
            // One pair missing.
            vec![(a, r0.clone()), (a, r1.clone()), (b, r0.clone())],
            // One pair twice, another missing.
            vec![
                (a, r0.clone()),
                (a, r0.clone()),
                (b, r0.clone()),
                (b, r1.clone()),
            ],
            // One node twice.
            vec![
                (a, r0.clone()),
                (a, r1.clone()),
                (a, r0.clone()),
                (a, r1.clone()),
            ],
            // Recipients out of order.
            vec![
                (a, r1.clone()),
                (a, r0.clone()),
                (b, r0.clone()),
                (b, r1.clone()),
            ],
            // Nodes out of node-set order.
            vec![
                (b, r0.clone()),
                (b, r1.clone()),
                (a, r0.clone()),
                (a, r1.clone()),
            ],
        ];
        for pairs in refused {
            assert_eq!(
                runtime.reconcile(
                    operation_hash,
                    RuntimeReleaseReconcileOffer::ContributionsReady {
                        signed_node_contributions: pool_contribution_set(&authenticated, &pairs),
                    },
                    NOW + 6,
                ),
                Err(RuntimeReleaseCoordinatorError::ProviderResult),
                "{pairs:?}"
            );
        }
        // The exact set settles.
        let exact = vec![(a, r0.clone()), (a, r1.clone()), (b, r0), (b, r1)];
        let settled = runtime
            .reconcile(
                operation_hash,
                RuntimeReleaseReconcileOffer::ContributionsReady {
                    signed_node_contributions: pool_contribution_set(&authenticated, &exact),
                },
                NOW + 6,
            )
            .unwrap();
        assert_pool_pairs(&authenticated, &contributions_of(settled), &exact);
    }

    #[tokio::test]
    async fn v2_wallet_binding_must_match() {
        let temp = tempdir().unwrap();
        let fixture = pool_release();
        let other = pool_release_with(2, 0x56);
        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Honest);
        let runtime = pool_coordinator(&owner_only_root(&temp), &nodes);

        // The Wallet signed another V2 request.
        let (wallet_request, wallet_response) = pool_wallet_bytes(&other.operation);
        assert_eq!(
            runtime
                .release(
                    &wallet_request,
                    &wallet_response,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        // A V1 Wallet answer does not bind a V2 operation.
        let (wallet_request, wallet_response) =
            wallet_request_response(&signed_runtime_release_operation(0x42));
        assert_eq!(
            runtime
                .release(
                    &wallet_request,
                    &wallet_response,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::WalletAuthority)
        );
        assert!(nodes
            .rights
            .iter()
            .all(|rights| rights.request_count() == 0));
        assert!(nodes
            .custody
            .iter()
            .all(|custody| custody.request_count() == 0));
    }

    #[tokio::test]
    async fn v2_operation_of_another_runtime_is_refused() {
        let temp = tempdir().unwrap();
        let fixture = pool_release();
        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Honest);
        // This Runtime is not the operation's issuer (Expected(own)).
        let runtime = pool_coordinator_for(&owner_only_root(&temp), &nodes, runtime_issuer(0x42));
        let (wallet_request, wallet_response) = pool_wallet_bytes(&fixture.operation);
        assert_eq!(
            runtime
                .release(
                    &wallet_request,
                    &wallet_response,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await,
            Err(RuntimeReleaseCoordinatorError::OperationAuthority)
        );
        assert!(nodes
            .rights
            .iter()
            .all(|rights| rights.request_count() == 0));
    }

    #[tokio::test]
    async fn journal_key_differs_from_operation_hash() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let fixture = pool_release();
        let any = RuntimeReleaseOperationAnyV1::V2(fixture.operation.clone());
        let journal_key = any.journal_key().unwrap();
        let authenticated = any
            .verify(
                RuntimeIssuerPolicyV1::Expected(pool_fixtures::runtime_issuer(POOL_RUNTIME_SEED)),
                NOW + 3,
            )
            .unwrap();
        // The journal key is the signed operation's hash; the release slots
        // hold the statement hash (L1).
        assert_eq!(journal_key, fixture.operation.canonical_hash().unwrap());
        assert_ne!(journal_key, authenticated.operation_hash());
        assert_eq!(
            authenticated.release_request_hash(),
            authenticated.operation_hash()
        );
        assert_eq!(any.expires_at(), NOW + 40);

        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Unreachable);
        let runtime = pool_coordinator(&root, &nodes);
        let (wallet_request, wallet_response) = pool_wallet_bytes(&fixture.operation);
        let outcome = runtime
            .release(&wallet_request, &wallet_response, any.clone(), NOW + 6)
            .await
            .unwrap();
        let RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } = outcome else {
            panic!("custody gave no answer: {outcome:?}");
        };
        assert_eq!(operation_hash, journal_key);
        let journal = RuntimeReleaseJournal::new(root);
        assert_eq!(
            journal
                .load(journal_key)
                .unwrap()
                .draft()
                .signed_runtime_release_operation(),
            &any
        );
        assert_eq!(
            journal.load(authenticated.operation_hash()).unwrap_err(),
            RuntimeReleaseJournalError::NotFound
        );
    }

    // -----------------------------------------------------------------
    // O1 option A.2 (Plan B T4.1): a renewal is a new V2 operation under
    // the same Wallet-signed rights request. Each operation is its own
    // journal record under its own journal key; there is no format change.
    // -----------------------------------------------------------------

    /// The successor's window: issued at `NOW + 42`, ends at `NOW + 80`,
    /// inside the same rights window (`NOW .. NOW + 180`).
    const SUCCESSOR_BASE: u64 = NOW + 40;

    /// A successor of `operation` under the same Wallet signature: the same
    /// rights request, recipients, policy and descriptor, another audit id
    /// and a later window, signed by the same Runtime.
    fn pool_successor(
        operation: &SignedRuntimeReleaseOperationV2,
        audit_request_id: u8,
    ) -> SignedRuntimeReleaseOperationV2 {
        use elastos_protected_content_contracts::RuntimeReleaseOperationStatementV2;
        let current = operation.statement();
        let statement = RuntimeReleaseOperationStatementV2::new(
            current.runtime_operation_issuer(),
            current.rights_request().clone(),
            current.recipients().to_vec(),
            current.policy_body().clone(),
            current.evidence_request().clone(),
            current.pool_descriptor().clone(),
            RuntimeReleaseAuditIdV1::new(Digest32::new([audit_request_id; 32])).unwrap(),
            SUCCESSOR_BASE + 2,
            SUCCESSOR_BASE + 40,
        )
        .unwrap();
        SignedRuntimeReleaseOperationV2::new(
            statement.clone(),
            pool_fixtures::signing_key(POOL_RUNTIME_SEED)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    fn journal_key_of(operation: &SignedRuntimeReleaseOperationV2) -> Digest32 {
        RuntimeReleaseOperationAnyV1::V2(operation.clone())
            .journal_key()
            .unwrap()
    }

    #[tokio::test]
    async fn each_operation_has_its_own_journal_record() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let fixture = pool_release();
        let successor = pool_successor(&fixture.operation, 0x92);
        // One Wallet signature serves both operations.
        let wallet = pool_wallet_bytes(&fixture.operation);
        assert_eq!(pool_wallet_bytes(&successor), wallet);
        let (initial_key, successor_key) = (
            journal_key_of(&fixture.operation),
            journal_key_of(&successor),
        );
        assert_ne!(initial_key, successor_key);

        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Honest);
        let runtime = pool_coordinator(&root, &nodes);
        let initial = contributions_of(
            runtime
                .release(
                    &wallet.0,
                    &wallet.1,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await
                .unwrap(),
        );
        assert_eq!(initial.len(), 4);
        let journal = RuntimeReleaseJournal::new(root.clone());
        let initial_record = journal.load(initial_key).unwrap();

        let nodes = pool_nodes_at(&successor, PoolCustodyMode::Honest, SUCCESSOR_BASE);
        let runtime = pool_coordinator(&root, &nodes);
        let renewed = contributions_of(
            runtime
                .release(
                    &wallet.0,
                    &wallet.1,
                    successor.clone().into(),
                    SUCCESSOR_BASE + 5,
                )
                .await
                .unwrap(),
        );
        assert_eq!(renewed.len(), 4);
        assert_pool_pairs_at(&successor, &renewed, SUCCESSOR_BASE);

        // Two records, each with its own operation and result; the first
        // is untouched by the second.
        assert_eq!(journal.load(initial_key).unwrap(), initial_record);
        let successor_record = journal.load(successor_key).unwrap();
        assert_eq!(
            successor_record.draft().signed_runtime_release_operation(),
            &RuntimeReleaseOperationAnyV1::V2(successor)
        );
        assert_eq!(
            successor_record
                .terminal_result()
                .unwrap()
                .contribution_count(),
            4
        );
        assert!(journal.list_unresolved().unwrap().is_empty());
    }

    #[tokio::test]
    async fn restart_mid_renewal_reconciles() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let fixture = pool_release();
        let successor = pool_successor(&fixture.operation, 0x93);
        let wallet = pool_wallet_bytes(&fixture.operation);
        let (initial_key, successor_key) = (
            journal_key_of(&fixture.operation),
            journal_key_of(&successor),
        );
        {
            let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Honest);
            let runtime = pool_coordinator(&root, &nodes);
            runtime
                .release(
                    &wallet.0,
                    &wallet.1,
                    fixture.operation.clone().into(),
                    NOW + 6,
                )
                .await
                .unwrap();
            // The renewal's rights are decided, then its custody calls are
            // lost and the process stops.
            let nodes = pool_nodes_at(&successor, PoolCustodyMode::Unreachable, SUCCESSOR_BASE);
            let runtime = pool_coordinator(&root, &nodes);
            assert_eq!(
                runtime
                    .release(
                        &wallet.0,
                        &wallet.1,
                        successor.clone().into(),
                        SUCCESSOR_BASE + 5,
                    )
                    .await
                    .unwrap(),
                RuntimeReleaseCoordinatorOutcome::Nonterminal {
                    operation_hash: successor_key,
                    reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
                }
            );
        }

        // After the restart only the renewal is unresolved, and it resumes
        // under its own key with the persisted decisions.
        let journal = RuntimeReleaseJournal::new(root.clone());
        let unresolved = journal.list_unresolved().unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            unresolved[0].draft().operation_hash().unwrap(),
            successor_key
        );
        let nodes = silent_pool_nodes_at(PoolCustodyMode::Honest, SUCCESSOR_BASE);
        let runtime = pool_coordinator(&root, &nodes);
        let renewed = contributions_of(
            runtime
                .resume_exact(successor_key, SUCCESSOR_BASE + 6)
                .await
                .unwrap(),
        );
        assert_pool_pairs_at(&successor, &renewed, SUCCESSOR_BASE);
        assert!(nodes
            .rights
            .iter()
            .all(|rights| rights.request_count() == 0));
        assert!(journal.list_unresolved().unwrap().is_empty());
        assert_eq!(
            journal
                .load(initial_key)
                .unwrap()
                .terminal_result()
                .unwrap()
                .contribution_count(),
            4
        );
    }

    /// A superseded operation whose nodes answer `Unavailable` keeps its own
    /// record. Once its window has ended it can no longer be resumed: the
    /// coordinator refuses it before any provider call, and the journal
    /// infers nothing from elapsed time (the record stays, byte for byte).
    /// The successor's record is unaffected.
    #[tokio::test]
    async fn superseded_record_settles_at_its_expiry() {
        let temp = tempdir().unwrap();
        let root = owner_only_root(&temp);
        let fixture = pool_release();
        let successor = pool_successor(&fixture.operation, 0x94);
        let wallet = pool_wallet_bytes(&fixture.operation);
        let (initial_key, successor_key) = (
            journal_key_of(&fixture.operation),
            journal_key_of(&successor),
        );

        let nodes = pool_nodes(&fixture.operation, PoolCustodyMode::Unreachable);
        let runtime = pool_coordinator(&root, &nodes);
        let RuntimeReleaseCoordinatorOutcome::Nonterminal { operation_hash, .. } = runtime
            .release(
                &wallet.0,
                &wallet.1,
                fixture.operation.clone().into(),
                NOW + 6,
            )
            .await
            .unwrap()
        else {
            panic!("custody gave no answer");
        };
        assert_eq!(operation_hash, initial_key);

        let nodes = pool_nodes_at(&successor, PoolCustodyMode::Honest, SUCCESSOR_BASE);
        let runtime = pool_coordinator(&root, &nodes);
        contributions_of(
            runtime
                .release(
                    &wallet.0,
                    &wallet.1,
                    successor.clone().into(),
                    SUCCESSOR_BASE + 5,
                )
                .await
                .unwrap(),
        );

        // Before its expiry the superseded record still resumes: its nodes
        // answer `Unavailable` (no exact result) and it stays nonterminal.
        let nodes = silent_pool_nodes(PoolCustodyMode::Unreachable);
        let runtime = pool_coordinator(&root, &nodes);
        assert_eq!(
            runtime.resume_exact(initial_key, NOW + 7).await.unwrap(),
            RuntimeReleaseCoordinatorOutcome::Nonterminal {
                operation_hash: initial_key,
                reason: RuntimeReleaseNonterminalReason::ProviderEffectUncertain,
            }
        );

        // At its expiry (`NOW + 40`) it is refused before any provider call.
        let file = runtime_record_bytes(&root, initial_key);
        let nodes = silent_pool_nodes(PoolCustodyMode::Honest);
        let runtime = pool_coordinator(&root, &nodes);
        assert_eq!(
            runtime.resume_exact(initial_key, NOW + 41).await,
            Err(RuntimeReleaseCoordinatorError::OperationAuthority)
        );
        assert!(nodes
            .custody
            .iter()
            .all(|custody| custody.request_count() == 0));
        assert_eq!(runtime_record_bytes(&root, initial_key), file);
        let journal = RuntimeReleaseJournal::new(root);
        assert!(journal
            .load(initial_key)
            .unwrap()
            .terminal_result()
            .is_none());
        assert_eq!(
            journal
                .load(successor_key)
                .unwrap()
                .terminal_result()
                .unwrap()
                .contribution_count(),
            4
        );
    }

    /// The stored journal file whose record names `key` (the record's
    /// operation-hash field, bytes 104..136 after the magic and slot).
    fn runtime_record_bytes(root: &Path, key: Digest32) -> Vec<u8> {
        let mut matching = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.len() == 64)
            })
            .map(|path| std::fs::read(path).unwrap())
            .filter(|bytes| bytes.get(104..136) == Some(key.as_bytes().as_slice()))
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "one record holds the key");
        matching.remove(0)
    }

    fn assert_pool_pairs_at(
        operation: &SignedRuntimeReleaseOperationV2,
        contributions: &[SignedNodeContributionV1],
        base: u64,
    ) {
        let authenticated = operation
            .verify(RuntimeIssuerPolicyV1::Declared, base + 3)
            .unwrap();
        let node_set = pool_node_set(&authenticated);
        let recipients = pool_recipients(&authenticated);
        let (a, b) = pool_node_order(&authenticated);
        let expected = [
            (a, recipients[0].clone()),
            (a, recipients[1].clone()),
            (b, recipients[0].clone()),
            (b, recipients[1].clone()),
        ];
        assert_eq!(contributions.len(), expected.len());
        for (contribution, (node, recipient)) in contributions.iter().zip(&expected) {
            let verified = authenticated
                .verify_node_contribution(contribution, &node_set, recipient, base + 6)
                .unwrap();
            assert_eq!(verified.node_public_key(), node_public_key(*node));
        }
    }
}
