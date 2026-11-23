use super::*;

const MEDIA_PROVIDER_CONFIG_FILE: &str = "protected-content/media-provider/config.json";

pub(super) const MEDIA_PROVIDER_CONFIG_SCHEMA_V1: &str =
    "elastos.protected-content.media-provider-config/v1";

const MEDIA_PROVIDER_OUTPUT_PROFILE_V1: &str = "browser_fmp4_h264_v1";

const MAX_MEDIA_PROVIDER_CONFIG_BYTES: usize = 8 * 1024;

const MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES: u64 = 512 * 1024 * 1024;

pub(super) const MEDIA_PROVIDER_TIMEOUT_MS_V1: u64 = 3_600_000;

const MEDIA_PROVIDER_MAX_STDIO_BYTES_V1: usize = 1 << 20;

pub(super) const MEDIA_PROVIDER_MAX_INPUT_BYTES_V1: u64 = 1 << 30;

const MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1: u64 = 64 << 20;

const MEDIA_PROVIDER_MAX_DURATION_SECS_V1: u64 = 1_800;

const MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1: u32 = 3_840;

const MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1: u32 = 2_160;

const MEDIA_PROVIDER_MAX_SOURCE_FPS_V1: u32 = 60;

const MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1: usize = MAX_PROTECT_MEDIA_SEGMENTS_V1 as usize;

const MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1: u64 = 2 << 30;

/// The verified copies a new mint asks the content plane for. One: pool
/// members hold no copies until the pool redesign raises this. It is never
/// below the accepted floor.
pub(crate) const PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET: u32 = 1;

/// Whether a check that asks for `minimum_replicas` copies also asks for a live
/// proof from another peer: only when it asks for another copy. Each check
/// applies this to its own requirement, so a mint (built at the new-mint
/// target) stays strict, and the re-check of a listing already made (built at
/// the accepted floor) still accepts that listing's one verified copy.
pub(crate) const fn protected_content_live_proof_required(minimum_replicas: u32) -> bool {
    minimum_replicas > 1
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMediaProviderConfigFile {
    schema: String,
    ffmpeg_path: String,
    ffprobe_path: String,
    staging_root: String,
    output_profile: String,
    timeout_ms: u64,
    max_stdio_bytes: usize,
    max_input_bytes: u64,
    max_output_part_bytes: u64,
    max_duration_secs: u64,
    max_source_width: u32,
    max_source_height: u32,
    max_source_fps: u32,
    max_segment_count: usize,
    max_total_output_bytes: u64,
}

pub(super) struct RuntimeMediaToolSource {
    pub(super) file: fs::File,
    size: u64,
}

struct RuntimeMediaToolImport {
    path: PathBuf,
    created: bool,
}

/// One critical step of a mint, traced at both ends.
///
/// Every trace on this path used to be an *end* marker -- "protected",
/// "provisioned", "verified". With only those, a step that is slow and a step
/// that is stuck look identical until it finishes, which is why a publish that
/// took nineteen minutes could not be attributed to any phase afterwards. A
/// step now announces itself before it begins and reports how long it took when
/// it stops.
///
/// It reports even when it stops by failing: the end is logged from `Drop`, so
/// an early `?` return still leaves a boundary in the log, marked `abandoned`
/// rather than `ok`. That is the case worth seeing, and it is the one an
/// explicit call at the end of the happy path would always miss.
///
/// DEBUG on purpose. An operator at INFO wants the outcome, not the itinerary;
/// this is for whoever is asking where the time went.
pub(crate) struct RuntimeMintStep {
    name: &'static str,
    request_id: String,
    started: std::time::Instant,
    outcome: &'static str,
    repeating: bool,
}

impl RuntimeMintStep {
    /// A step that happens once in a publish.
    pub(crate) fn begin(name: &'static str, request_id: &str) -> Self {
        tracing::debug!(step = name, %request_id, "runtime custody step: begin");
        Self {
            name,
            request_id: request_id.to_string(),
            started: std::time::Instant::now(),
            outcome: "abandoned",
            repeating: false,
        }
    }

    /// A step re-run by every poll of a wait.
    ///
    /// TRACE, not DEBUG. Waiting for a wallet approval or for a block to
    /// finalise means re-entering the same three steps every few seconds for
    /// minutes on end, and at DEBUG that repetition buries the things that
    /// happen once. What a reader needs from a wait is when it started and when
    /// it ended -- both of which are logged at DEBUG elsewhere -- not a
    /// transcript of every time nothing changed.
    pub(crate) fn begin_repeating(name: &'static str, request_id: &str) -> Self {
        tracing::trace!(step = name, %request_id, "runtime custody step: begin");
        Self {
            name,
            request_id: request_id.to_string(),
            started: std::time::Instant::now(),
            outcome: "abandoned",
            repeating: true,
        }
    }

    /// Mark the step as having run to completion. Anything that returns before
    /// this is reached is reported as abandoned.
    pub(crate) fn ok(mut self) {
        self.outcome = "ok";
    }

    /// Mark the step as having stopped because what it waits for has not
    /// happened yet.
    ///
    /// Without this, a chain answer of "not finalized yet" -- the expected
    /// shape of that wait, repeated every few seconds -- reads identically to a
    /// step that fell over. Distinguishing them is the whole point of recording
    /// an outcome, and `abandoned` is only useful if it stays rare.
    pub(crate) fn pending(mut self) {
        self.outcome = "pending";
    }
}

impl Drop for RuntimeMintStep {
    fn drop(&mut self) {
        let elapsed_ms = self.started.elapsed().as_millis();
        // A repeating step that ends badly is still worth DEBUG: the point of
        // quietening the loop is to hide the times nothing happened, not the
        // time something did.
        if self.repeating && self.outcome != "abandoned" {
            tracing::trace!(
                step = self.name,
                request_id = %self.request_id,
                outcome = self.outcome,
                elapsed_ms,
                "runtime custody step: end"
            );
            return;
        }
        tracing::debug!(
            step = self.name,
            request_id = %self.request_id,
            outcome = self.outcome,
            elapsed_ms,
            "runtime custody step: end"
        );
    }
}

/// Times one leg *inside* a step, for steps long enough that knowing they took
/// five minutes says nothing useful.
///
/// `availability_publish` is the case that forced this: it is a single step
/// that publishes the ciphertext, then reads a receipt, a manifest, and every
/// file back to prove the object replicated. When it takes five minutes, the
/// step timer can only report five minutes -- which of those legs spent them
/// is exactly the question, and was previously answerable only by guessing.
///
/// Reports on drop like `RuntimeMintStep`, so a leg that returns early is
/// still recorded rather than vanishing.
pub(crate) struct RuntimeCustodyPhase {
    name: &'static str,
    detail: String,
    started: std::time::Instant,
    outcome: &'static str,
}

impl RuntimeCustodyPhase {
    pub(crate) fn begin(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            detail: detail.into(),
            started: std::time::Instant::now(),
            outcome: "abandoned",
        }
    }

    pub(crate) fn ok(mut self) {
        self.outcome = "ok";
    }
}

impl Drop for RuntimeCustodyPhase {
    fn drop(&mut self) {
        tracing::debug!(
            phase = self.name,
            detail = %self.detail,
            outcome = self.outcome,
            elapsed_ms = self.started.elapsed().as_millis(),
            "runtime custody phase"
        );
    }
}

pub(crate) const RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE: &str =
    "Runtime custody download is denied without an owned copy";

/// A download refusal a person can act on, carried as data -- `code` on the
/// error envelope -- so an app says what is missing without reading the
/// sentence, which stays `RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyDownloadRefusal {
    /// The chain grants this account no access to the item.
    NoAccess,
    /// The head grants it and the finalized block does not yet: the grant is
    /// still being confirmed, and custody would refuse it until it is.
    Confirming,
}

impl RuntimeCustodyDownloadRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NoAccess => "no_access",
            Self::Confirming => "access_confirming",
        }
    }

    pub(crate) fn error(self) -> anyhow::Error {
        anyhow::Error::new(self).context(RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE)
    }
}

impl std::fmt::Display for RuntimeCustodyDownloadRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NoAccess => "the chain grants this account no access to the item",
            Self::Confirming => "the chain has not finalized this account's access yet",
        })
    }
}

impl std::error::Error for RuntimeCustodyDownloadRefusal {}

/// An item whose pool this Home cannot reach (Plan B T4.7): no copy of it can
/// be built, bought or opened here until the pool is added in Custody. It
/// travels as data -- `code` `custody_elsewhere` -- so an app says why
/// instead of failing generically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyElsewhere;

impl RuntimeCustodyElsewhere {
    pub(crate) const CODE: &'static str = "custody_elsewhere";

    pub(crate) fn error() -> anyhow::Error {
        anyhow::Error::new(Self).context(RUNTIME_CUSTODY_ELSEWHERE_MESSAGE)
    }

    /// Whether `error` is, at any depth, this refusal. Plan B T4.6: an item
    /// whose pool cannot be reached from here ([`RuntimeCustodyUnresolved`])
    /// answers the same refusal code to buy, adoption and download (T4.7).
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
            || error.downcast_ref::<RuntimeCustodyUnresolved>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyElsewhere {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("this Home cannot reach the custody pool of this item")
    }
}

impl std::error::Error for RuntimeCustodyElsewhere {}

/// Plan B T4.7: the code stays `custody_elsewhere`; its words say what to do.
pub(crate) const RUNTIME_CUSTODY_ELSEWHERE_MESSAGE: &str =
    "This item's pool cannot be reached from this Home yet. Add the pool in Custody.";

/// OPEN-LOOP F2: a pool open that failed after the Wallet signed. The signed
/// rights were spent on its one release (rev14), so asking again would mean a
/// new Wallet request: the open ends here, with no resumable stage, and the
/// Player or Reader offers Retry for the person to press. Its `code` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyPoolContentUnavailable;

impl RuntimeCustodyPoolContentUnavailable {
    pub(crate) const CODE: &'static str = "content_unavailable";

    /// The refusal, with `cause` in its detail chain.
    pub(crate) fn error(cause: &anyhow::Error) -> anyhow::Error {
        anyhow::Error::new(Self)
            .context(format!("{cause:?}"))
            .context(RUNTIME_CUSTODY_POOL_CONTENT_UNAVAILABLE_MESSAGE)
    }

    /// Whether `error` is, at any depth, this refusal.
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyPoolContentUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl std::error::Error for RuntimeCustodyPoolContentUnavailable {}

/// Wire identity of the typed answer a creator app gets when an attempt to
/// protect a file is refused because an earlier attempt for the same file is
/// already on record at different terms.
pub(crate) const RUNTIME_CUSTODY_CREATOR_MINT_BLOCKED_SCHEMA_V1: &str =
    "elastos.protected-content.creator-mint-blocked/v1";

/// What an earlier creator mint already on record means for a new attempt at
/// different terms, and what the creator may still do about it.
///
/// Mirrors [`RuntimeMintCreatorStage`] one-to-one and exists separately only so
/// the wire spelling an app branches on is fixed here rather than derived from
/// a type an app cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyCreatorMintBlockedState {
    /// Terms are on record and nothing was raised on any ledger.
    RecordedOnly,
    /// A transaction is out for the creator's approval and may still settle.
    ApprovalOutstanding,
    /// The mint settled; a seller and a token id exist.
    AlreadyMinted,
}

impl RuntimeCustodyCreatorMintBlockedState {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::RecordedOnly => "recorded_only",
            Self::ApprovalOutstanding => "approval_outstanding",
            Self::AlreadyMinted => "already_minted",
        }
    }
}

/// What a refused attempt collided with: how far the recorded attempt got and
/// which of its terms the new one would change.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyCreatorMintConflict {
    pub(crate) stage: Option<RuntimeCustodyUnfinishedMintStage>,
    pub(crate) differing_terms: Vec<&'static str>,
}

/// A refusal that carries its reason as data.
///
/// Re-terming a mint already in flight stays refused. What this adds is that
/// the creator is told what was recorded and which action is open to them,
/// without any app having to read the sentence. The recorded copies and price
/// travel here, to the person who entered them — never into the log.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyCreatorMintBlocked {
    state: RuntimeCustodyCreatorMintBlockedState,
    mint_id: String,
    copies: String,
    price: String,
    progress: Option<Value>,
    conflict: Option<RuntimeCustodyCreatorMintConflict>,
    /// Whether Resume can move this attempt forward. False only for an
    /// attempt whose mint reverted as a duplicate: nothing it does settles it.
    resumable: bool,
}

impl RuntimeCustodyCreatorMintBlocked {
    pub(crate) fn new(mint_id: Digest32, recorded: &RuntimeMintCreatorState) -> Self {
        let state = match recorded.stage() {
            RuntimeMintCreatorStage::Recorded => {
                RuntimeCustodyCreatorMintBlockedState::RecordedOnly
            }
            RuntimeMintCreatorStage::EffectRaised => {
                RuntimeCustodyCreatorMintBlockedState::ApprovalOutstanding
            }
            RuntimeMintCreatorStage::Settled => {
                RuntimeCustodyCreatorMintBlockedState::AlreadyMinted
            }
        };
        Self {
            state,
            mint_id: hex::encode(mint_id.as_bytes()),
            copies: recorded.desired_terms().copies().to_string(),
            price: recorded.desired_terms().price().to_string(),
            progress: None,
            conflict: None,
            resumable: true,
        }
    }

    /// An attempt whose mint transaction reverted because its content id was
    /// already bound (`IPAlreadyBound`, `InvalidTokenId`), and whose content id
    /// the chain's own binding confirms is bound. The file is minted; this
    /// attempt can never settle it, so it offers neither Start over nor
    /// Resume.
    pub(crate) fn reverted_as_duplicate(
        mint_id: Digest32,
        recorded: &RuntimeMintCreatorState,
    ) -> Self {
        Self {
            state: RuntimeCustodyCreatorMintBlockedState::AlreadyMinted,
            resumable: false,
            ..Self::new(mint_id, recorded)
        }
    }

    /// Attach what the new attempt collided with, so an app can say which
    /// terms differ and offer the recorded attempt back instead of a dead end.
    #[must_use]
    pub(crate) fn with_conflict(mut self, conflict: RuntimeCustodyCreatorMintConflict) -> Self {
        self.conflict = Some(conflict);
        self
    }

    /// Attach how far the blocked mint actually got.
    ///
    /// Opt-in for the same reason the waiting state's is: only a caller holding
    /// the mint record can say, and a caller that cannot must not fill it with
    /// a guess. It is what lets an app show which stage a blocked attempt
    /// reached instead of only that one exists.
    #[must_use]
    pub(crate) fn with_progress(mut self, progress: Value) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Stage name for the operator log. Carries no terms and no account.
    pub(crate) const fn state_label(&self) -> &'static str {
        self.state.wire_value()
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_CREATOR_MINT_BLOCKED_SCHEMA_V1,
            "state": self.state.wire_value(),
            "mint_id": self.mint_id,
            "recorded_copies": self.copies,
            "recorded_price": self.price,
            // A refused attempt is one whose transaction was sent or mined, or
            // that is listed: it is never set aside, only resumed.
            "can_start_over": false,
            // Resuming re-runs the recorded attempt from its own terms, which
            // moves it forward in every state: a settled mint whose listing
            // never published is finished by it, and a listed one only replays.
            // A mint that reverted as a duplicate is the one it cannot move.
            "can_resume": self.resumable,
        });
        if let Some(progress) = self.progress.as_ref() {
            answer["progress"] = progress.clone();
        }
        if let Some(conflict) = self.conflict.as_ref() {
            answer["differing_terms"] = json!(conflict.differing_terms);
            if let Some(stage) = conflict.stage {
                answer["stage"] = json!(stage.wire_value());
            }
        }
        answer
    }
}

impl std::fmt::Display for RuntimeCustodyCreatorMintBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.state {
            RuntimeCustodyCreatorMintBlockedState::RecordedOnly => {
                "An earlier attempt to protect this file is still on record at different terms"
            }
            RuntimeCustodyCreatorMintBlockedState::ApprovalOutstanding => {
                "An earlier attempt to protect this file already sent its transaction, so its terms can no longer change; resume it to finish"
            }
            RuntimeCustodyCreatorMintBlockedState::AlreadyMinted => {
                "This file is already protected and listed, so its terms can no longer change"
            }
        })
    }
}

impl std::error::Error for RuntimeCustodyCreatorMintBlocked {}

/// Wire identity of the state an app renders while a purchase settles.
pub(crate) const RUNTIME_CUSTODY_BUY_PROGRESS_SCHEMA_V1: &str =
    "elastos.protected-content.buy-progress/v1";

/// Where one purchase has got to.
///
/// A purchase is a sequence of waits, not a request: the wallet holds an
/// approval the person answers, the chain takes its own time to confirm what
/// they approved, and the right they bought becomes readable a block later
/// still. Each of those used to arrive as the same sentence, and Marketplace
/// dropped the sentence and showed "Media action could not be completed", so a
/// purchase that was proceeding normally read as one that had failed.
///
/// The stages are the buy twin of [`RuntimeCustodyOpenStage`] and carry the
/// same two facts an app decides from: whether asking again can answer
/// differently, and whether a person has to do something first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyBuyStage {
    /// The seller's payment token needs an allowance before the purchase can
    /// move it. Only an ERC-20 listing reaches this stage; a listing priced in
    /// the chain's own coin never does.
    AllowanceApproval,
    /// The Wallet holds the purchase itself. This is the approval that spends.
    PurchaseApproval,
    /// Approved, and the chain has not yet produced the evidence the purchase
    /// needs. Nobody can hurry it and nobody need act.
    ChainSettlement,
    /// The purchase is on the chain and the right it bought is not yet
    /// readable at the block Runtime trusts. The same purchase completes as
    /// soon as it is.
    AccessEvidence,
    /// The person answered the Wallet by declining. Asking again re-raises the
    /// same request rather than changing this answer, so an app offers a fresh
    /// purchase instead of a retry.
    Declined,
}

impl RuntimeCustodyBuyStage {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::AllowanceApproval => "allowance_approval",
            Self::PurchaseApproval => "purchase_approval",
            Self::ChainSettlement => "chain_settlement",
            Self::AccessEvidence => "access_evidence",
            Self::Declined => "declined",
        }
    }

    /// Whether re-issuing the identical buy can produce a different answer.
    const fn resumable(self) -> bool {
        match self {
            Self::AllowanceApproval
            | Self::PurchaseApproval
            | Self::ChainSettlement
            | Self::AccessEvidence => true,
            Self::Declined => false,
        }
    }

    /// Whether the person has to act before this stage can move.
    const fn needs_an_answer(self) -> bool {
        matches!(self, Self::AllowanceApproval | Self::PurchaseApproval)
    }
}

/// How far a purchase has got, carried as data beside the stable message.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyBuyProgress {
    stage: RuntimeCustodyBuyStage,
    /// Who is being waited on, and only while that is a fact worth stating. A
    /// chain wait names nobody: the signer has already done everything asked
    /// of them.
    approval: Option<RuntimeCustodyBuyApproval>,
}

/// Who answers the Wallet for a purchase, and where they answer it.
#[derive(Debug, Clone)]
struct RuntimeCustodyBuyApproval {
    /// True when the account is an external wallet reached through a
    /// connector, so the outstanding approval needs the person to act there.
    external_signer: bool,
    /// Names the connector when there is one, so an app can say "MetaMask"
    /// rather than "your wallet".
    connector_id: Option<String>,
}

impl RuntimeCustodyBuyProgress {
    /// The Wallet holds an approval for this purchase.
    pub(crate) fn awaiting_approval(
        stage: RuntimeCustodyBuyStage,
        external_signer: bool,
        connector_id: Option<&str>,
    ) -> Self {
        Self {
            stage,
            approval: Some(RuntimeCustodyBuyApproval {
                external_signer,
                connector_id: connector_id.map(ToString::to_string),
            }),
        }
    }

    /// A wait that asks nothing of anyone: the chain, or the right becoming
    /// readable.
    pub(crate) const fn waiting(stage: RuntimeCustodyBuyStage) -> Self {
        Self {
            stage,
            approval: None,
        }
    }

    /// The person declined the Wallet request.
    pub(crate) const fn declined() -> Self {
        Self {
            stage: RuntimeCustodyBuyStage::Declined,
            approval: None,
        }
    }

    /// Stage name for the operator log. Carries no account and no address.
    pub(crate) const fn stage_label(&self) -> &'static str {
        self.stage.wire_value()
    }

    /// Whether the person has to do something, or the purchase is simply
    /// waiting. An app polls in both cases; only one of them asks anything of
    /// the buyer.
    pub(crate) const fn awaits_person(&self) -> bool {
        match self.approval {
            Some(ref approval) => self.stage.needs_an_answer() && approval.external_signer,
            None => false,
        }
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_BUY_PROGRESS_SCHEMA_V1,
            "stage": self.stage.wire_value(),
            "resumable": self.stage.resumable(),
            "awaits_person": self.awaits_person(),
        });
        if let Some(approval) = self.approval.as_ref() {
            answer["external_signer"] = Value::Bool(approval.external_signer);
            answer["connector_id"] = approval
                .connector_id
                .as_ref()
                .map_or(Value::Null, |id| Value::String(id.clone()));
        }
        answer
    }
}

impl std::fmt::Display for RuntimeCustodyBuyProgress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.stage {
            RuntimeCustodyBuyStage::AllowanceApproval
            | RuntimeCustodyBuyStage::PurchaseApproval
                if self.awaits_person() =>
            {
                let what = if matches!(self.stage, RuntimeCustodyBuyStage::AllowanceApproval) {
                    "Allow the payment"
                } else {
                    "Approve this purchase"
                };
                match self
                    .approval
                    .as_ref()
                    .and_then(|approval| approval.connector_id.as_deref())
                {
                    Some(connector) => write!(
                        formatter,
                        "{what} in {connector}; the purchase continues on its own once you do"
                    ),
                    None => write!(
                        formatter,
                        "{what} in your wallet; the purchase continues on its own once you do"
                    ),
                }
            }
            RuntimeCustodyBuyStage::AllowanceApproval
            | RuntimeCustodyBuyStage::PurchaseApproval => {
                write!(
                    formatter,
                    "The wallet approval is still completing; nothing else is needed"
                )
            }
            RuntimeCustodyBuyStage::ChainSettlement => write!(
                formatter,
                "The purchase is approved and waiting for the network to confirm it; nothing \
                 else is needed"
            ),
            RuntimeCustodyBuyStage::AccessEvidence => write!(
                formatter,
                "The purchase is on the network and the copy is being confirmed as yours; \
                 nothing else is needed"
            ),
            RuntimeCustodyBuyStage::Declined => write!(
                formatter,
                "This purchase was declined in the wallet, so it did not go ahead"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyBuyProgress {}

/// Wire identity of the typed answer an app gets when the wallet's transaction
/// default for a chain cannot carry a protected-content transaction.
pub(crate) const RUNTIME_CUSTODY_WALLET_DEFAULT_UNUSABLE_SCHEMA_V1: &str =
    "elastos.protected-content.wallet-default-unusable/v1";

/// Why the wallet's transaction default for one chain cannot be used.
///
/// Five distinct conditions used to share one opaque sentence, so a creator or
/// a buyer was told only that something was unavailable and no app could tell
/// which of the five it was, let alone what to offer. Each arm here names one
/// condition; the sentence in `Display` names the way out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyWalletDefaultReason {
    /// No account is marked as the transaction default on this chain.
    NoTransactionDefaultForChainNamespace,
    /// Two accounts claim the default at the same instant, so neither wins.
    AmbiguousTransactionDefault,
    /// The default names an account the wallet no longer holds on this chain.
    DefaultAccountNotInWallet,
    /// The default cannot produce a signature: an external wallet whose
    /// connector is not linked. A linked one is signable through the handoff.
    DefaultAccountSigningUnavailable,
    /// The default's address is not usable on this chain.
    DefaultAccountAddressInvalid,
}

impl RuntimeCustodyWalletDefaultReason {
    /// Stable machine-readable spelling, shared by the wire answer and the
    /// operator log so the two can never drift apart.
    pub(crate) const fn wire_value(self) -> &'static str {
        match self {
            Self::NoTransactionDefaultForChainNamespace => {
                "no_transaction_default_for_chain_namespace"
            }
            Self::AmbiguousTransactionDefault => "ambiguous_transaction_default",
            Self::DefaultAccountNotInWallet => "default_account_not_in_wallet_for_chain_namespace",
            Self::DefaultAccountSigningUnavailable => "default_account_signing_unavailable",
            Self::DefaultAccountAddressInvalid => "default_account_address_invalid",
        }
    }
}

/// A refusal that carries its reason as data, sibling to
/// [`RuntimeCustodyCreatorMintBlocked`].
///
/// The refusal is unchanged and the opaque top-level sentence still stands
/// outermost, so nothing that matches on it breaks. What this adds is a typed
/// field an app branches on to offer the one action that fixes the state. It
/// carries the chain namespace so the sentence can name the network, and
/// nothing else: no account id, no address, no balance, no terms.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyWalletDefaultUnusable {
    reason: RuntimeCustodyWalletDefaultReason,
    chain_namespace: String,
}

impl RuntimeCustodyWalletDefaultUnusable {
    pub(crate) fn new(reason: RuntimeCustodyWalletDefaultReason, chain_namespace: &str) -> Self {
        Self {
            reason,
            chain_namespace: chain_namespace.to_string(),
        }
    }

    pub(crate) const fn reason(&self) -> RuntimeCustodyWalletDefaultReason {
        self.reason
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        self.reason.wire_value()
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({
            "schema": RUNTIME_CUSTODY_WALLET_DEFAULT_UNUSABLE_SCHEMA_V1,
            "reason": self.reason.wire_value(),
            "chain_namespace": self.chain_namespace,
        })
    }
}

impl std::fmt::Display for RuntimeCustodyWalletDefaultUnusable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let network = &self.chain_namespace;
        match self.reason {
            RuntimeCustodyWalletDefaultReason::NoTransactionDefaultForChainNamespace => write!(
                formatter,
                "No account is set as the transaction default for {network}; set one in Wallet, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::AmbiguousTransactionDefault => write!(
                formatter,
                "More than one account claims the transaction default for {network}; set a single default in Wallet, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::DefaultAccountNotInWallet => write!(
                formatter,
                "The transaction default for {network} names an account this wallet no longer holds; set a current account as the default in Wallet, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::DefaultAccountSigningUnavailable => write!(
                formatter,
                "The transaction default for {network} is an external wallet with no connector linked, so it cannot sign; link it in Wallet, or set a built-in account as the default, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::DefaultAccountAddressInvalid => write!(
                formatter,
                "The transaction default for {network} has an address this network cannot use; set an account on {network} as the default in Wallet, then try again"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyWalletDefaultUnusable {}

/// Wire identity of the typed answer an app gets when a mint already under way
/// is bound to an account that is no longer the wallet's transaction default.
pub(crate) const RUNTIME_CUSTODY_CREATOR_WALLET_DRIFT_SCHEMA_V1: &str =
    "elastos.protected-content.creator-wallet-drift/v1";

/// A mint already under way names one account, and the wallet now names
/// another as its transaction default for that chain.
///
/// The recorded account wins — a retry must not switch payer mid-flight, which
/// is what makes an effect identity durable (PRINCIPLES.md 19). The defect this
/// answers is not the pinning; it is the *silence*. Before this, changing the
/// transaction default and re-publishing the same object completed the mint on
/// the old account with nothing said, so a creator who had deliberately
/// switched wallets was told only that the listing succeeded.
///
/// So the refusal is the honest move (PRINCIPLES.md 11): stop, name both
/// accounts, and give the two ways out — drop the recorded terms and start over
/// on the current default, or set the recorded account back as the default.
///
/// Unlike [`RuntimeCustodyWalletDefaultUnusable`], this one does carry
/// addresses. It has to: the whole refusal is "these two differ", and an app
/// that cannot say which two has nothing to show. They are the creator's own
/// accounts, returned to the creator's own authenticated session, and the
/// Wallet surface already displays both. They stay out of the operator log all
/// the same — `reason_label` is the only thing logged.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyCreatorWalletDrift {
    chain_namespace: String,
    bound_address: String,
    default_address: String,
}

impl RuntimeCustodyCreatorWalletDrift {
    pub(crate) fn new(chain_namespace: &str, bound_address: &str, default_address: &str) -> Self {
        Self {
            chain_namespace: chain_namespace.to_string(),
            bound_address: bound_address.to_ascii_lowercase(),
            default_address: default_address.to_ascii_lowercase(),
        }
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        "creator_mint_bound_account_is_not_the_transaction_default"
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({
            "schema": RUNTIME_CUSTODY_CREATOR_WALLET_DRIFT_SCHEMA_V1,
            "reason": self.reason_label(),
            "chain_namespace": self.chain_namespace,
            "bound_address": self.bound_address,
            "default_address": self.default_address,
        })
    }
}

impl std::fmt::Display for RuntimeCustodyCreatorWalletDrift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "This mint is already bound to {bound} from an earlier attempt, but the transaction \
             default for {network} is now {default}. A mint keeps the account it started with, so \
             finish it by setting {bound} back as the default, or discard the recorded terms for \
             this object and protect it again on {default}",
            bound = self.bound_address,
            network = self.chain_namespace,
            default = self.default_address,
        )
    }
}

impl std::error::Error for RuntimeCustodyCreatorWalletDrift {}

/// Wire identity of the progress an app renders while a creator publish runs.
pub(crate) const RUNTIME_CUSTODY_CREATOR_PROGRESS_SCHEMA_V1: &str =
    "elastos.protected-content.creator-progress/v1";

/// How far a creator publish has actually got, read from the mint journal.
///
/// The Creator used to show four dots it drove itself, one of them labelled
/// "(not tracked)" because the client had no way to know: the whole
/// server-side pipeline happened inside one request, so "encrypt" went active
/// when the request was sent and "assemble" went done when it returned, and
/// the publish step in between was a guess dressed as a stage.
///
/// Every state here is evidence the journal already holds, so this cannot
/// drift from what the server actually did (PRINCIPLES.md 12) -- there is no
/// second source of truth to keep in step, only a projection of the first:
///
/// * `escrow`  the custody envelope. The mint record exists at all only once
///   protection produced an encrypted content identity, so reaching this
///   function means encryption is done; `custody_terminal` says whether the
///   2-of-3 envelope settled or aborted.
/// * `publish` the ciphertext reaching content availability, which is exactly
///   `content_availability` -- a verified receipt, not a hopeful one. This is
///   the stage that was untracked.
/// * `public_metadata` the mint's metadata reaching the public IPFS store
///   before a new approval. Nothing about it is persisted, so the journal
///   alone says only `pending` (no terms recorded), `done` (settled) or
///   `active`; the creator tail, which knows, says `done` once an approval
///   exists and `failed` when the publication failed
///   ([`runtime_custody_creator_progress_with_public_metadata`]).
/// * `listing` the chain mint and listing projection, which is the creator
///   state's own three-stage lifecycle.
///
/// The vocabulary is `pending` (has not begun), `active` (running), `done`
/// (durably finished) and `failed` (finished badly). A stage never claims to be
/// running when its input has not arrived, and never claims to be done because
/// it merely stopped.
pub(crate) fn runtime_custody_creator_progress(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
) -> Value {
    creator_progress(mint, None, false)
}

/// What the creator tail knows about the `public_metadata` stage that the
/// journal does not record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyPublicMetadataStage {
    /// An approval exists: its metadata was published before it was raised,
    /// or it settles under the authority it already has.
    Done,
    /// The publication, or the approval phase's admission, failed.
    Failed,
}

/// [`runtime_custody_creator_progress`] with the `public_metadata` stage the
/// creator tail established.
pub(crate) fn runtime_custody_creator_progress_with_public_metadata(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    stage: RuntimeCustodyPublicMetadataStage,
) -> Value {
    creator_progress(mint, Some(stage), false)
}

pub(crate) fn creator_listing_awaiting_seal_finality(
    mint: &PersistedRuntimeMint,
) -> RuntimeCustodyEffectPending {
    RuntimeCustodyEffectPending::awaiting_chain_settlement().with_progress(creator_progress(
        mint,
        Some(RuntimeCustodyPublicMetadataStage::Done),
        true,
    ))
}

fn creator_progress(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    public_metadata: Option<RuntimeCustodyPublicMetadataStage>,
    listing_awaiting_seal: bool,
) -> Value {
    use elastos_protected_content_runtime::RuntimeCustodyTerminalKind;

    // A terminal is not a success. `custody_terminal` is `Some` for an aborted
    // partial provision too, and reporting that as "done" told a creator their
    // escrow had settled at the exact moment the mint became unrecoverable.
    let escrow = match mint.custody_terminal() {
        Some(RuntimeCustodyTerminalKind::CustodyProvisioned) => "done",
        Some(RuntimeCustodyTerminalKind::AbortedPartialProvision) => "failed",
        None => "active",
    };
    // Availability work begins only once the envelope has settled, so before
    // that this stage has not started. Saying "active" for work that has not
    // begun — and for work that now never will — is the same untruth one stage
    // along.
    let publish = match (escrow, mint.content_availability().is_some()) {
        (_, true) => "done",
        ("done", false) => "active",
        _ => "pending",
    };
    let listing = match mint
        .creator_state()
        .map(elastos_protected_content_runtime::RuntimeMintCreatorState::stage)
    {
        None => "pending",
        Some(elastos_protected_content_runtime::RuntimeMintCreatorStage::Settled)
            if !listing_awaiting_seal =>
        {
            "done"
        }
        Some(_) => "active",
    };
    let public_metadata = match public_metadata {
        Some(RuntimeCustodyPublicMetadataStage::Done) => "done",
        Some(RuntimeCustodyPublicMetadataStage::Failed) => "failed",
        // The journal's view: it starts once terms are recorded, and a raised
        // wallet effect proves it done, since an approval is raised only after
        // the publication (STAB-01 / D1: the step ends once the roots are
        // pinned). Only between the terms and the effect is there no evidence.
        None => match mint
            .creator_state()
            .map(elastos_protected_content_runtime::RuntimeMintCreatorState::stage)
        {
            None => "pending",
            Some(elastos_protected_content_runtime::RuntimeMintCreatorStage::Recorded) => "active",
            Some(
                elastos_protected_content_runtime::RuntimeMintCreatorStage::EffectRaised
                | elastos_protected_content_runtime::RuntimeMintCreatorStage::Settled,
            ) => "done",
        },
    };
    json!({
        "schema": RUNTIME_CUSTODY_CREATOR_PROGRESS_SCHEMA_V1,
        "stages": [
            { "id": "escrow", "state": escrow },
            { "id": "publish", "state": publish },
            { "id": "public_metadata", "state": public_metadata },
            { "id": "listing", "state": listing },
        ],
    })
}

/// Wire identity of the typed answer an app gets while a protected-content
/// effect is still outstanding.
pub(crate) const RUNTIME_CUSTODY_EFFECT_PENDING_SCHEMA_V1: &str =
    "elastos.protected-content.effect-pending/v1";

/// What an outstanding effect is actually waiting for.
///
/// The distinction is the whole point: one of these needs the person to do
/// something and the other needs them to do nothing at all. Collapsing both
/// into "pending" is why the Creator told a creator to approve a transaction
/// they had already approved, while the real wait was chain evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyEffectPendingReason {
    /// The wallet approval has not completed. A managed account completes this
    /// in place; an external one is waiting on its connector, which means it is
    /// waiting on the person.
    WalletApproval,
    /// The approval is done and the chain has not yet produced the evidence the
    /// operation needs. Nobody can hurry it and nobody need act.
    ChainSettlement,
}

impl RuntimeCustodyEffectPendingReason {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::WalletApproval => "wallet_approval",
            Self::ChainSettlement => "chain_settlement",
        }
    }
}

/// A non-terminal waiting state, carried as data rather than prose.
///
/// Apps used to detect this by matching the English word "pending" in the
/// message. That is the same defect class as the opaque refusal it sits next
/// to: control flow decided by a sentence that exists to be read by a person,
/// and that no test pins. This carries the reason instead, plus enough about
/// the signer for an app to say whose turn it is -- and, when the answer is
/// "nobody's", to stop asking the creator to click anything.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyEffectPending {
    reason: RuntimeCustodyEffectPendingReason,
    /// Who is being waited on, and only where that is a fact worth stating.
    ///
    /// `None` for a chain wait: the signer has already done everything asked of
    /// them, so naming them would answer a question nobody is asking — and the
    /// site that raises a chain wait genuinely does not have the account in
    /// hand, so a default here would be an invention rather than a fact.
    signer: Option<RuntimeCustodyEffectPendingSigner>,
    /// How far the operation has got, when the raising site knows. This rides
    /// the pending answer rather than a channel of its own because the pending
    /// answer IS the poll response: an app waiting on a publish has exactly one
    /// thing arriving, and a second transport for progress would be a second
    /// thing to keep in step with it.
    progress: Option<Value>,
}

#[derive(Debug, Clone)]
struct RuntimeCustodyEffectPendingSigner {
    /// True when the signer is an external wallet reached through a connector,
    /// so the outstanding approval needs the person to act in that connector.
    external: bool,
    /// Names the connector when there is one, so an app can say "MetaMask"
    /// rather than "your wallet". A connector id is a local wallet-surface
    /// identifier, not a secret and not an account.
    connector_id: Option<String>,
}

impl RuntimeCustodyEffectPending {
    /// Waiting on the wallet approval, which is the only wait that can need a
    /// person.
    pub(crate) fn awaiting_wallet_approval(
        external_signer: bool,
        connector_id: Option<&str>,
    ) -> Self {
        Self {
            reason: RuntimeCustodyEffectPendingReason::WalletApproval,
            signer: Some(RuntimeCustodyEffectPendingSigner {
                external: external_signer,
                connector_id: connector_id.map(ToString::to_string),
            }),
            progress: None,
        }
    }

    /// Approved already; waiting on the chain. Never needs a person.
    pub(crate) const fn awaiting_chain_settlement() -> Self {
        Self {
            reason: RuntimeCustodyEffectPendingReason::ChainSettlement,
            signer: None,
            progress: None,
        }
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        self.reason.wire_value()
    }

    /// Whether the person has to do something, or the operation is simply
    /// waiting. An app polls in both cases; only one of them asks anything of
    /// the creator.
    pub(crate) const fn awaits_person(&self) -> bool {
        match self.signer {
            Some(ref signer) => {
                matches!(
                    self.reason,
                    RuntimeCustodyEffectPendingReason::WalletApproval
                ) && signer.external
            }
            None => false,
        }
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_EFFECT_PENDING_SCHEMA_V1,
            "reason": self.reason.wire_value(),
            "awaits_person": self.awaits_person(),
        });
        if let Some(signer) = self.signer.as_ref() {
            answer["external_signer"] = Value::Bool(signer.external);
            answer["connector_id"] = signer
                .connector_id
                .as_ref()
                .map_or(Value::Null, |id| Value::String(id.clone()));
        }
        if let Some(progress) = self.progress.as_ref() {
            answer["progress"] = progress.clone();
        }
        answer
    }

    /// Attach how far the publish has got. Only the sites that have the mint
    /// record in hand can say, and one of them (the chain-provider answer)
    /// cannot -- so this is opt-in rather than a constructor argument that
    /// would have to be filled with a guess.
    #[must_use]
    pub(crate) fn with_progress(mut self, progress: Value) -> Self {
        self.progress = Some(progress);
        self
    }
}

impl std::fmt::Display for RuntimeCustodyEffectPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            RuntimeCustodyEffectPendingReason::ChainSettlement => write!(
                formatter,
                "The transaction is approved and waiting for the network to confirm it; nothing \
                 else is needed"
            ),
            RuntimeCustodyEffectPendingReason::WalletApproval if self.awaits_person() => match self
                .signer
                .as_ref()
                .and_then(|signer| signer.connector_id.as_deref())
            {
                Some(connector) => write!(
                    formatter,
                    "Approve this transaction in {connector}; the listing continues on its own \
                         once you do"
                ),
                None => write!(
                    formatter,
                    "Approve this transaction in your wallet; the listing continues on its own \
                         once you do"
                ),
            },
            RuntimeCustodyEffectPendingReason::WalletApproval => write!(
                formatter,
                "The wallet approval is still completing; nothing else is needed"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyEffectPending {}

/// How far the publish of this object has actually got, read from the journal.
///
/// A creator watches one blocking request for the whole of a publish, so the
/// page can only guess which stage it is in, and it guesses the first one --
/// which is why a long content publish reads as a stalled "Encrypt & escrow"
/// when escrow finished in milliseconds. The journal has known better the
/// whole time: it records custody as provisioned before the publish begins,
/// and the same projection the creator tail returns can be read from it by
/// anyone, at any point, without touching the request that is in flight.
///
/// Answers `None` when this object has no mint intent, and in the brief window
/// where an intent exists but no record does -- there is genuinely nothing to
/// report yet, and inventing a stage would be the same guess in a new place.
///
/// The principal is the verified caller's, bound by the gateway before this is
/// reached, and the intent id derives from it -- so this cannot read another
/// principal's publish. Nothing here is an entitlement: it reports progress,
/// grants nothing, and takes no wallet authority.
pub(crate) fn runtime_custody_publish_progress(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<Option<Value>> {
    Ok(
        runtime_custody_open_mint_for_source(data_dir, principal_id, object_uri, source_storage)?
            .as_ref()
            .map(runtime_custody_creator_progress),
    )
}

pub(crate) const RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE: &str =
    "Runtime custody mint requires cleanup reconciliation";

/// The protect request of the source's current attempt went out and its
/// outcome is unknown. Typed so Creator offers Start over on it.
fn runtime_custody_dispatch_uncertain() -> anyhow::Error {
    RuntimeCustodyAttemptConflict::error(RuntimeCustodyAttemptConflictReason::DispatchUncertain)
}

/// What the creator sees when the encoder wrote more slices per frame than the
/// protection can describe. It is the outermost error of the mint, so Creator
/// shows it as it is.
pub(crate) const RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE: &str =
    "This video has too many slices per frame; re-encode it with fewer slices.";

/// Said of a prepared or protected part over its limit (the provider's own
/// wording for a clear part).
const RUNTIME_CUSTODY_MEDIA_PART_TOO_LARGE_MESSAGE: &str =
    "a prepared media part exceeds the 2 MiB part limit";

pub(crate) const RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE: &str =
    "Runtime custody mint was settled before draft persistence";

const CHAIN_PROVIDER_CONFIG_FILE: &str = "protected-content/chain-provider.json";

pub const PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1: &str =
    "elastos.protected-content.chain-provider-config/v1";

pub(super) const MAX_CHAIN_PROVIDER_CONFIG_BYTES: usize = 64 * 1024;

pub(crate) const PROTECTED_CONTENT_OBJECT_EPC1_PATH: &str = "protected-content/v1/object.epc1";

pub(super) const PROTECTED_CONTENT_OBJECT_MANIFEST_PATH: &str =
    "protected-content/v1/manifest.json";

const PROTECTED_CONTENT_OBJECT_MANIFEST_SCHEMA_V1: &str =
    "elastos.protected-content.object-manifest/v1";

const PROTECTED_CONTENT_V2_IDENTITY_PATH: &str = "protected-content/v2/identity.bin";

const PROTECTED_CONTENT_V2_MPD_PATH: &str = "protected-content/v2/stream.mpd";

/// The largest protected segment a v2 read fetches and a v2 mint accepts (the
/// manifest check enforces it on every listing): the
/// decrypt answer echoes the encrypted segment and the clear part as JSON
/// number arrays (4 characters per byte at worst), so `8 * cap` plus at most
/// 16 KiB of proof, keys and ids must stay under the 16 MiB provider frame.
/// `2 MiB - 32 KiB` leaves 256 KiB for that overhead.
pub(crate) const MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2: usize = 2 * 1024 * 1024 - 32 * 1024;

/// Whether a receipt's status proves the copies `requirement` asks for. A
/// single required copy is proven by this Home's verified pin, announced over
/// Carrier or not.
pub(super) fn protected_content_availability_status_accepted(
    status: &str,
    requirement: &RuntimeContentAvailabilityRequirement,
) -> bool {
    status == PROTECTED_CONTENT_AVAILABLE_STATUS
        || (!protected_content_live_proof_required(requirement.minimum_replicas())
            && matches!(status, "carrier_announced" | "local_pinned"))
}

pub(super) const CHAIN_PROTECTED_CONTENT_POLICY_OP: &str = "resolve_protected_content_policy";

pub(super) const CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1: &str =
    "elastos.chain.protected-content-policy/v1";

pub(super) const MEDIA_PROVIDER_PREPARED_DIR_NAME: &str = "prepared";

pub(super) const MEDIA_PROVIDER_SEGMENTS_DIR_NAME: &str = "segments";

pub(super) const RUNTIME_MEDIA_PREPARATION_RECEIPT_DOMAIN: &[u8] =
    b"elastos.protected-content.runtime-media-preparation-receipt/v1";

pub(crate) struct ResolvedRuntimeRightsPolicy {
    pub(super) body: RightsPolicyBodyV1,
    pub(super) identity: RightsPolicyIdentityV1,
}

impl ResolvedRuntimeRightsPolicy {
    pub(crate) fn body(&self) -> &RightsPolicyBodyV1 {
        &self.body
    }

    pub(crate) fn identity(&self) -> &RightsPolicyIdentityV1 {
        &self.identity
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainProtectedContentPolicyResponse {
    schema: String,
    policy_body: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProtectedContentChainProviderConfigFile {
    schema: String,
    protected_content_network: Value,
}

#[derive(Clone)]
pub struct RuntimeProtectedContentChainProviderConfig {
    protected_content_network: Value,
}

impl RuntimeProtectedContentChainProviderConfig {
    pub fn protected_content_network(&self) -> &Value {
        &self.protected_content_network
    }
}

pub(crate) fn runtime_mint_journal_root(data_dir: &Path) -> PathBuf {
    data_dir.join(RUNTIME_MINT_JOURNAL_ROOT)
}

pub(crate) fn runtime_mint_journal(data_dir: &Path) -> RuntimeMintJournal {
    RuntimeMintJournal::new(runtime_mint_journal_root(data_dir))
}

fn generate_runtime_content_access_id() -> anyhow::Result<ContentAccessIdV1> {
    loop {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        if let Ok(value) = ContentAccessIdV1::new(bytes) {
            return Ok(value);
        }
    }
}

pub(super) fn runtime_mint_intent_with_access_id(
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<RuntimeMintIntent> {
    RuntimeMintIntent::new_media_dash(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.media.preparation_receipt(),
        runtime_mint_media_renditions(&input.media),
        content_access_id,
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        selected_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))
}

pub(super) fn load_or_persist_runtime_mint_intent(
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
    required_completion: Option<Digest32>,
) -> anyhow::Result<RuntimeMintIntent> {
    // The source's current attempt: a new one once an earlier attempt was
    // archived, so a new mint never meets the identity of an archived one.
    let attempt = journal
        .current_attempt(
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    match journal.load_intent(attempt.request_id()) {
        Ok(existing) => {
            let expected = runtime_mint_intent_with_access_id(
                composition,
                input,
                selected_nodes,
                existing.content_access_id(),
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            if !existing.same_authority_as(&expected)
                || (required_completion.is_some()
                    && existing.completed_mint_id() != required_completion)
            {
                return Err(RuntimeCustodyAttemptConflict::error(
                    RuntimeCustodyAttemptConflictReason::AuthorityChanged,
                ));
            }
            Ok(existing)
        }
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound)
            if required_completion.is_none() =>
        {
            let intent = runtime_mint_intent_with_access_id(
                composition,
                input,
                selected_nodes,
                generate_runtime_content_access_id()?,
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            journal
                .persist_intent(&intent)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))
        }
        Err(_) => Err(anyhow::anyhow!(
            "Runtime custody mint intent is unavailable"
        )),
    }
}

fn runtime_mint_intent_with_access_id_object(
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<RuntimeMintIntent> {
    RuntimeMintIntent::new_object(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.content_type.clone(),
        &input.clear_plaintext,
        content_access_id,
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        selected_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))
}

fn load_or_persist_runtime_mint_intent_object(
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
    required_completion: Option<Digest32>,
) -> anyhow::Result<RuntimeMintIntent> {
    // The source's current attempt: a new one once an earlier attempt was
    // archived, so a new mint never meets the identity of an archived one.
    let attempt = journal
        .current_attempt(
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    match journal.load_intent(attempt.request_id()) {
        Ok(existing) => {
            let expected = runtime_mint_intent_with_access_id_object(
                composition,
                input,
                selected_nodes,
                existing.content_access_id(),
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            if !existing.same_authority_as(&expected)
                || (required_completion.is_some()
                    && existing.completed_mint_id() != required_completion)
            {
                return Err(RuntimeCustodyAttemptConflict::error(
                    RuntimeCustodyAttemptConflictReason::AuthorityChanged,
                ));
            }
            Ok(existing)
        }
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound)
            if required_completion.is_none() =>
        {
            let intent = runtime_mint_intent_with_access_id_object(
                composition,
                input,
                selected_nodes,
                generate_runtime_content_access_id()?,
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            journal
                .persist_intent(&intent)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))
        }
        Err(_) => Err(anyhow::anyhow!(
            "Runtime custody mint intent is unavailable"
        )),
    }
}

pub(super) fn load_completed_runtime_mint_facts(
    journal: &RuntimeMintJournal,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_id: Digest32,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let persisted = journal
        .load(mint_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let evidence = persisted
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let content_id = runtime_protected_content_id(persisted.draft().encrypted_content())?;
    Ok(runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        persisted.draft(),
        &content_id,
        evidence,
    ))
}

fn load_completed_runtime_mint_object_facts(
    journal: &RuntimeMintJournal,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    mint_id: Digest32,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let persisted = journal
        .load(mint_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let evidence = persisted
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let content_id = runtime_protected_content_id(persisted.draft().encrypted_content())?;
    Ok(runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        persisted.draft(),
        &content_id,
        evidence,
    ))
}

/// A crash between the protect session's close settlement and
/// `mark_intent_completed` leaves the intent at `SettledBeforeDraft(Closed)`
/// while every durable mint step may already have finished; the deterministic
/// intent identity then bricks the source object permanently (ELACITY-2307).
/// Adopt the finished record when one exists: return its mint id after
/// completing the intent. A record that is not fully terminal cannot be rolled
/// forward (the content key material is gone), so it fails closed for cleanup
/// reconciliation with the orphaned custody evidence logged. No record means
/// nothing durable survived the crash and the terminal abort stands.
pub(super) fn adopt_settled_runtime_mint_record(
    journal: &RuntimeMintJournal,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<Option<Digest32>> {
    let scan = journal
        .find_mint_record_for_intent(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    // Closed attempts cannot be continued, but what they left on the nodes is
    // real and nothing else reports it. Say so every time this intent is looked
    // at, whatever happens next.
    for abandoned in scan.abandoned() {
        tracing::warn!(
            request_id = %hex::encode(mint_intent.request_id().as_bytes()),
            mint_id = %hex::encode(abandoned.mint_id.as_bytes()),
            node_receipts_accepted = abandoned.accepted_orphan_count,
            nodes_possibly_holding_a_share = abandoned.uncertain_node_count,
            "abandoned runtime custody mint attempt left custody state on nodes; cleanup reconciliation required"
        );
    }
    let Some(record) = scan.open() else {
        // Every attempt for this intent is closed, so a fresh one is the only
        // way forward and is safe: new shares seal against a new envelope and
        // cannot combine with what any earlier attempt left behind.
        return Ok(None);
    };
    let fully_terminal = record.custody_terminal()
        == Some(RuntimeCustodyTerminalKind::CustodyProvisioned)
        && record.content_availability().is_some();
    if fully_terminal {
        let mint_id = record.draft().mint_id();
        journal
            .mark_intent_completed(mint_intent.request_id(), mint_id)
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        return Ok(Some(mint_id));
    }
    // This attempt can never finish -- its content key material did not outlive
    // the request that made it -- so keeping the record only wedges the object
    // it was minted from. Every later attempt on that path would find this
    // record, refuse to treat it as a candidate, and fail the same way forever.
    // Forget it instead, and say once what it left behind.
    //
    // Safe for what follows: a fresh attempt seals new shares against a new
    // envelope and cannot combine with anything this one left on the nodes.
    // Those shares open nothing without the envelope and no listing will ever
    // name them, so reclaiming the space is housekeeping, not a precondition.
    let mint_id = record.draft().mint_id();
    tracing::warn!(
        request_id = %hex::encode(mint_intent.request_id().as_bytes()),
        mint_id = %hex::encode(mint_id.as_bytes()),
        custody_terminal = ?record.custody_terminal(),
        content_availability_recorded = record.content_availability().is_some(),
        // What an operator needs is not "did anything start" but what was left
        // behind: shares this Runtime knows are held, and nodes that may be
        // holding one without ever having said so.
        node_receipts_accepted = record.accepted_orphans().len(),
        nodes_possibly_holding_a_share = record.uncertain_node_count(),
        "runtime custody mint attempt cannot finish and was discarded; its custody shares are inert residue"
    );
    journal
        .discard_unfinishable_mint(mint_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(None)
}

fn validate_owner_only_directory_with_error(
    path: &Path,
    label: &str,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| error_fn(format!("{label} is unavailable")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(error_fn(format!("{label} must be an owner-only directory")));
    }
    validate_owner_only_metadata_with_error(label, &metadata, false, error_fn)
}

fn invalid_chain_provider_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("protected-content Chain provider config is missing or unsafe: {reason}")
}

fn runtime_chain_provider_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CHAIN_PROVIDER_CONFIG_FILE)
}

pub fn load_runtime_protected_content_chain_provider_config(
    data_dir: &Path,
) -> anyhow::Result<Option<RuntimeProtectedContentChainProviderConfig>> {
    let config_path = runtime_chain_provider_config_path(data_dir);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            anyhow::bail!(
                "{}",
                invalid_chain_provider_config("config file is unavailable")
            )
        }
    }
    validate_owner_only_protected_content_dir_with_error(data_dir, invalid_chain_provider_config)?;
    let bytes = read_owner_only_protected_content_config_bytes(
        &config_path,
        MAX_CHAIN_PROVIDER_CONFIG_BYTES,
        "Chain provider config file",
        invalid_chain_provider_config,
    )?;
    let config: RuntimeProtectedContentChainProviderConfigFile = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_chain_provider_config("config JSON is invalid"))?;
    if config.schema != PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1
        || !config.protected_content_network.is_object()
    {
        anyhow::bail!(
            "{}",
            invalid_chain_provider_config("config fields are invalid")
        );
    }
    Ok(Some(RuntimeProtectedContentChainProviderConfig {
        protected_content_network: config.protected_content_network,
    }))
}

fn runtime_media_provider_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MEDIA_PROVIDER_CONFIG_FILE)
}

fn runtime_media_provider_root(data_dir: &Path) -> PathBuf {
    runtime_media_provider_config_path(data_dir)
        .parent()
        .expect("media-provider config has a parent")
        .to_path_buf()
}

fn runtime_media_provider_tools_root(data_dir: &Path) -> PathBuf {
    runtime_media_provider_root(data_dir).join("tools")
}

fn runtime_media_provider_staging_root(data_dir: &Path) -> PathBuf {
    runtime_media_provider_root(data_dir).join("staging")
}

pub fn load_runtime_media_provider_bridge_config(
    data_dir: &Path,
) -> anyhow::Result<Option<ProviderConfig>> {
    let config_path = runtime_media_provider_config_path(data_dir);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_media_provider_config("config file is unavailable")),
    }
    validate_owner_only_protected_content_dir_with_error(data_dir, invalid_media_provider_config)?;
    validate_owner_only_directory_with_error(
        &runtime_media_provider_root(data_dir),
        "media-provider root",
        invalid_media_provider_config,
    )?;
    validate_owner_only_directory_with_error(
        &runtime_media_provider_tools_root(data_dir),
        "media-provider tools root",
        invalid_media_provider_config,
    )?;
    validate_owner_only_directory_with_error(
        &runtime_media_provider_staging_root(data_dir),
        "media-provider staging root",
        invalid_media_provider_config,
    )?;
    let bytes = read_owner_only_protected_content_config_bytes(
        &config_path,
        MAX_MEDIA_PROVIDER_CONFIG_BYTES,
        "media-provider config file",
        invalid_media_provider_config,
    )?;
    let raw: RuntimeMediaProviderConfigFile = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_media_provider_config("config JSON is invalid"))?;
    let canonical_root = fs::canonicalize(runtime_media_provider_root(data_dir))
        .map_err(|_| invalid_media_provider_config("provider root is unavailable"))?;
    let expected_tools = canonical_root.join("tools");
    let expected_staging = canonical_root.join("staging");
    let expected_ffmpeg = expected_tools.join("ffmpeg");
    let expected_ffprobe = expected_tools.join("ffprobe");
    if raw.schema != MEDIA_PROVIDER_CONFIG_SCHEMA_V1
        || raw.output_profile != MEDIA_PROVIDER_OUTPUT_PROFILE_V1
        || Path::new(&raw.staging_root) != expected_staging
        || Path::new(&raw.ffmpeg_path) != expected_ffmpeg
        || Path::new(&raw.ffprobe_path) != expected_ffprobe
        || raw.timeout_ms == 0
        || raw.timeout_ms > MEDIA_PROVIDER_TIMEOUT_MS_V1
        || raw.max_stdio_bytes == 0
        || raw.max_stdio_bytes > MEDIA_PROVIDER_MAX_STDIO_BYTES_V1
        || raw.max_input_bytes == 0
        || raw.max_input_bytes > MEDIA_PROVIDER_MAX_INPUT_BYTES_V1
        || raw.max_output_part_bytes == 0
        || raw.max_output_part_bytes > MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1
        || raw.max_duration_secs == 0
        || raw.max_duration_secs > MEDIA_PROVIDER_MAX_DURATION_SECS_V1
        || raw.max_source_width == 0
        || raw.max_source_width > MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1
        || raw.max_source_height == 0
        || raw.max_source_height > MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1
        || raw.max_source_fps == 0
        || raw.max_source_fps > MEDIA_PROVIDER_MAX_SOURCE_FPS_V1
        || raw.max_segment_count == 0
        || raw.max_segment_count > MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1
        || raw.max_total_output_bytes == 0
        || raw.max_total_output_bytes > MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1
        || raw.max_total_output_bytes < raw.max_output_part_bytes
    {
        return Err(invalid_media_provider_config("config fields are invalid"));
    }
    validate_runtime_media_import(&expected_ffmpeg, &expected_tools, "ffmpeg")?;
    validate_runtime_media_import(&expected_ffprobe, &expected_tools, "ffprobe")?;
    Ok(Some(ProviderConfig {
        extra: json!({
            "provider_id": MEDIA_PROVIDER_PROCESS_ID,
            "staging_root": raw.staging_root,
            "ffmpeg_path": raw.ffmpeg_path,
            "ffprobe_path": raw.ffprobe_path,
            "output_profile": raw.output_profile,
            "timeout_ms": raw.timeout_ms,
            "max_stdio_bytes": raw.max_stdio_bytes,
            "max_input_bytes": raw.max_input_bytes,
            "max_output_part_bytes": raw.max_output_part_bytes,
            "max_duration_secs": raw.max_duration_secs,
            "max_source_width": raw.max_source_width,
            "max_source_height": raw.max_source_height,
            "max_source_fps": raw.max_source_fps,
            "max_segment_count": raw.max_segment_count,
            "max_total_output_bytes": raw.max_total_output_bytes,
        }),
        ..Default::default()
    }))
}

/// SHA-256 digests of ffmpeg and ffprobe read from a media-tools archive whose
/// checksum was just verified against the installed signed release manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignedMediaToolDigests {
    pub(crate) ffmpeg: [u8; 32],
    pub(crate) ffprobe: [u8; 32],
}

/// How a supplied pair may relate to an existing private import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediaToolsTrust {
    /// The supplied pair must equal the private import byte for byte.
    MustMatch,
    /// A differing private import is replaced, but only with bytes that hash to
    /// the signed release's digests.
    SignedRelease(SignedMediaToolDigests),
}

/// Whether a private import exists and either tool differs from the supplied pair.
pub(crate) fn runtime_media_import_differs(
    data_dir: &Path,
    tools_dir: &Path,
) -> anyhow::Result<bool> {
    if load_runtime_media_provider_bridge_config(data_dir)?.is_none() {
        return Ok(false);
    }
    let mut ffmpeg = open_runtime_media_tool(tools_dir, "ffmpeg")?;
    let mut ffprobe = open_runtime_media_tool(tools_dir, "ffprobe")?;
    let tools = runtime_media_provider_tools_root(data_dir);
    Ok(
        !runtime_media_tool_matches(&mut ffmpeg, &tools.join("ffmpeg"), "ffmpeg")?
            || !runtime_media_tool_matches(&mut ffprobe, &tools.join("ffprobe"), "ffprobe")?,
    )
}

pub(crate) fn prepare_runtime_media_provider_prerequisite(
    data_dir: &Path,
    tools_dir: &Path,
    trust: MediaToolsTrust,
) -> anyhow::Result<()> {
    // Open the complete supplied pair before creating or changing private state.
    let mut ffmpeg = open_runtime_media_tool(tools_dir, "ffmpeg")?;
    let mut ffprobe = open_runtime_media_tool(tools_dir, "ffprobe")?;
    match fs::symlink_metadata(runtime_media_provider_config_path(data_dir)) {
        Ok(_) => {
            load_runtime_media_provider_bridge_config(data_dir)?.ok_or_else(|| {
                invalid_media_provider_config("config file disappeared during validation")
            })?;
            let tools = runtime_media_provider_tools_root(data_dir);
            if runtime_media_tool_matches(&mut ffmpeg, &tools.join("ffmpeg"), "ffmpeg")?
                && runtime_media_tool_matches(&mut ffprobe, &tools.join("ffprobe"), "ffprobe")?
            {
                return Ok(());
            }
            let MediaToolsTrust::SignedRelease(digests) = trust else {
                return Err(invalid_media_provider_config(
                    "supplied media tools differ from the private imported pair",
                ));
            };
            // The config stores only private paths and operator-tuned limits, so a
            // release upgrade replaces the imported bytes and leaves the config alone.
            #[cfg(unix)]
            {
                let canonical_tools = fs::canonicalize(&tools)
                    .map_err(|_| invalid_media_provider_config("tools root is unavailable"))?;
                replace_runtime_media_pair(
                    &canonical_tools,
                    [
                        ("ffmpeg", &mut ffmpeg, &digests.ffmpeg),
                        ("ffprobe", &mut ffprobe, &digests.ffprobe),
                    ],
                )?;
                load_runtime_media_provider_bridge_config(data_dir)?.ok_or_else(|| {
                    invalid_media_provider_config("config file disappeared after upgrade")
                })?;
            }
            #[cfg(not(unix))]
            let _ = digests;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(invalid_media_provider_config("config file is unavailable")),
    }
    #[cfg(unix)]
    {
        ensure_media_provider_directory(data_dir, "Runtime data root")?;
        ensure_media_provider_directory(
            &protected_content_root(data_dir),
            "protected-content parent",
        )?;
        ensure_media_provider_directory(
            &runtime_media_provider_root(data_dir),
            "media-provider root",
        )?;
        let tools_root = runtime_media_provider_tools_root(data_dir);
        ensure_media_provider_directory(&tools_root, "media-provider tools root")?;
        let staging_root = runtime_media_provider_staging_root(data_dir);
        ensure_media_provider_directory(&staging_root, "media-provider staging root")?;

        let canonical_root = fs::canonicalize(runtime_media_provider_root(data_dir))
            .map_err(|_| invalid_media_provider_config("provider root is unavailable"))?;
        let canonical_tools = fs::canonicalize(&tools_root)
            .map_err(|_| invalid_media_provider_config("tools root is unavailable"))?;
        let canonical_staging = fs::canonicalize(&staging_root)
            .map_err(|_| invalid_media_provider_config("staging root is unavailable"))?;
        if canonical_tools != canonical_root.join("tools")
            || canonical_staging != canonical_root.join("staging")
        {
            return Err(invalid_media_provider_config(
                "private paths escape the provider root",
            ));
        }

        let config_path = runtime_media_provider_config_path(data_dir);
        let mut created_tools = Vec::new();
        let mut config_created = false;
        let result = (|| -> anyhow::Result<()> {
            let ffmpeg_import = import_runtime_media_tool(&canonical_tools, "ffmpeg", &mut ffmpeg)?;
            if ffmpeg_import.created {
                created_tools.push(ffmpeg_import.path.clone());
            }
            let ffprobe_import =
                import_runtime_media_tool(&canonical_tools, "ffprobe", &mut ffprobe)?;
            if ffprobe_import.created {
                created_tools.push(ffprobe_import.path.clone());
            }
            let config = RuntimeMediaProviderConfigFile {
                schema: MEDIA_PROVIDER_CONFIG_SCHEMA_V1.to_string(),
                ffmpeg_path: media_path_string(&ffmpeg_import.path, "ffmpeg")?,
                ffprobe_path: media_path_string(&ffprobe_import.path, "ffprobe")?,
                staging_root: media_path_string(&canonical_staging, "staging")?,
                output_profile: MEDIA_PROVIDER_OUTPUT_PROFILE_V1.to_string(),
                timeout_ms: MEDIA_PROVIDER_TIMEOUT_MS_V1,
                max_stdio_bytes: MEDIA_PROVIDER_MAX_STDIO_BYTES_V1,
                max_input_bytes: MEDIA_PROVIDER_MAX_INPUT_BYTES_V1,
                max_output_part_bytes: MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1,
                max_duration_secs: MEDIA_PROVIDER_MAX_DURATION_SECS_V1,
                max_source_width: MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1,
                max_source_height: MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1,
                max_source_fps: MEDIA_PROVIDER_MAX_SOURCE_FPS_V1,
                max_segment_count: MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1,
                max_total_output_bytes: MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1,
            };
            let mut bytes = serde_json::to_vec_pretty(&config)?;
            bytes.push(b'\n');
            create_private_file_atomically(&config_path, &bytes, 0o600, "config")?;
            config_created = true;
            load_runtime_media_provider_bridge_config(data_dir)?.ok_or_else(|| {
                invalid_media_provider_config("config file disappeared after setup")
            })?;
            Ok(())
        })();
        if result.is_err() {
            if config_created {
                let _ = fs::remove_file(&config_path);
            }
            for path in created_tools {
                let _ = fs::remove_file(path);
            }
            let _ = sync_runtime_storage_parent(&canonical_tools);
            let _ = sync_runtime_storage_parent(&canonical_root);
        }
        result
    }
    #[cfg(not(unix))]
    {
        let _ = (data_dir, ffmpeg, ffprobe);
        anyhow::bail!(
            "owner-only media-provider prerequisite setup is unsupported on this platform"
        )
    }
}

fn media_path_string(path: &Path, label: &str) -> anyhow::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_media_provider_config(format!("{label} path is not valid UTF-8")))
}

#[cfg(unix)]
pub(crate) fn ensure_media_provider_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_owner_only_directory_with_error(path, label, invalid_media_provider_config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).map_err(|_| {
                        invalid_media_provider_config(format!(
                            "{label} parent could not be created"
                        ))
                    })?;
                }
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(path).map_err(|_| {
                invalid_media_provider_config(format!("{label} could not be created"))
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_owner_only_directory_with_error(path, label, invalid_media_provider_config)
        }
        Err(_) => Err(invalid_media_provider_config(format!(
            "{label} is unavailable"
        ))),
    }
}

#[cfg(unix)]
pub(super) fn open_runtime_media_tool(
    tools_dir: &Path,
    name: &str,
) -> anyhow::Result<RuntimeMediaToolSource> {
    let candidate = tools_dir.join(name);
    let literal = if candidate.is_absolute() {
        candidate.clone()
    } else {
        std::env::current_dir()
            .map_err(|_| {
                invalid_media_provider_config(format!("{name} prerequisite is unavailable"))
            })?
            .join(&candidate)
    };
    let file = open_media_source_no_links(&literal, name)?;
    let metadata = file.metadata().map_err(|_| {
        invalid_media_provider_config(format!("{name} prerequisite metadata is unavailable"))
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || mode & 0o022 != 0
        || mode & 0o111 == 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES
    {
        return Err(invalid_media_provider_config(format!(
            "{name} prerequisite is unsafe or exceeds bounds"
        )));
    }
    Ok(RuntimeMediaToolSource {
        file,
        size: metadata.len(),
    })
}

#[cfg(not(unix))]
pub(super) fn open_runtime_media_tool(
    _tools_dir: &Path,
    _name: &str,
) -> anyhow::Result<RuntimeMediaToolSource> {
    anyhow::bail!("owner-only media-provider prerequisite setup is unsupported on this platform")
}

/// Open an absolute source path one directory at a time with `openat` and
/// `O_NOFOLLOW`, so no link anywhere on the path is followed and every checked
/// directory is the one the next step opens from. Callers that need a system link
/// in their own root (macOS /var) canonicalize that root first.
#[cfg(unix)]
fn open_media_source_no_links(literal: &Path, name: &str) -> anyhow::Result<fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let uid = unsafe { libc::geteuid() };
    let open_at = |dir: &fs::File, part: &std::ffi::OsStr, flags: libc::c_int| {
        let part = std::ffi::CString::new(part.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                part.as_ptr(),
                flags | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    };
    let check_dir = |dir: &fs::File, display: &Path| -> anyhow::Result<()> {
        let metadata = dir.metadata().map_err(|_| {
            invalid_media_provider_config(format!("{name} prerequisite parent is unavailable"))
        })?;
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(invalid_media_provider_config(format!(
                "{name} prerequisite parent is unsafe: {} is not owned by you or root. Choose a user-owned location with safe parents",
                display.display()
            )));
        }
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(invalid_media_provider_config(format!(
                "{name} prerequisite parent is unsafe: {} is world-writable. Choose a user-owned location with safe parents",
                display.display()
            )));
        }
        Ok(())
    };

    let parts: Vec<Component> = literal.components().collect();
    let Some((Component::Normal(file_name), dirs)) = parts.split_last() else {
        return Err(invalid_media_provider_config(format!(
            "{name} prerequisite path is invalid"
        )));
    };
    let mut display = PathBuf::from("/");
    let mut dir = fs::File::open("/").map_err(|_| {
        invalid_media_provider_config(format!("{name} prerequisite parent is unavailable"))
    })?;
    check_dir(&dir, &display)?;
    for part in dirs {
        let step = match part {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => continue,
            Component::ParentDir => {
                display.pop();
                std::ffi::OsStr::new("..")
            }
            Component::Normal(part) => {
                display.push(part);
                part
            }
        };
        dir = open_at(&dir, step, libc::O_DIRECTORY).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                invalid_media_provider_config(format!("media-provider prerequisite '{name}' was not found in the supplied tools directory"))
            } else {
                invalid_media_provider_config(format!(
                    "{name} prerequisite parent is unsafe: {} is a symbolic link or not a real directory",
                    display.display()
                ))
            }
        })?;
        check_dir(&dir, &display)?;
    }
    open_at(&dir, file_name, 0).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            invalid_media_provider_config(format!(
                "media-provider prerequisite '{name}' was not found in the supplied tools directory"
            ))
        } else if error.raw_os_error() == Some(libc::ELOOP) {
            invalid_media_provider_config(format!("{name} prerequisite is a symbolic link"))
        } else {
            invalid_media_provider_config(format!("{name} prerequisite is unavailable"))
        }
    })
}

#[cfg(unix)]
fn validate_runtime_media_import(path: &Path, tools_root: &Path, name: &str) -> anyhow::Result<()> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    if canonical != path || canonical.parent() != Some(tools_root) {
        return Err(invalid_media_provider_config(format!(
            "{name} import escapes the tools root"
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || mode != 0o500
        || metadata.len() == 0
        || metadata.len() > MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES
    {
        return Err(invalid_media_provider_config(format!(
            "{name} import is unsafe"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_runtime_media_import(
    _path: &Path,
    _tools_root: &Path,
    _name: &str,
) -> anyhow::Result<()> {
    anyhow::bail!("owner-only media-provider config validation is unsupported on this platform")
}

#[cfg(unix)]
fn import_runtime_media_tool(
    tools_root: &Path,
    name: &str,
    source: &mut RuntimeMediaToolSource,
) -> anyhow::Result<RuntimeMediaToolImport> {
    let destination = tools_root.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            validate_runtime_media_import(&destination, tools_root, name)?;
            if !runtime_media_tool_matches(source, &destination, name)? {
                return Err(invalid_media_provider_config(format!(
                    "{name} import conflicts with the discovered prerequisite"
                )));
            }
            return Ok(RuntimeMediaToolImport {
                path: destination,
                created: false,
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(invalid_media_provider_config(format!(
                "{name} import is unavailable"
            )))
        }
    }

    let temp_path = stage_runtime_media_tool(tools_root, name, source)?;
    let mut published = false;
    let result = (|| -> anyhow::Result<()> {
        fs::hard_link(&temp_path, &destination).map_err(|_| {
            invalid_media_provider_config(format!(
                "{name} import could not be installed atomically"
            ))
        })?;
        published = true;
        fs::remove_file(&temp_path)?;
        sync_runtime_storage_parent(tools_root)?;
        validate_runtime_media_import(&destination, tools_root, name)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        if published {
            let _ = fs::remove_file(&destination);
        }
        return Err(error);
    }
    Ok(RuntimeMediaToolImport {
        path: destination,
        created: true,
    })
}

/// Copy the supplied tool into an fsynced owner-only temporary file beside its destination.
#[cfg(unix)]
fn stage_runtime_media_tool(
    tools_root: &Path,
    name: &str,
    source: &mut RuntimeMediaToolSource,
) -> anyhow::Result<PathBuf> {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let temp_path = tools_root.join(format!(".{name}.tmp-{}", hex::encode(nonce)));
    let mut options = fs::OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(0o500)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temp_path).map_err(|_| {
        invalid_media_provider_config(format!("{name} temporary import could not be created"))
    })?;
    let result = (|| -> anyhow::Result<()> {
        source.file.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(
            &mut std::io::Read::by_ref(&mut source.file)
                .take(MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES + 1),
            &mut file,
        )?;
        if copied != source.size {
            return Err(invalid_media_provider_config(format!(
                "{name} prerequisite changed during import"
            )));
        }
        file.sync_all()?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o500))?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(temp_path)
}

/// Replace the private pair with the signed release's tools. Every staged copy is
/// hashed against the signed digest before any rename, so altered bytes publish
/// nothing. A tool whose private copy already has the signed digest is kept, which
/// also repairs a pair left half-replaced by an interrupted run. Each previous
/// import stays in place until its rename publishes the new bytes.
#[cfg(unix)]
fn replace_runtime_media_pair(
    tools_root: &Path,
    pair: [(&str, &mut RuntimeMediaToolSource, &[u8; 32]); 2],
) -> anyhow::Result<()> {
    let mut staged = Vec::with_capacity(pair.len());
    let result = (|| -> anyhow::Result<()> {
        for (name, source, expected) in pair {
            let destination = tools_root.join(name);
            validate_runtime_media_import(&destination, tools_root, name)?;
            if runtime_media_file_sha256(&destination, name)? == *expected {
                continue;
            }
            let temp_path = stage_runtime_media_tool(tools_root, name, source)?;
            staged.push((name, temp_path.clone(), destination));
            if runtime_media_file_sha256(&temp_path, name)? != *expected {
                return Err(invalid_media_provider_config(format!(
                    "{name} does not match the signed release media tools"
                )));
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        for (_, temp_path, _) in staged {
            let _ = fs::remove_file(temp_path);
        }
        return Err(error);
    }
    for (name, temp_path, destination) in staged {
        if fs::rename(&temp_path, &destination).is_err() {
            let _ = fs::remove_file(&temp_path);
            return Err(invalid_media_provider_config(format!(
                "{name} import could not be replaced atomically"
            )));
        }
        sync_runtime_storage_parent(tools_root)?;
        validate_runtime_media_import(&destination, tools_root, name)?;
    }
    Ok(())
}

#[cfg(unix)]
fn runtime_media_file_sha256(path: &Path, name: &str) -> anyhow::Result<[u8; 32]> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(
        &mut file.take(MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES + 1),
        &mut hasher,
    )?;
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
fn runtime_media_tool_matches(
    source: &mut RuntimeMediaToolSource,
    destination: &Path,
    name: &str,
) -> anyhow::Result<bool> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut imported = options
        .open(destination)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    if imported.metadata()?.len() != source.size {
        return Ok(false);
    }
    source.file.seek(SeekFrom::Start(0))?;
    let mut source_reader = std::io::Read::by_ref(&mut source.file).take(source.size + 1);
    let mut imported_reader = std::io::Read::by_ref(&mut imported).take(source.size + 1);
    let mut source_buffer = [0u8; 64 * 1024];
    let mut imported_buffer = [0u8; 64 * 1024];
    loop {
        let source_read = source_reader.read(&mut source_buffer)?;
        let imported_read = imported_reader.read(&mut imported_buffer)?;
        if source_read != imported_read
            || source_buffer[..source_read] != imported_buffer[..imported_read]
        {
            return Ok(false);
        }
        if source_read == 0 {
            return Ok(true);
        }
    }
}

#[cfg(unix)]
pub(super) fn create_private_file_atomically(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    label: &str,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_media_provider_config(format!("{label} parent is unavailable")))?;
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let temp_path = parent.join(format!(".{label}.tmp-{}", hex::encode(nonce)));
    let mut options = fs::OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temp_path).map_err(|_| {
        invalid_media_provider_config(format!("{label} temporary file could not be created"))
    })?;
    let mut published = false;
    let result = (|| -> anyhow::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temp_path, path)
            .map_err(|_| invalid_media_provider_config(format!("{label} appeared during setup")))?;
        published = true;
        fs::remove_file(&temp_path)?;
        sync_runtime_storage_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
        if published {
            let _ = fs::remove_file(path);
        }
    }
    result
}

fn runtime_protected_content_identity_hex(
    encrypted_content: &EncryptedContentIdentityV1,
) -> anyhow::Result<String> {
    Ok(format!(
        "0x{}",
        hex::encode(
            encrypted_content
                .canonical_bytes()
                .map_err(|_| anyhow::anyhow!("protected content identity is invalid"))?
        )
    ))
}

pub(super) fn runtime_content_access_id_hex(content_access_id: ContentAccessIdV1) -> String {
    format!("0x{}", hex::encode(content_access_id.as_bytes()))
}

pub(crate) async fn resolve_runtime_rights_policy(
    registry: &ProviderRegistry,
    encrypted_content: &EncryptedContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    action: RightsActionV1,
) -> anyhow::Result<ResolvedRuntimeRightsPolicy> {
    resolve_runtime_rights_policy_for_item(
        registry,
        encrypted_content,
        content_access_id,
        action,
        None,
    )
    .await
}

pub(super) async fn resolve_runtime_rights_policy_for_item(
    registry: &ProviderRegistry,
    encrypted_content: &EncryptedContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    action: RightsActionV1,
    expected_item: Option<elastos_protected_content_contracts::RightsExpectedItemV1>,
) -> anyhow::Result<ResolvedRuntimeRightsPolicy> {
    let mut request = json!({
        "op": CHAIN_PROTECTED_CONTENT_POLICY_OP,
        "encrypted_content": runtime_protected_content_identity_hex(encrypted_content)?,
        "content_access_id": runtime_content_access_id_hex(content_access_id),
        "action": runtime_rights_action_name(action),
    });
    if let Some(item) = expected_item {
        let token_id = hex::encode(item.token_id());
        request["expected_item"] = json!({
            "channel": format!("0x{}", hex::encode(item.channel().as_bytes())),
            "token_id": format!("0x{}", token_id.trim_start_matches('0')),
            "creator": format!("0x{}", hex::encode(item.creator().as_bytes())),
        });
    }
    let response_value = invoke_json_provider_classified(
        registry,
        CHAIN_PROVIDER_ID,
        CHAIN_PROTECTED_CONTENT_POLICY_OP,
        request,
        ProviderInvocationTransport::Local,
    )
    .await
    .map_err(|failure| match failure {
        ProviderInvocationFailure::Refused { ref code, .. }
            if expected_item.is_some() && code == "item_binding_not_final" =>
        {
            anyhow::Error::new(RuntimeMintSealAwaitingFinality)
        }
        failure => anyhow::Error::msg(
            failure.into_message(CHAIN_PROVIDER_ID, CHAIN_PROTECTED_CONTENT_POLICY_OP),
        ),
    })?;
    let response = serde_json::from_value::<ChainProtectedContentPolicyResponse>(response_value)?;
    if response.schema != CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1 {
        anyhow::bail!("chain provider returned an unsupported protected-content policy schema");
    }
    let policy_bytes = decode_0x_hex(&response.policy_body).ok_or_else(|| {
        anyhow::anyhow!("chain provider returned an invalid protected-content policy body")
    })?;
    let body = RightsPolicyBodyV1::from_canonical_bytes(&policy_bytes)?;
    if body.encrypted_content() != encrypted_content
        || body.content_access_id() != content_access_id
        || body.required_action() != action
        || body.expected_item() != expected_item
    {
        anyhow::bail!(
            "chain provider returned a protected-content policy that does not match the Runtime request"
        );
    }
    let identity = body.policy_identity()?;
    Ok(ResolvedRuntimeRightsPolicy { body, identity })
}

#[derive(Debug)]
pub(crate) struct RuntimeMintSealAwaitingFinality;

impl std::fmt::Display for RuntimeMintSealAwaitingFinality {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the mint's key binding is waiting for chain finality")
    }
}

impl std::error::Error for RuntimeMintSealAwaitingFinality {}

pub(crate) async fn ensure_finalized_mint_policy(
    registry: &ProviderRegistry,
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    terminal: &RuntimeMintCreatorTerminalEvidence,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeSealedRightsPolicyV1> {
    use elastos_protected_content_runtime::{
        seal_persisted_mint_rights_policy, RuntimeMintedItemV1, RuntimeSealedPolicyStoreV1,
    };

    anyhow::ensure!(
        mint.creator_state()
            .and_then(RuntimeMintCreatorState::terminal)
            == Some(terminal),
        "Runtime custody mint is not settled for the requested item"
    );
    let store =
        RuntimeSealedPolicyStoreV1::new(protected_content_root(data_dir).join("policy-seals"));
    if let Some(seal) = store.load_for_mint(mint, terminal.seller())? {
        return Ok(seal);
    }

    let item = RuntimeMintedItemV1::from_creator_terminal(terminal)?;
    let draft = mint.draft();
    let resolved = resolve_runtime_rights_policy_for_item(
        registry,
        draft.encrypted_content(),
        draft.content_access_id(),
        RightsActionV1::View,
        Some(item.expected_item()),
    )
    .await?;
    let seal = seal_persisted_mint_rights_policy(
        mint,
        terminal.seller(),
        &resolved.body().unsealed(),
        resolved.body(),
    )?;
    Ok(store.persist(&seal)?)
}

/// Which publisher a content object's manifest must name (D16, R40). Chosen
/// by the caller, which knows the listing's origin; never inferred from the
/// requirement's DID method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeManifestPublisherBinding {
    /// The manifest names exactly the publisher the requirement expects: the
    /// Runtime profile (`did:key`) the content was published under. Every
    /// package this Runtime or another one published (`LocalCreator`,
    /// `Imported`), and every publish.
    Exact,
    /// A listing adopted from a shared `metadata.json` (origin `Asset`) only.
    /// Its publisher is a `did:pkh` taken from the document, and it is
    /// ATTRIBUTION ONLY: it names the chain account the document states and
    /// authorizes nothing. The content object's manifest names the Runtime
    /// profile that published the bytes -- another namespace, with no mapping
    /// to the `did:pkh` -- so the manifest must name a well-formed `did:key`;
    /// the receipt, which the content plane binds to the publisher the
    /// `ensure` names, is what agrees with the requirement, and the bytes are
    /// bound by the content identity the document carries.
    AdoptedAttribution,
}

impl RuntimeManifestPublisherBinding {
    /// The binding a listing of this origin is verified under.
    pub(crate) fn for_origin(origin: &RuntimeCustodyListingOrigin) -> Self {
        match origin {
            RuntimeCustodyListingOrigin::Asset { .. }
            | RuntimeCustodyListingOrigin::Granted { .. } => Self::AdoptedAttribution,
            RuntimeCustodyListingOrigin::LocalCreator { .. }
            | RuntimeCustodyListingOrigin::Imported { .. } => Self::Exact,
        }
    }
}

/// Whether a content object's own manifest names the publisher an
/// availability requirement expects, under `binding` (R40).
pub(super) fn content_manifest_binds_publisher(
    manifest: &crate::content::ContentObjectManifest,
    requirement: &RuntimeContentAvailabilityRequirement,
    binding: RuntimeManifestPublisherBinding,
) -> bool {
    let expected = requirement.expected_publisher_did();
    match binding {
        RuntimeManifestPublisherBinding::Exact => {
            manifest.publisher_did.as_deref() == Some(expected)
        }
        RuntimeManifestPublisherBinding::AdoptedAttribution => {
            parse_runtime_publisher_pkh(expected).is_some()
                && manifest
                    .publisher_did
                    .as_deref()
                    .is_some_and(|publisher| crate::crypto::decode_did_key(publisher).is_ok())
        }
    }
}

/// Every file path of a v2 package, in the order and the spelling the package
/// layout gives them: the identity, the MPD, then each rendition's init and
/// segments (spec section 3).
fn protected_content_dash_package_paths(head: &CencDashMediaIdentityV2) -> Vec<String> {
    let mut paths = vec![
        PROTECTED_CONTENT_V2_IDENTITY_PATH.to_string(),
        PROTECTED_CONTENT_V2_MPD_PATH.to_string(),
    ];
    for rendition in head.renditions() {
        paths.push(runtime_media_dash_init_path(rendition.kind()));
        paths.extend(
            (0..rendition.segment_count())
                .map(|index| runtime_media_dash_segment_path(rendition.kind(), index)),
        );
    }
    paths
}

/// Every regular file under `directory` as a `/`-separated relative path.
/// Links and anything else are refused. The result is a set: package files are
/// looked up by path, and a sorted list is never read as segment order
/// (`seg-10` sorts before `seg-2`).
fn protected_content_dash_directory_paths(
    directory: &Path,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    const INVALID: &str = "protected content directory is invalid";
    let mut paths = std::collections::BTreeSet::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).map_err(|_| anyhow::anyhow!(INVALID))? {
            let entry = entry.map_err(|_| anyhow::anyhow!(INVALID))?;
            let file_type = entry.file_type().map_err(|_| anyhow::anyhow!(INVALID))?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(directory)
                    .ok()
                    .and_then(Path::to_str)
                    .map(|relative| relative.replace('\\', "/"))
                    .ok_or_else(|| anyhow::anyhow!(INVALID))?;
                paths.insert(relative);
            } else {
                anyhow::bail!(INVALID);
            }
        }
    }
    Ok(paths)
}

/// The cheap half of the directory check: the path set is exactly the package's
/// and `identity.bin` is exactly the head.
pub(super) fn verify_protected_content_dash_directory_shape(
    directory: &Path,
    head: &CencDashMediaIdentityV2,
) -> anyhow::Result<()> {
    let expected: std::collections::BTreeSet<String> = protected_content_dash_package_paths(head)
        .into_iter()
        .collect();
    if protected_content_dash_directory_paths(directory)? != expected {
        anyhow::bail!("protected content directory layout is invalid");
    }
    let canonical = head
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
    let descriptor = fs::read(directory.join(PROTECTED_CONTENT_V2_IDENTITY_PATH))
        .map_err(|_| anyhow::anyhow!("protected content descriptor is unavailable"))?;
    if descriptor != canonical {
        anyhow::bail!("protected content descriptor is invalid");
    }
    Ok(())
}

/// The full check of a staged v2 package against its head, one part at a time:
/// the layout, the descriptor, every init, and then every segment twice.
///
/// Pass A reads each segment and builds its Merkle leaf, and each rendition's
/// root must equal the head's. Pass B reads each segment again and requires it
/// to validate as a protected V2 segment under its proof against that root, so
/// a segment is proven in the place the head says it belongs. `timelines`, when
/// given, are the clear timelines the protection must have preserved.
pub(super) fn verify_protected_content_dash_directory(
    directory: &Path,
    head: &CencDashMediaIdentityV2,
    timelines: Option<&[Vec<Fmp4SegmentTimelineV2>]>,
) -> anyhow::Result<()> {
    verify_protected_content_dash_directory_shape(directory, head)?;
    let mpd = fs::metadata(directory.join(PROTECTED_CONTENT_V2_MPD_PATH))
        .map_err(|_| anyhow::anyhow!("protected content stream is unavailable"))?;
    if mpd.len() == 0 {
        anyhow::bail!("protected content stream is unavailable");
    }
    verify_staged_dash_parts(directory, head, |rendition_index, index, timeline, _| {
        if let Some(timelines) = timelines {
            let expected = timelines
                .get(rendition_index)
                .and_then(|rendition| rendition.get(index as usize));
            anyhow::ensure!(
                expected.is_some() && timeline.as_ref() == expected,
                "protected content media layout is invalid"
            );
        }
        Ok(())
    })
}

fn verify_staged_dash_parts(
    directory: &Path,
    head: &CencDashMediaIdentityV2,
    mut check_part: impl FnMut(usize, u32, Option<Fmp4SegmentTimelineV2>, u64) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    const INVALID: &str = "protected content media layout is invalid";
    let mut sessions = Vec::with_capacity(head.renditions().len());
    for (index, rendition) in head.renditions().iter().enumerate() {
        let init = fs::read(directory.join(runtime_media_dash_init_path(rendition.kind())))
            .map_err(|_| anyhow::anyhow!("protected content init is unavailable"))?;
        sessions.push(
            ValidatedCencDashRenditionSessionV2::new(head, index, &init)
                .map_err(|_| anyhow::anyhow!(INVALID))?,
        );
    }
    let read_segment = |kind, index| {
        fs::read(directory.join(runtime_media_dash_segment_path(kind, index)))
            .map_err(|_| anyhow::anyhow!("protected content segment is unavailable"))
    };
    let mut all_leaves = Vec::with_capacity(head.renditions().len());
    for rendition in head.renditions() {
        let mut leaves = Vec::with_capacity(rendition.segment_count() as usize);
        for index in 0..rendition.segment_count() {
            let bytes = read_segment(rendition.kind(), index)?;
            leaves.push(cenc_dash_segment_leaf_hash(
                rendition.kind(),
                index,
                Digest32::new(sha2::Sha256::digest(&bytes).into()),
                bytes.len() as u64,
            ));
        }
        if cenc_dash_merkle_root(&leaves).map_err(|_| anyhow::anyhow!(INVALID))?
            != rendition.segments_root()
        {
            anyhow::bail!("protected content media identity is invalid");
        }
        all_leaves.push(leaves);
    }
    for (rendition_index, (session, leaves)) in sessions.iter().zip(&all_leaves).enumerate() {
        let proofs = cenc_dash_merkle_audit_paths(leaves).map_err(|_| anyhow::anyhow!(INVALID))?;
        for index in 0..session.segment_count() {
            let bytes = read_segment(session.kind(), index)?;
            if bytes.len() > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 {
                anyhow::bail!(INVALID);
            }
            let layout = session
                .validate_proven_segment(index, &bytes, &proofs[index as usize])
                .map_err(|_| anyhow::anyhow!(INVALID))?;
            check_part(
                rendition_index,
                index,
                layout.timeline(),
                bytes.len() as u64,
            )?;
        }
    }
    Ok(())
}

/// Rebuild the signed media identity and playable MPD from encrypted staging.
/// The signed upload fixes rendition kind and segment count. The staged
/// inits supply timescales and the proven segments supply the MPD timelines.
pub(crate) fn rebuild_staged_remote_dash(
    directory: &Path,
    renditions: &[elastos_protected_content_contracts::ClearRenditionV1],
    kid: ContentAccessIdV1,
    expected_header: &CustodyProtectionHeader,
) -> anyhow::Result<CencDashMediaIdentityV2> {
    let mut declarations = Vec::with_capacity(renditions.len());
    let mut inits = Vec::with_capacity(renditions.len());
    for rendition in renditions {
        let kind = CencDashRenditionKindV2::from_code(rendition.kind)
            .ok_or_else(|| anyhow::anyhow!("seal_layout_invalid"))?;
        let init = read_runtime_media_prepared_part(
            &directory.join(runtime_media_dash_init_path(kind)),
            true,
            MAX_PROTECT_MEDIA_PART_BYTES_V1 as u64,
        )?;
        declarations.push(CencDashRenditionDeclV2::from_staged_init(
            kind,
            kid,
            &init,
            u32::try_from(rendition.segment_lengths.len())?,
        )?);
        inits.push(init);
    }
    let mut builder = CencDashIdentityBuilderV2::new(kid, declarations.clone())?;
    for declaration in declarations {
        for index in 0..declaration.segment_count {
            let bytes = read_runtime_media_prepared_part(
                &directory.join(runtime_media_dash_segment_path(declaration.kind, index)),
                true,
                MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 as u64,
            )?;
            builder.push_segment(&bytes)?;
        }
    }
    let head = builder.finish()?;
    let sessions = inits
        .iter()
        .enumerate()
        .map(|(index, init)| ValidatedCencDashRenditionSessionV2::new(&head, index, init))
        .collect::<Result<Vec<_>, _>>()?;
    let header = elastos_protected_content_custody::require_common_cenc_dash_protection_header_v2(
        &head, &sessions,
    )?;
    anyhow::ensure!(header == expected_header, "seal_finalize_binding_mismatch");
    let mut timelines = vec![Vec::new(); renditions.len()];
    verify_staged_dash_parts(directory, &head, |rendition, _, timeline, bytes| {
        let timeline = timeline.ok_or_else(|| anyhow::anyhow!("seal_layout_invalid"))?;
        timelines[rendition].push(CencDashMpdSegmentV2 { timeline, bytes });
        Ok(())
    })?;
    let mpd = build_cenc_dash_mpd_v2(
        &inits
            .iter()
            .zip(&timelines)
            .map(|(init, segments)| CencDashMpdRenditionV2 {
                protected_init: init,
                segments,
            })
            .collect::<Vec<_>>(),
    )?;
    for (relative, expected) in [
        (PROTECTED_CONTENT_V2_IDENTITY_PATH, head.canonical_bytes()?),
        (PROTECTED_CONTENT_V2_MPD_PATH, mpd.into_bytes()),
    ] {
        match fs::symlink_metadata(directory.join(relative)) {
            Ok(_) => {
                let recorded = read_runtime_media_prepared_part(
                    &directory.join(relative),
                    true,
                    expected.len() as u64,
                )?;
                anyhow::ensure!(recorded == expected, "seal_staging_mismatch");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_protected_content_staging_file(directory, relative, &expected)?
            }
            Err(error) => return Err(error.into()),
        }
    }
    verify_protected_content_dash_directory_shape(directory, &head)?;
    Ok(head)
}

/// The object directory's descriptor file, mirroring the role
/// `PROTECTED_CONTENT_IDENTITY_PATH`'s raw canonical bytes play for media,
/// but as JSON per the brief's exact schema. Every field is independently
/// derivable from `ChunkedPayloadObjectIdentityV1`, so — exactly like the
/// media descriptor — its bytes are fully deterministic from the identity
/// alone; no separate hash/length parameters are needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedContentObjectManifestV1 {
    schema: String,
    content_type: String,
    plaintext_bytes: u64,
    framed_header_bytes: u32,
    encrypted_content: ProtectedContentObjectManifestEncryptedContentV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedContentObjectManifestEncryptedContentV1 {
    sha256: String,
    bytes: u64,
}

pub(super) fn protected_content_object_manifest_bytes(
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<u8>> {
    let manifest = ProtectedContentObjectManifestV1 {
        schema: PROTECTED_CONTENT_OBJECT_MANIFEST_SCHEMA_V1.to_string(),
        content_type: object_identity.content_type().to_string(),
        plaintext_bytes: object_identity.plaintext_bytes(),
        framed_header_bytes: object_identity.framed_header_bytes(),
        encrypted_content: ProtectedContentObjectManifestEncryptedContentV1 {
            sha256: hex::encode(
                object_identity
                    .encrypted_content()
                    .ciphertext_sha256()
                    .as_bytes(),
            ),
            bytes: object_identity.encrypted_content().ciphertext_bytes(),
        },
    };
    serde_json::to_vec(&manifest)
        .map_err(|_| anyhow::anyhow!("protected content object manifest is invalid"))
}

/// Object twin of `verify_protected_content_directory`. The media function is
/// untouched — this is a fully parallel path so a change here can never move
/// media-side behaviour.
pub(super) fn verify_protected_content_object_directory(
    directory: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<()> {
    let expected_files = object_protected_content_files(object_identity)?;
    let expected_paths: Vec<String> = expected_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let actual_paths = protected_content_directory_files(directory)?;
    if actual_paths != expected_paths {
        anyhow::bail!("protected content directory layout is invalid");
    }
    let manifest_bytes = fs::read(directory.join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH))
        .map_err(|_| anyhow::anyhow!("protected content descriptor is unavailable"))?;
    if manifest_bytes != protected_content_object_manifest_bytes(object_identity)? {
        anyhow::bail!("protected content descriptor is invalid");
    }
    let (framed_sha256, framed_bytes) =
        sha256_file(&directory.join(PROTECTED_CONTENT_OBJECT_EPC1_PATH))
            .map_err(|_| anyhow::anyhow!("protected content object is unavailable"))?;
    if framed_bytes != object_identity.encrypted_content().ciphertext_bytes()
        || framed_sha256 != object_identity.encrypted_content().ciphertext_sha256()
    {
        anyhow::bail!("protected content object is invalid");
    }
    Ok(())
}

/// Hashes a file without holding it: the streamed twin of `fs::read` plus
/// `Sha256::digest`, so verifying a large object never buffers it.
pub(crate) fn sha256_file(path: &Path) -> anyhow::Result<(Digest32, u64)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let bytes = std::io::copy(&mut file, &mut hasher)?;
    Ok((Digest32::new(hasher.finalize().into()), bytes))
}

pub(super) fn object_protected_content_files(
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let manifest_bytes = protected_content_object_manifest_bytes(object_identity)?;
    let mut files = vec![
        content_object_file(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH, &manifest_bytes),
        crate::content::ContentObjectFile {
            path: PROTECTED_CONTENT_OBJECT_EPC1_PATH.to_string(),
            sha256: hex::encode(
                object_identity
                    .encrypted_content()
                    .ciphertext_sha256()
                    .as_bytes(),
            ),
            size: object_identity.encrypted_content().ciphertext_bytes(),
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

/// Which half of a v2 package a rendition's files live under, and the names
/// the runtime and the player speak for it.
fn runtime_media_dash_representation(kind: CencDashRenditionKindV2) -> &'static str {
    match kind {
        CencDashRenditionKindV2::Video => "video/avc1",
        CencDashRenditionKindV2::Audio => "audio/und/mp4a",
    }
}

pub(crate) fn runtime_media_dash_init_path(kind: CencDashRenditionKindV2) -> String {
    format!(
        "protected-content/v2/{}/init.mp4",
        runtime_media_dash_representation(kind)
    )
}

/// `index` is the Runtime's zero-based segment index; the file is `seg-(index+1)`
/// (unpadded, one-based; spec section 3).
pub(crate) fn runtime_media_dash_segment_path(kind: CencDashRenditionKindV2, index: u32) -> String {
    format!(
        "protected-content/v2/{}/seg-{}.m4s",
        runtime_media_dash_representation(kind),
        u64::from(index) + 1
    )
}

/// Checks a v2 manifest against its head and returns each rendition's Merkle
/// leaves, from the manifest alone (no segment is fetched).
///
/// Fails closed unless the manifest lists exactly the identity, the MPD, every
/// init and `seg-1..=count` of every rendition, and each entry agrees with the
/// head: the identity and inits by hash and size, every segment by a leaf that
/// folds into the rendition's committed root. Files are found by path, never
/// by position, because `seg-10` sorts before `seg-2`. Every segment's bytes
/// are still proven at read time, by the decrypt provider, against that root.
pub(crate) fn verify_protected_content_dash_manifest(
    manifest: &crate::content::ContentObjectManifest,
    head: &CencDashMediaIdentityV2,
) -> anyhow::Result<Vec<Vec<Digest32>>> {
    const INVALID: &str = "protected content object manifest is invalid";
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !manifest
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        || manifest.content_digest != content_object_digest(&manifest.files)
    {
        anyhow::bail!(INVALID);
    }
    let mut expected_files: u64 = 2;
    for rendition in head.renditions() {
        expected_files += 1 + u64::from(rendition.segment_count());
    }
    if manifest.files.len() as u64 != expected_files {
        anyhow::bail!(INVALID);
    }
    let by_path: BTreeMap<&str, &crate::content::ContentObjectFile> = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let entry = |path: &str| {
        by_path
            .get(path)
            .copied()
            .ok_or_else(|| anyhow::anyhow!(INVALID))
    };
    let matches = |file: &crate::content::ContentObjectFile, sha256: Digest32, size: u64| {
        file.size == size && file.sha256 == hex::encode(sha256.as_bytes())
    };
    let identity_bytes = head
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!(INVALID))?;
    if !matches(
        entry(PROTECTED_CONTENT_V2_IDENTITY_PATH)?,
        Digest32::new(sha2::Sha256::digest(&identity_bytes).into()),
        identity_bytes.len() as u64,
    ) {
        anyhow::bail!(INVALID);
    }
    entry(PROTECTED_CONTENT_V2_MPD_PATH)?;
    let mut all_leaves = Vec::with_capacity(head.renditions().len());
    for rendition in head.renditions() {
        let kind = rendition.kind();
        if !matches(
            entry(&runtime_media_dash_init_path(kind))?,
            rendition.init_segment_sha256(),
            rendition.init_segment_bytes(),
        ) {
            anyhow::bail!(INVALID);
        }
        let mut leaves = Vec::with_capacity(rendition.segment_count() as usize);
        for index in 0..rendition.segment_count() {
            let file = entry(&runtime_media_dash_segment_path(kind, index))?;
            let valid_hex = file.sha256.len() == 64
                && file
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            // The size bound is what keeps a read inside the provider frame: a
            // listing that declares a larger segment is refused here, before
            // any payment or open.
            if file.size == 0
                || file.size > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 as u64
                || !valid_hex
            {
                anyhow::bail!(INVALID);
            }
            let sha256: [u8; 32] = hex::decode(&file.sha256)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!(INVALID))?;
            leaves.push(cenc_dash_segment_leaf_hash(
                kind,
                index,
                Digest32::new(sha256),
                file.size,
            ));
        }
        if cenc_dash_merkle_root(&leaves).map_err(|_| anyhow::anyhow!(INVALID))?
            != rendition.segments_root()
        {
            anyhow::bail!(INVALID);
        }
        all_leaves.push(leaves);
    }
    Ok(all_leaves)
}

fn runtime_rights_action_name(action: RightsActionV1) -> &'static str {
    match action {
        RightsActionV1::View => "view",
        RightsActionV1::Stream => "stream",
        RightsActionV1::Download => "download",
        RightsActionV1::Execute => "execute",
    }
}

/// Object twin of `verify_protected_content_receipt`. Identical in every
/// respect except the last three lines, which build the evidence's
/// `encrypted_content`/identity-root from a `ChunkedPayloadObjectIdentityV1`
/// instead of a `CencFmp4MediaIdentityV1` — the media function is untouched.
#[derive(Debug)]
struct AuthenticatedContentReceiptExpired;

impl std::fmt::Display for AuthenticatedContentReceiptExpired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .write_str("protected content availability receipt is outside its freshness window")
    }
}

impl std::error::Error for AuthenticatedContentReceiptExpired {}

pub(super) fn verify_protected_content_object_receipt(
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    receipt_json: &[u8],
    object_identity: &ChunkedPayloadObjectIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    cid::Cid::try_from(content_cid)
        .map_err(|_| anyhow::anyhow!("protected content availability CID is invalid"))?;
    let receipt: crate::content::SignedAvailabilityReceipt =
        serde_json::from_slice(receipt_json)
            .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    if receipt.payload.schema != CONTENT_AVAILABILITY_RECEIPT_SCHEMA
        || receipt.signer_did != requirement.expected_provider_did()
        || receipt.payload.cid != content_cid
        || receipt.payload.uri != format!("elastos://{content_cid}")
        || receipt.payload.object_did.as_deref() != Some(requirement.expected_object_identity())
        || receipt.payload.publisher_did != requirement.expected_publisher_did()
        || receipt.payload.policy != requirement.policy()
        || !protected_content_availability_status_accepted(&receipt.payload.status, requirement)
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (protected_content_live_proof_required(requirement.minimum_replicas())
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || !content_manifest_binds_publisher(manifest, requirement, publisher_binding)
    {
        anyhow::bail!("protected content availability receipt binding is invalid");
    }
    let max_checked_at = now_unix_seconds
        .checked_add(requirement.max_future_skew_seconds())
        .ok_or_else(|| anyhow::anyhow!("protected content availability time is invalid"))?;
    if receipt.payload.checked_at > max_checked_at {
        anyhow::bail!("protected content availability receipt is outside its freshness window");
    }
    crate::crypto::verify_signed_json_envelope_against_dids(
        &receipt_json,
        CONTENT_AVAILABILITY_RECEIPT_DOMAIN,
        std::slice::from_ref(&requirement.expected_provider_did().to_string()),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability receipt signature is invalid"))?;
    if now_unix_seconds.saturating_sub(receipt.payload.checked_at) > requirement.max_age_seconds() {
        return Err(AuthenticatedContentReceiptExpired.into());
    }
    RuntimeVerifiedContentAvailability::new(
        content_cid,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        requirement,
        receipt.payload.replicas,
        receipt.payload.checked_at,
        Digest32::new(sha2::Sha256::digest(&receipt_json).into()),
        object_identity.encrypted_content().clone(),
        RuntimeVerifiedContentIdentityRootV1::for_object(object_identity)
            .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

/// DASH v2 twin of `verify_protected_content_receipt`. Identical in every
/// respect except the last two arguments, which build the evidence's
/// `encrypted_content` and identity root from the head -- the media function is
/// untouched.
pub(super) fn verify_protected_content_dash_receipt(
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    receipt_json: &[u8],
    head: &CencDashMediaIdentityV2,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    cid::Cid::try_from(content_cid)
        .map_err(|_| anyhow::anyhow!("protected content availability CID is invalid"))?;
    let receipt: crate::content::SignedAvailabilityReceipt =
        serde_json::from_slice(receipt_json)
            .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    if receipt.payload.schema != CONTENT_AVAILABILITY_RECEIPT_SCHEMA
        || receipt.signer_did != requirement.expected_provider_did()
        || receipt.payload.cid != content_cid
        || receipt.payload.uri != format!("elastos://{content_cid}")
        || receipt.payload.object_did.as_deref() != Some(requirement.expected_object_identity())
        || receipt.payload.publisher_did != requirement.expected_publisher_did()
        || receipt.payload.policy != requirement.policy()
        || !protected_content_availability_status_accepted(&receipt.payload.status, requirement)
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (protected_content_live_proof_required(requirement.minimum_replicas())
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || !content_manifest_binds_publisher(manifest, requirement, publisher_binding)
    {
        anyhow::bail!("protected content availability receipt binding is invalid");
    }
    let max_checked_at = now_unix_seconds
        .checked_add(requirement.max_future_skew_seconds())
        .ok_or_else(|| anyhow::anyhow!("protected content availability time is invalid"))?;
    if receipt.payload.checked_at > max_checked_at {
        anyhow::bail!("protected content availability receipt is outside its freshness window");
    }
    crate::crypto::verify_signed_json_envelope_against_dids(
        &receipt_json,
        CONTENT_AVAILABILITY_RECEIPT_DOMAIN,
        std::slice::from_ref(&requirement.expected_provider_did().to_string()),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability receipt signature is invalid"))?;
    if now_unix_seconds.saturating_sub(receipt.payload.checked_at) > requirement.max_age_seconds() {
        return Err(AuthenticatedContentReceiptExpired.into());
    }
    RuntimeVerifiedContentAvailability::new(
        content_cid,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        requirement,
        receipt.payload.replicas,
        receipt.payload.checked_at,
        Digest32::new(sha2::Sha256::digest(&receipt_json).into()),
        head.encrypted_content().clone(),
        RuntimeVerifiedContentIdentityRootV1::for_media_dash(head),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

/// Object twin of `verify_protected_content_manifest_and_files`. Each fetched
/// file is verified and dropped before the next one is fetched.
/// The manifest of an object item names exactly its identity's files.
pub(super) fn protected_content_object_manifest_files(
    manifest: &crate::content::ContentObjectManifest,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let expected_files = object_protected_content_files(object_identity)?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !content_object_files_match(&manifest.files, &expected_files)
        || manifest.content_digest != content_object_digest(&expected_files)
    {
        anyhow::bail!("protected content object manifest is invalid");
    }
    Ok(expected_files)
}

/// Object twin of `publish_and_verify_protected_content_availability`.
pub async fn publish_and_verify_protected_content_object_availability(
    registry: &ProviderRegistry,
    protected_content_dir: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    verify_protected_content_object_directory(protected_content_dir, object_identity)?;
    let publish_requirements = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        protected_content_live_proof_required(requirement.minimum_replicas()),
    )?
    .with_availability_policy(requirement.policy())?;
    // Each leg is timed separately. This step is the one a creator watches as
    // a stalled "Encrypt & escrow", and it is four different pieces of work:
    // publishing and replicating the ciphertext, then reading back a receipt,
    // a manifest and every file to prove it landed. Without this split the
    // only honest thing anyone can say about a slow publish is its total.
    let phase = RuntimeCustodyPhase::begin(
        "content_publish",
        protected_content_dir.display().to_string(),
    );
    let content_cid = crate::content::publish_directory_via_provider_with_kind_and_requirements(
        registry,
        protected_content_dir,
        PROTECTED_CONTENT_OBJECT_KIND,
        Some(requirement.expected_object_identity()),
        Some(requirement.expected_publisher_did()),
        publish_requirements,
    )
    .await?;
    phase.ok();
    let phase = RuntimeCustodyPhase::begin("availability_receipt", &content_cid);
    let receipt = fetch_content_availability_receipt(registry, &content_cid).await?;
    phase.ok();
    let phase = RuntimeCustodyPhase::begin("object_manifest", &content_cid);
    let manifest = crate::content::fetch_content_object_manifest(registry, &content_cid).await?;
    phase.ok();
    let phase = RuntimeCustodyPhase::begin("object_files_verify", &content_cid);
    verify_protected_content_object_manifest_and_files(
        registry,
        &content_cid,
        &manifest,
        object_identity,
    )
    .await?;
    phase.ok();
    let now_unix_seconds = now_unix_seconds();
    verify_protected_content_object_receipt(
        &content_cid,
        &manifest,
        &receipt,
        object_identity,
        requirement,
        now_unix_seconds,
        RuntimeManifestPublisherBinding::Exact,
    )
}

/// Evidence for building a remote sealer's signed completion. This retains
/// the receipt verified at publication time for later archival.
pub struct RemoteSealedPublication {
    availability: RuntimeVerifiedContentAvailability,
    file_cids: Vec<(String, String)>,
    availability_receipt: Vec<u8>,
    content: RuntimeContentIdentityV1,
    envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    commitment: Digest32,
}

impl RemoteSealedPublication {
    pub fn prepare_completion(
        &self,
        descriptor: &elastos_protected_content_contracts::SignedPoolDescriptorAnyV1,
        request: &elastos_protected_content_contracts::SignedMintRequestV1,
        sealer: NodePublicKey,
        now: u64,
    ) -> anyhow::Result<elastos_protected_content_contracts::SealCompletedV1> {
        use elastos_protected_content_contracts::{ClearLayoutV1, SealCompletedV1};

        let mint = request.verify_for_sealer(descriptor, sealer, now)?;
        anyhow::ensure!(
            self.envelope.custody_epoch() == mint.epoch,
            "remote seal publication differs from the requested epoch"
        );
        let content_identity = match (&mint.clear_layout, &self.content) {
            (
                ClearLayoutV1::Object {
                    content_type,
                    length,
                },
                RuntimeContentIdentityV1::Object(object),
            ) if object.content_type() == content_type && object.plaintext_bytes() == *length => {
                object.canonical_bytes()?
            }
            (ClearLayoutV1::DashV2 { renditions }, RuntimeContentIdentityV1::MediaDash(head))
                if head.default_kid() == mint.content_access_id
                    && head.renditions().len() == renditions.len()
                    && head
                        .renditions()
                        .iter()
                        .zip(renditions)
                        .all(|(head, clear)| {
                            head.kind().code() == clear.kind
                                && head.segment_count() as usize == clear.segment_lengths.len()
                        }) =>
            {
                head.canonical_bytes()?
            }
            _ => anyhow::bail!("remote seal publication differs from the signed layout"),
        };
        let peer = descriptor
            .member_peer_did(sealer)
            .ok_or_else(|| anyhow::anyhow!("remote seal publication has no sealer route"))?;
        Ok(SealCompletedV1 {
            pool: mint.pool,
            epoch: mint.epoch,
            descriptor_digest: descriptor.canonical_hash()?,
            sealer_node_public_key: sealer,
            sealer_device_did: peer.to_string(),
            content_publisher_did: self.availability.publisher_identity().to_string(),
            mint_request_hash: request.canonical_hash()?,
            content_access_id: mint.content_access_id,
            key_envelope: self.envelope.clone(),
            content_identity,
            content_key_commitment: self.commitment,
            package_cid: self.availability.content_cid().to_string(),
            file_cids: self.file_cids.clone(),
            availability_receipt: self.availability_receipt.clone(),
            completed_at: now,
        })
    }
}

/// Publish ciphertext only after every share's authenticated storage receipt
/// has been matched to the exact envelope and recipient. The caller obtains
/// those receipts through its private custody provisioning path and supplies
/// the independently resolved publisher and Content signer.
pub(crate) async fn publish_remote_sealed_content(
    registry: &ProviderRegistry,
    directory: &Path,
    content: &RuntimeContentIdentityV1,
    envelope: &elastos_protected_content_contracts::CustodyEnvelopeV1,
    receipts: &[crate::custody_pool_seal::VerifiedRemoteShareReceipt],
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RemoteSealedPublication> {
    use elastos_protected_content_contracts::CustodyNodeProvisioningRecordV1;

    let identity = envelope.key_envelope_identity()?;
    anyhow::ensure!(
        identity.encrypted_content() == content.encrypted_content(),
        "remote sealed content does not match its custody envelope"
    );
    let nodes = envelope.manifest().nodes();
    anyhow::ensure!(
        receipts.len() == nodes.len(),
        "remote sealed object has incomplete custody receipts"
    );
    for node in nodes {
        let key = node.node_public_key();
        let share = envelope
            .stored_share_for_node(key)
            .ok_or_else(|| anyhow::anyhow!("remote sealed object is missing a node share"))?;
        let record = CustodyNodeProvisioningRecordV1::new(
            identity.clone(),
            envelope.manifest().clone(),
            key,
            share.clone(),
        )?;
        let expected = record.record_identity()?;
        anyhow::ensure!(
            receipts
                .iter()
                .any(|receipt| receipt.matches(key, expected)),
            "remote sealed object has an invalid custody receipt"
        );
    }
    validate_protected_content_availability_requirement(requirement)?;
    match content {
        RuntimeContentIdentityV1::Object(object) => {
            verify_protected_content_object_directory(directory, object)?
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            verify_protected_content_dash_directory(directory, head, None)?
        }
        RuntimeContentIdentityV1::Media(_) => anyhow::bail!("unsupported remote seal identity"),
    }
    let publication = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        protected_content_live_proof_required(requirement.minimum_replicas()),
    )?
    .with_availability_policy(requirement.policy())?;
    let (cid, file_cids) = crate::content::publish_staged_protected_content(
        registry,
        directory,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        publication,
    )
    .await?;
    let manifest = crate::content::fetch_content_object_manifest(registry, &cid).await?;
    let binding = RuntimeManifestPublisherBinding::Exact;
    anyhow::ensure!(
        manifest.object_did.as_deref() == Some(requirement.expected_object_identity())
            && content_manifest_binds_publisher(&manifest, requirement, binding),
        "remote sealed package manifest has a different object or publisher"
    );
    match content {
        RuntimeContentIdentityV1::Object(object) => {
            protected_content_object_manifest_files(&manifest, object)?;
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            verify_protected_content_dash_manifest(&manifest, head)?;
        }
        RuntimeContentIdentityV1::Media(_) => anyhow::bail!("unsupported remote seal identity"),
    }
    let file_cids: Vec<_> = file_cids.into_iter().collect();
    verify_remote_seal_files(registry, &cid, &manifest, &file_cids).await?;
    let availability_receipt = fetch_content_availability_receipt(registry, &cid).await?;
    let now = now_unix_seconds();
    let availability = match content {
        RuntimeContentIdentityV1::Object(object) => verify_protected_content_object_receipt(
            &cid,
            &manifest,
            &availability_receipt,
            object,
            requirement,
            now,
            binding,
        )?,
        RuntimeContentIdentityV1::MediaDash(head) => verify_protected_content_dash_receipt(
            &cid,
            &manifest,
            &availability_receipt,
            head,
            requirement,
            now,
            binding,
        )?,
        RuntimeContentIdentityV1::Media(_) => anyhow::bail!("unsupported remote seal identity"),
    };
    Ok(RemoteSealedPublication {
        availability,
        file_cids,
        availability_receipt,
        content: content.clone(),
        envelope: identity,
        commitment: envelope.manifest().content_key_commitment(),
    })
}

/// Verify the remote sealer's already-published package. The authorized
/// publisher and receipt signer come from the caller's verified pool/root
/// configuration, independently of the completion.
pub async fn verify_remote_seal_availability(
    registry: &ProviderRegistry,
    output: &elastos_protected_content_runtime::VerifiedRemoteSealOutput<'_>,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    let statement = output.statement();
    validate_protected_content_availability_requirement(requirement)?;
    anyhow::ensure!(
        statement.content_publisher_did == requirement.expected_publisher_did(),
        "remote sealed package names a different publisher"
    );
    let cid = cid::Cid::try_from(statement.package_cid.as_str())?;
    anyhow::ensure!(
        cid.to_string() == statement.package_cid,
        "remote sealed package CID is not canonical"
    );
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &statement.package_cid).await?;
    let binding = RuntimeManifestPublisherBinding::Exact;
    anyhow::ensure!(
        manifest.object_did.as_deref() == Some(requirement.expected_object_identity())
            && content_manifest_binds_publisher(&manifest, requirement, binding),
        "remote sealed package manifest has a different object or publisher"
    );
    let cid = &statement.package_cid;
    match output.identity() {
        RuntimeContentIdentityV1::Object(object) => {
            protected_content_object_manifest_files(&manifest, object)?;
        }
        RuntimeContentIdentityV1::MediaDash(dash) => {
            verify_protected_content_dash_manifest(&manifest, dash)?;
        }
        RuntimeContentIdentityV1::Media(_) => anyhow::bail!("unsupported remote seal identity"),
    }
    verify_remote_seal_files(registry, cid, &manifest, &statement.file_cids).await?;
    // The completion's receipt is archived with it. The chain wait and
    // package reads can outlast that receipt's freshness window.
    let receipt = refresh_content_availability_receipt(registry, cid, requirement).await?;
    let now = now_unix_seconds();
    match output.identity() {
        RuntimeContentIdentityV1::Object(object) => verify_protected_content_object_receipt(
            cid,
            &manifest,
            &receipt,
            object,
            requirement,
            now,
            binding,
        ),
        RuntimeContentIdentityV1::MediaDash(dash) => verify_protected_content_dash_receipt(
            cid,
            &manifest,
            &receipt,
            dash,
            requirement,
            now,
            binding,
        ),
        RuntimeContentIdentityV1::Media(_) => anyhow::bail!("unsupported remote seal identity"),
    }
}

/// Check the sealer's fresh publication receipt and exact manifest before
/// starting the creator transaction. The receiver already proved and pinned
/// all the files. The minter reads the manifest and verifies the receipt
/// against the sealer DID bound to the request's signed descriptor.
pub(super) async fn verify_fresh_remote_seal_publication(
    registry: &ProviderRegistry,
    output: &elastos_protected_content_runtime::VerifiedRemoteSealOutput<'_>,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    let statement = output.statement();
    let cid = &statement.package_cid;
    anyhow::ensure!(
        cid::Cid::try_from(cid.as_str())?.to_string() == *cid,
        "remote sealed package CID is not canonical"
    );
    let manifest = crate::content::fetch_content_object_manifest(registry, cid).await?;
    remote_seal_manifest_file_cids(&manifest, &statement.file_cids)?;
    let now = now_unix_seconds();
    let binding = RuntimeManifestPublisherBinding::Exact;
    match output.identity() {
        RuntimeContentIdentityV1::Object(object) => {
            protected_content_object_manifest_files(&manifest, object)?;
            verify_protected_content_object_receipt(
                cid,
                &manifest,
                &statement.availability_receipt,
                object,
                requirement,
                now,
                binding,
            )
        }
        RuntimeContentIdentityV1::MediaDash(dash) => {
            verify_protected_content_dash_manifest(&manifest, dash)?;
            verify_protected_content_dash_receipt(
                cid,
                &manifest,
                &statement.availability_receipt,
                dash,
                requirement,
                now,
                binding,
            )
        }
        RuntimeContentIdentityV1::Media(_) => anyhow::bail!("unsupported remote seal identity"),
    }
}

/// Recover a completed seal whose original receipt has expired. Refresh only
/// after authenticating that receipt and its complete package binding. Content
/// re-verifies the same package and issues a fresh receipt for this Home.
pub(super) async fn verify_remote_mint_publication(
    registry: &ProviderRegistry,
    output: &elastos_protected_content_runtime::VerifiedRemoteSealOutput<'_>,
    requirement: RuntimeContentAvailabilityRequirement,
    local_signer_did: &str,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<(
    RuntimeContentAvailabilityRequirement,
    RuntimeVerifiedContentAvailability,
)> {
    match verify_fresh_remote_seal_publication(registry, output, &requirement, &now_unix_seconds)
        .await
    {
        Ok(evidence) => Ok((requirement, evidence)),
        Err(error) if error.is::<AuthenticatedContentReceiptExpired>() => {
            let local = RuntimeContentAvailabilityRequirement::new(
                local_signer_did,
                requirement.expected_object_identity(),
                requirement.expected_publisher_did(),
                requirement.policy(),
                requirement.minimum_replicas(),
                requirement.max_age_seconds(),
                requirement.max_future_skew_seconds(),
            )?;
            let evidence =
                verify_remote_seal_availability(registry, output, &local, now_unix_seconds).await?;
            Ok((local, evidence))
        }
        Err(error) => Err(error),
    }
}

async fn verify_remote_seal_files(
    registry: &ProviderRegistry,
    package_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    claimed: &[(String, String)],
) -> anyhow::Result<()> {
    let file_cids = remote_seal_manifest_file_cids(manifest, claimed)?;
    for (file, file_cid) in manifest.files.iter().zip(file_cids) {
        let size = usize::try_from(file.size)?;
        let bytes = crate::content::fetch_bytes_via_provider_capped(
            registry,
            package_cid,
            Some(&file.path),
            size,
        )
        .await?;
        crate::content::verify_content_object_file(package_cid, file, &bytes)?;
        drop(bytes);
        let bytes =
            crate::content::fetch_bytes_via_provider_capped(registry, file_cid, None, size).await?;
        crate::content::verify_content_object_file(file_cid, file, &bytes)?;
    }
    Ok(())
}

pub(super) fn remote_seal_manifest_file_cids<'a>(
    manifest: &crate::content::ContentObjectManifest,
    claimed: &'a [(String, String)],
) -> anyhow::Result<Vec<&'a str>> {
    anyhow::ensure!(
        manifest.files.len() == claimed.len(),
        "remote sealed file set differs from the package"
    );
    manifest
        .files
        .iter()
        .zip(claimed)
        .map(|(file, (path, cid))| {
            anyhow::ensure!(
                &file.path == path,
                "remote sealed file path differs from the package"
            );
            let parsed = cid::Cid::try_from(cid.as_str())?;
            anyhow::ensure!(
                parsed.to_string() == *cid,
                "remote sealed file CID is not canonical"
            );
            Ok(cid.as_str())
        })
        .collect()
}

/// Return both publication prerequisites for a verified remote output. The
/// terminal is supplied by the creator mint coordinator after settlement.
pub async fn verify_remote_seal_publication(
    registry: &ProviderRegistry,
    output: &elastos_protected_content_runtime::VerifiedRemoteSealOutput<'_>,
    terminal: &RuntimeMintCreatorTerminalEvidence,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<(RightsPolicyBodyV1, RuntimeVerifiedContentAvailability)> {
    let item =
        elastos_protected_content_runtime::RuntimeMintedItemV1::from_creator_terminal(terminal)?;
    let policy = resolve_runtime_rights_policy_for_item(
        registry,
        output.identity().encrypted_content(),
        output.statement().content_access_id,
        RightsActionV1::View,
        Some(item.expected_item()),
    )
    .await?;
    anyhow::ensure!(
        policy.body().chain_id() == item.chain_id(),
        "remote seal policy does not match the settled item's chain"
    );
    let availability =
        verify_remote_seal_availability(registry, output, requirement, now_unix_seconds).await?;
    Ok((policy.body().clone(), availability))
}

#[derive(Debug)]
pub(super) struct RuntimePreparedLibraryPublish {
    pub(super) input: RuntimeCustodyLibraryPublishInput,
    pub(super) request_id: Digest32,
    pub(super) output_receipt_digest: Digest32,
    pub(super) operation_root: PathBuf,
}

/// Both payloads are boxed. Each is large on its own — `Prepared` carries a
/// whole publish input including the listing terms, `Consumed` a preparation
/// record — so leaving either inline sizes every value of this enum, and the
/// common case, for the bigger of the two.
#[derive(Debug)]
pub(super) enum RuntimeLibraryMediaPreparation {
    Prepared(Box<RuntimePreparedLibraryPublish>),
    Consumed {
        record: Box<RuntimeMediaPreparationRecord>,
        operation_root: PathBuf,
    },
}

pub(super) enum RuntimeMediaProviderPrepareError {
    Settled,
    Unknown,
}

pub(super) fn runtime_media_staging_root(data_dir: &Path) -> PathBuf {
    data_dir
        .join(PROTECTED_CONTENT_ROOT)
        .join("media-provider")
        .join("staging")
}

pub(super) fn runtime_media_private_state_error(_reason: String) -> anyhow::Error {
    anyhow::anyhow!("Runtime custody media preparation private state is invalid")
}

pub(super) fn validate_runtime_media_staging_root(staging_root: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(staging_root)
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("Runtime custody media preparation private state is invalid");
    }
    validate_owner_only_metadata_with_error(
        "media-provider staging root",
        &metadata,
        false,
        runtime_media_private_state_error,
    )
}

/// Reads the creator's source object for media preparation through the
/// principal-root object path. A protected root (recovery activated) stores
/// every object as an encrypted `elastos.principal-root.object/v1` envelope,
/// which a raw file copy would hand to the media provider as ciphertext; an
/// unprotected root passes through unchanged. The whole object is held in
/// memory because a protected object is one AES-GCM envelope and cannot be
/// streamed. There is no size cap here: a protected root is read whole by the
/// principal-root object path, whose own limits are the protocol's.
pub(super) fn read_runtime_media_source(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_file_path: &Path,
) -> anyhow::Result<Vec<u8>> {
    const MESSAGE: &str = "Runtime custody media preparation input is invalid";
    let source = open_runtime_media_source_file(source_file_path)?;
    let stored_len = source
        .metadata()
        .map_err(|error| anyhow::Error::new(error).context(MESSAGE))?
        .len();
    drop(source);
    if stored_len == 0 {
        return Err(anyhow::anyhow!("stored source is empty").context(MESSAGE));
    }
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let bytes = crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &localhost_root,
        object_uri,
        source_file_path,
    )
    .map_err(|error| {
        tracing::warn!(
            %object_uri,
            error = ?error,
            "runtime custody media preparation: source object is unreadable"
        );
        error.context(MESSAGE)
    })?;
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("source plaintext is empty").context(MESSAGE));
    }
    Ok(bytes)
}

pub(super) fn runtime_media_source_digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(sha2::Sha256::digest(bytes).into())
}

pub(super) fn reset_runtime_media_operation_root(operation_root: &Path) -> anyhow::Result<()> {
    if operation_root.exists() {
        let metadata = fs::symlink_metadata(operation_root)
            .map_err(|_| runtime_media_private_state_error(String::new()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("Runtime custody media preparation private state is invalid");
        }
        fs::remove_dir_all(operation_root)
            .map_err(|_| runtime_media_private_state_error(String::new()))?;
    }
    fs::create_dir(operation_root).map_err(|_| runtime_media_private_state_error(String::new()))?;
    #[cfg(unix)]
    fs::set_permissions(operation_root, fs::Permissions::from_mode(0o700))
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    Ok(())
}

/// Stages the already-read source bytes as the media provider's input file.
/// The digest is re-checked here so the staged file is provably the bytes the
/// preparation record was keyed on.
pub(super) fn stage_runtime_media_provider_input(
    source_bytes: &[u8],
    destination_path: &Path,
    expected_digest: Digest32,
) -> anyhow::Result<()> {
    if source_bytes.is_empty() || runtime_media_source_digest(source_bytes) != expected_digest {
        anyhow::bail!("Runtime custody media preparation input is invalid");
    }
    let mut destination = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination_path)
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    #[cfg(unix)]
    fs::set_permissions(destination_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    destination
        .write_all(source_bytes)
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    destination
        .sync_all()
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    Ok(())
}

#[cfg(unix)]
fn open_runtime_media_source_file(path: &Path) -> anyhow::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        anyhow::bail!("Runtime custody media preparation input is invalid");
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_runtime_media_source_file(path: &Path) -> anyhow::Result<fs::File> {
    let file = fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    if !metadata.is_file() {
        anyhow::bail!("Runtime custody media preparation input is invalid");
    }
    Ok(file)
}

pub(super) fn read_runtime_media_prepared_part(
    path: &Path,
    require_non_empty: bool,
    max_output_part_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        options
            .open(path)
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    if !metadata.is_file()
        || metadata.len() > max_output_part_bytes
        || (require_non_empty && metadata.len() == 0)
    {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    std::io::Read::take(file, max_output_part_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    if bytes.len() as u64 > max_output_part_bytes || (require_non_empty && bytes.is_empty()) {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    Ok(bytes)
}

pub(super) fn parse_runtime_media_segment_name(name: &str) -> anyhow::Result<u32> {
    let Some(index) = name.strip_suffix(".m4s") else {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    };
    if index.len() != 8 || !index.as_bytes().iter().all(u8::is_ascii_digit) {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    index
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))
}

pub(super) async fn invoke_runtime_media_provider_prepare(
    registry: &ProviderRegistry,
    operation_id: Digest32,
) -> Result<RuntimePreparedMediaProviderOutputV2, RuntimeMediaProviderPrepareError> {
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: RUNTIME_PROVIDER_ID.to_string(),
            target: MEDIA_PROVIDER_ID.to_string(),
            op: "prepare".to_string(),
            request: json!({
                "op": "prepare",
                "operation_id": hex::encode(operation_id.as_bytes()),
            }),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
        .map_err(|_| RuntimeMediaProviderPrepareError::Unknown)?;
    match response.get("status").and_then(Value::as_str) {
        Some("ok") => response
            .get("data")
            .cloned()
            .ok_or(RuntimeMediaProviderPrepareError::Settled)
            .and_then(|data| {
                serde_json::from_value(data).map_err(|_| RuntimeMediaProviderPrepareError::Settled)
            }),
        Some("error")
            if response
                .get("data")
                .and_then(|data| data.get("operation_settled"))
                .and_then(Value::as_bool)
                == Some(true) =>
        {
            Err(RuntimeMediaProviderPrepareError::Settled)
        }
        _ => Err(RuntimeMediaProviderPrepareError::Unknown),
    }
}

/// Where a creator publish takes its mint terms from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyCreatorTermsSource {
    /// The terms the request carries: a new attempt, or a retry at the same
    /// terms.
    #[default]
    Requested,
    /// The terms already recorded for this mint, which is what Resume means.
    /// Nothing the request carries about terms is read.
    Recorded,
}

/// The publish-input fields the creator tail (chain mint, metadata, listing)
/// actually reads. Both publish inputs project into it, so the tail is one
/// kind-agnostic function instead of a media copy and an object copy:
/// everything kind-specific it needs, it reads from the persisted mint draft.
#[derive(Clone)]
pub(crate) struct RuntimeCustodyCreatorTailInput {
    pub object_uri: String,
    pub principal_id: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    /// The listing a marketplace displays. `None` keeps the pre-listing
    /// behaviour: a mint with no Elacity metadata folder.
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Size of the CLEAR content, which both `metadata.json` and
    /// `content.json` state. It is computed here from the bytes the publish
    /// actually carried, because it is not recoverable later: the content
    /// identity reachable at the metadata site exposes the content type and
    /// the chunk count, never the plaintext length, and the mint intent that
    /// does record it is keyed by request id rather than mint id.
    pub plaintext_bytes: u64,
    pub terms_source: RuntimeCustodyCreatorTermsSource,
    /// Where the source lives, which with the object and the principal names
    /// the attempt a conflicting new mint sets aside.
    pub source_storage: String,
}

impl std::fmt::Debug for RuntimeCustodyCreatorTailInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyCreatorTailInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .finish()
    }
}

impl From<&RuntimeCustodyLibraryPublishInput> for RuntimeCustodyCreatorTailInput {
    fn from(input: &RuntimeCustodyLibraryPublishInput) -> Self {
        Self {
            object_uri: input.object_uri.clone(),
            principal_id: input.principal_id.clone(),
            wallet_account_id: input.wallet_account_id.clone(),
            wallet_account_address: input.wallet_account_address.clone(),
            creator_mint_source_digest: input.creator_mint_source_digest,
            copies: input.copies.clone(),
            price: input.price.clone(),
            channel: input.channel.clone(),
            pay_token: input.pay_token.clone(),
            listing: input.listing.clone(),
            // The prepared renditions: every init segment plus every media
            // segment.
            plaintext_bytes: input.media.clear_bytes(),
            terms_source: RuntimeCustodyCreatorTermsSource::Requested,
            source_storage: input.source_storage.clone(),
        }
    }
}

impl From<&RuntimeCustodyLibraryPublishObjectInput> for RuntimeCustodyCreatorTailInput {
    fn from(input: &RuntimeCustodyLibraryPublishObjectInput) -> Self {
        Self {
            object_uri: input.object_uri.clone(),
            principal_id: input.principal_id.clone(),
            wallet_account_id: input.wallet_account_id.clone(),
            wallet_account_address: input.wallet_account_address.clone(),
            creator_mint_source_digest: input.creator_mint_source_digest,
            copies: input.copies.clone(),
            price: input.price.clone(),
            channel: input.channel.clone(),
            pay_token: input.pay_token.clone(),
            listing: input.listing.clone(),
            plaintext_bytes: input.clear_plaintext.len() as u64,
            terms_source: RuntimeCustodyCreatorTermsSource::Requested,
            source_storage: input.source_storage.clone(),
        }
    }
}

/// Object twin of `RuntimeCustodyLibraryPublishInput`. Deliberately a
/// separate type rather than an enum-widening of the media struct: every one
/// of that struct's ~15 production call sites (segment protection, mint
/// intent construction, staging directory writer, Debug impl) would need a
/// match arm added regardless of which shape is chosen, and a fully separate
/// type means the media struct and every function taking it verbatim by
/// reference stays completely untouched — the safest way to guarantee the
/// media path's behaviour cannot move.
#[derive(Clone)]
pub(crate) struct RuntimeCustodyLibraryPublishObjectInput {
    pub object_uri: String,
    pub principal_id: String,
    pub content_type: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    pub clear_plaintext: Vec<u8>,
    pub source_storage: String,
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Plan B S7-lite T7.6: the pool this mint goes into; `None` is this
    /// Home's own pool, else the only pool that admits it.
    pub pool_did: Option<String>,
}

impl std::fmt::Debug for RuntimeCustodyLibraryPublishObjectInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyLibraryPublishObjectInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("content_type", &self.content_type)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .field("clear_plaintext_bytes", &self.clear_plaintext.len())
            .field("source_storage", &self.source_storage)
            .finish()
    }
}

/// Object twin of `publish_runtime_custody_library_object`. Ends where the
/// media function's completed mint (custody-provisioned + content-available)
/// is ready. The creator/chain-mint/listing tail is NOT duplicated here: the
/// caller (`runtime_custody_publish_object_via_gateway`) runs the same shared
/// `runtime_custody_publish_creator_tail_from_facts` the media path runs, now
/// that the portable listing package carries either content kind.
pub(crate) async fn publish_runtime_custody_library_object_content(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    input: RuntimeCustodyLibraryPublishObjectInput,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let source = (
        input.principal_id.as_str(),
        input.object_uri.as_str(),
        input.source_storage.as_str(),
    );
    let existing = runtime_mint_attempt_state(data_dir, source.0, source.1, source.2)?
        .and_then(|(_, intent)| intent);
    if let Some(intent) = &existing {
        if intent.remote_seal_request().is_some() {
            return resume_runtime_custody_remote_object(data_dir, registry, &input, intent).await;
        }
    }
    let mut mint_pool = load_runtime_custody_mint_pool(
        data_dir,
        registry.clone(),
        input.pool_did.as_deref(),
        Some(source),
    )?;
    let (device_key, device_did) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let now = crate::auth::now_ts();
    let remote_enabled = remote_sealing_enabled(
        data_dir,
        existing.as_ref(),
        "protected_content_remote_object_sealing",
    );
    if remote_enabled {
        bind_remote_sealing_pool(data_dir, &registry, source, &mut mint_pool, now)?;
    }
    let composition = &mint_pool.composition;
    let used_pool = mint_pool.used.clone();
    let configured = composition
        .configured_nodes()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))?;
    let selected = mint_pool.selected_nodes(&configured, now)?;
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    let mint_journal = runtime_mint_journal(data_dir);
    let mint_intent = load_or_persist_runtime_mint_intent_object(
        &mint_journal,
        composition,
        &input,
        mint_nodes.clone(),
        mint_pool.completed_local_mint,
    )?;
    if let Some(mint_id) = mint_intent.completed_mint_id() {
        return load_completed_runtime_mint_object_facts(&mint_journal, &input, mint_id);
    }
    if remote_enabled {
        let descriptor = used_pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
        let local_nodes = own_custody_node_keys(data_dir)?;
        let intent = crate::remote_seal_source::prepare_remote_object_mint(
            &mint_journal,
            mint_intent.request_id(),
            &input.content_type,
            descriptor,
            &device_key,
            elastos_protected_content_runtime::RemoteSealLocalIdentity {
                endpoint_did: &device_did,
                node_keys: &local_nodes,
            },
            now,
        )?;
        return resume_runtime_custody_remote_object(data_dir, registry, &input, &intent).await;
    }
    if mint_intent.protect_settled_closed_before_draft() {
        if let Some(mint_id) = adopt_settled_runtime_mint_record(&mint_journal, &mint_intent)? {
            return load_completed_runtime_mint_object_facts(&mint_journal, &input, mint_id);
        }
    }
    let request_id = hex::encode(mint_intent.request_id().as_bytes());
    let step = RuntimeMintStep::begin("protect", &request_id);
    let protected = protect_runtime_custody_object(
        data_dir,
        &registry,
        &mint_journal,
        composition,
        &input.content_type,
        &input.clear_plaintext,
        &mint_intent,
    )
    .await?;
    step.ok();
    // DEBUG, like its media twin: at INFO an operator wants the mint's outcome,
    // not each phase of it.
    tracing::debug!(
        request_id = %request_id,
        content_kind = "object",
        framed_bytes = protected.object_identity.encrypted_content().ciphertext_bytes(),
        "runtime custody publish: object protected"
    );
    let step = RuntimeMintStep::begin("rights_policy", &request_id);
    let policy = resolve_runtime_rights_policy(
        registry.as_ref(),
        protected.object_identity.encrypted_content(),
        mint_intent.content_access_id(),
        RightsActionV1::View,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "Runtime custody rights policy resolution failed");
        error.context("Runtime custody rights policy is unavailable")
    })?;
    step.ok();
    let mint_draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::Object(protected.object_identity.clone()),
        mint_intent.content_access_id(),
        protected
            .envelope
            .key_envelope_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
        policy.identity().clone(),
        protected.envelope.manifest().content_key_commitment(),
        protected.envelope.manifest().threshold(),
        mint_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint draft is invalid"))?;
    let sign_key = device_key.clone();
    let mut coordinator = RuntimeMintCoordinator::new(
        runtime_mint_journal(data_dir),
        runtime_issuer,
        move |bytes| sign_key.sign(bytes).to_bytes(),
        selected,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint coordinator is invalid"))?
    .with_dispatch_clock(crate::auth::now_ts);
    if let Some(descriptor) = &used_pool {
        coordinator = coordinator.with_pool_provisioning(
            elastos_protected_content_runtime::RuntimeMintPoolProvisioning::new(
                descriptor.clone(),
                mint_intent.content_access_id(),
            ),
        );
    }
    let step = RuntimeMintStep::begin("custody_provision", &request_id);
    match coordinator
        .provision(&mint_draft, &protected.envelope, crate::auth::now_ts())
        .await
        .map_err(|_| anyhow::anyhow!("Runtime custody mint failed"))?
    {
        RuntimeMintCoordinatorOutcome::CustodyProvisioned { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        _ => {
            return Err(runtime_custody_mint_failed(
                &composition.diagnostics,
                runtime_custody_composition_pool_did(composition),
            ))
        }
    }
    step.ok();
    tracing::debug!(
        mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
        "runtime custody publish: object custody provisioned"
    );
    if let Some(descriptor) = &used_pool {
        record_runtime_pool_mint(data_dir, &mint_draft, descriptor, &device_key)?;
    }
    let content_id = runtime_protected_content_id(mint_draft.encrypted_content())?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, &input.principal_id)?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        device_did,
        content_id.clone(),
        publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody availability requirement is invalid"))?;
    let step = RuntimeMintStep::begin("staging", &request_id);
    write_protected_content_object_manifest(protected.staging.path(), &protected.object_identity)?;
    step.ok();
    // The long one. Publishing the ciphertext and proving it replicated is what
    // a creator sees as a stalled "Encrypt & escrow", because the whole server
    // round trip is one request from the browser's side.
    let step = RuntimeMintStep::begin("availability_publish", &request_id);
    let evidence = publish_and_verify_protected_content_object_availability(
        registry.as_ref(),
        protected.staging.path(),
        &protected.object_identity,
        &requirement,
        crate::auth::now_ts,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
            %error,
            "Runtime custody content availability verification failed"
        );
        error.context(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
    })?;
    step.ok();
    match coordinator
        .record_content_availability(&mint_draft, &requirement, evidence.clone())
        .map_err(|_| anyhow::anyhow!("Runtime custody availability record failed"))?
    {
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        _ => anyhow::bail!("Runtime custody availability record failed"),
    }
    let facts = runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        &mint_draft,
        &content_id,
        &evidence,
    );
    mint_journal
        .mark_intent_completed(mint_intent.request_id(), mint_draft.mint_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(facts)
}

async fn resume_runtime_custody_remote_object(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    intent: &RuntimeMintIntent,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let journal = runtime_mint_journal(data_dir);
    let attempt = journal.current_attempt(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )?;
    let expected = RuntimeMintIntent::new_object(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.content_type.clone(),
        &input.clear_plaintext,
        intent.content_access_id(),
        intent.custody_pool(),
        intent.custody_epoch(),
        intent.custody_committee_authorization(),
        intent.nodes().to_vec(),
    )?
    .for_attempt(attempt.attempt())?;
    if !intent.same_authority_as(&expected) {
        return Err(RuntimeCustodyAttemptConflict::error(
            RuntimeCustodyAttemptConflictReason::AuthorityChanged,
        ));
    }
    let record = finish_runtime_custody_remote_mint(data_dir, registry, &journal, intent, || {
        crate::remote_seal_source::RemoteSealObjectBytes::from_authorized_bytes(
            &input.clear_plaintext,
            intent,
        )
    })
    .await?;
    load_completed_runtime_mint_object_facts(&journal, input, record.draft().mint_id())
}

/// The result of a v2 protect: the protected package already laid out in a
/// private staging directory (the segments were written as they were produced,
/// never held together), the head that commits to it, and the key envelope.
/// Dropping it removes the staging directory.
pub(super) struct ProtectedRuntimeCustodyMediaDash {
    pub(super) staging: tempfile::TempDir,
    pub(super) media_identity: CencDashMediaIdentityV2,
    pub(super) envelope: CustodyEnvelopeV1,
}

enum RuntimeProtectRecoveryDisposition {
    Fresh,
    ReplayOpenAndSettleCancel,
    SettleCancel([u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]),
    SettleClose([u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]),
    TerminalAbort,
}

pub(super) async fn protect_runtime_custody_media(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectedRuntimeCustodyMediaDash> {
    let open_request =
        runtime_custody_open_protection_session_request(composition, input, mint_intent)?;
    match runtime_protect_recovery_disposition(mint_intent) {
        RuntimeProtectRecoveryDisposition::TerminalAbort => {
            // This intent settled its protect session before any draft existed,
            // so it can produce nothing and there is no record to adopt. Its
            // identity comes from the object path, so keeping it makes that
            // file unmintable for good. Forget it: this attempt still fails,
            // but the next one starts from nothing instead of meeting the same
            // wall forever.
            tracing::warn!(
                request_id = %hex::encode(mint_intent.request_id().as_bytes()),
                "runtime custody mint intent settled before any draft and was discarded"
            );
            journal
                .discard_unmintable_intent(mint_intent.request_id())
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleCancel(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleClose(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::ReplayOpenAndSettleCancel => {
            if !registry
                .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
                .await
            {
                return Err(runtime_custody_dispatch_uncertain());
            }
            let opened =
                invoke_typed_protect_provider(registry, "open_protection_session", &open_request)
                    .await
                    .map_err(|_| runtime_custody_dispatch_uncertain())?;
            if opened.status() != ProtectProviderResponseStatusV1::ProtectionSessionOpened {
                return Err(runtime_custody_dispatch_uncertain());
            }
            let handle = opened
                .protection_session_handle()
                .map_err(|_| runtime_custody_dispatch_uncertain())?
                .ok_or_else(runtime_custody_dispatch_uncertain)?;
            journal
                .mark_intent_protect_opened(mint_intent.request_id(), handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::Fresh => {}
    }

    if !registry
        .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
    {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    journal
        .mark_intent_protect_effect_started(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let opened =
        invoke_typed_protect_provider(registry, "open_protection_session", &open_request).await?;
    if opened.status() != ProtectProviderResponseStatusV1::ProtectionSessionOpened {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    let handle = opened
        .protection_session_handle()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    journal
        .mark_intent_protect_opened(mint_intent.request_id(), handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let protect_result = protect_opened_runtime_custody_session(
        data_dir,
        registry,
        journal,
        mint_intent.request_id(),
        handle,
        &opened,
        input,
        composition,
        mint_intent.content_access_id(),
    )
    .await;
    match protect_result {
        Ok(protected) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            Ok(protected)
        }
        Err(error) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await
            .map_err(|_| runtime_custody_dispatch_uncertain())?;
            Err(error)
        }
    }
}

/// The result of an object protect: the framed object already written to its
/// private staging file (each chunk was written as the provider returned it,
/// never held together), the identity that commits to it, and the key
/// envelope. Dropping it removes the staging directory.
struct ProtectedRuntimeCustodyObject {
    staging: tempfile::TempDir,
    object_identity: ChunkedPayloadObjectIdentityV1,
    envelope: CustodyEnvelopeV1,
}

/// Object twin of `protect_runtime_custody_media`. Reuses
/// `runtime_protect_recovery_disposition` and
/// `settle_runtime_custody_protect_session` UNCHANGED: both are already
/// content-kind-agnostic (they only ever inspect the mint intent's protect
/// recovery fields and dispatch the shared, kind-agnostic
/// `cancel_protection_session`/`close_protection_session` ops by opaque
/// handle), so the object-specific session-open/chunk/finalize sequence is
/// the only new logic here — the recovery/settlement state machine that
/// makes this resumable across restarts is not duplicated.
async fn protect_runtime_custody_object(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    content_type: &str,
    clear_plaintext: &[u8],
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectedRuntimeCustodyObject> {
    let open_request = runtime_custody_open_object_protection_session_request(
        composition,
        content_type,
        clear_plaintext.len() as u64,
        mint_intent,
    )?;
    let session_handle = *mint_intent.request_id().as_bytes();
    match runtime_protect_recovery_disposition(mint_intent) {
        RuntimeProtectRecoveryDisposition::TerminalAbort => {
            // This intent settled its protect session before any draft existed,
            // so it can produce nothing and there is no record to adopt. Its
            // identity comes from the object path, so keeping it makes that
            // file unmintable for good. Forget it: this attempt still fails,
            // but the next one starts from nothing instead of meeting the same
            // wall forever.
            tracing::warn!(
                request_id = %hex::encode(mint_intent.request_id().as_bytes()),
                "runtime custody mint intent settled before any draft and was discarded"
            );
            journal
                .discard_unmintable_intent(mint_intent.request_id())
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleCancel(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleClose(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::ReplayOpenAndSettleCancel => {
            if !registry
                .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
                .await
            {
                return Err(runtime_custody_dispatch_uncertain());
            }
            let opened = invoke_typed_protect_provider(
                registry,
                "open_object_protection_session",
                &open_request,
            )
            .await
            .map_err(|_| runtime_custody_dispatch_uncertain())?;
            if opened.status() != ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened {
                return Err(runtime_custody_dispatch_uncertain());
            }
            journal
                .mark_intent_protect_opened(mint_intent.request_id(), session_handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                session_handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::Fresh => {}
    }

    if !registry
        .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
    {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    journal
        .mark_intent_protect_effect_started(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let opened =
        invoke_typed_protect_provider(registry, "open_object_protection_session", &open_request)
            .await?;
    if opened.status() != ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    journal
        .mark_intent_protect_opened(mint_intent.request_id(), session_handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let protect_result = protect_opened_runtime_custody_object_session(
        data_dir,
        registry,
        journal,
        mint_intent.request_id(),
        session_handle,
        &opened,
        content_type,
        clear_plaintext,
        composition,
    )
    .await;
    match protect_result {
        Ok(protected) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                session_handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            Ok(protected)
        }
        Err(error) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                session_handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await
            .map_err(|_| runtime_custody_dispatch_uncertain())?;
            Err(error)
        }
    }
}

fn runtime_custody_open_object_protection_session_request(
    composition: &RuntimeCustodyComposition,
    content_type: &str,
    plaintext_bytes: u64,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectProviderRequestV1> {
    let nodes = composition
        .nodes
        .iter()
        .map(|node| {
            ProtectionSessionNodeV1::new(node.node_public_key, node.custody_public_key)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    ProtectProviderRequestV1::new_open_object_protection_session(
        mint_intent.request_id(),
        mint_intent.content_access_id(),
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        // The object protect provider enforces exactly 2-of-3 regardless of
        // what is requested here (Task 10 review, Important 2); this mirrors
        // that fixed value rather than exposing it as a caller choice.
        2,
        3,
        content_type.to_string(),
        plaintext_bytes,
        nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "This operation keeps protect-session authority and settlement inputs explicit at one boundary"
)]
async fn protect_opened_runtime_custody_object_session(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    opened: &ProtectProviderResponseV1,
    content_type: &str,
    clear_plaintext: &[u8],
    composition: &RuntimeCustodyComposition,
) -> anyhow::Result<ProtectedRuntimeCustodyObject> {
    let framed_header = opened
        .framed_header()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .to_vec();
    let staging = create_protected_content_object_staging_directory(data_dir)?;
    let epc1 = fs::File::create(staging.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH))
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    let mut sink = ObjectFramedStagingSink::new(std::io::BufWriter::new(epc1));
    sink.push(&framed_header)?;
    let session_id = Digest32::new(handle);
    for (chunk_index, chunk) in clear_plaintext
        .chunks(MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1)
        .enumerate()
    {
        let chunk_index = u32::try_from(chunk_index)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?;
        let protected = invoke_typed_protect_provider(
            registry,
            "protect_object_chunk",
            &ProtectProviderRequestV1::new_protect_object_chunk(session_id, chunk_index, chunk)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        )
        .await?;
        if protected.status() != ProtectProviderResponseStatusV1::ObjectChunkProtected {
            anyhow::bail!("Runtime custody protect provider is unavailable");
        }
        sink.push(
            protected
                .framed_chunk()
                .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
        )?;
    }
    let (framed_encrypted_content, _) = sink.finish()?;
    let finalized = invoke_typed_protect_provider(
        registry,
        "finalize_object_protection_session",
        &ProtectProviderRequestV1::new_finalize_object_protection_session(
            session_id,
            &framed_encrypted_content,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
    )
    .await?;
    if finalized.status() != ProtectProviderResponseStatusV1::ObjectProtectionSessionFinalized {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    let object_identity = finalized
        .object_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let envelope = finalized
        .custody_envelope()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let expected_object = ChunkedPayloadObjectIdentityV1::new(
        framed_encrypted_content,
        content_type,
        clear_plaintext.len() as u64,
        u32::try_from(framed_header.len())
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    if object_identity != expected_object
        || envelope.manifest().encrypted_content() != object_identity.encrypted_content()
        || envelope.manifest().custody_pool()
            != composition
                .signed_pool
                .pool_identity()
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?
        || envelope.manifest().custody_epoch()
            != composition
                .signed_epoch
                .epoch_identity()
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?
        || envelope.manifest().custody_committee_authorization()
            != composition
                .signed_committee_authorization
                .authorization_identity()
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?
    {
        anyhow::bail!("Runtime custody protect output is invalid");
    }
    // No object-analogue of media's `content_access_id` cross-check: the
    // media response's `ValidatedCencFmp4MediaSessionLayoutV1` structurally
    // carries `content_access_id` (verified above via
    // `protected_session.content_access_id() != content_access_id` in
    // `protect_opened_runtime_custody_session`), but neither
    // `ObjectProtectionSessionOpened` nor `ObjectProtectionSessionFinalized`
    // carries any artefact binding the session to the requested
    // `content_access_id` — the object protect-provider contract (Task 8)
    // has no field to check here. `content_access_id` is still bound
    // one layer up, into the mint draft itself
    // (`RuntimeMintDraft::new_from_identity`'s `content_access_id` argument),
    // so a wrong id cannot silently propagate into the completed mint; it
    // just is not independently re-verified against the protect session the
    // way media's is.
    journal
        .mark_intent_protect_finalized(request_id, handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(ProtectedRuntimeCustodyObject {
        staging,
        object_identity,
        envelope,
    })
}

fn runtime_protect_recovery_disposition(
    mint_intent: &RuntimeMintIntent,
) -> RuntimeProtectRecoveryDisposition {
    if let Some(handle) = mint_intent.protect_pending_close_handle() {
        RuntimeProtectRecoveryDisposition::SettleClose(handle)
    } else if let Some(handle) = mint_intent.protect_pending_cancel_handle() {
        RuntimeProtectRecoveryDisposition::SettleCancel(handle)
    } else if mint_intent.protect_open_request_pending() {
        RuntimeProtectRecoveryDisposition::ReplayOpenAndSettleCancel
    } else if mint_intent.protect_terminal_before_draft() {
        RuntimeProtectRecoveryDisposition::TerminalAbort
    } else {
        RuntimeProtectRecoveryDisposition::Fresh
    }
}

fn runtime_custody_open_protection_session_request(
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectProviderRequestV1> {
    let nodes = composition
        .nodes
        .iter()
        .map(|node| {
            ProtectionSessionNodeV1::new(node.node_public_key, node.custody_public_key)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let representations = input
        .media
        .renditions
        .iter()
        .map(|rendition| {
            let (mime_type, codecs) = pinned_declaration_v2(rendition.kind);
            ProtectionRepresentationV2::new(
                rendition.kind,
                mime_type,
                codecs,
                rendition.segment_count,
                &rendition.clear_init_segment,
            )
            .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    ProtectProviderRequestV1::new_open_protection_session_v2(
        mint_intent.request_id(),
        mint_intent.content_access_id(),
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        representations,
        // The Runtime adds no foreign protection-system boxes of its own.
        &[],
        nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))
}

enum RuntimeProtectSessionSettlementOp {
    Cancel,
    Close,
}

async fn settle_runtime_custody_protect_session(
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    op: RuntimeProtectSessionSettlementOp,
) -> anyhow::Result<()> {
    let (provider_op, request) = match op {
        RuntimeProtectSessionSettlementOp::Cancel => (
            "cancel_protection_session",
            ProtectProviderRequestV1::new_cancel_protection_session(handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        ),
        RuntimeProtectSessionSettlementOp::Close => (
            "close_protection_session",
            ProtectProviderRequestV1::new_close_protection_session(handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        ),
    };
    let response = invoke_typed_protect_provider(registry, provider_op, &request).await?;
    match (op, response.status()) {
        (
            RuntimeProtectSessionSettlementOp::Cancel,
            ProtectProviderResponseStatusV1::ProtectionSessionCancelled,
        ) => {
            journal
                .mark_intent_protect_cancelled_before_draft(request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        }
        (
            RuntimeProtectSessionSettlementOp::Close,
            ProtectProviderResponseStatusV1::ProtectionSessionClosed,
        ) => {
            journal
                .mark_intent_protect_closed_before_draft(request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        }
        (
            RuntimeProtectSessionSettlementOp::Cancel | RuntimeProtectSessionSettlementOp::Close,
            ProtectProviderResponseStatusV1::ProtectionSessionAlreadyAbsent,
        ) => {
            journal
                .mark_intent_protect_already_absent_before_draft(request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        }
        _ => return Err(runtime_custody_dispatch_uncertain()),
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "This operation keeps protect-session authority and settlement inputs explicit at one boundary"
)]
async fn protect_opened_runtime_custody_session(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    opened: &ProtectProviderResponseV1,
    input: &RuntimeCustodyLibraryPublishInput,
    composition: &RuntimeCustodyComposition,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<ProtectedRuntimeCustodyMediaDash> {
    const INVALID_OUTPUT: &str = "Runtime custody protect output is invalid";
    let renditions = &input.media.renditions;
    // One protected init per rendition, in request order.
    let protected_inits: Vec<Vec<u8>> = opened
        .protected_init_segments()
        .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    if protected_inits.len() != renditions.len()
        || protected_inits
            .iter()
            .any(|init| init.is_empty() || init.len() > MAX_PROTECT_MEDIA_PART_BYTES_V1)
    {
        anyhow::bail!(INVALID_OUTPUT);
    }
    let staging = create_protected_content_staging_directory(data_dir)?;
    for (rendition, init) in renditions.iter().zip(&protected_inits) {
        write_protected_content_staging_file(
            staging.path(),
            &runtime_media_dash_init_path(rendition.kind),
            init,
        )?;
    }
    // The head is rebuilt here from the protected parts as they come, so the
    // provider's finalized head is checked against the Runtime's own.
    let mut builder = CencDashIdentityBuilderV2::new(
        content_access_id,
        renditions
            .iter()
            .zip(&protected_inits)
            .map(|(rendition, init)| {
                CencDashRenditionDeclV2::from_init(
                    rendition.kind,
                    rendition.timescale,
                    init,
                    rendition.segment_count,
                )
            })
            .collect(),
    )
    .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    let mut receipt = RuntimeMediaPreparationReceiptV2::new(renditions.len())?;
    let mut mpd_segments: Vec<Vec<CencDashMpdSegmentV2>> = Vec::with_capacity(renditions.len());
    for (rendition_index, rendition) in renditions.iter().enumerate() {
        let rendition_index_wire = u8::try_from(rendition_index)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?;
        let clear_session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &rendition.clear_init_segment,
            CencLayoutProfile::V2,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        receipt.begin_rendition(
            rendition.kind,
            &rendition.clear_init_segment,
            rendition.segment_count,
        );
        let mut rendition_segments = Vec::with_capacity(rendition.segment_count as usize);
        for segment_index in 0..rendition.segment_count {
            // One clear part and one protected part are alive at a time, so the
            // memory of a mint does not grow with the duration.
            let clear = read_runtime_media_prepared_part(
                &runtime_prepared_segment_path(
                    &input.media.operation_root,
                    rendition.kind,
                    segment_index,
                ),
                true,
                MEDIA_PROVIDER_MAX_PREPARED_PART_BYTES_V2,
            )?;
            #[cfg(test)]
            input
                .media
                .part_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let timeline = clear_session
                .validate_segment(&clear)
                .ok()
                .and_then(|layout| layout.timeline())
                .ok_or_else(invalid_prepared_media_output)?;
            receipt.push_segment(segment_index, &clear);
            let request = ProtectProviderRequestV1::new_protect_media_segment_v2(
                handle,
                rendition_index_wire,
                segment_index,
                &clear,
            )
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?;
            drop(clear);
            let response =
                invoke_typed_protect_provider(registry, "protect_media_segment", &request).await?;
            drop(request);
            match response.status() {
                ProtectProviderResponseStatusV1::MediaSegmentProtected
                    if response.segment_index() == Some(segment_index) => {}
                ProtectProviderResponseStatusV1::Failure
                    if response.failure_reason()
                        == Some(ProtectFailureReasonV2::CencTooManySubsamples) =>
                {
                    anyhow::bail!(RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE);
                }
                _ => anyhow::bail!("Runtime custody protect provider is unavailable"),
            }
            let protected = response
                .protected_segment()
                .filter(|protected| !protected.is_empty())
                .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?;
            // The viewer fetches and decrypts a protected segment only up to
            // this size, so a larger one could never be played: refuse it here,
            // before anything of it is staged or published.
            if protected.len() > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 {
                anyhow::bail!(RUNTIME_CUSTODY_MEDIA_PART_TOO_LARGE_MESSAGE);
            }
            write_protected_content_staging_file(
                staging.path(),
                &runtime_media_dash_segment_path(rendition.kind, segment_index),
                protected,
            )?;
            builder
                .push_segment(protected)
                .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
            rendition_segments.push(CencDashMpdSegmentV2 {
                timeline,
                bytes: protected.len() as u64,
            });
        }
        mpd_segments.push(rendition_segments);
    }
    if receipt.finish() != input.media.preparation_receipt() {
        anyhow::bail!("Runtime custody media preparation output changed");
    }
    let finalized = invoke_typed_protect_provider(
        registry,
        "finalize_protection_session",
        &ProtectProviderRequestV1::new_finalize_protection_session(handle)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
    )
    .await?;
    if finalized.status() != ProtectProviderResponseStatusV1::ProtectionSessionFinalized {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    let media_identity = finalized
        .media_identity_v2()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?
        .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?;
    let envelope = finalized
        .custody_envelope()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?
        .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?;
    let expected_media = builder
        .finish()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    let sessions = protected_inits
        .iter()
        .enumerate()
        .map(|(index, init)| ValidatedCencDashRenditionSessionV2::new(&media_identity, index, init))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    let custody_pool = composition
        .signed_pool
        .pool_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?;
    let custody_epoch = composition
        .signed_epoch
        .epoch_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?;
    let custody_committee_authorization = composition
        .signed_committee_authorization
        .authorization_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?;
    // The CENC protection header the provider wrote into every init ships in a
    // public media file and is what a client reading the artifacts directly
    // will route on. Every rendition must carry one and the same header, under
    // one protection system, and it must name exactly this session's content
    // access id, pool, epoch and committee authorization. A provider that
    // omits it, or points it at some other quorum, fails here rather than
    // publishing. Every init must also have been written by the active
    // encoder: a new mint is produced only by the writer binding.
    let expected_protection_header = CustodyProtectionHeader::new(
        content_access_id,
        &custody_pool,
        &custody_epoch,
        &custody_committee_authorization,
        CencMediaSuite::DashV2,
    );
    let common_protection_header =
        elastos_protected_content_custody::require_common_cenc_dash_protection_header_v2(
            &media_identity,
            &sessions,
        )
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    if media_identity != expected_media
        || media_identity.default_kid() != content_access_id
        || *common_protection_header != expected_protection_header
        || !sessions
            .iter()
            .all(ValidatedCencDashRenditionSessionV2::protected_by_active_encoder)
        || envelope.manifest().encrypted_content() != media_identity.encrypted_content()
        || envelope.manifest().custody_pool() != custody_pool
        || envelope.manifest().custody_epoch() != custody_epoch
        || envelope.manifest().custody_committee_authorization() != custody_committee_authorization
    {
        anyhow::bail!(INVALID_OUTPUT);
    }
    write_protected_content_staging_file(
        staging.path(),
        PROTECTED_CONTENT_V2_IDENTITY_PATH,
        &media_identity
            .canonical_bytes()
            .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?,
    )?;
    let mpd = build_cenc_dash_mpd_v2(
        &protected_inits
            .iter()
            .zip(&mpd_segments)
            .map(|(protected_init, segments)| CencDashMpdRenditionV2 {
                protected_init,
                segments,
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    write_protected_content_staging_file(
        staging.path(),
        PROTECTED_CONTENT_V2_MPD_PATH,
        mpd.as_bytes(),
    )?;
    // The full check, once, on the private staging tree and before any draft
    // or custody effect exists: invalid output never reaches custody.
    let timelines: Vec<Vec<Fmp4SegmentTimelineV2>> = mpd_segments
        .iter()
        .map(|segments| segments.iter().map(|segment| segment.timeline).collect())
        .collect();
    verify_protected_content_dash_directory(staging.path(), &media_identity, Some(&timelines))?;
    journal
        .mark_intent_protect_finalized(request_id, handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(ProtectedRuntimeCustodyMediaDash {
        staging,
        media_identity,
        envelope,
    })
}

async fn invoke_typed_protect_provider(
    registry: &ProviderRegistry,
    op: &str,
    request: &ProtectProviderRequestV1,
) -> anyhow::Result<ProtectProviderResponseV1> {
    let request_value = serde_json::from_slice(
        &request
            .to_json_vec()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?;
    let data = invoke_json_provider(registry, PROTECT_PROVIDER_ID, op, request_value)
        .await
        .map_err(|_| anyhow::anyhow!("Runtime custody protect provider is unavailable"))?;
    ProtectProviderResponseV1::from_json_slice(
        &serde_json::to_vec(&data)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))
}

/// The private directory a package is staged in before it is published.
pub(crate) fn create_protected_content_staging_directory(
    data_dir: &Path,
) -> anyhow::Result<tempfile::TempDir> {
    let parent = protected_content_root(data_dir);
    fs::create_dir_all(&parent)?;
    tempfile::Builder::new()
        .prefix("publish-")
        .tempdir_in(&parent)
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))
}

/// Writes one staged file, creating its directories. A file is written once:
/// an existing one is an error, never overwritten.
fn write_protected_content_staging_file(
    staging: &Path,
    relative: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    const UNAVAILABLE: &str = "Runtime custody publish staging is unavailable";
    let path = staging.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| anyhow::anyhow!(UNAVAILABLE))?;
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|_| anyhow::anyhow!(UNAVAILABLE))?;
    file.write_all(bytes)
        .map_err(|_| anyhow::anyhow!(UNAVAILABLE))
}

/// Creates the private `publish-*` directory and its `protected-content/v1`
/// tree. Protect writes `object.epc1` into it as the chunks arrive.
pub(crate) fn create_protected_content_object_staging_directory(
    data_dir: &Path,
) -> anyhow::Result<tempfile::TempDir> {
    let parent = protected_content_root(data_dir);
    fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("publish-")
        .tempdir_in(&parent)
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    fs::create_dir_all(staging.path().join("protected-content/v1"))
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    Ok(staging)
}

pub(crate) fn write_protected_content_object_manifest(
    directory: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<()> {
    fs::write(
        directory.join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        protected_content_object_manifest_bytes(object_identity)?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))
}

/// Writes the framed object straight to its staging file and hashes it as it
/// goes, so protecting an object never holds the framed bytes together.
pub(super) struct ObjectFramedStagingSink<W: std::io::Write> {
    writer: W,
    hasher: sha2::Sha256,
    bytes: u64,
}

impl<W: std::io::Write> ObjectFramedStagingSink<W> {
    pub(super) fn new(writer: W) -> Self {
        Self {
            writer,
            hasher: sha2::Sha256::new(),
            bytes: 0,
        }
    }

    pub(super) fn push(&mut self, framed: &[u8]) -> anyhow::Result<()> {
        self.writer
            .write_all(framed)
            .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
        self.hasher.update(framed);
        self.bytes = self
            .bytes
            .checked_add(framed.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
        Ok(())
    }

    pub(super) fn finish(mut self) -> anyhow::Result<(EncryptedContentIdentityV1, W)> {
        self.writer
            .flush()
            .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
        let identity = EncryptedContentIdentityV1::new(
            Digest32::new(self.hasher.finalize().into()),
            self.bytes,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
        Ok((identity, self.writer))
    }
}

/// Test-only observability for the purchase-ledger lock: proves
/// `persist_runtime_custody_purchase` callers for the *same* lock path never
/// hold their critical section concurrently, without exposing anything from
/// production builds. Keyed by lock path so unrelated tests running in
/// parallel (distinct temp data dirs) cannot produce a false positive.
/// Compiled out entirely outside `cfg(test)`.
#[cfg(test)]
pub(super) static RUNTIME_PURCHASE_LOCK_TEST_STATE: OnceLock<
    StdMutex<HashMap<PathBuf, (usize, bool)>>,
> = OnceLock::new();

#[cfg(test)]
pub(crate) fn runtime_purchase_lock_test_overlap_detected(path: &Path) -> bool {
    runtime_purchase_lock_test_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(path)
        .is_some_and(|(_, overlapped)| *overlapped)
}

/// Remove `attempt`'s listing-package purchase record, under the purchase
/// ledger lock, and only while the record on disk is still that attempt: a
/// `Pending` purchase of the same mint with the same buy effect, created at
/// the same moment. `Ok(false)` when the record is gone, complete, or another
/// attempt -- which is then left exactly as it is.
///
/// Only for an attempt that is provably over without payment (R41). The
/// caller holds the market-purchase lock around this, so the removal and
/// R29's cross-path check never interleave.
pub(crate) fn retire_runtime_custody_purchase_attempt(
    data_dir: &Path,
    attempt: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<bool> {
    remove_runtime_custody_purchase_if(data_dir, attempt, |current| {
        matches!(
            current.progress,
            RuntimeCustodyPurchaseProgress::Pending { .. }
        ) && current.acquisition_stage.effect_id == attempt.acquisition_stage.effect_id
            && current.created_at == attempt.created_at
    })
}
