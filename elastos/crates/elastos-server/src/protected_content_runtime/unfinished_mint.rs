//! Unfinished creator mints: which of them a creator is offered back, and how
//! an attempt that never sent a transaction is set aside so a new mint of the
//! same file proceeds.
//!
//! An attempt that sent nothing on chain never blocks a new one. It is
//! archived -- its journal records moved aside under
//! `protected-content/runtime-mint-set-aside-<date>/`, never deleted -- and
//! the source moves on to a new attempt with an identity of its own. An
//! attempt whose transaction was sent or mined is never archived: it keeps its
//! terms and is finished by Resume, so no token is ever left behind.
//! [`RuntimeCustodyUnfinishedMintStage::may_start_over`] is that rule;
//! [`RuntimeCustodyUnfinishedMintStage::recoverable`] decides whether Creator
//! offers an attempt back or archives it without asking.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use elastos_protected_content_contracts::Digest32;
use elastos_protected_content_runtime::{
    PersistedRuntimeMint, RuntimeCustodyTerminalKind, RuntimeMintArchivedAttemptV1,
    RuntimeMintCreatorDesiredTerms, RuntimeMintCreatorStage, RuntimeMintJournalError,
};
use serde_json::{json, Value};

/// Resume found no recorded terms to run from: the attempt stopped before its
/// terms were recorded, so only the creator can supply them.
pub(crate) const RUNTIME_CUSTODY_CREATOR_NOTHING_TO_RESUME_MESSAGE: &str =
    "This file has no recorded terms to resume from. Enter its terms and protect it again";

/// What the Wallet says about the one transaction a creator attempt raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyCreatorEffectProgress {
    /// The approval is out and nobody has answered it.
    AwaitingApproval,
    /// The approval expired or was declined, and nothing was ever signed.
    ClosedWithoutTransaction,
    /// Something was signed or sent; it may already be on chain.
    Sent,
    /// The transaction has a receipt.
    Mined,
    /// The approval went to an external connector that signs and broadcasts
    /// outside the Wallet, so nothing the Wallet says proves nothing was sent.
    InConnector { connector: String },
    /// The Wallet could not be asked. Never read as closed.
    WalletUnreachable,
    /// Neither the effect store nor the Wallet holds the approval. Never read
    /// as closed: an evicted record looks the same as one never raised.
    NotOnRecord,
}

/// How far an unfinished creator mint got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyUnfinishedMintStage {
    /// The custody fan-out never settled; shares may already be on nodes.
    EscrowIncomplete,
    /// Escrowed, and the ciphertext never reached verified availability.
    PublishIncomplete,
    /// Terms recorded, nothing raised on any ledger.
    RecordedOnly,
    /// A Wallet approval is out.
    ApprovalPending,
    /// The approval went to an external connector, which may sign and send
    /// without the Wallet knowing.
    ApprovalInConnector,
    /// The approval expired or was declined before anything was signed.
    ApprovalClosed,
    /// Signed or sent, no receipt yet.
    TransactionSent,
    /// The transaction has a receipt; the mint has not settled here yet.
    TransactionMined,
    /// A transaction was raised and its state could not be confirmed.
    TransactionUnconfirmed,
    /// Settled on chain, and the listing was never finished.
    ListingNotAssembled,
}

impl RuntimeCustodyUnfinishedMintStage {
    pub(crate) const fn wire_value(self) -> &'static str {
        match self {
            Self::EscrowIncomplete => "escrow_incomplete",
            Self::PublishIncomplete => "publish_incomplete",
            Self::RecordedOnly => "recorded_only",
            Self::ApprovalPending => "approval_pending",
            Self::ApprovalInConnector => "approval_in_connector",
            Self::ApprovalClosed => "approval_closed",
            Self::TransactionSent => "transaction_sent",
            Self::TransactionMined => "transaction_mined",
            Self::TransactionUnconfirmed => "transaction_unconfirmed",
            Self::ListingNotAssembled => "listing_not_assembled",
        }
    }

    /// An attempt is recoverable when anything irreversible or costly already
    /// happened: the key was escrowed to the pool, a Wallet approval is still
    /// out, or a transaction was sent or mined. Creator offers those back. It
    /// is unrecoverable when nothing of that kind came of it -- terms recorded
    /// and nothing raised, or an approval that expired or was declined before
    /// anything was signed -- and those are archived without asking. An
    /// unknown is always read as recoverable.
    pub(crate) const fn recoverable(self) -> bool {
        !matches!(self, Self::RecordedOnly | Self::ApprovalClosed)
    }

    /// The never-block rule, in one place: what may happen to this attempt
    /// when a new mint of the same file starts, or the creator chooses Start
    /// over. Both the archive path and [`Self::may_start_over`] read it.
    ///
    /// Only an attempt that put nothing on chain is set aside. A pending
    /// approval in the Wallet is declined first and the attempt set aside only
    /// once the Wallet confirms it closed with nothing signed. An attempt whose
    /// transaction was sent or mined, or that settled, keeps its terms and is
    /// finished by Resume. One whose state cannot be confirmed -- the Wallet
    /// cannot be asked, the approval is not on record, or it went to an
    /// external connector -- is refused, and Resume is its way on.
    pub(crate) const fn disposition(self) -> RuntimeCustodyAttemptDisposition {
        match self {
            Self::EscrowIncomplete
            | Self::PublishIncomplete
            | Self::RecordedOnly
            | Self::ApprovalClosed => RuntimeCustodyAttemptDisposition::SetAside,
            Self::ApprovalPending => RuntimeCustodyAttemptDisposition::SetAsideOnceDeclined,
            Self::TransactionSent | Self::TransactionMined | Self::ListingNotAssembled => {
                RuntimeCustodyAttemptDisposition::Keep
            }
            Self::ApprovalInConnector | Self::TransactionUnconfirmed => {
                RuntimeCustodyAttemptDisposition::Refuse
            }
        }
    }

    /// Whether Start over may be offered for this attempt.
    pub(crate) const fn may_start_over(self) -> bool {
        matches!(
            self.disposition(),
            RuntimeCustodyAttemptDisposition::SetAside
                | RuntimeCustodyAttemptDisposition::SetAsideOnceDeclined
        )
    }

    /// Whether Resume can run from recorded terms. The two stages before
    /// terms are recorded can only continue once the creator enters them.
    pub(crate) const fn has_recorded_terms(self) -> bool {
        !matches!(self, Self::EscrowIncomplete | Self::PublishIncomplete)
    }
}

/// What [`RuntimeCustodyUnfinishedMintStage::disposition`] allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyAttemptDisposition {
    /// Nothing went on chain: set it aside.
    SetAside,
    /// Decline its Wallet approval, and set it aside once the Wallet confirms
    /// the approval closed with nothing signed.
    SetAsideOnceDeclined,
    /// A transaction was sent or mined, or the mint settled: keep it, and
    /// refuse other terms naming them.
    Keep,
    /// Its state cannot be confirmed: refuse, and leave it to Resume.
    Refuse,
}

/// Classify one mint record. `effect` is what the Wallet says about the
/// raised transaction, when there is one; `listed` is whether the Library
/// already holds the finished publish of the object.
///
/// `None` means nothing is unfinished: no attempt started past an aborted
/// fan-out, an escrowed and published mint whose terms were never recorded
/// (a new protect continues from it), or a mint that is finished.
pub(crate) fn classify_runtime_custody_unfinished_mint(
    mint: &PersistedRuntimeMint,
    effect: Option<RuntimeCustodyCreatorEffectProgress>,
    listed: bool,
) -> Option<RuntimeCustodyUnfinishedMintStage> {
    use RuntimeCustodyUnfinishedMintStage as Stage;
    match mint.custody_terminal() {
        // An aborted fan-out is carried out of the way by the next publish of
        // the object; nothing of it can be continued.
        Some(RuntimeCustodyTerminalKind::AbortedPartialProvision) => return None,
        None => return Some(Stage::EscrowIncomplete),
        Some(RuntimeCustodyTerminalKind::CustodyProvisioned) => {}
    }
    if mint.content_availability().is_none() {
        return Some(Stage::PublishIncomplete);
    }
    let creator_state = mint.creator_state()?;
    match creator_state.stage() {
        RuntimeMintCreatorStage::Recorded => Some(Stage::RecordedOnly),
        RuntimeMintCreatorStage::Settled => (!listed).then_some(Stage::ListingNotAssembled),
        // A legacy operator approval is only raised once the mint landed.
        RuntimeMintCreatorStage::EffectRaised if creator_state.operator_approval().is_some() => {
            Some(Stage::TransactionMined)
        }
        RuntimeMintCreatorStage::EffectRaised => Some(match effect {
            Some(RuntimeCustodyCreatorEffectProgress::AwaitingApproval) => Stage::ApprovalPending,
            Some(RuntimeCustodyCreatorEffectProgress::ClosedWithoutTransaction) => {
                Stage::ApprovalClosed
            }
            Some(RuntimeCustodyCreatorEffectProgress::Sent) => Stage::TransactionSent,
            Some(RuntimeCustodyCreatorEffectProgress::Mined) => Stage::TransactionMined,
            Some(RuntimeCustodyCreatorEffectProgress::InConnector { .. }) => {
                Stage::ApprovalInConnector
            }
            Some(
                RuntimeCustodyCreatorEffectProgress::WalletUnreachable
                | RuntimeCustodyCreatorEffectProgress::NotOnRecord,
            )
            | None => Stage::TransactionUnconfirmed,
        }),
    }
}

/// The open mint record for one source object, if its publish ever got as far
/// as one.
pub(crate) fn runtime_custody_open_mint_for_source(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<Option<PersistedRuntimeMint>> {
    let journal = super::runtime_mint_journal(data_dir);
    let attempt = journal
        .current_attempt(principal_id, object_uri, source_storage)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
    match journal.find_mint_record_for_intent(attempt.request_id()) {
        Ok(scan) => Ok(scan.open().cloned()),
        Err(RuntimeMintJournalError::NotFound) => Ok(None),
        Err(_) => anyhow::bail!("Runtime custody mint intent is unavailable"),
    }
}

/// The terms a resume runs from: the ones recorded for this object's mint.
pub(crate) fn runtime_custody_recorded_creator_terms(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<RuntimeMintCreatorDesiredTerms> {
    runtime_custody_open_mint_for_source(data_dir, principal_id, object_uri, source_storage)?
        .as_ref()
        .and_then(PersistedRuntimeMint::creator_state)
        .map(|state| state.desired_terms().clone())
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_CREATOR_NOTHING_TO_RESUME_MESSAGE))
}

/// The recorded terms, as the creator who entered them reads them back. They
/// travel to that creator only -- never into a log.
pub(crate) fn runtime_custody_creator_terms_json(terms: &RuntimeMintCreatorDesiredTerms) -> Value {
    json!({
        "copies": terms.copies(),
        "price": terms.price(),
        "pay_token": terms.pay_token(),
        "channel": terms.ledger(),
        "access_method": terms.access_method(),
        "reseller_cut": terms.reseller_cut(),
        "royalties": terms
            .royalties()
            .iter()
            .map(|royalty| json!({ "address": royalty.address(), "units": royalty.units() }))
            .collect::<Vec<_>>(),
    })
}

/// Which recorded terms a new attempt would change, by name, so a refusal can
/// say which instead of only that they differ.
pub(crate) fn runtime_custody_creator_differing_terms(
    recorded: &RuntimeMintCreatorDesiredTerms,
    requested: &RuntimeMintCreatorDesiredTerms,
) -> Vec<&'static str> {
    [
        (
            "account",
            recorded.wallet_account_id() != requested.wallet_account_id(),
        ),
        ("copies", recorded.copies() != requested.copies()),
        ("price", recorded.price() != requested.price()),
        ("royalties", recorded.royalties() != requested.royalties()),
        (
            "access_method",
            recorded.access_method() != requested.access_method(),
        ),
        (
            "reseller_cut",
            recorded.reseller_cut() != requested.reseller_cut(),
        ),
        ("channel", recorded.ledger() != requested.ledger()),
        ("pay_token", recorded.pay_token() != requested.pay_token()),
    ]
    .into_iter()
    .filter_map(|(name, differs)| differs.then_some(name))
    .collect()
}

/// One unfinished mint as Creator lists it.
pub(crate) fn runtime_custody_unfinished_mint_json(
    mint: &PersistedRuntimeMint,
    stage: RuntimeCustodyUnfinishedMintStage,
) -> Value {
    json!({
        "mint_id": hex::encode(mint.draft().mint_id().as_bytes()),
        "stage": stage.wire_value(),
        "recoverable": stage.recoverable(),
        "resume": if stage.has_recorded_terms() { "recorded_terms" } else { "enter_terms" },
        "can_start_over": stage.may_start_over(),
        "terms": mint
            .creator_state()
            .map(|state| runtime_custody_creator_terms_json(state.desired_terms())),
        "progress": super::runtime_custody_creator_progress(mint),
    })
}

static RUNTIME_CUSTODY_CREATOR_ATTEMPT_LOCKS: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();

/// Serialises everything that decides on a creator attempt and then acts on
/// that decision: raising its Wallet approval, and dropping it.
///
/// Both read the journal and the Wallet before they write, so without one
/// lock a drop could land between a publish's check and its raise, and the
/// approval it then raised would answer to nothing on record.
pub(crate) fn runtime_custody_creator_attempt_lock(
    data_dir: &Path,
    mint_id: Digest32,
) -> Arc<tokio::sync::Mutex<()>> {
    let key = super::runtime_mint_journal_root(data_dir).join(hex::encode(mint_id.as_bytes()));
    let mut locks = match RUNTIME_CUSTODY_CREATOR_ATTEMPT_LOCKS
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
    {
        Ok(locks) => locks,
        Err(poisoned) => poisoned.into_inner(),
    };
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

/// Why an attempt was archived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyAttemptArchiveReason {
    /// A new mint of the same file started.
    NewAttempt,
    /// The creator chose Start over.
    StartOver,
    /// Nothing irreversible came of it, so it was set aside without asking.
    Unrecoverable,
}

impl RuntimeCustodyAttemptArchiveReason {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::NewAttempt => "new_attempt",
            Self::StartOver => "start_over",
            Self::Unrecoverable => "unrecoverable",
        }
    }
}

/// A publish set its source's unfinished attempt aside and has to run again,
/// as the new attempt it now is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeCustodyCreatorAttemptArchived;

impl std::fmt::Display for RuntimeCustodyCreatorAttemptArchived {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "The earlier unfinished attempt to protect this file was set aside; protecting it again starts a new one",
        )
    }
}

impl std::error::Error for RuntimeCustodyCreatorAttemptArchived {}

/// Whether a settled mint's listing was published, which makes it a listing
/// people can buy rather than an unfinished attempt. Fails closed: a listing
/// file that exists and cannot be read is an error, never "not listed".
pub(crate) fn runtime_custody_mint_is_finished(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
) -> anyhow::Result<bool> {
    if !mint
        .creator_state()
        .is_some_and(|state| state.stage() == RuntimeMintCreatorStage::Settled)
    {
        return Ok(false);
    }
    match super::load_runtime_custody_listing(data_dir, mint.draft().mint_id()) {
        Ok(listing) => Ok(listing.is_some()),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "runtime custody creator mint: a settled mint's listing could not be read; keeping it"
            );
            Err(RuntimeCustodyAttemptConflict::error(
                RuntimeCustodyAttemptConflictReason::ListingUnreadable,
            ))
        }
    }
}

/// What the caller knows about the attempt it is archiving.
pub(crate) struct RuntimeCustodyAttemptArchive<'a> {
    pub(crate) mint: Option<&'a PersistedRuntimeMint>,
    pub(crate) stage: Option<RuntimeCustodyUnfinishedMintStage>,
    pub(crate) reason: RuntimeCustodyAttemptArchiveReason,
    /// The attempt's Wallet approval was declined on its behalf, and the
    /// Wallet confirmed it closed before anything was signed.
    pub(crate) approval_declined: bool,
}

/// Archive the current attempt at one source. The caller has classified it,
/// decided it may be archived, and holds the creator attempt lock when it has
/// a mint record. `None` when the source has no attempt on record.
pub(crate) fn archive_runtime_custody_attempt(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
    archive: RuntimeCustodyAttemptArchive<'_>,
) -> anyhow::Result<Option<RuntimeMintArchivedAttemptV1>> {
    let RuntimeCustodyAttemptArchive {
        mint,
        stage,
        reason,
        approval_declined,
    } = archive;
    let journal = super::runtime_mint_journal(data_dir);
    let attempt = journal
        .current_attempt(principal_id, object_uri, source_storage)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let now = crate::auth::now_ts();
    let creator_state = mint.and_then(PersistedRuntimeMint::creator_state);
    let note = json!({
        "schema": RUNTIME_CUSTODY_ATTEMPT_ARCHIVE_SCHEMA_V1,
        "archived_at": now,
        "reason": reason.wire_value(),
        "object_uri": object_uri,
        "attempt": attempt.attempt(),
        "request_id": hex::encode(attempt.request_id().as_bytes()),
        "mint_id": mint.map(|mint| hex::encode(mint.draft().mint_id().as_bytes())),
        "stage": stage.map(RuntimeCustodyUnfinishedMintStage::wire_value),
        "terms": creator_state.map(|state| runtime_custody_creator_terms_json(state.desired_terms())),
        // Only an attempt that sent nothing is ever archived, so this names
        // the approval it raised, if any, and how it was closed.
        "chain": {
            "transaction": "none",
            "effect_id": creator_state.and_then(|state| state.effect()).map(|effect| effect.effect_id()),
            "approval_request_id": creator_state
                .and_then(|state| state.effect())
                .map(|effect| effect.approval_request_id()),
            "approval_declined": approval_declined,
        },
    });
    let archive_dir = data_dir
        .join(super::PROTECTED_CONTENT_ROOT)
        .join(format!("runtime-mint-set-aside-{}", utc_date_stamp(now)));
    let archived = match journal.archive_current_attempt(
        principal_id,
        object_uri,
        source_storage,
        &archive_dir,
        &serde_json::to_vec_pretty(&note)?,
    ) {
        Ok(archived) => archived,
        Err(RuntimeMintJournalError::NotFound) => return Ok(None),
        Err(_) => anyhow::bail!("Runtime custody mint intent is unavailable"),
    };
    tracing::debug!(
        mint_id = ?mint.map(|mint| hex::encode(mint.draft().mint_id().as_bytes())),
        attempt = archived.attempt(),
        reason = reason.wire_value(),
        stage = ?stage.map(RuntimeCustodyUnfinishedMintStage::wire_value),
        approval_declined,
        "runtime custody creator mint: archived an unfinished attempt"
    );
    Ok(Some(archived))
}

/// Wire identity of the note filed beside an archived attempt.
pub(crate) const RUNTIME_CUSTODY_ATTEMPT_ARCHIVE_SCHEMA_V1: &str =
    "elastos.protected-content.runtime-mint-archive/v1";

/// `YYYYMMDD` in UTC, for the archive directory an attempt is filed under.
pub(crate) fn utc_date_stamp(unix_secs: u64) -> String {
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let days = (unix_secs / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}")
}

/// Wire identity of the refusal an app reads when an attempt cannot continue
/// as it stands.
pub(crate) const RUNTIME_CUSTODY_ATTEMPT_CONFLICT_SCHEMA_V1: &str =
    "elastos.protected-content.attempt-conflict/v1";

/// Why an unfinished attempt cannot continue as it stands. Each of these stays
/// refused -- carrying on would bind new work to an attempt it does not belong
/// to -- and each is answered by Start over, which sets the attempt aside so a
/// new one can begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyAttemptConflictReason {
    /// The file's bytes are not the ones the attempt prepared.
    SourceChanged,
    /// The attempt was started under another account, deployment or custody
    /// selection than this request carries.
    AuthorityChanged,
    /// The attempt's protect request was sent and its outcome is unknown, so
    /// it cannot be replayed or dropped here.
    DispatchUncertain,
    /// The attempt's Wallet approval is still open, or could not be confirmed
    /// closed: setting it aside could leave it free to mint later.
    ApprovalOpen,
    /// The attempt's approval went to an external connector, which may sign
    /// and send without the Wallet knowing. Never declined, never set aside.
    ApprovalInConnector,
    /// The attempt settled and its listing file cannot be read, so whether it
    /// is a live listing cannot be told; it is kept as it is.
    ListingUnreadable,
}

/// A refusal of the kind above, carried as data so Creator can offer Start
/// over instead of a dead end. Its sentence is unchanged from before the type
/// existed.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyAttemptConflict {
    reason: RuntimeCustodyAttemptConflictReason,
    /// Whether Start over can set the attempt aside: decided by whoever can
    /// ask the Wallet, and `false` until then.
    can_start_over: bool,
    /// For an approval that could not be confirmed closed: why.
    approval: Option<RuntimeCustodyApprovalConflict>,
}

/// Why an earlier attempt's Wallet approval could not be confirmed closed.
/// Each has its own copy; Resume is the way on for all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyApprovalConflict {
    /// The Wallet still shows it open after the decline was asked for.
    StillOpen,
    /// The Wallet could not be asked.
    WalletUnreachable,
    /// The approval is not on record, so it cannot be shown closed.
    NotOnRecord,
    /// It went to this external connector.
    InConnector(String),
}

impl RuntimeCustodyAttemptConflict {
    pub(crate) fn error(reason: RuntimeCustodyAttemptConflictReason) -> anyhow::Error {
        anyhow::Error::new(Self {
            reason,
            can_start_over: false,
            approval: None,
        })
    }

    /// The refusal of an attempt whose approval could not be confirmed
    /// closed. Nothing is set aside, and Resume is offered.
    pub(crate) fn approval(approval: RuntimeCustodyApprovalConflict) -> anyhow::Error {
        let reason = match approval {
            RuntimeCustodyApprovalConflict::InConnector(_) => {
                RuntimeCustodyAttemptConflictReason::ApprovalInConnector
            }
            _ => RuntimeCustodyAttemptConflictReason::ApprovalOpen,
        };
        anyhow::Error::new(Self {
            reason,
            can_start_over: false,
            approval: Some(approval),
        })
    }

    /// Resume is the way on wherever the earlier attempt holds an approval.
    const fn can_resume(&self) -> bool {
        matches!(
            self.reason,
            RuntimeCustodyAttemptConflictReason::ApprovalOpen
                | RuntimeCustodyAttemptConflictReason::ApprovalInConnector
        )
    }

    /// Only the three refusals that stand in the way of a fresh attempt are
    /// answered by Start over; the other two need the Wallet or an operator.
    pub(crate) const fn answered_by_start_over(&self) -> bool {
        matches!(
            self.reason,
            RuntimeCustodyAttemptConflictReason::SourceChanged
                | RuntimeCustodyAttemptConflictReason::AuthorityChanged
                | RuntimeCustodyAttemptConflictReason::DispatchUncertain
        )
    }

    pub(crate) fn set_can_start_over(&mut self, can_start_over: bool) {
        self.can_start_over = can_start_over && self.answered_by_start_over();
    }

    #[cfg(test)]
    pub(crate) const fn reason(&self) -> RuntimeCustodyAttemptConflictReason {
        self.reason
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_ATTEMPT_CONFLICT_SCHEMA_V1,
            "reason": match self.reason {
                RuntimeCustodyAttemptConflictReason::SourceChanged => "source_changed",
                RuntimeCustodyAttemptConflictReason::AuthorityChanged => "authority_changed",
                RuntimeCustodyAttemptConflictReason::DispatchUncertain => "dispatch_uncertain",
                RuntimeCustodyAttemptConflictReason::ApprovalOpen => "approval_open",
                RuntimeCustodyAttemptConflictReason::ApprovalInConnector => "approval_in_connector",
                RuntimeCustodyAttemptConflictReason::ListingUnreadable => "listing_unreadable",
            },
            "can_start_over": self.can_start_over,
            "can_resume": self.can_resume(),
        });
        match &self.approval {
            Some(RuntimeCustodyApprovalConflict::StillOpen) => {
                answer["cause"] = json!("still_open")
            }
            Some(RuntimeCustodyApprovalConflict::WalletUnreachable) => {
                answer["cause"] = json!("wallet_unreachable")
            }
            Some(RuntimeCustodyApprovalConflict::NotOnRecord) => {
                answer["cause"] = json!("not_on_record")
            }
            Some(RuntimeCustodyApprovalConflict::InConnector(connector)) => {
                answer["connector"] = json!(connector)
            }
            None => {}
        }
        answer
    }
}

impl std::fmt::Display for RuntimeCustodyAttemptConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.approval {
            Some(RuntimeCustodyApprovalConflict::InConnector(connector)) => {
                return write!(
                    formatter,
                    "The earlier approval for this file went to {connector}. Runtime cannot tell whether it was signed there, so that attempt is kept. Resume it to finish."
                );
            }
            Some(RuntimeCustodyApprovalConflict::WalletUnreachable) => {
                return formatter.write_str(
                    "Wallet could not be reached to confirm the earlier approval for this file. Resume it to continue, or try again once Wallet is available.",
                );
            }
            Some(RuntimeCustodyApprovalConflict::NotOnRecord) => {
                return formatter.write_str(
                    "The earlier approval for this file is not on record here, so it cannot be confirmed closed. Resume it to continue.",
                );
            }
            Some(RuntimeCustodyApprovalConflict::StillOpen) | None => {}
        }
        formatter.write_str(match self.reason {
            RuntimeCustodyAttemptConflictReason::SourceChanged => {
                "Runtime custody media preparation conflicts with existing authority"
            }
            RuntimeCustodyAttemptConflictReason::AuthorityChanged => {
                "Runtime custody mint intent conflicts with existing authority"
            }
            RuntimeCustodyAttemptConflictReason::DispatchUncertain => {
                super::RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE
            }
            RuntimeCustodyAttemptConflictReason::ApprovalOpen => {
                "An earlier approval for this file is still open in Wallet. Decline it there, then try again."
            }
            RuntimeCustodyAttemptConflictReason::ApprovalInConnector => {
                "The earlier approval for this file went to an external wallet. Runtime cannot tell whether it was signed there, so that attempt is kept. Resume it to finish."
            }
            RuntimeCustodyAttemptConflictReason::ListingUnreadable => {
                "This file's listing could not be read, so its earlier attempt is kept as it is"
            }
        })
    }
}

impl std::error::Error for RuntimeCustodyAttemptConflict {}

static RUNTIME_CUSTODY_SOURCE_LOCKS: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();

/// Serialises a publish of one source with setting that source's attempt
/// aside, keyed by the source's first-attempt identity. Without it a publish
/// still running after a reload could write into an attempt a Start over is
/// moving.
pub(crate) fn runtime_custody_source_lock(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<Arc<tokio::sync::Mutex<()>>> {
    let base = elastos_protected_content_runtime::RuntimeMintIntent::request_id_for_source(
        principal_id,
        object_uri,
        source_storage,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
    let key = super::runtime_mint_journal_root(data_dir)
        .join(format!("source-{}", hex::encode(base.as_bytes())));
    let mut locks = match RUNTIME_CUSTODY_SOURCE_LOCKS
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
    {
        Ok(locks) => locks,
        Err(poisoned) => poisoned.into_inner(),
    };
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}
