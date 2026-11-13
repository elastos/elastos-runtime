//! Unfinished creator mints, as the gateway sees them: what the Wallet says
//! about each attempt's transaction, and setting an attempt that sent nothing
//! aside so a new mint of the same file proceeds. The rules are
//! [`crate::protected_content_runtime::RuntimeCustodyUnfinishedMintStage::may_start_over`]
//! and
//! [`crate::protected_content_runtime::RuntimeCustodyUnfinishedMintStage::recoverable`].

use super::*;

use crate::protected_content_runtime::{
    RuntimeCustodyApprovalConflict, RuntimeCustodyAttemptArchiveReason,
    RuntimeCustodyAttemptConflict, RuntimeCustodyAttemptDisposition,
    RuntimeCustodyCreatorEffectProgress, RuntimeCustodyUnfinishedMintStage,
};

/// What became of one object's unfinished mint once it was looked at.
#[derive(Debug)]
pub(crate) enum RuntimeCustodyUnfinishedMintOutcome {
    /// Nothing unfinished: no mint, or one that needs nothing from anyone.
    Nothing,
    /// An unrecoverable attempt, now archived.
    Archived,
    /// A recoverable attempt, as Creator lists it.
    Unfinished(serde_json::Value),
}

/// What became of a request to set a source's attempt aside.
#[derive(Debug)]
pub(crate) enum RuntimeCustodyAttemptArchiveOutcome {
    /// The source has no attempt on record.
    Nothing,
    /// The attempt sent its transaction, mined, or is listed: it is never set
    /// aside. It keeps its terms and is finished by Resume.
    Kept {
        mint: Box<elastos_protected_content_runtime::PersistedRuntimeMint>,
        stage: Option<RuntimeCustodyUnfinishedMintStage>,
    },
    /// The attempt was moved aside, and the source is on a new attempt.
    Archived(elastos_protected_content_runtime::RuntimeMintArchivedAttemptV1),
}

impl RuntimeCustodyAttemptArchiveOutcome {
    /// The refusal a kept attempt answers a new mint with: the terms that
    /// would change are named and Resume is offered. `None` for any other
    /// outcome.
    pub(crate) fn kept_refusal(
        &self,
        requested: Option<&elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms>,
    ) -> Option<anyhow::Error> {
        let Self::Kept { mint, stage } = self else {
            return None;
        };
        let recorded = mint.creator_state()?;
        let blocked = crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked::new(
            mint.draft().mint_id(),
            recorded,
        )
        .with_progress(crate::protected_content_runtime::runtime_custody_creator_progress(mint))
        .with_conflict(
            crate::protected_content_runtime::RuntimeCustodyCreatorMintConflict {
                stage: *stage,
                differing_terms: requested
                    .map(|requested| {
                        crate::protected_content_runtime::runtime_custody_creator_differing_terms(
                            recorded.desired_terms(),
                            requested,
                        )
                    })
                    .unwrap_or_default(),
            },
        );
        tracing::warn!(
            state = blocked.state_label(),
            "Runtime custody creator mint kept an attempt whose transaction was sent or mined"
        );
        Some(anyhow::Error::new(blocked))
    }
}

/// What the Wallet says about the transaction this attempt raised, or `None`
/// when it raised none. Nothing uncertain is ever read as closed.
async fn runtime_custody_creator_effect_progress(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
) -> Option<RuntimeCustodyCreatorEffectProgress> {
    let effect = creator_state.effect()?;
    Some(
        match runtime_transaction_effect_progress(state, authority, effect.effect_id()).await {
            Ok(RuntimeTransactionEffectProgress::AwaitingApproval) => {
                RuntimeCustodyCreatorEffectProgress::AwaitingApproval
            }
            Ok(RuntimeTransactionEffectProgress::ClosedWithoutSignature) => {
                RuntimeCustodyCreatorEffectProgress::ClosedWithoutTransaction
            }
            Ok(RuntimeTransactionEffectProgress::Signed) => {
                RuntimeCustodyCreatorEffectProgress::Sent
            }
            Ok(RuntimeTransactionEffectProgress::Mined) => {
                RuntimeCustodyCreatorEffectProgress::Mined
            }
            Ok(RuntimeTransactionEffectProgress::InConnector(connector)) => {
                RuntimeCustodyCreatorEffectProgress::InConnector { connector }
            }
            Ok(RuntimeTransactionEffectProgress::Unknown) => {
                RuntimeCustodyCreatorEffectProgress::NotOnRecord
            }
            Err((status, _)) => {
                tracing::warn!(
                    status = %status,
                    "runtime custody creator mint: the Wallet could not say what became of a raised transaction"
                );
                RuntimeCustodyCreatorEffectProgress::WalletUnreachable
            }
        },
    )
}

/// How far one mint record got. `None` when nothing is unfinished, which
/// includes a settled mint whose listing was published. An unreadable listing
/// is an error, never "not listed".
pub(super) async fn classify_runtime_custody_creator_attempt(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
) -> anyhow::Result<Option<RuntimeCustodyUnfinishedMintStage>> {
    Ok(
        assess_runtime_custody_creator_attempt(state, authority, mint)
            .await?
            .0,
    )
}

/// The stage of one mint record, and what the Wallet said about its
/// transaction on the way there.
async fn assess_runtime_custody_creator_attempt(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
) -> anyhow::Result<(
    Option<RuntimeCustodyUnfinishedMintStage>,
    Option<RuntimeCustodyCreatorEffectProgress>,
)> {
    let listed =
        crate::protected_content_runtime::runtime_custody_mint_is_finished(&state.data_dir, mint)?;
    let effect = match mint.creator_state() {
        Some(creator_state) => {
            runtime_custody_creator_effect_progress(state, authority, creator_state).await
        }
        None => None,
    };
    let stage = crate::protected_content_runtime::classify_runtime_custody_unfinished_mint(
        mint,
        effect.clone(),
        listed,
    );
    Ok((stage, effect))
}

/// The refusal of an attempt whose approval could not be confirmed closed,
/// from what the Wallet last said about it.
fn approval_unconfirmed(effect: Option<&RuntimeCustodyCreatorEffectProgress>) -> anyhow::Error {
    let approval = match effect {
        Some(RuntimeCustodyCreatorEffectProgress::InConnector { connector }) => {
            RuntimeCustodyApprovalConflict::InConnector(connector.clone())
        }
        Some(RuntimeCustodyCreatorEffectProgress::WalletUnreachable) => {
            RuntimeCustodyApprovalConflict::WalletUnreachable
        }
        Some(RuntimeCustodyCreatorEffectProgress::AwaitingApproval) => {
            RuntimeCustodyApprovalConflict::StillOpen
        }
        _ => RuntimeCustodyApprovalConflict::NotOnRecord,
    };
    tracing::warn!(
        approval = ?approval,
        "runtime custody creator mint: an earlier attempt's Wallet approval could not be confirmed closed; nothing was set aside"
    );
    RuntimeCustodyAttemptConflict::approval(approval)
}

/// Whether Start over could set this source's current attempt aside, asked
/// without changing anything: the attempt sent nothing on chain and is not a
/// listing. A pending approval counts, since Start over declines it first.
pub(crate) async fn runtime_custody_attempt_may_start_over(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> bool {
    match crate::protected_content_runtime::runtime_custody_open_mint_for_source(
        &state.data_dir,
        principal_id,
        object_uri,
        source_storage,
    ) {
        // Nothing past the intent or the preparation: nothing went on chain.
        Ok(None) => true,
        Ok(Some(mint)) => {
            match classify_runtime_custody_creator_attempt(state, authority, &mint).await {
                Ok(Some(stage)) => stage.may_start_over(),
                // Escrowed and published with no terms: nothing went on chain.
                Ok(None) => mint.creator_state().is_none(),
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Set a source's current attempt aside -- only if it never sent a
/// transaction. The caller holds the source lock, and the creator attempt lock
/// for `mint` when there is one.
///
/// An attempt whose transaction was sent or mined, or whose mint is listed, is
/// kept (`Kept`): it stays as it is and is finished by Resume. Every other
/// attempt follows [`RuntimeCustodyUnfinishedMintStage::disposition`]: an
/// approval in the Wallet is declined, and the attempt archived only once the
/// Wallet confirms it closed with nothing signed (approved meanwhile: kept); an
/// approval that went to an external connector is never declined; anything
/// that cannot be confirmed is refused with `approval_open` or
/// `approval_in_connector`, and nothing moves.
pub(super) async fn archive_runtime_custody_creator_attempt_locked(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
    mint: Option<&elastos_protected_content_runtime::PersistedRuntimeMint>,
    reason: RuntimeCustodyAttemptArchiveReason,
) -> anyhow::Result<RuntimeCustodyAttemptArchiveOutcome> {
    let kept = |mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
                stage: Option<RuntimeCustodyUnfinishedMintStage>| {
        Ok(RuntimeCustodyAttemptArchiveOutcome::Kept {
            mint: Box::new(mint.clone()),
            stage,
        })
    };
    let mut approval_declined = false;
    let stage = match mint {
        None => None,
        Some(mint) => {
            if crate::protected_content_runtime::runtime_custody_mint_is_finished(
                &state.data_dir,
                mint,
            )? {
                return kept(mint, None);
            }
            let (stage, effect) =
                assess_runtime_custody_creator_attempt(state, authority, mint).await?;
            match stage.map(RuntimeCustodyUnfinishedMintStage::disposition) {
                // Escrowed and published with no terms yet: nothing on chain.
                None | Some(RuntimeCustodyAttemptDisposition::SetAside) => {}
                Some(RuntimeCustodyAttemptDisposition::Keep) => return kept(mint, stage),
                Some(RuntimeCustodyAttemptDisposition::Refuse) => {
                    return Err(approval_unconfirmed(effect.as_ref()));
                }
                Some(RuntimeCustodyAttemptDisposition::SetAsideOnceDeclined) => {
                    let Some((creator_state, approval_id)) =
                        mint.creator_state().and_then(|creator_state| {
                            creator_state
                                .effect()
                                .map(|effect| (creator_state, effect.approval_request_id()))
                        })
                    else {
                        return Err(approval_unconfirmed(None));
                    };
                    decline_attempt_approval(state, authority, approval_id).await;
                    // Re-read: only the Wallet's own answer says the approval
                    // is closed, and it may have been approved meanwhile.
                    match runtime_custody_creator_effect_progress(state, authority, creator_state)
                        .await
                    {
                        Some(RuntimeCustodyCreatorEffectProgress::ClosedWithoutTransaction) => {
                            approval_declined = true;
                        }
                        Some(RuntimeCustodyCreatorEffectProgress::Sent) => {
                            return kept(
                                mint,
                                Some(RuntimeCustodyUnfinishedMintStage::TransactionSent),
                            );
                        }
                        Some(RuntimeCustodyCreatorEffectProgress::Mined) => {
                            return kept(
                                mint,
                                Some(RuntimeCustodyUnfinishedMintStage::TransactionMined),
                            );
                        }
                        reread => return Err(approval_unconfirmed(reread.as_ref())),
                    }
                }
            }
            stage
        }
    };
    let archived = crate::protected_content_runtime::archive_runtime_custody_attempt(
        &state.data_dir,
        principal_id,
        object_uri,
        source_storage,
        crate::protected_content_runtime::RuntimeCustodyAttemptArchive {
            mint,
            stage,
            reason,
            approval_declined,
        },
    )?;
    Ok(match archived {
        Some(archived) => RuntimeCustodyAttemptArchiveOutcome::Archived(archived),
        None => RuntimeCustodyAttemptArchiveOutcome::Nothing,
    })
}

/// Ask the Wallet to decline the approval an attempt left out. Its answer is
/// not trusted here: the caller re-reads the approval's state.
async fn decline_attempt_approval(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    approval_request_id: &str,
) {
    if let Err(error) = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::RejectApproval {
            request_id: approval_request_id.to_string(),
            reason: "The attempt to protect this file was set aside".to_string(),
        },
    )
    .await
    {
        tracing::debug!(
            error = %error,
            "runtime custody creator mint: the Wallet did not decline an earlier attempt's approval"
        );
    }
}

/// Set a source's current attempt aside, taking the creator attempt lock for
/// its mint record when it has one. The caller holds the source lock.
pub(crate) async fn archive_runtime_custody_creator_attempt(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
    reason: RuntimeCustodyAttemptArchiveReason,
) -> anyhow::Result<RuntimeCustodyAttemptArchiveOutcome> {
    let found = crate::protected_content_runtime::runtime_custody_open_mint_for_source(
        &state.data_dir,
        principal_id,
        object_uri,
        source_storage,
    )?;
    let Some(found) = found else {
        return archive_runtime_custody_creator_attempt_locked(
            state,
            authority,
            principal_id,
            object_uri,
            source_storage,
            None,
            reason,
        )
        .await;
    };
    let attempt = crate::protected_content_runtime::runtime_custody_creator_attempt_lock(
        &state.data_dir,
        found.draft().mint_id(),
    );
    let _attempt = attempt.lock().await;
    // Read again under the lock: a publish may have moved it since the scan.
    let mint = crate::protected_content_runtime::runtime_custody_open_mint_for_source(
        &state.data_dir,
        principal_id,
        object_uri,
        source_storage,
    )?;
    archive_runtime_custody_creator_attempt_locked(
        state,
        authority,
        principal_id,
        object_uri,
        source_storage,
        mint.as_ref(),
        reason,
    )
    .await
}

/// Look at one object's unfinished mint for Creator: offer it back when it can
/// be recovered, archive it without asking when it cannot. The caller holds
/// the source lock.
pub(crate) async fn runtime_custody_unfinished_mint_via_gateway(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<RuntimeCustodyUnfinishedMintOutcome> {
    let Some(found) = crate::protected_content_runtime::runtime_custody_open_mint_for_source(
        &state.data_dir,
        principal_id,
        object_uri,
        source_storage,
    )?
    else {
        return Ok(RuntimeCustodyUnfinishedMintOutcome::Nothing);
    };
    let attempt = crate::protected_content_runtime::runtime_custody_creator_attempt_lock(
        &state.data_dir,
        found.draft().mint_id(),
    );
    let _attempt = attempt.lock().await;
    // Read again under the lock: a publish may have moved it since the scan.
    let Some(mint) = crate::protected_content_runtime::runtime_custody_open_mint_for_source(
        &state.data_dir,
        principal_id,
        object_uri,
        source_storage,
    )?
    else {
        return Ok(RuntimeCustodyUnfinishedMintOutcome::Nothing);
    };
    let Some(stage) = classify_runtime_custody_creator_attempt(state, authority, &mint).await?
    else {
        return Ok(RuntimeCustodyUnfinishedMintOutcome::Nothing);
    };
    if stage.recoverable() {
        return Ok(RuntimeCustodyUnfinishedMintOutcome::Unfinished(
            crate::protected_content_runtime::runtime_custody_unfinished_mint_json(&mint, stage),
        ));
    }
    match archive_runtime_custody_creator_attempt_locked(
        state,
        authority,
        principal_id,
        object_uri,
        source_storage,
        Some(&mint),
        RuntimeCustodyAttemptArchiveReason::Unrecoverable,
    )
    .await?
    {
        RuntimeCustodyAttemptArchiveOutcome::Archived(_) => {
            Ok(RuntimeCustodyUnfinishedMintOutcome::Archived)
        }
        _ => Ok(RuntimeCustodyUnfinishedMintOutcome::Nothing),
    }
}
