//! Public metadata sharing at the gateway (META-PUBLIC A4/A5): admin-only
//! adapters over `public_metadata_consent` (the consent record, the
//! withdrawal marker and the state lock) and the public IPFS store.
//!
//! - `GET /api/apps/creator/public-ipfs` is the Creator's read-only status:
//!   whether sharing is offered (`gate_open`), the consent, the withdrawal and
//!   the store. The Creator neither enables nor stops.
//! - Consent and "Stop sharing metadata" live in Inbox: one Runtime-built
//!   card per state ([`append_public_metadata_notifications`]) and the two
//!   Inbox actions, Agree ([`public_metadata_enable`], the admin's exact
//!   passkey step-up) and Stop ([`public_metadata_stop`], the durable
//!   withdrawal and its detached completion).
//!
//! An Inbox refusal answers `{code, detail}`, as custody refusals do.

use super::*;
use crate::custody_pool_setup::CustodyRefusal;
use crate::notifications::{
    PublicMetadataCard, PublicMetadataCardState, PublicMetadataStoreReading,
};
use crate::public_ipfs_store::{self, PublicIpfsStore, StoreLiveness};
use crate::public_metadata_consent::{
    self as consent, ConsentRecord, ConsentState, MarkerRepair, PublicMetadataError,
    ENABLE_OPERATION, STATE_LOCK_BUDGET, WITHDRAWAL_LOCK_BUDGET,
};

const STEP_UP_MAX_AGE_SECS: u64 = 180;
/// The `stop_pending` an unreadable marker shows until a Stop repairs it.
const MARKER_UNREADABLE: &str = "the withdrawal state is unreadable";

#[derive(Serialize)]
struct PublicIpfsStoreView {
    liveness: &'static str,
    ready: bool,
    peers: u32,
}

#[derive(Serialize)]
struct PublicIpfsView {
    admin: bool,
    /// Whether this Home offers sharing (A5). `false` opens the Creator as on
    /// develop.
    gate_open: bool,
    consent_enabled: bool,
    withdrawing: bool,
    stop_pending: Option<String>,
    store: PublicIpfsStoreView,
}

/// Whether the launch's passkey is a Home admin (A4 §1.3 authorization). It
/// reads no flag: Stop needs only this and the Inbox launch.
fn public_ipfs_admin(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<bool> {
    Ok(match context.proof_binding_id.as_deref() {
        None => false,
        Some(proof_binding_id) => {
            let principal =
                crate::auth::load_principal_for_proof_binding(data_dir, proof_binding_id)?;
            crate::auth::ensure_proof_binding_not_revoked(&principal)?;
            crate::auth::is_admin(&principal)
        }
    })
}

fn require_public_ipfs_admin(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<()> {
    if public_ipfs_admin(data_dir, context)? {
        Ok(())
    } else {
        Err(anyhow::anyhow!("admin passkey required"))
    }
}

fn refusal_of(error: &PublicMetadataError) -> anyhow::Error {
    CustodyRefusal::with_detail(error.code().as_str(), error.detail()).into()
}

fn liveness_name(liveness: StoreLiveness) -> &'static str {
    match liveness {
        StoreLiveness::Running => "running",
        StoreLiveness::Down => "down",
        StoreLiveness::Unknown => "unknown",
    }
}

pub(super) async fn creator_public_ipfs_read(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let refused = |error: anyhow::Error| system_error_response(error);
    let launch =
        match require_home_launch_token_binding(&state.data_dir, &headers, &[CREATOR_CAPSULE_ID]) {
            Ok(launch) => launch,
            Err(error) => return refused(error),
        };
    let admin = match public_ipfs_admin(&state.data_dir, &launch.context) {
        Ok(admin) => admin,
        Err(error) => return refused(error),
    };
    let consent_enabled = consent::consent_enabled(&state.data_dir).unwrap_or_else(|error| {
        tracing::warn!(error = %format!("{error:#}"), "public IPFS consent is unreadable");
        false
    });
    // An unreadable marker reads as a withdrawal, never as a free store.
    let (withdrawing, stop_pending) = match consent::read_withdrawal_marker(&state.data_dir) {
        Ok(marker) => (
            marker.is_some(),
            marker.and_then(|marker| marker.stop_pending),
        ),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "public IPFS withdrawal is unreadable");
            (true, Some(MARKER_UNREADABLE.to_string()))
        }
    };
    // This read also refreshes the slot's last-known reading (A45-F3).
    let store = match state.provider_registry.as_ref() {
        Some(registry) => {
            let status = PublicIpfsStore::status(registry).await;
            PublicIpfsStoreView {
                liveness: liveness_name(status.liveness),
                ready: status.ready,
                peers: status.peers,
            }
        }
        None => PublicIpfsStoreView {
            liveness: liveness_name(StoreLiveness::Down),
            ready: false,
            peers: 0,
        },
    };
    Json(PublicIpfsView {
        admin,
        gate_open: consent::public_metadata_offered(&state.data_dir),
        consent_enabled,
        withdrawing,
        stop_pending,
        store,
    })
    .into_response()
}

/// Inbox Agree: the admin's passkey over exactly the request the Runtime
/// builds, compared with the one the card showed before it is spent; then
/// the consent is recorded and the store started under the state lock.
/// Readiness is the card's and the Creator's to report.
pub(super) async fn public_metadata_enable(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    step_up_token: Option<&str>,
    step_up_request: Option<&serde_json::Value>,
) -> anyhow::Result<String> {
    let data_dir = &state.data_dir;
    require_public_ipfs_admin(data_dir, &launch.context)?;
    // Only a Home that offers sharing takes a new consent (A5).
    if let Some(reason) = consent::public_metadata_not_offered(data_dir) {
        return Err(CustodyRefusal::with_detail(consent::PUBLIC_METADATA_OFF, reason).into());
    }
    let Some(step_up_token) = step_up_token else {
        anyhow::bail!("fresh passkey verification is required to turn on metadata sharing");
    };
    let expected = consent::enable_step_up_request();
    // What the admin was shown must be what the Runtime records, checked
    // before the passkey approval is spent.
    if step_up_request != Some(&expected) {
        return Err(CustodyRefusal::new("changed").into());
    }
    let Some(registry) = state.provider_registry.clone() else {
        return Err(refusal_of(&PublicMetadataError::not_ready(
            "the provider registry is not running",
        )));
    };
    // Refused before the step-up, so a withdrawal never spends an approval.
    if consent::read_withdrawal_marker(data_dir)?.is_some() {
        return Err(CustodyRefusal::new("withdrawal_in_progress").into());
    }
    // The consent write this Enable follows; any later write means a
    // withdrawal (or another Enable) completed while it waited.
    let seen = consent::read_consent(data_dir)?.map(|record| record.generation);
    consume_passkey_step_up_token(
        data_dir,
        step_up_token,
        launch,
        STEP_UP_MAX_AGE_SECS,
        ENABLE_OPERATION,
        &expected,
    )?;
    let guard = consent::acquire_public_state_lock(data_dir, STATE_LOCK_BUDGET)
        .await
        .map_err(|error| refusal_of(&error))?;
    // A Stop that arrived while this waited wins, also one that completed.
    if consent::read_withdrawal_marker(data_dir)?.is_some() {
        return Err(CustodyRefusal::new("withdrawal_in_progress").into());
    }
    // The gate may have closed while this waited (A5): no Enabled write.
    if let Some(reason) = consent::public_metadata_not_offered(data_dir) {
        return Err(CustodyRefusal::with_detail(consent::PUBLIC_METADATA_OFF, reason).into());
    }
    match consent::read_consent(data_dir)? {
        record if record.as_ref().map(|record| &record.generation) == seen.as_ref() => {}
        // Another Enable won the race: the consent this one asks for stands.
        Some(record) if record.is_current_enabled() => {
            return Ok("Metadata sharing is on.".to_string());
        }
        _ => return Err(CustodyRefusal::new("withdrawal_in_progress").into()),
    }
    consent::write_consent(
        data_dir,
        ConsentState::Enabled,
        &launch.context.principal_id,
        &guard,
    )?;
    // The consent stands whatever the start does; the supervisor retries a
    // store that is down while consent is enabled.
    if let Err(error) = PublicIpfsStore::start(&registry, data_dir, &guard).await {
        tracing::warn!(
            code = error.code().as_str(),
            detail = error.detail(),
            "public IPFS store did not start"
        );
    }
    drop(guard);
    Ok("Metadata sharing is on. Your Home is starting its public IPFS node.".to_string())
}

const STOPPING: &str = "Stopping metadata sharing. Your Home keeps trying until it is off.";

/// Inbox Stop sharing (and Try again): needs the Inbox launch and an admin,
/// never either flag, and no step-up. It records the withdrawal now and
/// completes it in a detached task, which the caller's disconnect cannot
/// cancel. Idempotent: the first withdrawal stands.
pub(super) async fn public_metadata_stop(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
) -> anyhow::Result<String> {
    let data_dir = state.data_dir.clone();
    let principal = launch.context.principal_id.clone();
    require_public_ipfs_admin(&data_dir, &launch.context)?;
    let Some(registry) = state.provider_registry.clone() else {
        return Err(refusal_of(&PublicMetadataError::not_ready(
            "the provider registry is not running",
        )));
    };
    if consent::read_withdrawal_marker(&data_dir).is_ok() {
        // Durable before it returns: the acknowledgement barrier.
        consent::create_withdrawal_marker(&data_dir, &principal)?;
        tokio::spawn(async move {
            public_ipfs_store::log_withdrawal(
                public_ipfs_store::complete_withdrawal(&registry, &data_dir).await,
            );
        });
        return Ok(STOPPING.to_string());
    }
    // The marker is unreadable (A45-F5): the detached task that owns the
    // completion repairs it first, so the caller's cancellation, also while
    // waiting for the guard, stops neither. The answer waits only for the
    // repair to be durable.
    let (acknowledged, acknowledgement) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let guard =
            match consent::acquire_public_state_lock(&data_dir, WITHDRAWAL_LOCK_BUDGET).await {
                Ok(guard) => guard,
                Err(error) => {
                    let _ = acknowledged.send(Err(anyhow::anyhow!(
                        "the withdrawal could not be recorded: {}",
                        error.detail()
                    )));
                    return;
                }
            };
        let repaired = consent::repair_withdrawal_marker(&data_dir, &principal, &guard);
        // `complete_withdrawal` takes the guard itself: release it first.
        drop(guard);
        let complete = matches!(
            repaired,
            Ok(MarkerRepair::Kept(_) | MarkerRepair::Replaced(_))
        );
        let _ = acknowledged.send(repaired);
        if complete {
            public_ipfs_store::log_withdrawal(
                public_ipfs_store::complete_withdrawal(&registry, &data_dir).await,
            );
        }
    });
    match acknowledgement.await {
        Ok(Ok(MarkerRepair::AlreadyRemoved)) => Ok("Metadata sharing is off.".to_string()),
        Ok(Ok(_)) => Ok(STOPPING.to_string()),
        Ok(Err(error)) => Err(error.context("the withdrawal could not be recorded")),
        Err(_) => Err(anyhow::anyhow!("the withdrawal could not be recorded")),
    }
}

/// One snapshot of the public metadata state (A4 §1.3, marker first), which
/// both the card and its Home events signature use. It reads files and the
/// status slot's last definite reading, never the provider.
fn public_metadata_card_state(state: &GatewayState) -> PublicMetadataCardState {
    let data_dir = &state.data_dir;
    let store = state
        .provider_registry
        .as_ref()
        .and_then(PublicIpfsStore::last_known)
        .map(|status| PublicMetadataStoreReading {
            running: status.liveness == StoreLiveness::Running,
            ready: status.ready,
        });
    let with = |card, since| PublicMetadataCardState { card, store, since };
    match consent::read_withdrawal_marker(data_dir) {
        Ok(Some(marker)) => {
            return with(
                PublicMetadataCard::Stopping {
                    stop_pending: marker.stop_pending,
                },
                marker.created_at,
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "public IPFS withdrawal is unreadable");
            return with(
                PublicMetadataCard::Stopping {
                    stop_pending: Some(MARKER_UNREADABLE.to_string()),
                },
                0,
            );
        }
    }
    let record = match consent::read_consent(data_dir) {
        Ok(record) => record,
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "public IPFS consent is unreadable");
            return with(PublicMetadataCard::ConsentUnreadable, 0);
        }
    };
    let since = record.as_ref().map_or(0, |record| record.changed_at);
    let enabled = record
        .as_ref()
        .is_some_and(ConsentRecord::is_current_enabled);
    let card = match (enabled, consent::public_metadata_not_offered(data_dir)) {
        (true, None) => PublicMetadataCard::Sharing,
        (true, Some(reason)) => PublicMetadataCard::Paused {
            reason: reason.to_string(),
        },
        (false, None) => PublicMetadataCard::Offer {
            step_up_request: consent::enable_step_up_request(),
        },
        (false, Some(_)) => PublicMetadataCard::Hidden,
    };
    with(card, since)
}

/// Adds the public metadata card for an admin, as custody requests are
/// added: the files stay the only truth.
pub(super) fn append_public_metadata_notifications(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    notifications: &mut HomeNotificationsSummary,
) {
    if !public_ipfs_admin(&state.data_dir, context).unwrap_or(false) {
        return;
    }
    let mut projected = crate::notifications::NotificationSummary::default();
    crate::notifications::project_public_metadata_notifications(
        &mut projected,
        &public_metadata_card_state(state),
    );
    if projected.entries.is_empty() {
        return;
    }
    let projected = home_notifications_summary(projected);
    notifications.unread_count += projected.unread_count;
    notifications.attention_count += projected.attention_count;
    notifications.entries.extend(projected.entries);
}

/// The admin's Home events line for the card (A45-F3), from the same
/// snapshot as the card; `None` for anyone else.
pub(super) fn public_metadata_realtime_signature(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
) -> Option<String> {
    public_ipfs_admin(&state.data_dir, context)
        .ok()?
        .then(|| public_metadata_card_state(state).realtime_signature())
}
