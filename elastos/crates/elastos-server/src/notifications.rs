use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use elastos_common::localhost::rooted_localhost_fs_path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::room_service::RoomSummary;

const NOTIFICATIONS_SCHEMA: &str = "elastos.notifications/v1";
const NOTIFICATIONS_ROOT_URI: &str = "localhost://Local/Shared/System/Notifications";
const NOTIFICATIONS_FILE: &str = "notifications.json";
const NOTIFICATION_EVENTS_FILE: &str = "events.json";
const ROOM_ACCESS_REQUEST_KIND: &str = "room_access_request";
const ROOM_ACCESS_REQUEST_ID_PREFIX: &str = "room-access-request:";
const ROOM_ACCESS_REQUEST_TTL_SECS: u64 = 10 * 60;
const EXTERNAL_HTTP_REQUEST_KIND: &str = "external_http_request";
const CONTACT_REQUEST_KIND: &str = "contact_request";
const CONTACT_REQUEST_ID_PREFIX: &str = "contact-request:";
const CUSTODY_NODE_REQUEST_KIND: &str = crate::custody_surface::INBOX_KIND_NODE_REQUEST;
/// A request whose approval began and did not finish: only approving it
/// again settles it, so it stays past its expiry.
const CUSTODY_NODE_APPROVING_KIND: &str = crate::custody_surface::INBOX_KIND_NODE_APPROVING;
/// A request whose approval began and set nothing up yet: Approve or
/// Decline.
const CUSTODY_NODE_RESUMABLE_KIND: &str = crate::custody_surface::INBOX_KIND_NODE_RESUMABLE;
/// A request whose approval stopped part way and cannot finish.
const CUSTODY_NODE_INCOMPLETE_KIND: &str = crate::custody_surface::INBOX_KIND_NODE_INCOMPLETE;
/// A request whose approval began, on a Home that now serves another owner.
const CUSTODY_NODE_TAKEN_KIND: &str = crate::custody_surface::INBOX_KIND_NODE_TAKEN;
const CUSTODY_NODE_REQUEST_ID_PREFIX: &str = "custody-node-request:";
/// This Home's node is in its owner's signed pool; informational.
const CUSTODY_POOL_ACTIVE_KIND: &str = crate::custody_surface::INBOX_KIND_POOL_ACTIVE;
const CUSTODY_POOL_ACTIVE_ID_PREFIX: &str = "custody-pool-active:";
const DIRECT_MESSAGE_KIND: &str = "direct_message";
const DIRECT_MESSAGE_ID_PREFIX: &str = "direct-message:";
const COMMUNITY_MESSAGE_KIND: &str = "community_message";
const COMMUNITY_MESSAGE_ID_PREFIX: &str = "community-message:";
const NOTIFICATION_EVENTS_SCHEMA: &str = "elastos.notification-events/v1";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationSummary {
    #[serde(default)]
    pub unread_count: usize,
    #[serde(default)]
    pub attention_count: usize,
    #[serde(default)]
    pub entries: Vec<NotificationEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEntryView {
    pub id: String,
    pub source_app: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub action_ref: Option<NotificationActionRef>,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub severity: NotificationSeverity,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub acted: bool,
    #[serde(default)]
    pub dismissed: bool,
    /// Its action is approved with a passkey, over `step_up_request`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub passkey_approval: bool,
    /// The exact request the entry's passkey approves, or the request a
    /// decline-only card shows: the card reads its fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_request: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationActionRef {
    pub app: String,
    pub action_id: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationSeverity {
    #[default]
    Info,
    Attention,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NotificationStore {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    entries: Vec<NotificationEntryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationEntryRecord {
    id: String,
    source_app: String,
    kind: String,
    title: String,
    body: String,
    #[serde(default)]
    action_ref: Option<NotificationActionRef>,
    created_at: u64,
    #[serde(default)]
    expires_at: Option<u64>,
    severity: NotificationSeverity,
    #[serde(default)]
    read: bool,
    #[serde(default)]
    acted: bool,
    #[serde(default)]
    dismissed: bool,
    /// The local Profile this entry belongs to. Absent for Home-wide entries.
    /// Many accounts can share one Home, so an owned entry is shown to, and
    /// changed by, its owner only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_profile_did: Option<String>,
    /// The newest scoped Community projection this account has observed.
    /// Older readers accept this optional field and keep the existing flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_seq: Option<u64>,
    /// When the user last dismissed or rejected this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dismissed_at: Option<u64>,
}

impl NotificationEntryRecord {
    /// Whether `viewer` (the signed-in account's Profile DID, if any) may see
    /// or change this entry. A direct-message entry without an owner predates
    /// per-account entries; it is shown to nobody.
    fn visible_to(&self, viewer: Option<&str>) -> bool {
        match self.owner_profile_did.as_deref() {
            Some(owner) => viewer == Some(owner),
            None => !matches!(
                self.kind.as_str(),
                DIRECT_MESSAGE_KIND | COMMUNITY_MESSAGE_KIND
            ),
        }
    }

    fn view(&self) -> NotificationEntryView {
        NotificationEntryView {
            id: self.id.clone(),
            source_app: self.source_app.clone(),
            kind: self.kind.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            action_ref: self.action_ref.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            severity: self.severity,
            read: self.read,
            acted: self.acted,
            dismissed: self.dismissed,
            passkey_approval: false,
            step_up_request: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NotificationEventStore {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    entries: Vec<NotificationEventRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationEventRecord {
    id: String,
    notification_id: String,
    source_app: String,
    title: String,
    body: String,
    #[serde(default)]
    action_ref: Option<NotificationActionRef>,
    created_at: u64,
    disposition: NotificationEventDisposition,
    #[serde(default)]
    resolution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_profile_did: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum NotificationEventDisposition {
    Appeared,
    Resolved,
}

pub fn sync_room_notifications(data_dir: &Path, summary: &RoomSummary) -> anyhow::Result<()> {
    let _store = lock_store(data_dir)?;
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    let existing_ids = store
        .entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }

    let now = now_ts();
    let managed_ids = summary
        .pending_requests
        .iter()
        .map(|request| room_access_request_notification_id(&request.request_id))
        .collect::<Vec<_>>();

    store.entries.retain(|entry| {
        if entry.kind != ROOM_ACCESS_REQUEST_KIND {
            return entry.expires_at.is_none_or(|expires_at| expires_at > now);
        }
        managed_ids.iter().any(|id| id == &entry.id)
            && entry.expires_at.is_none_or(|expires_at| expires_at > now)
    });

    let room_title = if summary.room_control.title.trim().is_empty() {
        "Room".to_string()
    } else {
        summary.room_control.title.clone()
    };

    for request in &summary.pending_requests {
        let id = room_access_request_notification_id(&request.request_id);
        let expires_at = Some(request.requested_at + ROOM_ACCESS_REQUEST_TTL_SECS);
        if let Some(existing) = store.entries.iter_mut().find(|entry| entry.id == id) {
            existing.title = format!("{} wants to join Chat", request.display_name);
            existing.body = format!(
                "{} on {} wants to join {}.",
                request.display_name, request.device_label, room_title
            );
            existing.action_ref = Some(NotificationActionRef {
                app: summary.room_slug.clone(),
                action_id: format!("room-approve-request:{}", request.request_id),
            });
            existing.expires_at = expires_at;
            existing.severity = NotificationSeverity::Attention;
            existing.source_app = summary.room_slug.clone();
            continue;
        }

        store.entries.push(NotificationEntryRecord {
            id: id.clone(),
            source_app: summary.room_slug.clone(),
            kind: ROOM_ACCESS_REQUEST_KIND.to_string(),
            title: format!("{} wants to join Chat", request.display_name),
            body: format!(
                "{} on {} wants to join {}.",
                request.display_name, request.device_label, room_title
            ),
            action_ref: Some(NotificationActionRef {
                app: summary.room_slug.clone(),
                action_id: format!("room-approve-request:{}", request.request_id),
            }),
            created_at: request.requested_at,
            expires_at,
            severity: NotificationSeverity::Attention,
            read: false,
            acted: false,
            dismissed: false,
            owner_profile_did: None,
            message_seq: None,
            dismissed_at: None,
        });
        if !existing_ids.contains(&id) {
            record_event(
                data_dir,
                NotificationEventRecord {
                    id: format!("appeared:{id}"),
                    notification_id: id.clone(),
                    source_app: summary.room_slug.clone(),
                    title: format!("{} wants to join Chat", request.display_name),
                    body: format!(
                        "{} on {} wants to join {}.",
                        request.display_name, request.device_label, room_title
                    ),
                    action_ref: Some(NotificationActionRef {
                        app: summary.room_slug.clone(),
                        action_id: format!("room-approve-request:{}", request.request_id),
                    }),
                    created_at: request.requested_at,
                    disposition: NotificationEventDisposition::Appeared,
                    resolution: None,
                    owner_profile_did: None,
                },
            )?;
        }
    }

    // Command and verified incoming-event boundaries sync this projection, so
    // persist only a real change.
    let serialized = serde_json::to_vec_pretty(&store)?;
    let unchanged = match fs::read(&path) {
        Ok(existing) => existing == serialized,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => store.entries.is_empty(),
        Err(err) => return Err(err).with_context(|| format!("failed to read {}", path.display())),
    };
    if unchanged {
        return Ok(());
    }

    write_json_atomic(&path, &store)
}

/// A pending incoming contact request projected from the principal-scoped
/// contact store. This module never reads collaboration state itself.
#[derive(Debug, Clone)]
pub struct PendingContactRequestNotification {
    pub request_hash: String,
    pub display_name: String,
    pub handle: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

/// Projects pending incoming contact requests into one read response.
///
/// The contact store remains the only durable truth. Home and Inbox reads do
/// not copy these entries into the shared notification store, and a decided,
/// revoked, or expired request disappears from the next projection naturally.
pub fn project_contact_request_notifications(
    summary: &mut NotificationSummary,
    pending: &[PendingContactRequestNotification],
) {
    let now = now_ts();
    summary
        .entries
        .retain(|entry| entry.kind != CONTACT_REQUEST_KIND);
    let mut pending = pending
        .iter()
        .filter(|request| request.expires_at > now)
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.request_hash.cmp(&right.request_hash))
    });
    for request in pending {
        let id = contact_request_notification_id(&request.request_hash);
        let title =
            contact_request_notification_title(&request.display_name, request.handle.as_deref());
        let body = "Accepting adds them to People.".to_string();
        summary.entries.push(NotificationEntryView {
            id,
            source_app: "people".to_string(),
            kind: CONTACT_REQUEST_KIND.to_string(),
            title,
            body,
            action_ref: Some(NotificationActionRef {
                app: "inbox".to_string(),
                action_id: format!("contact-accept-request:{}", request.request_hash),
            }),
            created_at: request.created_at,
            expires_at: Some(request.expires_at),
            severity: NotificationSeverity::Attention,
            read: false,
            acted: false,
            dismissed: false,
            passkey_approval: false,
            step_up_request: None,
        });
    }
    summary.unread_count = summary.entries.iter().filter(|entry| !entry.read).count();
    summary.attention_count = summary
        .entries
        .iter()
        .filter(|entry| entry.severity == NotificationSeverity::Attention)
        .count();
}

/// A custody request waiting for this Home's admin, projected from the
/// node's own request records. This module never reads custody state itself.
#[derive(Debug, Clone)]
pub struct PendingCustodyRequestNotification {
    pub request_id: String,
    pub owner_name: String,
    pub term_days: u16,
    pub run_by: String,
    pub location: String,
    pub received_at: u64,
    pub expires_at: u64,
    pub stage: CustodyRequestStage,
    /// What the admin's passkey approves; the Inbox card shows its fields.
    pub step_up_request: serde_json::Value,
}

/// Where a custody request stands for its admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyRequestStage {
    /// Waiting for Approve or Decline, until it expires.
    Waiting,
    /// Approving began and did not finish: only approving again settles it,
    /// past its expiry too.
    Finishing,
    /// Approving began and set nothing up yet: approving again finishes it,
    /// and declining is still possible. It stays past its expiry too.
    Resumable,
    /// Approving began and cannot finish, because this Home's custody state is
    /// incomplete: only declining settles it, past its expiry too.
    Incomplete,
    /// Approving began, and this Home now serves another owner: only declining
    /// settles it, past its expiry too.
    ServesAnother,
}

impl CustodyRequestStage {
    /// Settled by Decline alone, with no passkey.
    fn declines_only(self) -> bool {
        matches!(self, Self::Incomplete | Self::ServesAnother)
    }
}

/// Projects custody requests into one read response, as contact requests
/// are: the request records stay the only truth, and a decided or expired
/// request is simply gone from the next read. The caller passes requests
/// only to an admin.
pub fn project_custody_request_notifications(
    summary: &mut NotificationSummary,
    pending: &[PendingCustodyRequestNotification],
) {
    let now = now_ts();
    summary.entries.retain(|entry| {
        ![
            CUSTODY_NODE_REQUEST_KIND,
            CUSTODY_NODE_APPROVING_KIND,
            CUSTODY_NODE_RESUMABLE_KIND,
            CUSTODY_NODE_INCOMPLETE_KIND,
            CUSTODY_NODE_TAKEN_KIND,
        ]
        .contains(&entry.kind.as_str())
    });
    let mut pending = pending
        .iter()
        .filter(|request| request.stage != CustodyRequestStage::Waiting || request.expires_at > now)
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
    for request in pending {
        summary.entries.push(NotificationEntryView {
            id: format!("{CUSTODY_NODE_REQUEST_ID_PREFIX}{}", request.request_id),
            source_app: "custody".to_string(),
            kind: match request.stage {
                CustodyRequestStage::Waiting => CUSTODY_NODE_REQUEST_KIND,
                CustodyRequestStage::Finishing => CUSTODY_NODE_APPROVING_KIND,
                CustodyRequestStage::Resumable => CUSTODY_NODE_RESUMABLE_KIND,
                CustodyRequestStage::Incomplete => CUSTODY_NODE_INCOMPLETE_KIND,
                CustodyRequestStage::ServesAnother => CUSTODY_NODE_TAKEN_KIND,
            }
            .to_string(),
            title: match request.stage {
                CustodyRequestStage::Waiting => {
                    format!("{} asks this Home to hold custody", request.owner_name)
                }
                CustodyRequestStage::Finishing | CustodyRequestStage::Resumable => {
                    format!("Finish approving {}'s custody request", request.owner_name)
                }
                CustodyRequestStage::Incomplete => {
                    format!(
                        "Approving {}'s custody request could not finish",
                        request.owner_name
                    )
                }
                CustodyRequestStage::ServesAnother => {
                    format!(
                        "{}'s custody request can no longer be approved",
                        request.owner_name
                    )
                }
            },
            body: match request.stage {
                CustodyRequestStage::Waiting => format!(
                    "{} asks this Home to be a node in their custody pool for {} days, \
                     run by {} in {}. {} Approving needs your passkey.",
                    request.owner_name,
                    request.term_days,
                    request.run_by,
                    request.location,
                    crate::custody_surface::NODE_REQUEST_DUTIES
                ),
                CustodyRequestStage::Resumable => format!(
                    "Approving {}'s request did not finish, and nothing was set up yet. \
                     {} Approve again to finish, or decline it.",
                    request.owner_name,
                    crate::custody_surface::NODE_REQUEST_DUTIES
                ),
                CustodyRequestStage::Finishing => format!(
                    "Approving {}'s request did not finish. {} Approve again to finish \
                     setting up this Home as their custody node.",
                    request.owner_name,
                    crate::custody_surface::NODE_REQUEST_DUTIES
                ),
                CustodyRequestStage::Incomplete => format!(
                    "This Home's custody state is incomplete and needs repair. \
                     Decline {}'s request to tell them.",
                    request.owner_name
                ),
                CustodyRequestStage::ServesAnother => {
                    "This Home serves another owner now. Decline this request.".to_string()
                }
            },
            action_ref: Some(NotificationActionRef {
                app: "inbox".to_string(),
                action_id: format!(
                    "{}:{}",
                    if request.stage.declines_only() {
                        crate::custody_surface::INBOX_ACTION_DECLINE_REQUEST
                    } else {
                        crate::custody_surface::INBOX_ACTION_APPROVE_REQUEST
                    },
                    request.request_id
                ),
            }),
            created_at: request.received_at,
            expires_at: Some(request.expires_at),
            severity: NotificationSeverity::Attention,
            read: false,
            acted: false,
            dismissed: false,
            passkey_approval: !request.stage.declines_only(),
            step_up_request: Some(request.step_up_request.clone()),
        });
    }
    summary.unread_count = summary.entries.iter().filter(|entry| !entry.read).count();
    summary.attention_count = summary
        .entries
        .iter()
        .filter(|entry| entry.severity == NotificationSeverity::Attention)
        .count();
}

/// The public metadata card's state (META-PUBLIC A4 §1.3), first match wins
/// in the order of its variants. Built once per read from one snapshot that
/// both the card and its Home events signature use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicMetadataCard {
    /// The withdrawal marker is present, or unreadable.
    Stopping { stop_pending: Option<String> },
    /// The consent record cannot be read.
    ConsentUnreadable,
    /// Enabled, and sharing is offered.
    Sharing,
    /// Enabled, and sharing is not offered now; `reason` names why.
    Paused { reason: String },
    /// No record or Disabled, and sharing is offered.
    Offer { step_up_request: serde_json::Value },
    /// No record or Disabled, and sharing is not offered: no card.
    Hidden,
}

/// The public store's last definite reading (never a live provider read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicMetadataStoreReading {
    pub running: bool,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMetadataCardState {
    pub card: PublicMetadataCard,
    pub store: Option<PublicMetadataStoreReading>,
    /// When the state it shows began (the marker's or the consent's time).
    pub since: u64,
}

const PUBLIC_METADATA_CARD_ID: &str = "public-metadata";
const PUBLIC_METADATA_KINDS: [&str; 5] = [
    crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_CONSENT,
    crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_SHARING,
    crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_PAUSED,
    crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_STOPPING,
    crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_UNREADABLE,
];

impl PublicMetadataCardState {
    fn kind(&self) -> Option<&'static str> {
        Some(match self.card {
            PublicMetadataCard::Stopping { .. } => {
                crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_STOPPING
            }
            PublicMetadataCard::ConsentUnreadable => {
                crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_UNREADABLE
            }
            PublicMetadataCard::Sharing => {
                crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_SHARING
            }
            PublicMetadataCard::Paused { .. } => {
                crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_PAUSED
            }
            PublicMetadataCard::Offer { .. } => {
                crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_CONSENT
            }
            PublicMetadataCard::Hidden => return None,
        })
    }

    /// The admin's Home events line (A45-F3):
    /// `public-metadata:<card kind>:<liveness>:<ready>:<stop_pending sha256
    /// prefix>`. No time and no peer count, so it moves only when the card
    /// would.
    pub fn realtime_signature(&self) -> String {
        let liveness = match self.store {
            Some(reading) if reading.running => "running",
            Some(_) => "down",
            None => "none",
        };
        let ready = self.store.is_some_and(|reading| reading.ready);
        let stop_pending = match &self.card {
            PublicMetadataCard::Stopping {
                stop_pending: Some(reason),
            } => hex::encode(Sha256::digest(reason.as_bytes()))[..16].to_string(),
            _ => String::new(),
        };
        format!(
            "public-metadata:{}:{liveness}:{ready}:{stop_pending}",
            self.kind().unwrap_or("none")
        )
    }
}

fn public_metadata_entry(state: &PublicMetadataCardState) -> Option<NotificationEntryView> {
    let kind = state.kind()?;
    let stop = || NotificationActionRef {
        app: "inbox".to_string(),
        action_id: crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_STOP.to_string(),
    };
    let (title, body, action_ref, severity, read, step_up_request) = match &state.card {
        PublicMetadataCard::Stopping { stop_pending } => (
            "Stopping metadata sharing".to_string(),
            match stop_pending {
                None => "Stopping…".to_string(),
                Some(reason) => format!("Still stopping: {reason}. Your Home keeps trying."),
            },
            stop(),
            if stop_pending.is_some() {
                NotificationSeverity::Attention
            } else {
                NotificationSeverity::Info
            },
            stop_pending.is_none(),
            None,
        ),
        PublicMetadataCard::ConsentUnreadable => (
            "Metadata sharing".to_string(),
            "Metadata sharing state can't be read. Stop sharing to reset it.".to_string(),
            stop(),
            NotificationSeverity::Attention,
            false,
            None,
        ),
        PublicMetadataCard::Sharing => (
            "Metadata sharing is on".to_string(),
            format!(
                "Your Home shares minted assets' metadata on public IPFS.{}",
                match state.store {
                    Some(reading) if reading.running && reading.ready => {
                        " Its public IPFS node is ready."
                    }
                    Some(reading) if reading.running => " Its public IPFS node is starting.",
                    Some(_) => " Its public IPFS node is not running.",
                    None => "",
                }
            ),
            stop(),
            NotificationSeverity::Info,
            true,
            None,
        ),
        PublicMetadataCard::Paused { reason } => (
            "Metadata sharing is paused".to_string(),
            format!("Metadata sharing is paused on this Home ({reason}). Your consent is kept."),
            stop(),
            NotificationSeverity::Info,
            true,
            None,
        ),
        // A quiet standing card: info AND an explicit `read: true`, since an
        // info entry alone still counts unread. It keeps no read or dismiss
        // state of its own.
        PublicMetadataCard::Offer { step_up_request } => (
            "Share minted assets' metadata on public IPFS?".to_string(),
            crate::public_metadata_consent::CONSENT_WORDING.to_string(),
            NotificationActionRef {
                app: "inbox".to_string(),
                action_id: crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_ENABLE.to_string(),
            },
            NotificationSeverity::Info,
            true,
            Some(step_up_request.clone()),
        ),
        PublicMetadataCard::Hidden => return None,
    };
    Some(NotificationEntryView {
        id: PUBLIC_METADATA_CARD_ID.to_string(),
        source_app: "creator".to_string(),
        kind: kind.to_string(),
        title,
        body,
        action_ref: Some(action_ref),
        created_at: state.since,
        expires_at: None,
        severity,
        read,
        acted: false,
        dismissed: false,
        passkey_approval: step_up_request.is_some(),
        step_up_request,
    })
}

/// Projects the public metadata card into one read response. Pure: the
/// caller builds the snapshot (admin only), and this never reads state.
pub fn project_public_metadata_notifications(
    summary: &mut NotificationSummary,
    state: &PublicMetadataCardState,
) {
    summary
        .entries
        .retain(|entry| !PUBLIC_METADATA_KINDS.contains(&entry.kind.as_str()));
    if let Some(entry) = public_metadata_entry(state) {
        summary.entries.push(entry);
    }
    summary.unread_count = summary.entries.iter().filter(|entry| !entry.read).count();
    summary.attention_count = summary
        .entries
        .iter()
        .filter(|entry| entry.severity == NotificationSeverity::Attention)
        .count();
}

/// Records, once per pool, that this Home's node is in its owner's signed
/// pool. The entry belongs to the admin Profile the owner told, and an older
/// pool's entry gives way. The same pool again, even dismissed, changes
/// nothing.
pub(crate) fn upsert_custody_pool_active_notification(
    data_dir: &Path,
    owner_profile_did: &str,
    fingerprint_full: &str,
    // Plan B T2.2: the pools this node is in now; their entries stay.
    kept_fingerprints: &[String],
    title: &str,
    body: &str,
    created_at: u64,
) -> anyhow::Result<()> {
    let _store = lock_store(data_dir)?;
    let id = custody_pool_active_id(owner_profile_did, fingerprint_full);
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    if store.entries.iter().any(|entry| entry.id == id) {
        return Ok(());
    }
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }
    let kept: Vec<String> = kept_fingerprints
        .iter()
        .map(|print| custody_pool_active_id(owner_profile_did, print))
        .collect();
    store.entries.retain(|entry| {
        entry.kind != CUSTODY_POOL_ACTIVE_KIND
            || entry.owner_profile_did.as_deref() != Some(owner_profile_did)
            || kept.contains(&entry.id)
    });
    store.entries.push(NotificationEntryRecord {
        id: id.clone(),
        source_app: "custody".to_string(),
        kind: CUSTODY_POOL_ACTIVE_KIND.to_string(),
        title: title.to_string(),
        body: body.to_string(),
        action_ref: None,
        created_at,
        expires_at: None,
        severity: NotificationSeverity::Info,
        read: false,
        acted: false,
        dismissed: false,
        owner_profile_did: Some(owner_profile_did.to_string()),
        message_seq: None,
        dismissed_at: None,
    });
    record_event(
        data_dir,
        NotificationEventRecord {
            id: format!("appeared:{id}"),
            notification_id: id,
            source_app: "custody".to_string(),
            title: title.to_string(),
            body: body.to_string(),
            action_ref: None,
            created_at,
            disposition: NotificationEventDisposition::Appeared,
            resolution: None,
            owner_profile_did: Some(owner_profile_did.to_string()),
        },
    )?;
    write_json_atomic(&path, &store)
}

/// Adds the admin's entry for the pool this node is in now: one for an
/// older pool, or from an owner it no longer serves, is not shown. The
/// caller passes an admin's Profile only.
pub(crate) fn project_custody_pool_active_notifications(
    summary: &mut NotificationSummary,
    data_dir: &Path,
    owner_profile_did: &str,
    // Plan B T2.2: one per pool this node is in now.
    current_fingerprints: &[String],
) -> anyhow::Result<()> {
    let current: Vec<String> = current_fingerprints
        .iter()
        .map(|print| custody_pool_active_id(owner_profile_did, print))
        .collect();
    summary
        .entries
        .retain(|entry| entry.kind != CUSTODY_POOL_ACTIVE_KIND);
    summary.entries.extend(
        live_entries(data_dir, Some(owner_profile_did))?
            .into_iter()
            .filter(|entry| entry.kind == CUSTODY_POOL_ACTIVE_KIND && current.contains(&entry.id)),
    );
    *summary = summary_from(std::mem::take(&mut summary.entries));
    Ok(())
}

/// One entry per pool and per admin Profile told, so each admin keeps and
/// dismisses its own.
fn custody_pool_active_id(owner_profile_did: &str, fingerprint_full: &str) -> String {
    format!("{CUSTODY_POOL_ACTIVE_ID_PREFIX}{owner_profile_did}:{fingerprint_full}")
}

fn contact_request_notification_title(display_name: &str, handle: Option<&str>) -> String {
    match handle {
        Some(handle) => format!("{display_name} (@{handle}) wants to add you"),
        None => format!("{display_name} wants to add you"),
    }
}

fn contact_request_notification_id(request_hash: &str) -> String {
    format!("{CONTACT_REQUEST_ID_PREFIX}{request_hash}")
}

/// Records that a direct message arrived, one live entry per conversation.
/// A repeat message resurfaces the entry; reading the conversation in Chat
/// resolves it through [`mark_acted_for_action`] with the same action id.
/// The sender name is the signed Profile name the receive path verified —
/// this module never invents one.
pub fn upsert_direct_message_notification(
    data_dir: &Path,
    owner_profile_did: &str,
    conversation_id: &str,
    sender_display_name: &str,
    now: u64,
) -> anyhow::Result<()> {
    let _store = lock_store(data_dir)?;
    let id = direct_message_notification_id(conversation_id);
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }
    // Entries from before per-account ownership are shown to nobody; drop them.
    store
        .entries
        .retain(|entry| entry.kind != DIRECT_MESSAGE_KIND || entry.owner_profile_did.is_some());
    let owner = Some(owner_profile_did.to_string());
    let title = format!("New message from {sender_display_name}");
    let body = format!("{sender_display_name} sent you a message in Chat.");
    let action_ref = Some(NotificationActionRef {
        app: "chat-room".to_string(),
        action_id: direct_message_notification_action_id(conversation_id),
    });

    if let Some(existing) = store
        .entries
        .iter_mut()
        .find(|entry| entry.id == id && entry.owner_profile_did == owner)
    {
        existing.source_app = "chat-room".to_string();
        existing.kind = DIRECT_MESSAGE_KIND.to_string();
        existing.title = title;
        existing.body = body;
        existing.action_ref = action_ref;
        existing.created_at = now;
        existing.severity = NotificationSeverity::Attention;
        existing.read = false;
        existing.acted = false;
        existing.dismissed = false;
        return write_json_atomic(&path, &store);
    }

    store.entries.push(NotificationEntryRecord {
        id: id.clone(),
        source_app: "chat-room".to_string(),
        kind: DIRECT_MESSAGE_KIND.to_string(),
        title: title.clone(),
        body: body.clone(),
        action_ref: action_ref.clone(),
        created_at: now,
        expires_at: None,
        severity: NotificationSeverity::Attention,
        read: false,
        acted: false,
        dismissed: false,
        owner_profile_did: owner.clone(),
        message_seq: None,
        dismissed_at: None,
    });
    record_event(
        data_dir,
        NotificationEventRecord {
            id: format!("appeared:{id}"),
            notification_id: id,
            source_app: "chat-room".to_string(),
            title,
            body,
            action_ref,
            created_at: now,
            disposition: NotificationEventDisposition::Appeared,
            resolution: None,
            owner_profile_did: owner,
        },
    )?;
    write_json_atomic(&path, &store)
}

/// The action id that resolves a conversation's message notification. Chat's
/// conversation read marks it acted; the entry's own action ref carries the
/// same id so an Inbox resolution and a Chat read converge on one record.
pub fn direct_message_notification_action_id(conversation_id: &str) -> String {
    format!("chat-open-direct:{conversation_id}")
}

/// This account's direct conversations whose newest message notification
/// has not been acted on yet, which is when the person opens the conversation.
pub fn unread_direct_message_conversations(
    data_dir: &Path,
    owner_profile_did: &str,
) -> anyhow::Result<std::collections::HashSet<String>> {
    let path = notifications_path(data_dir)?;
    let store = read_json_or_default::<NotificationStore>(&path)?;
    Ok(store
        .entries
        .iter()
        .filter(|entry| entry.kind == DIRECT_MESSAGE_KIND && !entry.acted)
        .filter(|entry| entry.visible_to(Some(owner_profile_did)))
        .filter_map(|entry| entry.id.strip_prefix(DIRECT_MESSAGE_ID_PREFIX))
        .map(str::to_string)
        .collect())
}

/// True for the per-conversation direct message notification entries.
pub fn is_direct_message_notification_id(id: &str) -> bool {
    id.starts_with(DIRECT_MESSAGE_ID_PREFIX)
}

fn direct_message_notification_id(conversation_id: &str) -> String {
    format!("{DIRECT_MESSAGE_ID_PREFIX}{conversation_id}")
}

fn community_message_notification_id(scope: (&str, &str)) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"elastos.notifications.community.v1".as_slice(),
        scope.0.as_bytes(),
        scope.1.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!(
        "{COMMUNITY_MESSAGE_ID_PREFIX}{}",
        hex::encode(digest.finalize())
    )
}

/// Sync a verified scoped projection and optionally acknowledge only returned
/// remote rows. One account's read cannot acknowledge another account or a
/// message projected after its read snapshot.
pub(crate) fn sync_community_message_notification(
    data_dir: &Path,
    owner_profile_did: &str,
    scope: (&str, &str),
    latest_remote_seq: u64,
    read_through: Option<u64>,
    now: u64,
) -> anyhow::Result<bool> {
    let _lock = lock_store(data_dir)?;
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    let id = community_message_notification_id(scope);
    let owner = Some(owner_profile_did.to_string());
    let index = store
        .entries
        .iter()
        .position(|entry| entry.id == id && entry.owner_profile_did == owner);
    let index = match index {
        Some(index) => index,
        None if latest_remote_seq == 0 => return Ok(false),
        None => {
            store.entries.push(NotificationEntryRecord {
                id,
                source_app: "chat-room".to_string(),
                kind: COMMUNITY_MESSAGE_KIND.to_string(),
                title: "New Community messages".to_string(),
                body: "New messages are available in Community.".to_string(),
                action_ref: Some(NotificationActionRef {
                    app: "chat-room".to_string(),
                    action_id: "chat-open-community".to_string(),
                }),
                created_at: now,
                expires_at: None,
                severity: NotificationSeverity::Attention,
                read: false,
                acted: false,
                dismissed: false,
                owner_profile_did: owner,
                message_seq: None,
                dismissed_at: None,
            });
            store.entries.len() - 1
        }
    };
    let entry = &mut store.entries[index];
    let mut changed = false;
    if latest_remote_seq > entry.message_seq.unwrap_or(0) {
        entry.message_seq = Some(latest_remote_seq);
        entry.created_at = now;
        entry.read = false;
        entry.acted = false;
        entry.dismissed = false;
        changed = true;
    }
    if read_through
        .is_some_and(|through| entry.message_seq.is_some_and(|seq| seq <= through) && !entry.acted)
    {
        entry.read = true;
        entry.acted = true;
        changed = true;
    }
    let unread = !entry.acted;
    if changed {
        if store.schema.trim().is_empty() {
            store.schema = NOTIFICATIONS_SCHEMA.to_string();
        }
        write_json_atomic(&path, &store)?;
    }
    Ok(unread)
}

/// The Home-wide entries. Entries owned by one account, such as direct
/// messages, are added per reader by [`project_direct_message_notifications`].
pub fn load_summary(data_dir: &Path) -> anyhow::Result<NotificationSummary> {
    let entries = live_entries(data_dir, None)?;
    Ok(summary_from(entries))
}

/// Adds the signed-in account's own direct-message entries to one Home or
/// Inbox read response.
pub fn project_direct_message_notifications(
    summary: &mut NotificationSummary,
    data_dir: &Path,
    owner_profile_did: &str,
) -> anyhow::Result<()> {
    project_owned_message_notifications(summary, data_dir, owner_profile_did, DIRECT_MESSAGE_KIND)
}

pub(crate) fn project_community_message_notifications(
    summary: &mut NotificationSummary,
    data_dir: &Path,
    owner_profile_did: &str,
) -> anyhow::Result<()> {
    project_owned_message_notifications(
        summary,
        data_dir,
        owner_profile_did,
        COMMUNITY_MESSAGE_KIND,
    )
}

fn project_owned_message_notifications(
    summary: &mut NotificationSummary,
    data_dir: &Path,
    owner_profile_did: &str,
    kind: &str,
) -> anyhow::Result<()> {
    summary.entries.retain(|entry| entry.kind != kind);
    summary.entries.extend(
        live_entries(data_dir, Some(owner_profile_did))?
            .into_iter()
            .filter(|entry| entry.kind == kind),
    );
    *summary = summary_from(std::mem::take(&mut summary.entries));
    Ok(())
}

/// Unexpired, unresolved entries `viewer` may see.
fn live_entries(
    data_dir: &Path,
    viewer: Option<&str>,
) -> anyhow::Result<Vec<NotificationEntryView>> {
    let path = notifications_path(data_dir)?;
    let store = read_json_or_default::<NotificationStore>(&path)?;
    let now = now_ts();
    Ok(store
        .entries
        .iter()
        .filter(|entry| entry.expires_at.is_none_or(|expires_at| expires_at > now))
        .filter(|entry| !entry.dismissed && !entry.acted)
        .filter(|entry| entry.visible_to(viewer))
        .map(NotificationEntryRecord::view)
        .collect())
}

fn summary_from(entries: Vec<NotificationEntryView>) -> NotificationSummary {
    NotificationSummary {
        unread_count: entries.iter().filter(|entry| !entry.read).count(),
        attention_count: entries
            .iter()
            .filter(|entry| entry.severity == NotificationSeverity::Attention)
            .count(),
        entries,
    }
}

pub fn upsert_external_http_request(
    data_dir: &Path,
    request_id: &str,
    source_app: &str,
    title: &str,
    body: &str,
    approve_action_id: &str,
    created_at: u64,
) -> anyhow::Result<()> {
    let _store = lock_store(data_dir)?;
    let id = external_http_request_notification_id(request_id);
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    let already_exists = store.entries.iter().any(|entry| entry.id == id);
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }

    if let Some(existing) = store.entries.iter_mut().find(|entry| entry.id == id) {
        existing.source_app = source_app.to_string();
        existing.kind = EXTERNAL_HTTP_REQUEST_KIND.to_string();
        existing.title = title.to_string();
        existing.body = body.to_string();
        existing.action_ref = Some(NotificationActionRef {
            app: source_app.to_string(),
            action_id: approve_action_id.to_string(),
        });
        existing.severity = NotificationSeverity::Attention;
        existing.dismissed = false;
        existing.dismissed_at = None;
        existing.acted = false;
        write_json_atomic(&path, &store)?;
        return Ok(());
    }

    store.entries.push(NotificationEntryRecord {
        id: id.clone(),
        source_app: source_app.to_string(),
        kind: EXTERNAL_HTTP_REQUEST_KIND.to_string(),
        title: title.to_string(),
        body: body.to_string(),
        action_ref: Some(NotificationActionRef {
            app: source_app.to_string(),
            action_id: approve_action_id.to_string(),
        }),
        created_at,
        expires_at: None,
        severity: NotificationSeverity::Attention,
        read: false,
        acted: false,
        dismissed: false,
        owner_profile_did: None,
        message_seq: None,
        dismissed_at: None,
    });
    if !already_exists {
        record_event(
            data_dir,
            NotificationEventRecord {
                id: format!("appeared:{id}"),
                notification_id: id,
                source_app: source_app.to_string(),
                title: title.to_string(),
                body: body.to_string(),
                action_ref: Some(NotificationActionRef {
                    app: source_app.to_string(),
                    action_id: approve_action_id.to_string(),
                }),
                created_at,
                disposition: NotificationEventDisposition::Appeared,
                resolution: None,
                owner_profile_did: None,
            },
        )?;
    }
    write_json_atomic(&path, &store)
}

/// Whether the user dismissed or rejected this external HTTP request less than
/// `quiet_secs` before `now`, so asking again would only nag.
pub fn external_http_request_recently_dismissed(
    data_dir: &Path,
    request_id: &str,
    now: u64,
    quiet_secs: u64,
) -> anyhow::Result<bool> {
    let id = external_http_request_notification_id(request_id);
    let store = read_json_or_default::<NotificationStore>(&notifications_path(data_dir)?)?;
    Ok(store.entries.iter().any(|entry| {
        entry.id == id
            && entry.dismissed
            && entry
                .dismissed_at
                .is_some_and(|at| now < at.saturating_add(quiet_secs))
    }))
}

pub fn dismiss_external_http_request(data_dir: &Path, request_id: &str) -> anyhow::Result<bool> {
    dismiss(
        data_dir,
        None,
        &external_http_request_notification_id(request_id),
    )
}

fn external_http_request_notification_id(request_id: &str) -> String {
    format!("external-http-request:{request_id}")
}

/// Resolves the entries `viewer` may see whose action is `action_id`.
pub fn mark_acted_for_action(
    data_dir: &Path,
    viewer: Option<&str>,
    action_id: &str,
) -> anyhow::Result<usize> {
    let _store = lock_store(data_dir)?;
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }

    let mut updated = 0usize;
    for entry in &mut store.entries {
        if entry
            .action_ref
            .as_ref()
            .map(|action_ref| action_ref.action_id.as_str())
            == Some(action_id)
            && !entry.acted
            && entry.visible_to(viewer)
        {
            record_event(
                data_dir,
                NotificationEventRecord {
                    id: format!("resolved:{}", entry.id),
                    notification_id: entry.id.clone(),
                    source_app: entry.source_app.clone(),
                    title: entry.title.clone(),
                    body: entry.body.clone(),
                    action_ref: entry.action_ref.clone(),
                    created_at: now_ts(),
                    disposition: NotificationEventDisposition::Resolved,
                    resolution: Some("acted".to_string()),
                    owner_profile_did: entry.owner_profile_did.clone(),
                },
            )?;
            entry.acted = true;
            entry.read = true;
            updated += 1;
        }
    }

    if updated > 0 {
        write_json_atomic(&path, &store)?;
    }
    Ok(updated)
}

pub fn mark_read(data_dir: &Path, viewer: Option<&str>, id: &str) -> anyhow::Result<bool> {
    let _store = lock_store(data_dir)?;
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }

    let mut updated = false;
    for entry in &mut store.entries {
        if entry.id == id && !entry.read && entry.visible_to(viewer) {
            entry.read = true;
            updated = true;
        }
    }

    if updated {
        write_json_atomic(&path, &store)?;
    }
    Ok(updated)
}

pub fn dismiss(data_dir: &Path, viewer: Option<&str>, id: &str) -> anyhow::Result<bool> {
    let _store = lock_store(data_dir)?;
    let path = notifications_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationStore>(&path)?;
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATIONS_SCHEMA.to_string();
    }

    let mut updated = false;
    for entry in &mut store.entries {
        if entry.id == id && !entry.dismissed && entry.visible_to(viewer) {
            record_event(
                data_dir,
                NotificationEventRecord {
                    id: format!("resolved:{}", entry.id),
                    notification_id: entry.id.clone(),
                    source_app: entry.source_app.clone(),
                    title: entry.title.clone(),
                    body: entry.body.clone(),
                    action_ref: entry.action_ref.clone(),
                    created_at: now_ts(),
                    disposition: NotificationEventDisposition::Resolved,
                    resolution: Some("dismissed".to_string()),
                    owner_profile_did: entry.owner_profile_did.clone(),
                },
            )?;
            entry.dismissed = true;
            entry.dismissed_at = Some(now_ts());
            entry.read = true;
            updated = true;
        }
    }

    if updated {
        write_json_atomic(&path, &store)?;
    }
    Ok(updated)
}

fn notifications_path(data_dir: &Path) -> anyhow::Result<PathBuf> {
    let root_dir = notifications_root_dir(data_dir)?;
    Ok(root_dir.join(NOTIFICATIONS_FILE))
}

fn notification_events_path(data_dir: &Path) -> anyhow::Result<PathBuf> {
    let root_dir = notifications_root_dir(data_dir)?;
    Ok(root_dir.join(NOTIFICATION_EVENTS_FILE))
}

fn notifications_root_dir(data_dir: &Path) -> anyhow::Result<PathBuf> {
    rooted_localhost_fs_path(data_dir, NOTIFICATIONS_ROOT_URI)
        .context("failed to resolve notifications root")
}

/// Serializes every read-modify-write of the shared store, so one account's
/// write never replaces another's fresh entry with an older snapshot. Held by
/// each public writer; internal helpers such as [`record_event`] run under it.
fn lock_store(data_dir: &Path) -> anyhow::Result<crate::host_lock::FileLock> {
    let root = notifications_root_dir(data_dir)?;
    fs::create_dir_all(&root)?;
    crate::collaboration_core::lock_owner_only_file(&root.join(".notifications.lock"))
        .context("failed to lock the notification store")
}

/// Runs under the caller's [`lock_store`].
fn record_event(data_dir: &Path, event: NotificationEventRecord) -> anyhow::Result<()> {
    let path = notification_events_path(data_dir)?;
    let mut store = read_json_or_default::<NotificationEventStore>(&path)?;
    if store.schema.trim().is_empty() {
        store.schema = NOTIFICATION_EVENTS_SCHEMA.to_string();
    }
    if store.entries.iter().any(|entry| entry.id == event.id) {
        return Ok(());
    }
    store.entries.push(event);
    if store.entries.len() > 4096 {
        store.entries = store.entries.split_off(store.entries.len() - 4096);
    }
    write_json_atomic(&path, &store)
}

fn room_access_request_notification_id(request_id: &str) -> String {
    format!("{ROOM_ACCESS_REQUEST_ID_PREFIX}{request_id}")
}

fn read_json_or_default<T>(path: &Path) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("invalid {}", path.display()))
}

fn write_json_atomic<T>(path: &Path, value: &T) -> anyhow::Result<()>
where
    T: Serialize,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path missing parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("notifications")
    ));
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::room_service::{PendingRequestView, RoomControlSummary, RoomSummary};

    fn sample_summary() -> RoomSummary {
        RoomSummary {
            room_slug: "chat-room".to_string(),
            room_control: RoomControlSummary {
                title: "Exec Room".to_string(),
                ..Default::default()
            },
            pending_requests: vec![PendingRequestView {
                request_id: "req-1".to_string(),
                display_name: "Alice".to_string(),
                device_label: "Phone".to_string(),
                requested_at: now_ts(),
                capabilities: crate::room_service::room_access_capabilities(),
            }],
            ..Default::default()
        }
    }

    const ALICE: &str = "did:key:z6MkAlice";
    const BOB: &str = "did:key:z6MkBob";

    fn owned_summary(data: &Path, owner: &str) -> NotificationSummary {
        let mut summary = load_summary(data).unwrap();
        project_direct_message_notifications(&mut summary, data, owner).unwrap();
        summary
    }

    #[test]
    fn community_unread_is_account_scoped_monotonic_and_snapshot_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let scope = ("network-one", "community-one");
        let foreign_scope = ("network-two", "community-two");
        let sync = |owner, scope, latest, read| {
            sync_community_message_notification(tmp.path(), owner, scope, latest, read, now_ts())
                .unwrap()
        };
        assert!(!sync(ALICE, scope, 0, None));
        assert!(sync(ALICE, scope, 7, None));
        assert!(sync(BOB, scope, 7, None));
        assert!(sync(ALICE, foreign_scope, 31, None));
        assert!(load_summary(tmp.path()).unwrap().entries.is_empty());
        let mut alice = load_summary(tmp.path()).unwrap();
        project_community_message_notifications(&mut alice, tmp.path(), ALICE).unwrap();
        assert_eq!(alice.unread_count, 2);
        assert!(alice.entries.iter().all(|entry| {
            entry.title == "New Community messages"
                && entry.body == "New messages are available in Community."
                && entry.action_ref.as_ref().is_some_and(|action| {
                    action.app == "chat-room" && action.action_id == "chat-open-community"
                })
        }));
        // Bob's read and the other network's read leave Alice's entry alone.
        assert!(!sync(BOB, scope, 7, Some(7)));
        assert!(!sync(ALICE, foreign_scope, 31, Some(31)));
        assert!(sync(ALICE, scope, 7, None));
        assert!(!mark_read(
            tmp.path(),
            Some(BOB),
            &community_message_notification_id(scope)
        )
        .unwrap());
        assert!(!sync(ALICE, scope, 7, Some(7)));
        let read_bytes = fs::read(notifications_path(tmp.path()).unwrap()).unwrap();
        // A repeated or older metadata projection cannot resurface read rows.
        assert!(!sync(ALICE, scope, 7, None));
        assert!(!sync(ALICE, scope, 6, None));
        assert_eq!(
            fs::read(notifications_path(tmp.path()).unwrap()).unwrap(),
            read_bytes
        );
        assert!(sync(ALICE, scope, 8, None));
        // A stale response cannot acknowledge the later row, including when
        // its metadata lookup ran before the newer notification was saved.
        assert!(sync(ALICE, scope, 7, Some(7)));
        assert!(sync(ALICE, scope, 8, Some(7)));
        assert!(!sync(ALICE, scope, 8, Some(8)));
        assert!(!sync(BOB, scope, 7, None));
    }

    #[test]
    fn community_watermark_is_optional_private_and_preserves_old_notification_records() {
        let tmp = tempfile::tempdir().unwrap();
        upsert_direct_message_notification(tmp.path(), ALICE, "direct:old", "Pat", now_ts())
            .unwrap();
        let path = notifications_path(tmp.path()).unwrap();
        let before: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(before["entries"][0].get("message_seq").is_none());
        sync_community_message_notification(
            tmp.path(),
            ALICE,
            ("network", "community"),
            4,
            Some(4),
            now_ts(),
        )
        .unwrap();
        let after: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(after["entries"][0], before["entries"][0]);
        assert_eq!(after["entries"][1]["message_seq"], 4);
        // The old record shape admits unknown optional fields and retains
        // the same action and flags during Undo. Watermarks stay private.
        #[derive(Deserialize)]
        struct OldRecord {
            id: String,
            read: bool,
            acted: bool,
        }
        let old: OldRecord = serde_json::from_value(after["entries"][1].clone()).unwrap();
        assert_eq!(
            old.id,
            community_message_notification_id(("network", "community"))
        );
        assert!(old.read && old.acted);
        let record: NotificationEntryRecord =
            serde_json::from_value(after["entries"][1].clone()).unwrap();
        assert!(serde_json::to_value(record.view())
            .unwrap()
            .get("message_seq")
            .is_none());
        let legacy: NotificationStore = serde_json::from_value(before).unwrap();
        assert!(legacy.entries[0].message_seq.is_none());
    }

    #[test]
    fn direct_message_notifications_belong_to_one_account() {
        let tmp = tempfile::tempdir().unwrap();
        upsert_direct_message_notification(tmp.path(), ALICE, "direct:alice-x", "Xan", now_ts())
            .unwrap();
        upsert_direct_message_notification(tmp.path(), BOB, "direct:bob-y", "Yan", now_ts())
            .unwrap();

        // Each account sees only its own dot and Inbox entry.
        assert_eq!(
            unread_direct_message_conversations(tmp.path(), ALICE).unwrap(),
            ["direct:alice-x".to_string()].into()
        );
        assert_eq!(
            unread_direct_message_conversations(tmp.path(), BOB).unwrap(),
            ["direct:bob-y".to_string()].into()
        );
        assert!(load_summary(tmp.path()).unwrap().entries.is_empty());
        let alice = owned_summary(tmp.path(), ALICE);
        assert_eq!(alice.entries.len(), 1);
        assert_eq!(alice.unread_count, 1);
        assert_eq!(alice.entries[0].title, "New message from Xan");

        // Neither another account nor the Home CLI can change Alice's entry.
        let alice_id = direct_message_notification_id("direct:alice-x");
        let alice_action = direct_message_notification_action_id("direct:alice-x");
        for viewer in [Some(BOB), None] {
            assert!(!mark_read(tmp.path(), viewer, &alice_id).unwrap());
            assert!(!dismiss(tmp.path(), viewer, &alice_id).unwrap());
            assert_eq!(
                mark_acted_for_action(tmp.path(), viewer, &alice_action).unwrap(),
                0
            );
        }
        assert_eq!(owned_summary(tmp.path(), ALICE).unread_count, 1);

        // Alice opening her conversation clears only her entry.
        assert_eq!(
            mark_acted_for_action(tmp.path(), Some(ALICE), &alice_action).unwrap(),
            1
        );
        assert!(unread_direct_message_conversations(tmp.path(), ALICE)
            .unwrap()
            .is_empty());
        assert_eq!(owned_summary(tmp.path(), BOB).unread_count, 1);
    }

    #[test]
    fn concurrent_writes_from_many_accounts_keep_every_alert() {
        let tmp = tempfile::tempdir().unwrap();
        let accounts = 12;
        let per_account = 5;
        std::thread::scope(|scope| {
            for account in 0..accounts {
                let data = tmp.path();
                scope.spawn(move || {
                    let owner = format!("did:key:z6MkAccount{account}");
                    for index in 0..per_account {
                        upsert_direct_message_notification(
                            data,
                            &owner,
                            &format!("direct:{account}-{index}"),
                            "Peer",
                            now_ts(),
                        )
                        .unwrap();
                        // Reads and clears by another account race the writes.
                        mark_read(data, Some(&owner), "room-access-request:none").unwrap();
                    }
                });
            }
        });
        for account in 0..accounts {
            assert_eq!(
                unread_direct_message_conversations(
                    tmp.path(),
                    &format!("did:key:z6MkAccount{account}")
                )
                .unwrap()
                .len(),
                per_account
            );
        }
    }

    #[test]
    fn a_direct_message_entry_without_an_owner_is_shown_to_nobody() {
        let tmp = tempfile::tempdir().unwrap();
        let path = notifications_path(tmp.path()).unwrap();
        write_json_atomic(
            &path,
            &serde_json::json!({
                "schema": NOTIFICATIONS_SCHEMA,
                "entries": [{
                    "id": direct_message_notification_id("direct:legacy"),
                    "source_app": "chat-room",
                    "kind": DIRECT_MESSAGE_KIND,
                    "title": "New message from Old",
                    "body": "Old sent you a message in Chat.",
                    "created_at": now_ts(),
                    "severity": "attention",
                }],
            }),
        )
        .unwrap();
        for viewer in [ALICE, BOB] {
            assert!(owned_summary(tmp.path(), viewer).entries.is_empty());
            assert!(unread_direct_message_conversations(tmp.path(), viewer)
                .unwrap()
                .is_empty());
        }
        assert!(load_summary(tmp.path()).unwrap().entries.is_empty());

        // The next message for any account drops it.
        upsert_direct_message_notification(tmp.path(), ALICE, "direct:new", "New", now_ts())
            .unwrap();
        let store = read_json_or_default::<NotificationStore>(&path).unwrap();
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.entries[0].owner_profile_did.as_deref(), Some(ALICE));
    }

    #[test]
    fn sync_room_notifications_creates_attention_entry() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();
        let summary = load_summary(tmp.path()).unwrap();
        assert_eq!(summary.unread_count, 1);
        assert_eq!(summary.attention_count, 1);
        assert_eq!(summary.entries[0].source_app, "chat-room");
        assert_eq!(summary.entries[0].id, "room-access-request:req-1");
        assert_eq!(summary.entries[0].kind, ROOM_ACCESS_REQUEST_KIND);
        assert_eq!(
            summary.entries[0]
                .action_ref
                .as_ref()
                .map(|action_ref| action_ref.action_id.as_str()),
            Some("room-approve-request:req-1")
        );
    }

    #[test]
    fn sync_room_notifications_prunes_stale_pair_requests() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();
        let empty = RoomSummary::default();
        sync_room_notifications(tmp.path(), &empty).unwrap();
        let summary = load_summary(tmp.path()).unwrap();
        assert!(summary.entries.is_empty());
    }

    #[test]
    fn mark_acted_for_action_hides_notification_entry() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();
        let updated =
            mark_acted_for_action(tmp.path(), None, "room-approve-request:req-1").unwrap();
        assert_eq!(updated, 1);
        let summary = load_summary(tmp.path()).unwrap();
        assert!(summary.entries.is_empty());
    }

    #[test]
    fn mark_read_updates_entry_state() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();
        let updated = mark_read(tmp.path(), None, "room-access-request:req-1").unwrap();
        assert!(updated);
        let summary = load_summary(tmp.path()).unwrap();
        assert_eq!(summary.unread_count, 0);
        assert!(summary.entries[0].read);
    }

    #[test]
    fn dismiss_hides_entry() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();
        let updated = dismiss(tmp.path(), None, "room-access-request:req-1").unwrap();
        assert!(updated);
        let summary = load_summary(tmp.path()).unwrap();
        assert!(summary.entries.is_empty());
    }

    #[test]
    fn contact_request_notification_names_the_person_once() {
        assert_eq!(
            contact_request_notification_title("Morgan", None),
            "Morgan wants to add you"
        );
        assert_eq!(
            contact_request_notification_title("Morgan", Some("morgan")),
            "Morgan (@morgan) wants to add you"
        );
    }

    #[test]
    fn contact_request_notifications_are_pure_inbox_projections() {
        let tmp = tempfile::tempdir().unwrap();
        let now = now_ts();
        let pending = vec![PendingContactRequestNotification {
            request_hash: "sha256:req".to_string(),
            display_name: "Morgan".to_string(),
            handle: Some("morgan".to_string()),
            created_at: now,
            expires_at: now + 600,
        }];
        let mut summary = load_summary(tmp.path()).unwrap();
        project_contact_request_notifications(&mut summary, &pending);
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.attention_count, 1);
        let entry = &summary.entries[0];
        assert_eq!(entry.kind, CONTACT_REQUEST_KIND);
        assert_eq!(entry.id, "contact-request:sha256:req");
        assert_eq!(entry.source_app, "people");
        assert_eq!(entry.title, "Morgan (@morgan) wants to add you");
        assert_eq!(entry.body, "Accepting adds them to People.");
        // The notification points at Inbox and never carries the decision:
        // its action is the Inbox review reference, resolved by Inbox alone.
        assert_eq!(
            entry.action_ref,
            Some(NotificationActionRef {
                app: "inbox".to_string(),
                action_id: "contact-accept-request:sha256:req".to_string(),
            })
        );
        assert_eq!(entry.expires_at, Some(now + 600));
        assert!(!notifications_path(tmp.path()).unwrap().exists());

        // Re-projecting replaces the dynamic row instead of duplicating it.
        project_contact_request_notifications(&mut summary, &pending);
        assert_eq!(summary.entries.len(), 1);

        // A decided (or revoked, or expired) request leaves the pending
        // projection without mutating a second durable store.
        project_contact_request_notifications(&mut summary, &[]);
        assert!(summary.entries.is_empty());
        assert!(!notifications_path(tmp.path()).unwrap().exists());
    }

    #[test]
    fn custody_request_notifications_carry_their_exact_step_up_request() {
        let tmp = tempfile::tempdir().unwrap();
        let now = now_ts();
        let request =
            |id: &str, received_at: u64, expires_at: u64| PendingCustodyRequestNotification {
                request_id: id.to_string(),
                owner_name: "Olivia".to_string(),
                term_days: 365,
                run_by: "Nadia".to_string(),
                location: "Porto".to_string(),
                received_at,
                expires_at,
                stage: CustodyRequestStage::Waiting,
                step_up_request: serde_json::json!({ "request_id": id, "term_days": 365 }),
            };
        let pending = vec![
            request("bb", now - 5, now + 600),
            request("aa", now - 10, now + 600),
            request("cc", now - 20, now),
            // Its approval began: it stays past its end, to be finished.
            PendingCustodyRequestNotification {
                stage: CustodyRequestStage::Finishing,
                ..request("dd", now - 30, now - 1)
            },
        ];
        let mut summary = load_summary(tmp.path()).unwrap();
        project_custody_request_notifications(&mut summary, &pending);
        // The expired waiting one is gone; the rest are oldest first.
        assert_eq!(
            summary
                .entries
                .iter()
                .map(|entry| (entry.id.as_str(), entry.kind.as_str()))
                .collect::<Vec<_>>(),
            [
                ("custody-node-request:dd", CUSTODY_NODE_APPROVING_KIND),
                ("custody-node-request:aa", CUSTODY_NODE_REQUEST_KIND),
                ("custody-node-request:bb", CUSTODY_NODE_REQUEST_KIND),
            ]
        );
        assert_eq!(summary.attention_count, 3);
        assert_eq!(summary.unread_count, 3);
        let finishing = &summary.entries[0];
        assert_eq!(finishing.title, "Finish approving Olivia's custody request");
        assert_eq!(
            finishing
                .action_ref
                .as_ref()
                .map(|action| action.action_id.as_str()),
            Some("custody-approve-request:dd")
        );
        assert_eq!(
            finishing.step_up_request,
            Some(serde_json::json!({ "request_id": "dd", "term_days": 365 }))
        );
        let entry = &summary.entries[1];
        assert_eq!(entry.kind, CUSTODY_NODE_REQUEST_KIND);
        assert_eq!(entry.source_app, "custody");
        assert_eq!(entry.title, "Olivia asks this Home to hold custody");
        // OPEN-LOOP F1 (ADV-14): the one consent names both duties.
        for approvable in [entry, finishing] {
            assert!(
                approvable.body.contains(
                    "This Home will hold a key share and keep a copy of this pool's files."
                ),
                "{}",
                approvable.body
            );
        }
        assert_eq!(
            entry.action_ref,
            Some(NotificationActionRef {
                app: "inbox".to_string(),
                action_id: "custody-approve-request:aa".to_string(),
            })
        );
        assert_eq!(entry.created_at, now - 10);
        assert_eq!(entry.expires_at, Some(now + 600));
        assert_eq!(
            entry.step_up_request,
            Some(serde_json::json!({ "request_id": "aa", "term_days": 365 }))
        );

        project_custody_request_notifications(&mut summary, &pending);
        assert_eq!(summary.entries.len(), 3);
        project_custody_request_notifications(&mut summary, &[]);
        assert!(summary.entries.is_empty());
        assert!(!notifications_path(tmp.path()).unwrap().exists());
    }

    #[test]
    fn an_approval_that_set_nothing_up_is_approved_or_declined_with_its_passkey_card() {
        let now = now_ts();
        let mut summary = NotificationSummary::default();
        project_custody_request_notifications(
            &mut summary,
            &[PendingCustodyRequestNotification {
                request_id: "ee".to_string(),
                owner_name: "Olivia".to_string(),
                term_days: 365,
                run_by: "Nadia".to_string(),
                location: "Porto".to_string(),
                received_at: now - 30,
                expires_at: now - 1,
                stage: CustodyRequestStage::Resumable,
                step_up_request: serde_json::json!({ "request_id": "ee" }),
            }],
        );
        assert_eq!(summary.entries.len(), 1, "it stays past its end");
        let entry = &summary.entries[0];
        assert_eq!(entry.kind, CUSTODY_NODE_RESUMABLE_KIND);
        assert_eq!(entry.title, "Finish approving Olivia's custody request");
        assert!(entry.body.contains("or decline it"), "{}", entry.body);
        assert!(entry.passkey_approval);
        assert_eq!(
            entry
                .action_ref
                .as_ref()
                .map(|action| action.action_id.as_str()),
            Some("custody-approve-request:ee")
        );
    }

    #[test]
    fn direct_message_notification_resolves_on_read_and_resurfaces_on_new_mail() {
        let tmp = tempfile::tempdir().unwrap();
        let conversation = "direct:sha256:abc";
        upsert_direct_message_notification(tmp.path(), ALICE, conversation, "Alice", 100).unwrap();
        let summary = owned_summary(tmp.path(), ALICE);
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.entries[0].kind, DIRECT_MESSAGE_KIND);
        assert_eq!(summary.entries[0].id, "direct-message:direct:sha256:abc");
        assert_eq!(summary.entries[0].title, "New message from Alice");
        assert_eq!(summary.entries[0].source_app, "chat-room");
        assert_eq!(
            summary.entries[0]
                .action_ref
                .as_ref()
                .map(|action| action.action_id.as_str()),
            Some("chat-open-direct:direct:sha256:abc")
        );

        // A second message keeps one entry per conversation.
        upsert_direct_message_notification(tmp.path(), ALICE, conversation, "Alice", 101).unwrap();
        assert_eq!(owned_summary(tmp.path(), ALICE).entries.len(), 1);

        // Reading the conversation resolves it.
        let acted = mark_acted_for_action(
            tmp.path(),
            Some(ALICE),
            &direct_message_notification_action_id(conversation),
        )
        .unwrap();
        assert_eq!(acted, 1);
        assert!(owned_summary(tmp.path(), ALICE).entries.is_empty());

        // New mail after a read resurfaces the same entry, unread again.
        upsert_direct_message_notification(tmp.path(), ALICE, conversation, "Alice Renamed", 102)
            .unwrap();
        let resurfaced = owned_summary(tmp.path(), ALICE);
        assert_eq!(resurfaced.entries.len(), 1);
        assert!(!resurfaced.entries[0].read);
        assert_eq!(
            resurfaced.entries[0].title,
            "New message from Alice Renamed"
        );
    }

    #[test]
    fn sync_room_notifications_does_not_write_shared_native_chat_state() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();

        let shared_native_chat = tmp
            .path()
            .join("localhost/Users/self/.AppData/LocalHost/Chat");
        assert!(!shared_native_chat.exists());
    }

    #[test]
    fn sync_room_notifications_records_appeared_event() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();

        let events: NotificationEventStore =
            read_json_or_default(&notification_events_path(tmp.path()).unwrap()).unwrap();
        assert_eq!(events.entries.len(), 1);
        assert_eq!(
            events.entries[0].disposition,
            NotificationEventDisposition::Appeared
        );
        assert_eq!(
            events.entries[0].notification_id,
            "room-access-request:req-1"
        );
    }

    #[test]
    fn dismiss_records_resolved_event() {
        let tmp = tempfile::tempdir().unwrap();
        sync_room_notifications(tmp.path(), &sample_summary()).unwrap();
        dismiss(tmp.path(), None, "room-access-request:req-1").unwrap();

        let events: NotificationEventStore =
            read_json_or_default(&notification_events_path(tmp.path()).unwrap()).unwrap();
        assert_eq!(events.entries.len(), 2);
        assert_eq!(
            events.entries[1].disposition,
            NotificationEventDisposition::Resolved
        );
        assert_eq!(events.entries[1].resolution.as_deref(), Some("dismissed"));
    }
    #[test]
    fn external_http_request_appears_once_and_can_be_dismissed() {
        let tmp = tempfile::tempdir().unwrap();
        upsert_external_http_request(
            tmp.path(),
            "wallet-prices",
            "wallet",
            "Wallet requests market prices",
            "Wallet wants approved HTTP access to CoinGecko.",
            "wallet-price-http-approve:coingecko",
            42,
        )
        .unwrap();
        upsert_external_http_request(
            tmp.path(),
            "wallet-prices",
            "wallet",
            "Wallet requests market prices",
            "Wallet wants approved HTTP access to CoinGecko.",
            "wallet-price-http-approve:coingecko",
            43,
        )
        .unwrap();

        let summary = load_summary(tmp.path()).unwrap();
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.entries[0].kind, EXTERNAL_HTTP_REQUEST_KIND);
        assert_eq!(
            summary.entries[0]
                .action_ref
                .as_ref()
                .map(|action| action.action_id.as_str()),
            Some("wallet-price-http-approve:coingecko")
        );

        assert!(dismiss_external_http_request(tmp.path(), "wallet-prices").unwrap());
        assert!(load_summary(tmp.path()).unwrap().entries.is_empty());
    }

    // ── META-PUBLIC A4 §1.3: the public metadata card, row by row ──────

    fn public_state(card: PublicMetadataCard) -> PublicMetadataCardState {
        PublicMetadataCardState {
            card,
            store: Some(PublicMetadataStoreReading {
                running: true,
                ready: true,
            }),
            since: 42,
        }
    }

    fn public_entry(state: &PublicMetadataCardState) -> Option<NotificationEntryView> {
        let mut summary = NotificationSummary::default();
        project_public_metadata_notifications(&mut summary, state);
        assert!(summary.entries.len() <= 1);
        assert_eq!(
            summary.unread_count,
            summary.entries.iter().filter(|entry| !entry.read).count()
        );
        summary.entries.pop()
    }

    #[test]
    fn public_card_stopping_row() {
        let entry = public_entry(&public_state(PublicMetadataCard::Stopping {
            stop_pending: None,
        }))
        .unwrap();
        assert_eq!(
            entry.kind,
            crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_STOPPING
        );
        assert_eq!(entry.body, "Stopping…");
        assert_eq!(
            entry.action_ref.unwrap().action_id,
            crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_STOP
        );
        assert!(!entry.passkey_approval);
        let entry = public_entry(&public_state(PublicMetadataCard::Stopping {
            stop_pending: Some("the repo lock is still held".into()),
        }))
        .unwrap();
        assert_eq!(
            entry.body,
            "Still stopping: the repo lock is still held. Your Home keeps trying."
        );
    }

    #[test]
    fn public_card_unreadable_consent_row() {
        let entry = public_entry(&public_state(PublicMetadataCard::ConsentUnreadable)).unwrap();
        assert_eq!(
            entry.kind,
            crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_UNREADABLE
        );
        assert_eq!(
            entry.body,
            "Metadata sharing state can't be read. Stop sharing to reset it."
        );
        assert_eq!(
            entry.action_ref.unwrap().action_id,
            crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_STOP
        );
    }

    #[test]
    fn public_card_sharing_row_shows_the_last_known_store_state() {
        for (store, sentence) in [
            (
                Some(PublicMetadataStoreReading {
                    running: true,
                    ready: true,
                }),
                " Its public IPFS node is ready.",
            ),
            (
                Some(PublicMetadataStoreReading {
                    running: true,
                    ready: false,
                }),
                " Its public IPFS node is starting.",
            ),
            (
                Some(PublicMetadataStoreReading {
                    running: false,
                    ready: false,
                }),
                " Its public IPFS node is not running.",
            ),
            (None, ""),
        ] {
            let entry = public_entry(&PublicMetadataCardState {
                card: PublicMetadataCard::Sharing,
                store,
                since: 1,
            })
            .unwrap();
            assert_eq!(
                entry.kind,
                crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_SHARING
            );
            assert_eq!(
                entry.body,
                format!("Your Home shares minted assets' metadata on public IPFS.{sentence}")
            );
            assert_eq!(
                entry.action_ref.unwrap().action_id,
                crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_STOP
            );
            assert!(entry.read);
        }
    }

    #[test]
    fn public_card_paused_row() {
        let entry = public_entry(&public_state(PublicMetadataCard::Paused {
            reason: "protected content is off".into(),
        }))
        .unwrap();
        assert_eq!(
            entry.kind,
            crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_PAUSED
        );
        assert_eq!(
            entry.body,
            "Metadata sharing is paused on this Home (protected content is off). \
             Your consent is kept."
        );
        assert_eq!(
            entry.action_ref.unwrap().action_id,
            crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_STOP
        );
    }

    /// The offer is a quiet standing card: info AND an explicit `read: true`,
    /// so it never counts unread; its passkey approves exactly the request.
    #[test]
    fn public_card_offer_row_is_quiet_and_exact() {
        let request = serde_json::json!({ "wording_version": 1, "wording_sha256": "ab" });
        let entry = public_entry(&public_state(PublicMetadataCard::Offer {
            step_up_request: request.clone(),
        }))
        .unwrap();
        assert_eq!(
            entry.kind,
            crate::custody_surface::INBOX_KIND_PUBLIC_METADATA_CONSENT
        );
        assert_eq!(entry.body, crate::public_metadata_consent::CONSENT_WORDING);
        assert_eq!(entry.severity, NotificationSeverity::Info);
        assert!(entry.read);
        assert!(entry.passkey_approval);
        assert_eq!(entry.step_up_request, Some(request));
        assert_eq!(
            entry.action_ref.unwrap().action_id,
            crate::custody_surface::INBOX_ACTION_PUBLIC_METADATA_ENABLE
        );
    }

    /// No card, and any card projected before is gone: the snapshot is the
    /// only truth.
    #[test]
    fn public_card_hidden_row_projects_nothing() {
        let mut summary = NotificationSummary::default();
        project_public_metadata_notifications(
            &mut summary,
            &public_state(PublicMetadataCard::Sharing),
        );
        assert_eq!(summary.entries.len(), 1);
        project_public_metadata_notifications(
            &mut summary,
            &public_state(PublicMetadataCard::Hidden),
        );
        assert!(summary.entries.is_empty());
        assert_eq!(summary.unread_count, 0);
    }

    #[test]
    fn public_card_signature_has_its_fields_and_nothing_else() {
        let state = PublicMetadataCardState {
            card: PublicMetadataCard::Stopping {
                stop_pending: Some("x".into()),
            },
            store: Some(PublicMetadataStoreReading {
                running: true,
                ready: false,
            }),
            since: 1,
        };
        let signature = state.realtime_signature();
        let prefix = &hex::encode(sha2::Sha256::digest(b"x"))[..16];
        assert_eq!(
            signature,
            format!("public-metadata:public_metadata_stopping:running:false:{prefix}")
        );
        // The time is not part of it.
        assert_eq!(
            PublicMetadataCardState {
                since: 99,
                ..state.clone()
            }
            .realtime_signature(),
            signature
        );
        let hidden = PublicMetadataCardState {
            card: PublicMetadataCard::Hidden,
            store: None,
            since: 0,
        };
        assert_eq!(
            hidden.realtime_signature(),
            "public-metadata:none:none:false:"
        );
    }
}
