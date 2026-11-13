//! Pool active, owner side: after install, this Home tells each member node
//! that it is in the signed pool.
//!
//! Gateway-free: the Custody app's install and notify routes adapt it, and
//! the custody message plane's delivery pass resends through the one consent
//! handler. The notice is rebuilt from the installed composition on each
//! pass until its member acknowledges it; the notice set records only who
//! was told.
//!
//! Plan B T3.3 (X5, L13): once a member acknowledged the notice, the pass
//! also sends it the owner's signed pool descriptor, and again at each new
//! sequence. A descriptor that cannot be signed yet, as before the admin
//! enabled the descriptor message type, waits for a later pass.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::collaboration_config::read_owner_only_file;
use crate::collaboration_custody_messages::{
    terminal_state_for, CollaborationCustodyMessageService, CustodyOutboxState,
    WeakCustodyMessageService,
};
use crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument;
use crate::custody_consent::CustodyWriteGuard;
use crate::custody_consent_protocol::{
    signed_composition_facts, CustodyMessageRefusal, CustodyMessageType, CustodyPayload,
    CustodyPoolActivePayload, CustodyPoolDescriptorPayload, CustodyPoolMember,
    CustodyPoolThreshold, MAX_POOL_ACTIVE_CONFIG_BYTES,
};
use crate::custody_owner_requests::AcceptedContact;
use crate::custody_pool_setup::{CustodyRefusal, PoolMemberView};
use crate::protected_content_config::{ensure_owner_only_dir, MAX_CUSTODY_COMPOSITION_FILE_BYTES};
use crate::protected_content_runtime::{
    protected_content_root, runtime_custody_composition_config_path, write_owner_only_bytes,
};

const NOTICES_FILE: &str = "custody-pool-notices.json";
const NOTICES_SCHEMA_V1: &str = "elastos.protected-content.custody-pool-notices/v1";
/// Room for a member list at the threshold's largest size.
const MAX_NOTICES_FILE_BYTES: usize = 64 * 1024;
const NOTICE_OUTBOX_PREFIX: &str = "custody-pool-active:";
const DESCRIPTOR_OUTBOX_PREFIX: &str = "custody-pool-descriptor:";
/// This Home's own node, from Include this Home: nobody to tell.
const THIS_HOME: &str = "this_home";
/// A member whose node is not an accepted contact's Home.
const NOT_CONTACT: &str = "not_contact";
/// The composition does not fit a notice; telling again cannot fix it.
const TOO_LARGE: &str = "too_large";
/// The members' Run by and Location were not kept, as after an install from
/// the terminal, so no notice can be built.
const MISSING_LABELS: &str = "missing_labels";
/// The installed pool is gone, unreadable, ended or another one than the
/// set is for, so no notice can be built for this set.
const POOL_UNAVAILABLE: &str = "pool_unavailable";

/// The notice set changes one writer at a time: the delivery pass resends
/// while the admin installs or notifies again.
static NOTICES_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NoticeState {
    Pending,
    Delivered,
    Refused,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeMemberV1 {
    share: u8,
    /// The member node's Home DID; absent for this Home's own node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_profile_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_name: Option<String>,
    state: NoticeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    /// Plan B T3.3: the owner's descriptor sent to this member, by sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    descriptor: Option<DescriptorDeliveryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorDeliveryV1 {
    sequence: u64,
    state: NoticeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolNoticesFileV1 {
    schema: String,
    fingerprint_full: String,
    /// The admin's Profile that signs the notices.
    local_profile_did: String,
    members: Vec<NoticeMemberV1>,
}

/// Who was told about the installed pool, as the Custody app shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PoolNoticesView {
    pub(crate) fingerprint_full: String,
    pub(crate) members: Vec<NoticeMemberView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NoticeMemberView {
    pub(crate) share: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recipient_name: Option<String>,
    pub(crate) state: NoticeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
}

impl PoolNoticesView {
    fn of(set: &PoolNoticesFileV1) -> Self {
        Self {
            fingerprint_full: set.fingerprint_full.clone(),
            members: set
                .members
                .iter()
                .map(|member| NoticeMemberView {
                    share: member.share,
                    recipient_name: member.recipient_name.clone(),
                    state: member.state,
                    code: member.code.clone(),
                })
                .collect(),
        }
    }
}

/// Signs and queues this Home's pool notices. The message service is the
/// real one; it is a seam so the rules here are tested without Carrier.
#[async_trait::async_trait]
pub(crate) trait NoticeOutbox: Send + Sync {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        notice: CustodyPoolActivePayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>>;

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()>;

    /// `None` when the outbox does not know the key, as after a restart.
    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState>;

    /// Drops what the outbox holds under `key`.
    fn forget(&self, key: &str);

    /// Plan B T3.3: signs the owner's pool descriptor for a member.
    fn sign_descriptor(
        &self,
        _local_profile_did: &str,
        _recipient_profile_did: &str,
        _descriptor: CustodyPoolDescriptorPayload,
        _now: u64,
        _expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("this outbox does not sign pool descriptors")
    }

    /// Queues the message and attempts it once now.
    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState>;
}

#[async_trait::async_trait]
impl NoticeOutbox for CollaborationCustodyMessageService {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        notice: CustodyPoolActivePayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.prepare(
            local_profile_did,
            recipient_profile_did,
            &CustodyPayload::PoolActive(notice),
            now,
            expires_at,
        )
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()> {
        CollaborationCustodyMessageService::enqueue(self, key, local_profile_did, envelope, now)
    }

    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState> {
        self.outbox_state(key, now)
    }

    fn forget(&self, key: &str) {
        CollaborationCustodyMessageService::forget(self, key);
    }

    fn sign_descriptor(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        descriptor: CustodyPoolDescriptorPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.prepare(
            local_profile_did,
            recipient_profile_did,
            &CustodyPayload::PoolDescriptor(descriptor),
            now,
            expires_at,
        )
    }

    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        CollaborationCustodyMessageService::send(self, key, local_profile_did, envelope, now).await
    }
}

#[async_trait::async_trait]
impl NoticeOutbox for WeakCustodyMessageService {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        notice: CustodyPoolActivePayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        NoticeOutbox::sign(
            &live_service(self)?,
            local_profile_did,
            recipient_profile_did,
            notice,
            now,
            expires_at,
        )
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()> {
        NoticeOutbox::enqueue(&live_service(self)?, key, local_profile_did, envelope, now)
    }

    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState> {
        self.upgrade()?.outbox_state(key, now)
    }

    fn forget(&self, key: &str) {
        if let Some(service) = self.upgrade() {
            service.forget(key);
        }
    }

    fn sign_descriptor(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        descriptor: CustodyPoolDescriptorPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        NoticeOutbox::sign_descriptor(
            &live_service(self)?,
            local_profile_did,
            recipient_profile_did,
            descriptor,
            now,
            expires_at,
        )
    }

    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        NoticeOutbox::send(&live_service(self)?, key, local_profile_did, envelope, now).await
    }
}

fn live_service(
    weak: &WeakCustodyMessageService,
) -> anyhow::Result<CollaborationCustodyMessageService> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("custody messages have stopped"))
}

/// The installed pool as the Runtime loader accepted it, with the exact
/// composition bytes its members are told about.
struct InstalledPool {
    config: Vec<u8>,
    fingerprint_full: String,
    members: Vec<PoolMemberView>,
}

fn installed_pool(data_dir: &Path) -> anyhow::Result<Option<InstalledPool>> {
    let Some(pool) = crate::custody_pool_setup::read_pool(data_dir)? else {
        return Ok(None);
    };
    let config = read_owner_only_file(
        &runtime_custody_composition_config_path(data_dir),
        MAX_CUSTODY_COMPOSITION_FILE_BYTES,
        "custody composition",
    )?;
    if sha256_label(&config) != pool.fingerprint_full {
        anyhow::bail!("the custody pool changed while it was read");
    }
    Ok(Some(InstalledPool {
        config,
        fingerprint_full: pool.fingerprint_full,
        members: pool.members,
    }))
}

/// The notice for the member holding `share`: the exact composition, and
/// its facts read from it as the protocol reads them. `labels` are every
/// member's `(share, run_by, location)`. They are this owner's display text,
/// from its members record: the composition holds only their hashed ids, and
/// a node does not check the labels against them.
pub(crate) fn pool_active_notice(
    config: &[u8],
    labels: &[(u8, String, String)],
    share: u8,
) -> anyhow::Result<CustodyPoolActivePayload> {
    let facts = signed_composition_facts(config)?;
    let mut members: Vec<CustodyPoolMember> = labels
        .iter()
        .map(|(share, run_by, location)| CustodyPoolMember {
            location: location.clone(),
            run_by: run_by.clone(),
            share: *share,
        })
        .collect();
    members.sort_by_key(|member| member.share);
    Ok(CustodyPoolActivePayload {
        config: base64::engine::general_purpose::STANDARD.encode(config),
        fingerprint_full: sha256_label(config),
        members,
        pool_start: facts.start,
        share,
        term_end: facts.end,
        threshold: CustodyPoolThreshold {
            required: facts.threshold.required(),
            total: facts.threshold.total(),
        },
    })
}

/// Every member's labels, or `None` when any were not kept.
fn member_labels(pool: &InstalledPool) -> Option<Vec<(u8, String, String)>> {
    pool.members
        .iter()
        .map(|member| match (&member.run_by, &member.location) {
            (Some(run_by), Some(location)) => {
                Some((member.share, run_by.clone(), location.clone()))
            }
            _ => None,
        })
        .collect()
}

/// What a pass can build notices from: the installed pool the set is for,
/// with every member's labels, or why it cannot.
enum Rebuild {
    Ready {
        config: Vec<u8>,
        labels: Vec<(u8, String, String)>,
    },
    Settle(&'static str),
}

fn rebuild_for(data_dir: &Path, fingerprint_full: &str) -> Rebuild {
    let pool = match installed_pool(data_dir) {
        Ok(Some(pool)) if pool.fingerprint_full == fingerprint_full => pool,
        Ok(_) => return Rebuild::Settle(POOL_UNAVAILABLE),
        Err(error) => {
            tracing::debug!(
                error = %format!("{error:#}"),
                "the installed custody pool is unreadable"
            );
            return Rebuild::Settle(POOL_UNAVAILABLE);
        }
    };
    match member_labels(&pool) {
        Some(labels) => Rebuild::Ready {
            config: pool.config,
            labels,
        },
        None => Rebuild::Settle(MISSING_LABELS),
    }
}

/// After an install: who of the pool's members this Home tells, and who it
/// cannot. A new install replaces the set.
pub(crate) fn record_install(
    data_dir: &Path,
    sender: &VerifiedCollaborationProfileDocument,
    contacts: &[AcceptedContact],
) -> anyhow::Result<PoolNoticesView> {
    let pool = installed_pool(data_dir)?.ok_or_else(|| CustodyRefusal::new("no_pool"))?;
    let set = notice_set(&pool, sender, contacts);
    let _guard = lock()?;
    store_set(data_dir, &set)?;
    tracing::debug!("custody pool notices recorded");
    Ok(PoolNoticesView::of(&set))
}

fn notice_set(
    pool: &InstalledPool,
    sender: &VerifiedCollaborationProfileDocument,
    contacts: &[AcceptedContact],
) -> PoolNoticesFileV1 {
    let too_large = pool.config.len() > MAX_POOL_ACTIVE_CONFIG_BYTES;
    if too_large {
        tracing::warn!(
            bytes = pool.config.len(),
            "this pool's composition is too large to tell its members"
        );
    }
    let members = pool
        .members
        .iter()
        .map(|member| {
            let skipped = |recipient_home: Option<String>, code: &str| NoticeMemberV1 {
                share: member.share,
                recipient_home,
                recipient_profile_did: None,
                recipient_name: None,
                state: NoticeState::Skipped,
                code: Some(code.to_string()),
                descriptor: None,
            };
            if member.this_home {
                return skipped(None, THIS_HOME);
            }
            let Some(home) = member.home_id.clone() else {
                return skipped(None, NOT_CONTACT);
            };
            let Some(contact) = contact_for(contacts, &home) else {
                return skipped(Some(home), NOT_CONTACT);
            };
            NoticeMemberV1 {
                share: member.share,
                recipient_home: Some(home),
                recipient_profile_did: Some(contact.profile_did.clone()),
                recipient_name: Some(contact.name.clone()),
                state: if too_large {
                    NoticeState::Refused
                } else {
                    NoticeState::Pending
                },
                code: too_large.then(|| TOO_LARGE.to_string()),
                descriptor: None,
            }
        })
        .collect();
    PoolNoticesFileV1 {
        schema: NOTICES_SCHEMA_V1.to_string(),
        fingerprint_full: pool.fingerprint_full.clone(),
        local_profile_did: sender.document().profile_did.clone(),
        members,
    }
}

/// The delivery-pass step: each member still waiting is settled from what
/// the outbox saw, and one the outbox no longer holds, as after a restart,
/// gets a fresh notice built from the installed pool while that pool is the
/// one the set is for. A member whose notice can no longer be built settles
/// once. Nothing is read beyond the set when nobody waits.
pub(crate) fn resume_notices(
    data_dir: &Path,
    outbox: &dyn NoticeOutbox,
    now: u64,
) -> anyhow::Result<()> {
    if !present(&notices_path(data_dir))? {
        return Ok(());
    }
    let _guard = lock()?;
    let Some(mut set) = load_set(data_dir)? else {
        return Ok(());
    };
    if !set
        .members
        .iter()
        .any(|member| matches!(member.state, NoticeState::Pending | NoticeState::Delivered))
    {
        return Ok(());
    }
    let loaded = set.clone();
    // Built at most once per pass, and only when a notice must be built.
    let mut rebuild: Option<Rebuild> = None;
    for member in set
        .members
        .iter_mut()
        .filter(|member| member.state == NoticeState::Pending)
    {
        let Some(key) = notice_key(&loaded.fingerprint_full, member) else {
            continue;
        };
        match outbox.state(&key, now) {
            Some(CustodyOutboxState::Delivered) => member.state = NoticeState::Delivered,
            Some(CustodyOutboxState::Refused(code)) => refuse(member, code),
            Some(CustodyOutboxState::Pending) => {}
            Some(CustodyOutboxState::Expired) | None => {
                match rebuild.get_or_insert_with(|| rebuild_for(data_dir, &loaded.fingerprint_full))
                {
                    Rebuild::Ready { config, labels } => {
                        let queued = signed_notice(
                            outbox,
                            &loaded.local_profile_did,
                            member,
                            config,
                            labels,
                            now,
                        )
                        .and_then(|envelope| {
                            outbox.enqueue(&key, &loaded.local_profile_did, envelope, now)
                        });
                        if let Err(error) = queued {
                            settle_failure(member, &error);
                        }
                    }
                    Rebuild::Settle(code) => refuse(member, code.to_string()),
                }
            }
        }
    }
    deliver_descriptors(data_dir, outbox, &mut set, now);
    if set != loaded {
        store_set(data_dir, &set)?;
    }
    Ok(())
}

/// X5 (L13): each member that acknowledged the pool notice gets the owner's
/// current descriptor, while the installed pool is the one the set is for.
fn deliver_descriptors(
    data_dir: &Path,
    outbox: &dyn NoticeOutbox,
    set: &mut PoolNoticesFileV1,
    now: u64,
) {
    if !set
        .members
        .iter()
        .any(|member| member.state == NoticeState::Delivered)
    {
        return;
    }
    if installed_fingerprint(data_dir).as_deref() != Some(set.fingerprint_full.as_str()) {
        return;
    }
    let descriptor = match crate::custody_pool_descriptor::owner_descriptor(data_dir, now) {
        Ok(Some(descriptor)) => descriptor,
        Ok(None) => return,
        Err(error) => {
            tracing::debug!(
                error = %format!("{error:#}"),
                "the custody pool descriptor waits for the next pass"
            );
            return;
        }
    };
    let sequence = descriptor.statement().sequence();
    let payload = match CustodyPoolDescriptorPayload::new(&descriptor) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "the custody pool descriptor is not sendable");
            return;
        }
    };
    let fingerprint_full = set.fingerprint_full.clone();
    let local_profile_did = set.local_profile_did.clone();
    for member in set
        .members
        .iter_mut()
        .filter(|member| member.state == NoticeState::Delivered)
    {
        let (Some(key), Some(recipient)) = (
            descriptor_key(&fingerprint_full, member, sequence),
            member.recipient_profile_did.clone(),
        ) else {
            continue;
        };
        let sent = member
            .descriptor
            .as_ref()
            .filter(|sent| sent.sequence == sequence)
            .map(|sent| sent.state);
        match sent {
            Some(state) if state != NoticeState::Pending => continue,
            Some(_) => match outbox.state(&key, now) {
                Some(CustodyOutboxState::Delivered) => {
                    set_descriptor(member, sequence, NoticeState::Delivered, None);
                    continue;
                }
                Some(CustodyOutboxState::Refused(code)) => {
                    set_descriptor(member, sequence, NoticeState::Refused, Some(code));
                    continue;
                }
                Some(CustodyOutboxState::Pending) => continue,
                Some(CustodyOutboxState::Expired) | None => {}
            },
            None => {}
        }
        let queued = outbox
            .sign_descriptor(
                &local_profile_did,
                &recipient,
                payload.clone(),
                now,
                now.saturating_add(CustodyMessageType::PoolDescriptor.max_lifetime_secs()),
            )
            .and_then(|envelope| outbox.enqueue(&key, &local_profile_did, envelope, now));
        match queued {
            Ok(()) => set_descriptor(member, sequence, NoticeState::Pending, None),
            Err(error) => match terminal_state_for(&error) {
                // This Home's own Profile lacks the descriptor scope. That is
                // no refusal by the member: once the owner grants the scope,
                // a later pass sends this same sequence (T33-F1).
                _ if lacks_local_signing_scope(&error) => tracing::debug!(
                    "a custody pool descriptor waits for this Home's custody signing scope"
                ),
                Some(CustodyOutboxState::Refused(code)) => {
                    set_descriptor(member, sequence, NoticeState::Refused, Some(code));
                }
                _ => tracing::debug!(
                    error = %format!("{error:#}"),
                    "a custody pool descriptor waits for the next pass"
                ),
            },
        }
    }
}

/// On the sending path `SignerNotAuthorized` is always about this Home's own
/// Profile: signing checks it, and queueing re-verifies the envelope against
/// it. No member refused anything.
fn lacks_local_signing_scope(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<CustodyMessageRefusal>(),
        Some(CustodyMessageRefusal::SignerNotAuthorized)
    )
}

fn set_descriptor(
    member: &mut NoticeMemberV1,
    sequence: u64,
    state: NoticeState,
    code: Option<String>,
) {
    member.descriptor = Some(DescriptorDeliveryV1 {
        sequence,
        state,
        code,
    });
}

/// A member's descriptor outbox key, scoped to the pool and the sequence.
fn descriptor_key(
    fingerprint_full: &str,
    member: &NoticeMemberV1,
    sequence: u64,
) -> Option<String> {
    let pool = fingerprint_full
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint_full);
    member.recipient_home.as_deref().map(|home| {
        format!(
            "{DESCRIPTOR_OUTBOX_PREFIX}{}:{sequence}:{home}",
            pool.get(..16).unwrap_or(pool)
        )
    })
}

/// The installed composition file's fingerprint, read without the term gate
/// so a descriptor still follows after the members' term (F1).
fn installed_fingerprint(data_dir: &Path) -> Option<String> {
    read_owner_only_file(
        &runtime_custody_composition_config_path(data_dir),
        MAX_CUSTODY_COMPOSITION_FILE_BYTES,
        "custody composition",
    )
    .ok()
    .map(|config| sha256_label(&config))
}

/// What notify needs from the running Home.
pub(crate) struct NoticeHost<'a> {
    pub(crate) data_dir: &'a Path,
    pub(crate) outbox: &'a dyn NoticeOutbox,
    /// The admin's Profile, which signs a set made afresh.
    pub(crate) profile: &'a VerifiedCollaborationProfileDocument,
    pub(crate) contacts: &'a [AcceptedContact],
}

/// Notify members again: every member waiting, refused (except for a
/// composition too large to send) or not matched to a contact is renewed
/// and waits again with a fresh notice, and each
/// is tried once now. A pool installed without a set, such as from the
/// terminal, gets one. The custody write lock covers the file write only
/// and is released before any send.
pub(crate) async fn notify_members(
    write: CustodyWriteGuard,
    host: &NoticeHost<'_>,
    now: u64,
) -> anyhow::Result<PoolNoticesView> {
    let data_dir = host.data_dir;
    let pool = installed_pool(data_dir)?.ok_or_else(|| CustodyRefusal::new("no_pool"))?;
    let attempts = {
        let _guard = lock()?;
        let mut set = match load_set(data_dir)? {
            Some(mut set) if set.fingerprint_full == pool.fingerprint_full => {
                for member in set.members.iter_mut() {
                    renew(
                        member,
                        host.contacts,
                        pool.config.len() > MAX_POOL_ACTIVE_CONFIG_BYTES,
                    );
                    if member.state == NoticeState::Pending {
                        if let Some(key) = notice_key(&set.fingerprint_full, member) {
                            host.outbox.forget(&key);
                        }
                    }
                }
                set
            }
            _ => notice_set(&pool, host.profile, host.contacts),
        };
        let labels = member_labels(&pool);
        let mut attempts = Vec::new();
        for member in set
            .members
            .iter_mut()
            .filter(|member| member.state == NoticeState::Pending)
        {
            let Some(key) = notice_key(&set.fingerprint_full, member) else {
                continue;
            };
            let Some(labels) = labels.as_deref() else {
                refuse(member, MISSING_LABELS.to_string());
                continue;
            };
            match signed_notice(
                host.outbox,
                &set.local_profile_did,
                member,
                &pool.config,
                labels,
                now,
            ) {
                Ok(envelope) => attempts.push((member.share, key, envelope)),
                Err(error) => settle_failure(member, &error),
            }
        }
        store_set(data_dir, &set)?;
        (set.local_profile_did, set.fingerprint_full, attempts)
    };
    drop(write);
    let (local_profile_did, fingerprint_full, attempts) = attempts;
    let mut outcomes = Vec::new();
    for (share, key, envelope) in attempts {
        let outcome = host
            .outbox
            .send(&key, &local_profile_did, envelope, now)
            .await;
        outcomes.push((share, outcome));
    }
    let _guard = lock()?;
    let mut set = load_set(data_dir)?
        .filter(|set| set.fingerprint_full == fingerprint_full)
        .ok_or_else(|| anyhow::anyhow!("the custody pool notices changed while sending"))?;
    for (share, outcome) in outcomes {
        let Some(member) = set
            .members
            .iter_mut()
            .find(|member| member.share == share && member.state == NoticeState::Pending)
        else {
            continue;
        };
        match outcome {
            Ok(CustodyOutboxState::Delivered) => member.state = NoticeState::Delivered,
            Ok(CustodyOutboxState::Refused(code)) => refuse(member, code),
            Ok(CustodyOutboxState::Pending | CustodyOutboxState::Expired) => {}
            Err(error) => settle_failure(member, &error),
        }
    }
    store_set(data_dir, &set)?;
    Ok(PoolNoticesView::of(&set))
}

/// The set for the installed pool whose fingerprint is `fingerprint_full`,
/// for the Custody summary.
pub(crate) fn pool_notices_view(
    data_dir: &Path,
    fingerprint_full: &str,
) -> anyhow::Result<Option<PoolNoticesView>> {
    Ok(load_set(data_dir)?
        .filter(|set| set.fingerprint_full == fingerprint_full)
        .map(|set| PoolNoticesView::of(&set)))
}

/// Notify again's view of one member: one waiting, or refused for anything
/// but its size, waits again, and one that was not a contact is matched
/// again, so a set recorded while contacts could not be read recovers. Its
/// contact is read afresh; one no longer a contact is skipped. In a pool
/// whose composition is `too_large` to send, a matched member is refused for
/// that instead of waiting. This Home's own node and a member already
/// refused for size stay as they are.
fn renew(member: &mut NoticeMemberV1, contacts: &[AcceptedContact], too_large: bool) {
    let retry = match member.state {
        NoticeState::Pending => true,
        NoticeState::Refused => member.code.as_deref() != Some(TOO_LARGE),
        NoticeState::Skipped => member.code.as_deref() == Some(NOT_CONTACT),
        NoticeState::Delivered => false,
    };
    let Some(home) = member.recipient_home.clone().filter(|_| retry) else {
        return;
    };
    match contact_for(contacts, &home) {
        Some(contact) => {
            member.recipient_profile_did = Some(contact.profile_did.clone());
            member.recipient_name = Some(contact.name.clone());
            // The pool-wide size rule holds before anything waits again.
            if too_large {
                member.state = NoticeState::Refused;
                member.code = Some(TOO_LARGE.to_string());
            } else {
                member.state = NoticeState::Pending;
                member.code = None;
            }
        }
        None => {
            member.recipient_profile_did = None;
            member.recipient_name = None;
            member.state = NoticeState::Skipped;
            member.code = Some(NOT_CONTACT.to_string());
        }
    }
}

/// The accepted contact whose Home is `home`: its Profile's sole endpoint.
fn contact_for<'a>(contacts: &'a [AcceptedContact], home: &str) -> Option<&'a AcceptedContact> {
    contacts
        .iter()
        .find(|contact| contact.profile.sole_endpoint_did().ok() == Some(home))
}

fn signed_notice(
    outbox: &dyn NoticeOutbox,
    local_profile_did: &str,
    member: &NoticeMemberV1,
    config: &[u8],
    labels: &[(u8, String, String)],
    now: u64,
) -> anyhow::Result<Vec<u8>> {
    let recipient = member
        .recipient_profile_did
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("a told member has no Profile"))?;
    let notice = pool_active_notice(config, labels, member.share)?;
    outbox.sign(
        local_profile_did,
        recipient,
        notice,
        now,
        now.saturating_add(CustodyMessageType::PoolActive.max_lifetime_secs()),
    )
}

/// A failure no retry fixes settles the member once, as the outbox would;
/// any other waits for the next pass.
fn settle_failure(member: &mut NoticeMemberV1, error: &anyhow::Error) {
    match terminal_state_for(error) {
        // This Home's own Profile lacks the notice scope. That is no refusal
        // by the member: once the owner grants the scope, a later pass sends
        // the notice (T33-F1).
        _ if lacks_local_signing_scope(error) => {
            tracing::debug!("a custody pool notice waits for this Home's custody signing scope")
        }
        Some(CustodyOutboxState::Refused(code)) => refuse(member, code),
        Some(CustodyOutboxState::Expired) => refuse(member, "expired".to_string()),
        _ => tracing::debug!(
            error = %format!("{error:#}"),
            "a custody pool notice waits for the next pass"
        ),
    }
}

fn refuse(member: &mut NoticeMemberV1, code: String) {
    tracing::debug!(%code, share = member.share, "a pool member refused its notice");
    member.state = NoticeState::Refused;
    member.code = Some(code);
}

/// A member's outbox key, scoped to the pool, so a later pool never reads an
/// earlier one's delivery.
fn notice_key(fingerprint_full: &str, member: &NoticeMemberV1) -> Option<String> {
    let pool = fingerprint_full
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint_full);
    member.recipient_home.as_deref().map(|home| {
        format!(
            "{NOTICE_OUTBOX_PREFIX}{}:{home}",
            pool.get(..16).unwrap_or(pool)
        )
    })
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn lock() -> anyhow::Result<std::sync::MutexGuard<'static, ()>> {
    NOTICES_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("custody pool notice lock is poisoned"))
}

fn notices_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(NOTICES_FILE)
}

fn load_set(data_dir: &Path) -> anyhow::Result<Option<PoolNoticesFileV1>> {
    let path = notices_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(&path, MAX_NOTICES_FILE_BYTES, "custody pool notices")?;
    let set: PoolNoticesFileV1 = serde_json::from_slice(&bytes)?;
    if set.schema != NOTICES_SCHEMA_V1 {
        anyhow::bail!("custody pool notices have an unknown schema");
    }
    Ok(Some(set))
}

fn store_set(data_dir: &Path, set: &PoolNoticesFileV1) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(set)?;
    if bytes.len() > MAX_NOTICES_FILE_BYTES {
        anyhow::bail!("custody pool notices exceed their byte limit");
    }
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    write_owner_only_bytes(&notices_path(data_dir), &bytes)
}

fn present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(anyhow::Error::new(error).context("custody pool notices file is unavailable"))
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
