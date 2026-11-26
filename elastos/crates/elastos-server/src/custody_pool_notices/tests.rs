use super::*;
use std::collections::BTreeMap;

use crate::collaboration_network::VerifiedCollaborationNetworkProfile;
use crate::collaboration_profile_authority::{
    signed_profile_document_for_test, with_signing_scope_for_test,
};
use crate::custody_consent::lock_custody_writes;
use crate::custody_consent_protocol::{prepare_custody_message, verify_custody_message};
use crate::custody_consent_protocol::{CustodyMessageRefusal, CUSTODY_SIGNING_SCOPE};
use crate::custody_node_card::tests::{card_for_device, carrier_descriptor_bytes};
use crate::custody_owner_requests::tests::Party;
use crate::custody_pool_setup::CardInput;
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::protected_content_config::{
    signed_custody_composition_config_at, validated_custody_node_descriptor,
};
use elastos_protected_content_contracts::ThresholdV1;
use elastos_runtime::signature::{generate_keypair, SigningKey};

const STORAGE: &[&str] = &["chain", "custody", "ipfs"];

/// Stands in for the message service: a "signed" notice is its payload's
/// JSON, and each attempt ends in the state the test chose.
#[derive(Default)]
struct FakeOutbox {
    queued: Mutex<Vec<(String, String, Vec<u8>)>>,
    states: Mutex<BTreeMap<String, CustodyOutboxState>>,
    forgotten: Mutex<Vec<String>>,
    /// What an immediate attempt ends in; pending when unset.
    answer: Mutex<Option<CustodyOutboxState>>,
    /// Plan B T3.3: signs pool descriptors, as an admin with the full scope.
    signs_descriptors: bool,
    /// T33-F1: signs notices and descriptors for real, with this Home's
    /// Profile.
    signer: Mutex<Option<RealSigner>>,
}

/// This Home's signing key, network and current Profile.
struct RealSigner {
    device: SigningKey,
    network: VerifiedCollaborationNetworkProfile,
    profile: VerifiedCollaborationProfileDocument,
}

impl FakeOutbox {
    fn queued(&self) -> Vec<(String, String, Vec<u8>)> {
        self.queued.lock().unwrap().clone()
    }

    fn settle(&self, key: &str, state: CustodyOutboxState) {
        self.states.lock().unwrap().insert(key.to_string(), state);
    }

    fn notices(&self) -> Vec<(String, CustodyPoolActivePayload)> {
        self.queued()
            .into_iter()
            .map(|(key, _, envelope)| {
                let signed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
                (
                    key,
                    serde_json::from_value(signed["notice"].clone()).unwrap(),
                )
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl NoticeOutbox for FakeOutbox {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        notice: CustodyPoolActivePayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        assert_eq!(
            expires_at,
            now + CustodyMessageType::PoolActive.max_lifetime_secs()
        );
        if let Some(signer) = self.signer.lock().unwrap().as_ref() {
            return prepare_custody_message(
                &signer.device,
                &signer.network,
                &signer.profile,
                recipient_profile_did,
                &CustodyPayload::PoolActive(notice),
                now,
                expires_at,
            );
        }
        Ok(serde_json::to_vec(&serde_json::json!({
            "from": local_profile_did,
            "to": recipient_profile_did,
            "notice": notice,
        }))?)
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        _now: u64,
    ) -> anyhow::Result<()> {
        self.queued.lock().unwrap().push((
            key.to_string(),
            local_profile_did.to_string(),
            envelope,
        ));
        self.settle(key, CustodyOutboxState::Pending);
        Ok(())
    }

    fn state(&self, key: &str, _now: u64) -> Option<CustodyOutboxState> {
        self.states.lock().unwrap().get(key).cloned()
    }

    fn sign_descriptor(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        descriptor: CustodyPoolDescriptorPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if let Some(signer) = self.signer.lock().unwrap().as_ref() {
            return prepare_custody_message(
                &signer.device,
                &signer.network,
                &signer.profile,
                recipient_profile_did,
                &CustodyPayload::PoolDescriptor(descriptor),
                now,
                expires_at,
            );
        }
        anyhow::ensure!(
            self.signs_descriptors,
            "the descriptor type is not in scope"
        );
        assert_eq!(
            expires_at,
            now + CustodyMessageType::PoolDescriptor.max_lifetime_secs()
        );
        Ok(serde_json::to_vec(&serde_json::json!({
            "from": local_profile_did,
            "to": recipient_profile_did,
            "descriptor": descriptor,
        }))?)
    }

    fn forget(&self, key: &str) {
        self.states.lock().unwrap().remove(key);
        self.forgotten.lock().unwrap().push(key.to_string());
    }

    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        NoticeOutbox::enqueue(self, key, local_profile_did, envelope, now)?;
        let state = self
            .answer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(CustodyOutboxState::Pending);
        self.settle(key, state.clone());
        Ok(state)
    }
}

/// An owner Home with an installed pool: this Home's own node when
/// `include_this_home`, and remote nodes, of which Bob and Dave are the
/// admin's contacts. The epoch numbers shares in node key order, so tests
/// name members, not shares.
struct Owner {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    admin: Party,
    nodes: Vec<Party>,
    contacts: Vec<AcceptedContact>,
}

const NODE_LABELS: [(&str, &str); 3] = [("Bob", "Oslo"), ("Carol", "Kyiv"), ("Dave", "Rome")];

async fn owner(include_this_home: bool) -> Owner {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    let (home, _) = elastos_identity::load_or_create_did(&data_dir).unwrap();
    crate::custody_pool_setup::create_signing_key(&data_dir).unwrap();
    let remote = if include_this_home { 2 } else { 3 };
    let nodes: Vec<Party> = NODE_LABELS[..remote]
        .iter()
        .map(|(name, _)| Party::new(name, true))
        .collect();
    let mut cards = Vec::new();
    if include_this_home {
        crate::custody_pool_setup::tests::write_included_node(&data_dir, "Home", "Paris");
        cards.push(CardInput::ThisHome);
    }
    for (node, (_, location)) in nodes.iter().zip(NODE_LABELS) {
        cards.push(CardInput::Remote {
            text: card_for_device(&node.device.verifying_key(), node.name, location, STORAGE),
        });
    }
    crate::custody_pool_setup::install(&data_dir, &cards, 365)
        .await
        .unwrap();
    // Carol is nobody's contact.
    let contacts = nodes
        .iter()
        .filter(|node| node.name != "Carol")
        .map(Party::contact)
        .collect();
    Owner {
        _dir: dir,
        admin: Party::on("Olivia", home, true),
        data_dir,
        nodes,
        contacts,
    }
}

impl Owner {
    fn node(&self, name: &str) -> &Party {
        self.nodes.iter().find(|node| node.name == name).unwrap()
    }

    /// The outbox key of `name`'s notice about the installed pool.
    fn key(&self, name: &str) -> String {
        let fingerprint = self.fingerprint_full();
        let digest = fingerprint.strip_prefix("sha256:").unwrap();
        format!(
            "custody-pool-active:{}:{}",
            &digest[..16],
            self.node(name).did()
        )
    }

    fn record(&self) -> PoolNoticesView {
        record_install(&self.data_dir, &self.admin.profile, &self.contacts).unwrap()
    }

    fn view(&self) -> PoolNoticesView {
        pool_notices_view(&self.data_dir, &self.fingerprint_full())
            .unwrap()
            .unwrap()
    }

    fn fingerprint_full(&self) -> String {
        sha256_label(&self.config())
    }

    fn config(&self) -> Vec<u8> {
        std::fs::read(runtime_custody_composition_config_path(&self.data_dir)).unwrap()
    }

    /// Who holds `share`: "Home" for this Home's own node, else a node name.
    fn who(&self, share: u8) -> String {
        let pool = crate::custody_pool_setup::read_pool(&self.data_dir)
            .unwrap()
            .unwrap();
        let member = pool
            .members
            .iter()
            .find(|member| member.share == share)
            .unwrap();
        if member.this_home {
            return "Home".to_string();
        }
        let home = member.home_id.as_deref().unwrap();
        self.nodes
            .iter()
            .find(|node| node.did() == home)
            .unwrap()
            .name
            .to_string()
    }

    fn share_of(&self, who: &str) -> u8 {
        (1..=3).find(|share| self.who(*share) == who).unwrap()
    }

    fn states(&self) -> BTreeMap<String, (NoticeState, Option<String>)> {
        self.view()
            .members
            .into_iter()
            .map(|member| (self.who(member.share), (member.state, member.code)))
            .collect()
    }

    /// Changes `who`'s member in the stored set.
    fn set_member(&self, who: &str, state: NoticeState, code: Option<String>) {
        let share = self.share_of(who);
        let mut set = load_set(&self.data_dir).unwrap().unwrap();
        let member = set
            .members
            .iter_mut()
            .find(|member| member.share == share)
            .unwrap();
        member.state = state;
        member.code = code;
        store_set(&self.data_dir, &set).unwrap();
    }

    async fn notify(&self, outbox: &FakeOutbox) -> anyhow::Result<PoolNoticesView> {
        notify_members(
            lock_custody_writes().await,
            &NoticeHost {
                data_dir: &self.data_dir,
                outbox,
                profile: &self.admin.profile,
                contacts: &self.contacts,
            },
            crate::auth::now_ts(),
        )
        .await
    }
}

fn code(value: &str) -> Option<String> {
    Some(value.to_string())
}

fn states(
    entries: &[(&str, NoticeState, Option<String>)],
) -> BTreeMap<String, (NoticeState, Option<String>)> {
    entries
        .iter()
        .map(|(who, state, code)| (who.to_string(), (*state, code.clone())))
        .collect()
}

#[tokio::test]
async fn an_install_records_who_is_told_and_who_cannot_be() {
    let owner = owner(true).await;
    let recorded = owner.record();
    assert_eq!(recorded.fingerprint_full, owner.fingerprint_full());
    assert_eq!(recorded, owner.view());
    let mut expected = vec![
        (
            owner.share_of("Home"),
            serde_json::json!({ "share": owner.share_of("Home"), "state": "skipped", "code": "this_home" }),
        ),
        (
            owner.share_of("Bob"),
            serde_json::json!({ "share": owner.share_of("Bob"), "recipient_name": "Bob", "state": "pending" }),
        ),
        (
            owner.share_of("Carol"),
            serde_json::json!({ "share": owner.share_of("Carol"), "state": "skipped", "code": "not_contact" }),
        ),
    ];
    expected.sort_by_key(|(share, _)| *share);
    let expected: Vec<serde_json::Value> = expected.into_iter().map(|(_, member)| member).collect();
    assert_eq!(
        serde_json::to_value(&recorded).unwrap()["members"],
        serde_json::Value::Array(expected)
    );
    // Only the set for the installed pool is shown.
    assert!(
        pool_notices_view(&owner.data_dir, &sha256_label(b"another pool"))
            .unwrap()
            .is_none()
    );
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(notices_path(&owner.data_dir))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn each_pass_builds_the_notice_again_for_a_member_still_waiting() {
    let owner = owner(true).await;
    owner.record();
    let now = crate::auth::now_ts();

    // After a restart the outbox is empty: only the contact that waits is
    // told, with the exact installed composition.
    let restarted = FakeOutbox::default();
    resume_notices(&owner.data_dir, &restarted, now).unwrap();
    let notices = restarted.notices();
    assert_eq!(notices.len(), 1);
    let (key, notice) = &notices[0];
    assert_eq!(key, &owner.key("Bob"));
    let config = owner.config();
    let facts = signed_composition_facts(&config).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&notice.config)
            .unwrap(),
        config
    );
    assert_eq!(notice.fingerprint_full, owner.fingerprint_full());
    assert_eq!(notice.share, owner.share_of("Bob"));
    assert_eq!(
        (notice.pool_start, notice.term_end),
        (facts.start, facts.end)
    );
    assert_eq!(
        (notice.threshold.required, notice.threshold.total),
        (facts.threshold.required(), facts.threshold.total())
    );
    let labels: Vec<(u8, &str, &str)> = notice
        .members
        .iter()
        .map(|member| {
            (
                member.share,
                member.run_by.as_str(),
                member.location.as_str(),
            )
        })
        .collect();
    let mut expected = vec![
        (owner.share_of("Home"), "Home", "Paris"),
        (owner.share_of("Bob"), "Bob", "Oslo"),
        (owner.share_of("Carol"), "Carol", "Kyiv"),
    ];
    expected.sort();
    assert_eq!(labels, expected);
    let signed: serde_json::Value = serde_json::from_slice(&restarted.queued()[0].2).unwrap();
    assert_eq!(signed["from"], owner.admin.profile_did());
    assert_eq!(signed["to"], owner.node("Bob").profile_did());

    // Queued, it is left alone; an expired envelope gets a fresh one.
    resume_notices(&owner.data_dir, &restarted, now + 10).unwrap();
    assert_eq!(restarted.queued().len(), 1);
    restarted.settle(&owner.key("Bob"), CustodyOutboxState::Expired);
    resume_notices(&owner.data_dir, &restarted, now + 20).unwrap();
    assert_eq!(restarted.queued().len(), 2);
    assert_eq!(owner.states()["Bob"], (NoticeState::Pending, None));
}

#[tokio::test]
async fn a_told_member_is_not_told_again_and_a_refusal_settles_once() {
    let owner = owner(false).await;
    owner.record();
    let now = crate::auth::now_ts();
    let outbox = FakeOutbox::default();
    resume_notices(&owner.data_dir, &outbox, now).unwrap();
    assert_eq!(outbox.queued().len(), 2);
    outbox.settle(&owner.key("Bob"), CustodyOutboxState::Delivered);
    outbox.settle(
        &owner.key("Dave"),
        CustodyOutboxState::Refused("not_member".to_string()),
    );
    resume_notices(&owner.data_dir, &outbox, now + 10).unwrap();
    assert_eq!(
        owner.states(),
        states(&[
            ("Bob", NoticeState::Delivered, None),
            ("Carol", NoticeState::Skipped, code("not_contact")),
            ("Dave", NoticeState::Refused, code("not_member")),
        ])
    );
    // Nobody waits: a restarted outbox sends nothing.
    let restarted = FakeOutbox::default();
    resume_notices(&owner.data_dir, &restarted, now + 20).unwrap();
    assert!(restarted.queued().is_empty());
}

#[tokio::test]
async fn a_pool_the_set_is_not_for_settles_its_waiting_members_once() {
    let unavailable = || {
        states(&[
            ("Bob", NoticeState::Refused, code("pool_unavailable")),
            ("Carol", NoticeState::Skipped, code("not_contact")),
            ("Dave", NoticeState::Refused, code("pool_unavailable")),
        ])
    };
    // The installed pool is another one than the set is for.
    let mismatched = owner(false).await;
    mismatched.record();
    let expected = unavailable();
    let mut set = load_set(&mismatched.data_dir).unwrap().unwrap();
    set.fingerprint_full = sha256_label(b"an older pool");
    store_set(&mismatched.data_dir, &set).unwrap();
    let outbox = FakeOutbox::default();
    resume_notices(&mismatched.data_dir, &outbox, crate::auth::now_ts()).unwrap();
    assert!(outbox.queued().is_empty());
    let settled = load_set(&mismatched.data_dir).unwrap().unwrap();
    let states: Vec<_> = settled
        .members
        .iter()
        .map(|member| {
            (
                mismatched.who(member.share),
                (member.state, member.code.clone()),
            )
        })
        .collect();
    assert_eq!(states.into_iter().collect::<BTreeMap<_, _>>(), expected);

    // The installed pool is gone or unreadable.
    let gone = owner(false).await;
    gone.record();
    let expected = unavailable();
    let names: BTreeMap<u8, String> = (1..=3).map(|share| (share, gone.who(share))).collect();
    std::fs::remove_file(runtime_custody_composition_config_path(&gone.data_dir)).unwrap();
    let outbox = FakeOutbox::default();
    resume_notices(&gone.data_dir, &outbox, crate::auth::now_ts()).unwrap();
    resume_notices(&gone.data_dir, &outbox, crate::auth::now_ts()).unwrap();
    assert!(outbox.queued().is_empty());
    let settled: BTreeMap<_, _> = load_set(&gone.data_dir)
        .unwrap()
        .unwrap()
        .members
        .into_iter()
        .map(|member| (names[&member.share].clone(), (member.state, member.code)))
        .collect();
    assert_eq!(settled, expected);
}

#[tokio::test]
async fn a_later_pool_never_inherits_what_the_outbox_saw_for_an_earlier_one() {
    let owner = owner(false).await;
    owner.record();
    let first_key = owner.key("Bob");
    let outbox = FakeOutbox::default();
    outbox.settle(&first_key, CustodyOutboxState::Delivered);
    // The same nodes in a new pool.
    std::fs::remove_file(runtime_custody_composition_config_path(&owner.data_dir)).unwrap();
    let cards: Vec<CardInput> = owner
        .nodes
        .iter()
        .zip(NODE_LABELS)
        .map(|(node, (_, location))| CardInput::Remote {
            text: card_for_device(&node.device.verifying_key(), node.name, location, STORAGE),
        })
        .collect();
    crate::custody_pool_setup::install(&owner.data_dir, &cards, 365)
        .await
        .unwrap();
    owner.record();
    assert_ne!(owner.key("Bob"), first_key);
    resume_notices(&owner.data_dir, &outbox, crate::auth::now_ts()).unwrap();
    assert_eq!(owner.states()["Bob"], (NoticeState::Pending, None));
    assert!(outbox
        .queued()
        .iter()
        .any(|(key, _, _)| key == &owner.key("Bob")));
}

#[tokio::test]
async fn notify_again_tells_waiting_and_refused_members_now() {
    let owner = owner(false).await;
    owner.record();
    owner.set_member("Bob", NoticeState::Refused, code("not_served_owner"));
    let outbox = FakeOutbox::default();
    outbox.settle(
        &owner.key("Bob"),
        CustodyOutboxState::Refused("x".to_string()),
    );
    *outbox.answer.lock().unwrap() = Some(CustodyOutboxState::Delivered);

    let view = owner.notify(&outbox).await.unwrap();
    assert_eq!(view, owner.view());
    assert_eq!(
        owner.states(),
        states(&[
            ("Bob", NoticeState::Delivered, None),
            ("Carol", NoticeState::Skipped, code("not_contact")),
            ("Dave", NoticeState::Delivered, None),
        ])
    );
    let mut forgotten = outbox.forgotten.lock().unwrap().clone();
    forgotten.sort();
    let mut expected = vec![owner.key("Bob"), owner.key("Dave")];
    expected.sort();
    assert_eq!(forgotten, expected);
    assert_eq!(outbox.queued().len(), 2);

    // A composition too large to send is not tried again.
    owner.set_member("Bob", NoticeState::Refused, code("too_large"));
    let outbox = FakeOutbox::default();
    owner.notify(&outbox).await.unwrap();
    assert!(outbox.queued().is_empty());
    assert_eq!(
        owner.states()["Bob"],
        (NoticeState::Refused, code("too_large"))
    );
}

#[tokio::test]
async fn notify_again_makes_a_set_when_none_was_recorded() {
    let owner = owner(false).await;
    let outbox = FakeOutbox::default();
    let view = owner.notify(&outbox).await.unwrap();
    assert_eq!(view.fingerprint_full, owner.fingerprint_full());
    assert_eq!(
        owner.states(),
        states(&[
            ("Bob", NoticeState::Pending, None),
            ("Carol", NoticeState::Skipped, code("not_contact")),
            ("Dave", NoticeState::Pending, None),
        ])
    );
    assert_eq!(outbox.queued().len(), 2);
}

#[tokio::test]
async fn notify_again_finds_members_that_became_contacts() {
    let owner = owner(false).await;
    // Recorded while the message plane was down: nobody could be matched.
    record_install(&owner.data_dir, &owner.admin.profile, &[]).unwrap();
    assert_eq!(
        owner.states(),
        states(&[
            ("Bob", NoticeState::Skipped, code("not_contact")),
            ("Carol", NoticeState::Skipped, code("not_contact")),
            ("Dave", NoticeState::Skipped, code("not_contact")),
        ])
    );
    let outbox = FakeOutbox::default();
    *outbox.answer.lock().unwrap() = Some(CustodyOutboxState::Delivered);
    owner.notify(&outbox).await.unwrap();
    assert_eq!(
        owner.states(),
        states(&[
            ("Bob", NoticeState::Delivered, None),
            ("Carol", NoticeState::Skipped, code("not_contact")),
            ("Dave", NoticeState::Delivered, None),
        ])
    );
    let view = owner.view();
    let named: Vec<_> = view
        .members
        .iter()
        .filter_map(|member| member.recipient_name.clone())
        .collect();
    assert_eq!(named.len(), 2);
    let sent: Vec<String> = outbox
        .queued()
        .into_iter()
        .map(|(_, _, envelope)| {
            let signed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
            signed["to"].as_str().unwrap().to_string()
        })
        .collect();
    assert!(sent.contains(&owner.node("Bob").profile_did().to_string()));
    assert!(sent.contains(&owner.node("Dave").profile_did().to_string()));
}

/// A pool installed from the terminal: no Run by or Location was kept for
/// its members.
async fn terminal_owner() -> Owner {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    let (home, _) = elastos_identity::load_or_create_did(&data_dir).unwrap();
    crate::custody_pool_setup::create_signing_key(&data_dir).unwrap();
    let nodes: Vec<Party> = NODE_LABELS
        .iter()
        .map(|(name, _)| Party::new(name, true))
        .collect();
    let descriptors = nodes
        .iter()
        .zip(NODE_LABELS)
        .map(|(node, (name, location))| {
            let bytes = carrier_descriptor_bytes(&node.device.verifying_key(), name, location);
            validated_custody_node_descriptor(&bytes, "terminal node").unwrap()
        })
        .collect();
    crate::protected_content_config::install_custody_composition(
        &data_dir,
        &crate::custody_pool_setup::policy_authority_key_path(&data_dir),
        descriptors,
        365,
    )
    .unwrap();
    let contacts = nodes.iter().map(Party::contact).collect();
    Owner {
        _dir: dir,
        admin: Party::on("Olivia", home, true),
        data_dir,
        nodes,
        contacts,
    }
}

#[tokio::test]
async fn a_pool_without_kept_labels_settles_its_members_once() {
    let owner = terminal_owner().await;
    owner.record();
    let outbox = FakeOutbox::default();
    resume_notices(&owner.data_dir, &outbox, crate::auth::now_ts()).unwrap();
    assert!(outbox.queued().is_empty());
    let missing = states(&[
        ("Bob", NoticeState::Refused, code("missing_labels")),
        ("Carol", NoticeState::Refused, code("missing_labels")),
        ("Dave", NoticeState::Refused, code("missing_labels")),
    ]);
    assert_eq!(owner.states(), missing);
    // Notify again cannot build them either.
    owner.notify(&outbox).await.unwrap();
    assert!(outbox.queued().is_empty());
    assert_eq!(owner.states(), missing);
}

#[tokio::test]
async fn notify_without_a_pool_is_no_pool() {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    let admin = Party::new("Olivia", true);
    let outbox = FakeOutbox::default();
    let error = notify_members(
        lock_custody_writes().await,
        &NoticeHost {
            data_dir: &data_dir,
            outbox: &outbox,
            profile: &admin.profile,
            contacts: &[],
        },
        crate::auth::now_ts(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<CustodyRefusal>().unwrap().code(),
        "no_pool"
    );
    assert!(record_install(&data_dir, &admin.profile, &[]).is_err());
}

#[test]
fn a_composition_too_large_to_send_is_refused_for_every_member_told() {
    let bob = Party::new("Bob", true);
    let admin = Party::new("Olivia", true);
    let member = |share: u8, home_id: Option<String>, this_home: bool| PoolMemberView {
        share,
        run_by: Some(format!("Node {share}")),
        location: Some(format!("Place {share}")),
        home_id,
        provides: Vec::new(),
        this_home,
        registered: true,
    };
    let pool = InstalledPool {
        config: vec![b'x'; MAX_POOL_ACTIVE_CONFIG_BYTES + 1],
        fingerprint_full: sha256_label(b"large"),
        members: vec![
            member(1, None, true),
            member(2, Some(bob.did()), false),
            member(3, Some(Party::new("Carol", true).did()), false),
        ],
    };
    let set = notice_set(&pool, &admin.profile, &[bob.contact()]);
    let states: Vec<(NoticeState, Option<&str>)> = set
        .members
        .iter()
        .map(|member| (member.state, member.code.as_deref()))
        .collect();
    assert_eq!(
        states,
        [
            (NoticeState::Skipped, Some("this_home")),
            (NoticeState::Refused, Some("too_large")),
            (NoticeState::Skipped, Some("not_contact")),
        ]
    );
}

/// The installed composition's bytes for `members` nodes under
/// `threshold`, as install writes them.
fn composition_bytes(
    members: usize,
    threshold: ThresholdV1,
    label: impl Fn(&str, usize) -> String,
) -> Vec<u8> {
    let (authority, _) = generate_keypair();
    let descriptors = (1..=members)
        .map(|index| {
            let (device, _) = generate_keypair();
            let bytes = carrier_descriptor_bytes(
                &device.verifying_key(),
                &label("Node", index),
                &label("Place", index),
            );
            validated_custody_node_descriptor(&bytes, "measured node").unwrap()
        })
        .collect();
    let config = signed_custody_composition_config_at(
        &authority,
        descriptors,
        730,
        threshold,
        crate::auth::now_ts(),
    )
    .unwrap();
    serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap()
}

/// The longest label a node may have (`MAX_CUSTODY_NODE_LABEL_BYTES`).
fn longest_label(kind: &str, index: usize) -> String {
    let label = format!("{kind} {index:02} ");
    format!("{label}{}", "x".repeat(64 - label.len()))
}

fn short_label(kind: &str, index: usize) -> String {
    format!("{kind} {index:02}")
}

/// Measured sizes: a notice carries the whole composition, which grows with
/// each member. The composition holds labels only as fixed-size ids, so its
/// size does not change with them; the labels travel beside it. Both a
/// Runtime pool and a large one fit a signed notice, with the longest labels.
#[test]
fn compositions_of_three_and_nine_members_fit_a_notice() {
    let (trusted, _) = generate_keypair();
    let network = crate::collaboration_discovery_runtime::tests::signed_profile(
        crate::custody_owner_requests::tests::NETWORK,
        &trusted,
        vec![],
    );
    let owner = Party::new("Olivia", true);
    let node = Party::new("Bob", true);
    let now = crate::auth::now_ts();
    for (members, required, measured) in [(3usize, 2u8, 14_583usize), (9, 5, 40_117)] {
        let threshold = ThresholdV1::new(required, members as u8).unwrap();
        let short = composition_bytes(members, threshold, short_label);
        let config = composition_bytes(members, threshold, longest_label);
        assert_eq!(short.len(), measured, "{members} members");
        assert_eq!(config.len(), measured, "{members} members, longest labels");
        assert!(config.len() <= MAX_POOL_ACTIVE_CONFIG_BYTES);
        let labels: Vec<(u8, String, String)> = (1..=members as u8)
            .map(|share| {
                let index = usize::from(share);
                (
                    share,
                    longest_label("Node", index),
                    longest_label("Place", index),
                )
            })
            .collect();
        assert!(labels
            .iter()
            .all(|(_, run_by, location)| run_by.len() == 64 && location.len() == 64));
        let notice = pool_active_notice(&config, &labels, 1).unwrap();
        assert_eq!(notice.threshold.total as usize, members);
        let envelope = prepare_custody_message(
            &owner.device,
            &network,
            &owner.profile,
            node.profile_did(),
            &CustodyPayload::PoolActive(notice),
            now,
            now + 60,
        )
        .unwrap();
        verify_custody_message(
            &envelope,
            &network,
            &owner.profile,
            Some(&node.profile),
            CustodyMessageType::PoolActive,
            now,
        )
        .unwrap();
    }
}

#[test]
fn notify_again_keeps_a_pool_too_large_to_send_from_waiting_again() {
    let bob = Party::new("Bob", true);
    let member = |state: NoticeState, code: Option<&str>| NoticeMemberV1 {
        share: 2,
        recipient_home: Some(bob.did()),
        recipient_profile_did: None,
        recipient_name: None,
        state,
        code: code.map(str::to_string),
        descriptor: None,
    };
    for start in [
        member(NoticeState::Skipped, Some("not_contact")),
        member(NoticeState::Pending, None),
        member(NoticeState::Refused, Some("not_member")),
    ] {
        let mut renewed = start.clone();
        renew(&mut renewed, &[bob.contact()], true);
        assert_eq!(
            (renewed.state, renewed.code.as_deref()),
            (NoticeState::Refused, Some("too_large")),
            "{start:?}"
        );
        assert_eq!(renewed.recipient_name.as_deref(), Some("Bob"));
    }
    let mut this_home = NoticeMemberV1 {
        recipient_home: None,
        ..member(NoticeState::Skipped, Some("this_home"))
    };
    renew(&mut this_home, &[bob.contact()], true);
    assert_eq!(this_home.code.as_deref(), Some("this_home"));
}

/// Plan B T3.3 (X5, L13): the descriptor follows an acknowledged notice, and
/// waits while the owner cannot sign it yet.
#[tokio::test]
async fn a_descriptor_follows_an_acknowledged_pool_notice() {
    let owner = owner(false).await;
    owner.record();
    let now = crate::auth::now_ts();
    // Without the descriptor scope, nothing but notices is queued.
    let without_scope = FakeOutbox::default();
    resume_notices(&owner.data_dir, &without_scope, now).unwrap();
    without_scope.settle(&owner.key("Bob"), CustodyOutboxState::Delivered);
    resume_notices(&owner.data_dir, &without_scope, now + 10).unwrap();
    assert!(without_scope
        .queued()
        .iter()
        .all(|(key, _, _)| key.starts_with("custody-pool-active:")));

    let outbox = FakeOutbox {
        signs_descriptors: true,
        ..FakeOutbox::default()
    };
    outbox.settle(&owner.key("Bob"), CustodyOutboxState::Delivered);
    resume_notices(&owner.data_dir, &outbox, now + 20).unwrap();
    let descriptors = outbox
        .queued()
        .into_iter()
        .filter(|(key, _, _)| key.starts_with("custody-pool-descriptor:"))
        .collect::<Vec<_>>();
    // Only Bob acknowledged his notice; Dave still waits for his.
    assert_eq!(descriptors.len(), 1);
    let (key, _, envelope) = &descriptors[0];
    assert!(key.ends_with(&format!(":1:{}", owner.node("Bob").did())));
    let signed: serde_json::Value = serde_json::from_slice(envelope).unwrap();
    assert_eq!(signed["to"], owner.node("Bob").profile_did());
    let payload: CustodyPoolDescriptorPayload =
        serde_json::from_value(signed["descriptor"].clone()).unwrap();
    assert_eq!(payload.signed_descriptor().unwrap().sequence(), 1);

    // Delivered once: the next pass sends nothing more for this sequence.
    outbox.settle(key, CustodyOutboxState::Delivered);
    resume_notices(&owner.data_dir, &outbox, now + 30).unwrap();
    assert_eq!(
        outbox
            .queued()
            .iter()
            .filter(|(queued, _, _)| queued.starts_with("custody-pool-descriptor:"))
            .count(),
        1
    );
}

/// T33-F1: this Home's own Profile without the custody scope is no refusal
/// by the member. The typed refusal leaves the sequence waiting in the kept
/// state, and once the owner grants the scope a later pass queues the same
/// sequence.
#[tokio::test]
async fn a_descriptor_waits_for_this_homes_signing_scope() {
    let owner = owner(false).await;
    owner.record();
    let now = crate::auth::now_ts();
    let (trusted, _) = generate_keypair();
    let network = crate::collaboration_discovery_runtime::tests::signed_profile(
        crate::custody_owner_requests::tests::NETWORK,
        &trusted,
        vec![],
    );
    let (profile_key, _) = generate_keypair();
    let (device, _) = generate_keypair();
    let unscoped = signed_profile_document_for_test(
        &profile_key,
        "Olivia",
        None,
        1,
        None,
        now - 100,
        vec![crate::crypto::encode_signing_key_did(&device)],
    )
    .unwrap();
    // This Home's Profile holds the custody scope of a build before the
    // descriptor type: it signs notices, not descriptors.
    let notice_types: Vec<&str> = CUSTODY_SIGNING_SCOPE
        .1
        .iter()
        .copied()
        .filter(|kind| {
            *kind != crate::custody_consent_protocol::CUSTODY_POOL_DESCRIPTOR_PAYLOAD_TYPE
        })
        .collect();
    let without_descriptor = with_signing_scope_for_test(
        &profile_key,
        &unscoped,
        (CUSTODY_SIGNING_SCOPE.0, &notice_types),
    )
    .unwrap();
    let signer = |profile| RealSigner {
        device: device.clone(),
        network: network.clone(),
        profile,
    };
    let descriptors = |outbox: &FakeOutbox| {
        outbox
            .queued()
            .into_iter()
            .filter(|(key, _, _)| key.starts_with("custody-pool-descriptor:"))
            .collect::<Vec<_>>()
    };
    let bob = owner.node("Bob");

    // The notices go out, and Bob acknowledges his.
    let outbox = FakeOutbox {
        signer: Mutex::new(Some(signer(without_descriptor))),
        ..FakeOutbox::default()
    };
    resume_notices(&owner.data_dir, &outbox, now).unwrap();
    outbox.settle(&owner.key("Bob"), CustodyOutboxState::Delivered);

    // The real signer refuses with the typed refusal for this Home's Profile.
    let descriptor = crate::custody_pool_descriptor::owner_descriptor(&owner.data_dir, now)
        .unwrap()
        .unwrap();
    let error = outbox
        .sign_descriptor(
            owner.admin.profile_did(),
            bob.profile_did(),
            CustodyPoolDescriptorPayload::new(&descriptor).unwrap(),
            now,
            now + CustodyMessageType::PoolDescriptor.max_lifetime_secs(),
        )
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<CustodyMessageRefusal>(),
        Some(&CustodyMessageRefusal::SignerNotAuthorized)
    );

    // The pass sends nothing and keeps no settled state for the sequence.
    resume_notices(&owner.data_dir, &outbox, now + 10).unwrap();
    assert!(descriptors(&outbox).is_empty());
    let kept = load_set(&owner.data_dir).unwrap().unwrap();
    assert!(kept.members.iter().all(|member| member
        .descriptor
        .as_ref()
        .is_none_or(|sent| sent.state == NoticeState::Pending)));

    // The owner grants the scope. A later pass, reloading the kept state
    // with a fresh outbox, queues the same sequence for Bob.
    let scoped =
        with_signing_scope_for_test(&profile_key, &unscoped, CUSTODY_SIGNING_SCOPE).unwrap();
    let outbox = FakeOutbox {
        signer: Mutex::new(Some(signer(scoped.clone()))),
        ..FakeOutbox::default()
    };
    outbox.settle(&owner.key("Bob"), CustodyOutboxState::Delivered);
    resume_notices(&owner.data_dir, &outbox, now + 20).unwrap();
    let queued = descriptors(&outbox);
    assert_eq!(queued.len(), 1);
    let (key, _, envelope) = &queued[0];
    assert!(key.ends_with(&format!(
        ":{}:{}",
        descriptor.statement().sequence(),
        bob.did()
    )));
    verify_custody_message(
        envelope,
        &network,
        &scoped,
        Some(&bob.profile),
        CustodyMessageType::PoolDescriptor,
        now + 20,
    )
    .unwrap();
    let kept = load_set(&owner.data_dir).unwrap().unwrap();
    assert!(kept.members.iter().any(|member| member.descriptor.as_ref()
        == Some(&DescriptorDeliveryV1 {
            sequence: descriptor.statement().sequence(),
            state: NoticeState::Pending,
            code: None,
        })));
}

/// T33-F1, the pool notice: this Home's own Profile without the custody scope
/// is no refusal by the member. The typed refusal leaves the notice waiting
/// in the kept state, and once the owner grants the scope a later pass sends
/// it.
#[tokio::test]
async fn a_notice_waits_for_this_homes_signing_scope() {
    let owner = owner(false).await;
    owner.record();
    let now = crate::auth::now_ts();
    let (trusted, _) = generate_keypair();
    let network = crate::collaboration_discovery_runtime::tests::signed_profile(
        crate::custody_owner_requests::tests::NETWORK,
        &trusted,
        vec![],
    );
    let (profile_key, _) = generate_keypair();
    let (device, _) = generate_keypair();
    let unscoped = signed_profile_document_for_test(
        &profile_key,
        "Olivia",
        None,
        1,
        None,
        now - 100,
        vec![crate::crypto::encode_signing_key_did(&device)],
    )
    .unwrap();
    let signer = |profile| RealSigner {
        device: device.clone(),
        network: network.clone(),
        profile,
    };
    let bob = owner.node("Bob");
    let bob_state = || {
        load_set(&owner.data_dir)
            .unwrap()
            .unwrap()
            .members
            .into_iter()
            .find(|member| member.recipient_profile_did.as_deref() == Some(bob.profile_did()))
            .unwrap()
    };

    // The real signer refuses with the typed refusal for this Home's Profile.
    let outbox = FakeOutbox {
        signer: Mutex::new(Some(signer(unscoped.clone()))),
        ..FakeOutbox::default()
    };
    let Rebuild::Ready { config, labels } = rebuild_for(&owner.data_dir, &owner.fingerprint_full())
    else {
        panic!("the installed pool rebuilds its notice");
    };
    let error = signed_notice(
        &outbox,
        owner.admin.profile_did(),
        &bob_state(),
        &config,
        &labels,
        now,
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<CustodyMessageRefusal>(),
        Some(&CustodyMessageRefusal::SignerNotAuthorized)
    );

    // The pass sends nothing, and Bob's notice still waits in the kept state.
    resume_notices(&owner.data_dir, &outbox, now).unwrap();
    assert!(outbox.queued().is_empty());
    let kept = bob_state();
    assert_eq!((kept.state, kept.code), (NoticeState::Pending, None));

    // The owner grants the scope. A later pass, reloading the kept state
    // with a fresh outbox, sends Bob's notice.
    let scoped =
        with_signing_scope_for_test(&profile_key, &unscoped, CUSTODY_SIGNING_SCOPE).unwrap();
    let outbox = FakeOutbox {
        signer: Mutex::new(Some(signer(scoped.clone()))),
        ..FakeOutbox::default()
    };
    resume_notices(&owner.data_dir, &outbox, now + 20).unwrap();
    let queued = outbox.queued();
    let (_, _, envelope) = queued
        .iter()
        .find(|(key, _, _)| *key == owner.key("Bob"))
        .expect("Bob's notice is queued");
    verify_custody_message(
        envelope,
        &network,
        &scoped,
        Some(&bob.profile),
        CustodyMessageType::PoolActive,
        now + 20,
    )
    .unwrap();
    assert_eq!(bob_state().state, NoticeState::Pending);
}
