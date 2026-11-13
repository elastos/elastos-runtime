//! Plan B T3.3: the owner's signed pool descriptor, a member's copy, and the
//! pool address text form.

use super::*;
use std::path::{Path, PathBuf};

use elastos_protected_content_contracts::{
    CustodyEpochIssuerKeyV1, PoolAddressAnyV1, PoolAddressV1, PoolAddressV2,
    PoolDescriptorStatementV1, PoolDescriptorStatementV2, PoolDidV1, PoolEpochBundleV1,
    PoolMemberRouteV1, PoolMemberRouteV2, PoolMemberV1, SignedPoolDescriptorAnyV1,
    SignedPoolDescriptorV1, SignedPoolDescriptorV2, SignedPoolDescriptorV3, ThresholdV1,
};

use crate::custody_consent::{lock_custody_writes, ServedPoolFacts};
use crate::custody_consent_protocol::{CustodyPoolDescriptorPayload, CUSTODY_SIGNING_SCOPE};
use crate::custody_node_card::tests::{card_for_device, carrier_descriptor_bytes};
use crate::custody_node_card::{parse_node_card, Fingerprint};
use crate::custody_owner_requests::tests::Party;
use crate::custody_pool_setup::CardInput;
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::protected_content_config::{
    install_custody_composition, signed_custody_composition_config_at,
    validated_custody_node_descriptor,
};

const STORAGE: &[&str] = &["chain", "custody", "ipfs"];
const NODE_LABELS: [(&str, &str); 3] = [("Bob", "Oslo"), ("Carol", "Kyiv"), ("Dave", "Rome")];

struct Owner {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    nodes: Vec<Party>,
}

fn new_owner_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    elastos_identity::load_or_create_did(&data_dir).unwrap();
    crate::custody_pool_setup::create_signing_key(&data_dir).unwrap();
    (dir, data_dir)
}

/// A pool installed from the terminal: no cards are kept.
fn terminal_owner() -> Owner {
    let (dir, data_dir) = new_owner_dir();
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
    install_custody_composition(
        &data_dir,
        &crate::custody_pool_setup::policy_authority_key_path(&data_dir),
        descriptors,
        365,
    )
    .unwrap();
    Owner {
        _dir: dir,
        data_dir,
        nodes,
    }
}

/// A pool installed from the Custody app with three remote cards kept.
async fn card_owner() -> Owner {
    let (dir, data_dir) = new_owner_dir();
    let nodes: Vec<Party> = NODE_LABELS
        .iter()
        .map(|(name, _)| Party::new(name, true))
        .collect();
    let cards = nodes
        .iter()
        .zip(NODE_LABELS)
        .map(|(node, (name, location))| CardInput::Remote {
            text: card_for_device(&node.device.verifying_key(), name, location, STORAGE),
        })
        .collect::<Vec<_>>();
    crate::custody_pool_setup::install(&data_dir, &cards, 365)
        .await
        .unwrap();
    Owner {
        _dir: dir,
        data_dir,
        nodes,
    }
}

fn now() -> u64 {
    crate::auth::now_ts()
}

fn owner_pool(data_dir: &Path) -> PoolDidV1 {
    let key = crate::protected_content_config::policy_authority_public_key(
        &crate::custody_pool_setup::policy_authority_key_path(data_dir),
    )
    .unwrap();
    PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(key).unwrap())
}

fn another_pool() -> PoolDidV1 {
    let key = elastos_runtime::signature::SigningKey::from_bytes(&[9u8; 32]);
    PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(key.verifying_key().to_bytes()).unwrap())
}

/// What the member at `index` of the descriptor's committee knows of its pool.
fn served_facts(epochs: &[PoolEpochBundleV1], index: usize) -> ServedPoolFacts {
    let bundle = &epochs[0];
    let pool = bundle.signed_pool().statement();
    let epoch = bundle.signed_epoch().statement();
    let node = &epoch.nodes()[index];
    ServedPoolFacts {
        issuer_fingerprint_full: Fingerprint::of(pool.issuer().as_bytes()).full,
        pool_start: pool
            .members()
            .iter()
            .map(|member| member.valid_from())
            .max()
            .unwrap(),
        term_end: pool
            .members()
            .iter()
            .map(|member| member.valid_until())
            .min()
            .unwrap(),
        required: epoch.threshold().required(),
        total: epoch.threshold().total(),
        share: node.share_coordinate().get(),
        own_node_key: *node.node_public_key().as_bytes(),
    }
}

/// The owner's v3 descriptor as readers take it (item 10, #388 A2).
fn any(descriptor: &SignedPoolDescriptorV3) -> SignedPoolDescriptorAnyV1 {
    descriptor.clone().into()
}

/// Plan B T2.2: a member keeps a pool's descriptor in that pool's
/// served-pools entry, so the entry is there first, as approving makes it.
fn store_served(
    member_dir: &Path,
    facts: &ServedPoolFacts,
    descriptor: &SignedPoolDescriptorAnyV1,
    now: u64,
) -> Result<(), WireRefusal> {
    crate::custody_consent::update_served_pools(member_dir, |pools| {
        pools
            .entries
            .entry(facts.issuer_fingerprint_full.clone())
            .or_insert_with(|| crate::custody_consent::ServedPoolEntryV2 {
                owner_home: "did:key:z6MkTestOwner".to_string(),
                consent: crate::custody_consent::ServedConsentV2 {
                    term_days: 365,
                    signing_key_fingerprint_full: facts.issuer_fingerprint_full.clone(),
                },
                root_path: format!(
                    "pools/{}",
                    facts.issuer_fingerprint_full.trim_start_matches("sha256:")
                ),
                admin_profile_did: None,
                pool_did: None,
                served_pool: None,
                descriptor: None,
            });
        Ok(())
    })
    .unwrap();
    store_member_descriptor(member_dir, facts, descriptor, now)
}

/// Plan B T2.2: the descriptor bytes a member keeps in that pool's entry.
fn kept_descriptor_bytes(member_dir: &Path, facts: &ServedPoolFacts) -> Vec<u8> {
    let entry = crate::custody_consent::served_pools(member_dir)
        .unwrap()
        .entries
        .remove(&facts.issuer_fingerprint_full)
        .expect("the pool's entry");
    base64::engine::general_purpose::STANDARD
        .decode(entry.descriptor.expect("a kept descriptor"))
        .unwrap()
}

fn member_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("member");
    owner_only_dir(&data_dir);
    (dir, data_dir)
}

// ---------------------------------------------------------------------------
// Owner
// ---------------------------------------------------------------------------

#[test]
fn owner_descriptor_covers_installed_epoch_and_members() {
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let verified = descriptor.verify(now).unwrap();
    assert_eq!(verified.pool(), &owner_pool(&owner.data_dir));
    let statement = descriptor.statement();
    assert_eq!(statement.epochs().len(), 1);
    let epoch = statement.epochs()[0].signed_epoch().statement();
    assert_eq!(statement.members().len(), epoch.nodes().len());
    for (member, node) in statement.members().iter().zip(epoch.nodes()) {
        assert_eq!(member.node_public_key(), node.node_public_key());
        let roles = member.roles();
        assert!(roles.hold && roles.serve && roles.seal);
    }
    assert_eq!(*statement.serve_policy(), ServePolicyV1::DEFAULT);
    assert_eq!(
        statement.mint_policy(),
        &MintPolicyV1::owner_default(own_runtime_issuer(&owner.data_dir).unwrap())
    );
}

#[test]
fn owner_descriptor_reads_members_and_threshold_from_the_installed_composition() {
    // L2: the Runtime loader holds three routes, so the pool has three members.
    let owner = terminal_owner();
    let descriptor = owner_descriptor(&owner.data_dir, now()).unwrap().unwrap();
    let epoch = descriptor.statement().epochs()[0]
        .signed_epoch()
        .statement();
    assert_eq!(epoch.threshold(), ThresholdV1::new(2, 3).unwrap());
    assert_eq!(descriptor.statement().members().len(), 3);
}

#[test]
fn owner_builds_sequence_one_lazily_for_a_legacy_pool() {
    // L14: a pool installed before descriptors existed has no file; the
    // first read builds sequence 1, and later reads reuse it.
    let owner = terminal_owner();
    assert!(!owner_descriptor_path(&owner.data_dir).exists());
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    assert_eq!(first.statement().sequence(), 1);
    assert!(owner_descriptor_path(&owner.data_dir).exists());
    let again = owner_descriptor(&owner.data_dir, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(again, first);
}

#[tokio::test]
async fn policy_change_bumps_sequence() {
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let serve = ServePolicyV1 {
        max_servers_per_session: 2,
        ..ServePolicyV1::DEFAULT
    };
    let changed = set_owner_policies(
        &lock_custody_writes().await,
        &owner.data_dir,
        serve,
        first.statement().mint_policy().clone(),
        now + 1,
    )
    .unwrap();
    assert_eq!(changed.statement().sequence(), 2);
    assert_eq!(*changed.statement().serve_policy(), serve);
    // The stored policies carry forward.
    let read = owner_descriptor(&owner.data_dir, now + 2).unwrap().unwrap();
    assert_eq!(read, changed);
}

#[test]
fn owner_descriptor_re_signs_after_the_pool_term() {
    // F1: the members' term has ended, and the owner still re-signs, so the
    // pool's items keep playing.
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let term_end = served_facts(first.statement().epochs(), 0).term_end;
    let after_term = term_end + 10 * 86_400;
    let late = owner_descriptor(&owner.data_dir, after_term)
        .unwrap()
        .unwrap();
    assert_eq!(late.statement().sequence(), 2);
    late.verify(after_term).unwrap();
}

#[test]
fn owner_descriptor_sequence_stays_monotonic_across_compositions() {
    // 17:55: a renewed composition continues the sequence; it never starts
    // again at 1, so each node's high-water mark accepts the renewed pool.
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    assert_eq!(first.statement().sequence(), 1);

    let key_bytes: [u8; 32] = std::fs::read(crate::custody_pool_setup::policy_authority_key_path(
        &owner.data_dir,
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let authority = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    let descriptors = owner
        .nodes
        .iter()
        .zip(NODE_LABELS)
        .map(|(node, (name, location))| {
            let bytes = carrier_descriptor_bytes(&node.device.verifying_key(), name, location);
            validated_custody_node_descriptor(&bytes, "terminal node").unwrap()
        })
        .collect();
    let renewed = signed_custody_composition_config_at(
        &authority,
        descriptors,
        365,
        ThresholdV1::new(2, 3).unwrap(),
        now + 3_600,
    )
    .unwrap();
    write_owner_only_bytes(
        &runtime_custody_composition_config_path(&owner.data_dir),
        &serde_json::to_vec(&serde_json::to_value(&renewed).unwrap()).unwrap(),
    )
    .unwrap();

    let second = owner_descriptor(&owner.data_dir, now + 3_600)
        .unwrap()
        .unwrap();
    assert_eq!(second.statement().sequence(), 2);
    assert_ne!(second.statement().epochs(), first.statement().epochs());
}

#[test]
fn owner_signs_only_v3_descriptors() {
    // #388 A2: the owner writes the v3 format (`WciOperated`, every slot
    // empty), and its file keeps those exact bytes.
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    assert!(descriptor
        .canonical_bytes()
        .unwrap()
        .starts_with(b"elastos.protected-content.pool-descriptor/v3\0"));
    assert_eq!(
        load_owner_descriptor(&owner.data_dir).unwrap(),
        Some(any(&descriptor))
    );
    assert_eq!(
        descriptor.verify(now).unwrap().admits_new_release(),
        Ok(elastos_protected_content_contracts::PoolTrustModeV1::WciOperated)
    );
}

/// #388 A2: a stored v2 owner record (trust absent) is re-signed as v3 at its
/// sequence + 1. The old signed bytes are never re-encoded: they still decode
/// and verify as the same v2, and a member keeps its v2 copy as signed until
/// the newer v3 arrives.
#[test]
fn v2_owner_record_is_resigned_as_v3_at_sequence_plus_one_and_old_bytes_are_kept() {
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let statement = first.statement();
    let v2_statement = PoolDescriptorStatementV2::new(
        *statement.pool(),
        statement.sequence(),
        statement.epochs().to_vec(),
        statement
            .members()
            .iter()
            .map(|member| member.member().clone())
            .collect(),
        *statement.serve_policy(),
        statement.mint_policy().clone(),
        statement.issued_at(),
        statement.expires_at(),
    )
    .unwrap();
    let signature = policy_authority_signature(
        &crate::custody_pool_setup::policy_authority_key_path(&owner.data_dir),
        &v2_statement.canonical_bytes().unwrap(),
    )
    .unwrap();
    let v2 = SignedPoolDescriptorV2::new(v2_statement, signature).unwrap();
    let v2_bytes = v2.canonical_bytes().unwrap();
    // The owner record as a pre-#388 build stored it.
    write_owner_only_bytes(
        &owner_descriptor_path(&owner.data_dir),
        &serde_json::to_vec(&OwnerDescriptorFileV1 {
            schema: OWNER_DESCRIPTOR_SCHEMA_V1.to_string(),
            descriptor_base64: base64::engine::general_purpose::STANDARD.encode(&v2_bytes),
        })
        .unwrap(),
    )
    .unwrap();
    let (_member, member_dir) = member_dir();
    let historical: SignedPoolDescriptorAnyV1 = v2.clone().into();
    let historical_facts = served_facts(historical.epochs(), 1);
    store_served(&member_dir, &historical_facts, &historical, now).unwrap();

    let resigned = owner_descriptor(&owner.data_dir, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        resigned.statement().sequence(),
        v2.statement().sequence() + 1
    );
    assert_eq!(
        resigned.verify(now + 60).unwrap().admits_new_release(),
        Ok(elastos_protected_content_contracts::PoolTrustModeV1::WciOperated)
    );
    assert_eq!(
        load_owner_descriptor(&owner.data_dir).unwrap(),
        Some(any(&resigned))
    );
    // The old bytes are unchanged: the same v2, trust absent, read-only.
    let decoded = SignedPoolDescriptorAnyV1::from_canonical_bytes(&v2_bytes).unwrap();
    assert_eq!(decoded, historical);
    assert_eq!(decoded.canonical_bytes().unwrap(), v2_bytes);
    assert_eq!(decoded.verify(now + 60).unwrap().trust(), None);
    // The member kept its v2 copy as signed, then takes the newer v3.
    assert_eq!(
        kept_descriptor_bytes(&member_dir, &historical_facts),
        v2_bytes
    );
    let pool = owner_pool(&owner.data_dir);
    assert_eq!(
        served_descriptor(&member_dir, &pool, now + 60)
            .unwrap()
            .unwrap()
            .admits_new_release(),
        Err(elastos_protected_content_contracts::PoolContractError::TrustRequired)
    );
    let newer = any(&resigned);
    store_served(
        &member_dir,
        &served_facts(newer.epochs(), 1),
        &newer,
        now + 60,
    )
    .unwrap();
    assert_eq!(describe(&member_dir, &pool, now + 60).unwrap(), Some(newer));
}

#[tokio::test]
async fn remote_member_routes_are_peer_dids_without_tickets() {
    // Item 10: each route is the member's Carrier peer DID. The owner keeps
    // the members' cards, and no card ticket enters the signed descriptor.
    let owner = card_owner().await;
    let descriptor = owner_descriptor(&owner.data_dir, now()).unwrap().unwrap();
    let bytes = descriptor.canonical_bytes().unwrap();
    for node in &owner.nodes {
        assert!(
            descriptor
                .statement()
                .members()
                .iter()
                .any(|member| member.route().peer_did() == node.did()),
            "{} is a member",
            node.name
        );
        let (_, location) = NODE_LABELS
            .iter()
            .find(|(name, _)| *name == node.name)
            .unwrap();
        let card = card_for_device(&node.device.verifying_key(), node.name, location, STORAGE);
        let ticket = parse_node_card(&card).unwrap().ticket;
        assert!(
            !bytes
                .windows(ticket.len())
                .any(|window| window == ticket.as_bytes()),
            "{}'s ticket is not signed",
            node.name
        );
    }
}

// ---------------------------------------------------------------------------
// Member
// ---------------------------------------------------------------------------

#[tokio::test]
async fn member_orders_descriptors_by_sequence_within_its_served_pool() {
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let facts = served_facts(first.statement().epochs(), 1);
    let (_member, member_dir) = member_dir();
    store_served(&member_dir, &facts, &any(&first), now).unwrap();
    // The same sequence again, and an older one, are stale.
    assert_eq!(
        store_served(&member_dir, &facts, &any(&first), now),
        Err(WireRefusal::new("stale_notice"))
    );
    let second = set_owner_policies(
        &lock_custody_writes().await,
        &owner.data_dir,
        ServePolicyV1 {
            max_servers_per_session: 2,
            ..ServePolicyV1::DEFAULT
        },
        first.statement().mint_policy().clone(),
        now + 1,
    )
    .unwrap();
    store_served(&member_dir, &facts, &any(&second), now + 1).unwrap();
    assert_eq!(
        store_served(&member_dir, &facts, &any(&first), now + 1),
        Err(WireRefusal::new("stale_notice"))
    );
    let kept = served_descriptor(&member_dir, &owner_pool(&owner.data_dir), now + 1)
        .unwrap()
        .unwrap();
    assert_eq!(kept.sequence(), 2);
}

#[test]
fn member_refuses_descriptor_without_its_served_pool() {
    // L13: the pool start selects the composition; a descriptor for another
    // composition of the same owner is not the served pool.
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let mut facts = served_facts(descriptor.statement().epochs(), 0);
    facts.pool_start += 1;
    let (_member, member_dir) = member_dir();
    assert_eq!(
        store_served(&member_dir, &facts, &any(&descriptor), now),
        Err(WireRefusal::new("not_member"))
    );
    assert!(
        served_descriptor(&member_dir, &owner_pool(&owner.data_dir), now)
            .unwrap()
            .is_none()
    );
}

#[test]
fn member_refuses_descriptor_from_a_pool_it_does_not_serve() {
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let epochs = descriptor.statement().epochs();
    let (_member, member_dir) = member_dir();
    // Another owner's pool signing key.
    let mut other_owner = served_facts(epochs, 0);
    other_owner.issuer_fingerprint_full = Fingerprint::of(&[7u8; 32]).full;
    // A node outside the committee.
    let mut outsider = served_facts(epochs, 0);
    outsider.own_node_key = [0x42; 32];
    // A member at another share.
    let mut wrong_share = served_facts(epochs, 0);
    wrong_share.share = served_facts(epochs, 1).share;
    for facts in [other_owner, outsider, wrong_share] {
        assert_eq!(
            store_served(&member_dir, &facts, &any(&descriptor), now),
            Err(WireRefusal::new("not_member"))
        );
    }
}

#[test]
fn describe_answers_owner_or_member_copy_only() {
    let owner = terminal_owner();
    let now = now();
    let pool = owner_pool(&owner.data_dir);
    let owned = describe(&owner.data_dir, &pool, now).unwrap().unwrap();
    assert!(matches!(owned, SignedPoolDescriptorAnyV1::V3(_)));
    assert_eq!(owned.pool(), &pool);
    assert!(describe(&owner.data_dir, &another_pool(), now)
        .unwrap()
        .is_none());

    let (_member, member_dir) = member_dir();
    assert!(describe(&member_dir, &pool, now).unwrap().is_none());
    store_served(&member_dir, &served_facts(owned.epochs(), 2), &owned, now).unwrap();
    assert_eq!(describe(&member_dir, &pool, now).unwrap(), Some(owned));
    assert!(describe(&member_dir, &another_pool(), now)
        .unwrap()
        .is_none());
}

#[test]
fn member_keeps_a_historical_v1_descriptor_as_signed() {
    // Item 10: readers take any version. A v1 descriptor with a ticket is
    // kept and described as its original bytes; its verified form has no
    // ticket, and (#388 A2) no trust, and otherwise equals the owner's.
    let owner = terminal_owner();
    let now = now();
    let owned = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let statement = owned.statement();
    let members = statement
        .members()
        .iter()
        .map(|member| {
            PoolMemberV1::new(
                member.node_public_key(),
                member.roles(),
                PoolMemberRouteV1::new(
                    member.route().peer_did().to_owned(),
                    Some("ticket".to_string()),
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let v1_statement = PoolDescriptorStatementV1::new(
        *statement.pool(),
        statement.sequence(),
        statement.epochs().to_vec(),
        members,
        *statement.serve_policy(),
        statement.mint_policy().clone(),
        statement.issued_at(),
        statement.expires_at(),
    )
    .unwrap();
    let signature = policy_authority_signature(
        &crate::custody_pool_setup::policy_authority_key_path(&owner.data_dir),
        &v1_statement.canonical_bytes().unwrap(),
    )
    .unwrap();
    let v1: SignedPoolDescriptorAnyV1 = SignedPoolDescriptorV1::new(v1_statement, signature)
        .unwrap()
        .into();

    let (_member, member_dir) = member_dir();
    let v1_facts = served_facts(v1.epochs(), 0);
    store_served(&member_dir, &v1_facts, &v1, now).unwrap();
    assert_eq!(
        kept_descriptor_bytes(&member_dir, &v1_facts),
        v1.canonical_bytes().unwrap()
    );
    let pool = owner_pool(&owner.data_dir);
    assert_eq!(describe(&member_dir, &pool, now).unwrap(), Some(v1));
    let kept = served_descriptor(&member_dir, &pool, now).unwrap().unwrap();
    let verified = owned.verify(now).unwrap();
    assert_eq!(kept.trust(), None);
    assert_eq!(kept.pool(), verified.pool());
    assert_eq!(kept.sequence(), verified.sequence());
    for member in statement.members() {
        assert_eq!(
            kept.member(member.node_public_key()),
            verified.member(member.node_public_key())
        );
    }
}

// ---------------------------------------------------------------------------
// Transport and scope
// ---------------------------------------------------------------------------

#[test]
fn descriptor_message_fits_the_payload_bound() {
    // L9: the base64 of a descriptor at its cap, in the payload, fits a
    // collaboration message payload.
    let at_cap = CustodyPoolDescriptorPayload {
        descriptor: "A".repeat(MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1.div_ceil(3) * 4),
    };
    assert!(
        serde_json::to_vec(&at_cap).unwrap().len()
            <= elastos_common::collaboration_protocol::MAX_COLLABORATION_PAYLOAD_BYTES
    );
    // A real descriptor travels and decodes exactly.
    let owner = terminal_owner();
    let descriptor = owner_descriptor(&owner.data_dir, now()).unwrap().unwrap();
    let payload = CustodyPoolDescriptorPayload::new(&descriptor).unwrap();
    assert_eq!(payload.signed_descriptor().unwrap(), any(&descriptor));
    // One byte over the cap is refused before decoding.
    let over = CustodyPoolDescriptorPayload {
        descriptor: "A".repeat(MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1.div_ceil(3) * 4 + 4),
    };
    assert!(over.signed_descriptor().is_err());
}

#[test]
fn owner_without_the_descriptor_scope_is_asked_to_enable_again() {
    // L13c: a Profile enabled before the descriptor type existed lacks part
    // of the current scope, so custody messages read as not enabled and the
    // Custody app asks once more.
    use crate::collaboration_profile_authority::{
        signed_profile_document_for_test, with_signing_scope_for_test,
    };
    let (device, _) = elastos_runtime::signature::generate_keypair();
    let (profile_key, _) = elastos_runtime::signature::generate_keypair();
    let default = signed_profile_document_for_test(
        &profile_key,
        "Olivia",
        None,
        1,
        None,
        now() - 100,
        vec![crate::crypto::encode_signing_key_did(&device)],
    )
    .unwrap();
    let (service, current) = CUSTODY_SIGNING_SCOPE;
    let older: Vec<&str> = current
        .iter()
        .copied()
        .filter(|object_type| *object_type != crate::custody_surface::MESSAGE_POOL_DESCRIPTOR)
        .collect();
    assert_eq!(older.len() + 1, current.len());
    let enabled_before =
        with_signing_scope_for_test(&profile_key, &default, (service, older.as_slice())).unwrap();
    assert!(!crate::custody_consent::custody_messages_enabled(
        &enabled_before
    ));
    let enabled_now =
        with_signing_scope_for_test(&profile_key, &default, CUSTODY_SIGNING_SCOPE).unwrap();
    assert!(crate::custody_consent::custody_messages_enabled(
        &enabled_now
    ));
}

#[test]
fn pool_address_text_round_trips_and_refuses_garbage() {
    // Item 10: the text form encodes the ticketless v2 address.
    let address = PoolAddressV2::new(
        another_pool(),
        PoolMemberRouteV2::new("did:key:z6MkPoolOwnerHome".into()).unwrap(),
    )
    .unwrap();
    let text = encode_pool_address(&address).unwrap();
    assert!(text.starts_with(POOL_ADDRESS_TEXT_PREFIX));
    assert!(!text.contains('='));
    let parsed = PoolAddressAnyV1::V2(address);
    assert_eq!(parse_pool_address(&text).unwrap(), parsed);
    // Surrounding whitespace from a paste is tolerated.
    assert_eq!(parse_pool_address(&format!("  {text}\n")).unwrap(), parsed);
    // A historical v1 address, with a ticket, still parses.
    let v1 = PoolAddressV1::new(
        another_pool(),
        PoolMemberRouteV1::new(
            "did:key:z6MkPoolOwnerHome".into(),
            Some("ticket".to_string()),
        )
        .unwrap(),
    )
    .unwrap();
    let v1_text = format!(
        "{POOL_ADDRESS_TEXT_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v1.canonical_bytes().unwrap())
    );
    let parsed_v1 = parse_pool_address(&v1_text).unwrap();
    assert_eq!(parsed_v1.peer_did(), "did:key:z6MkPoolOwnerHome");
    assert_eq!(parsed_v1, PoolAddressAnyV1::V1(v1));
    for garbage in [
        "",
        "elastos-pool:",
        "elastos-pool:!!!",
        "elastos-pool:AAAA",
        &text[POOL_ADDRESS_TEXT_PREFIX.len()..],
        &format!("elastos-node:{}", &text[POOL_ADDRESS_TEXT_PREFIX.len()..]),
    ] {
        assert!(parse_pool_address(garbage).is_err(), "{garbage:?}");
    }
}

/// Plan B T4.8: a server count above the epoch's total (L2) is refused
/// before anything is signed; the stored descriptor stays as it was.
#[tokio::test]
async fn set_owner_policies_refuses_m_above_the_epoch_total_before_signing() {
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let total = first.statement().epochs()[0]
        .signed_epoch()
        .statement()
        .threshold()
        .total();
    let too_many = ServePolicyV1 {
        max_servers_per_session: total + 1,
        ..ServePolicyV1::DEFAULT
    };
    // The serve policy itself is valid (at most four); only the epoch bounds it.
    assert!(
        usize::from(total + 1) <= elastos_protected_content_contracts::MAX_SESSION_RECIPIENTS_V2
    );
    let error = set_owner_policies(
        &lock_custody_writes().await,
        &owner.data_dir,
        too_many,
        first.statement().mint_policy().clone(),
        now + 1,
    )
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<crate::custody_pool_setup::CustodyRefusal>()
            .map(crate::custody_pool_setup::CustodyRefusal::code),
        Some("too_many_servers")
    );
    // Nothing was signed: the next read is the first descriptor.
    assert_eq!(
        owner_descriptor(&owner.data_dir, now + 2).unwrap().unwrap(),
        first
    );
    // The epoch's total itself is accepted, and verifies.
    let at_total = ServePolicyV1 {
        max_servers_per_session: total,
        ..ServePolicyV1::DEFAULT
    };
    let signed = set_owner_policies(
        &lock_custody_writes().await,
        &owner.data_dir,
        at_total,
        first.statement().mint_policy().clone(),
        now + 3,
    )
    .unwrap();
    signed.verify(now + 3).unwrap();
}

/// Plan B T2.2 (re-anchor F6): one descriptor per served pool, and the
/// resolver's served source sees every one.
#[tokio::test]
async fn served_descriptors_lists_every_served_pool() {
    let now = now();
    let first_owner = terminal_owner();
    let second_owner = terminal_owner();
    let first = any(&owner_descriptor(&first_owner.data_dir, now)
        .unwrap()
        .unwrap());
    let second = any(&owner_descriptor(&second_owner.data_dir, now)
        .unwrap()
        .unwrap());
    assert_ne!(first.pool(), second.pool());
    let (_member, member_dir) = member_dir();
    let first_facts = served_facts(first.epochs(), 1);
    let second_facts = served_facts(second.epochs(), 1);
    // A pool this node does not serve keeps nothing.
    assert_eq!(
        store_member_descriptor(&member_dir, &first_facts, &first, now),
        Err(WireRefusal::new("not_member"))
    );
    store_served(&member_dir, &first_facts, &first, now).unwrap();
    store_served(&member_dir, &second_facts, &second, now).unwrap();

    let kept = served_descriptors(&member_dir, now).unwrap();
    assert_eq!(kept.len(), 2);
    for (owner, descriptor) in [(&first_owner, &first), (&second_owner, &second)] {
        let pool = owner_pool(&owner.data_dir);
        assert!(kept.contains(descriptor));
        assert_eq!(
            served_descriptor(&member_dir, &pool, now)
                .unwrap()
                .unwrap()
                .sequence(),
            descriptor.sequence()
        );
        let entry = &crate::custody_consent::served_pools(&member_dir)
            .unwrap()
            .entries[&Fingerprint::of(pool.issuer().as_bytes()).full];
        assert_eq!(entry.pool_did, pool.to_did_key().ok());
    }
}

// ---------------------------------------------------------------------------
// Plan B S7-lite T7.3 (S7L-F2): a node takes a minter's provisioning only for
// the pool its own records bind to the root holding the request's node.
// ---------------------------------------------------------------------------

fn attacker_xwing(
    seed: u8,
) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    use x_wing::kem::Decapsulator as _;
    use x_wing::KeyExport as _;
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

fn node_key(bytes: [u8; 32]) -> NodePublicKey {
    NodePublicKey::new(bytes).unwrap()
}

#[test]
fn trusted_pool_root_is_the_served_entry_root_only() {
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let facts = served_facts(descriptor.statement().epochs(), 1);
    let (_member, member_dir) = member_dir();
    store_served(&member_dir, &facts, &any(&descriptor), now).unwrap();
    let trusted = trusted_pool_root(&member_dir, &owner_pool(&owner.data_dir))
        .unwrap()
        .unwrap();
    assert_eq!(
        trusted.root_path,
        format!(
            "pools/{}",
            facts.issuer_fingerprint_full.trim_start_matches("sha256:")
        )
    );
    assert_eq!(trusted.kept.unwrap().sequence(), 1);
    // A pool this member does not serve has no trusted root.
    assert_eq!(
        trusted_pool_root(&member_dir, &another_pool()).unwrap(),
        None
    );
}

#[test]
fn guard_member_refuses_a_share_for_a_pool_it_does_not_serve() {
    use elastos_protected_content_contracts::test_fixtures::{
        pool_bundle, pool_descriptor_signed_by,
    };
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let facts = served_facts(descriptor.statement().epochs(), 1);
    let (_member, member_dir) = member_dir();
    store_served(&member_dir, &facts, &any(&descriptor), now).unwrap();
    // An attacker signs its own pool's descriptor naming the victim's node:
    // its pool is not one the victim serves.
    let bundle = pool_bundle(attacker_xwing, now);
    let attacker: SignedPoolDescriptorAnyV1 =
        pool_descriptor_signed_by(&bundle, 9, now, 0x66).into();
    let victim = node_key(facts.own_node_key);
    let trusted = trusted_pool_root(&member_dir, attacker.pool()).unwrap();
    assert_eq!(trusted, None);
    assert_eq!(
        check_pool_provision(trusted.as_ref(), Some(victim), &attacker, victim),
        Err("pool_not_served")
    );
}

#[test]
fn a_home_that_uses_the_pool_is_accepted_for_its_pool_root() {
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let facts = served_facts(descriptor.statement().epochs(), 1);
    let (_member, member_dir) = member_dir();
    store_served(&member_dir, &facts, &any(&descriptor), now).unwrap();
    let node = node_key(facts.own_node_key);
    let trusted = trusted_pool_root(&member_dir, &owner_pool(&owner.data_dir)).unwrap();
    assert_eq!(
        check_pool_provision(trusted.as_ref(), Some(node), &any(&descriptor), node),
        Ok(())
    );
    // Another root's node, or no node key at that root, is refused.
    let other = node_key(
        *descriptor.statement().epochs()[0]
            .signed_epoch()
            .statement()
            .nodes()[0]
            .node_public_key()
            .as_bytes(),
    );
    assert_eq!(
        check_pool_provision(trusted.as_ref(), Some(node), &any(&descriptor), other),
        Err("node_not_in_pool_root")
    );
    assert_eq!(
        check_pool_provision(trusted.as_ref(), None, &any(&descriptor), node),
        Err("node_not_in_pool_root")
    );
}

#[tokio::test]
async fn guard_provisioning_under_a_descriptor_older_than_the_kept_one_is_refused() {
    let owner = terminal_owner();
    let now = now();
    let first = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    let facts = served_facts(first.statement().epochs(), 1);
    let (_member, member_dir) = member_dir();
    store_served(&member_dir, &facts, &any(&first), now).unwrap();
    let second = set_owner_policies(
        &lock_custody_writes().await,
        &owner.data_dir,
        ServePolicyV1 {
            max_servers_per_session: 2,
            ..ServePolicyV1::DEFAULT
        },
        first.statement().mint_policy().clone(),
        now + 1,
    )
    .unwrap();
    store_served(&member_dir, &facts, &any(&second), now + 1).unwrap();
    let node = node_key(facts.own_node_key);
    let trusted = trusted_pool_root(&member_dir, &owner_pool(&owner.data_dir)).unwrap();
    assert_eq!(
        check_pool_provision(trusted.as_ref(), Some(node), &any(&first), node),
        Err("stale_descriptor")
    );
    assert_eq!(
        check_pool_provision(trusted.as_ref(), Some(node), &any(&second), node),
        Ok(())
    );
}

#[test]
fn owner_pool_is_held_by_the_owners_own_root() {
    let owner = terminal_owner();
    let now = now();
    let descriptor = owner_descriptor(&owner.data_dir, now).unwrap().unwrap();
    // A terminal owner holds no node of its own pool here: no trusted root.
    let trusted = trusted_pool_root(&owner.data_dir, &owner_pool(&owner.data_dir)).unwrap();
    match trusted {
        None => {}
        Some(trusted) => assert_eq!(
            trusted.kept.unwrap().sequence(),
            descriptor.statement().sequence()
        ),
    }
}
