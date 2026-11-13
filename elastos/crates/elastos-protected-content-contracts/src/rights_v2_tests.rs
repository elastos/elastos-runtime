//! ADV-01: one `rights-request/v2` (implementation contract rev 6, §3 and
//! §4 steps 1 and 8).
//!
//! One layout carries the direct form (tag 0, one recipient, no delivery
//! key) and the pool form (tag 1, 1..=4 servers and the per-open delivery
//! key), with `chain_id` last. The wallet signs the v2 consent text: the
//! direct form keeps P5's `Device:` line, and the pool form shows
//! `Delivery key:` and one `Server:` line per server.
//!
//! The vectors at the end were computed with an independent implementation
//! (Python: canonical encoding, SHA-256, Keccak-256, EIP-191 and RFC 6979
//! over secp256k1). Before computing them, that implementation reproduced
//! values pinned elsewhere: `canonical_signature_golden_vectors` (the V1
//! wallet signature and signed-request hash) and P5's KAT (the 333-byte
//! text, its EIP-191 digest and its request hash). Golden vectors are
//! append-only.

use ed25519_dalek::SigningKey;
use hex::encode;
use k256::ecdsa::SigningKey as WalletSigningKey;
use sha2::{Digest as _, Sha256};

use crate::test_support::{
    archived_pre_alignment_v2_request_bytes, archived_pre_alignment_v2_wrapper_bytes,
    custody_committee_authorization_identity, custody_epoch_identity, digest, node_set, wallet,
    NOW,
};
use crate::{
    CanonicalContract, ContractError, CustodyPoolIdentityV1, DeliveryKeyIdentityV1,
    EncryptedContentIdentityV1, KeyEnvelopeIdentityV1, ProfileIdentityV1,
    ProtectedContentBindingV1, RecipientKeyIdentityV1, ReplayNonce16, RightsActionV1, RightsError,
    RightsPolicyIdentityV1, RightsRequestAnyV1, RightsRequestV2, RuntimeSessionBindingV1,
    ThresholdV1, WalletSignedRightsRequestAnyV1, WalletSignedRightsRequestV2,
    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, PRE_ALIGNMENT_V2,
};

/// Test-only bounds (§3): the longest legal consent text of each form.
const MAX_RIGHTS_V2_DIRECT_TEXT_BYTES: usize = 365;
const MAX_RIGHTS_V2_POOL_TEXT_BYTES: usize = 482;

const P5_CHAIN: u64 = 8453;
const RIGHTS_REQUEST_V2_DOMAIN: &str = "elastos.protected-content.rights-request/v2";

/// Copied verbatim from P5:498 (`KAT_V2_MESSAGE`, patch
/// `0005-DKMS-05-DKMS-04-rights-request-v2-with-readable-cons.patch` in
/// `elacity-post-quantum-roadmap/source/patches/elastos-runtime/01-series-1-key-plane/`).
/// History only: ADV-01 keeps lines 1-10 byte for byte, and its `Request:`
/// value differs because the canonical layout differs.
const ROADMAP_P5_KAT_V2_MESSAGE: &str = "ElastOS rights-request/v2 chain 8453\n\nOpen protected content.\n\nAction:  View\nAccount: 0x4a62316623ad457f02cdc5d997ded67a383ec569\nDevice:  0xa0a0a0a0a0a0a0a0\nProfile: 0x9109db55f79797a3\nPool:    0x3535353535353535 (2 of 3)\nExpires: 2000000120 (unix seconds)\nRequest: 0x4ef9ecec75f1c17176eadb66ea514c3665fe5b023848cc0a62841f48d410f309\n";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn xwing_recipient(byte: u8) -> RecipientKeyIdentityV1 {
    RecipientKeyIdentityV1::new(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, digest(byte)).unwrap()
}

fn envelope_with(
    content: &EncryptedContentIdentityV1,
    threshold: ThresholdV1,
) -> KeyEnvelopeIdentityV1 {
    KeyEnvelopeIdentityV1::new(
        content.clone(),
        digest(0x22),
        512,
        node_set().node_set_id().unwrap(),
        threshold,
        CustodyPoolIdentityV1::new(digest(0x35), 512).unwrap(),
        custody_epoch_identity(),
        custody_committee_authorization_identity(),
    )
    .unwrap()
}

fn binding_with_threshold(threshold: ThresholdV1) -> ProtectedContentBindingV1 {
    let content = EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap();
    ProtectedContentBindingV1::new(
        content.clone(),
        envelope_with(&content, threshold),
        RightsPolicyIdentityV1::new(digest(0x44), 384).unwrap(),
        ProfileIdentityV1::from_public_key_bytes(
            SigningKey::from_bytes(&[0x26; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        wallet(7),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap()
}

/// The binding of P5's KAT: content `digest(0x11)` of 4096 bytes, envelope
/// `digest(0x22)` of 512 bytes on the test node set (2 of 3), pool
/// `digest(0x35)`, policy `digest(0x44)` of 384 bytes, the ed25519 Profile
/// `[0x26; 32]`, wallet 7 and session binding `digest(0x66)`.
fn p5_kat_binding() -> ProtectedContentBindingV1 {
    binding_with_threshold(node_set().threshold())
}

/// V-D: P5's KAT request in the direct form.
fn direct_request() -> RightsRequestV2 {
    RightsRequestV2::new_direct(
        p5_kat_binding(),
        RightsActionV1::View,
        xwing_recipient(0xa0),
        NOW,
        NOW + 120,
        ReplayNonce16::new([0x55; 16]),
        P5_CHAIN,
    )
    .unwrap()
}

fn pool_request_with(
    recipients: Vec<RecipientKeyIdentityV1>,
    delivery: DeliveryKeyIdentityV1,
    chain_id: u64,
) -> RightsRequestV2 {
    RightsRequestV2::new(
        p5_kat_binding(),
        RightsActionV1::View,
        recipients,
        delivery,
        NOW,
        NOW + 120,
        ReplayNonce16::new([0x55; 16]),
        chain_id,
    )
    .unwrap()
}

/// V-P: the same binding in the pool form, with three servers.
fn pool_request() -> RightsRequestV2 {
    pool_request_with(
        vec![
            xwing_recipient(0xb1),
            xwing_recipient(0xb2),
            xwing_recipient(0xb3),
        ],
        DeliveryKeyIdentityV1::new(digest(0xa0)),
        P5_CHAIN,
    )
}

/// The legal maxima (§3): `u64::MAX` chain and expiry, `Download`, a
/// `16 of 16` envelope. `servers` is `None` for the direct form.
fn maximum_request(servers: Option<u8>) -> RightsRequestV2 {
    let binding = binding_with_threshold(ThresholdV1::new(16, 16).unwrap());
    let issued_at = u64::MAX - 300;
    let nonce = ReplayNonce16::new([0x55; 16]);
    let request = match servers {
        None => RightsRequestV2::new_direct(
            binding,
            RightsActionV1::Download,
            xwing_recipient(0xa0),
            issued_at,
            u64::MAX,
            nonce,
            u64::MAX,
        ),
        Some(count) => RightsRequestV2::new(
            binding,
            RightsActionV1::Download,
            (0..count)
                .map(|index| xwing_recipient(0xb1 + index))
                .collect(),
            DeliveryKeyIdentityV1::new(digest(0xa0)),
            issued_at,
            u64::MAX,
            nonce,
            u64::MAX,
        ),
    };
    request.unwrap()
}

/// Wallet `seed`'s EIP-191 signature over `message`, as the wallet produces
/// it (65 bytes, v = 0 or 1).
fn wallet_signature_over(message: &str, seed: u8) -> Vec<u8> {
    let (signature, recovery_id) = WalletSigningKey::from_slice(&[seed; 32])
        .unwrap()
        .sign_prehash_recoverable(&elastos_auth::ethereum_signed_message_hash(
            message.as_bytes(),
        ))
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    bytes
}

/// The seven-line v1 layout that V2 signed before ADV-01, over `request`'s
/// own (v2) hash. R4: a signature over it must not verify.
fn v1_layout_text(request: &RightsRequestV2) -> String {
    format!(
        "ElastOS\n\nOpen protected content.\n\nAction:  {action}\nAccount: 0x{account}\nExpires: {expires} (unix seconds)\nRequest: 0x{request}\n",
        action = request.action().label(),
        account = encode(request.binding().wallet().as_bytes()),
        expires = request.expires_at(),
        request = encode(request.request_hash().unwrap().as_bytes()),
    )
}

fn fingerprint(bytes: &[u8]) -> String {
    encode(&bytes[..8])
}

fn line<'a>(message: &'a str, label: &str) -> &'a str {
    message
        .lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} line in:\n{message}"))
}

/// The bytes after the recipients: tag, optional delivery key, issued,
/// expires, nonce and chain.
fn tail_len(request: &RightsRequestV2) -> usize {
    let delivery = if request.delivery_key().is_some() {
        32
    } else {
        0
    };
    1 + delivery + 8 + 8 + 16 + 8
}

// ---------------------------------------------------------------------------
// V-H: history against P5
// ---------------------------------------------------------------------------

#[test]
fn rights_v2_text_lines_match_the_p5_kat_except_request() {
    let request = direct_request();
    let message = request.signing_message().unwrap();
    let ours: Vec<&str> = message.split('\n').collect();
    let p5: Vec<&str> = ROADMAP_P5_KAT_V2_MESSAGE.split('\n').collect();
    assert_eq!(ours.len(), p5.len());
    assert_eq!(
        ours[..10],
        p5[..10],
        "lines 1-10 must equal P5's:\n{message}"
    );
    assert!(ours[10].starts_with("Request: 0x"));
    assert_ne!(ours[10], p5[10], "the Request value must differ from P5's");
    assert_eq!(message.len(), ROADMAP_P5_KAT_V2_MESSAGE.len());

    let canonical = request.canonical_bytes().unwrap();
    assert!(canonical.starts_with(RIGHTS_REQUEST_V2_DOMAIN.as_bytes()));
    assert_eq!(canonical[RIGHTS_REQUEST_V2_DOMAIN.len()], 0);
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

#[test]
fn rights_v2_direct_and_pool_round_trip() {
    let direct = direct_request();
    assert_eq!(direct.delivery_key(), None);
    assert_eq!(direct.recipients(), [xwing_recipient(0xa0)].as_slice());
    assert_eq!(direct.chain_id(), P5_CHAIN);
    let pool = pool_request();
    assert_eq!(
        pool.delivery_key(),
        Some(DeliveryKeyIdentityV1::new(digest(0xa0)))
    );
    assert_eq!(pool.recipients().len(), 3);
    assert_eq!(pool.chain_id(), P5_CHAIN);

    for request in [direct, pool] {
        let bytes = request.canonical_bytes().unwrap();
        assert_eq!(
            RightsRequestV2::from_canonical_bytes(&bytes).unwrap(),
            request
        );
        match RightsRequestAnyV1::from_canonical_bytes(&bytes).unwrap() {
            RightsRequestAnyV1::V2(decoded) => assert_eq!(decoded, request),
            RightsRequestAnyV1::V1(_) => panic!("V2 bytes decoded as V1"),
        }
        let message = request.signing_message().unwrap();
        let signed =
            WalletSignedRightsRequestV2::new(request.clone(), wallet_signature_over(&message, 7))
                .unwrap();
        let signed_bytes = signed.canonical_bytes().unwrap();
        assert_eq!(
            WalletSignedRightsRequestV2::from_canonical_bytes(&signed_bytes).unwrap(),
            signed
        );
        match WalletSignedRightsRequestAnyV1::from_canonical_bytes(&signed_bytes).unwrap() {
            WalletSignedRightsRequestAnyV1::V2(decoded) => assert_eq!(decoded, signed),
            WalletSignedRightsRequestAnyV1::V1(_) => panic!("V2 bytes decoded as V1"),
        }
    }
}

#[test]
fn guard_rights_v2_tag0_with_two_recipients_is_refused() {
    // A pool request with two servers, re-tagged as the direct form: the
    // tag and the delivery key (33 bytes) become the single tag byte 0.
    let pool = pool_request_with(
        vec![xwing_recipient(0xb1), xwing_recipient(0xb2)],
        DeliveryKeyIdentityV1::new(digest(0xa0)),
        P5_CHAIN,
    );
    let bytes = pool.canonical_bytes().unwrap();
    let tag_at = bytes.len() - tail_len(&pool);
    assert_eq!(bytes[tag_at], 1);
    let mut direct_with_two = bytes[..tag_at].to_vec();
    direct_with_two.push(0);
    direct_with_two.extend_from_slice(&bytes[tag_at + 33..]);
    assert_eq!(
        RightsRequestV2::from_canonical_bytes(&direct_with_two),
        Err(ContractError::InvalidField("rights_request.recipients"))
    );
}

#[test]
fn guard_rights_v2_tag1_with_zero_or_five_recipients_is_refused() {
    let delivery = DeliveryKeyIdentityV1::new(digest(0xa0));
    for recipients in [
        vec![],
        (0xb1..=0xb5).map(xwing_recipient).collect::<Vec<_>>(),
    ] {
        assert_eq!(
            RightsRequestV2::new(
                p5_kat_binding(),
                RightsActionV1::View,
                recipients,
                delivery,
                NOW,
                NOW + 120,
                ReplayNonce16::new([0x55; 16]),
                P5_CHAIN,
            ),
            Err(ContractError::InvalidField("rights_request.recipients"))
        );
    }

    // On the wire: the recipient count of a one-server pool request set to
    // 0 and to 5.
    let pool = pool_request_with(vec![xwing_recipient(0xb1)], delivery, P5_CHAIN);
    let bytes = pool.canonical_bytes().unwrap();
    let recipient_bytes = 2 + xwing_recipient(0xb1).canonical_bytes().unwrap().len();
    let count_at = bytes.len() - tail_len(&pool) - recipient_bytes - 1;
    assert_eq!(bytes[count_at], 1);
    for count in [0, 5] {
        let mut changed = bytes.clone();
        changed[count_at] = count;
        assert_eq!(
            RightsRequestV2::from_canonical_bytes(&changed),
            Err(ContractError::InvalidField("rights_request.recipients"))
        );
    }
}

#[test]
fn guard_rights_v2_chain_zero_is_refused() {
    assert_eq!(
        RightsRequestV2::new_direct(
            p5_kat_binding(),
            RightsActionV1::View,
            xwing_recipient(0xa0),
            NOW,
            NOW + 120,
            ReplayNonce16::new([0x55; 16]),
            0,
        ),
        Err(ContractError::InvalidField("rights_request.chain_id"))
    );
    let mut bytes = pool_request().canonical_bytes().unwrap();
    let chain_at = bytes.len() - 8;
    bytes[chain_at..].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        RightsRequestV2::from_canonical_bytes(&bytes),
        Err(ContractError::InvalidField("rights_request.chain_id"))
    );
}

#[test]
fn guard_rights_v2_unknown_tag_is_refused() {
    let pool = pool_request();
    let mut bytes = pool.canonical_bytes().unwrap();
    let tag_at = bytes.len() - tail_len(&pool);
    for tag in [2, 0xff] {
        bytes[tag_at] = tag;
        assert_eq!(
            RightsRequestV2::from_canonical_bytes(&bytes),
            Err(ContractError::InvalidField("rights_request.delivery_key"))
        );
    }
}

#[test]
fn guard_rights_v2_trailing_bytes_are_refused() {
    for request in [direct_request(), pool_request()] {
        let mut bytes = request.canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            RightsRequestV2::from_canonical_bytes(&bytes),
            Err(ContractError::TrailingBytes)
        );
    }
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

#[test]
fn rights_v2_direct_text_uses_device_line() {
    let request = direct_request();
    let message = request.signing_message().unwrap();
    assert_eq!(
        line(&message, "Device:"),
        format!(
            "Device:  0x{}",
            fingerprint(xwing_recipient(0xa0).key_id().as_bytes())
        )
    );
    assert!(!message.contains("Delivery key:"), "{message}");
    assert!(!message.contains("Server:"), "{message}");
}

#[test]
fn rights_v2_pool_text_uses_delivery_key_and_server_lines() {
    let request = pool_request();
    let message = request.signing_message().unwrap();
    let delivery = request.delivery_key().unwrap();
    let mut expected = vec![
        format!("ElastOS rights-request/v2 chain {P5_CHAIN}"),
        String::new(),
        "Open protected content.".to_string(),
        String::new(),
        "Action:  View".to_string(),
        format!("Account: 0x{}", encode(wallet(7).as_bytes())),
        format!(
            "Delivery key: 0x{}",
            fingerprint(delivery.digest().as_bytes())
        ),
        format!(
            "Profile: 0x{}",
            fingerprint(request.binding().profile().public_key_bytes())
        ),
        format!(
            "Pool:    0x{} (2 of 3)",
            fingerprint(digest(0x35).as_bytes())
        ),
    ];
    for recipient in request.recipients() {
        expected.push(format!(
            "Server:  0x{}",
            fingerprint(recipient.key_id().as_bytes())
        ));
    }
    expected.push(format!("Expires: {} (unix seconds)", NOW + 120));
    expected.push(format!(
        "Request: 0x{}",
        encode(request.request_hash().unwrap().as_bytes())
    ));
    assert_eq!(message, format!("{}\n", expected.join("\n")));

    assert!(!message.contains("Device:"), "{message}");
    assert_eq!(
        line(&message, "Delivery key:"),
        format!(
            "Delivery key: 0x{}",
            fingerprint(delivery.digest().as_bytes())
        )
    );
    assert!(message.ends_with('\n') && !message.ends_with("\n\n"));
    assert!(!message.contains('\r'));
    let at = |label: &str| message.find(label).unwrap();
    assert!(at("Pool:") < at("Server:"));
    assert!(message.rfind("Server:").unwrap() < at("Expires:"));
    assert_eq!(message.matches("Server:  0x").count(), 3);
}

#[test]
fn rights_v2_changed_delivery_or_server_changes_a_visible_line() {
    let base = pool_request().signing_message().unwrap();
    let visible = |message: &str| {
        message
            .lines()
            .filter(|line| !line.starts_with("Request:"))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    let other_delivery = pool_request_with(
        vec![
            xwing_recipient(0xb1),
            xwing_recipient(0xb2),
            xwing_recipient(0xb3),
        ],
        DeliveryKeyIdentityV1::new(digest(0xa1)),
        P5_CHAIN,
    )
    .signing_message()
    .unwrap();
    assert_ne!(
        line(&base, "Delivery key:"),
        line(&other_delivery, "Delivery key:")
    );
    assert_ne!(visible(&base), visible(&other_delivery));

    let other_server = pool_request_with(
        vec![
            xwing_recipient(0xb1),
            xwing_recipient(0xb2),
            xwing_recipient(0xb4),
        ],
        DeliveryKeyIdentityV1::new(digest(0xa0)),
        P5_CHAIN,
    )
    .signing_message()
    .unwrap();
    assert_ne!(visible(&base), visible(&other_server));
    assert!(other_server.contains(&format!(
        "Server:  0x{}",
        fingerprint(digest(0xb4).as_bytes())
    )));
}

#[test]
fn rights_v2_changed_chain_changes_line_one() {
    let base = pool_request().signing_message().unwrap();
    let other = pool_request_with(
        vec![
            xwing_recipient(0xb1),
            xwing_recipient(0xb2),
            xwing_recipient(0xb3),
        ],
        DeliveryKeyIdentityV1::new(digest(0xa0)),
        20,
    )
    .signing_message()
    .unwrap();
    assert_eq!(
        base.lines().next(),
        Some("ElastOS rights-request/v2 chain 8453")
    );
    assert_eq!(
        other.lines().next(),
        Some("ElastOS rights-request/v2 chain 20")
    );
}

// ---------------------------------------------------------------------------
// Length bounds (§3)
// ---------------------------------------------------------------------------

#[test]
fn rights_v2_direct_text_at_legal_maximum_is_365_bytes() {
    let message = maximum_request(None).signing_message().unwrap();
    assert_eq!(message.len(), 365, "{message}");
    assert!(message.len() <= MAX_RIGHTS_V2_DIRECT_TEXT_BYTES);
    assert_eq!(
        direct_request().signing_message().unwrap().len(),
        333,
        "V-D is the P5 fixture length"
    );
}

#[test]
fn rights_v2_pool_text_with_one_server_at_legal_maximum_is_398_bytes() {
    let message = maximum_request(Some(1)).signing_message().unwrap();
    assert_eq!(message.len(), 398, "{message}");
    assert!(message.len() <= MAX_RIGHTS_V2_POOL_TEXT_BYTES);
}

#[test]
fn rights_v2_pool_text_at_legal_maximum_is_482_bytes() {
    let request = maximum_request(Some(4));
    let message = request.signing_message().unwrap();
    assert_eq!(message.len(), 482, "{message}");
    assert_eq!(message.len(), MAX_RIGHTS_V2_POOL_TEXT_BYTES);
    assert_eq!(request.action(), RightsActionV1::Download);
    assert_eq!(request.chain_id(), u64::MAX);
    assert_eq!(request.expires_at(), u64::MAX);
    assert!(message.contains("(16 of 16)"));
    assert_eq!(pool_request().signing_message().unwrap().len(), 422);
}

// ---------------------------------------------------------------------------
// R4: V2 signs only the v2 text
// ---------------------------------------------------------------------------

#[test]
fn guard_rights_v2_signature_over_v1_layout_text_is_refused() {
    for request in [direct_request(), pool_request()] {
        let signed = WalletSignedRightsRequestV2::new(
            request.clone(),
            wallet_signature_over(&v1_layout_text(&request), 7),
        )
        .unwrap();
        assert_eq!(
            signed.verify_unclaimed_at(NOW + 1),
            Err(RightsError::WalletMismatch)
        );
    }
}

#[test]
fn rights_v2_signature_over_v2_text_verifies() {
    for request in [direct_request(), pool_request()] {
        let signed = WalletSignedRightsRequestV2::new(
            request.clone(),
            wallet_signature_over(&request.signing_message().unwrap(), 7),
        )
        .unwrap();
        assert_eq!(
            signed.verify_unclaimed_at(NOW + 1),
            Ok(request.request_hash().unwrap())
        );
    }
}

// ---------------------------------------------------------------------------
// R5: pre-alignment bytes are refused with a typed error
// ---------------------------------------------------------------------------

#[test]
fn guard_pre_alignment_v2_bytes_are_refused_as_unsupported() {
    let unsupported = ContractError::UnsupportedVersion(PRE_ALIGNMENT_V2);
    for n in 1..=4 {
        let bytes = archived_pre_alignment_v2_request_bytes(n);
        assert_eq!(
            RightsRequestV2::from_canonical_bytes(&bytes),
            Err(unsupported.clone())
        );
        assert_eq!(
            RightsRequestAnyV1::from_canonical_bytes(&bytes),
            Err(unsupported.clone())
        );
        let wrapped = archived_pre_alignment_v2_wrapper_bytes(n);
        assert_eq!(
            WalletSignedRightsRequestV2::from_canonical_bytes(&wrapped),
            Err(unsupported.clone())
        );
        assert_eq!(
            WalletSignedRightsRequestAnyV1::from_canonical_bytes(&wrapped),
            Err(unsupported.clone())
        );
    }
    // The V2 operation leg is `guard_pre_alignment_v2_rights_in_an_operation_are_refused_as_unsupported`
    // in `pool_tests.rs`, next to the operation fixture.
}

#[test]
fn truncated_unified_v2_request_is_an_ordinary_decode_error() {
    let pool = pool_request();
    let mut bytes = pool.canonical_bytes().unwrap();
    bytes.pop();
    // 73 - 1 = 72 bytes after the recipients: not the 64-byte rule.
    assert_eq!(tail_len(&pool) - 1, 72);
    assert_eq!(
        RightsRequestV2::from_canonical_bytes(&bytes),
        Err(ContractError::UnexpectedEnd)
    );
}

/// AD01-F9: the rule looks only at length, so a malformed tail of exactly
/// 64 bytes is classified with the old format. Both are refusals; this pins
/// the accepted collision.
#[test]
fn guard_malformed_64_byte_tail_is_classified_unsupported() {
    let pool = pool_request();
    let mut bytes = pool.canonical_bytes().unwrap();
    bytes.truncate(bytes.len() - 9);
    assert_eq!(tail_len(&pool) - 9, 64);
    assert_eq!(
        RightsRequestV2::from_canonical_bytes(&bytes),
        Err(ContractError::UnsupportedVersion(PRE_ALIGNMENT_V2))
    );
}

// ---------------------------------------------------------------------------
// Replay scope (AD01-F7): tag and delivery key
// ---------------------------------------------------------------------------

#[test]
fn rights_v2_replay_key_changes_with_tag_and_delivery() {
    // The same single recipient, with and without a delivery key.
    let direct = direct_request();
    let pool = pool_request_with(
        vec![xwing_recipient(0xa0)],
        DeliveryKeyIdentityV1::new(digest(0xa0)),
        P5_CHAIN,
    );
    let other_delivery = pool_request_with(
        vec![xwing_recipient(0xa0)],
        DeliveryKeyIdentityV1::new(digest(0xa1)),
        P5_CHAIN,
    );
    let keys = [direct, pool, other_delivery].map(|request| request.replay_claim_key().unwrap());
    assert_ne!(keys[0], keys[1], "tag 0 and tag 1 are different scopes");
    assert_ne!(keys[1], keys[2], "the delivery key is in the scope");
    assert_ne!(
        keys[0].authority_scope_hash(),
        keys[1].authority_scope_hash()
    );
    assert!(keys
        .iter()
        .all(|key| key.nonce() == ReplayNonce16::new([0x55; 16])));
}

// ---------------------------------------------------------------------------
// Vectors (step 8), append-only
// ---------------------------------------------------------------------------

/// Prints the values pinned below (`--ignored --nocapture`).
#[test]
#[ignore = "prints the ADV-01 vectors"]
fn rights_v2_vector_dump() {
    for (name, request) in [("V-D", direct_request()), ("V-P", pool_request())] {
        let bytes = request.canonical_bytes().unwrap();
        let message = request.signing_message().unwrap();
        let signed =
            WalletSignedRightsRequestV2::new(request.clone(), wallet_signature_over(&message, 7))
                .unwrap();
        let wrapper = signed.canonical_bytes().unwrap();
        println!(
            "{name} canonical ({} bytes): {}",
            bytes.len(),
            encode(&bytes)
        );
        println!(
            "{name} request hash: {}",
            encode(request.request_hash().unwrap().as_bytes())
        );
        println!("{name} text ({} bytes): {message:?}", message.len());
        println!("{name} eip191: {}", encode(request.signing_hash().unwrap()));
        println!("{name} signature: {}", encode(signed.wallet_signature()));
        println!(
            "{name} wrapper ({} bytes): {}",
            wrapper.len(),
            encode(&wrapper)
        );
        println!(
            "{name} wrapper sha256: {}",
            encode(Sha256::digest(&wrapper))
        );
        let key = request.replay_claim_key().unwrap();
        println!(
            "{name} replay key: scope {} nonce {}",
            encode(key.authority_scope_hash().as_bytes()),
            encode(key.nonce().as_bytes())
        );
    }
    println!(
        "V-MAX: {:?}",
        maximum_request(Some(4)).signing_message().unwrap()
    );
}

struct Vector {
    canonical_len: usize,
    canonical_hex: &'static [&'static str],
    request_hash: &'static str,
    text: &'static str,
    eip191_digest: &'static str,
    wallet_signature: &'static str,
    wrapper_len: usize,
    wrapper_hex: &'static [&'static str],
    wrapper_sha256: &'static str,
}

fn assert_vector(request: &RightsRequestV2, vector: &Vector) {
    let bytes = request.canonical_bytes().unwrap();
    assert_eq!(bytes.len(), vector.canonical_len);
    assert_eq!(encode(&bytes), vector.canonical_hex.concat());
    assert_eq!(
        encode(request.request_hash().unwrap().as_bytes()),
        vector.request_hash
    );
    let message = request.signing_message().unwrap();
    assert_eq!(message, vector.text);
    assert_eq!(
        encode(request.signing_hash().unwrap()),
        vector.eip191_digest
    );
    let signed =
        WalletSignedRightsRequestV2::new(request.clone(), wallet_signature_over(&message, 7))
            .unwrap();
    assert_eq!(encode(signed.wallet_signature()), vector.wallet_signature);
    let wrapper = signed.canonical_bytes().unwrap();
    assert_eq!(wrapper.len(), vector.wrapper_len);
    assert_eq!(encode(&wrapper), vector.wrapper_hex.concat());
    assert_eq!(encode(Sha256::digest(&wrapper)), vector.wrapper_sha256);
    assert_eq!(
        WalletSignedRightsRequestV2::from_canonical_bytes(&wrapper).unwrap(),
        signed
    );
    assert_eq!(
        signed.verify_unclaimed_at(NOW + 1),
        Ok(request.request_hash().unwrap())
    );
}

/// V-D: P5's fixture in the direct form (333-byte text).
#[test]
fn rights_v2_vector_v_d() {
    assert_vector(
        &direct_request(),
        &Vector {
            canonical_len: V_D_CANONICAL_LEN,
            canonical_hex: V_D_CANONICAL_HEX,
            request_hash: V_D_REQUEST_HASH,
            text: V_D_TEXT,
            eip191_digest: V_D_EIP191_DIGEST,
            wallet_signature: V_D_WALLET_SIGNATURE,
            wrapper_len: V_D_WRAPPER_LEN,
            wrapper_hex: V_D_WRAPPER_HEX,
            wrapper_sha256: V_D_WRAPPER_SHA256,
        },
    );
    assert_eq!(V_D_TEXT.len(), 333);
}

/// V-P: the same binding, servers `digest(0xb1..=0xb3)`, delivery
/// `digest(0xa0)` (422-byte text).
#[test]
fn rights_v2_vector_v_p() {
    assert_vector(
        &pool_request(),
        &Vector {
            canonical_len: V_P_CANONICAL_LEN,
            canonical_hex: V_P_CANONICAL_HEX,
            request_hash: V_P_REQUEST_HASH,
            text: V_P_TEXT,
            eip191_digest: V_P_EIP191_DIGEST,
            wallet_signature: V_P_WALLET_SIGNATURE,
            wrapper_len: V_P_WRAPPER_LEN,
            wrapper_hex: V_P_WRAPPER_HEX,
            wrapper_sha256: V_P_WRAPPER_SHA256,
        },
    );
    assert_eq!(V_P_TEXT.len(), 422);
}

/// V-MAX: the 482-byte pool text in full.
#[test]
fn rights_v2_vector_v_max() {
    assert_eq!(
        maximum_request(Some(4)).signing_message().unwrap(),
        V_MAX_TEXT
    );
    assert_eq!(V_MAX_TEXT.len(), 482);
}

/// V-SCOPE: the replay claim keys of V-D and V-P (scope hash and nonce).
#[test]
fn rights_v2_vector_v_scope() {
    for (request, scope_hash) in [
        (direct_request(), V_D_SCOPE_HASH),
        (pool_request(), V_P_SCOPE_HASH),
    ] {
        let key = request.replay_claim_key().unwrap();
        assert_eq!(encode(key.authority_scope_hash().as_bytes()), scope_hash);
        assert_eq!(key.nonce(), ReplayNonce16::new([0x55; 16]));
    }
}

// Appended 2026-11-12 (ADV-01). Computed independently (see the module
// comment); `rights_v2_vector_dump` prints the Rust values.

const V_D_CANONICAL_LEN: usize = 1061;
const V_D_CANONICAL_HEX: &[&str] = &[
    "656c6173746f732e70726f7465637465642d636f6e74656e742e7269676874732d726571756573742f7632000346656c",
    "6173746f732e70726f7465637465642d636f6e74656e742e62696e64696e672f7631000057656c6173746f732e70726f",
    "7465637465642d636f6e74656e742e656e637279707465642d636f6e74656e742f763100111111111111111111111111",
    "1111111111111111111111111111111111111111000000000000100001e8656c6173746f732e70726f7465637465642d",
    "636f6e74656e742e6b65792d656e76656c6f70652f7631000057656c6173746f732e70726f7465637465642d636f6e74",
    "656e742e656e637279707465642d636f6e74656e742f7631001111111111111111111111111111111111111111111111",
    "111111111111111111000000000000100022222222222222222222222222222222222222222222222222222222222222",
    "220000020076829d63f49117ce5a0cfa158520eb9c78b03bd24d81a49f2b2f2f43c98395f602030057656c6173746f73",
    "2e70726f7465637465642d636f6e74656e742e637573746f64792d706f6f6c2e6964656e746974792f76310035353535",
    "35353535353535353535353535353535353535353535353535353535000002000058656c6173746f732e70726f746563",
    "7465642d636f6e74656e742e637573746f64792d65706f63682d6964656e746974792f76310033333333333333333333",
    "3333333333333333333333333333333333333333333300000200006a656c6173746f732e70726f7465637465642d636f",
    "6e74656e742e637573746f64792d636f6d6d69747465652d617574686f72697a6174696f6e2e6964656e746974792f76",
    "31003636363636363636363636363636363636363636363636363636363636363636000002000058656c6173746f732e",
    "70726f7465637465642d636f6e74656e742e7269676874732d706f6c6963792d6964656e746974792f76310044444444",
    "4444444444444444444444444444444444444444444444444444444400000180004e656c6173746f732e70726f746563",
    "7465642d636f6e74656e742e70726f66696c652d6964656e746974792f7631009109db55f79797a396462fb895c2adce",
    "a7e8683c2f3056c07a5475155537b73e4a62316623ad457f02cdc5d997ded67a383ec569666666666666666666666666",
    "666666666666666666666666666666666666666601010084656c6173746f732e70726f7465637465642d636f6e74656e",
    "742e726563697069656e742d6b65792d6964656e746974792f763100002e656c6173746f732d7877696e672d64726166",
    "7430362d686b64662d7368613235362d61657332353667636d2f7631a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
    "a0a0a0a0a0a0a0a0a0a0a0a0000000000077359400000000007735947855555555555555555555555555555555000000",
    "0000002105",
];
const V_D_REQUEST_HASH: &str = "2710237178efbc9ff255b3a5cb814be1c77f848b66010baa9872cc38d838585c";
const V_D_TEXT: &str = "ElastOS rights-request/v2 chain 8453\n\nOpen protected content.\n\nAction:  View\nAccount: 0x4a62316623ad457f02cdc5d997ded67a383ec569\nDevice:  0xa0a0a0a0a0a0a0a0\nProfile: 0x9109db55f79797a3\nPool:    0x3535353535353535 (2 of 3)\nExpires: 2000000120 (unix seconds)\nRequest: 0x2710237178efbc9ff255b3a5cb814be1c77f848b66010baa9872cc38d838585c\n";
const V_D_EIP191_DIGEST: &str = "e1d2bfb28d1a7135d5f3950054bfab3128b40e624d8c6de73cdf61561e7a0771";
const V_D_WALLET_SIGNATURE: &str = "74db06e2cc61b683d65e7e3848d8e26ed975ae370c36a844cdac6df5829f742f4af6321b1701d7120a1f5c604b96f89f64c4d79600f2507c84c25eb3b66087dc00";
const V_D_WRAPPER_LEN: usize = 1188;
const V_D_WRAPPER_HEX: &[&str] = &[
    "656c6173746f732e70726f7465637465642d636f6e74656e742e77616c6c65742d7369676e65642d7269676874732d72",
    "6571756573742f7632000425656c6173746f732e70726f7465637465642d636f6e74656e742e7269676874732d726571",
    "756573742f7632000346656c6173746f732e70726f7465637465642d636f6e74656e742e62696e64696e672f76310000",
    "57656c6173746f732e70726f7465637465642d636f6e74656e742e656e637279707465642d636f6e74656e742f763100",
    "1111111111111111111111111111111111111111111111111111111111111111000000000000100001e8656c6173746f",
    "732e70726f7465637465642d636f6e74656e742e6b65792d656e76656c6f70652f7631000057656c6173746f732e7072",
    "6f7465637465642d636f6e74656e742e656e637279707465642d636f6e74656e742f7631001111111111111111111111",
    "111111111111111111111111111111111111111111000000000000100022222222222222222222222222222222222222",
    "222222222222222222222222220000020076829d63f49117ce5a0cfa158520eb9c78b03bd24d81a49f2b2f2f43c98395",
    "f602030057656c6173746f732e70726f7465637465642d636f6e74656e742e637573746f64792d706f6f6c2e6964656e",
    "746974792f7631003535353535353535353535353535353535353535353535353535353535353535000002000058656c",
    "6173746f732e70726f7465637465642d636f6e74656e742e637573746f64792d65706f63682d6964656e746974792f76",
    "3100333333333333333333333333333333333333333333333333333333333333333300000200006a656c6173746f732e",
    "70726f7465637465642d636f6e74656e742e637573746f64792d636f6d6d69747465652d617574686f72697a6174696f",
    "6e2e6964656e746974792f76310036363636363636363636363636363636363636363636363636363636363636360000",
    "02000058656c6173746f732e70726f7465637465642d636f6e74656e742e7269676874732d706f6c6963792d6964656e",
    "746974792f763100444444444444444444444444444444444444444444444444444444444444444400000180004e656c",
    "6173746f732e70726f7465637465642d636f6e74656e742e70726f66696c652d6964656e746974792f7631009109db55",
    "f79797a396462fb895c2adcea7e8683c2f3056c07a5475155537b73e4a62316623ad457f02cdc5d997ded67a383ec569",
    "666666666666666666666666666666666666666666666666666666666666666601010084656c6173746f732e70726f74",
    "65637465642d636f6e74656e742e726563697069656e742d6b65792d6964656e746974792f763100002e656c6173746f",
    "732d7877696e672d647261667430362d686b64662d7368613235362d61657332353667636d2f7631a0a0a0a0a0a0a0a0",
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000000077359400000000007735947855555555555555",
    "5555555555555555550000000000002105004174db06e2cc61b683d65e7e3848d8e26ed975ae370c36a844cdac6df582",
    "9f742f4af6321b1701d7120a1f5c604b96f89f64c4d79600f2507c84c25eb3b66087dc00",
];
const V_D_WRAPPER_SHA256: &str = "2d1ca6437924a53707f4baf79023a96b34a718ac28948037a300852dcbb06fcd";
const V_D_SCOPE_HASH: &str = "d0364a70559dae18ecad47106bf858cf222369afc65e7948b1cfe3797015e74f";

const V_P_CANONICAL_LEN: usize = 1361;
const V_P_CANONICAL_HEX: &[&str] = &[
    "656c6173746f732e70726f7465637465642d636f6e74656e742e7269676874732d726571756573742f7632000346656c",
    "6173746f732e70726f7465637465642d636f6e74656e742e62696e64696e672f7631000057656c6173746f732e70726f",
    "7465637465642d636f6e74656e742e656e637279707465642d636f6e74656e742f763100111111111111111111111111",
    "1111111111111111111111111111111111111111000000000000100001e8656c6173746f732e70726f7465637465642d",
    "636f6e74656e742e6b65792d656e76656c6f70652f7631000057656c6173746f732e70726f7465637465642d636f6e74",
    "656e742e656e637279707465642d636f6e74656e742f7631001111111111111111111111111111111111111111111111",
    "111111111111111111000000000000100022222222222222222222222222222222222222222222222222222222222222",
    "220000020076829d63f49117ce5a0cfa158520eb9c78b03bd24d81a49f2b2f2f43c98395f602030057656c6173746f73",
    "2e70726f7465637465642d636f6e74656e742e637573746f64792d706f6f6c2e6964656e746974792f76310035353535",
    "35353535353535353535353535353535353535353535353535353535000002000058656c6173746f732e70726f746563",
    "7465642d636f6e74656e742e637573746f64792d65706f63682d6964656e746974792f76310033333333333333333333",
    "3333333333333333333333333333333333333333333300000200006a656c6173746f732e70726f7465637465642d636f",
    "6e74656e742e637573746f64792d636f6d6d69747465652d617574686f72697a6174696f6e2e6964656e746974792f76",
    "31003636363636363636363636363636363636363636363636363636363636363636000002000058656c6173746f732e",
    "70726f7465637465642d636f6e74656e742e7269676874732d706f6c6963792d6964656e746974792f76310044444444",
    "4444444444444444444444444444444444444444444444444444444400000180004e656c6173746f732e70726f746563",
    "7465642d636f6e74656e742e70726f66696c652d6964656e746974792f7631009109db55f79797a396462fb895c2adce",
    "a7e8683c2f3056c07a5475155537b73e4a62316623ad457f02cdc5d997ded67a383ec569666666666666666666666666",
    "666666666666666666666666666666666666666601030084656c6173746f732e70726f7465637465642d636f6e74656e",
    "742e726563697069656e742d6b65792d6964656e746974792f763100002e656c6173746f732d7877696e672d64726166",
    "7430362d686b64662d7368613235362d61657332353667636d2f7631b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    "b1b1b1b1b1b1b1b1b1b1b1b10084656c6173746f732e70726f7465637465642d636f6e74656e742e726563697069656e",
    "742d6b65792d6964656e746974792f763100002e656c6173746f732d7877696e672d647261667430362d686b64662d73",
    "68613235362d61657332353667636d2f7631b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    "b2b20084656c6173746f732e70726f7465637465642d636f6e74656e742e726563697069656e742d6b65792d6964656e",
    "746974792f763100002e656c6173746f732d7877696e672d647261667430362d686b64662d7368613235362d61657332",
    "353667636d2f7631b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b301a0a0a0a0a0a0a0",
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000077359400000000007735947855555555555555",
    "5555555555555555550000000000002105",
];
const V_P_REQUEST_HASH: &str = "8d57a4bcc483c6486c213cc8713d3df254625bf045d335e3bb94c61c10d9cf58";
const V_P_TEXT: &str = "ElastOS rights-request/v2 chain 8453\n\nOpen protected content.\n\nAction:  View\nAccount: 0x4a62316623ad457f02cdc5d997ded67a383ec569\nDelivery key: 0xa0a0a0a0a0a0a0a0\nProfile: 0x9109db55f79797a3\nPool:    0x3535353535353535 (2 of 3)\nServer:  0xb1b1b1b1b1b1b1b1\nServer:  0xb2b2b2b2b2b2b2b2\nServer:  0xb3b3b3b3b3b3b3b3\nExpires: 2000000120 (unix seconds)\nRequest: 0x8d57a4bcc483c6486c213cc8713d3df254625bf045d335e3bb94c61c10d9cf58\n";
const V_P_EIP191_DIGEST: &str = "45234962a95fb27a1ed9b9b5c45f69eb504dade3f882f9bfae4ad131ca506ad8";
const V_P_WALLET_SIGNATURE: &str = "9eabe4233b7cac36945830e4fe652db6cd1f74cbc37e5d2ebdc8f71839546fe2148737a0f87810c696c594ef0322fec88fa37c6d168957a7e0d3c61782a02aa801";
const V_P_WRAPPER_LEN: usize = 1488;
const V_P_WRAPPER_HEX: &[&str] = &[
    "656c6173746f732e70726f7465637465642d636f6e74656e742e77616c6c65742d7369676e65642d7269676874732d72",
    "6571756573742f7632000551656c6173746f732e70726f7465637465642d636f6e74656e742e7269676874732d726571",
    "756573742f7632000346656c6173746f732e70726f7465637465642d636f6e74656e742e62696e64696e672f76310000",
    "57656c6173746f732e70726f7465637465642d636f6e74656e742e656e637279707465642d636f6e74656e742f763100",
    "1111111111111111111111111111111111111111111111111111111111111111000000000000100001e8656c6173746f",
    "732e70726f7465637465642d636f6e74656e742e6b65792d656e76656c6f70652f7631000057656c6173746f732e7072",
    "6f7465637465642d636f6e74656e742e656e637279707465642d636f6e74656e742f7631001111111111111111111111",
    "111111111111111111111111111111111111111111000000000000100022222222222222222222222222222222222222",
    "222222222222222222222222220000020076829d63f49117ce5a0cfa158520eb9c78b03bd24d81a49f2b2f2f43c98395",
    "f602030057656c6173746f732e70726f7465637465642d636f6e74656e742e637573746f64792d706f6f6c2e6964656e",
    "746974792f7631003535353535353535353535353535353535353535353535353535353535353535000002000058656c",
    "6173746f732e70726f7465637465642d636f6e74656e742e637573746f64792d65706f63682d6964656e746974792f76",
    "3100333333333333333333333333333333333333333333333333333333333333333300000200006a656c6173746f732e",
    "70726f7465637465642d636f6e74656e742e637573746f64792d636f6d6d69747465652d617574686f72697a6174696f",
    "6e2e6964656e746974792f76310036363636363636363636363636363636363636363636363636363636363636360000",
    "02000058656c6173746f732e70726f7465637465642d636f6e74656e742e7269676874732d706f6c6963792d6964656e",
    "746974792f763100444444444444444444444444444444444444444444444444444444444444444400000180004e656c",
    "6173746f732e70726f7465637465642d636f6e74656e742e70726f66696c652d6964656e746974792f7631009109db55",
    "f79797a396462fb895c2adcea7e8683c2f3056c07a5475155537b73e4a62316623ad457f02cdc5d997ded67a383ec569",
    "666666666666666666666666666666666666666666666666666666666666666601030084656c6173746f732e70726f74",
    "65637465642d636f6e74656e742e726563697069656e742d6b65792d6964656e746974792f763100002e656c6173746f",
    "732d7877696e672d647261667430362d686b64662d7368613235362d61657332353667636d2f7631b1b1b1b1b1b1b1b1",
    "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10084656c6173746f732e70726f7465637465642d636f6e74",
    "656e742e726563697069656e742d6b65792d6964656e746974792f763100002e656c6173746f732d7877696e672d6472",
    "61667430362d686b64662d7368613235362d61657332353667636d2f7631b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    "b2b2b2b2b2b2b2b2b2b2b2b2b2b20084656c6173746f732e70726f7465637465642d636f6e74656e742e726563697069",
    "656e742d6b65792d6964656e746974792f763100002e656c6173746f732d7877696e672d647261667430362d686b6466",
    "2d7368613235362d61657332353667636d2f7631b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
    "b3b3b3b301a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000077359400000000",
    "007735947855555555555555555555555555555555000000000000210500419eabe4233b7cac36945830e4fe652db6cd",
    "1f74cbc37e5d2ebdc8f71839546fe2148737a0f87810c696c594ef0322fec88fa37c6d168957a7e0d3c61782a02aa801",
];
const V_P_WRAPPER_SHA256: &str = "6b2ad232d04393d07f3276278f7954351af174bc9c2bd0a06b85444de33a7585";
const V_P_SCOPE_HASH: &str = "dae496a9f204b06c5acce435f5dc51333fb5fa246f09b891979a9dc2dc8a2359";

const V_MAX_TEXT: &str = "ElastOS rights-request/v2 chain 18446744073709551615\n\nOpen protected content.\n\nAction:  Download\nAccount: 0x4a62316623ad457f02cdc5d997ded67a383ec569\nDelivery key: 0xa0a0a0a0a0a0a0a0\nProfile: 0x9109db55f79797a3\nPool:    0x3535353535353535 (16 of 16)\nServer:  0xb1b1b1b1b1b1b1b1\nServer:  0xb2b2b2b2b2b2b2b2\nServer:  0xb3b3b3b3b3b3b3b3\nServer:  0xb4b4b4b4b4b4b4b4\nExpires: 18446744073709551615 (unix seconds)\nRequest: 0x972c01b78f7ef3d615d4682eac6d6f80519e03c2e22c15a852d98ed00abb736f\n";
