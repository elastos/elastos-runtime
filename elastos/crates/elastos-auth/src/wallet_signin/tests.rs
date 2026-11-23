use super::*;
use crate::{ethereum_signed_message_hash, normalize_evm_address};
use k256::ecdsa::SigningKey;
use std::collections::HashSet;

const NOW: u64 = 1_800_000_000;
const SECRET: [u8; 32] = [9; 32];

fn input() -> WalletProofInput {
    WalletProofInput {
        origin: "https://home.example".into(),
        uri: "https://home.example/login".into(),
        home_id: "home-1".into(),
        chain_id: 8453,
        address: "0x4a62316623ad457F02cDC5D997deD67a383EC569".into(),
        nonce: [11; 32],
        issued_at: NOW,
        ttl_secs: DEFAULT_WALLET_PROOF_TTL_SECS,
        purpose: WalletProofPurpose::SignIn {
            account_id: "account-1".into(),
        },
    }
}

fn sign_with(key: u8, message: &str) -> Vec<u8> {
    let key = SigningKey::from_bytes((&[key; 32]).into()).unwrap();
    let (signature, recovery) = key
        .sign_prehash_recoverable(&ethereum_signed_message_hash(message.as_bytes()))
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    bytes
}

fn verify(
    challenge: &WalletProofChallenge,
    message: &str,
    signature: &[u8],
    now: u64,
) -> Result<WalletProofToConsume, WalletProofError> {
    challenge.verify(message, signature, &input().purpose, &SECRET, now)
}

fn refuses_rebinding(change: impl FnOnce(&mut WalletProofInput)) {
    let original = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let mut changed = input();
    change(&mut changed);
    let origin_line = format!(
        "{} wants you to sign in with your Ethereum account:\n",
        changed.origin
    );
    let target = WalletProofChallenge::new(changed, &SECRET).unwrap();
    assert!(target.message().starts_with(&origin_line));
    assert_ne!(target.message(), original.message());
    assert!(matches!(
        verify(
            &target,
            original.message(),
            &sign_with(7, original.message()),
            NOW
        ),
        Err(WalletProofError::TextMismatch)
    ));
}

// Break: omit configured origin from the builder.
#[test]
fn origin_is_bound() {
    refuses_rebinding(|i| {
        i.origin = "https://other.example".into();
        i.uri = "https://other.example/login".into();
    });
    refuses_rebinding(|i| {
        i.origin = "http://home.example".into();
        i.uri = "http://home.example/login".into();
    });
    refuses_rebinding(|i| {
        i.origin = "https://home.example:8443".into();
        i.uri = "https://home.example:8443/login".into();
    });
}

// Break: omit configured URI from the builder.
#[test]
fn uri_is_bound() {
    refuses_rebinding(|i| i.uri.push_str("/other"));
}

// Break: omit stable Home ID from the resources.
#[test]
fn home_id_is_bound() {
    refuses_rebinding(|i| i.home_id = "home-2".into());
}

// Break: replace the supplied chain with a constant.
#[test]
fn chain_is_bound() {
    refuses_rebinding(|i| i.chain_id = 1);
}

// Break: replace the supplied address with a constant.
#[test]
fn address_is_bound() {
    refuses_rebinding(|i| i.address = "0x0000000000000000000000000000000000000001".into());
}

// Break: replace the nonce with a fixed value.
#[test]
fn nonce_is_bound() {
    refuses_rebinding(|i| i.nonce = [12; 32]);
}

// Break: replace issued_at with a fixed time.
#[test]
fn issued_at_is_bound() {
    refuses_rebinding(|i| {
        i.issued_at += 1;
        i.ttl_secs -= 1; // Hold expiry fixed so issuance is checked on its own.
    });
}

// Break: ignore the caller's shorter TTL.
#[test]
fn expiry_is_bound() {
    refuses_rebinding(|i| i.ttl_secs -= 1);
}

// Break: omit the ceremony commitment resource.
#[test]
fn ceremony_is_in_signed_text() {
    let original = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let other = WalletProofChallenge::new(input(), &[10; 32]).unwrap();
    assert_ne!(original.message(), other.message());
    assert!(matches!(
        verify(
            &other,
            original.message(),
            &sign_with(7, original.message()),
            NOW
        ),
        Err(WalletProofError::TextMismatch)
    ));
    assert!(!original.message().contains(&hex::encode(SECRET)));
}

// Break: remove the browser-secret possession comparison.
#[test]
fn browser_must_know_ceremony_secret() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    assert!(matches!(
        c.verify(
            c.message(),
            &sign_with(7, c.message()),
            &input().purpose,
            &[10; 32],
            NOW
        ),
        Err(WalletProofError::CeremonyMismatch)
    ));
}

fn purposes() -> Vec<WalletProofPurpose> {
    use WalletProofPurpose::*;
    vec![
        CreateAccount,
        SignIn {
            account_id: "account-1".into(),
        },
        ConfirmOperation {
            account_id: "account-1".into(),
            operation: "export-kit".into(),
            digest: [1; 32],
        },
        AddMethod {
            account_id: "account-1".into(),
            method_digest: [2; 32],
        },
        AddMethodDuringRecovery {
            account_id: "account-1".into(),
            method_digest: [2; 32],
        },
    ]
}

fn active_purposes() -> Vec<WalletProofPurpose> {
    purposes()
        .into_iter()
        .filter(|purpose| {
            matches!(
                purpose,
                WalletProofPurpose::SignIn { .. } | WalletProofPurpose::AddMethod { .. }
            )
        })
        .collect()
}

// Break: use one statement for all purposes, or omit expected-purpose comparison.
#[test]
fn every_purpose_is_visible_and_cross_purpose_reuse_fails() {
    let purposes = purposes();
    let mut messages = HashSet::new();
    for purpose in &active_purposes() {
        let mut i = input();
        i.purpose = purpose.clone();
        let c = WalletProofChallenge::new(i, &SECRET).unwrap();
        let signature = sign_with(7, c.message());
        assert!(messages.insert(c.message().to_string()));
        let phrase = match purpose {
            WalletProofPurpose::CreateAccount => "Create an account",
            WalletProofPurpose::SignIn { .. } => "Sign in for account",
            WalletProofPurpose::ConfirmOperation { .. } => "Confirm operation export-kit; SHA-256:",
            WalletProofPurpose::AddMethod { .. } => "Add a sign-in method; SHA-256:",
            WalletProofPurpose::AddMethodDuringRecovery { .. } => {
                "Add a sign-in method during recovery; SHA-256:"
            }
        };
        assert!(c.message().contains(phrase));
        for expected in &purposes {
            let result = c.verify(c.message(), &signature, expected, &SECRET, NOW);
            if purpose == expected {
                let result = result.unwrap().consume(&mut Store::default()).unwrap();
                assert_eq!(result.purpose(), purpose);
            } else {
                assert!(matches!(result, Err(WalletProofError::PurposeMismatch)));
                let mut other = input();
                other.purpose = expected.clone();
                let other = WalletProofChallenge::new(other, &SECRET);
                if !active_purposes().contains(expected) {
                    assert_eq!(other.err(), Some(WalletProofError::InvalidInput));
                    continue;
                }
                let other = other.unwrap();
                assert!(matches!(
                    other.verify(c.message(), &signature, expected, &SECRET, NOW),
                    Err(WalletProofError::TextMismatch)
                ));
            }
        }
    }
}

// Break: omit account ID from any account-bound statement.
#[test]
fn account_intent_is_bound() {
    for purpose in active_purposes() {
        let mut i = input();
        i.purpose = purpose;
        let original = WalletProofChallenge::new(i.clone(), &SECRET).unwrap();
        match &mut i.purpose {
            WalletProofPurpose::SignIn { account_id }
            | WalletProofPurpose::ConfirmOperation { account_id, .. }
            | WalletProofPurpose::AddMethod { account_id, .. }
            | WalletProofPurpose::AddMethodDuringRecovery { account_id, .. } => {
                *account_id = "account-2".into()
            }
            WalletProofPurpose::CreateAccount => unreachable!(),
        }
        let expected = i.purpose.clone();
        let other = WalletProofChallenge::new(i, &SECRET).unwrap();
        assert_ne!(original.message(), other.message());
        assert!(matches!(
            other.verify(
                original.message(),
                &sign_with(7, original.message()),
                &expected,
                &SECRET,
                NOW
            ),
            Err(WalletProofError::TextMismatch)
        ));
    }
}

// Break: omit operation name or digest from the confirmation statement.
#[test]
fn operation_name_and_digest_are_bound() {
    let mut i = input();
    i.purpose = purposes()[2].clone();
    let original = i.purpose.statement().unwrap();
    for change_name in [true, false] {
        let mut changed = i.clone();
        if let WalletProofPurpose::ConfirmOperation {
            operation, digest, ..
        } = &mut changed.purpose
        {
            if change_name {
                *operation = "import-kit".into();
            } else {
                *digest = [3; 32];
            }
        }
        assert_ne!(changed.purpose.statement().unwrap(), original);
        assert_eq!(
            WalletProofChallenge::new(changed, &SECRET).err(),
            Some(WalletProofError::InvalidInput)
        );
    }
}

// Break: omit the proposed method's digest from either add-purpose statement.
#[test]
fn added_method_digest_is_bound() {
    for purpose in active_purposes()
        .into_iter()
        .filter(|p| matches!(p, WalletProofPurpose::AddMethod { .. }))
    {
        let mut i = input();
        i.purpose = purpose;
        let original = WalletProofChallenge::new(i.clone(), &SECRET).unwrap();
        match &mut i.purpose {
            WalletProofPurpose::AddMethod { method_digest, .. }
            | WalletProofPurpose::AddMethodDuringRecovery { method_digest, .. } => {
                *method_digest = [4; 32]
            }
            _ => unreachable!(),
        }
        let expected = i.purpose.clone();
        let other = WalletProofChallenge::new(i, &SECRET).unwrap();
        assert_ne!(other.message(), original.message());
        assert!(matches!(
            other.verify(
                original.message(),
                &sign_with(7, original.message()),
                &expected,
                &SECRET,
                NOW
            ),
            Err(WalletProofError::TextMismatch)
        ));
    }
}

// Break: replace exact-text comparison with parsed-field-only verification.
#[test]
fn altered_text_is_refused_even_with_valid_signature() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    for message in [
        c.message()
            .replace("Sign in for account", "Add a method for account"),
        c.message().replace('\n', "\r\n"),
        format!("{}\n", c.message()),
        c.message().replace("Version: 1", "Version: 2"),
        c.message().replace("Nonce:", "Nonce: 00\nNonce:"),
    ] {
        assert!(matches!(
            verify(&c, &message, &sign_with(7, &message), NOW),
            Err(WalletProofError::TextMismatch)
        ));
    }
}

// Break: compare signed text case-insensitively instead of byte-for-byte.
#[test]
fn case_only_text_change_is_refused() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let changed = c.message().replacen("Create", "create", 1);
    assert_ne!(changed, c.message());
    assert!(changed.eq_ignore_ascii_case(c.message()));
    assert!(matches!(
        verify(&c, &changed, &sign_with(7, &changed), NOW),
        Err(WalletProofError::TextMismatch)
    ));
}

// Break: allow clock skew before issuance, or change >= expiry to > expiry.
#[test]
fn clock_edges_use_inclusive_issue_and_exclusive_expiry() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let sig = sign_with(7, c.message());
    for now in [NOW, NOW + 299] {
        assert!(verify(&c, c.message(), &sig, now).is_ok());
    }
    assert!(matches!(
        verify(&c, c.message(), &sig, NOW - 1),
        Err(WalletProofError::NotYetValid)
    ));
    for now in [NOW + 300, u64::MAX] {
        assert!(matches!(
            verify(&c, c.message(), &sig, now),
            Err(WalletProofError::Expired)
        ));
    }
}

// Break: allow early use, or keep a not-yet-valid refusal after the clock recovers.
#[test]
fn no_clock_skew_and_retry_recovers() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let signature = sign_with(7, c.message());
    let mut store = Store::default();
    assert!(matches!(
        verify(&c, c.message(), &signature, NOW - 1),
        Err(WalletProofError::NotYetValid)
    ));
    assert!(store.consumed.is_empty());
    verify(&c, c.message(), &signature, NOW)
        .unwrap()
        .consume(&mut store)
        .unwrap();
    assert_eq!(store.effects.len(), 1);
}

// Break: allow zero/overlong TTL or timestamp wrap/fallback.
#[test]
fn invalid_lifetimes_and_unrepresentable_dates_are_refused() {
    for (issued_at, ttl_secs) in [
        (NOW, 0),
        (NOW, 301),
        (u64::MAX, 1),
        (u64::MAX - 10, 1),
        (253_402_300_799, 1),
    ] {
        let mut i = input();
        i.issued_at = issued_at;
        i.ttl_secs = ttl_secs;
        assert!(matches!(
            WalletProofChallenge::new(i, &SECRET),
            Err(WalletProofError::InvalidInput)
        ));
    }
    let mut i = input();
    i.ttl_secs = 1;
    let c = WalletProofChallenge::new(i, &SECRET).unwrap();
    assert!(verify(&c, c.message(), &sign_with(7, c.message()), NOW).is_ok());
    assert!(matches!(
        verify(&c, c.message(), &sign_with(7, c.message()), NOW + 1),
        Err(WalletProofError::Expired)
    ));
}

// Break: remove recovered-address equality.
#[test]
fn another_key_is_refused() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    assert!(matches!(
        verify(&c, c.message(), &sign_with(8, c.message()), NOW),
        Err(WalletProofError::InvalidSignature)
    ));
}

// Break: normalize high-S input into an accepted low-S proof.
#[test]
fn malleable_high_s_signature_is_refused() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let mut sig = sign_with(7, c.message());
    let parsed = Signature::try_from(&sig[..64]).unwrap();
    let high_s = Signature::from_scalars(parsed.r().to_bytes(), (-parsed.s()).to_bytes()).unwrap();
    assert!(high_s.normalize_s().is_some());
    sig[..64].copy_from_slice(&high_s.to_bytes());
    sig[64] ^= 1;
    assert!(matches!(
        verify(&c, c.message(), &sig, NOW),
        Err(WalletProofError::InvalidSignature)
    ));
}

// The local guard is deliberate defence in depth: shared recovery also refuses high-S.
#[test]
fn shared_recovery_also_refuses_high_s() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let mut signature = sign_with(7, c.message());
    let parsed = Signature::try_from(&signature[..64]).unwrap();
    let high_s = Signature::from_scalars(parsed.r().to_bytes(), (-parsed.s()).to_bytes()).unwrap();
    signature[..64].copy_from_slice(&high_s.to_bytes());
    signature[64] ^= 1;
    assert!(recover_evm_address(c.message(), &hex::encode(signature)).is_err());
}

// A relaxed local 64-byte gate still reaches the shared 65-byte requirement.
#[test]
fn shared_recovery_also_refuses_compact_form() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let signature = sign_with(7, c.message());
    let mut compact = signature[..64].to_vec();
    compact[32] |= signature[64] << 7;
    assert!(matches!(
        verify(&c, c.message(), &compact, NOW),
        Err(WalletProofError::InvalidSignature)
    ));
    assert_eq!(
        recover_evm_address(c.message(), &hex::encode(compact)).unwrap_err(),
        "EVM signature must be 65 bytes"
    );
}

// Break: accept compact, contract, or ERC-6492 wrapped forms instead of 65 bytes.
#[test]
fn contract_wrapped_compact_and_oversize_signatures_are_refused() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let signature = sign_with(7, c.message());
    let mut wrapped = signature.clone();
    wrapped.extend_from_slice(&[0x64, 0x92].repeat(16));
    for bad in [
        vec![],
        vec![0x16, 0x26, 0xba, 0x7e],
        signature[..64].to_vec(),
        wrapped,
        vec![0; 8193],
    ] {
        assert!(matches!(
            verify(&c, c.message(), &bad, NOW),
            Err(WalletProofError::InvalidSignature)
        ));
    }
}

// Break: accept a contract owner's recovered key as the contract address.
#[test]
fn contract_owner_signature_is_not_contract_proof() {
    let mut i = input();
    // The deployed WETH address from the EIP-4361 examples. The disposable key
    // signs the text, but its signature supplies no ERC-1271 contract authority.
    i.address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".into();
    let c = WalletProofChallenge::new(i, &SECRET).unwrap();
    assert!(matches!(
        verify(&c, c.message(), &sign_with(7, c.message()), NOW),
        Err(WalletProofError::InvalidSignature)
    ));
}

// Break: accept arbitrary v, zero scalars, or a corrupted signature.
#[test]
fn malformed_signatures_are_refused_and_standard_v_forms_work() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let signature = sign_with(7, c.message());
    assert!(verify(&c, c.message(), &signature, NOW).is_ok());
    let mut legacy = signature.clone();
    legacy[64] += 27;
    assert!(verify(&c, c.message(), &legacy, NOW).is_ok());
    for v in [2, 26, 29, 35, 255] {
        let mut bad = signature.clone();
        bad[64] = v;
        assert!(matches!(
            verify(&c, c.message(), &bad, NOW),
            Err(WalletProofError::InvalidSignature)
        ));
    }
    assert!(matches!(
        verify(&c, c.message(), &[0; 65], NOW),
        Err(WalletProofError::InvalidSignature)
    ));
    let mut bad = signature;
    bad[0] ^= 1;
    assert!(matches!(
        verify(&c, c.message(), &bad, NOW),
        Err(WalletProofError::InvalidSignature)
    ));
}

// Break: remove the 8 KiB limit, or reject exactly 8 KiB as oversize.
#[test]
fn text_size_limit_is_checked_before_crypto() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    assert_eq!(MAX_WALLET_PROOF_BYTES, 8_192);
    for len in [8_191, 8_192] {
        assert!(matches!(
            verify(&c, &"x".repeat(len), &[0; 65], NOW),
            Err(WalletProofError::TextMismatch)
        ));
    }
    assert!(matches!(
        verify(&c, &"x".repeat(8_193), &[0; 65], NOW),
        Err(WalletProofError::Oversize)
    ));
    let mut i = input();
    i.uri = "x".repeat(8_193);
    assert!(matches!(
        WalletProofChallenge::new(i, &SECRET),
        Err(WalletProofError::Oversize)
    ));
}

// Break: allow raw delimiters, unbounded fields or a foreign-origin URI into text.
#[test]
fn builder_refuses_injection_invalid_origin_and_unbounded_fields() {
    for origin in [
        "home.example",
        "https://home.example/path",
        "https://user@home.example",
        "https://home.example\\evil",
        "https://home.example\n",
    ] {
        let mut i = input();
        i.origin = origin.into();
        assert!(WalletProofChallenge::new(i, &SECRET).is_err());
    }
    for uri in [
        "https://other.example/login",
        "https://home.example/%zz",
        "https://home.example/\"",
        "https://home.example/#a#b",
        "https://home.example/é",
    ] {
        let mut i = input();
        i.uri = uri.into();
        assert!(WalletProofChallenge::new(i, &SECRET).is_err());
    }
    for value in [
        "".to_string(),
        "a\nNonce: injected".to_string(),
        "a b".to_string(),
        "a".repeat(513),
    ] {
        let mut i = input();
        i.home_id = value.clone();
        assert!(WalletProofChallenge::new(i, &SECRET).is_err());
        let mut i = input();
        i.purpose = WalletProofPurpose::SignIn {
            account_id: value.clone(),
        };
        assert!(WalletProofChallenge::new(i, &SECRET).is_err());
        let mut i = input();
        i.purpose = WalletProofPurpose::ConfirmOperation {
            account_id: "account-1".into(),
            operation: value,
            digest: [1; 32],
        };
        assert!(WalletProofChallenge::new(i, &SECRET).is_err());
    }
    let mut i = input();
    i.chain_id = 0;
    assert!(WalletProofChallenge::new(i, &SECRET).is_err());
    let mut i = input();
    i.address = "0x01".into();
    assert!(WalletProofChallenge::new(i, &SECRET).is_err());
}

// Break: accept a space inside an account ID or an operation name.
#[test]
fn spaces_inside_account_ids_and_operation_names_are_refused() {
    for mut purpose in purposes().into_iter().skip(1) {
        match &mut purpose {
            WalletProofPurpose::SignIn { account_id }
            | WalletProofPurpose::ConfirmOperation { account_id, .. }
            | WalletProofPurpose::AddMethod { account_id, .. }
            | WalletProofPurpose::AddMethodDuringRecovery { account_id, .. } => {
                *account_id = "account 1".into();
            }
            WalletProofPurpose::CreateAccount => unreachable!(),
        }
        let mut i = input();
        i.purpose = purpose;
        assert_eq!(
            WalletProofChallenge::new(i, &SECRET).err(),
            Some(WalletProofError::InvalidInput)
        );
    }
    let mut i = input();
    i.purpose = WalletProofPurpose::ConfirmOperation {
        account_id: "account-1".into(),
        operation: "export kit".into(),
        digest: [1; 32],
    };
    assert_eq!(
        WalletProofChallenge::new(i, &SECRET).err(),
        Some(WalletProofError::InvalidInput)
    );
}

// Break: silently repair mixed-case input with an invalid EIP-55 checksum.
#[test]
fn mixed_case_address_requires_checksum_uniform_case_is_canonicalised() {
    let expected = input().address;
    for address in [
        expected.clone(),
        format!("0x{}", expected[2..].to_ascii_lowercase()),
        format!("0x{}", expected[2..].to_ascii_uppercase()),
    ] {
        let mut i = input();
        i.address = address;
        let c = WalletProofChallenge::new(i, &SECRET).unwrap();
        assert_eq!(c.message().lines().nth(1), Some(expected.as_str()));
    }
    for (index, byte) in expected
        .bytes()
        .enumerate()
        .skip(2)
        .filter(|(_, b)| b.is_ascii_alphabetic())
    {
        let mut wrong = expected.clone().into_bytes();
        wrong[index] = if byte.is_ascii_lowercase() {
            byte.to_ascii_uppercase()
        } else {
            byte.to_ascii_lowercase()
        };
        let mut i = input();
        i.address = String::from_utf8(wrong).unwrap();
        assert_eq!(
            WalletProofChallenge::new(i, &SECRET).err(),
            Some(WalletProofError::InvalidInput)
        );
    }
}

// Break: allow raw URI brackets in a path, query or fragment.
#[test]
fn uri_brackets_are_confined_to_host() {
    for suffix in ["/[x]", "/x[y", "/x]y", "/?q=[x]", "/#part[x]"] {
        let mut i = input();
        i.uri = format!("{}{suffix}", i.origin);
        assert_eq!(
            WalletProofChallenge::new(i, &SECRET).err(),
            Some(WalletProofError::InvalidInput)
        );
    }
    let mut i = input();
    i.origin = "https://[::1]".into();
    i.uri = "https://[::1]/login?x=%5Bvalue%5D#part".into();
    assert!(WalletProofChallenge::new(i, &SECRET).is_ok());
}

// Break: allow uppercase hosts or reject uppercase path/query/fragment text.
#[test]
fn host_is_lowercase_and_uri_suffix_keeps_case() {
    for origin in [
        "https://HOME.example",
        "https://home.EXAMPLE",
        "https://[::ABCD]",
    ] {
        let mut i = input();
        i.origin = origin.into();
        i.uri = format!("{origin}/login");
        assert_eq!(
            WalletProofChallenge::new(i, &SECRET).err(),
            Some(WalletProofError::InvalidInput)
        );
    }
    let mut i = input();
    i.uri = "https://home.example/Login?Query=Value#Fragment".into();
    let c = WalletProofChallenge::new(i.clone(), &SECRET).unwrap();
    assert!(c.message().contains(&format!("URI: {}\n", i.uri)));
}

// Break: allow the all-zero value as a challenge nonce.
#[test]
fn all_zero_nonce_is_refused() {
    let mut i = input();
    i.nonce = [0; 32];
    assert_eq!(
        WalletProofChallenge::new(i, &SECRET).err(),
        Some(WalletProofError::InvalidInput)
    );
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    consumed: HashSet<(String, [u8; 32])>,
    effects: Vec<String>,
    retained_until: Vec<u64>,
    fail: bool,
}

impl WalletProofStore for Store {
    type Error = &'static str;

    fn insert_if_absent(
        &mut self,
        key: WalletProofUse,
        expires_at: u64,
        result: &WalletProofResult,
    ) -> Result<(), &'static str> {
        if self.fail {
            return Err("disk failed");
        }
        let identity = (key.home_id().to_string(), *key.nonce());
        if !self.consumed.insert(identity) {
            return Err("replay");
        }
        self.effects.push(result.binding().id());
        self.retained_until.push(expires_at);
        Ok(())
    }
}

// Break: release the proof result without calling the store.
#[test]
fn replay_and_replay_after_restart_are_refused() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let sig = sign_with(7, c.message());
    let mut store = Store::default();
    let result = verify(&c, c.message(), &sig, NOW)
        .unwrap()
        .consume(&mut store)
        .unwrap();
    assert_eq!(result.binding().chain_id, Some(8453));
    assert_eq!(
        result.binding().subject,
        input().address.to_ascii_lowercase()
    );
    assert_eq!(store.effects.len(), 1);
    assert_eq!(
        verify(&c, c.message(), &sig, NOW)
            .unwrap()
            .consume(&mut store),
        Err("replay")
    );
    let durable = serde_json::to_vec(&store).unwrap();
    drop(store);
    let mut restarted: Store = serde_json::from_slice(&durable).unwrap();
    let rebuilt = WalletProofChallenge::new(input(), &SECRET).unwrap();
    assert_eq!(
        verify(&rebuilt, rebuilt.message(), &sig, NOW + 1)
            .unwrap()
            .consume(&mut restarted),
        Err("replay")
    );
    assert_eq!(restarted.effects.len(), 1);
    assert_eq!(restarted.retained_until, vec![NOW + 300]);
}

// Break: discard the store's error.
#[test]
fn storage_failure_withholds_result_and_retry_can_commit() {
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let sig = sign_with(7, c.message());
    let mut store = Store {
        fail: true,
        ..Store::default()
    };
    assert_eq!(
        verify(&c, c.message(), &sig, NOW)
            .unwrap()
            .consume(&mut store),
        Err("disk failed")
    );
    assert!(store.consumed.is_empty());
    assert!(store.effects.is_empty());
    assert!(store.retained_until.is_empty());
    store.fail = false;
    assert!(verify(&c, c.message(), &sig, NOW)
        .unwrap()
        .consume(&mut store)
        .is_ok());
}

// Break: omit Home identity from the consumption key.
#[test]
fn same_nonce_on_two_homes_does_not_collide() {
    let mut store = Store::default();
    for home_id in ["home-1", "home-2"] {
        let mut i = input();
        i.home_id = home_id.into();
        let c = WalletProofChallenge::new(i, &SECRET).unwrap();
        let sig = sign_with(7, c.message());
        verify(&c, c.message(), &sig, NOW)
            .unwrap()
            .consume(&mut store)
            .unwrap();
        assert!(store.consumed.contains(&(home_id.into(), input().nonce)));
        assert_eq!(
            verify(&c, c.message(), &sig, NOW)
                .unwrap()
                .consume(&mut store),
            Err("replay")
        );
    }
    assert_eq!(store.effects.len(), 2);
    assert_eq!(store.retained_until, vec![NOW + 300; 2]);
}

// Break: derive value-printing Debug or Display for any new public type.
#[test]
fn every_public_type_redacts_debug_and_display() {
    fn formats(value: &(impl std::fmt::Debug + std::fmt::Display)) -> Vec<String> {
        vec![
            format!("{value:?}"),
            format!("{value:#?}"),
            format!("{value}"),
            format!("{value:#}"),
        ]
    }
    let c = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let signature = sign_with(7, c.message());
    let pending = verify(&c, c.message(), &signature, NOW).unwrap();
    let signature_hex = hex::encode(&signature);
    let nonce_hex = hex::encode(input().nonce);
    let mut sensitive_input = input();
    sensitive_input.origin = c.message().into();
    sensitive_input.uri = signature_hex.clone();
    sensitive_input.home_id = nonce_hex.clone();
    let mut output = formats(&sensitive_input);
    output.extend(formats(&c));
    output.extend(formats(&pending));
    output.extend(formats(&pending.consumption));
    output.extend(formats(&pending.result));
    for purpose in [
        WalletProofPurpose::CreateAccount,
        WalletProofPurpose::SignIn {
            account_id: input().address,
        },
        WalletProofPurpose::ConfirmOperation {
            account_id: c.message().into(),
            operation: signature_hex.clone(),
            digest: input().nonce,
        },
        WalletProofPurpose::AddMethod {
            account_id: nonce_hex.clone(),
            method_digest: input().nonce,
        },
        WalletProofPurpose::AddMethodDuringRecovery {
            account_id: signature_hex.clone(),
            method_digest: input().nonce,
        },
    ] {
        output.extend(formats(&purpose));
    }
    for error in [
        WalletProofError::InvalidInput,
        WalletProofError::Oversize,
        WalletProofError::TextMismatch,
        WalletProofError::PurposeMismatch,
        WalletProofError::CeremonyMismatch,
        WalletProofError::NotYetValid,
        WalletProofError::Expired,
        WalletProofError::InvalidSignature,
    ] {
        output.extend(formats(&error));
        assert_eq!(error.to_string(), "Wallet proof refused. Please try again.");
    }
    let private = [
        input().address,
        input().address.to_ascii_lowercase(),
        input().address.to_ascii_uppercase(),
        c.message().into(),
        "https://home.example".into(),
        nonce_hex.clone(),
        nonce_hex.to_ascii_uppercase(),
        format!("{:?}", input().nonce),
        format!("{:#?}", input().nonce),
        signature_hex.clone(),
        signature_hex.to_ascii_uppercase(),
        format!("{signature:?}"),
        format!("{signature:#?}"),
        hex::encode(SECRET),
    ];
    for text in output {
        for value in &private {
            assert!(
                !text.contains(value),
                "private proof material in formatted output"
            );
        }
    }
}

// Break: scope consumption by purpose or message hash rather than Home and nonce.
#[test]
fn consumption_key_is_shared_across_purposes() {
    let mut store = Store::default();
    for (index, purpose) in active_purposes().into_iter().enumerate() {
        let mut i = input();
        i.purpose = purpose.clone();
        let c = WalletProofChallenge::new(i, &SECRET).unwrap();
        let sig = sign_with(7, c.message());
        let result = c
            .verify(c.message(), &sig, &purpose, &SECRET, NOW)
            .unwrap()
            .consume(&mut store);
        if index == 0 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err("replay"));
        }
    }
    assert_eq!(store.effects.len(), 1);
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors.json")).unwrap()
}

// Break: alter the EIP-191 prefix, byte length, hashing or recovery.
#[test]
fn eip4361_examples_have_independent_known_answer_hashes_and_signatures() {
    for vector in vectors()["vectors"].as_array().unwrap().iter() {
        let message = vector["message"].as_str().unwrap();
        let signature = vector["signature"].as_str().unwrap();
        let (address, hash) = recover_evm_address(message, signature).unwrap();
        assert_eq!(
            address,
            normalize_evm_address(vector["signer"].as_str().unwrap())
        );
        assert_eq!(format!("0x{}", hex::encode(hash)), vector["hash"]);
    }
}

// Break: change any canonical byte, purpose, nonce encoding, checksum or commitment.
#[test]
fn scripted_phone_signing_primitive_matches_full_home_proof() {
    let fixture = vectors();
    let vector = &fixture["vectors"][0];
    let mut legacy = input();
    legacy.purpose = WalletProofPurpose::CreateAccount;
    assert_eq!(
        WalletProofChallenge::new(legacy, &SECRET).err(),
        Some(WalletProofError::InvalidInput)
    );
    let challenge = WalletProofChallenge::new(input(), &SECRET).unwrap();
    let signature = hex::decode(
        vector["signature"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify(
            &challenge,
            vector["message"].as_str().unwrap(),
            &signature,
            NOW
        ),
        Err(WalletProofError::TextMismatch)
    ));
    let mut store = Store::default();
    let result = verify(
        &challenge,
        challenge.message(),
        &sign_with(7, challenge.message()),
        NOW,
    )
    .unwrap()
    .consume(&mut store)
    .unwrap();
    assert_eq!(
        result.binding().subject,
        normalize_evm_address(vector["signer"].as_str().unwrap())
    );
}

#[test]
fn review_note_unused_wallet_proof_purposes_are_refused() {
    for purpose in [
        WalletProofPurpose::CreateAccount,
        WalletProofPurpose::ConfirmOperation {
            account_id: "account-1".into(),
            operation: "export-kit".into(),
            digest: [1; 32],
        },
        WalletProofPurpose::AddMethodDuringRecovery {
            account_id: "account-1".into(),
            method_digest: [2; 32],
        },
    ] {
        let mut i = input();
        i.purpose = purpose;
        assert_eq!(
            WalletProofChallenge::new(i, &SECRET).err(),
            Some(WalletProofError::InvalidInput)
        );
    }
}
