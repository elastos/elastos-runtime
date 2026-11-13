//! `classify_protected_content_item_finality`: whether an item the finalized
//! market read cannot find is bound at the chain head. Classification only:
//! it reads the head, and its answer names nothing a purchase, an open or a
//! release could rest on.

use super::*;

const FINALIZED_HASH: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const HEAD_HASH: &str = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const GATEWAY: &str = "0x00000000000000000000000000000000000000aa";
const STORE: &str = "0x00000000000000000000000000000000000000cc";
const LEDGER: &str = "0x0000000000000000000000000000000000000022";
const OPERATIVE: &str = "0x0000000000000000000000000000000000000044";
const KID: &str = "0x0123456789abcdef0123456789abcdef";
const FINALIZED_AT: u64 = RIGHTS_EVIDENCE_NOW - 1_000;
const HEAD_AT: u64 = RIGHTS_EVIDENCE_NOW - 2;

fn head_at() -> Value {
    json!({ "blockHash": HEAD_HASH, "requireCanonical": true })
}

/// Chain id, then the finalized block, then the head: what every
/// classification read asks first.
fn blocks() -> Vec<(&'static str, Value, Value)> {
    vec![
        ("eth_chainId", json!([]), json!("0x14")),
        (
            "eth_getBlockByNumber",
            json!(["finalized", false]),
            finalized_block_json_at("0x2c", FINALIZED_HASH, FINALIZED_AT),
        ),
        (
            "eth_getBlockByNumber",
            json!(["latest", false]),
            finalized_block_json_at("0x2f4", HEAD_HASH, HEAD_AT),
        ),
    ]
}

/// The item's operative, read at the head block by its hash.
fn operative_at_head(operative: &str) -> (&'static str, Value, Value) {
    (
        "eth_call",
        json!([
            { "to": GATEWAY, "data": encode_authority_gateway_operative_call(LEDGER, "0x3").unwrap() },
            head_at()
        ]),
        json!(format!("0x{:0>64}", operative.trim_start_matches("0x"))),
    )
}

fn provider_with_sources(sources: Vec<String>) -> ChainProvider {
    provider_with_rights_rpc_policies_and_purchase(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        json!([]),
        protected_content_market_source(sources),
    )
}

fn classify_item(provider: &mut ChainProvider) -> Response {
    provider.handle(Request::ClassifyProtectedContentItemFinality {
        network: "esc-local".to_string(),
        ledger: Some(LEDGER.to_string()),
        token_id: Some("0x3".to_string()),
        content_access_id: None,
    })
}

/// The answer the item finality fixture records: the item bound at the head.
pub(super) fn bound_item_finality_answer() -> Value {
    let mut sequence = blocks();
    sequence.push(operative_at_head(OPERATIVE));
    // The first source cannot be reached; one source that answers is enough.
    let mut provider = provider_with_sources(vec![
        "http://127.0.0.1:9".to_string(),
        spawn_rpc_sequence_asserting_server(sequence),
    ]);
    ok_data(classify_item(&mut provider))
}

#[test]
fn classify_item_finality_reads_the_item_at_the_head() {
    let answer = bound_item_finality_answer();
    assert_eq!(answer["schema"], PROTECTED_CONTENT_ITEM_FINALITY_SCHEMA);
    assert_eq!(answer["network"], "esc-local");
    assert_eq!(answer["chain_id"], 20);
    assert_eq!(answer["ledger"], LEDGER);
    assert_eq!(answer["token_id"], "0x3");
    assert_eq!(answer["content_access_id"], Value::Null);
    assert_eq!(answer["bound_at_head"], true);
    assert_eq!(answer["head_block_number"], 0x2f4);
    assert_eq!(answer["head_block_timestamp"], HEAD_AT);
    assert_eq!(answer["finalized_block_number"], 0x2c);
    assert_eq!(answer["finalized_block_timestamp"], FINALIZED_AT);
}

/// Nothing in the answer is evidence: no operative, no folder, no access,
/// and a schema of its own, so no reader of an item or an access answer
/// takes it for one.
#[test]
fn classify_item_finality_answer_carries_nothing_a_decision_rests_on() {
    let answer = bound_item_finality_answer();
    for field in [
        "operative",
        "token_uri",
        "has_access",
        "finalized_block_hash",
        "offers",
    ] {
        assert!(answer.get(field).is_none(), "{field} in {answer}");
    }
    for schema in [
        PROTECTED_CONTENT_ITEM_SCHEMA,
        PROTECTED_CONTENT_KID_BINDING_SCHEMA,
        PROTECTED_CONTENT_ITEM_OFFERS_SCHEMA,
        PROTECTED_CONTENT_PURCHASE_ACCESS_SCHEMA,
        PROTECTED_CONTENT_ITEM_ACCESS_SCHEMA,
    ] {
        assert_ne!(answer["schema"], schema);
    }
}

#[test]
fn classify_item_finality_answers_unbound_at_the_head() {
    let mut sequence = blocks();
    sequence.push(operative_at_head(EVM_ZERO_ADDRESS));
    let mut provider = provider_with_sources(vec![
        spawn_rpc_sequence_asserting_server(sequence),
        "http://127.0.0.1:9".to_string(),
    ]);
    let answer = ok_data(classify_item(&mut provider));
    assert_eq!(answer["bound_at_head"], false);
}

#[test]
fn classify_item_finality_reads_a_kid_binding_at_the_head() {
    let mut sequence = blocks();
    sequence.push((
        "eth_call",
        json!([
            { "to": GATEWAY, "data": encode_authority_gateway_cstore_call().unwrap() },
            head_at()
        ]),
        json!(format!("0x{:0>64}", STORE.trim_start_matches("0x"))),
    ));
    sequence.push((
        "eth_call",
        json!([
            { "to": STORE, "data": encode_ip_reference_call(KID).unwrap() },
            head_at()
        ]),
        json!(format!(
            "0x{:0>64}{:0>64}",
            LEDGER.trim_start_matches("0x"),
            "3"
        )),
    ));
    sequence.push(operative_at_head(OPERATIVE));
    let mut provider = provider_with_sources(vec![
        spawn_rpc_sequence_asserting_server(sequence),
        "http://127.0.0.1:9".to_string(),
    ]);
    let answer = ok_data(
        provider.handle(Request::ClassifyProtectedContentItemFinality {
            network: "esc-local".to_string(),
            ledger: None,
            token_id: None,
            content_access_id: Some(KID.to_ascii_uppercase().replacen("0X", "0x", 1)),
        }),
    );
    assert_eq!(answer["content_access_id"], KID);
    assert_eq!(answer["ledger"], Value::Null);
    assert_eq!(answer["bound_at_head"], true);
}

#[test]
fn classify_item_finality_answers_an_unbound_kid_without_asking_for_an_operative() {
    let mut sequence = blocks();
    sequence.push((
        "eth_call",
        json!([
            { "to": GATEWAY, "data": encode_authority_gateway_cstore_call().unwrap() },
            head_at()
        ]),
        json!(format!("0x{:0>64}", STORE.trim_start_matches("0x"))),
    ));
    sequence.push((
        "eth_call",
        json!([
            { "to": STORE, "data": encode_ip_reference_call(KID).unwrap() },
            head_at()
        ]),
        json!(format!("0x{:0>128}", "")),
    ));
    let mut provider = provider_with_sources(vec![
        spawn_rpc_sequence_asserting_server(sequence),
        "http://127.0.0.1:9".to_string(),
    ]);
    let answer = ok_data(
        provider.handle(Request::ClassifyProtectedContentItemFinality {
            network: "esc-local".to_string(),
            ledger: None,
            token_id: None,
            content_access_id: Some(KID.to_string()),
        }),
    );
    assert_eq!(answer["bound_at_head"], false);
}

#[test]
fn classify_item_finality_needs_exactly_one_subject() {
    let mut provider = provider_with_sources(vec![
        "http://127.0.0.1:9".to_string(),
        "http://127.0.0.1:19".to_string(),
    ]);
    for (ledger, token_id, content_access_id) in [
        (None, None, None),
        (Some(LEDGER), None, None),
        (Some(LEDGER), Some("0x3"), Some(KID)),
        (Some("0x22"), Some("0x3"), None),
        (None, None, Some("0x0123")),
    ] {
        assert_eq!(
            error_code(
                provider.handle(Request::ClassifyProtectedContentItemFinality {
                    network: "esc-local".to_string(),
                    ledger: ledger.map(str::to_string),
                    token_id: token_id.map(str::to_string),
                    content_access_id: content_access_id.map(str::to_string),
                })
            ),
            "invalid_protected_content_item_finality_request",
            "{ledger:?} {token_id:?} {content_access_id:?}"
        );
    }
}

#[test]
fn classify_item_finality_without_an_answering_source_is_an_error() {
    let mut provider = provider_with_sources(vec![
        "http://127.0.0.1:9".to_string(),
        "http://127.0.0.1:19".to_string(),
    ]);
    assert_eq!(
        error_code(classify_item(&mut provider)),
        "insufficient_protected_content_item_finality_observations"
    );
}

#[test]
fn classify_item_finality_refuses_the_wire_form_with_an_unknown_field() {
    let request = serde_json::from_value::<Request>(json!({
        "op": "classify_protected_content_item_finality",
        "network": "esc-local",
        "ledger": LEDGER,
        "token_id": "0x3",
        "block": "finalized",
    }));
    assert!(request.is_err());
}
