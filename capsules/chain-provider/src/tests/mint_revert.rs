//! A mint transaction that reverted (`status` `0x0`): the receipt carries no
//! revert data, so the provider replays the call at the transaction's own
//! block and reads the revert. A second mint of the same content id
//! (`IPAlreadyBound`, `InvalidTokenId`) answers `already_bound`; any other
//! revert stays the plain failure.
//!
//! A reverted receipt means something only at the confirmation depth, in a
//! block the source carries canonically, and only for the attempted
//! transaction. A duplicate answer stops the Runtime's attempt, so it needs two
//! sources that agree, and it never outweighs a source that saw the mint
//! succeed.

use super::*;

const HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const CREATOR: &str = "0x0000000000000000000000000000000000000011";
const LEDGER: &str = "0x0000000000000000000000000000000000000022";
const BLOCK: &str = "0x2a";
const BLOCK_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MINT_INPUT: &str = "0x6d696e74";
const TOKEN_URI: &str = "ipfs://protected-content";

/// `IPAlreadyBound(bytes16 contentId)` as the contract encodes it: the
/// selector, then the content id left-aligned in one 32-byte word.
fn ip_already_bound_revert(content_id: [u8; 16]) -> Vec<u8> {
    let mut data = vec![0x47, 0xfe, 0x91, 0x9d];
    data.extend_from_slice(&content_id);
    data.extend_from_slice(&[0u8; 16]);
    data
}

/// `InvalidTokenId()`: the selector alone.
const INVALID_TOKEN_ID_REVERT: [u8; 4] = [0x3f, 0x6c, 0xc7, 0x68];

/// `Error(string)` with an empty reason: a revert that says nothing about a
/// duplicate.
const ERROR_STRING_REVERT: &str = "0x08c379a0\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000000";

fn hex_of(bytes: &[u8]) -> String {
    format!("0x{}", encode_hex(bytes))
}

/// Twelve confirmations past [`BLOCK`]: the shallowest decisive depth.
const DEEP_HEAD: &str = "0x35";
/// Eleven confirmations: one short of the depth.
const SHALLOW_HEAD: &str = "0x34";

/// The attempted transaction as a source returns it, in the receipt's block.
fn attempted_transaction() -> Value {
    json!({
        "hash": HASH,
        "from": CREATOR,
        "to": LEDGER,
        "input": MINT_INPUT,
        "value": "0x0",
        "blockNumber": BLOCK,
        "blockHash": BLOCK_HASH,
    })
}

/// What one source is asked about a reverted mint: the chain, the receipt
/// (`0x0`), the head and the receipt's canonical block, then the transaction
/// and the replay at its block.
fn reverted_mint_source(replay: RpcReply) -> String {
    reverted_mint_source_at(
        DEEP_HEAD,
        canonical_block_json(BLOCK, BLOCK_HASH, vec![HASH]),
        attempted_transaction(),
        replay,
    )
}

fn reverted_mint_source_at(
    head: &str,
    canonical_block: Value,
    transaction: Value,
    replay: RpcReply,
) -> String {
    let call = json!({
        "from": CREATOR,
        "to": LEDGER,
        "data": MINT_INPUT,
        "value": "0x0",
    });
    spawn_rpc_sequence_asserting_server_with_replies(vec![
        ("eth_chainId", json!([]), RpcReply::Result(json!("0x2105"))),
        (
            "eth_getTransactionReceipt",
            json!([HASH]),
            RpcReply::Result(protected_content_mint_receipt_json(
                HASH,
                CREATOR,
                LEDGER,
                BLOCK,
                BLOCK_HASH,
                "0x0",
                Vec::new(),
            )),
        ),
        ("eth_blockNumber", json!([]), RpcReply::Result(json!(head))),
        (
            "eth_getBlockByNumber",
            json!([BLOCK, false]),
            RpcReply::Result(canonical_block),
        ),
        (
            "eth_getTransactionByHash",
            json!([HASH]),
            RpcReply::Result(transaction),
        ),
        ("eth_call", json!([call, BLOCK]), replay),
    ])
}

/// A source that cannot answer at all: nothing listens there.
fn unreachable_source() -> String {
    "http://127.0.0.1:9".to_string()
}

/// A source that carries the mint as a success, canonically and at depth.
fn successful_source() -> String {
    spawn_rpc_state_server(canonical_mint_receipt_source(DEEP_HEAD))
}

fn duplicate_revert() -> RpcReply {
    reverted_with(&hex_of(&ip_already_bound_revert([0xab; 16])))
}

fn ordinary_revert() -> RpcReply {
    reverted_with(ERROR_STRING_REVERT)
}

fn reverted_with(data: &str) -> RpcReply {
    RpcReply::Error(json!({
        "code": 3,
        "message": "execution reverted",
        "data": data,
    }))
}

fn mint_receipt_answer(sources: Vec<String>) -> Response {
    let mut provider = provider_with_creator_mint_rpc_and_market_sources(
        "http://127.0.0.1:9".to_string(),
        sources,
    );
    provider.handle(Request::ResolveProtectedContentMintReceipt {
        network: "base-local".to_string(),
        hash: HASH.to_string(),
        creator: CREATOR.to_string(),
        ledger: LEDGER.to_string(),
        token_uri: TOKEN_URI.to_string(),
        op_type_code: 1,
    })
}

fn mint_receipt_code(sources: Vec<String>) -> String {
    error_code(mint_receipt_answer(sources))
}

#[test]
fn classify_mint_revert_reads_only_the_selector() {
    // v3-drm-protocol ed00fe4, `cast sig`.
    assert_eq!(IP_ALREADY_BOUND_ERROR_SELECTOR, [0x47, 0xfe, 0x91, 0x9d]);
    assert_eq!(INVALID_TOKEN_ID_ERROR_SELECTOR, [0x3f, 0x6c, 0xc7, 0x68]);

    assert_eq!(
        classify_mint_revert(&ip_already_bound_revert([0xab; 16])),
        MintRevertKind::AlreadyBound
    );
    assert_eq!(
        classify_mint_revert(&INVALID_TOKEN_ID_REVERT),
        MintRevertKind::AlreadyBound
    );
    // A longer payload behind the same selector is still a duplicate.
    let mut longer = ip_already_bound_revert([0xab; 16]);
    longer.extend_from_slice(&[0x11; 64]);
    assert_eq!(classify_mint_revert(&longer), MintRevertKind::AlreadyBound);

    // Another error, a panic, a short or empty revert: never a duplicate.
    for other in [
        &[0x08, 0xc3, 0x79, 0xa0, 0x00, 0x00][..],
        &[0x4e, 0x48, 0x7b, 0x71][..],
        &[0x47, 0xfe, 0x91][..],
        &[0x3f][..],
        &[][..],
    ] {
        assert_eq!(
            classify_mint_revert(other),
            MintRevertKind::Other,
            "{other:02x?}"
        );
    }
}

#[test]
fn reverted_duplicate_mint_answers_already_bound_for_each_error() {
    assert_eq!(
        PROTECTED_CONTENT_MINT_RECEIPT_ALREADY_BOUND_CODE,
        "protected_content_mint_receipt_reverted_already_bound"
    );
    for (error, revert) in [
        (
            "IPAlreadyBound",
            hex_of(&ip_already_bound_revert([0xab; 16])),
        ),
        ("InvalidTokenId", hex_of(&INVALID_TOKEN_ID_REVERT)),
    ] {
        assert_eq!(
            mint_receipt_code(vec![
                reverted_mint_source(reverted_with(&revert)),
                reverted_mint_source(reverted_with(&revert)),
            ]),
            PROTECTED_CONTENT_MINT_RECEIPT_ALREADY_BOUND_CODE,
            "{error}"
        );
    }
}

#[test]
fn other_revert_stays_failed() {
    // Another error, and a replay that does not revert at all.
    for replay in [
        reverted_with(ERROR_STRING_REVERT),
        reverted_with("0x"),
        RpcReply::Result(json!("0x")),
    ] {
        assert_eq!(
            mint_receipt_code(vec![
                reverted_mint_source(replay.clone()),
                reverted_mint_source(replay),
            ]),
            "protected_content_mint_receipt_failed"
        );
    }
}

#[test]
fn shallow_reverted_mint_receipt_is_pending() {
    // One confirmation short of the depth, a reverted receipt is a block the
    // chain can still take back: ordinary and duplicate reverts both wait.
    for (label, replay) in [
        ("ordinary", ordinary_revert()),
        ("duplicate", duplicate_revert()),
    ] {
        let source = || {
            reverted_mint_source_at(
                SHALLOW_HEAD,
                canonical_block_json(BLOCK, BLOCK_HASH, vec![HASH]),
                attempted_transaction(),
                replay.clone(),
            )
        };
        assert_eq!(
            mint_receipt_code(vec![source(), source()]),
            "protected_content_mint_receipt_pending",
            "{label}"
        );
    }
}

#[test]
fn non_canonical_reverted_mint_receipt_is_not_a_revert() {
    let off_chain_block = || {
        canonical_block_json(
            BLOCK,
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            vec![HASH],
        )
    };
    for (label, replay) in [
        ("ordinary", ordinary_revert()),
        ("duplicate", duplicate_revert()),
    ] {
        let source = || {
            reverted_mint_source_at(
                DEEP_HEAD,
                off_chain_block(),
                attempted_transaction(),
                replay.clone(),
            )
        };
        // At depth, but the source's canonical chain does not carry the
        // receipt's block: while another source may still answer, it waits.
        assert_eq!(
            mint_receipt_code(vec![source(), unreachable_source()]),
            "protected_content_mint_receipt_pending",
            "{label}: another source pending"
        );
        // With none left to wait for, the answer is the canonical-block
        // disagreement, never a failed or duplicate mint.
        match mint_receipt_answer(vec![source(), source()]) {
            Response::Error { code, message } => {
                assert_eq!(code, "invalid_protected_content_mint_receipt", "{label}");
                assert_eq!(
                    message,
                    "protected-content mint receipt block does not match the canonical block",
                    "{label}"
                );
            }
            other => panic!("{label}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn reverted_mint_transaction_that_is_not_the_attempt_is_not_a_duplicate() {
    let with = |field: &str, value: Value| {
        let mut transaction = attempted_transaction();
        match value {
            Value::Null => {
                transaction.as_object_mut().unwrap().remove(field);
            }
            value => transaction[field] = value,
        }
        transaction
    };
    for (label, transaction) in [
        (
            "another transaction hash",
            with(
                "hash",
                json!("0x2222222222222222222222222222222222222222222222222222222222222222"),
            ),
        ),
        (
            "another signer",
            with("from", json!("0x0000000000000000000000000000000000000099")),
        ),
        ("another block number", with("blockNumber", json!("0x29"))),
        (
            "another block hash",
            with(
                "blockHash",
                json!("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            ),
        ),
        ("no block hash", with("blockHash", Value::Null)),
    ] {
        let source = || {
            reverted_mint_source_at(
                DEEP_HEAD,
                canonical_block_json(BLOCK, BLOCK_HASH, vec![HASH]),
                transaction.clone(),
                duplicate_revert(),
            )
        };
        assert_eq!(
            mint_receipt_code(vec![source(), source()]),
            "protected_content_mint_receipt_failed",
            "{label}"
        );
    }
}

#[test]
fn one_duplicate_source_does_not_decide_alone() {
    // Another source may still answer: wait for it.
    assert_eq!(
        mint_receipt_code(vec![
            reverted_mint_source(duplicate_revert()),
            unreachable_source(),
        ]),
        "protected_content_mint_receipt_pending"
    );
    // The other source reads another revert: the plain failure.
    assert_eq!(
        mint_receipt_code(vec![
            reverted_mint_source(ordinary_revert()),
            reverted_mint_source(duplicate_revert()),
        ]),
        "protected_content_mint_receipt_failed"
    );
    // Nothing left to corroborate it: the plain failure, as before the replay.
    let off_chain = reverted_mint_source_at(
        DEEP_HEAD,
        canonical_block_json(
            BLOCK,
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            vec![HASH],
        ),
        attempted_transaction(),
        duplicate_revert(),
    );
    assert_eq!(
        mint_receipt_code(vec![reverted_mint_source(duplicate_revert()), off_chain]),
        "protected_content_mint_receipt_failed"
    );
}

#[test]
fn duplicate_revert_never_outweighs_a_successful_source() {
    // One success, one duplicate, a third source still pending: wait.
    assert_eq!(
        mint_receipt_code(vec![
            reverted_mint_source(duplicate_revert()),
            successful_source(),
            unreachable_source(),
        ]),
        "protected_content_mint_receipt_pending"
    );
    // One success, one duplicate, nothing left to wait for: the sources
    // conflict, and the attempt is never read as already minted.
    assert_eq!(
        mint_receipt_code(vec![
            reverted_mint_source(duplicate_revert()),
            successful_source(),
        ]),
        "conflicting_protected_content_mint_receipt_observations"
    );
    // Two matching successes settle the mint whatever a third source says.
    let data = ok_data(mint_receipt_answer(vec![
        reverted_mint_source(duplicate_revert()),
        successful_source(),
        successful_source(),
    ]));
    assert_eq!(data["token_id"], "0x3");
}
