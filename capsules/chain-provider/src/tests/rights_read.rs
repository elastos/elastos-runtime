//! The rights read is bounded: its sources are asked together, the whole read
//! has a deadline, and the evidence it returns is stamped when the read ends.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const BLOCK_HASH: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn requests(counter: &std::sync::Arc<AtomicUsize>) -> usize {
    counter.load(Ordering::SeqCst)
}

/// One source's full answer to a rights read, the `eth_call` given after
/// `eth_call_wait`.
fn rights_script(
    operation: &SignedRuntimeReleaseOperationV1,
    eth_call_wait: Duration,
) -> Vec<ScriptedReply> {
    let policy = operation.statement().policy_body();
    let expected_data = encode_has_access_by_content_id_call(
        "0x12345678",
        policy.content_access_id().as_bytes(),
        &wallet_subject_hex(operation),
    )
    .unwrap();
    vec![
        ScriptedReply::rpc("eth_chainId", json!([]), json!("0x14")),
        ScriptedReply::rpc(
            "eth_getBlockByNumber",
            json!(["finalized", false]),
            finalized_block_json("0x2a", BLOCK_HASH),
        ),
        ScriptedReply::rpc(
            "eth_call",
            json!([
                { "to": "0x0000000000000000000000000000000000000001", "data": expected_data },
                { "blockHash": BLOCK_HASH, "requireCanonical": true }
            ]),
            evm_bool_word(true),
        )
        .delayed(eth_call_wait),
    ]
}

fn rights_provider(sources: Vec<String>) -> ChainProvider {
    let mut provider = provider_with_rights_rpc_and_policies(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        protected_content_policy_sources("view", sources),
    );
    provider.sleep = record_sleep;
    provider
}

fn read_rights_evidence(
    provider: &mut ChainProvider,
    operation: &SignedRuntimeReleaseOperationV1,
) -> Response {
    provider.handle(Request::ProtectedContentRightsEvidence {
        signed_runtime_release_operation: contract_hex(operation),
    })
}

fn evidence_of(data: &Value) -> RightsEvaluationEvidenceV1 {
    let bytes = decode_hex(
        data["rights_evaluation_evidence"].as_str().unwrap(),
        None,
        "rights_evaluation_evidence",
    )
    .unwrap();
    RightsEvaluationEvidenceV1::from_canonical_bytes(&bytes).unwrap()
}

static STAMP_CLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

/// The operation is verified at the first reading; the read then takes five
/// seconds.
fn clock_read_takes_five_seconds() -> u64 {
    if STAMP_CLOCK_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
        RIGHTS_EVIDENCE_NOW
    } else {
        RIGHTS_EVIDENCE_NOW + 5
    }
}

#[test]
fn rights_evidence_is_stamped_when_the_read_ends() {
    let operation = protected_content_signed_operation();
    let (first, _) = spawn_scripted_rpc_server(rights_script(&operation, Duration::ZERO));
    let (second, _) = spawn_scripted_rpc_server(rights_script(&operation, Duration::ZERO));
    let mut provider = rights_provider(vec![first, second]);
    provider.now_unix_seconds = clock_read_takes_five_seconds;

    let evidence = evidence_of(&ok_data(read_rights_evidence(&mut provider, &operation)));
    assert_eq!(evidence.acquired_at(), RIGHTS_EVIDENCE_NOW + 5);
    // Thirty seconds from then would outlive the operation, so the operation
    // end bounds it.
    assert_eq!(evidence.expires_at(), operation.statement().expires_at());
}

static EXPIRY_CLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

/// The read ends one second before the operation does.
fn clock_read_outlives_operation() -> u64 {
    if EXPIRY_CLOCK_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
        RIGHTS_EVIDENCE_NOW
    } else {
        2_000_000_039
    }
}

#[test]
fn rights_evidence_that_would_arrive_expired_is_refused_with_its_own_code() {
    let operation = protected_content_signed_operation();
    assert_eq!(operation.statement().expires_at(), 2_000_000_040);
    let (first, _) = spawn_scripted_rpc_server(rights_script(&operation, Duration::ZERO));
    let (second, _) = spawn_scripted_rpc_server(rights_script(&operation, Duration::ZERO));
    let mut provider = rights_provider(vec![first, second]);
    provider.now_unix_seconds = clock_read_outlives_operation;

    assert_eq!(
        error_code(read_rights_evidence(&mut provider, &operation)),
        "rights_evidence_expired"
    );
}

#[test]
fn rights_read_asks_its_sources_together() {
    let operation = protected_content_signed_operation();
    let wait = Duration::from_millis(800);
    let (first, _) = spawn_scripted_rpc_server(rights_script(&operation, wait));
    let (second, _) = spawn_scripted_rpc_server(rights_script(&operation, wait));
    let (third, third_counter) = spawn_scripted_rpc_server(Vec::new());
    let mut provider = rights_provider(vec![first, second, third]);
    provider.now_unix_seconds = rights_evidence_now;

    let started = Instant::now();
    ok_data(read_rights_evidence(&mut provider, &operation));
    let elapsed = started.elapsed();
    // One after the other the two slow sources take at least twice the wait.
    assert!(elapsed < wait * 2, "rights read took {elapsed:?}");
    // Asking together does not ask more: two sources agreed, so the third
    // was never asked.
    assert_eq!(requests(&third_counter), 0);
}

#[test]
fn a_stalled_rights_source_drops_out_and_the_next_source_answers() {
    let operation = protected_content_signed_operation();
    let (stalled, _) = spawn_scripted_rpc_server(vec![ScriptedReply::Stall]);
    let (second, _) = spawn_scripted_rpc_server(rights_script(&operation, Duration::ZERO));
    let (third, third_counter) =
        spawn_scripted_rpc_server(rights_script(&operation, Duration::ZERO));
    let mut provider = rights_provider(vec![stalled, second, third]);
    provider.now_unix_seconds = rights_evidence_now;
    provider.rights_read_request_timeout = Duration::from_millis(300);

    let started = Instant::now();
    let evidence = evidence_of(&ok_data(read_rights_evidence(&mut provider, &operation)));
    assert!(evidence.has_access());
    assert_eq!(requests(&third_counter), 3);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "rights read took {:?}",
        started.elapsed()
    );
}

#[test]
fn rights_read_ends_at_its_deadline_when_no_source_answers() {
    let operation = protected_content_signed_operation();
    let (first, _) = spawn_scripted_rpc_server(vec![ScriptedReply::Stall]);
    let (second, _) = spawn_scripted_rpc_server(vec![ScriptedReply::Stall]);
    let mut provider = rights_provider(vec![first, second]);
    provider.now_unix_seconds = rights_evidence_now;
    provider.rights_read_budget = Duration::from_millis(400);

    let started = Instant::now();
    assert_eq!(
        error_code(read_rights_evidence(&mut provider, &operation)),
        "insufficient_rights_observations"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "rights read took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_rate_limit_retry_that_would_outlast_the_read_is_not_made() {
    let (limited, counter) = spawn_scripted_rpc_server(vec![
        ScriptedReply::RateLimited(None),
        ScriptedReply::rpc("eth_chainId", json!([]), json!("0x14")),
    ]);
    let mut provider = provider_with_rpc(limited.clone());
    provider.sleep = record_sleep;
    let network = provider.evm_network("esc-local").unwrap().clone();
    // The first backoff is 250 ms; the read has less than that left.
    let deadline = RpcReadDeadline::after(Duration::from_millis(100), Duration::from_secs(5));

    assert!(provider
        .evm_rpc_within(&network, "eth_chainId", json!([]), Some(deadline))
        .is_err());
    assert_eq!(requests(&counter), 1);
    assert!(recorded_sleeps().is_empty());
    // One shortened answer does not prove the origin stays rate-limited.
    assert_eq!(
        provider.corroboration_order(std::slice::from_ref(&limited)),
        vec![limited]
    );
}
