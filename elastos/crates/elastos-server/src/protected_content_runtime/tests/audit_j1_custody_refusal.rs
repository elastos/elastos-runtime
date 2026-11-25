//! AUDIT-REPRO J1 (coll-journey-audit-20261117.md J1-F7), fixed by STAB-33: a
//! custody node's refusal code on the mint path, as Creator receives it.

/// J1-F7: a pool node that refuses a share because its host storage is full
/// (or has no maximum) answers a typed code. Creator must get that code as a
/// specific, actionable error, not the bare "Runtime custody mint failed".
///
/// Retargeted (STAB-33 ruling): this test now asserts at the Creator error
/// boundary. The node's failure goes through the same two steps the pool
/// adapter (`invoke_pool_custody`) applies to it: it is recorded in the
/// composition's diagnostics and classified. The aborted mint's error, and
/// the envelope Creator reads, must then carry that code. Classification
/// stays code-free (`RefusedWithoutEffect`, so the share is never resent).
#[test]
fn audit_j1_f7_a_pool_node_storage_refusal_reaches_the_creator() {
    let op = crate::custody_surface::OP_CUSTODY_PROVISION_POOL_NODE_SHARE;
    for code in [
        crate::host_trust::HOST_STORAGE_FULL,
        crate::host_trust::HOST_STORAGE_MAX_UNSET,
    ] {
        let failure = super::super::ProviderInvocationFailure::Refused {
            code: code.to_string(),
            message: "this host's storage is full".to_string(),
        };
        // What the pool adapter does with a node's failure.
        let diagnostics = super::super::RuntimeCustodyCallDiagnostics::default();
        diagnostics.record(
            op,
            &failure
                .clone()
                .into_message(super::super::CUSTODY_PROVIDER_ID, op),
        );
        let refused = super::super::classify_custody_failure(op, &failure);
        assert_eq!(
            refused,
            elastos_protected_content_runtime::RuntimeProviderCallError::RefusedWithoutEffect
        );

        // What the aborted mint answers, and what Creator reads of it.
        let error = super::super::runtime_custody_mint_failed(
            &diagnostics,
            Some("did:key:zpool".to_string()),
        );
        assert_ne!(
            error.to_string(),
            "Runtime custody mint failed",
            "J1-F7: the node's `{code}` refusal reaches Creator as the bare failure"
        );
        let envelope = crate::library::provider_error_from_for_test(&error);
        assert_eq!(
            envelope["pool_node_refused"]["code"], code,
            "J1-F7: the node's `{code}` refusal does not reach Creator: {envelope}"
        );
        assert_eq!(envelope["pool_node_refused"]["action"], "host_storage");
        assert_eq!(envelope["pool_node_refused"]["pool_did"], "did:key:zpool");
    }
}

/// STAB-33: the refusal the pool's nodes reported reaches Creator as a typed
/// error that names the pool and the host-storage action, and keeps the
/// stable "Runtime custody mint failed" sentence. Any other refusal keeps the
/// plain failure.
#[test]
fn stab_33_a_pool_node_storage_refusal_is_a_typed_creator_error() {
    let op = crate::custody_surface::OP_CUSTODY_PROVISION_POOL_NODE_SHARE;
    let reported = |code: &str| {
        let diagnostics = super::super::RuntimeCustodyCallDiagnostics::default();
        let failure = super::super::ProviderInvocationFailure::Refused {
            code: code.to_string(),
            message: "this host's storage is full".to_string(),
        };
        diagnostics.record(
            op,
            &failure.into_message(super::super::CUSTODY_PROVIDER_ID, op),
        );
        diagnostics
    };
    for code in [
        crate::host_trust::HOST_STORAGE_FULL,
        crate::host_trust::HOST_STORAGE_MAX_UNSET,
    ] {
        let error = super::super::runtime_custody_mint_failed(
            &reported(code),
            Some("did:key:zpool".to_string()),
        );
        assert!(
            error.to_string().starts_with("Runtime custody mint failed"),
            "{error}"
        );
        let envelope = crate::library::provider_error_from_for_test(&error);
        assert_eq!(envelope["pool_node_refused"]["code"], code, "{envelope}");
        assert_eq!(envelope["pool_node_refused"]["pool_did"], "did:key:zpool");
        assert_eq!(envelope["pool_node_refused"]["action"], "host_storage");
    }
    let plain = super::super::runtime_custody_mint_failed(&reported("rights_denied"), None);
    assert_eq!(plain.to_string(), "Runtime custody mint failed");
    assert!(crate::library::provider_error_from_for_test(&plain)
        .get("pool_node_refused")
        .is_none());
}
