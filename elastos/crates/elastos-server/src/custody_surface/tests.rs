use std::collections::BTreeSet;

use super::*;

#[test]
fn surface_ids_are_unique() {
    let mut seen = BTreeSet::new();
    for item in CUSTODY_SURFACE {
        assert!(!item.id.is_empty(), "an empty id is declared");
        assert!(!item.stage.is_empty(), "{} names no stage", item.id);
        assert!(
            seen.insert((item.kind, item.id)),
            "{} is declared twice as {:?}",
            item.id,
            item.kind
        );
    }
}

#[test]
fn every_row_is_an_approved_runtime_custody_item() {
    for item in CUSTODY_SURFACE {
        assert_eq!(item.stage, STAGE_RUNTIME_CUSTODY, "{}", item.id);
        assert_eq!(item.approval, Approval::Existing, "{}", item.id);
    }
}

#[test]
fn custody_is_the_one_runtime_provider_target() {
    assert!(carrier_target_allowed(TARGET_CUSTODY));
    assert!(is_runtime_provider_target(TARGET_CUSTODY));
    for other in ["content", "model", "rights", "status", "evaluate", ""] {
        assert!(!carrier_target_allowed(other), "{other}");
        assert!(!is_runtime_provider_target(other), "{other}");
    }
}

#[test]
fn custody_declares_the_four_public_ops_in_order() {
    assert_eq!(
        declared_ops(TARGET_CUSTODY).collect::<Vec<_>>(),
        [
            "status",
            "provision_node_share",
            "release_contribution",
            "evaluate"
        ]
    );
}

#[test]
fn private_custody_ops_are_never_declared() {
    for op in [
        "evaluate_rights",
        "prepare_evidence",
        "settle_evidence",
        "shutdown",
    ] {
        assert!(
            CUSTODY_SURFACE.iter().all(|item| item.id != op),
            "{op} must stay out of the custody surface"
        );
    }
}
