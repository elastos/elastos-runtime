use std::collections::BTreeSet;

use super::*;

#[test]
fn surface_ids_are_unique() {
    let mut seen = BTreeSet::new();
    for item in CUSTODY_SURFACE {
        assert!(!item.id.is_empty(), "an empty id is declared");
        assert!(!item.stage.is_empty(), "{} names no stage", item.id);
        assert!(
            seen.insert(item.key()),
            "{} is declared twice as {:?}",
            item.id,
            item.kind
        );
    }
}

#[test]
fn carrier_allowlist_reads_the_surface() {
    let targets: Vec<_> = CUSTODY_SURFACE
        .iter()
        .filter_map(|item| match item.kind {
            SurfaceKind::CarrierTarget { runtime_provider } => Some((item.id, runtime_provider)),
            _ => None,
        })
        .collect();
    assert_eq!(
        targets,
        [
            (TARGET_CUSTODY, true),
            (TARGET_COLLABORATION_CUSTODY, false),
            // Plan B T3.4: a pool member's viewing sessions.
            (TARGET_CUSTODY_POOL, true),
        ]
    );
    for (target, runtime_provider) in targets {
        assert!(carrier_target_allowed(target), "{target}");
        assert!(
            crate::carrier::carrier_provider_target_allowed(target),
            "{target}"
        );
        assert_eq!(
            is_runtime_provider_target(target),
            runtime_provider,
            "{target}"
        );
    }
    // Custody answers only what it declares; other planes keep their own list.
    for target in ["custody.pool", "custody-pools", "content", "model", ""] {
        assert!(!carrier_target_allowed(target), "{target}");
        assert!(!is_runtime_provider_target(target), "{target}");
    }
    assert!(crate::carrier::carrier_provider_target_allowed("content"));
    // Plan B T3.4: the pool target is allowed on purpose now.
    assert!(crate::carrier::carrier_provider_target_allowed(
        "custody-pool"
    ));
    assert!(!crate::carrier::carrier_provider_target_allowed(
        "custody.pool"
    ));

    // Every op declared on a target names a declared target.
    for item in CUSTODY_SURFACE {
        if let SurfaceKind::CarrierOp { target } = item.kind {
            assert!(carrier_target_allowed(target), "{} names {target}", item.id);
            assert!(carrier_op_allowed(target, item.id));
        }
    }
    assert!(carrier_op_allowed(TARGET_COLLABORATION_CUSTODY, "query"));
    assert!(carrier_op_allowed(TARGET_COLLABORATION_CUSTODY, "deliver"));
    assert!(carrier_op_allowed(TARGET_CUSTODY, "release_contribution"));
    assert!(!carrier_op_allowed(TARGET_CUSTODY, "query"));
    assert!(!carrier_op_allowed(
        TARGET_COLLABORATION_CUSTODY,
        "release_contribution"
    ));
    assert!(!carrier_op_allowed(TARGET_CUSTODY, "evaluate_rights"));
    assert!(!carrier_op_allowed("content", "fetch"));

    // Plan B T1.7 (L15): a Runtime-local op names a declared target, and the
    // Carrier allow-list never admits it.
    for item in CUSTODY_SURFACE {
        if let SurfaceKind::RuntimeLocalOp { target } = item.kind {
            assert!(carrier_target_allowed(target), "{} names {target}", item.id);
            assert!(runtime_local_op_allowed(target, item.id), "{}", item.id);
            assert!(!carrier_op_allowed(target, item.id), "{}", item.id);
        }
    }
    assert!(carrier_op_allowed(
        TARGET_CUSTODY,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION
    ));
    assert!(!carrier_op_allowed(
        TARGET_CUSTODY,
        OP_CUSTODY_SIGN_POOL_STATEMENT
    ));
    assert!(runtime_local_op_allowed(
        TARGET_CUSTODY,
        OP_CUSTODY_SIGN_POOL_STATEMENT
    ));
    assert!(!runtime_local_op_allowed(
        TARGET_COLLABORATION_CUSTODY,
        OP_CUSTODY_SIGN_POOL_STATEMENT
    ));
    assert!(!runtime_local_op_allowed(TARGET_CUSTODY, "evaluate_rights"));
}

#[test]
fn custody_target_ops_list_both_planes_in_surface_order() {
    assert_eq!(
        declared_ops(TARGET_CUSTODY).collect::<Vec<_>>(),
        [
            OP_CUSTODY_STATUS,
            OP_CUSTODY_PROVISION_NODE_SHARE,
            OP_CUSTODY_RELEASE_CONTRIBUTION,
            OP_CUSTODY_EVALUATE,
            OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
            OP_CUSTODY_SIGN_POOL_STATEMENT,
            OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        ]
    );
    assert_eq!(
        declared_ops(TARGET_COLLABORATION_CUSTODY).collect::<Vec<_>>(),
        [
            OP_COLLABORATION_CUSTODY_QUERY,
            OP_COLLABORATION_CUSTODY_DELIVER
        ]
    );
    assert_eq!(declared_ops("content").count(), 0);
    assert_eq!(
        declared_ops(TARGET_CUSTODY_POOL).collect::<Vec<_>>(),
        [
            OP_CUSTODY_POOL_DESCRIBE,
            OP_CUSTODY_POOL_SESSION_PREPARE,
            OP_CUSTODY_POOL_SESSION_OPEN,
            OP_CUSTODY_POOL_SESSION_READ,
            OP_CUSTODY_POOL_SESSION_CLOSE,
        ]
    );
}

#[test]
fn custody_capsule_methods_match_the_surface() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../capsules/custody/capsule.json"))
            .expect("custody capsule manifest");
    let manifest_methods: BTreeSet<&str> = manifest["interfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .flat_map(|interface| interface["methods"].as_array().expect("methods"))
        .map(|method| method["id"].as_str().expect("method id"))
        .collect();
    let declared: BTreeSet<&str> = CUSTODY_SURFACE
        .iter()
        .filter(|item| matches!(item.kind, SurfaceKind::CapsuleMethod))
        .map(|item| item.id)
        .collect();
    assert_eq!(manifest_methods, declared);
}

/// META-PUBLIC: the public IPFS store's routes, its enable step-up and its
/// Runtime-only target wait for their #173 record, and the Carrier
/// allow-list admits none of them.
#[test]
fn public_store_items_are_pending_173() {
    let listed: BTreeSet<(String, &str)> = pending_approvals()
        .into_iter()
        .filter(|item| item.stage == "meta-public")
        .map(|item| (format!("{:?}", item.kind), item.id))
        .collect();
    let route = |method: &'static str, path| (format!("{:?}", SurfaceKind::Route { method }), path);
    let kind = |id| (format!("{:?}", SurfaceKind::InboxKind), id);
    let action = |id| (format!("{:?}", SurfaceKind::InboxAction), id);
    // A4: consent and Stop live in Inbox; the Creator keeps only its read
    // (R1 removed the enable and disable routes).
    assert_eq!(
        listed,
        BTreeSet::from([
            route("GET", "/api/apps/creator/public-ipfs"),
            (
                format!("{:?}", SurfaceKind::StepUpOp),
                "creator.public_ipfs.enable"
            ),
            (
                format!("{:?}", SurfaceKind::RuntimeOnlyTarget),
                "public-ipfs"
            ),
            kind("public_metadata_consent"),
            kind("public_metadata_sharing"),
            kind("public_metadata_paused"),
            kind("public_metadata_stopping"),
            kind("public_metadata_unreadable"),
            action("public-metadata-enable"),
            action("public-metadata-stop"),
        ])
    );
    assert_eq!(PUBLIC_STORE_SURFACE.len(), listed.len());
    let mut keys = BTreeSet::new();
    for item in PUBLIC_STORE_SURFACE {
        assert!(keys.insert(item.key()), "{} is declared twice", item.id);
        assert!(!carrier_target_allowed(item.id), "{}", item.id);
        assert!(!is_runtime_provider_target(item.id), "{}", item.id);
    }
}

#[test]
fn step_up_ops_and_routes_are_declared() {
    let step_ups: BTreeSet<&str> = CUSTODY_SURFACE
        .iter()
        .filter(|item| matches!(item.kind, SurfaceKind::StepUpOp))
        .map(|item| item.id)
        .collect();
    assert_eq!(
        step_ups,
        BTreeSet::from([
            STEP_UP_LOCAL_NODE_INCLUDE,
            STEP_UP_LOCAL_NODE_REMOVE,
            STEP_UP_POOL_INSTALL,
            STEP_UP_MESSAGES_ENABLE,
            STEP_UP_NODE_REQUEST_APPROVE,
            STEP_UP_KNOWN_POOL_ADD,
            STEP_UP_SERVED_POOL_REMOVE,
            STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER,
        ])
    );
    // Plan B T2.3: `:pool` is the fingerprint hex, never a DID.
    assert!(ROUTE_POOL_SERVED.ends_with("/:pool"));
    assert!(ROUTE_POOL_SERVED.starts_with(ROUTE_POOLS_SERVED));
    assert_eq!(
        ROUTE_POOL_SERVED_PUBLISHER,
        format!("{ROUTE_POOL_SERVED}/publisher")
    );
    for item in CUSTODY_SURFACE {
        if let SurfaceKind::Route { method } = item.kind {
            assert!(
                item.id.starts_with("/api/apps/custody/"),
                "{method} {} is outside the Custody app",
                item.id
            );
            assert!(
                matches!(method, "GET" | "POST" | "DELETE"),
                "{method} {}",
                item.id
            );
        }
    }
}

#[test]
fn pending_approvals_are_the_173_items() {
    let pending: BTreeSet<(String, &str)> = pending_approvals()
        .into_iter()
        .filter(|item| CUSTODY_SURFACE.contains(item))
        .map(|item| (format!("{:?}", item.kind), item.id))
        .collect();
    let route = |method: &'static str, path| (format!("{:?}", SurfaceKind::Route { method }), path);
    let step_up = |id| (format!("{:?}", SurfaceKind::StepUpOp), id);
    let method = |id| (format!("{:?}", SurfaceKind::CapsuleMethod), id);
    let message = |id| (format!("{:?}", SurfaceKind::MessageType), id);
    let inbox_kind = |id| (format!("{:?}", SurfaceKind::InboxKind), id);
    let inbox_action = |id| (format!("{:?}", SurfaceKind::InboxAction), id);
    let decline = |id| {
        (
            format!(
                "{:?}",
                SurfaceKind::DeclineCode {
                    message: MESSAGE_NODE_DECISION
                }
            ),
            id,
        )
    };
    let pool_op = |id| {
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierOp {
                    target: TARGET_CUSTODY_POOL
                }
            ),
            id,
        )
    };
    let expected = BTreeSet::from([
        // Already named in the #173 heads-up.
        route("DELETE", ROUTE_LOCAL_NODE),
        step_up(STEP_UP_LOCAL_NODE_REMOVE),
        method("custody.local_node.remove"),
        // #388 A1: the host trust operator setting (setup only).
        (
            format!("{:?}", SurfaceKind::OperatorSetting),
            OPERATOR_SETTING_HOST_TRUST,
        ),
        // Custody discovery and consent.
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierTarget {
                    runtime_provider: false
                }
            ),
            TARGET_COLLABORATION_CUSTODY,
        ),
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierOp {
                    target: TARGET_COLLABORATION_CUSTODY
                }
            ),
            OP_COLLABORATION_CUSTODY_QUERY,
        ),
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierOp {
                    target: TARGET_COLLABORATION_CUSTODY
                }
            ),
            OP_COLLABORATION_CUSTODY_DELIVER,
        ),
        route("POST", ROUTE_POOL_NOTIFY),
        route("GET", ROUTE_OFFER),
        route("POST", ROUTE_OFFER),
        route("POST", ROUTE_NODES_FIND),
        route("POST", ROUTE_NODE_REQUESTS),
        route("POST", ROUTE_MESSAGES_ENABLE),
        step_up(STEP_UP_MESSAGES_ENABLE),
        step_up(STEP_UP_NODE_REQUEST_APPROVE),
        method("custody.pool.notify"),
        method("custody.offer.read"),
        method("custody.offer.set"),
        method("custody.messages.enable"),
        method("custody.nodes.find"),
        method("custody.node_requests.send"),
        message(MESSAGE_OFFER_QUERY),
        message(MESSAGE_OFFER),
        message(MESSAGE_NODE_REQUEST),
        message(MESSAGE_NODE_DECISION),
        message(MESSAGE_POOL_ACTIVE),
        // Plan B T3.3 (S3): the signed pool descriptor.
        message(MESSAGE_POOL_DESCRIPTOR),
        // Plan B T3.4 (S3): the pool session target and its ops.
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierTarget {
                    runtime_provider: true
                }
            ),
            TARGET_CUSTODY_POOL,
        ),
        pool_op(OP_CUSTODY_POOL_DESCRIBE),
        pool_op(OP_CUSTODY_POOL_SESSION_PREPARE),
        pool_op(OP_CUSTODY_POOL_SESSION_OPEN),
        pool_op(OP_CUSTODY_POOL_SESSION_READ),
        pool_op(OP_CUSTODY_POOL_SESSION_CLOSE),
        inbox_kind(INBOX_KIND_NODE_REQUEST),
        inbox_kind(INBOX_KIND_NODE_APPROVING),
        inbox_kind(INBOX_KIND_NODE_RESUMABLE),
        inbox_kind(INBOX_KIND_NODE_INCOMPLETE),
        inbox_kind(INBOX_KIND_NODE_TAKEN),
        inbox_kind(INBOX_KIND_POOL_ACTIVE),
        inbox_action(INBOX_ACTION_APPROVE_REQUEST),
        inbox_action(INBOX_ACTION_DECLINE_REQUEST),
        // Plan B T4.3 (S4): the pools this Home uses.
        route("GET", ROUTE_POOLS_KNOWN),
        route("POST", ROUTE_POOLS_KNOWN),
        step_up(STEP_UP_KNOWN_POOL_ADD),
        method(METHOD_KNOWN_POOLS_READ),
        method(METHOD_KNOWN_POOL_ADD),
        // Plan B T1.7 (S1, L15): pool release.
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierOp {
                    target: TARGET_CUSTODY
                }
            ),
            OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        ),
        (
            format!(
                "{:?}",
                SurfaceKind::RuntimeLocalOp {
                    target: TARGET_CUSTODY
                }
            ),
            OP_CUSTODY_SIGN_POOL_STATEMENT,
        ),
        // Plan B S7-lite T7.3: an admitted minter provisions a pool node.
        (
            format!(
                "{:?}",
                SurfaceKind::CarrierOp {
                    target: TARGET_CUSTODY
                }
            ),
            OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        ),
        // Plan B T2.2 (S2-U1): the ninth pool's decline.
        decline(DECLINE_TOO_MANY_POOLS),
        // Plan B T2.3: Hosting's served pools and Stop serving.
        route("GET", ROUTE_POOLS_SERVED),
        route("DELETE", ROUTE_POOL_SERVED),
        step_up(STEP_UP_SERVED_POOL_REMOVE),
        method(METHOD_SERVED_POOLS_READ),
        method(METHOD_SERVED_POOL_REMOVE),
        // Plan B T2.3 (S2-A3, S2-R3-F1): Confirm publisher.
        route("POST", ROUTE_POOL_SERVED_PUBLISHER),
        step_up(STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER),
        method(METHOD_SERVED_POOL_CONFIRM_PUBLISHER),
    ]);
    assert_eq!(pending, expected);
    for item in pending_approvals() {
        if matches!(
            item.id,
            OP_CUSTODY_RELEASE_POOL_CONTRIBUTION | OP_CUSTODY_SIGN_POOL_STATEMENT
        ) {
            assert_eq!(item.stage, "pool-release", "{}", item.id);
        }
        if matches!(
            item.id,
            ROUTE_POOLS_KNOWN | STEP_UP_KNOWN_POOL_ADD | METHOD_KNOWN_POOLS_READ
        ) {
            assert_eq!(item.stage, STAGE_POOL_PLAY, "{}", item.id);
        }
    }
    assert!(pending_approvals()
        .iter()
        .all(|item| item.approval == Approval::Pending173));
}

/// The wire values are law: a rename here breaks Homes already running.
#[test]
fn custody_wire_values_stay_fixed() {
    assert_eq!(TARGET_CUSTODY, "custody");
    assert_eq!(TARGET_COLLABORATION_CUSTODY, "collaboration-custody");
    assert_eq!(OP_COLLABORATION_CUSTODY_QUERY, "query");
    assert_eq!(OP_COLLABORATION_CUSTODY_DELIVER, "deliver");
    assert_eq!(
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        "release_pool_contribution"
    );
    assert_eq!(OP_CUSTODY_SIGN_POOL_STATEMENT, "sign_pool_statement");
    assert_eq!(
        OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        "provision_pool_node_share"
    );
    assert_eq!(STAGE_POOL_SEAL, "pool-seal");
    assert_eq!(MESSAGE_SERVICE_CUSTODY, "custody");
    assert_eq!(STEP_UP_LOCAL_NODE_INCLUDE, "custody.local_node.include");
    assert_eq!(STEP_UP_LOCAL_NODE_REMOVE, "custody.local_node.remove");
    assert_eq!(STEP_UP_POOL_INSTALL, "custody.pool.install");
    assert_eq!(STEP_UP_MESSAGES_ENABLE, "custody.messages.enable");
    assert_eq!(STEP_UP_NODE_REQUEST_APPROVE, "custody.node_request.approve");
    assert_eq!(OPERATOR_ACTION_NODE_CARD_READ, "custody.node_card.read");
    assert_eq!(MESSAGE_OFFER_QUERY, "elastos.custody.offer-query/v1");
    assert_eq!(MESSAGE_OFFER, "elastos.custody.offer/v1");
    assert_eq!(MESSAGE_NODE_REQUEST, "elastos.custody.node-request/v1");
    assert_eq!(MESSAGE_NODE_DECISION, "elastos.custody.node-decision/v1");
    assert_eq!(MESSAGE_POOL_ACTIVE, "elastos.custody.pool-active/v1");
    assert_eq!(
        MESSAGE_POOL_DESCRIPTOR,
        "elastos.custody.pool-descriptor/v1"
    );
    assert_eq!(TARGET_CUSTODY_POOL, "custody-pool");
    assert_eq!(OP_CUSTODY_POOL_DESCRIBE, "describe");
    assert_eq!(OP_CUSTODY_POOL_SESSION_PREPARE, "session.prepare");
    assert_eq!(OP_CUSTODY_POOL_SESSION_OPEN, "session.open");
    assert_eq!(OP_CUSTODY_POOL_SESSION_READ, "session.read");
    assert_eq!(OP_CUSTODY_POOL_SESSION_CLOSE, "session.close");
    assert_eq!(ROUTE_POOLS_KNOWN, "/api/apps/custody/pools/known");
    assert_eq!(STEP_UP_KNOWN_POOL_ADD, "custody.known_pool.add");
    assert_eq!(METHOD_KNOWN_POOLS_READ, "custody.known_pools.read");
    assert_eq!(METHOD_KNOWN_POOL_ADD, "custody.known_pool.add");
    assert_eq!(STAGE_POOL_PLAY, "pool-play");
    assert_eq!(INBOX_ACTION_APPROVE_REQUEST, "custody-approve-request");
    assert_eq!(INBOX_ACTION_DECLINE_REQUEST, "custody-decline-request");
    assert_eq!(INBOX_KIND_NODE_REQUEST, "custody_node_request");
    assert_eq!(INBOX_KIND_POOL_ACTIVE, "custody_pool_active");
    assert_eq!(ROUTE_SUMMARY, "/api/apps/custody/summary");
    assert_eq!(
        ROUTE_POOL_MEMBER_REGISTER,
        "/api/apps/custody/pool/members/:share/register"
    );
}

/// Plan B T2.2 (S2-U1): every decline code is a surface row, and every row is
/// a code; `too_many_pools` waits for #173 in stage `pool-hosting`.
#[test]
fn decline_codes_match_the_surface() {
    use crate::custody_consent_protocol::CustodyDeclineCode;
    let declared: Vec<&str> = declared_decline_codes().collect();
    let codes: Vec<&str> = CustodyDeclineCode::ALL
        .iter()
        .map(|code| code.code())
        .collect();
    assert_eq!(declared, codes);
    for code in CustodyDeclineCode::ALL {
        // The wire value is the serde name.
        assert_eq!(
            serde_json::to_value(code).unwrap(),
            serde_json::json!(code.code())
        );
    }
    let row = CUSTODY_SURFACE
        .iter()
        .find(|item| item.id == DECLINE_TOO_MANY_POOLS)
        .unwrap();
    assert_eq!(row.approval, Approval::Pending173);
    assert_eq!(row.stage, STAGE_POOL_HOSTING);
    assert_eq!(
        row.kind,
        SurfaceKind::DeclineCode {
            message: MESSAGE_NODE_DECISION
        }
    );
    for item in CUSTODY_SURFACE
        .iter()
        .filter(|item| matches!(item.kind, SurfaceKind::DeclineCode { .. }))
        .filter(|item| item.id != DECLINE_TOO_MANY_POOLS)
    {
        assert_eq!(item.approval, Approval::Existing, "{}", item.id);
    }
}

/// Plan B T2.3: Hosting's rows wait for #173 in stage `pool-hosting`.
#[test]
fn hosting_rows_are_pool_hosting_items() {
    for id in [
        ROUTE_POOLS_SERVED,
        ROUTE_POOL_SERVED,
        STEP_UP_SERVED_POOL_REMOVE,
        METHOD_SERVED_POOLS_READ,
        METHOD_SERVED_POOL_REMOVE,
        ROUTE_POOL_SERVED_PUBLISHER,
        STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER,
        METHOD_SERVED_POOL_CONFIRM_PUBLISHER,
    ] {
        let rows: Vec<_> = CUSTODY_SURFACE
            .iter()
            .filter(|item| item.id == id)
            .collect();
        assert!(!rows.is_empty(), "{id}");
        for row in rows {
            assert_eq!(row.stage, STAGE_POOL_HOSTING, "{id}");
            assert_eq!(row.approval, Approval::Pending173, "{id}");
        }
    }
}
