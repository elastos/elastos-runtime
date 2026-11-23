//! The custody wire surface, declared once.
//!
//! Every custody Carrier target and Carrier op is a row of
//! [`CUSTODY_SURFACE`]. Call sites use the constants below, and the Carrier
//! allow-list and the runtime-target check read the table, so a new item
//! lands in one place together with its approval state.
//!
//! The wire values are fixed: Homes already running speak them. Later work
//! only adds rows.
//!
//! `stage` names the work that brought an item:
//! - `runtime-custody`: the custody provider plane of protected content.

/// What kind of wire item a row declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SurfaceKind {
    /// A provider target that a Carrier peer may invoke. A runtime provider
    /// target is served by the Runtime's own provider registry entry.
    CarrierTarget { runtime_provider: bool },
    /// An op that a Carrier peer may invoke on `target`.
    CarrierOp { target: &'static str },
}

/// Whether the #173 approval record already covers an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Approval {
    Existing,
}

/// One declared custody wire item.
// Rows are read by the conformance tests and the #173 record today; later
// tasks read their ops and approvals at run time.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SurfaceItem {
    pub id: &'static str,
    pub kind: SurfaceKind,
    pub stage: &'static str,
    pub approval: Approval,
}

const STAGE_RUNTIME_CUSTODY: &str = "runtime-custody";

// Carrier targets and their ops.
pub(crate) const TARGET_CUSTODY: &str = "custody";
pub(crate) const OP_CUSTODY_STATUS: &str = "status";
pub(crate) const OP_CUSTODY_PROVISION_NODE_SHARE: &str = "provision_node_share";
pub(crate) const OP_CUSTODY_RELEASE_CONTRIBUTION: &str = "release_contribution";
pub(crate) const OP_CUSTODY_EVALUATE: &str = "evaluate";

const fn item(
    id: &'static str,
    kind: SurfaceKind,
    stage: &'static str,
    approval: Approval,
) -> SurfaceItem {
    SurfaceItem {
        id,
        kind,
        stage,
        approval,
    }
}

const fn existing(id: &'static str, kind: SurfaceKind, stage: &'static str) -> SurfaceItem {
    item(id, kind, stage, Approval::Existing)
}

const CUSTODY_OP: SurfaceKind = SurfaceKind::CarrierOp {
    target: TARGET_CUSTODY,
};

/// Every custody wire item.
pub(crate) const CUSTODY_SURFACE: &[SurfaceItem] = &[
    // Carrier targets.
    existing(
        TARGET_CUSTODY,
        SurfaceKind::CarrierTarget {
            runtime_provider: true,
        },
        STAGE_RUNTIME_CUSTODY,
    ),
    // Carrier ops.
    existing(OP_CUSTODY_STATUS, CUSTODY_OP, STAGE_RUNTIME_CUSTODY),
    existing(
        OP_CUSTODY_PROVISION_NODE_SHARE,
        CUSTODY_OP,
        STAGE_RUNTIME_CUSTODY,
    ),
    existing(
        OP_CUSTODY_RELEASE_CONTRIBUTION,
        CUSTODY_OP,
        STAGE_RUNTIME_CUSTODY,
    ),
    existing(OP_CUSTODY_EVALUATE, CUSTODY_OP, STAGE_RUNTIME_CUSTODY),
];

fn carrier_target(target: &str) -> Option<&'static SurfaceItem> {
    CUSTODY_SURFACE
        .iter()
        .find(|item| item.id == target && matches!(item.kind, SurfaceKind::CarrierTarget { .. }))
}

/// Whether a Carrier peer may invoke the custody provider target `target`.
pub(crate) fn carrier_target_allowed(target: &str) -> bool {
    carrier_target(target).is_some()
}

/// Whether `target` is a custody target the Runtime serves from its own
/// provider registry entry rather than a provider process.
pub(crate) fn is_runtime_provider_target(target: &str) -> bool {
    matches!(
        carrier_target(target).map(|item| item.kind),
        Some(SurfaceKind::CarrierTarget {
            runtime_provider: true
        })
    )
}

/// Every op `target` declares, in surface order.
pub(crate) fn declared_ops(target: &str) -> impl Iterator<Item = &'static str> + '_ {
    CUSTODY_SURFACE
        .iter()
        .filter_map(move |item| match item.kind {
            SurfaceKind::CarrierOp { target: declared } if declared == target => Some(item.id),
            _ => None,
        })
}

#[cfg(test)]
mod tests;
