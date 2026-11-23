//! Records the Runtime has already written to disk. Every later change must
//! keep reading them: each fixture decodes into today's type and encodes back
//! to the same JSON, and records written before a field gained its default
//! still decode.

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use super::super::{
    RuntimeCustodyListingOrigin, RuntimeCustodyListingRecord, RuntimeCustodyPurchaseProgress,
    RuntimeCustodyPurchaseRecord, RuntimeCustodyViewerLifecycleStatus, RuntimeCustodyViewerRecord,
    RUNTIME_LISTING_SCHEMA_V1, RUNTIME_PORTABLE_LISTING_SCHEMA_V1, RUNTIME_PURCHASE_SCHEMA_V1,
    RUNTIME_VIEWER_SCHEMA_V1,
};

const LISTING_LOCAL_V1: &[u8] = include_bytes!("../testdata/runtime-custody-listing-local-v1.json");
const LISTING_IMPORTED_V1: &[u8] =
    include_bytes!("../testdata/runtime-custody-listing-imported-v1.json");
const PURCHASE_PENDING_V1: &[u8] =
    include_bytes!("../testdata/runtime-custody-purchase-pending-v1.json");
const VIEWER_STATE_V1: &[u8] = include_bytes!("../testdata/runtime-custody-viewer-state-v1.json");
const VIEWER_STATE_V1_BEFORE_DEFAULTS: &[u8] =
    include_bytes!("../testdata/runtime-custody-viewer-state-v1-before-defaults.json");

fn decode_exact<T: DeserializeOwned + Serialize>(fixture: &[u8]) -> T {
    let original: Value = serde_json::from_slice(fixture).expect("fixture is JSON");
    let record: T = serde_json::from_slice(fixture).expect("fixture decodes");
    assert_eq!(
        serde_json::to_value(&record).expect("record encodes"),
        original,
        "record must encode back to the stored JSON"
    );
    record
}

#[test]
fn local_creator_listing_record_v1_keeps_reading() {
    let record: RuntimeCustodyListingRecord = decode_exact(LISTING_LOCAL_V1);
    assert_eq!(record.schema, RUNTIME_LISTING_SCHEMA_V1);
    assert_eq!(record.package.schema, RUNTIME_PORTABLE_LISTING_SCHEMA_V1);
    assert!(matches!(
        record.origin,
        RuntimeCustodyListingOrigin::LocalCreator { .. }
    ));
    assert!(record.package.payment_processor.is_some());
}

#[test]
fn imported_listing_record_v1_keeps_reading() {
    let record: RuntimeCustodyListingRecord = decode_exact(LISTING_IMPORTED_V1);
    assert!(matches!(
        record.origin,
        RuntimeCustodyListingOrigin::Imported { .. }
    ));
    assert!(record.package.payment_processor.is_some());
}

#[test]
fn pending_purchase_record_v1_keeps_reading() {
    let record: RuntimeCustodyPurchaseRecord = decode_exact(PURCHASE_PENDING_V1);
    assert_eq!(record.schema, RUNTIME_PURCHASE_SCHEMA_V1);
    assert!(record.approval_stage.is_some());
    assert!(matches!(
        record.progress,
        RuntimeCustodyPurchaseProgress::Pending {
            confirmed_buy: None
        }
    ));
}

#[test]
fn viewer_state_record_v1_keeps_reading() {
    let record: RuntimeCustodyViewerRecord = decode_exact(VIEWER_STATE_V1);
    assert_eq!(record.schema, RUNTIME_VIEWER_SCHEMA_V1);
    assert_eq!(
        record.lifecycle_status,
        RuntimeCustodyViewerLifecycleStatus::Active
    );
    assert_eq!(record.next_media_part_index, 3);
    assert!(record.pending_release.is_some());
}

#[test]
fn viewer_state_record_v1_before_defaults_keeps_reading() {
    let record: RuntimeCustodyViewerRecord =
        serde_json::from_slice(VIEWER_STATE_V1_BEFORE_DEFAULTS).expect("older record decodes");
    assert_eq!(record.next_media_part_index, 0);
    assert!(record.pending_release.is_none());
    assert_eq!(
        record.lifecycle_status,
        RuntimeCustodyViewerLifecycleStatus::Closed
    );
}

// The same records read through the Runtime's own loaders, from where the
// Runtime keeps them, so path, ownership and identity checks apply too.

fn owner_only_data_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("temp dir");
    let data_dir = temp.path().join("data");
    super::support::owner_only_dir(&data_dir);
    (temp, data_dir)
}

#[cfg(unix)]
#[test]
fn listing_record_v1_loads_from_its_runtime_path() {
    let (_temp, data) = owner_only_data_dir();
    let decoded: RuntimeCustodyListingRecord = decode_exact(LISTING_LOCAL_V1);
    let mint_id = super::super::parse_mint_id_hex(&decoded.package.mint_id).expect("mint id");
    super::super::write_owner_only_bytes(
        &super::super::runtime_listing_path(data.as_path(), mint_id),
        LISTING_LOCAL_V1,
    )
    .expect("fixture is placed");
    let loaded = super::super::load_runtime_custody_listing(data.as_path(), mint_id)
        .expect("listing loads")
        .expect("listing is present");
    assert_eq!(loaded, decoded);
}

#[cfg(unix)]
#[test]
fn purchase_record_v1_loads_from_its_runtime_path() {
    let (_temp, data) = owner_only_data_dir();
    let decoded: RuntimeCustodyPurchaseRecord = decode_exact(PURCHASE_PENDING_V1);
    let mint_id = super::super::parse_mint_id_hex(&decoded.mint_id).expect("mint id");
    super::super::write_owner_only_bytes(
        &super::super::runtime_purchase_path(data.as_path(), &decoded.principal_id, mint_id),
        PURCHASE_PENDING_V1,
    )
    .expect("fixture is placed");
    let loaded =
        super::super::load_runtime_custody_purchase(data.as_path(), &decoded.principal_id, mint_id)
            .expect("purchase loads")
            .expect("purchase is present");
    assert_eq!(loaded, decoded);
}

#[cfg(unix)]
#[test]
fn viewer_state_record_v1_loads_from_its_runtime_path() {
    let (_temp, data) = owner_only_data_dir();
    let decoded: RuntimeCustodyViewerRecord = decode_exact(VIEWER_STATE_V1);
    let mint_id = super::super::parse_mint_id_hex(&decoded.mint_id).expect("mint id");
    super::super::write_owner_only_bytes(
        &super::super::runtime_viewer_path(data.as_path(), &decoded.principal_id, mint_id),
        VIEWER_STATE_V1,
    )
    .expect("fixture is placed");
    let loaded = super::super::load_runtime_custody_viewer_record(
        data.as_path(),
        &decoded.principal_id,
        mint_id,
    )
    .expect("viewer record loads")
    .expect("viewer record is present");
    assert!(loaded == decoded);
}

/// Set on an unchanged tree to record the Runtime-written listing once.
const RECORD_LISTING_FIXTURE: &str = "ELASTOS_RECORD_LISTING_FIXTURE";

#[cfg(unix)]
#[test]
fn local_creator_listing_v1_fixture_is_what_the_runtime_writes() {
    let (_temp, data) = owner_only_data_dir();
    let mint_id = elastos_protected_content_contracts::Digest32::new([0x11; 32]);
    let record = super::support::runtime_custody_listing_record_for_test(
        mint_id,
        "person:local:fixture",
        "Fixture item",
        1_763_700_000,
    );
    super::super::persist_runtime_custody_listing(data.as_path(), &record)
        .expect("listing persists");
    let written = std::fs::read(super::super::runtime_listing_path(data.as_path(), mint_id))
        .expect("listing file");
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/protected_content_runtime/testdata/runtime-custody-listing-local-v1.json"
    );
    if std::env::var_os(RECORD_LISTING_FIXTURE).is_some() {
        std::fs::write(fixture, &written).expect("fixture is recorded");
    }
    assert_eq!(
        written, LISTING_LOCAL_V1,
        "the listing record encoding moved"
    );
}
