//! STAB-REPRO S2 on a pool MEMBER Home (red, no fix). The user's Share-link
//! screenshot came from Home-6, a member of Home-4's pool, which still got
//! "This item's pool cannot be reached from this Home yet. Add the pool in
//! Custody."
//!
//! The import (`import_runtime_custody_listing`) takes its route in
//! `rebuild_runtime_portable_content` from
//! `runtime_custody_composition_holds_key_envelope` alone. That reads only
//! `protected-content/custody-composition.json`. A member has a served pool
//! (`custody-served-pool.json`, `custody-served-pools.json`) but no
//! composition (Home-6 as found live), so it is routed exactly like a
//! stranger to the pool: `PoolBound`, then
//! `non_holder_check(PortableVerifyMode::Import)`, which refuses before the
//! pool, including the member's own served pool, is looked at.
//!
//! The key envelope is the live item's (Home-4 `runtime-listings/9672d187…`).

use std::sync::Arc;

use crate::protected_content_runtime as pcr;
use elastos_runtime::provider::ProviderRegistry;

const LIVE_KEY_ENVELOPE_B64: &str = "ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5rZXktZW52ZWxvcGUvdjEAAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmVuY3J5cHRlZC1jb250ZW50L3YxADwgcO75+dlViabaAf0vdNem25583gANd3r2bvXi52cGAAAAAACZhilqpRHEXhzf2pN7vufWtw6R84KEdeewmRiBoUYk5yDBNwAAH8Eaw13mhpmFxYqv7EJdjAJJ5Bf2WnTo8uDWMocgrWIPKAIDAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmN1c3RvZHktcG9vbC5pZGVudGl0eS92MQBoVhs44MatP6paxeMCeVn+/PgqDTYt4Pc/dbuWQgXxAgAAFK0AWGVsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY3VzdG9keS1lcG9jaC1pZGVudGl0eS92MQBYAUylfYRJ/PiXQRc2dStAqNzbGtruhX1+phTK+0jPvwAAENcAamVsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY3VzdG9keS1jb21taXR0ZWUtYXV0aG9yaXphdGlvbi5pZGVudGl0eS92MQBdsQQVq2QSNi4Nj3xL6RWFVyy9MFNg8MJSVMCoiOOeuwAAAaI=";

#[test]
fn stab_s2_share_link_import_on_a_pool_member_home_is_not_refused_as_unresolved() {
    // A member Home's data dir as Home-6 has it: no custody composition.
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let key_envelope = pcr::decode_canonical_contract_base64::<
        elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    >(LIVE_KEY_ENVELOPE_B64, 64 * 1024, "key envelope")
    .unwrap();

    // The import's own route decision, step by step.
    let holds =
        pcr::runtime_custody_composition_holds_key_envelope(dir.path(), &registry, &key_envelope)
            .unwrap();
    let route = pcr::draft_node_bindings_for(pcr::ItemMintPath::Composition, holds);
    let outcome = match route {
        pcr::DraftNodeBindings::Composition => Ok(()),
        pcr::DraftNodeBindings::PoolBound => {
            pcr::non_holder_check(pcr::PortableVerifyMode::Import).map(|_| ())
        }
    };
    assert!(
        outcome.is_ok(),
        "a Share-link import on a member of the item's pool must not be refused as \
         unresolved (holds={holds}, route={route:?}): {:#}",
        outcome.unwrap_err()
    );
}
