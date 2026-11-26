//! STAB-REPRO S2 (red, no fix): on Home-7, Marketplace > Add listing with a
//! Share link answers "This item's pool cannot be reached from this Home
//! yet. Add the pool in Custody." although Home-7 already uses the item's
//! pool (Home-4's, in `custody-known-pools.json`).
//!
//! A Share link names the listing package folder (`listing.json`), so the
//! page sends it to `import_runtime_custody`. Home-7 has no custody
//! composition, so `runtime_custody_composition_holds_key_envelope` is
//! `false` and the import takes the non-holder rebuild
//! (`rebuild_non_holder_portable_content`). Its first line,
//! `non_holder_check(PortableVerifyMode::Import)`, refuses every import
//! with `RuntimeCustodyUnresolved` before the item's pool is resolved at
//! all, so a Home that knows the pool is refused the same as one that does
//! not.

#[test]
fn stab_s2_import_on_a_non_holder_is_not_refused_before_its_pool_is_resolved() {
    use crate::protected_content_runtime as pcr;
    let answer = pcr::non_holder_check(pcr::PortableVerifyMode::Import);
    assert!(
        answer.is_ok(),
        "an import on a Home that does not hold the ciphertext must reach the \
         pool resolution, not be refused up front: {:#}",
        answer.unwrap_err()
    );
}
