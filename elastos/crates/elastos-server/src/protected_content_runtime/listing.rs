use super::*;
use elastos_protected_content_provider_contracts::PROTECTION;
use elastos_protected_content_runtime::RuntimeContentIdentityV1;

/// The fewest verified copies a protected item may have and still be listed,
/// bought or opened. One: the creator's Home holds the ciphertext and serves
/// it to any peer. Listings verified with more copies stay valid, and a raised
/// new-mint target leaves this floor alone, so items already listed keep
/// their validity.
pub(crate) const PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR: u32 = 1;

/// The native pay token: the pay token a granted listing states.
pub(crate) const RUNTIME_CUSTODY_ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

const RUNTIME_LISTING_SOURCE_ROOT: &str = "protected-content/runtime-listing-sources";

pub(super) const RUNTIME_LISTING_SCHEMA_V1: &str = "elastos.library.runtime-custody-listing/v1";

pub(super) const RUNTIME_PORTABLE_LISTING_SCHEMA_V1: &str =
    "elastos.protected-content.portable-listing/v1";

const RUNTIME_PORTABLE_LISTING_SCHEMA_V2: &str = "elastos.protected-content.portable-listing/v2";

pub(super) const RUNTIME_PORTABLE_LISTING_SCHEMA_V3: &str =
    "elastos.protected-content.portable-listing/v3";

pub(super) const MAX_RUNTIME_PORTABLE_LISTING_BYTES: u64 = 128 * 1024;

/// V3 carries the base64-encoded signed completion and its file CID table.
pub(crate) const MAX_RUNTIME_REMOTE_PORTABLE_LISTING_BYTES: u64 = 1024 * 1024;

/// Plan B T4.6: the availability a purchase records when the listing proved
/// it by a verified fetch, which makes no receipt.
pub(crate) const RUNTIME_PURCHASE_VERIFIED_FETCH_DIGEST: &str = "verified-fetch";

pub(super) const RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-listings/v1";

pub(super) const RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-availability-summary/v1";

const RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE: &str = "available";

const RUNTIME_CUSTODY_LISTING_ACCESS_CREATOR: &str = "creator";

const RUNTIME_CUSTODY_LISTING_ACCESS_PURCHASED: &str = "purchased";

pub(super) const MAX_RUNTIME_CUSTODY_LISTINGS: usize = 128;

pub(super) const MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES: usize = 256;

pub(super) const RUNTIME_POOL_MINT_SHARE_SCHEMA_V1: &str =
    "elastos.protected-content.runtime-pool-mint/v2";

/// What a pool-minted listing carries (S7I-F2): this Runtime's signed share
/// statement for the item, kept per mint once its custody is provisioned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePoolMintRecordV2 {
    pub(super) schema: String,
    /// Standard base64 of the `SignedPoolMintShareV1` canonical bytes.
    pub(crate) mint_share_base64: String,
}

pub(super) fn runtime_pool_mint_path(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    runtime_pool_mints_dir(data_dir).join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

/// The pool mint record of `mint_id`, if this Home minted it into a pool it
/// uses.
pub(crate) fn runtime_pool_mint_record(
    data_dir: &Path,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimePoolMintRecordV2>> {
    let Some(record) = read_runtime_pool_mint_file::<RuntimePoolMintRecordV2>(
        &runtime_pool_mint_path(data_dir, mint_id),
    )?
    else {
        return Ok(None);
    };
    if record.schema != RUNTIME_POOL_MINT_SHARE_SCHEMA_V1 {
        anyhow::bail!("the runtime pool mint record has an unknown schema");
    }
    Ok(Some(record))
}

/// The manifest of a V1 media item names exactly its identity's files.
/// Plan B T4.6: also the open's manifest-only check on a non-holder.
pub(super) fn protected_content_media_manifest_files(
    manifest: &crate::content::ContentObjectManifest,
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let expected_files = protected_content_files(media_identity)?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !content_object_files_match(&manifest.files, &expected_files)
        || manifest.content_digest != content_object_digest(&expected_files)
    {
        anyhow::bail!("protected content object manifest is invalid");
    }
    Ok(expected_files)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePortableListingPackage {
    pub(crate) schema: String,
    pub(crate) mint_id: String,
    pub(crate) content_id: String,
    pub(crate) content_cid: String,
    pub(crate) metadata_cid: String,
    pub(crate) token_uri: String,
    pub(crate) publisher_profile_did: String,
    pub(crate) display_name: String,
    /// Media listings only. Kept as the FIRST of the two identity fields and
    /// in its original position so a media package's JSON is byte-identical
    /// to what every listing already on disk carries — `package_sha256`
    /// (recomputed over `serde_json::to_vec(package)` on every load) and the
    /// listing CID both depend on that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) media_identity_base64: Option<String>,
    /// Object listings only: a `RuntimeContentIdentityV1` canonical encoding
    /// (kind byte ‖ nested identity), reusing Task 12's already-reviewed
    /// encoding rather than inventing a second one. Absent on every media
    /// listing, so media packages keep their exact pre-object bytes.
    ///
    /// Exactly one of the two fields is present; see
    /// [`RuntimePortableListingPackage::decode_and_validate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) content_identity_base64: Option<String>,
    pub(crate) content_access_id: String,
    pub(crate) key_envelope_identity_base64: String,
    pub(crate) rights_policy_identity_base64: String,
    pub(crate) content_key_commitment_base64: String,
    pub(crate) seller_address: String,
    pub(crate) chain_namespace: String,
    pub(crate) network: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payment_processor: Option<String>,
    /// The mint's own transaction. Absent only on a listing adopted from an
    /// asset's shared `metadata.json` (origin `Asset`): chain and document do
    /// not state it, and a made-up hash would be a fabricated fact (D11).
    /// Skipped when absent so every package that carries it keeps its bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mint_transaction_hash: Option<String>,
    /// When the creator published it. Absent exactly when
    /// `mint_transaction_hash` is, for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) published_at: Option<u64>,
    /// Plan B POOL-MINT (S7I-F2): an item a Home minted through a pool it
    /// uses carries the minting Home's signed share statement for it, so
    /// every Home, the pool owner included, rebuilds it on the pool path with
    /// the same `mint_id`. Absent keeps every other package's bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pool_mint_share_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sealed_rights_policy_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) remote_seal: Option<RuntimePortableRemoteSealV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePortableRemoteSealV1 {
    pub(super) descriptor_base64: String,
    pub(super) request_base64: String,
    pub(super) completion_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeSourceListing {
    pub(crate) listing_uri: String,
    pub(crate) package_sha256: String,
}

impl RuntimeSourceListing {
    fn validate(&self) -> anyhow::Result<()> {
        if self.listing_uri
            != format!(
                "elastos://{}",
                runtime_portable_listing_cid(&self.listing_uri)?
            )
            || self.package_sha256.len() != 64
            || !self
                .package_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        Ok(())
    }
}

fn runtime_adopted_asset_cid(uri: &str) -> Option<&str> {
    let cid = uri
        .strip_prefix("elastos://")
        .or_else(|| uri.strip_prefix("ipfs://"))?;
    validate_runtime_custody_cid(cid).ok()?;
    Some(cid)
}

/// Optional local metadata, outside the closed listing/v1 format so an older
/// Runtime can still read and open the listing after an upgrade or rollback.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeListingSourceExtension {
    schema: String,
    mint_id: String,
    local_package_sha256: String,
    asset_cid: String,
    source_listing: RuntimeSourceListing,
}

impl RuntimeListingSourceExtension {
    const SCHEMA: &'static str = "elastos.library.runtime-listing-source/v1";
    const MAX_BYTES: u64 = 4096;

    fn for_record(record: &RuntimeCustodyListingRecord) -> anyhow::Result<Option<Self>> {
        let RuntimeCustodyListingOrigin::Asset {
            asset_uri,
            source_listing: Some(source),
        } = &record.origin
        else {
            return Ok(None);
        };
        source.validate()?;
        parse_mint_id_hex(&record.package.mint_id)?;
        let asset_cid = runtime_adopted_asset_cid(asset_uri)
            .filter(|cid| *cid == record.package.metadata_cid)
            .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
        Ok(Some(Self {
            schema: Self::SCHEMA.to_string(),
            mint_id: record.package.mint_id.clone(),
            local_package_sha256: runtime_portable_package_sha256(&record.package),
            asset_cid: asset_cid.to_string(),
            source_listing: source.clone(),
        }))
    }

    fn matches(&self, record: &RuntimeCustodyListingRecord) -> bool {
        let RuntimeCustodyListingOrigin::Asset { asset_uri, .. } = &record.origin else {
            return false;
        };
        self.schema == Self::SCHEMA
            && self.mint_id == record.package.mint_id
            && self.local_package_sha256 == runtime_portable_package_sha256(&record.package)
            && self.asset_cid == record.package.metadata_cid
            && runtime_adopted_asset_cid(asset_uri) == Some(self.asset_cid.as_str())
            && self.source_listing.validate().is_ok()
    }
}

fn runtime_listing_source_path(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    data_dir
        .join(RUNTIME_LISTING_SOURCE_ROOT)
        .join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

fn open_runtime_listing_source_file(path: &Path) -> anyhow::Result<fs::File> {
    let invalid = || anyhow::anyhow!("Runtime listing source extension is invalid");
    // lstat rejects an ordinary FIFO before open. Nonblocking/no-follow
    // also prevents a concurrent file swap from blocking or following a link.
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() {
        return Err(invalid());
    }
    #[cfg(unix)]
    validate_owner_only_metadata_with_error(
        "Runtime listing source extension",
        &before,
        true,
        |_| anyhow::anyhow!("Runtime listing source extension is invalid"),
    )?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let after = file.metadata()?;
    if !after.is_file() {
        return Err(invalid());
    }
    #[cfg(unix)]
    validate_owner_only_metadata_with_error(
        "Runtime listing source extension",
        &after,
        true,
        |_| anyhow::anyhow!("Runtime listing source extension is invalid"),
    )?;
    Ok(file)
}

fn decode_runtime_listing_record(
    data_dir: &Path,
    bytes: &[u8],
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    let mut record: RuntimeCustodyListingRecord = serde_json::from_slice(bytes)?;
    // The base keeps its original error/validation semantics. Optional local
    // provenance must never make a paid listing unreadable or unauthorize it.
    let source = (|| -> anyhow::Result<RuntimeListingSourceExtension> {
        let mint_id = parse_mint_id_hex(&record.package.mint_id)?;
        let file =
            open_runtime_listing_source_file(&runtime_listing_source_path(data_dir, mint_id))?;
        let mut bytes = Vec::new();
        file.take(RuntimeListingSourceExtension::MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > RuntimeListingSourceExtension::MAX_BYTES {
            anyhow::bail!("Runtime listing source extension is invalid");
        }
        Ok(serde_json::from_slice(&bytes)?)
    })();
    let Ok(source) = source else {
        return Ok(record);
    };
    if !source.matches(&record) {
        return Ok(record);
    }
    if let RuntimeCustodyListingOrigin::Asset { source_listing, .. } = &mut record.origin {
        *source_listing = Some(source.source_listing);
    }
    Ok(record)
}

fn availability_kind_receipt() -> String {
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::RECEIPT.to_string()
}

fn availability_kind_is_receipt(kind: &str) -> bool {
    kind == elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::RECEIPT
}

/// Plan B T4.6: `kind` says how availability was proven. A record written
/// before it has no `kind` and reads as a receipt; a receipt is written
/// without `kind`, so such a record keeps its exact bytes. A verified fetch
/// has no replicas and no receipt digest (both empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyListingAvailabilitySummary {
    #[serde(
        default = "availability_kind_receipt",
        skip_serializing_if = "availability_kind_is_receipt"
    )]
    pub(super) kind: String,
    pub(super) checked_at: u64,
    pub(super) observed_replicas: u32,
    pub(super) receipt_digest: String,
}

impl RuntimeCustodyListingAvailabilitySummary {
    pub(crate) fn from_evidence(
        evidence: &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
    ) -> Self {
        Self {
            kind: evidence.kind().to_string(),
            checked_at: evidence.checked_at(),
            observed_replicas: evidence.observed_replicas(),
            receipt_digest: evidence
                .receipt_digest()
                .map(|digest| hex::encode(digest.as_bytes()))
                .unwrap_or_default(),
        }
    }

    pub(crate) fn is_verified_fetch(&self) -> bool {
        self.kind
            == elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH
    }

    /// What a purchase records of this availability: the receipt digest, or
    /// `verified-fetch` when no receipt was made (Plan B T4.6).
    pub(crate) fn purchase_digest(&self) -> String {
        if self.is_verified_fetch() {
            RUNTIME_PURCHASE_VERIFIED_FETCH_DIGEST.to_string()
        } else {
            format!("sha256:{}", self.receipt_digest)
        }
    }

    /// The availability receipt this listing was recorded against, as the bare
    /// hex the record stores. Callers that need the `sha256:` spelling add it.
    // Unused since T4.6 records `purchase_digest`; kept for review.
    #[allow(dead_code)]
    pub(crate) fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyListingRecord {
    pub(crate) schema: String,
    pub(crate) origin: RuntimeCustodyListingOrigin,
    pub(crate) package: RuntimePortableListingPackage,
    pub(crate) availability: RuntimeCustodyListingAvailabilitySummary,
}

impl RuntimeCustodyListingRecord {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != RUNTIME_LISTING_SCHEMA_V1 {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        self.package.decode_and_validate()?;
        match &self.origin {
            RuntimeCustodyListingOrigin::LocalCreator {
                principal_id,
                listing_uri,
                package_sha256,
            } => {
                validate_runtime_custody_public_text(principal_id)?;
                validate_runtime_portable_listing_origin(
                    listing_uri,
                    package_sha256,
                    &self.package,
                )?;
                validate_runtime_published_package_facts(&self.package)?;
            }
            RuntimeCustodyListingOrigin::Imported {
                listing_uri,
                package_sha256,
            } => {
                validate_runtime_portable_listing_origin(
                    listing_uri,
                    package_sha256,
                    &self.package,
                )?;
                validate_runtime_published_package_facts(&self.package)?;
            }
            RuntimeCustodyListingOrigin::Asset {
                asset_uri,
                source_listing,
            } => {
                validate_runtime_adopted_package_facts(asset_uri, &self.package)?;
                if let Some(source) = source_listing {
                    source.validate()?;
                }
            }
            RuntimeCustodyListingOrigin::Granted { asset_uri } => {
                validate_runtime_adopted_package_facts(asset_uri, &self.package)?;
                validate_runtime_granted_package_terms(&self.package)?;
            }
        }
        let availability = &self.availability;
        let valid = match availability.kind.as_str() {
            elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::RECEIPT => {
                availability.observed_replicas >= PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
                    && availability.receipt_digest.len() == 64
                    && hex::decode(&availability.receipt_digest)
                        .is_ok_and(|bytes| bytes.len() == 32)
            }
            // Only an adopted listing on a non-holder proves availability by
            // a verified fetch (S4-U2).
            elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH => {
                matches!(
                    self.origin,
                    RuntimeCustodyListingOrigin::Asset { .. }
                        | RuntimeCustodyListingOrigin::Granted { .. }
                ) && availability.observed_replicas == 0
                    && availability.receipt_digest.is_empty()
            }
            _ => false,
        };
        if availability.checked_at == 0 || !valid {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        Ok(())
    }

    pub(crate) fn portable_package_digest(&self) -> String {
        let package_sha256 = match &self.origin {
            RuntimeCustodyListingOrigin::LocalCreator { package_sha256, .. }
            | RuntimeCustodyListingOrigin::Imported { package_sha256, .. } => {
                package_sha256.clone()
            }
            // Never published, so never stated: computed over the package the
            // same way a published one's digest was, which is what a purchase
            // record binds to.
            RuntimeCustodyListingOrigin::Asset { .. }
            | RuntimeCustodyListingOrigin::Granted { .. } => {
                runtime_portable_package_sha256(&self.package)
            }
        };
        format!("sha256:{package_sha256}")
    }
}

/// `sha256` over a package's canonical bytes, bare hex.
fn runtime_portable_package_sha256(package: &RuntimePortableListingPackage) -> String {
    serde_json::to_vec(package)
        .map(|bytes| hex::encode(sha2::Sha256::digest(bytes)))
        .unwrap_or_default()
}

/// A package this Runtime or another one published (origins `LocalCreator`
/// and `Imported`): the mint's transaction and publication time are facts it
/// states, and its publisher is a Runtime profile, a `did:key`.
fn validate_runtime_published_package_facts(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    if package.mint_transaction_hash.is_none() || package.published_at.is_none() {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    crate::crypto::decode_did_key(&package.publisher_profile_did)
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

/// A package adopted from an asset's shared `metadata.json` (origin `Asset`,
/// D11 and D16): it states neither fact the shared document lacks, its
/// publisher is the document's `did:pkh` on the package's own chain, and the
/// asset it names is the package's own metadata folder.
fn validate_runtime_adopted_package_facts(
    asset_uri: &str,
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    if package.mint_transaction_hash.is_some()
        || package.published_at.is_some()
        || runtime_portable_listing_cid(asset_uri)? != package.metadata_cid
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    let chain_id = package
        .chain_namespace
        .strip_prefix("eip155:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    match parse_runtime_publisher_pkh(&package.publisher_profile_did) {
        Some((pkh_chain_id, _)) if pkh_chain_id == chain_id => Ok(()),
        _ => anyhow::bail!("Runtime custody portable listing is invalid"),
    }
}

/// The terms a granted listing states (origin `Granted`): one copy, sold by
/// the item's own operative for nothing in the native token. No seller ever
/// offered them, which is what keeps them from passing for an offer.
fn runtime_granted_package_terms(operative: &str) -> (String, String, String, String) {
    (
        operative.to_ascii_lowercase(),
        "0x1".to_string(),
        "0x0".to_string(),
        RUNTIME_CUSTODY_ZERO_ADDRESS.to_string(),
    )
}

fn validate_runtime_granted_package_terms(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    let (seller_address, quantity, price, pay_token) =
        runtime_granted_package_terms(&package.operative);
    if package.seller_address != seller_address
        || package.quantity != quantity
        || package.price != price
        || package.pay_token != pay_token
        || package.payment_processor.is_some()
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(())
}

fn validate_runtime_portable_listing_origin(
    listing_uri: &str,
    package_sha256: &str,
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    if listing_uri != format!("elastos://{}", runtime_portable_listing_cid(listing_uri)?)
        || package_sha256.len() != 64
        || hex::decode(package_sha256).map_or(true, |bytes| bytes.len() != 32)
        || package_sha256 != hex::encode(sha2::Sha256::digest(serde_json::to_vec(package)?))
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(super) struct DecodedRuntimePortableAsset {
    pub(super) content_identity: RuntimeContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    rights_policy: RightsPolicyIdentityV1,
    content_key_commitment: Digest32,
    /// POOL-MINT: minted through a pool its minter uses (signed share statement).
    pool_minted: bool,
    remote_content_publisher: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePortableMetadata {
    schema: String,
    name: String,
    mime_type: String,
    codecs: String,
    encrypted_content_cid: String,
    content_access_id: String,
    protected_content_identity: String,
    mint_id: String,
    publisher_profile_did: String,
    /// Mirrors [`RuntimePortableListingPackage`]'s pair exactly (same order,
    /// same skip-when-absent rule), so a media metadata document keeps its
    /// pre-object bytes and `verify_runtime_portable_metadata` can compare
    /// both fields field-for-field against the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media_identity_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_identity_base64: Option<String>,
    key_envelope_identity_base64: String,
    rights_policy_identity_base64: String,
    content_key_commitment_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rights_policy_seal_required: Option<bool>,
}

/// The two base64 identity fields a portable listing/metadata document
/// carries for `content_identity`: `(media_identity_base64,
/// content_identity_base64)`, exactly one of which is `Some`.
///
/// Media keeps writing `media_identity_base64` with the bare
/// `CencFmp4MediaIdentityV1` canonical bytes it always wrote — the object
/// widening must not move a single byte of a media listing, because
/// `package_sha256` and the listing CID are computed over them.
pub(crate) fn runtime_portable_identity_fields(
    content_identity: &RuntimeContentIdentityV1,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    match content_identity {
        RuntimeContentIdentityV1::Media(media) => Ok((
            Some(base64::engine::general_purpose::STANDARD.encode(media.canonical_bytes()?)),
            None,
        )),
        // A head rides the object field, kind byte included (spec section 2).
        RuntimeContentIdentityV1::Object(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            Ok((
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(
                    content_identity.canonical_bytes().map_err(|_| {
                        anyhow::anyhow!("Runtime custody portable listing is invalid")
                    })?,
                )),
            ))
        }
    }
}

/// The `codecs` declaration a portable listing carries for a content kind:
/// the media identity's own `codecs` string, and the empty string for an
/// object, which has no codec declaration at all. Not a placeholder that is
/// then ignored — `verify_runtime_portable_metadata` compares the published
/// document's `codecs` against exactly this value, so an object metadata
/// document declaring any codec is rejected.
pub(crate) fn runtime_portable_content_codecs(
    content_identity: &RuntimeContentIdentityV1,
) -> std::borrow::Cow<'_, str> {
    match content_identity {
        RuntimeContentIdentityV1::Media(media) => std::borrow::Cow::Borrowed(media.codecs()),
        // The head pins its codecs per kind, so the joined string is the head's
        // own: video first, then audio, as the head lists them.
        RuntimeContentIdentityV1::MediaDash(head) => std::borrow::Cow::Owned(
            head.renditions()
                .iter()
                .map(|rendition| rendition.codecs())
                .collect::<Vec<_>>()
                .join(","),
        ),
        RuntimeContentIdentityV1::Object(_) => std::borrow::Cow::Borrowed(""),
    }
}

impl RuntimePortableListingPackage {
    pub(crate) fn check_encoded_listing_size(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let limit = if self.schema == RUNTIME_PORTABLE_LISTING_SCHEMA_V3 {
            MAX_RUNTIME_REMOTE_PORTABLE_LISTING_BYTES
        } else {
            MAX_RUNTIME_PORTABLE_LISTING_BYTES
        };
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "Runtime custody portable listing is too large"
        );
        Ok(())
    }

    fn policy_creator(&self) -> &str {
        self.publisher_profile_did
            .strip_prefix(&format!("did:pkh:{}:", self.chain_namespace))
            .unwrap_or(&self.seller_address)
    }

    /// The finalized policy retains the draft's original policy and adds the
    /// exact chain item. The provisional identity still determines the mint ID.
    pub(super) fn sealed_policy(&self) -> anyhow::Result<Option<RightsPolicyBodyV1>> {
        let Some(encoded) = self.sealed_rights_policy_base64.as_deref() else {
            return Ok(None);
        };
        let policy: RightsPolicyBodyV1 =
            decode_runtime_portable_contract(encoded, MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize)?;
        let item = elastos_protected_content_runtime::RuntimeMintedItemV1::from_parts(
            &self.chain_namespace,
            &self.ledger,
            &self.token_id,
            self.policy_creator(),
        )?;
        let provisional: RightsPolicyIdentityV1 = decode_runtime_portable_contract(
            &self.rights_policy_identity_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
        anyhow::ensure!(
            policy.unsealed().policy_identity()? == provisional
                && policy.chain_id() == item.chain_id()
                && policy.expected_item() == Some(item.expected_item())
                && runtime_content_access_id_hex(policy.content_access_id())
                    == self.content_access_id,
            "the sealed policy does not match the portable listing",
        );
        Ok(Some(policy))
    }

    pub(super) fn decode_and_validate(&self) -> anyhow::Result<DecodedRuntimePortableAsset> {
        // The token URI names the metadata DIRECTORY. It used to name the
        // `metadata.json` inside it, which is what put a doubled path on chain
        // once the Operative appended its own suffix, so listings published
        // before that fix carry the older spelling and still verify.
        let directory_uri = format!("ipfs://{}", self.metadata_cid);
        let legacy_file_uri = format!("{directory_uri}/metadata.json");
        let expected_schema = if self.remote_seal.is_some() {
            anyhow::ensure!(
                self.sealed_rights_policy_base64.is_some(),
                "a remote mint needs a sealed rights policy"
            );
            RUNTIME_PORTABLE_LISTING_SCHEMA_V3
        } else if self.sealed_rights_policy_base64.is_some() {
            RUNTIME_PORTABLE_LISTING_SCHEMA_V2
        } else {
            RUNTIME_PORTABLE_LISTING_SCHEMA_V1
        };
        if self.schema != expected_schema
            || (self.token_uri != directory_uri && self.token_uri != legacy_file_uri)
            || self.published_at == Some(0)
        {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let _ = parse_mint_id_hex(&self.mint_id)?;
        validate_runtime_custody_public_text(&self.content_id)?;
        validate_runtime_custody_cid(&self.content_cid)?;
        validate_runtime_custody_cid(&self.metadata_cid)?;
        validate_runtime_custody_profile_did(&self.publisher_profile_did)?;
        validate_runtime_custody_display_name(&self.display_name)?;
        validate_runtime_custody_evm_address(&self.seller_address)?;
        validate_runtime_custody_public_text(&self.chain_namespace)?;
        validate_runtime_custody_public_text(&self.network)?;
        validate_runtime_custody_evm_address(&self.ledger)?;
        validate_runtime_custody_canonical_quantity(&self.token_id)?;
        validate_runtime_custody_evm_address(&self.operative)?;
        validate_runtime_custody_canonical_quantity(&self.quantity)?;
        validate_runtime_custody_canonical_quantity(&self.price)?;
        validate_runtime_custody_evm_address(&self.pay_token)?;
        if let Some(payment_processor) = &self.payment_processor {
            validate_runtime_custody_evm_address(payment_processor)?;
        }
        // Both facts are optional at this level; which origin may omit them
        // is `RuntimeCustodyListingRecord::validate`'s to judge. What is
        // present must still be canonical.
        if let Some(mint_transaction_hash) = &self.mint_transaction_hash {
            let transaction_hash = decode_0x_hex(mint_transaction_hash)
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
            if *mint_transaction_hash != format!("0x{}", hex::encode(transaction_hash)) {
                anyhow::bail!("Runtime custody portable listing is invalid");
            }
        }
        // Exactly one identity field, dispatched on which one is present —
        // never a default, never a silently-ignored second field. A media
        // listing MUST use `media_identity_base64` (the bare media canonical
        // bytes it always used); an object listing MUST use
        // `content_identity_base64`. A `RuntimeContentIdentityV1::Media`
        // hiding inside `content_identity_base64` is a cross-kind encoding
        // that would give one listing two possible byte encodings, so it is
        // rejected rather than accepted.
        let content_identity = match (&self.media_identity_base64, &self.content_identity_base64) {
            (Some(media_identity_base64), None) => {
                RuntimeContentIdentityV1::Media(decode_runtime_portable_contract(
                    media_identity_base64,
                    MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
                )?)
            }
            (None, Some(content_identity_base64)) => {
                let decoded = RuntimeContentIdentityV1::from_canonical_bytes(
                    &decode_runtime_portable_base64(
                        content_identity_base64,
                        MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
                    )?,
                )
                .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
                match decoded {
                    RuntimeContentIdentityV1::Object(_)
                    | RuntimeContentIdentityV1::MediaDash(_) => decoded,
                    RuntimeContentIdentityV1::Media(_) => {
                        anyhow::bail!("Runtime custody portable listing is invalid")
                    }
                }
            }
            (Some(_), Some(_)) | (None, None) => {
                anyhow::bail!("Runtime custody portable listing is invalid")
            }
        };
        let key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1 =
            decode_runtime_portable_contract(
                &self.key_envelope_identity_base64,
                MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
            )?;
        let rights_policy = decode_runtime_portable_contract(
            &self.rights_policy_identity_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
        let content_access_id = ContentAccessIdV1::new(
            decode_0x_hex(&self.content_access_id)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        if self.content_access_id != format!("0x{}", hex::encode(content_access_id.as_bytes())) {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let content_key_commitment = Digest32::new(
            decode_runtime_portable_base64(&self.content_key_commitment_base64, 32)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?,
        );
        if content_identity.encrypted_content() != key_envelope.encrypted_content()
            || runtime_protected_content_id(content_identity.encrypted_content())?
                != self.content_id
            || content_identity.content_type().len() > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
            || runtime_portable_content_codecs(&content_identity).len()
                > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
        {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let pool_minter = verify_pool_mint_share(
            self.pool_mint_share_b64.as_deref(),
            &key_envelope,
            content_access_id,
        )?;
        if let Some(policy) = self.sealed_policy()? {
            anyhow::ensure!(
                policy.encrypted_content() == content_identity.encrypted_content(),
                "the sealed policy names different encrypted content",
            );
        }
        let remote_content_publisher = self
            .remote_seal
            .as_ref()
            .map(|proof| {
                let minter = pool_minter.ok_or_else(|| {
                    anyhow::anyhow!("a remotely sealed listing must bind its pool mint")
                })?;
                proof.verify(
                    &key_envelope,
                    content_access_id,
                    &content_identity,
                    content_key_commitment,
                    &self.content_cid,
                    minter,
                )
            })
            .transpose()?;
        Ok(DecodedRuntimePortableAsset {
            content_identity,
            content_access_id,
            key_envelope,
            rights_policy,
            content_key_commitment,
            pool_minted: pool_minter.is_some(),
            remote_content_publisher,
        })
    }
}

impl RuntimePortableRemoteSealV1 {
    pub(super) fn verify(
        &self,
        envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
        kid: ContentAccessIdV1,
        identity: &RuntimeContentIdentityV1,
        commitment: Digest32,
        cid: &str,
        minter: RuntimeOperationIssuerKeyV1,
    ) -> anyhow::Result<String> {
        use elastos_protected_content_contracts::{
            SignedMintRequestV1, SignedSealCompletedV1, MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
        };
        let descriptor = decode_runtime_portable_contract(
            &self.descriptor_base64,
            MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
        )?;
        let completion: SignedSealCompletedV1 = decode_runtime_portable_contract(
            &self.completion_base64,
            elastos_protected_content_runtime::MAX_REMOTE_SEAL_COMPLETION_BYTES,
        )?;
        let request: SignedMintRequestV1 = decode_runtime_portable_contract(
            &self.request_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
        let statement = completion.verify_historical(&descriptor, envelope, kid)?;
        completion.verify_for_request_at(
            &descriptor,
            &request,
            statement.sealer_node_public_key,
            statement.completed_at,
        )?;
        let output = elastos_protected_content_runtime::verify_recorded_remote_seal_attestation(
            &completion,
            &descriptor,
            &request,
            statement.sealer_node_public_key,
        )?;
        anyhow::ensure!(
            statement.package_cid == cid
                && output.identity() == identity
                && statement.content_key_commitment == commitment
                && request.statement().minter_issuer == minter,
            "the remote seal completion does not match the portable listing"
        );
        validate_runtime_custody_profile_did(&statement.content_publisher_did)?;
        Ok(statement.content_publisher_did.clone())
    }
}

/// Plan B POOL-MINT (S7I-F2): whether a listing's item was minted through a
/// pool its minter uses. The carried share statement must be signed by the
/// minter it names and name exactly this item's key envelope and KID; a
/// tampered or swapped one is refused. Returns the verified minter identity.
pub(super) fn verify_pool_mint_share(
    encoded: Option<&str>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<Option<RuntimeOperationIssuerKeyV1>> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let mint_share: elastos_protected_content_contracts::SignedPoolMintShareV1 =
        decode_runtime_portable_contract(encoded, MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize)?;
    let statement = mint_share
        .verify_for_item(key_envelope, content_access_id)
        .map_err(|error| {
            tracing::debug!(
                ?error,
                "a pool-minted listing's share statement does not verify"
            );
            anyhow::anyhow!("Runtime custody portable listing is invalid")
        })?;
    Ok(Some(statement.minter_runtime_issuer()))
}

fn runtime_portable_listing_cid(uri: &str) -> anyhow::Result<&str> {
    let value = uri
        .strip_prefix("elastos://")
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    validate_runtime_custody_cid(value)?;
    Ok(value)
}

fn validate_runtime_custody_cid(value: &str) -> anyhow::Result<()> {
    let parsed = cid::Cid::try_from(value)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    anyhow::ensure!(
        parsed.to_string() == value,
        "Runtime custody portable listing is invalid"
    );
    Ok(())
}

/// A publisher identity, typed by its DID method (D16): a Runtime profile's
/// `did:key`, or the `did:pkh` an adopted package names. Which of the two a
/// package may carry depends on its origin, which
/// `RuntimeCustodyListingRecord::validate` knows and this does not.
fn validate_runtime_custody_profile_did(value: &str) -> anyhow::Result<()> {
    validate_runtime_custody_public_text(value)?;
    if parse_runtime_publisher_pkh(value).is_some() {
        return Ok(());
    }
    crate::crypto::decode_did_key(value)
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

fn decode_runtime_portable_base64(value: &str, max: usize) -> anyhow::Result<Vec<u8>> {
    decode_canonical_base64_bytes(value, max, "portable listing")
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

fn decode_runtime_portable_contract<T: CanonicalContract>(
    value: &str,
    max: usize,
) -> anyhow::Result<T> {
    T::from_canonical_bytes(&decode_runtime_portable_base64(value, max)?)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

/// Fetch one named file from a published directory, verified against the
/// directory's own manifest.
///
/// Sibling files are expected: a listing directory now carries the Elacity
/// documents beside the runtime's `manifest.json`. What makes that safe is
/// unchanged — `verify_content_object_file` checks the named file's bytes
/// against the hash the manifest records for it, so a sibling can neither
/// stand in for it nor alter it.
/// MEMBER-COPIES: the package of the protected listing folder whose manifest
/// and `listing.json` are these, read as an import reads it, and the custody
/// pool its key envelope names.
pub(crate) fn protected_listing_package(
    manifest: &crate::content::ContentObjectManifest,
    bytes: &[u8],
) -> anyhow::Result<(
    RuntimePortableListingPackage,
    elastos_protected_content_contracts::CustodyPoolIdentityV1,
)> {
    runtime_portable_listing_package(manifest, bytes)
        .map(|(package, decoded)| (package, decoded.key_envelope.custody_pool()))
}

/// MC-F6: the minting Home's signed share statement a pool-minted listing
/// carries, verified for the listing's own key envelope and KID; `None` for
/// a listing minted any other way.
pub(crate) fn listing_pool_mint_share(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<Option<elastos_protected_content_contracts::PoolMintShareStatementV1>> {
    let decoded = package.decode_and_validate()?;
    let Some(encoded) = package.pool_mint_share_b64.as_deref() else {
        return Ok(None);
    };
    let mint_share: elastos_protected_content_contracts::SignedPoolMintShareV1 =
        decode_runtime_portable_contract(encoded, MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize)?;
    let statement = mint_share
        .verify_for_item(&decoded.key_envelope, decoded.content_access_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    Ok(Some(statement.clone()))
}

/// MEMBER-COPIES: the custody pool a listing package's key envelope names.
pub(crate) fn listing_custody_pool(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<elastos_protected_content_contracts::CustodyPoolIdentityV1> {
    Ok(package.decode_and_validate()?.key_envelope.custody_pool())
}

/// The package a protected listing folder holds, read as every Home reads
/// one: its exact bytes decode and validate, and the folder's manifest is a
/// protected-content listing linking exactly the payload and the metadata
/// folder the package names.
fn runtime_portable_listing_package(
    manifest: &crate::content::ContentObjectManifest,
    bytes: &[u8],
) -> anyhow::Result<(RuntimePortableListingPackage, DecodedRuntimePortableAsset)> {
    let package: RuntimePortableListingPackage = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    package.check_encoded_listing_size(bytes)?;
    if serde_json::to_vec(&package)? != bytes {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    let decoded = package.decode_and_validate()?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != "protected-content-listing"
        || manifest.links.len() != 2
        || !manifest
            .links
            .iter()
            .any(|link| link.rel == "encrypted-content" && link.cid == package.content_cid)
        || !manifest
            .links
            .iter()
            .any(|link| link.rel == "metadata" && link.cid == package.metadata_cid)
        || manifest.object_did.as_deref() != Some(package.content_id.as_str())
        || manifest.publisher_did.as_deref() != Some(package.publisher_profile_did.as_str())
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok((package, decoded))
}

async fn fetch_runtime_portable_file(
    registry: &ProviderRegistry,
    cid: &str,
    path: &str,
) -> anyhow::Result<(crate::content::ContentObjectManifest, Vec<u8>)> {
    let limit = if path == "listing.json" {
        MAX_RUNTIME_REMOTE_PORTABLE_LISTING_BYTES
    } else {
        MAX_RUNTIME_PORTABLE_LISTING_BYTES
    };
    let manifest = crate::content::fetch_content_object_manifest(registry, cid).await?;
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == path && file.size <= limit)
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let bytes = crate::content::fetch_bytes_via_provider_capped(
        registry,
        cid,
        Some(path),
        file.size as usize,
    )
    .await?;
    crate::content::verify_content_object_file(cid, file, &bytes)?;
    Ok((manifest, bytes))
}

async fn verify_runtime_portable_metadata(
    registry: &ProviderRegistry,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
) -> anyhow::Result<()> {
    // `manifest.json` is where the runtime's document lives in a listing
    // published since the Elacity folder took the `metadata.json` name. Older
    // listings have it at `metadata.json` with no siblings, so that name is
    // tried second — and only accepted when the document there really is the
    // runtime's, so an Elacity `metadata.json` from a folder whose
    // `manifest.json` is missing is refused rather than mistaken for one.
    let (manifest, bytes, is_listing_folder) =
        match fetch_runtime_portable_file(registry, &package.metadata_cid, "manifest.json").await {
            Ok((manifest, bytes)) => (manifest, bytes, true),
            Err(_) => {
                let (manifest, bytes) =
                    fetch_runtime_portable_file(registry, &package.metadata_cid, "metadata.json")
                        .await?;
                (manifest, bytes, false)
            }
        };
    let metadata: RuntimePortableMetadata = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    // The one interop fact a marketplace rejects outright: the listing
    // document's `kid` is the on-chain `contentId`, and the content market
    // refuses an asset whose metadata disagrees. Checking it here turns a
    // listing that would fail silently on chain into one that fails where the
    // cause is legible. Only a listing folder has the document to check.
    if is_listing_folder {
        let (_, listing_bytes) =
            fetch_runtime_portable_file(registry, &package.metadata_cid, "metadata.json").await?;
        let listing: serde_json::Value = serde_json::from_slice(&listing_bytes)
            .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        let expected_kid = format!("0x{}", package.content_access_id.trim_start_matches("0x"));
        if listing.get("kid").and_then(serde_json::Value::as_str) != Some(expected_kid.as_str()) {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        if metadata.rights_policy_seal_required.is_some() {
            let shared = shared_read_dataset(&listing)?;
            anyhow::ensure!(
                shared.is_some_and(|dataset| dataset.rights_policy_seal_required),
                "the mint metadata disagrees on whether a seal is required",
            );
        }
    }
    if metadata.rights_policy_seal_required.is_some() {
        anyhow::ensure!(
            metadata.rights_policy_seal_required == Some(true)
                && package.sealed_rights_policy_base64.is_some(),
            "the minted listing requires a sealed policy",
        );
    }
    if serde_json::to_vec(&metadata)? != bytes
        || manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != "directory"
        || metadata.schema != "elastos.protected-content.metadata/v1"
        || metadata.name != package.display_name
        || metadata.mime_type != decoded.content_identity.content_type()
        || metadata.codecs != runtime_portable_content_codecs(&decoded.content_identity)
        || metadata.encrypted_content_cid != package.content_cid
        || metadata.content_access_id != package.content_access_id
        || metadata.protected_content_identity != package.content_id
        || metadata.mint_id != package.mint_id
        || metadata.publisher_profile_did != package.publisher_profile_did
        || metadata.media_identity_base64 != package.media_identity_base64
        || metadata.content_identity_base64 != package.content_identity_base64
        || metadata.key_envelope_identity_base64 != package.key_envelope_identity_base64
        || metadata.rights_policy_identity_base64 != package.rights_policy_identity_base64
        || metadata.content_key_commitment_base64 != package.content_key_commitment_base64
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(())
}

async fn verify_runtime_portable_chain(
    registry: &ProviderRegistry,
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    let chain_id = package
        .chain_namespace
        .strip_prefix("eip155:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let resolve = |request| async move {
        let response = registry
            .send_raw(CHAIN_PROVIDER_ID, &request)
            .await
            .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        response
            .get("data")
            .cloned()
            .filter(|_| response.get("status").and_then(Value::as_str) == Some("ok"))
            .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))
    };
    // The one reader of the mint hash. Only an imported listing reaches here,
    // and a published package always states it.
    let mint_transaction_hash = package
        .mint_transaction_hash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let receipt: crate::api::gateway::ResolvedProtectedContentMintReceipt = serde_json::from_value(
        resolve(json!({
            "op": "resolve_protected_content_mint_receipt", "network": package.network,
            "hash": mint_transaction_hash, "creator": package.seller_address,
            "ledger": package.ledger, "token_uri": package.token_uri, "op_type_code": 1,
        }))
        .await?,
    )?;
    let listing: crate::api::gateway::ResolvedProtectedContentVerifiedListing = serde_json::from_value(resolve(json!({
        "op": "resolve_protected_content_verified_listing", "network": package.network,
        "seller": package.seller_address, "ledger": package.ledger, "token_id": package.token_id,
    })).await?)?;
    if receipt.schema != "elastos.chain.protected-content-mint-receipt/v1"
        || listing.schema != "elastos.chain.protected-content-verified-listing/v1"
        || receipt.network != package.network
        || listing.network != package.network
        || receipt.chain_id != chain_id
        || listing.chain_id != chain_id
        || receipt.token_id != package.token_id
        || receipt.operative != package.operative
        || !listing.seller.eq_ignore_ascii_case(&package.seller_address)
        || !listing.ledger.eq_ignore_ascii_case(&package.ledger)
        || listing.token_id != package.token_id
        || listing.operative != package.operative
        || listing.quantity != package.quantity
        || listing.price != package.price
        || !listing.pay_token.eq_ignore_ascii_case(&package.pay_token)
        || listing.payment_processor != package.payment_processor
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(())
}

/// How an item was minted. Every M1 item is composition-minted; T7.6 adds
/// `Pool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemMintPath {
    Composition,
    /// Plan B POOL-MINT: minted by a Home through a pool it uses and does
    /// not own; pool-bound on every Home, so `mint_id` is the same everywhere.
    Pool,
}

/// Which node bindings a draft rebuilt here carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DraftNodeBindings {
    /// This Home's composition's selected nodes, as at mint.
    Composition,
    /// The item's epoch committee, bound by `pool_node_owner_state_root`
    /// (S4-Q15).
    PoolBound,
}

/// The one binding choice (re-anchor fix F2): every verifier and rebuild
/// site asks here. A composition-minted item keeps its composition bindings
/// on its holder and owner, and is pool-bound on a Home that does not hold
/// it. T7.6 adds the pool-minted branch, pool-bound everywhere.
pub(crate) fn draft_node_bindings_for(
    item: ItemMintPath,
    holds_ciphertext: bool,
) -> DraftNodeBindings {
    match item {
        ItemMintPath::Composition if holds_ciphertext => DraftNodeBindings::Composition,
        ItemMintPath::Composition | ItemMintPath::Pool => DraftNodeBindings::PoolBound,
    }
}

/// Why a portable listing is being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortableVerifyMode {
    /// A package imported from a listing URI.
    Import,
    /// A listing adopted from an asset or a grant.
    Adopt,
    /// The fresh check before a buy or an open.
    Open,
}

/// What a Home that does not hold the ciphertext checks (S4-U2, D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonHolderCheck {
    /// The manifest against the bound identity only, for an import, an
    /// adoption and an open alike (D7-A). The pool server that serves the
    /// parts checks each one against the manifest's verified leaves before
    /// it is served (`custody_pool_service::ContentPlanePoolContentPort`),
    /// so nothing is fetched here that is not about to be played.
    ManifestOnly,
}

/// Every non-holder verification resolves the item's pool the same way
/// (D2-A): from a verified pool descriptor this Home keeps (own, served or
/// known), matched against the package's key envelope, and never from any
/// other field the Share link or the package carries. A pool no descriptor
/// here verifies is `custody_unresolved`, whatever the package says.
pub(crate) fn non_holder_check(mode: PortableVerifyMode) -> anyhow::Result<NonHolderCheck> {
    match mode {
        PortableVerifyMode::Import | PortableVerifyMode::Adopt | PortableVerifyMode::Open => {
            Ok(NonHolderCheck::ManifestOnly)
        }
    }
}

/// The item's pool, from this Home's own, served and known pools.
pub(crate) async fn runtime_custody_pool_for_key_envelope(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    now: u64,
) -> Result<
    elastos_protected_content_runtime::ResolvedPoolV1,
    elastos_protected_content_runtime::PoolResolveError,
> {
    crate::custody_pool_resolver::home_pool_resolver(data_dir, registry)
        .resolve(key_envelope, &[], now)
        .await
}

/// [`runtime_custody_pool_for_key_envelope`] from what this Home keeps, with
/// no Carrier call and no refresh: the listing (T4.7) uses it.
pub(crate) fn runtime_custody_pool_for_key_envelope_cached(
    data_dir: &Path,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    now: u64,
) -> Result<
    elastos_protected_content_runtime::ResolvedPoolV1,
    elastos_protected_content_runtime::PoolResolveError,
> {
    let mut candidates = Vec::new();
    if let Ok(Some(own)) = crate::custody_pool_descriptor::owner_descriptor(data_dir, now) {
        candidates.push(("own", own.into()));
    }
    for served in
        crate::custody_pool_descriptor::served_descriptors(data_dir, now).unwrap_or_default()
    {
        candidates.push(("served", served));
    }
    for known in crate::custody_pool_resolver::known_pool_descriptors(data_dir) {
        candidates.push(("known", known));
    }
    elastos_protected_content_runtime::resolve_pool_from_candidates(
        candidates,
        &elastos_protected_content_runtime::AcceptAnyPool,
        key_envelope,
        &[],
        now,
    )
}

/// Pool-bound node bindings (S4-Q15): each node of the item's epoch, in the
/// epoch's order, with the operator and failure domain its committee names
/// and `pool_node_owner_state_root` as its owner-state root.
pub(crate) fn pool_bound_node_bindings(
    resolved: &elastos_protected_content_runtime::ResolvedPoolV1,
) -> anyhow::Result<Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>> {
    let epoch_identity = resolved
        .epoch
        .epoch_identity()
        .map_err(|_| anyhow::anyhow!("the item's custody epoch is invalid"))?;
    let members = resolved.epoch.signed_pool().statement().members();
    resolved
        .epoch
        .signed_epoch()
        .statement()
        .nodes()
        .iter()
        .map(|node| {
            let key = node.node_public_key();
            let member = members
                .iter()
                .find(|member| member.node_public_key() == key)
                .ok_or_else(|| anyhow::anyhow!("the item's custody committee is incomplete"))?;
            elastos_protected_content_runtime::RuntimeMintNodeBinding::new(
                key,
                member.operator_id(),
                member.failure_domain_id(),
                elastos_protected_content_runtime::pool_node_owner_state_root(
                    resolved.descriptor.pool(),
                    epoch_identity,
                    key,
                ),
            )
            .map_err(|_| anyhow::anyhow!("the item's custody committee is invalid"))
        })
        .collect()
}

/// A non-holder's availability check (S4-U2): the content plane is asked
/// for the files by CID (local store, then Carrier holders), and nothing is
/// pinned or ensured here.
pub(crate) async fn verify_non_holder_content(
    registry: &ProviderRegistry,
    content_cid: &str,
    content_id: &str,
    identity: &RuntimeContentIdentityV1,
    expected_publisher: Option<&str>,
    check: NonHolderCheck,
    now: u64,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1> {
    use elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1 as Root;

    let manifest = crate::content::fetch_content_object_manifest(registry, content_cid).await?;
    if let Some(expected_publisher) = expected_publisher {
        anyhow::ensure!(
            manifest.publisher_did.as_deref() == Some(expected_publisher)
                && manifest.object_did.as_deref() == Some(content_id),
            "the remote sealed manifest does not match the signed publication"
        );
    }
    // D7-A: the manifest against the bound identity, and nothing else is
    // fetched. Each part is checked against the manifest's verified leaves
    // by the pool server that serves it.
    let NonHolderCheck::ManifestOnly = check;
    let root = match identity {
        RuntimeContentIdentityV1::Media(media) => {
            protected_content_media_manifest_files(&manifest, media)?;
            Root::for_media(media)
        }
        RuntimeContentIdentityV1::Object(object) => {
            protected_content_object_manifest_files(&manifest, object)?;
            Root::for_object(object)
                .map_err(|_| anyhow::anyhow!("protected content object identity is invalid"))?
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            verify_protected_content_dash_manifest(&manifest, head)?;
            Root::for_media_dash(head)
        }
    };
    let fetch = elastos_protected_content_runtime::RuntimeVerifiedContentFetchV1::new(
        content_cid,
        content_id,
        now,
        identity.encrypted_content().clone(),
        root,
    )
    .map_err(|_| anyhow::anyhow!("protected content availability is invalid"))?;
    Ok(elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VerifiedFetch(fetch))
}

/// The non-holder rebuild: the item's pool is resolved, the content checked
/// as `mode` asks, and the draft bound to the pool's committee. Its
/// `mint_id` is this Home's own (adoption takes it from this draft).
async fn rebuild_non_holder_portable_content(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    now_unix_seconds: u64,
    mode: PortableVerifyMode,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    let check = non_holder_check(mode)?;
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let resolved = runtime_custody_pool_for_key_envelope(
        data_dir,
        registry.clone(),
        &decoded.key_envelope,
        now_unix_seconds,
    )
    .await
    .map_err(|error| {
        tracing::debug!(%error, "runtime custody: the item's pool is unresolved");
        RuntimeCustodyUnresolved::error()
    })?;
    let evidence = verify_non_holder_content(
        registry,
        &package.content_cid,
        &package.content_id,
        &decoded.content_identity,
        decoded.remote_content_publisher.as_deref(),
        check,
        now_unix_seconds,
    )
    .await?;
    let draft = RuntimeMintDraft::new_from_identity(
        decoded.content_identity.clone(),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        pool_bound_node_bindings(&resolved)?,
    )?;
    Ok((draft, evidence))
}

/// Original package, metadata and chain checks precede this import-only
/// compatibility path. An older composition mint binds its creator's node
/// owner-state roots; an independent Home instead has the verified pool's
/// roots. That local identity must not be compared with the creator's ID.
/// Pool mints and composition holders still require the original ID exactly.
async fn verify_runtime_import_content(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    let result = rebuild_runtime_portable_content(
        data_dir,
        registry,
        package,
        decoded,
        crate::auth::now_ts(),
        RuntimeManifestPublisherBinding::Exact,
        PortableVerifyMode::Import,
    )
    .await?;
    // Bind this rule to the branch that actually verified the content,
    // rather than sampling mutable composition state a second time.
    let strict = decoded.pool_minted
        || matches!(
            &result.1,
            elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::Receipt(_)
        );
    if strict && result.0.mint_id() != parse_mint_id_hex(&package.mint_id)? {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(result)
}

/// Whether this Home's custody pool holds the keys `key_envelope` names: the
/// envelope's node set -- its members under its own threshold -- is the one
/// this Home's composition selects. That is exactly what a draft rebuilt here
/// is bound to (`RuntimeMintDraft::new_from_identity`), and the only nodes a
/// release from here can reach. The pool, epoch and committee identities are
/// not compared: an epoch renewed over the same members still holds the key.
/// The threshold must be the epoch's own: an envelope asking for more (or
/// fewer) of the same members is not one this pool issued.
///
/// A Home with no custody composition holds no keys at all: `false`, so its
/// purchases answer that rather than waiting forever.
pub(crate) fn runtime_custody_composition_holds_key_envelope(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
) -> anyhow::Result<bool> {
    let Some(composition) = load_runtime_custody_composition(data_dir, registry.clone())? else {
        return Ok(false);
    };
    let threshold = composition.signed_epoch.statement().threshold();
    if key_envelope.threshold() != threshold {
        return Ok(false);
    }
    let configured = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        crate::auth::now_ts(),
        &configured,
    )?;
    let node_set = elastos_protected_content_contracts::NodeSetV1::new(
        threshold,
        selected
            .iter()
            .map(|node| node.binding().node_public_key())
            .collect(),
    );
    Ok(node_set
        .ok()
        .and_then(|node_set| node_set.node_set_id().ok())
        .is_some_and(|node_set_id| node_set_id == key_envelope.node_set_id()))
}

/// Plan B T4.7: whether a buy from this Home has a route to the item's pool:
/// this Home's own pool holds the keys, or a cached descriptor (own, served
/// or known; no Carrier call) resolves the item's epoch with a server.
/// `Err` when the document or this Home's custody state cannot be read now.
pub(crate) fn runtime_custody_pool_route_for_shared_dataset(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    dataset: &crate::protected_content_market::SharedReadDataset,
    now: u64,
) -> anyhow::Result<bool> {
    let key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1 =
        decode_runtime_portable_contract(
            &dataset.key_envelope_identity_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
    runtime_custody_pool_route_for_key_envelope(data_dir, registry, &key_envelope, now)
}

/// [`runtime_custody_pool_route_for_shared_dataset`] for a decoded key
/// envelope. It is sync on purpose: no source here may call Carrier.
pub(crate) fn runtime_custody_pool_route_for_key_envelope(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    now: u64,
) -> anyhow::Result<bool> {
    if runtime_custody_composition_holds_key_envelope(data_dir, registry, key_envelope)? {
        return Ok(true);
    }
    Ok(runtime_custody_pool_for_key_envelope_cached(data_dir, key_envelope, now).is_ok())
}

/// Everything [`verify_runtime_portable_content`] does except compare the
/// rebuilt draft's `mint_id` with the package's: a fresh availability receipt,
/// the published content verified against the package's identity, and the
/// mint draft rebuilt from it. Adoption takes its `mint_id` from exactly this
/// draft, because a package built from a shared document has no `mint_id` of
/// its own to compare against.
pub(super) async fn rebuild_runtime_portable_content(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
    mode: PortableVerifyMode,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    // Before anything is pinned: the one binding choice (re-anchor fix F2).
    // A Home whose pool holds the item keeps the receipt path and its
    // composition bindings; any other Home goes through the item's pool.
    let holds =
        runtime_custody_composition_holds_key_envelope(data_dir, registry, &decoded.key_envelope)?;
    let item = if decoded.pool_minted {
        ItemMintPath::Pool
    } else {
        ItemMintPath::Composition
    };
    if draft_node_bindings_for(item, holds) == DraftNodeBindings::PoolBound {
        return rebuild_non_holder_portable_content(
            data_dir,
            registry,
            package,
            decoded,
            now_unix_seconds,
            mode,
        )
        .await;
    }
    let (draft, receipt) = match &decoded.content_identity {
        RuntimeContentIdentityV1::Media(media_identity) => {
            verify_runtime_portable_media(
                data_dir,
                registry,
                package,
                decoded,
                media_identity,
                now_unix_seconds,
                publisher_binding,
            )
            .await
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            verify_runtime_portable_media_dash(
                data_dir,
                registry,
                package,
                decoded,
                head,
                now_unix_seconds,
                publisher_binding,
            )
            .await
        }
        RuntimeContentIdentityV1::Object(object_identity) => {
            verify_runtime_portable_object(
                data_dir,
                registry,
                package,
                decoded,
                object_identity,
                now_unix_seconds,
                publisher_binding,
            )
            .await
        }
    }?;
    Ok((draft, receipt.into()))
}

/// Object twin of [`verify_runtime_portable_media`]. Step for step the same
/// sequence — re-observe availability, fetch and verify the published files
/// against the listing's own identity, verify the receipt, resolve the
/// custody composition's currently selected nodes, and rebuild the mint draft (its
/// `mint_id` is compared by the caller, `verify_runtime_portable_content`). The media function is
/// untouched; only the three content-shaped steps differ (object manifest and
/// `object.epc1` instead of `identity.bin` + `init.mp4` + segments, the object
/// receipt twin, and `RuntimeMintDraft::new_from_identity` with an
/// `Object` identity instead of `RuntimeMintDraft::new` from raw media bytes).
#[allow(clippy::too_many_arguments)]
async fn verify_runtime_portable_object(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    // Same clock discipline as the media path: a dead candidate's connect
    // timeouts can outlast the receipt's future-skew allowance.
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let trusted_receipt_signer_did =
        crate::collaboration_profile_authority::load_existing_device_did(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        trusted_receipt_signer_did,
        &package.content_id,
        &package.publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    let receipt =
        refresh_content_availability_receipt(registry, &package.content_cid, &requirement).await?;
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &package.content_cid).await?;
    verify_protected_content_object_manifest_and_files(
        registry,
        &package.content_cid,
        &manifest,
        object_identity,
    )
    .await?;
    let availability = verify_protected_content_object_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        object_identity,
        &requirement,
        now_unix_seconds.max(crate::auth::now_ts()),
        publisher_binding,
    )?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let configured_nodes = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now_unix_seconds.max(crate::auth::now_ts()),
        &configured_nodes,
    )?;
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::Object(object_identity.clone()),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    Ok((draft, availability))
}

/// DASH v2 twin of `verify_runtime_portable_object`: the same refresh, receipt
/// and selection, with the content check reduced to the manifest. The head is
/// the identity, so no segment is fetched here; each is proven against the
/// head's root when it is read.
#[allow(clippy::too_many_arguments)]
async fn verify_runtime_portable_media_dash(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    head: &CencDashMediaIdentityV2,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let trusted_receipt_signer_did =
        crate::collaboration_profile_authority::load_existing_device_did(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        trusted_receipt_signer_did,
        &package.content_id,
        &package.publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    let receipt =
        refresh_content_availability_receipt(registry, &package.content_cid, &requirement).await?;
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &package.content_cid).await?;
    verify_protected_content_dash_manifest(&manifest, head)?;
    let availability = verify_protected_content_dash_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        head,
        &requirement,
        now_unix_seconds.max(crate::auth::now_ts()),
        publisher_binding,
    )?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let configured_nodes = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now_unix_seconds.max(crate::auth::now_ts()),
        &configured_nodes,
    )?;
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(head.clone()),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    Ok((draft, availability))
}

#[allow(clippy::too_many_arguments)]
async fn verify_runtime_portable_media(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    media_identity: &CencFmp4MediaIdentityV1,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    // The caller samples its clock before the fresh ensure; walking a dead
    // candidate's connect timeouts can take longer than the receipt's
    // future-skew allowance, so a receipt stamped at completion would read
    // as "in the future". Verify against the later of the two clocks (a
    // fixed test clock ahead of wall time is preserved).
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let trusted_receipt_signer_did =
        crate::collaboration_profile_authority::load_existing_device_did(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        trusted_receipt_signer_did,
        &package.content_id,
        &package.publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    // "Fresh" is a new observation, not the receipt stored at mint time:
    // that one is older than the freshness window for every purchase made
    // more than a minute after the mint. Ask the content plane to ensure the
    // CID again under the same bindings, then read the receipt it produced.
    let receipt =
        refresh_content_availability_receipt(registry, &package.content_cid, &requirement).await?;
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &package.content_cid).await?;
    let (init, segments) = verify_protected_content_manifest_and_files(
        registry,
        &package.content_cid,
        &manifest,
        media_identity,
    )
    .await?;
    let availability = verify_protected_content_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        media_identity,
        &requirement,
        // Re-sampled: the refresh above may have walked dead-candidate timeouts.
        now_unix_seconds.max(crate::auth::now_ts()),
        publisher_binding,
    )?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let configured_nodes = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        // Re-sampled: the refresh above may have walked dead-candidate timeouts.
        now_unix_seconds.max(crate::auth::now_ts()),
        &configured_nodes,
    )?;
    let draft = RuntimeMintDraft::new(
        &init,
        &segments,
        media_identity.mime_type(),
        media_identity.codecs(),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    Ok((draft, availability))
}

pub(crate) async fn import_runtime_custody_listing(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    listing_uri: &str,
) -> anyhow::Result<Value> {
    validate_runtime_custody_public_text(principal_id)?;
    let listing_cid = runtime_portable_listing_cid(listing_uri)?;
    let mut stage = crate::action_trace::Stage::new("listing_fetch", "content");
    let fetched = tracing::Instrument::instrument(
        fetch_runtime_portable_file(&registry, listing_cid, "listing.json"),
        stage.span(),
    )
    .await;
    stage.result(&fetched);
    let (manifest, bytes) = fetched?;
    let mut stage = crate::action_trace::Stage::new("package_validation", "object");
    let (package, decoded) = stage.checked(runtime_portable_listing_package(&manifest, &bytes))?;
    // T8-M4: what an imported listing must state about itself is checked
    // before anything is asked of the network: a package lacking a published
    // package's facts is refused here, not after reading its folders.
    let package_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    stage.checked(validate_runtime_portable_listing_origin(
        listing_uri,
        &package_sha256,
        &package,
    ))?;
    stage.checked(validate_runtime_published_package_facts(&package))?;
    stage.finish("ok");
    let mut stage = crate::action_trace::Stage::new("metadata_verification", "content");
    let result = tracing::Instrument::instrument(
        verify_runtime_portable_metadata(&registry, &package, &decoded),
        stage.span(),
    )
    .await;
    stage.result(&result);
    result?;
    let mut stage = crate::action_trace::Stage::new("chain_verification", "chain");
    let result = tracing::Instrument::instrument(
        verify_runtime_portable_chain(&registry, &package),
        stage.span(),
    )
    .await;
    stage.result(&result);
    result?;
    let mut stage = crate::action_trace::Stage::new("content_verification", "content");
    let verified = tracing::Instrument::instrument(
        verify_runtime_import_content(data_dir, &registry, &package, &decoded),
        stage.span(),
    )
    .await;
    stage.result(&verified);
    let (draft, verified_availability) = verified?;
    let mut stage = crate::action_trace::Stage::new("listing_persist", "object");
    let availability =
        RuntimeCustodyListingAvailabilitySummary::from_evidence(&verified_availability);
    let source = RuntimeSourceListing {
        listing_uri: listing_uri.to_string(),
        package_sha256,
    };
    let (origin, package) = if matches!(
        &verified_availability,
        elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VerifiedFetch(_)
    ) {
        let mut local = package;
        local.mint_id = hex::encode(draft.mint_id().as_bytes());
        // The original creator and token URI were chain-verified above.
        // Use adoption's account attribution without trusting an outer
        // metadata publisher or changing the immutable source package hash.
        let chain_id = local
            .chain_namespace
            .strip_prefix("eip155:")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
        local.publisher_profile_did = format!(
            "did:pkh:eip155:{chain_id}:{}",
            local.seller_address.to_ascii_lowercase()
        );
        local.token_uri = format!("ipfs://{}", local.metadata_cid);
        local.mint_transaction_hash = None;
        local.published_at = None;
        (
            RuntimeCustodyListingOrigin::Asset {
                asset_uri: format!("elastos://{}", local.metadata_cid),
                source_listing: Some(source),
            },
            local,
        )
    } else {
        (
            RuntimeCustodyListingOrigin::Imported {
                listing_uri: source.listing_uri,
                package_sha256: source.package_sha256,
            },
            package,
        )
    };
    let mut expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin,
        package,
        availability,
    };
    stage.checked(expected.validate())?;
    // All remote verification has finished. Serialize only the local
    // comparison and base/extension writes with other Add requests.
    let _write = crate::custody_consent::lock_custody_writes().await;
    // A granted listing states terms nobody offered: the creator's own
    // package replaces it. Granted copies are bound to the item, not to the
    // listing's terms, and keep opening.
    let existing = stage
        .checked(load_runtime_custody_listing(data_dir, draft.mint_id()))?
        .filter(|existing| !existing.origin.is_granted());
    if let Some(mut existing) = existing {
        let source_added = match (&mut existing.origin, &mut expected.origin) {
            (
                RuntimeCustodyListingOrigin::Asset {
                    asset_uri,
                    source_listing,
                },
                RuntimeCustodyListingOrigin::Asset {
                    asset_uri: expected_asset,
                    source_listing: Some(source),
                },
            ) if runtime_adopted_asset_cid(asset_uri)
                .is_some_and(|cid| Some(cid) == runtime_adopted_asset_cid(expected_asset)) =>
            {
                *expected_asset = asset_uri.clone();
                if source_listing.is_none() {
                    *source_listing = Some(source.clone());
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        if existing.schema != expected.schema
            || existing.origin != expected.origin
            || existing.package != expected.package
            || (existing.availability.checked_at == expected.availability.checked_at
                && existing.availability != expected.availability)
        {
            stage.finish("conflict");
            anyhow::bail!("Runtime custody listing is invalid");
        }
        if source_added && expected.availability.checked_at < existing.availability.checked_at {
            expected.availability = existing.availability.clone();
        }
        if source_added || expected.availability.checked_at > existing.availability.checked_at {
            stage.checked(persist_runtime_custody_listing(data_dir, &expected))?;
        }
    } else {
        stage.checked(persist_runtime_custody_listing(data_dir, &expected))?;
    }
    stage.finish("ok");
    Ok(json!({
        "schema": "elastos.library.runtime-custody-import/v1",
        "listing_uri": listing_uri,
        "mint_id": expected.package.mint_id,
        "status": "verified",
    }))
}

/// Decode the `content_identity_base64` a shared document's ElastOS
/// protection entry carries (`ProtectedContentIdentities`): the kind-prefixed
/// `RuntimeContentIdentityV1` encoding for an object, or the bare
/// `CencFmp4MediaIdentityV1` bytes for media.
///
/// Dispatched exactly as [`RuntimePortableListingPackage::decode_and_validate`]
/// dispatches its two fields: the kind-prefixed form is tried first and
/// accepted only when it is an `Object`; otherwise the bytes must be a bare
/// media identity. A kind-prefixed `Media` is refused, as it is for a package:
/// it would give one asset two encodings.
pub(crate) fn decode_runtime_shared_content_identity(
    encoded: &str,
) -> anyhow::Result<RuntimeContentIdentityV1> {
    let bytes =
        decode_runtime_portable_base64(encoded, MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize)?;
    match RuntimeContentIdentityV1::from_canonical_bytes(&bytes) {
        Ok(RuntimeContentIdentityV1::Object(object)) => {
            return Ok(RuntimeContentIdentityV1::Object(object))
        }
        Ok(RuntimeContentIdentityV1::MediaDash(head)) => {
            return Ok(RuntimeContentIdentityV1::MediaDash(head))
        }
        Ok(RuntimeContentIdentityV1::Media(_)) => {
            anyhow::bail!("Runtime custody portable listing is invalid")
        }
        Err(_) => {}
    }
    CencFmp4MediaIdentityV1::from_canonical_bytes(&bytes)
        .map(RuntimeContentIdentityV1::Media)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

/// Why an adoption did not produce read-side records. Every one of these
/// leaves the market purchase exactly as complete as it was.
pub(crate) const RUNTIME_MARKET_ADOPTION_CONFLICT_MESSAGE: &str =
    "another listing already records this mint";

/// R39: whether `package` sells exactly what `purchase` paid for -- the same
/// item (chain, network, ledger, token, operative, KID) from the same seller at
/// the same price, pay token and processor. Addresses compare without regard
/// to case; quantity is availability, not a term.
fn runtime_listing_sells_on_market_terms(
    package: &RuntimePortableListingPackage,
    purchase: &crate::protected_content_market::RuntimeMarketPurchaseRecord,
) -> bool {
    let item = &purchase.item;
    let offer = &purchase.offer;
    let same_address = |left: Option<&str>, right: Option<&str>| match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    };
    package.chain_namespace == item.chain_namespace
        && package.network == item.network
        && package.ledger.eq_ignore_ascii_case(&item.ledger)
        && package.token_id.eq_ignore_ascii_case(&item.token_id)
        && package.operative.eq_ignore_ascii_case(&item.operative)
        && crate::protected_content_market::normalize_runtime_market_kid(&package.content_access_id)
            .is_some_and(|kid| item.kid.as_deref() == Some(kid.as_str()))
        && package.seller_address.eq_ignore_ascii_case(&offer.seller)
        && package.price == offer.price
        && package.pay_token.eq_ignore_ascii_case(&offer.pay_token)
        && same_address(
            package.payment_processor.as_deref(),
            offer.payment_processor.as_deref(),
        )
}

/// The terms an adopted listing states: the offer a market purchase paid, or
/// the zero terms of a granted copy.
pub(crate) struct RuntimeAdoptedListingTerms {
    pub(crate) seller_address: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    pub(crate) payment_processor: Option<String>,
}

/// The listing a shared `metadata.json` describes for `item`, on `terms`:
/// the package built from the document, its content verified the way the
/// open path verifies it, and its `mint_id` taken from the rebuilt draft and
/// never from any document. Nothing is written.
///
/// `verify_runtime_portable_metadata` (which reads the ElastOS-only
/// `manifest.json`) and `verify_runtime_portable_chain` (whose facts the
/// caller proved from the chain) are deliberately not run.
async fn build_adopted_runtime_listing(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    item: &crate::protected_content_market::RuntimeMarketItem,
    origin: RuntimeCustodyListingOrigin,
    dataset: &crate::protected_content_market::SharedReadDataset,
    terms: RuntimeAdoptedListingTerms,
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    // A document whose stated type contradicts the identity it carries says
    // two things about one asset; neither is adopted.
    if !dataset.mime_type.is_empty() && dataset.mime_type != dataset.content_identity.content_type()
    {
        anyhow::bail!("the shared document's mimeType disagrees with its content identity");
    }
    let (RuntimeCustodyListingOrigin::Asset { asset_uri, .. }
    | RuntimeCustodyListingOrigin::Granted { asset_uri }) = &origin
    else {
        anyhow::bail!("Runtime custody listing is invalid");
    };
    let folder_cid = runtime_portable_listing_cid(asset_uri)?.to_string();
    let (media_identity_base64, content_identity_base64) =
        runtime_portable_identity_fields(&dataset.content_identity)?;
    let mut package = RuntimePortableListingPackage {
        schema: RUNTIME_PORTABLE_LISTING_SCHEMA_V1.to_string(),
        // Filled in from the rebuilt draft below; a valid placeholder only so
        // the package can be decoded first.
        mint_id: "00".repeat(32),
        content_id: runtime_protected_content_id(dataset.content_identity.encrypted_content())?,
        content_cid: dataset.content_cid.clone(),
        metadata_cid: folder_cid.clone(),
        token_uri: format!("ipfs://{folder_cid}"),
        publisher_profile_did: dataset.publisher_identity.clone(),
        display_name: dataset.name.clone(),
        media_identity_base64,
        content_identity_base64,
        content_access_id: dataset.kid.clone(),
        key_envelope_identity_base64: dataset.key_envelope_identity_base64.clone(),
        rights_policy_identity_base64: dataset.rights_policy_identity_base64.clone(),
        content_key_commitment_base64: dataset.content_key_commitment_base64.clone(),
        seller_address: terms.seller_address,
        chain_namespace: item.chain_namespace.clone(),
        network: item.network.clone(),
        ledger: item.ledger.to_ascii_lowercase(),
        token_id: item.token_id.to_ascii_lowercase(),
        operative: item.operative.to_ascii_lowercase(),
        quantity: terms.quantity,
        price: terms.price,
        pay_token: terms.pay_token,
        payment_processor: terms.payment_processor,
        mint_transaction_hash: None,
        published_at: None,
        // POOL-MINT (S7I-F2): the item's pool path, from its shared document.
        pool_mint_share_b64: dataset.pool_mint_share_b64.clone(),
        sealed_rights_policy_base64: None,
        remote_seal: None,
    };
    let decoded = package.decode_and_validate()?;
    if dataset.rights_policy_seal_required {
        let item = elastos_protected_content_runtime::RuntimeMintedItemV1::from_parts(
            &package.chain_namespace,
            &package.ledger,
            &package.token_id,
            package.policy_creator(),
        )?;
        let policy = resolve_runtime_rights_policy_for_item(
            registry,
            decoded.content_identity.encrypted_content(),
            decoded.content_access_id,
            RightsActionV1::View,
            Some(item.expected_item()),
        )
        .await?;
        package.schema = RUNTIME_PORTABLE_LISTING_SCHEMA_V2.to_string();
        package.sealed_rights_policy_base64 = Some(
            base64::engine::general_purpose::STANDARD.encode(policy.body().canonical_bytes()?),
        );
        package.sealed_policy()?;
    }
    let (draft, verified_availability) = rebuild_runtime_portable_content(
        data_dir,
        registry,
        &package,
        &decoded,
        crate::auth::now_ts(),
        RuntimeManifestPublisherBinding::AdoptedAttribution,
        PortableVerifyMode::Adopt,
    )
    .await?;
    package.mint_id = hex::encode(draft.mint_id().as_bytes());
    let expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin,
        package,
        availability: RuntimeCustodyListingAvailabilitySummary::from_evidence(
            &verified_availability,
        ),
    };
    expected.validate()?;
    Ok(expected)
}

/// Adoption for a chain grant: the listing and owned copy of an item the
/// chain grants `account` access to without any purchase or mint of this
/// principal's -- a channel admin's, say. Access is the chain's to decide,
/// not how it was come by.
///
/// The caller has verified `item` (all three legs of the binding check, so
/// its KID is proven) and read `access_evidence` for that KID at the
/// finalized block. The listing binds to one this Home already holds for the
/// mint, whatever its terms; otherwise it is recorded on zero terms (origin
/// `Granted`), which nothing ever buys, shares or lists. The owned copy is
/// recorded as `granted` unless this principal already holds a record for
/// the mint, which is left exactly as it is.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_runtime_granted_listing(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    principal_id: &str,
    profile_did: &str,
    item: &crate::protected_content_market::RuntimeMarketItem,
    asset_uri: &str,
    dataset: &crate::protected_content_market::SharedReadDataset,
    account_id: &str,
    address: &str,
    access_evidence: RuntimeCustodyPurchaseAccessEvidenceRecord,
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    if item.kid.as_deref() != Some(dataset.kid.as_str())
        || !access_evidence.has_access
        || access_evidence.content_access_id.as_deref() != Some(dataset.kid.as_str())
        || !access_evidence.wallet.eq_ignore_ascii_case(address)
    {
        anyhow::bail!("Runtime custody grant does not bind to this document");
    }
    let (seller_address, quantity, price, pay_token) =
        runtime_granted_package_terms(&item.operative);
    let expected = build_adopted_runtime_listing(
        data_dir,
        registry,
        item,
        RuntimeCustodyListingOrigin::Granted {
            asset_uri: asset_uri.to_string(),
        },
        dataset,
        RuntimeAdoptedListingTerms {
            seller_address,
            quantity,
            price,
            pay_token,
            payment_processor: None,
        },
    )
    .await?;
    let mint_id = parse_mint_id_hex(&expected.package.mint_id)?;
    let listing = match load_runtime_custody_listing(data_dir, mint_id)? {
        // Whatever listing this Home already holds for the mint is the one the
        // copy opens through; a grant overwrites nothing.
        Some(existing) => {
            existing.validate()?;
            tracing::debug!(
                mint_id = %existing.package.mint_id,
                "runtime custody: granted copy bound to the listing already held for its mint"
            );
            existing
        }
        None => {
            persist_runtime_custody_listing(data_dir, &expected)?;
            expected
        }
    };
    // Decided under the purchase lock: a purchase of this mint that lands
    // first is never overwritten by the grant.
    let now = crate::auth::now_ts();
    let record = RuntimeCustodyPurchaseRecord {
        schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.to_string(),
        profile_did: profile_did.to_string(),
        mint_id: listing.package.mint_id.clone(),
        content_id: listing.package.content_id.clone(),
        cid: listing.package.content_cid.clone(),
        listing_sha256: listing.portable_package_digest(),
        seller_address: listing.package.seller_address.clone(),
        chain_namespace: listing.package.chain_namespace.clone(),
        network: listing.package.network.clone(),
        ledger: listing.package.ledger.clone(),
        token_id: listing.package.token_id.clone(),
        operative: listing.package.operative.clone(),
        price: listing.package.price.clone(),
        pay_token: listing.package.pay_token.clone(),
        payment_processor: listing.package.payment_processor.clone(),
        availability_receipt_digest: listing.availability.purchase_digest(),
        account_id: account_id.to_string(),
        address: address.to_ascii_lowercase(),
        approval_stage: None,
        acquisition_stage: runtime_custody_grant_stage(
            &listing.package.chain_namespace,
            &listing.package.network,
        ),
        acquisition: RuntimeCustodyAcquisitionV1::Granted,
        capsule_uri: None,
        progress: RuntimeCustodyPurchaseProgress::Granted {
            access_evidence,
            acquired_at: now,
        },
        created_at: now,
        updated_at: now,
    };
    if create_runtime_custody_purchase_if_absent(data_dir, &record)? {
        tracing::debug!(
            mint_id = %listing.package.mint_id,
            "runtime custody: chain-granted copy recorded from the shared document"
        );
    }
    Ok(listing)
}

/// Adoption, steps 2-4 (D10): build the listing package a published listing
/// would have carried from the shared document and the market purchase, run
/// the content verification the open path runs, and record the listing
/// (origin `Asset`) and a purchase record (acquisition `market`) that the
/// unchanged open path then consumes.
///
/// `mint_id` is the rebuilt draft's, computed here and never read from any
/// document. `verify_runtime_portable_metadata` (which reads the ElastOS-only
/// `manifest.json`) and `verify_runtime_portable_chain` (whose facts the
/// purchase already proved) are deliberately not run.
///
/// Nothing is written unless every check passed. Returns the listing record
/// the purchase record is bound to: the adopted one, or (R39) the listing of
/// the same mint this Home already held on the same terms.
pub(crate) async fn adopt_runtime_market_listing(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    profile_did: &str,
    purchase: &crate::protected_content_market::RuntimeMarketPurchaseRecord,
    dataset: &crate::protected_content_market::SharedReadDataset,
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    let RuntimeCustodyPurchaseProgress::Complete { terminal } = &purchase.progress else {
        anyhow::bail!("Runtime market purchase is not complete");
    };
    if purchase.item.kid.as_deref() != Some(dataset.kid.as_str()) {
        anyhow::bail!("Runtime market purchase does not bind to this document");
    }
    // The open path asks the purchase record for the chain's access answer
    // on this KID; a purchase whose KID was proven after it completed (R46)
    // must have read it before anything is adopted.
    if !terminal.access_evidence.as_ref().is_some_and(|evidence| {
        evidence.has_access && evidence.content_access_id.as_deref() == Some(dataset.kid.as_str())
    }) {
        anyhow::bail!("Runtime market purchase has no access evidence for this document");
    }
    let expected = build_adopted_runtime_listing(
        data_dir,
        registry,
        &purchase.item,
        RuntimeCustodyListingOrigin::Asset {
            asset_uri: purchase.asset_uri.clone(),
            source_listing: None,
        },
        dataset,
        RuntimeAdoptedListingTerms {
            seller_address: purchase.offer.seller.to_ascii_lowercase(),
            quantity: "0x1".to_string(),
            price: purchase.offer.price.clone(),
            pay_token: purchase.offer.pay_token.to_ascii_lowercase(),
            payment_processor: purchase
                .offer
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase),
        },
    )
    .await?;
    let draft_mint_id = parse_mint_id_hex(&expected.package.mint_id)?;
    // The listing the purchase record binds to: the adopted one, or (R39) a
    // listing of this same mint this Home already holds on exactly the terms
    // the purchase paid.
    let expected = match load_runtime_custody_listing(data_dir, draft_mint_id)? {
        Some(existing)
            if existing.origin == expected.origin && existing.package == expected.package =>
        {
            if expected.availability.checked_at > existing.availability.checked_at {
                persist_runtime_custody_listing(data_dir, &expected)?;
            }
            expected
        }
        // R39: this Home already holds a listing of this mint -- imported from
        // its published package, say -- on the very terms this purchase paid.
        // The purchase opens through it, bound to its own package digest;
        // nothing is overwritten.
        Some(existing) if runtime_listing_sells_on_market_terms(&existing.package, purchase) => {
            existing.validate()?;
            tracing::debug!(
                mint_id = %existing.package.mint_id,
                "runtime custody: market purchase bound to the listing already held for its mint"
            );
            existing
        }
        // A granted listing states terms nobody offered, so the listing this
        // purchase paid on replaces it. The granted copies bound to it are
        // bound to the item, not to its terms, and keep opening.
        Some(existing) if existing.origin.is_granted() => {
            tracing::debug!(
                mint_id = %existing.package.mint_id,
                "runtime custody: market purchase replaced a granted listing"
            );
            persist_runtime_custody_listing(data_dir, &expected)?;
            expected
        }
        // One listing per mint on a Home. A listing this Home already holds
        // on other terms -- another seller or price -- is never overwritten by
        // a purchase that does not match it (per-purchase terms on the open
        // path are a recorded follow-up).
        Some(_) => anyhow::bail!(RUNTIME_MARKET_ADOPTION_CONFLICT_MESSAGE),
        None => {
            persist_runtime_custody_listing(data_dir, &expected)?;
            expected
        }
    };
    if load_runtime_custody_purchase(data_dir, &purchase.principal_id, draft_mint_id)?.is_none() {
        let now = crate::auth::now_ts();
        let record = RuntimeCustodyPurchaseRecord {
            schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
            principal_id: purchase.principal_id.clone(),
            profile_did: profile_did.to_string(),
            mint_id: expected.package.mint_id.clone(),
            content_id: expected.package.content_id.clone(),
            cid: expected.package.content_cid.clone(),
            listing_sha256: expected.portable_package_digest(),
            seller_address: expected.package.seller_address.clone(),
            chain_namespace: expected.package.chain_namespace.clone(),
            network: expected.package.network.clone(),
            ledger: expected.package.ledger.clone(),
            token_id: expected.package.token_id.clone(),
            operative: expected.package.operative.clone(),
            price: expected.package.price.clone(),
            pay_token: expected.package.pay_token.clone(),
            payment_processor: expected.package.payment_processor.clone(),
            availability_receipt_digest: expected.availability.purchase_digest(),
            account_id: purchase.account_id.clone(),
            address: purchase.address.clone(),
            approval_stage: purchase.approval_stage.clone(),
            acquisition_stage: purchase.acquisition_stage.clone(),
            acquisition: RuntimeCustodyAcquisitionV1::Market,
            capsule_uri: None,
            progress: purchase.progress.clone(),
            created_at: now,
            updated_at: now,
        };
        persist_runtime_custody_purchase(data_dir, &record)?;
    }
    tracing::debug!(
        mint_id = %expected.package.mint_id,
        "runtime custody: market purchase adopted from the shared document"
    );
    Ok(expected)
}

/// How a principal came to own this copy.
///
/// Nothing downstream of the entitlement check reads this. The right to open
/// is the chain's answer to `hasAccess`, and buying and minting are two ways of
/// arriving at the same answer -- so an owned copy behaves identically either
/// way. This records only which one happened, so a reader can tell provenance
/// without that changing what the copy can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeCustodyAcquisitionV1 {
    /// Bought from a listing. Every record written before minted copies
    /// existed is one of these, which is why it is the default.
    #[default]
    Bought,
    /// Minted by this principal: the copy was theirs from the first block.
    Minted,
    /// Bought on the market from any live offer, and adopted from the asset's
    /// shared `metadata.json` rather than from a published listing package.
    Market,
    /// Granted by the chain without a purchase or a mint of this principal's
    /// -- a channel admin's access, say -- and adopted from the asset's shared
    /// `metadata.json`. No transaction stands behind it; the finalized grant
    /// does.
    Granted,
}

impl RuntimeCustodyAcquisitionV1 {
    /// How a copy says it was come by, in the spelling its record carries.
    pub(crate) const fn wire_value(self) -> &'static str {
        match self {
            Self::Bought => "bought",
            Self::Minted => "minted",
            Self::Market => "market",
            Self::Granted => "granted",
        }
    }
}

/// R3: every CID a runtime listing on this Home (created, imported, bought
/// or granted) names as its listing folder, payload or metadata folder. A
/// listing file that cannot be read is an error, so a caller never gives up a
/// pin on a guess.
pub(crate) fn runtime_listing_cids(
    data_dir: &Path,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(std::collections::BTreeSet::new())
        }
        Err(error) => return Err(error.into()),
    };
    let mut cids = std::collections::BTreeSet::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let record = decode_runtime_listing_record(data_dir, &fs::read(&path)?)?;
        let folder = match &record.origin {
            RuntimeCustodyListingOrigin::LocalCreator { listing_uri, .. }
            | RuntimeCustodyListingOrigin::Imported { listing_uri, .. } => listing_uri,
            RuntimeCustodyListingOrigin::Asset { asset_uri, .. }
            | RuntimeCustodyListingOrigin::Granted { asset_uri } => asset_uri,
        };
        if let Some(listing) = folder.strip_prefix("elastos://") {
            cids.insert(listing.to_string());
        }
        if let RuntimeCustodyListingOrigin::Asset {
            source_listing: Some(source),
            ..
        } = &record.origin
        {
            source.validate()?;
            cids.insert(runtime_portable_listing_cid(&source.listing_uri)?.to_string());
        }
        cids.insert(record.package.content_cid);
        cids.insert(record.package.metadata_cid);
    }
    Ok(cids)
}

/// Every runtime listing record on this Home, in directory order. A record
/// that cannot be read is skipped and logged, so one bad file hides none of
/// the others.
fn runtime_listing_records(data_dir: &Path) -> Vec<RuntimeCustodyListingRecord> {
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| {
            fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| decode_runtime_listing_record(data_dir,&bytes))
                .inspect_err(|error| {
                    tracing::debug!(path = %path.display(), error = %format!("{error:#}"), "a runtime listing record is unreadable");
                })
                .ok()
        })
        .collect()
}

/// STAB-10 (J4-F7, D3): the custody pool of the runtime listing here whose
/// artifact set (listing folder, payload or metadata folder) is `cid`, so a
/// content fetch asks that pool's members first. `None` when no listing on
/// this Home names it.
pub(crate) fn runtime_listing_custody_pool_of_cid(
    data_dir: &Path,
    cid: &str,
) -> Option<elastos_protected_content_contracts::CustodyPoolIdentityV1> {
    runtime_listing_records(data_dir)
        .into_iter()
        .find(|record| {
            record.package.content_cid == cid
                || record.package.metadata_cid == cid
                || record
                    .origin
                    .listing_uri()
                    .and_then(|uri| uri.strip_prefix("elastos://"))
                    == Some(cid)
        })
        .and_then(|record| listing_custody_pool(&record.package).ok())
}

/// STAB-07 (J1-F3, A2-F1; D3): the mints this Home created and listed, whose
/// pool members it keeps asking for copies until each confirms.
pub(crate) fn runtime_local_creator_mint_ids(data_dir: &Path) -> Vec<Digest32> {
    runtime_listing_records(data_dir)
        .into_iter()
        .filter(|record| {
            matches!(
                record.origin,
                RuntimeCustodyListingOrigin::LocalCreator { .. }
            )
        })
        .filter_map(|record| parse_mint_id_hex(&record.package.mint_id).ok())
        .collect()
}

pub(crate) fn list_runtime_custody_listings(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Value> {
    if principal_id.trim().is_empty() {
        anyhow::bail!("Runtime custody listing principal is invalid");
    }
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    let (listing_paths, truncated) =
        select_runtime_custody_listing_paths(&root, MAX_RUNTIME_CUSTODY_LISTINGS)?;
    let mut listings = Vec::with_capacity(listing_paths.len());
    for path in listing_paths {
        let bytes = fs::read(path)?;
        let record = decode_runtime_listing_record(data_dir, &bytes)
            .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
        record.validate()?;
        // A listing adopted after a market purchase, or built for a chain
        // grant, was never published as a listing: it has no package link to
        // share, and its terms were never offered. It is still this person's
        // held copy, so it is listed for them (D4, STAB-19) -- the market
        // catalog is one page, and a copy past that page would otherwise be
        // on no Explore surface -- and for nobody else, who would be shown a
        // mint on terms nobody offered.
        let held_copy = matches!(
            record.origin,
            RuntimeCustodyListingOrigin::Asset {
                source_listing: None,
                ..
            } | RuntimeCustodyListingOrigin::Granted { .. }
        );
        // J2-F6: one record this Home cannot read (a broken purchase file,
        // say) costs its own row, not the whole shelf.
        match runtime_custody_listing_summary(data_dir, principal_id, &record) {
            Ok(summary) => {
                if held_copy && summary["access_state"] != RUNTIME_CUSTODY_LISTING_ACCESS_PURCHASED
                {
                    continue;
                }
                listings.push(summary);
            }
            Err(error) => tracing::warn!(
                mint_id = %record.package.mint_id,
                error = %format!("{error:#}"),
                "runtime custody shelf: a listing row was skipped"
            ),
        }
    }
    Ok(json!({
        "schema": RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1,
        "truncated": truncated,
        "listings": listings,
    }))
}

/// Which chain assets this Home already holds a listing for, and what this
/// person may do with each.
///
/// The catalog names an asset by its channel and token, which is how the
/// chain names it; a listing here is named by its mint. This is the join
/// between the two, and it is made inside Runtime rather than by a surface,
/// because the channel an item lives on is deliberately not published to one.
///
/// The access state is this person's, so two people on one Home see their own
/// answer for the same asset.
pub(crate) fn runtime_custody_listing_chain_index(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Vec<RuntimeCustodyListingChainIdentity>> {
    if principal_id.trim().is_empty() {
        anyhow::bail!("Runtime custody listing principal is invalid");
    }
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    // J2-F10: the join is not the shelf. It reads every listing this Home
    // holds, so an item past the shelf's row bound (a creator's own new
    // mint, say) is still marked on Explore.
    let (listing_paths, _) = select_runtime_custody_listing_paths(&root, usize::MAX)?;
    let mut index = Vec::with_capacity(listing_paths.len());
    for path in listing_paths {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(record) = decode_runtime_listing_record(data_dir, &bytes) else {
            continue;
        };
        if record.validate().is_err() {
            continue;
        }
        // J2-F6: one unreadable purchase costs its own row, not the join.
        let access_state =
            match runtime_custody_listing_access_state(data_dir, principal_id, &record) {
                Ok(access_state) => access_state,
                Err(error) => {
                    tracing::warn!(
                        mint_id = %record.package.mint_id,
                        error = %format!("{error:#}"),
                        "runtime custody chain index: a listing was skipped"
                    );
                    continue;
                }
            };
        // A granted listing exists for the person the chain granted it to.
        // Anyone else would be shown a mint on terms nobody offered.
        if record.origin.is_granted() && access_state == RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE {
            continue;
        }
        index.push(RuntimeCustodyListingChainIdentity {
            chain_namespace: record.package.chain_namespace.clone(),
            ledger: record.package.ledger.to_ascii_lowercase(),
            token_id: record.package.token_id.to_ascii_lowercase(),
            mint_id: record.package.mint_id.clone(),
            access_state: access_state.to_string(),
        });
    }
    Ok(index)
}

/// One asset this Home holds, named the way the chain names it.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyListingChainIdentity {
    pub(crate) chain_namespace: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) mint_id: String,
    pub(crate) access_state: String,
}

/// At most `cap` listing files, the smallest mint file names first, and
/// whether any were left out.
pub(super) fn select_runtime_custody_listing_paths(
    root: &Path,
    cap: usize,
) -> anyhow::Result<(Vec<PathBuf>, bool)> {
    if !root.is_dir() {
        return Ok((Vec::new(), false));
    }
    let mut selected = BTreeMap::<String, PathBuf>::new();
    let mut truncated = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let name = name.to_string();
        if selected.len() < cap {
            selected.insert(name, path);
            continue;
        }
        truncated = true;
        let Some(last_name) = selected.keys().next_back().cloned() else {
            continue;
        };
        if name < last_name {
            selected.remove(&last_name);
            selected.insert(name, path);
        }
    }
    Ok((selected.into_values().collect(), truncated))
}

pub(super) fn runtime_custody_listing_summary(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<Value> {
    let availability = runtime_custody_listing_availability(record);
    let access_state = runtime_custody_listing_access_state(data_dir, principal_id, record)?;
    let purchase_in_flight =
        runtime_custody_listing_purchase_in_flight(data_dir, principal_id, record)?;
    let content_identity = record.package.decode_and_validate()?.content_identity;
    // `mime_type`/`codecs` keep their exact media values (the listing summary
    // is a pre-existing public shape); an object listing reports its declared
    // `content_type` as `mime_type` and an empty `codecs`, which is what its
    // published metadata document carries too.
    Ok(json!({
        "schema": RUNTIME_LISTING_SCHEMA_V1,
        "mint_id": record.package.mint_id,
        "display_name": record.package.display_name,
        // Where this listing's package lives, which is the whole of what one
        // person needs to give another for the item to reach their shelf. It
        // is a public content address that the listing already published; the
        // answer to `publish` has carried it since listings existed, and no
        // surface has ever shown it.
        "listing_uri": record.origin.listing_uri(),
        // What this item is, in the two words the viewer session already
        // speaks. An app used to read the kind out of `mime_type`, which is a
        // second rule for a question Runtime answers here from the identity
        // itself, and a second rule can disagree with the one the open path
        // enforces.
        "content_kind": runtime_custody_content_kind(&content_identity),
        // Where this listing's published metadata document lives -- the same
        // directory the media token's URI names, which carries the title the
        // creator typed, the cover they chose and the category they picked.
        //
        // The CID travels rather than the document: a shelf of items would
        // otherwise make this Home fetch and parse one document per row before
        // it could answer at all, and the surface reads them from its own
        // `/ipfs/` route, which is already backed by the local node and its
        // disk cache. What comes out of that document is presentation only --
        // price, quantity and access are answered here and nowhere else.
        "metadata_cid": record.package.metadata_cid,
        "mime_type": content_identity.content_type(),
        "codecs": runtime_portable_content_codecs(&content_identity),
        "quantity": record.package.quantity,
        "price": record.package.price,
        "pay_token": record.package.pay_token,
        "seller_address": record.package.seller_address,
        // J2-F3: the chain names the item by (chain namespace, ledger,
        // token), so a local card can key the chain's access watch.
        "chain_namespace": record.package.chain_namespace,
        "ledger": record.package.ledger,
        "token_id": record.package.token_id,
        "published_at": record.package.published_at,
        "availability": availability,
        "access_state": access_state,
        // A purchase this person started and has not finished. It is its own
        // field rather than another `access_state`, because a state is a value
        // consumers switch on and a new one falls silently into whatever their
        // default does -- while an unknown FIELD is refused loudly by the
        // parser on the other side of this contract.
        "purchase_in_flight": purchase_in_flight,
    }))
}

pub(super) fn runtime_custody_listing_availability(record: &RuntimeCustodyListingRecord) -> Value {
    json!({
        "schema": RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1,
        "status": if record.availability.is_verified_fetch() {
            "last_verified_fetch"
        } else {
            "last_verified_receipt"
        },
        "checked_at": record.availability.checked_at,
        "required_replicas": PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        "observed_replicas": record.availability.observed_replicas,
        "receipt_digest": record.availability.receipt_digest,
        "recheck_before_buy": true,
        "recheck_before_open": true,
    })
}

/// Whether this person has a purchase of this item under way.
///
/// A purchase lives in Runtime, not in the page that started it, so closing
/// Marketplace or reloading it leaves the attempt running and the row looking
/// untouched. Pressing Buy again resumes the same attempt against the same
/// effect rather than starting a second one, which is safe but invisible --
/// and a person who cannot see that their purchase is still going has no way
/// to tell it from one that never started.
///
/// A record that has reached `Complete` is not in flight: the copy is theirs
/// and `access_state` already says so.
fn runtime_custody_listing_purchase_in_flight(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<bool> {
    let mint_id = parse_mint_id_hex(&record.package.mint_id)?;
    Ok(
        load_runtime_custody_purchase(data_dir, principal_id, mint_id)?.is_some_and(|purchase| {
            matches!(
                purchase.progress,
                RuntimeCustodyPurchaseProgress::Pending { .. }
            )
        }),
    )
}

fn runtime_custody_listing_access_state(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<&'static str> {
    if matches!(
        &record.origin,
        RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: creator,
            ..
        } if creator == principal_id
    ) {
        return Ok(RUNTIME_CUSTODY_LISTING_ACCESS_CREATOR);
    }
    let mint_id = parse_mint_id_hex(&record.package.mint_id)?;
    let Some(purchase) = load_runtime_custody_purchase(data_dir, principal_id, mint_id)? else {
        return Ok(RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE);
    };
    if purchase.mint_id != record.package.mint_id
        || purchase.content_id != record.package.content_id
    {
        anyhow::bail!("Runtime custody purchase is invalid");
    }
    // A granted copy is held exactly as a bought one is; `acquisition` says
    // which it was. It is bound to the mint and content checked above, not to
    // the terms of whichever listing now stands for the mint.
    let purchased = match purchase.progress {
        RuntimeCustodyPurchaseProgress::Complete { .. } => {
            purchase.listing_sha256 == record.portable_package_digest()
        }
        RuntimeCustodyPurchaseProgress::Granted { .. } => true,
        RuntimeCustodyPurchaseProgress::Pending { .. } => false,
    };
    Ok(if purchased {
        RUNTIME_CUSTODY_LISTING_ACCESS_PURCHASED
    } else {
        RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE
    })
}

pub(super) fn truncate_utf8_to_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn validate_runtime_custody_display_name(value: &str) -> anyhow::Result<()> {
    validate_runtime_custody_public_text(value)?;
    if value.chars().all(char::is_whitespace) {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

fn validate_runtime_custody_public_text(value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(crate) fn validate_runtime_custody_canonical_quantity(value: &str) -> anyhow::Result<()> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    if raw.is_empty()
        || raw.len() > 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    if raw.len() > 1 && raw.starts_with('0') {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(crate) fn validate_runtime_custody_evm_address(value: &str) -> anyhow::Result<()> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    if raw.len() != 40
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(crate) fn persist_runtime_custody_listing(
    data_dir: &Path,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<()> {
    let extension = RuntimeListingSourceExtension::for_record(record)?
        .map(|extension| serde_json::to_vec(&extension))
        .transpose()?;
    if extension
        .as_ref()
        .is_some_and(|bytes| bytes.len() as u64 > RuntimeListingSourceExtension::MAX_BYTES)
    {
        anyhow::bail!("Runtime listing source extension is invalid");
    }
    let mint_id = parse_mint_id_hex(&record.package.mint_id)?;
    write_owner_only_bytes(
        &runtime_listing_path(data_dir, mint_id),
        &serde_json::to_vec(record)?,
    )?;
    // Base first: if the optional second atomic write fails, the paid
    // package and its N-1-readable listing remain valid. A verified retry
    // can recreate missing, stale or malformed local provenance.
    if let Some(bytes) = extension {
        write_owner_only_bytes(&runtime_listing_source_path(data_dir, mint_id), &bytes)?;
    }
    Ok(())
}

pub(crate) fn load_runtime_custody_listing(
    data_dir: &Path,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimeCustodyListingRecord>> {
    let path = runtime_listing_path(data_dir, mint_id);
    if !path.exists() {
        return Ok(None);
    }
    let record = decode_runtime_listing_record(data_dir, &fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    record.validate()?;
    Ok(Some(record))
}

pub(crate) fn runtime_custody_creator_listing_package(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    facts: &RuntimeCustodyLibraryPublishFacts,
    publisher_principal_id: &str,
    terminal: &RuntimeMintCreatorTerminalEvidence,
    seal: Option<&elastos_protected_content_runtime::RuntimeSealedRightsPolicyV1>,
) -> anyhow::Result<RuntimePortableListingPackage> {
    let mint_id = mint.draft().mint_id();
    let availability = mint
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, publisher_principal_id)?;
    let remote_seal = runtime_mint_journal(data_dir).load_remote_mint_proof(mint_id)?;
    if remote_seal.is_none() && availability.publisher_identity() != publisher_profile_did {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    let (media_identity_base64, content_identity_base64) =
        runtime_portable_identity_fields(mint.draft().content_identity())
            .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    // Plan B POOL-MINT (S7I-F2): a pool mint carries its share statement.
    let pool_mint_share_b64 =
        runtime_pool_mint_record(data_dir, mint_id)?.map(|record| record.mint_share_base64);
    let remote_seal = remote_seal
        .map(|(descriptor, request, completion)| -> anyhow::Result<_> {
            let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
            Ok(RuntimePortableRemoteSealV1 {
                descriptor_base64: encode(descriptor.canonical_bytes()?),
                request_base64: encode(request.canonical_bytes()?),
                completion_base64: encode(completion.canonical_bytes()?),
            })
        })
        .transpose()?;
    if remote_seal.is_some() {
        anyhow::ensure!(seal.is_some(), "a remote mint needs a sealed rights policy");
    }
    let package = RuntimePortableListingPackage {
        schema: if remote_seal.is_some() {
            RUNTIME_PORTABLE_LISTING_SCHEMA_V3
        } else if seal.is_some() {
            RUNTIME_PORTABLE_LISTING_SCHEMA_V2
        } else {
            RUNTIME_PORTABLE_LISTING_SCHEMA_V1
        }
        .to_string(),
        mint_id: hex::encode(mint_id.as_bytes()),
        content_id: facts.content_id.clone(),
        content_access_id: format!(
            "0x{}",
            hex::encode(mint.draft().content_access_id().as_bytes())
        ),
        content_cid: facts.content_cid.clone(),
        metadata_cid: terminal.metadata_cid().to_string(),
        token_uri: terminal.token_uri().to_string(),
        publisher_profile_did,
        display_name: facts.display_name.clone(),
        media_identity_base64,
        content_identity_base64,
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().key_envelope().canonical_bytes()?),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().policy().canonical_bytes()?),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().content_key_commitment().as_bytes()),
        quantity: terminal.quantity().to_string(),
        seller_address: terminal.seller().to_ascii_lowercase(),
        chain_namespace: terminal.chain_namespace().to_string(),
        network: terminal.network().to_string(),
        ledger: terminal.ledger().to_ascii_lowercase(),
        token_id: terminal.token_id().to_ascii_lowercase(),
        operative: terminal.operative().to_ascii_lowercase(),
        price: terminal.price().to_string(),
        pay_token: terminal.pay_token().to_ascii_lowercase(),
        payment_processor: terminal.payment_processor().map(str::to_ascii_lowercase),
        mint_transaction_hash: Some(terminal.transaction_hash().to_ascii_lowercase()),
        published_at: Some(terminal.published_at()),
        pool_mint_share_b64,
        sealed_rights_policy_base64: seal
            .map(|seal| {
                seal.sealed_policy()
                    .canonical_bytes()
                    .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
            })
            .transpose()?,
        remote_seal,
    };
    if package.remote_seal.is_some() {
        let decoded = package.decode_and_validate()?;
        anyhow::ensure!(
            decoded.remote_content_publisher.as_deref() == Some(availability.publisher_identity()),
            "remote content publisher differs from the journal"
        );
    }
    Ok(package)
}

/// The on-disk shape of an owned protected item: the `.ddrm` the Library shows
/// and the viewer opens.
pub(crate) const RUNTIME_CUSTODY_CAPSULE_SCHEMA_V1: &str =
    "elastos.library.protected-content-capsule/v1";

/// The document a `.ddrm` file contains.
///
/// It is the asset's own `metadata.json` -- the same document the token URI
/// resolves to -- with the handful of facts only the chain can supply raised to
/// the top level beside it: the authority governing the asset, its `kid`, the
/// `tokenId` minted on the ledger, the ledger itself, and the content type that
/// decides which viewer opens it.
///
/// Those five are lifted rather than left to readers to dig out, because they
/// are what every reader needs first and what `metadata.json` alone cannot
/// answer: a `tokenId` does not exist until the mint emits it, and an authority
/// may not have been configured when the metadata was written. The metadata is
/// carried whole rather than summarised, so a capsule is self-describing and
/// can be read without fetching anything.
///
/// `metadataUri` names where that document was published, so the embedded copy
/// can always be checked against the one the token URI resolves to.
pub(crate) fn runtime_custody_capsule_document(
    package: &RuntimePortableListingPackage,
    metadata: &Value,
    acquisition: RuntimeCustodyAcquisitionV1,
) -> Value {
    // Stated at mint time when the network had a market configured; otherwise
    // recovered afterwards from the gateway that emitted the mint's own
    // `ItemListed`, which IS the authority.
    let authority = metadata
        .get("properties")
        .and_then(|properties| properties.get("authority"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut capsule = serde_json::json!({
        "schema": RUNTIME_CUSTODY_CAPSULE_SCHEMA_V1,
        "authority": authority,
        "kid": package.content_access_id,
        "tokenId": package.token_id,
        "ledger": package.ledger,
        "contentType": runtime_custody_capsule_content_type(metadata),
        "operative": package.operative,
        "chainNamespace": package.chain_namespace,
        "network": package.network,
        "mintId": package.mint_id,
        "contentId": package.content_id,
        "contentCid": package.content_cid,
        "acquisition": acquisition,
        "metadataUri": format!("ipfs://{}", package.metadata_cid),
        "metadata": metadata,
    });
    // An adopted copy knows no mint transaction (D11); it says nothing rather
    // than stating one as `null`.
    if let Some(mint_transaction_hash) = &package.mint_transaction_hash {
        capsule["mintTransactionHash"] = Value::String(mint_transaction_hash.clone());
    }
    capsule
}

/// What the capsule protects, taken from the metadata document that describes
/// it.
///
/// `media.mimeType` is read first because that is where the MIME lives. In the
/// Elacity asset schema `media.contentType` is a category word -- Video, Audio,
/// Image, 3D Model, Document -- which a marketplace indexes on and which is
/// useless for deciding what this is. Older folders, and any that state only
/// one of the two, still answer through the fallback.
pub(crate) fn runtime_custody_capsule_content_type(metadata: &Value) -> String {
    let media = metadata.get("media");
    let mime = media
        .and_then(|media| media.get("mimeType"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !mime.is_empty() {
        return mime.to_string();
    }
    media
        .and_then(|media| media.get("contentType"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn persist_runtime_custody_creator_listing(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    package: RuntimePortableListingPackage,
    publisher_principal_id: &str,
    listing_uri: String,
) -> anyhow::Result<()> {
    let mint_id = mint.draft().mint_id();
    let evidence = mint
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    let expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin: RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: publisher_principal_id.to_string(),
            package_sha256: hex::encode(sha2::Sha256::digest(serde_json::to_vec(&package)?)),
            listing_uri,
        },
        package,
        availability: RuntimeCustodyListingAvailabilitySummary::from_evidence(
            &evidence.clone().into(),
        ),
    };
    expected.validate()?;
    if let Some(existing) = load_runtime_custody_listing(data_dir, mint_id)? {
        if existing == expected {
            return Ok(());
        }
        anyhow::bail!("Runtime custody listing is invalid");
    }
    persist_runtime_custody_listing(data_dir, &expected)
}

/// Held for the lifetime of one `persist_runtime_custody_purchase` critical
/// section. Records entry/exit against `path`'s holder count and latches
/// `true` if a second holder for the same path is ever observed while this
/// one is still live — the exact overlap `ExclusiveFileLock` must prevent.
/// The deliberate sleep widens the window: while this probe is alive the
/// real OS-level `flock` is held, so every other thread contending for the
/// same lock path is genuinely parked in the kernel, not merely lucky not to
/// race. That turns "no overlap ever observed" from a probabilistic outcome
/// into a deterministic one.
#[cfg(test)]
pub(super) struct RuntimePurchaseLockTestProbe {
    path: PathBuf,
}

#[cfg(test)]
impl RuntimePurchaseLockTestProbe {
    pub(super) fn enter(path: PathBuf) -> Self {
        {
            let mut state = runtime_purchase_lock_test_state()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = state.entry(path.clone()).or_insert((0, false));
            entry.0 += 1;
            if entry.0 > 1 {
                entry.1 = true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        Self { path }
    }
}

#[cfg(test)]
impl Drop for RuntimePurchaseLockTestProbe {
    fn drop(&mut self) {
        let mut state = runtime_purchase_lock_test_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = state.get_mut(&self.path) {
            entry.0 -= 1;
        }
    }
}

/// Record `purchase` only when this principal holds no record for its mint,
/// deciding under the purchase ledger lock. `Ok(false)` when a record --
/// a purchase under way, say -- was already there; it is left exactly as it
/// is.
pub(crate) fn create_runtime_custody_purchase_if_absent(
    data_dir: &Path,
    purchase: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<bool> {
    let mint_id = parse_mint_id_hex(&purchase.mint_id)?;
    let lock_path = runtime_purchase_lock_path(data_dir, &purchase.principal_id);
    #[cfg(unix)]
    if let Some(parent) = lock_path.parent() {
        ensure_owner_only_runtime_storage_parent(parent)?;
    }
    #[cfg(not(unix))]
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    if load_runtime_custody_purchase(data_dir, &purchase.principal_id, mint_id)?.is_some() {
        return Ok(false);
    }
    write_owner_only_bytes(
        &runtime_purchase_path(data_dir, &purchase.principal_id, mint_id),
        &serde_json::to_vec(purchase)?,
    )?;
    Ok(true)
}

/// Attach a Library file to the same minted record verified before filing it.
pub(crate) fn attach_runtime_custody_minted_capsule(
    data_dir: &Path,
    expected: &RuntimeCustodyPurchaseRecord,
    capsule_uri: String,
) -> anyhow::Result<bool> {
    if expected.acquisition != RuntimeCustodyAcquisitionV1::Minted || expected.capsule_uri.is_some()
    {
        return Ok(false);
    }
    let mint_id = parse_mint_id_hex(&expected.mint_id)?;
    let lock_path = runtime_purchase_lock_path(data_dir, &expected.principal_id);
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    let Some(mut current) =
        load_runtime_custody_purchase(data_dir, &expected.principal_id, mint_id)?
    else {
        return Ok(false);
    };
    if current != *expected {
        return Ok(false);
    }
    current.capsule_uri = Some(capsule_uri);
    write_owner_only_bytes(
        &runtime_purchase_path(data_dir, &expected.principal_id, mint_id),
        &serde_json::to_vec(&current)?,
    )?;
    Ok(true)
}

/// The kind of one protected item, in the same two words the viewer session
/// already speaks.
///
/// This exists so that a listing can say what it is before anyone opens it.
/// Marketplace used to decide the viewer from the item's MIME, which is a
/// second rule for a question [`expected_runtime_custody_viewer_capsule`]
/// already answers, and a second rule can disagree. The arms here are that
/// function's arms: media is the player's, an object is the reader's, and a
/// test holds the two together.
/// [`runtime_custody_content_kind`] for the content a listing package names.
pub(crate) fn runtime_custody_package_content_kind(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<&'static str> {
    Ok(runtime_custody_content_kind(
        &package.decode_and_validate()?.content_identity,
    ))
}

pub(crate) const fn runtime_custody_content_kind(
    content_identity: &RuntimeContentIdentityV1,
) -> &'static str {
    match content_identity {
        RuntimeContentIdentityV1::Media(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA
        }
        RuntimeContentIdentityV1::Object(_) => RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT,
    }
}

#[cfg(test)]
pub(crate) fn runtime_listing_path_for_test(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    runtime_listing_path(data_dir, mint_id)
}

pub(super) fn runtime_listing_path(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    data_dir
        .join(RUNTIME_LISTING_ROOT)
        .join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

/// The lock file guarding a principal's purchase-ledger directory. Every
/// `persist_runtime_custody_purchase` call for this principal serializes
/// through this lock before writing, so two concurrent purchase writes never
/// race on the durable record's rename.
pub(super) fn runtime_purchase_lock_path(data_dir: &Path, principal_id: &str) -> PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(principal_id.as_bytes());
    data_dir
        .join(RUNTIME_PURCHASE_ROOT)
        .join(hex::encode(hasher.finalize()))
        .join(".lock")
}

/// R9: strip an optional `0x`, require exactly 32 hex digits, lowercase,
/// re-prefix `0x`.
pub(crate) fn normalize_runtime_market_kid(value: &str) -> Option<String> {
    let value = value.trim();
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    (raw.len() == 32 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("0x{}", raw.to_ascii_lowercase()))
}

/// The read dataset, taken from the shared `metadata.json` only (D4).
#[derive(Debug, Clone)]
pub(crate) struct SharedReadDataset {
    /// `0x` + 32 lowercase hex (R9).
    pub(crate) kid: String,
    /// `media.uri` without `ipfs://`.
    pub(crate) content_cid: String,
    /// `media.mimeType`.
    pub(crate) mime_type: String,
    /// `name`.
    pub(crate) name: String,
    pub(crate) rights_policy_identity_base64: String,
    pub(crate) key_envelope_identity_base64: String,
    pub(crate) content_key_commitment_base64: String,
    /// `content_identity_base64`, decoded.
    pub(crate) content_identity: RuntimeContentIdentityV1,
    /// `did:pkh:eip155:<properties.chainId>:<properties.publisher>` (D16).
    pub(crate) publisher_identity: String,
    /// Plan B POOL-MINT (S7I-F2): the minting Home's signed share statement,
    /// when the item was minted through a pool its minter uses.
    pub(crate) pool_mint_share_b64: Option<String>,
    pub(crate) rights_policy_seal_required: bool,
}

/// Any protection scheme this Runtime speaks, current or not.
pub(crate) const ELASTOS_PROTECTION_SCHEME_PREFIX: &str = "cenc:elastos-";

pub(crate) fn shared_text(metadata: &serde_json::Value, pointer: &str) -> anyhow::Result<String> {
    metadata
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("shared metadata has no {pointer}"))
}

/// The read dataset from an asset's shared `metadata.json` (D4, R12).
///
/// `Ok(None)` when the document names no ElastOS protection at all -- neither
/// an `asset.protections[*].protectionType` nor a `media.protectionType[*]` in
/// the ElastOS scheme -- which makes the asset foreign. An ElastOS entry that
/// cannot be adopted (a `-v0` entry, or a `-v1` entry missing an identity) is
/// an error, not foreign: the asset is ours, just not adoptable.
///
/// `manifest.json` is never read; nothing here needs anything but the
/// document every marketplace reads.
pub(crate) fn shared_read_dataset(
    metadata: &serde_json::Value,
) -> anyhow::Result<Option<SharedReadDataset>> {
    let protections = metadata
        .pointer("/asset/protections")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let scheme = |entry: &serde_json::Value| {
        entry
            .get("protectionType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let identity = |entry: &serde_json::Value, field: &str| {
        entry
            .get(field)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let adoptable = protections.iter().find_map(|entry| {
        if !PROTECTION.registry().is_listed_scheme(&scheme(entry)) {
            return None;
        }
        Some((
            identity(entry, "rights_policy_identity_base64")?,
            identity(entry, "key_envelope_identity_base64")?,
            identity(entry, "content_key_commitment_base64")?,
            identity(entry, "content_identity_base64")?,
            identity(entry, "pool_mint_share_base64"),
            entry.get("rights_policy_seal_required"),
        ))
    });
    let Some((
        rights_policy,
        key_envelope,
        content_key_commitment,
        content_identity,
        pool_mint_share_b64,
        seal_requirement,
    )) = adoptable
    else {
        let media_schemes: Vec<String> = match metadata.pointer("/media/protectionType") {
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(serde_json::Value::String(value)) => vec![value.clone()],
            _ => Vec::new(),
        };
        let elastos = protections
            .iter()
            .map(scheme)
            .chain(media_schemes)
            .any(|scheme| scheme.starts_with(ELASTOS_PROTECTION_SCHEME_PREFIX));
        if elastos {
            anyhow::bail!("the shared document's ElastOS protection cannot be adopted");
        }
        return Ok(None);
    };
    let rights_policy_seal_required = match seal_requirement {
        None => false,
        Some(serde_json::Value::Bool(true)) => true,
        Some(_) => anyhow::bail!("shared metadata has an invalid rights policy seal requirement"),
    };
    // R9: every KID the document states is normalized, and all of them must
    // name the same one.
    let mut kid: Option<String> = None;
    for pointer in ["/kid", "/properties/kid", "/asset/kid"] {
        let Some(value) = metadata.pointer(pointer) else {
            continue;
        };
        let named = value
            .as_str()
            .and_then(normalize_runtime_market_kid)
            .ok_or_else(|| anyhow::anyhow!("shared metadata names an invalid kid"))?;
        match &kid {
            Some(first) if *first != named => {
                anyhow::bail!("shared metadata names two kids")
            }
            Some(_) => {}
            None => kid = Some(named),
        }
    }
    let kid = kid.ok_or_else(|| anyhow::anyhow!("shared metadata names no kid"))?;
    let media_uri = shared_text(metadata, "/media/uri")?;
    let content_cid = media_uri
        .strip_prefix("ipfs://")
        .ok_or_else(|| anyhow::anyhow!("shared metadata media.uri is not ipfs://"))?
        .to_string();
    let publisher = shared_text(metadata, "/properties/publisher")?.to_ascii_lowercase();
    validate_runtime_custody_evm_address(&publisher)
        .map_err(|_| anyhow::anyhow!("shared metadata publisher is not an address"))?;
    let chain_id = match metadata.pointer("/properties/chainId") {
        Some(serde_json::Value::Number(number)) => number.as_u64(),
        Some(serde_json::Value::String(text)) => text.parse::<u64>().ok(),
        _ => None,
    }
    .ok_or_else(|| anyhow::anyhow!("shared metadata names no chain"))?;
    Ok(Some(SharedReadDataset {
        kid,
        content_cid,
        mime_type: metadata
            .pointer("/media/mimeType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        name: shared_text(metadata, "/name")?,
        rights_policy_identity_base64: rights_policy,
        key_envelope_identity_base64: key_envelope,
        content_key_commitment_base64: content_key_commitment,
        content_identity: decode_runtime_shared_content_identity(&content_identity)?,
        publisher_identity: format!("did:pkh:eip155:{chain_id}:{publisher}"),
        pool_mint_share_b64,
        rights_policy_seal_required,
    }))
}
