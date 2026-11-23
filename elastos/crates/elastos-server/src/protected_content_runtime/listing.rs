use super::*;

pub(super) const RUNTIME_LISTING_SCHEMA_V1: &str = "elastos.library.runtime-custody-listing/v1";

pub(super) const RUNTIME_PORTABLE_LISTING_SCHEMA_V1: &str =
    "elastos.protected-content.portable-listing/v1";

const MAX_RUNTIME_PORTABLE_LISTING_BYTES: u64 = 128 * 1024;

pub(super) const RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-listings/v1";

pub(super) const RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-availability-summary/v1";

const RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE: &str = "available";

const RUNTIME_CUSTODY_LISTING_ACCESS_CREATOR: &str = "creator";

const RUNTIME_CUSTODY_LISTING_ACCESS_PURCHASED: &str = "purchased";

pub(super) const MAX_RUNTIME_CUSTODY_LISTINGS: usize = 128;

pub(super) const MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES: usize = 256;

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
    pub(crate) media_identity_base64: String,
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
    pub(crate) mint_transaction_hash: String,
    pub(crate) published_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyListingAvailabilitySummary {
    pub(super) checked_at: u64,
    pub(super) observed_replicas: u32,
    pub(super) receipt_digest: String,
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
            }
        }
        if self.availability.checked_at == 0
            || self.availability.observed_replicas < PROTECTED_CONTENT_MIN_REPLICAS
            || self.availability.receipt_digest.len() != 64
            || hex::decode(&self.availability.receipt_digest)
                .map_or(true, |bytes| bytes.len() != 32)
        {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        Ok(())
    }

    pub(crate) fn portable_package_digest(&self) -> String {
        let package_sha256 = match &self.origin {
            RuntimeCustodyListingOrigin::LocalCreator { package_sha256, .. }
            | RuntimeCustodyListingOrigin::Imported { package_sha256, .. } => package_sha256,
        };
        format!("sha256:{package_sha256}")
    }
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
    pub(super) media_identity: CencFmp4MediaIdentityV1,
    content_access_id: ContentAccessIdV1,
    key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    rights_policy: RightsPolicyIdentityV1,
    content_key_commitment: Digest32,
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
    media_identity_base64: String,
    key_envelope_identity_base64: String,
    rights_policy_identity_base64: String,
    content_key_commitment_base64: String,
}

impl RuntimePortableListingPackage {
    pub(super) fn decode_and_validate(&self) -> anyhow::Result<DecodedRuntimePortableAsset> {
        if self.schema != RUNTIME_PORTABLE_LISTING_SCHEMA_V1
            || self.token_uri != format!("ipfs://{}/metadata.json", self.metadata_cid)
            || self.published_at == 0
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
        let transaction_hash = decode_0x_hex(&self.mint_transaction_hash)
            .filter(|bytes| bytes.len() == 32)
            .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        if self.mint_transaction_hash != format!("0x{}", hex::encode(transaction_hash)) {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let media_identity: CencFmp4MediaIdentityV1 = decode_runtime_portable_contract(
            &self.media_identity_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
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
        if media_identity.encrypted_content() != key_envelope.encrypted_content()
            || runtime_protected_content_id(media_identity.encrypted_content())? != self.content_id
            || media_identity.mime_type().len() > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
            || media_identity.codecs().len() > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
        {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        Ok(DecodedRuntimePortableAsset {
            media_identity,
            content_access_id,
            key_envelope,
            rights_policy,
            content_key_commitment,
        })
    }
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

fn validate_runtime_custody_profile_did(value: &str) -> anyhow::Result<()> {
    validate_runtime_custody_public_text(value)?;
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

/// Decodes a fetched portable listing and checks it against the manifest it
/// came with. Every listing import validates its package here.
fn runtime_portable_listing_package(
    manifest: &crate::content::ContentObjectManifest,
    bytes: &[u8],
) -> anyhow::Result<(RuntimePortableListingPackage, DecodedRuntimePortableAsset)> {
    let package: RuntimePortableListingPackage = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
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
    let manifest = crate::content::fetch_content_object_manifest(registry, cid).await?;
    let file = manifest
        .files
        .first()
        .filter(|file| {
            manifest.files.len() == 1
                && file.path == path
                && file.size <= MAX_RUNTIME_PORTABLE_LISTING_BYTES
        })
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let bytes = crate::content::fetch_bytes_via_provider(registry, cid, Some(path)).await?;
    if bytes.len() as u64 > MAX_RUNTIME_PORTABLE_LISTING_BYTES {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    crate::content::verify_content_object_file(cid, file, &bytes)?;
    Ok((manifest, bytes))
}

async fn verify_runtime_portable_metadata(
    registry: &ProviderRegistry,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
) -> anyhow::Result<()> {
    let (manifest, bytes) =
        fetch_runtime_portable_file(registry, &package.metadata_cid, "metadata.json").await?;
    let metadata: RuntimePortableMetadata = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    if serde_json::to_vec(&metadata)? != bytes
        || manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != "directory"
        || !manifest.links.is_empty()
        || metadata.schema != "elastos.protected-content.metadata/v1"
        || metadata.name != package.display_name
        || metadata.mime_type != decoded.media_identity.mime_type()
        || metadata.codecs != decoded.media_identity.codecs()
        || metadata.encrypted_content_cid != package.content_cid
        || metadata.content_access_id != package.content_access_id
        || metadata.protected_content_identity != package.content_id
        || metadata.mint_id != package.mint_id
        || metadata.publisher_profile_did != package.publisher_profile_did
        || metadata.media_identity_base64 != package.media_identity_base64
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
    let receipt: crate::api::gateway::ResolvedProtectedContentMintReceipt = serde_json::from_value(
        resolve(json!({
            "op": "resolve_protected_content_mint_receipt", "network": package.network,
            "hash": package.mint_transaction_hash, "creator": package.seller_address,
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

pub(super) async fn verify_runtime_portable_media(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    now_unix_seconds: u64,
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
        PROTECTED_CONTENT_MIN_REPLICAS,
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
        &decoded.media_identity,
    )
    .await?;
    let availability = verify_protected_content_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        &decoded.media_identity,
        &requirement,
        // Re-sampled: the refresh above may have walked dead-candidate timeouts.
        now_unix_seconds.max(crate::auth::now_ts()),
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
        decoded.media_identity.mime_type(),
        decoded.media_identity.codecs(),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    if draft.mint_id() != parse_mint_id_hex(&package.mint_id)? {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
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
    let (manifest, bytes) =
        fetch_runtime_portable_file(&registry, listing_cid, "listing.json").await?;
    let (package, decoded) = runtime_portable_listing_package(&manifest, &bytes)?;
    verify_runtime_portable_metadata(&registry, &package, &decoded).await?;
    verify_runtime_portable_chain(&registry, &package).await?;
    let (draft, verified_availability) = verify_runtime_portable_media(
        data_dir,
        &registry,
        &package,
        &decoded,
        crate::auth::now_ts(),
    )
    .await?;
    let availability = RuntimeCustodyListingAvailabilitySummary {
        checked_at: verified_availability.checked_at(),
        observed_replicas: verified_availability.observed_replicas(),
        receipt_digest: hex::encode(verified_availability.receipt_digest().as_bytes()),
    };
    let package_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    let expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin: RuntimeCustodyListingOrigin::Imported {
            listing_uri: listing_uri.to_string(),
            package_sha256,
        },
        package,
        availability,
    };
    expected.validate()?;
    if let Some(existing) = load_runtime_custody_listing(data_dir, draft.mint_id())? {
        if existing.schema != expected.schema
            || existing.origin != expected.origin
            || existing.package != expected.package
            || (existing.availability.checked_at == expected.availability.checked_at
                && existing.availability != expected.availability)
        {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        if expected.availability.checked_at > existing.availability.checked_at {
            persist_runtime_custody_listing(data_dir, &expected)?;
        }
    } else {
        persist_runtime_custody_listing(data_dir, &expected)?;
    }
    Ok(json!({
        "schema": "elastos.library.runtime-custody-import/v1",
        "listing_uri": listing_uri,
        "mint_id": expected.package.mint_id,
        "status": "verified",
    }))
}

pub(crate) fn list_runtime_custody_listings(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Value> {
    if principal_id.trim().is_empty() {
        anyhow::bail!("Runtime custody listing principal is invalid");
    }
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    let (listing_paths, truncated) = select_runtime_custody_listing_paths(&root)?;
    let mut listings = Vec::with_capacity(listing_paths.len());
    for path in listing_paths {
        let bytes = fs::read(path)?;
        let record: RuntimeCustodyListingRecord = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
        record.validate()?;
        listings.push(runtime_custody_listing_summary(
            data_dir,
            principal_id,
            &record,
        )?);
    }
    Ok(json!({
        "schema": RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1,
        "truncated": truncated,
        "listings": listings,
    }))
}

pub(super) fn select_runtime_custody_listing_paths(
    root: &Path,
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
        if selected.len() < MAX_RUNTIME_CUSTODY_LISTINGS {
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

fn runtime_custody_listing_summary(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<Value> {
    let availability = runtime_custody_listing_availability(record);
    let access_state = runtime_custody_listing_access_state(data_dir, principal_id, record)?;
    let media = record.package.decode_and_validate()?.media_identity;
    Ok(json!({
        "schema": RUNTIME_LISTING_SCHEMA_V1,
        "mint_id": record.package.mint_id,
        "display_name": record.package.display_name,
        "mime_type": media.mime_type(),
        "codecs": media.codecs(),
        "quantity": record.package.quantity,
        "price": record.package.price,
        "pay_token": record.package.pay_token,
        "seller_address": record.package.seller_address,
        "token_id": record.package.token_id,
        "published_at": record.package.published_at,
        "availability": availability,
        "access_state": access_state,
    }))
}

fn runtime_custody_listing_availability(record: &RuntimeCustodyListingRecord) -> Value {
    json!({
        "schema": RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1,
        "status": "last_verified_receipt",
        "checked_at": record.availability.checked_at,
        "required_replicas": PROTECTED_CONTENT_MIN_REPLICAS,
        "observed_replicas": record.availability.observed_replicas,
        "receipt_digest": record.availability.receipt_digest,
        "recheck_before_buy": true,
        "recheck_before_open": true,
    })
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
    let purchased = matches!(
        purchase.progress,
        RuntimeCustodyPurchaseProgress::Complete { .. }
    ) && purchase.listing_sha256 == record.portable_package_digest();
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

fn validate_runtime_custody_canonical_quantity(value: &str) -> anyhow::Result<()> {
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

fn validate_runtime_custody_evm_address(value: &str) -> anyhow::Result<()> {
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
    write_owner_only_bytes(
        &runtime_listing_path(data_dir, parse_mint_id_hex(&record.package.mint_id)?),
        &serde_json::to_vec(record)?,
    )
}

pub(crate) fn load_runtime_custody_listing(
    data_dir: &Path,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimeCustodyListingRecord>> {
    let path = runtime_listing_path(data_dir, mint_id);
    if !path.exists() {
        return Ok(None);
    }
    let record: RuntimeCustodyListingRecord = serde_json::from_slice(&fs::read(path)?)
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
) -> anyhow::Result<RuntimePortableListingPackage> {
    let mint_id = mint.draft().mint_id();
    let availability = mint
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, publisher_principal_id)?;
    if availability.publisher_identity() != publisher_profile_did {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(RuntimePortableListingPackage {
        schema: RUNTIME_PORTABLE_LISTING_SCHEMA_V1.to_string(),
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
        media_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().media_identity().canonical_bytes()?),
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
        mint_transaction_hash: terminal.transaction_hash().to_ascii_lowercase(),
        published_at: terminal.published_at(),
    })
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
        availability: RuntimeCustodyListingAvailabilitySummary {
            checked_at: evidence.checked_at(),
            observed_replicas: evidence.observed_replicas(),
            receipt_digest: hex::encode(evidence.receipt_digest().as_bytes()),
        },
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

pub(super) fn runtime_listing_path(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    data_dir
        .join(RUNTIME_LISTING_ROOT)
        .join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}
