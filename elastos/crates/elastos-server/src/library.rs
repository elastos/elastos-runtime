use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _};
use base64::Engine as _;
use elastos_common::localhost::rooted_localhost_fs_path;
use elastos_runtime::provider::{
    Provider, ProviderError, ProviderInvocation, ProviderInvocationTransport, ProviderRegistry,
    ProviderTransfer, ResourceRequest, ResourceResponse,
};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zip::{ZipArchive, ZipWriter};

const LIBRARY_OBJECT_SCHEMA: &str = "elastos.library.object/v1";
const LIBRARY_ROOT_SCHEMA: &str = "elastos.library.root/v1";
const LIBRARY_EVENT_SCHEMA: &str = "elastos.library.event/v1";
const LIBRARY_ARCHIVE_ENTRIES_SCHEMA: &str = "elastos.library.archive-entries/v1";
const LIBRARY_ARCHIVE_EXTRACT_ENTRIES_SCHEMA: &str = "elastos.library.archive-extract-entries/v1";
const LIBRARY_ARCHIVE_PREVIEW_ENTRY_SCHEMA: &str = "elastos.library.archive-preview-entry/v1";
const LIBRARY_VISIBILITY_SCHEMA: &str = "elastos.library.visibility/v1";
const LIBRARY_TRASH_RECORD_SCHEMA: &str = "elastos.library.trash-record/v1";
const MAX_LIBRARY_EVENTS: usize = 256;
const MAX_ARCHIVE_LIST_ENTRIES: usize = 512;
const MAX_ARCHIVE_PREVIEW_BYTES: usize = 64 * 1024;
/// Entries in one archive that Library extracts (#449). Home's start check
/// reads every protected file, so one archive cannot add an unbounded number.
const MAX_ARCHIVE_EXTRACT_ENTRIES: usize = 10_000;
/// Bytes one archive entry may expand to when Library extracts it: the same
/// 100 MiB as one Library upload (`MAX_GATEWAY_FILE_SIZE`) (#449).
const MAX_ARCHIVE_ENTRY_BYTES: u64 = 100 * 1024 * 1024;
/// Bytes one archive may expand to, counting every entry a reader passes
/// over, in one extraction, listing or preview (#449).
const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 1024 * 1024 * 1024;
/// Selected files a Spaces write-back holds in memory before it sends them.
const MAX_ARCHIVE_SPACES_WRITE_BACK_BYTES: u64 = 256 * 1024 * 1024;
const RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE: &str = "Runtime custody publish input invalid";
const RUNTIME_CUSTODY_SHARE_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody sharing is not available yet";
const RUNTIME_CUSTODY_PUBLISHED_PAYLOAD: &str = "runtime_custody_encrypted";
pub(crate) const RUNTIME_CUSTODY_PUBLISH_UNSUPPORTED_TYPE_MESSAGE: &str =
    "Runtime custody publish does not support this file type";
/// Refusal for the three protected viewer operations on any route that does
/// not verify `executable_actor`. See [`LibraryRequestRoute`].
pub(crate) const RUNTIME_CUSTODY_VIEWER_ROUTE_DENIED_MESSAGE: &str =
    "Runtime custody viewer operations require the verified viewer gateway route";

static LIBRARY_EVENT_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();

pub(crate) fn library_event_notifier() -> &'static tokio::sync::Notify {
    LIBRARY_EVENT_NOTIFY.get_or_init(tokio::sync::Notify::new)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryObject {
    schema: &'static str,
    uri: String,
    name: String,
    kind: &'static str,
    mime: String,
    size: u64,
    created_at: u64,
    modified_at: u64,
    revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    viewer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    viewers: Vec<LibraryViewerOption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail_uri: Option<String>,
    availability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
    published: bool,
    /// The active publication: its own CID, link, time and the file revision
    /// it shares, which can differ from the file's current bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication: Option<Value>,
    shared: bool,
    capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryViewerOption {
    id: String,
    label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    default: bool,
}

#[derive(Debug, Clone, Serialize)]
struct LibraryRoot {
    schema: &'static str,
    id: &'static str,
    label: &'static str,
    uri: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryPublishRecord {
    schema: String,
    object_uri: String,
    cid: String,
    published_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unpublished_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shared_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    share_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    share_grants: Vec<LibraryShareGrant>,
    #[serde(default = "default_publish_content_security")]
    content_security: Value,
    receipt: Value,
    availability: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listing_uri: Option<String>,
    /// The file revision this publication shares (plain publications).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    /// This publication's owner id in Content, stable across rename and move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication_id: Option<String>,
    /// The size of the published bytes (plain publications).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryShareGrant {
    schema: String,
    grant_id: String,
    recipient: String,
    uri: String,
    cid: String,
    policy: String,
    #[serde(default = "default_share_key_release")]
    key_release: Value,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryTrashRecord {
    schema: String,
    trash_uri: String,
    original_uri: String,
    original_name: String,
    trashed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryEvent {
    schema: String,
    event_id: String,
    op: String,
    uri: String,
    at: u64,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    details: Value,
}

/// Which route one Library request arrived on.
///
/// Only [`LibraryRequestRoute::VerifiedGatewayLaunchToken`] —
/// `api::gateway_provider_proxy::gateway_provider_proxy` — cryptographically
/// verifies the home launch token and then strips any client-supplied
/// `executable_actor` before inserting the verified
/// `required.launch_context.executable_actor`. Every other entry point
/// (`ObjectProvider::send_raw`, the capsule resource-bridge route, and
/// `handle_object_provider_runtime_request`) leaves that field exactly as the
/// caller wrote it, so the three protected viewer operations — whose session
/// binding is keyed on it — are refused there instead of trusting it.
///
/// This is deliberately NOT the same signal as the gateway Wallet authority:
/// the proxy passes `gateway_authority: None` for `open_viewer`/`read_viewer`/
/// `close_viewer` (it only builds a Wallet authority for protected `publish`
/// and `buy`), so keying off that would reject the verified route itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LibraryRequestRoute {
    /// The gateway provider proxy, after home-launch-token verification.
    VerifiedGatewayLaunchToken,
    /// Any route whose request fields are entirely caller-supplied.
    UnverifiedCaller,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum ObjectProviderRequest {
    Roots {
        principal_id: String,
    },
    List {
        principal_id: String,
        #[serde(default)]
        uri: Option<String>,
    },
    Stat {
        principal_id: String,
        uri: String,
    },
    Read {
        principal_id: String,
        uri: String,
    },
    Download {
        principal_id: String,
        uri: String,
    },
    ExtractArchive {
        principal_id: String,
        uri: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    ArchiveEntries {
        principal_id: String,
        uri: String,
    },
    ArchivePreviewEntry {
        principal_id: String,
        uri: String,
        entry: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    ArchiveExtractEntries {
        principal_id: String,
        uri: String,
        destination_uri: String,
        #[serde(default)]
        entries: Vec<String>,
        #[serde(default)]
        conflict_policy: Option<String>,
        #[serde(default)]
        if_revision: Option<String>,
        #[serde(default)]
        cancel: bool,
    },
    CompressArchive {
        principal_id: String,
        #[serde(default)]
        uri: Option<String>,
        #[serde(default)]
        uris: Vec<String>,
        #[serde(default)]
        if_revision: Option<String>,
    },
    Write {
        principal_id: String,
        uri: String,
        data: String,
        #[serde(default)]
        mime: Option<String>,
        #[serde(default)]
        if_revision: Option<String>,
        #[serde(default)]
        create_only: bool,
    },
    Mkdir {
        principal_id: String,
        parent_uri: String,
        name: String,
    },
    Rename {
        principal_id: String,
        uri: String,
        name: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    Move {
        principal_id: String,
        uri: String,
        target_parent_uri: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    Copy {
        principal_id: String,
        uri: String,
        target_parent_uri: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    Trash {
        principal_id: String,
        uri: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    Restore {
        principal_id: String,
        uri: String,
        #[serde(default)]
        target_uri: Option<String>,
        #[serde(default)]
        if_revision: Option<String>,
    },
    DeletePermanently {
        principal_id: String,
        uri: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    EmptyTrash {
        principal_id: String,
    },
    Status {
        principal_id: String,
        uri: String,
    },
    Sync {
        principal_id: String,
        uri: String,
    },
    Events {
        principal_id: String,
        #[serde(default)]
        uri: Option<String>,
        #[serde(default)]
        since: Option<u64>,
        #[serde(default)]
        limit: Option<usize>,
    },
    Publish {
        principal_id: String,
        uri: String,
        #[serde(default)]
        if_revision: Option<String>,
        #[serde(default)]
        /// Boxed because this one variant carries every term of a mint --
        /// channel, token, price scale, access method, royalty split, the
        /// whole listing -- and an enum is as large as its largest variant.
        /// Every other request here would otherwise pay for it.
        protection: Option<Box<LibraryPublishProtectionRequest>>,
    },
    /// Read-only: how far this object's publish has got. Takes no revision
    /// and no protection terms, because it changes nothing.
    PublishProgress {
        principal_id: String,
        uri: String,
    },
    Unpublish {
        principal_id: String,
        uri: String,
        #[serde(default)]
        if_revision: Option<String>,
    },
    Repair {
        principal_id: String,
        uri: String,
    },
    /// Start over: set this object's unfinished protection attempt aside --
    /// archived, never deleted -- so protecting it again starts a new attempt.
    /// A settled and listed mint is refused beneath this request.
    DiscardProtection {
        principal_id: String,
        uri: String,
    },
    /// The unfinished mints of the files in one folder: the recoverable ones
    /// to offer back, while the unrecoverable ones are archived on the way.
    UnfinishedProtections {
        principal_id: String,
        uri: String,
    },
    Share {
        principal_id: String,
        uri: String,
        #[serde(default)]
        recipients: Vec<String>,
        #[serde(default)]
        policy: Option<String>,
        #[serde(default)]
        key_release_policy: Option<String>,
    },
    SharedAccess {
        principal_id: String,
        uri: String,
        recipient: String,
        #[serde(default)]
        recipient_proof: Option<Value>,
    },
    ListRuntimeCustody {
        principal_id: String,
    },
    ImportRuntimeCustody {
        principal_id: String,
        listing_uri: String,
    },
    Buy {
        principal_id: String,
        mint_id: String,
    },
    /// Buy one copy of a live market offer on the terms the buyer agreed to.
    /// The wire is exactly §5.2 (R20); `item`, `asset_uri` and `seller` are
    /// claims the purchase re-derives before trusting any of them.
    BuyOffer {
        principal_id: String,
        item: crate::protected_content_market::RuntimeMarketBuyItemClaim,
        asset_uri: String,
        seller: String,
        agreed: crate::protected_content_market::RuntimeMarketAgreedTerms,
    },
    /// Rebuild the local copy of an item this principal owns.
    ///
    /// A `.ddrm` capsule is made out of public material: the metadata document
    /// the token URI resolves to, and the content the listing names. Owning the
    /// access token is what makes the copy theirs, and that lives on the chain,
    /// so the local file can always be built again from those same sources.
    /// Buying and minting both write it as a side effect; this is how a person
    /// asks for it on its own, when that write never happened, when the file
    /// was deleted, or when they hold the token on a Home that never held it.
    ///
    /// Exactly one of `mint_id` and `item`: a copy bought on the market is
    /// named by its item (§5.2's shape), since until it is adopted there is
    /// no mint for it on this Home.
    DownloadOwnedCopy {
        principal_id: String,
        #[serde(default)]
        mint_id: Option<String>,
        #[serde(default)]
        item: Option<crate::protected_content_market::RuntimeMarketBuyItemClaim>,
    },
    OpenViewer {
        principal_id: String,
        mint_id: String,
        /// The verified viewer capsule (`elacity-player` or
        /// `elacity-reader`). Never trusted from the client: the gateway
        /// proxy overwrites this with `required.launch_context.executable_actor`
        /// before this request reaches here, exactly as it already does for
        /// `launch_id`/`session_id`/`grant_id`, and
        /// `handle_runtime_custody_library_request` refuses the viewer
        /// operations outright on every route that does not do that overwrite
        /// (see [`LibraryRequestRoute`]).
        #[serde(default)]
        executable_actor: Option<String>,
        #[serde(default)]
        launch_id: Option<String>,
        #[serde(default)]
        proof_binding_id: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        grant_id: Option<String>,
    },
    ReadViewer {
        principal_id: String,
        mint_id: String,
        viewer_session_handle: String,
        #[serde(default)]
        executable_actor: Option<String>,
        #[serde(default)]
        launch_id: Option<String>,
        #[serde(default)]
        proof_binding_id: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        grant_id: Option<String>,
        /// Media's part selector: absent means the init segment, `Some(n)`
        /// means segment `n`. Refused outright on an object session.
        #[serde(default)]
        segment_index: Option<u32>,
        /// The object's part selector: which framed chunk to decrypt.
        /// Required on an object session (an object has no init part, so
        /// there is nothing for "absent" to mean) and refused outright on a
        /// media session — never accepted and ignored.
        #[serde(default)]
        chunk_index: Option<u32>,
    },
    CloseViewer {
        principal_id: String,
        mint_id: String,
        viewer_session_handle: String,
        #[serde(default)]
        executable_actor: Option<String>,
        #[serde(default)]
        launch_id: Option<String>,
        #[serde(default)]
        proof_binding_id: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        grant_id: Option<String>,
    },
}

impl ObjectProviderRequest {
    /// A buy the Marketplace page asks for (`buy`, `buy_offer`): its answers
    /// must never carry this Home's account (D14, R31).
    fn is_marketplace_buy(&self) -> bool {
        matches!(self, Self::Buy { .. } | Self::BuyOffer { .. })
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "held boxed in `ObjectProviderRequest::Publish`, so the empty resume variant costs nothing"
)]
enum LibraryPublishProtectionRequest {
    RuntimeCustody {
        copies: String,
        /// What a buyer pays for one copy, as a decimal amount of the pay
        /// token below -- "0.001", not its base units.
        ///
        /// The amount rather than the integer, because an integer of some
        /// token's smallest unit says nothing about which token, and a caller
        /// that scaled for six decimals while the mint settles in eighteen
        /// agrees on the digits and disagrees by a factor of a million. The
        /// decimals live with the pay token in this Runtime's configuration,
        /// so the scaling happens where they are known and no caller has to
        /// declare what its number meant.
        price: String,
        /// The channel this mint publishes into.
        ///
        /// A mint term, beside copies and price, rather than part of the
        /// listing below: the listing is optional metadata a marketplace
        /// displays, while a mint without a channel has nowhere to settle.
        ///
        /// Defaulted so the field's absence is a clear refusal rather than a
        /// decode error, and required in `runtime_custody_listing_terms`.
        #[serde(default)]
        channel: String,
        /// The token the sale is priced in. Absent takes the mint source's
        /// first offered token, which is what a caller that does not choose
        /// means.
        #[serde(default)]
        pay_token: Option<String>,

        /// The listing a marketplace actually displays. Optional: absent means
        /// the pre-listing behaviour, a mint with no Elacity metadata folder,
        /// so an existing caller keeps working unchanged.
        #[serde(default)]
        listing: Option<LibraryPublishListingRequest>,
        /// A new mint of this file, as opposed to a retry or a poll of the one
        /// in flight: whatever attempt is unfinished is set aside first.
        #[serde(default)]
        new_attempt: bool,
        /// Plan B S7-lite T7.6: the pool to mint into, by DID. Absent takes
        /// this Home's own pool, else the only pool that admits this Home.
        #[serde(default)]
        pool_did: Option<String>,
    },
    /// Resume the mint already recorded for this object, at its recorded
    /// terms. Carries no terms on purpose: the person types nothing, and a
    /// resume can only ever continue what was agreed.
    RuntimeCustodyResume {},
}

/// Creator-supplied listing terms.
///
/// `deny_unknown_fields` on purpose: a caller that sends a field this build
/// does not understand is asking for something it will not get, and silently
/// dropping it is how a listing ends up claiming terms nobody applied.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LibraryPublishListingRequest {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    thumbnail: Option<LibraryPublishThumbnailRequest>,
    /// Must total exactly `RUNTIME_CUSTODY_ROYALTY_TOTAL_UNITS`. The protocol's
    /// own 50 units are minted by the contracts and are not the creator's to
    /// set, so they never appear here.
    #[serde(default)]
    royalties: Vec<LibraryPublishRoyaltyRequest>,
    /// How people reach the asset: `free`, `buy_once` or `buy_and_resell`.
    /// Absent means buy once, which is what every caller written before
    /// creators could choose meant.
    #[serde(default)]
    access_method: Option<String>,
    /// The resale cut in deci-percent (900 is 90%), for `buy_and_resell` only.
    #[serde(default)]
    reseller_cut: Option<u16>,
    /// How many decimal places the caller scaled `price` by.
    ///
    /// The price crosses this boundary as an integer of the pay token's
    /// smallest unit, which says nothing about which token that is. A caller
    /// that scaled for a six-decimal token and a mint that settles in an
    /// eighteen-decimal one agree on the digits and disagree by a factor of a
    /// million, so the meaning has to travel with the number and be checked
    /// against the token the mint will actually use.
    ///

    #[serde(default)]
    adult: bool,
    #[serde(default)]
    licensing: Option<Value>,
    #[serde(default)]
    legal_attestation: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LibraryPublishThumbnailRequest {
    mime: String,
    bytes_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LibraryPublishRoyaltyRequest {
    address: String,
    units: u32,
}

/// The creator's whole share of a primary sale, in ERC-1155 `ROYALTY_SHARE`
/// units. 1000 exist per asset and one unit is 0.1% of the sale: the creator
/// splits 950 and the protocol owner's 50 are minted by the contracts
/// themselves. A split that does not total this is not one the chain can
/// honour, and a listing showing it would describe a payout that will not
/// happen.
const RUNTIME_CUSTODY_ROYALTY_TOTAL_UNITS: u32 = 950;

/// Upper bound on a cover thumbnail, before base64. Large enough for a real
/// cover, small enough that a publish cannot be used to push arbitrary bulk
/// through the metadata directory.
const RUNTIME_CUSTODY_THUMBNAIL_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Validated listing terms. Distinct from the request type so nothing
/// downstream can reach an unvalidated field.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyListingTerms {
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) category: String,
    pub(crate) tags: Vec<String>,
    pub(crate) thumbnail: Option<RuntimeCustodyListingThumbnail>,
    pub(crate) royalties: Vec<RuntimeCustodyListingRoyalty>,
    /// The access method this mint creates, alongside the royalty split it
    /// sits with: both are terms the chain call is re-encoded from on a
    /// retry, not descriptions of the asset.
    pub(crate) access_method: elastos_protected_content_runtime::RuntimeMintAccessMethod,
    pub(crate) reseller_cut: Option<u16>,
    /// The decimal scale the creator's price was expressed in, checked against
    /// the pay token the mint settles in before anything is signed.
    pub(crate) adult: bool,
    pub(crate) licensing: Option<Value>,
    pub(crate) legal_attestation: Option<Value>,
}

#[derive(Clone)]
pub(crate) struct RuntimeCustodyListingThumbnail {
    pub(crate) mime: String,
    pub(crate) bytes: Vec<u8>,
}

/// Never renders the image bytes: a debug line is for an operator, and an
/// operator needs the size, not the picture.
impl std::fmt::Debug for RuntimeCustodyListingThumbnail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyListingThumbnail")
            .field("mime", &self.mime)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyListingRoyalty {
    pub(crate) address: String,
    pub(crate) units: u32,
}

struct LoadedRuntimeCustodyPublishInput {
    copies: String,
    price: String,
    /// The channel this mint publishes into, lower-cased. Never empty: a
    /// publish that named none was refused before this was built.
    channel: String,
    /// The token the sale is priced in, lower-cased. Empty means the mint
    /// source's first offered token.
    pay_token: String,
    listing: Option<RuntimeCustodyListingTerms>,
    new_attempt: bool,
    /// Plan B S7-lite T7.6: the chosen pool's DID; `None` takes the default.
    pool_did: Option<String>,
}

pub struct ObjectProvider {
    data_dir: PathBuf,
    registry: Weak<ProviderRegistry>,
}

impl ObjectProvider {
    pub fn new(data_dir: PathBuf, registry: Weak<ProviderRegistry>) -> Self {
        Self { data_dir, registry }
    }
}

#[async_trait::async_trait]
impl Provider for ObjectProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "object provider does not support URI resource routing; use raw operations".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["object"]
    }

    fn name(&self) -> &'static str {
        "object-provider"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let request = match serde_json::from_value::<ObjectProviderRequest>(request.clone()) {
            Ok(request) => request,
            Err(err) => return Ok(provider_error("invalid_request", &err.to_string())),
        };

        let data_dir = self.data_dir.clone();
        let marketplace_buy = request.is_marketplace_buy();
        let result = match request {
            ObjectProviderRequest::Publish {
                principal_id,
                uri,
                if_revision,
                protection,
            } => {
                let Some(registry) = self.registry.upgrade() else {
                    return Ok(provider_error(
                        "library_error",
                        "object provider registry unavailable",
                    ));
                };
                library_publish(
                    &data_dir,
                    registry,
                    &principal_id,
                    &uri,
                    if_revision.as_deref(),
                    protection.map(|protection| *protection),
                    None,
                )
                .await
            }
            ObjectProviderRequest::Unpublish {
                principal_id,
                uri,
                if_revision,
            } => {
                let Some(registry) = self.registry.upgrade() else {
                    return Ok(provider_error(
                        "library_error",
                        "object provider registry unavailable",
                    ));
                };
                library_unpublish(
                    &data_dir,
                    registry,
                    &principal_id,
                    &uri,
                    if_revision.as_deref(),
                )
                .await
            }
            ObjectProviderRequest::Repair { principal_id, uri } => {
                let Some(registry) = self.registry.upgrade() else {
                    return Ok(provider_error(
                        "library_error",
                        "object provider registry unavailable",
                    ));
                };
                library_repair(&data_dir, registry, &principal_id, &uri).await
            }
            request @ (ObjectProviderRequest::ListRuntimeCustody { .. }
            | ObjectProviderRequest::ImportRuntimeCustody { .. }
            | ObjectProviderRequest::DiscardProtection { .. }
            | ObjectProviderRequest::UnfinishedProtections { .. }
            | ObjectProviderRequest::Buy { .. }
            | ObjectProviderRequest::BuyOffer { .. }
            | ObjectProviderRequest::DownloadOwnedCopy { .. }
            | ObjectProviderRequest::OpenViewer { .. }
            | ObjectProviderRequest::ReadViewer { .. }
            | ObjectProviderRequest::CloseViewer { .. }) => {
                let Some(registry) = self.registry.upgrade() else {
                    return Ok(provider_error(
                        "library_error",
                        "object provider registry unavailable",
                    ));
                };
                handle_runtime_custody_library_request(
                    data_dir,
                    registry,
                    request,
                    None,
                    LibraryRequestRoute::UnverifiedCaller,
                )
                .await
            }
            request => handle_library_request_serialized(data_dir, request).await,
        };

        Ok(match result {
            Ok(data) => provider_ok(data),
            Err(err) => marketplace_buy_error_from(marketplace_buy, &err),
        })
    }
}

/// Handle one raw object provider request inside an isolated provider process.
///
/// The standalone provider owns principal-root object storage and Library event
/// state. Content publish/unpublish/repair are coordinated by Runtime for now,
/// because the current stdio provider ABI has no provider-to-provider
/// invocation channel.
pub fn handle_object_provider_raw_request(data_dir: &Path, request: &Value) -> Value {
    let request = match serde_json::from_value::<ObjectProviderRequest>(request.clone()) {
        Ok(request) => request,
        Err(err) => return provider_error("invalid_request", &err.to_string()),
    };

    let result = match request {
        ObjectProviderRequest::Publish { .. }
        | ObjectProviderRequest::Unpublish { .. }
        | ObjectProviderRequest::Repair { .. }
        | ObjectProviderRequest::DiscardProtection { .. }
        | ObjectProviderRequest::UnfinishedProtections { .. }
        | ObjectProviderRequest::ListRuntimeCustody { .. }
        | ObjectProviderRequest::ImportRuntimeCustody { .. }
        | ObjectProviderRequest::Buy { .. }
        | ObjectProviderRequest::BuyOffer { .. }
        | ObjectProviderRequest::DownloadOwnedCopy { .. }
        | ObjectProviderRequest::OpenViewer { .. }
        | ObjectProviderRequest::ReadViewer { .. }
        | ObjectProviderRequest::CloseViewer { .. } => Err(anyhow!(
            "library content operation requires Runtime content coordinator"
        )),
        request => handle_library_request(data_dir, request),
    };

    match result {
        Ok(data) => provider_ok(data),
        Err(err) => provider_error_from("library_error", &err),
    }
}

pub fn handle_library_upload_bytes(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    mime: Option<&str>,
    if_revision: Option<&str>,
    bytes: &[u8],
) -> anyhow::Result<Value> {
    let object =
        write_library_file_bytes(data_dir, principal_id, uri, mime, if_revision, false, bytes)?;
    Ok(provider_ok(json!({
        "object": object,
        "transport": "raw-body",
    })))
}

pub(crate) async fn handle_library_upload_bytes_runtime(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    uri: &str,
    mime: Option<&str>,
    if_revision: Option<&str>,
    bytes: &[u8],
) -> anyhow::Result<Value> {
    if is_webspace_uri(uri) {
        let uri = clean_webspace_uri(uri)?;
        let receipt = webspace_write_bytes(&registry, &uri, bytes).await?;
        let object = webspace_stat_object(data_dir, &registry, &uri).await?;
        return Ok(provider_ok(json!({
            "object": object,
            "transport": "raw-body",
            "provider_receipt": receipt,
        })));
    }
    handle_library_upload_bytes(data_dir, principal_id, uri, mime, if_revision, bytes)
}

pub(crate) struct LibraryDownloadBytes {
    pub(crate) filename: String,
    pub(crate) mime: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LibraryArchiveFormat {
    TarGz,
    Zip,
}

impl LibraryArchiveFormat {
    pub(crate) fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("tar.gz")
            .to_ascii_lowercase()
            .as_str()
        {
            "tar.gz" | "tgz" | "gzip" | "gz" => Ok(Self::TarGz),
            "zip" => Ok(Self::Zip),
            other => bail!("unsupported Library archive format: {other}"),
        }
    }

    fn mime(self) -> &'static str {
        match self {
            Self::TarGz => "application/gzip",
            Self::Zip => "application/zip",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Zip => "zip",
        }
    }
}

pub(crate) fn handle_library_download_bytes_with_format(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<LibraryDownloadBytes> {
    let (object, filename, bytes) =
        library_download_object(data_dir, principal_id, uri, archive_format)?;
    Ok(LibraryDownloadBytes {
        filename,
        mime: object.mime,
        bytes,
    })
}

pub(crate) fn handle_library_download_selection_bytes_with_format(
    data_dir: &Path,
    principal_id: &str,
    uris: &[String],
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<LibraryDownloadBytes> {
    let (filename, bytes) =
        archive_library_selection(data_dir, principal_id, uris, archive_format)?;
    Ok(LibraryDownloadBytes {
        filename,
        mime: archive_format.mime().to_string(),
        bytes,
    })
}

pub(crate) async fn handle_library_download_bytes_runtime(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    uri: &str,
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<LibraryDownloadBytes> {
    if is_webspace_uri(uri) {
        return webspace_download_bytes(data_dir, &registry, uri).await;
    }
    handle_library_download_bytes_with_format(data_dir, principal_id, uri, archive_format)
}

pub(crate) async fn handle_library_download_selection_bytes_runtime(
    data_dir: &Path,
    principal_id: &str,
    uris: &[String],
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<LibraryDownloadBytes> {
    if uris.iter().any(|uri| is_webspace_uri(uri)) {
        bail!("Spaces selections cannot be archived from Library yet");
    }
    handle_library_download_selection_bytes_with_format(
        data_dir,
        principal_id,
        uris,
        archive_format,
    )
}

/// Handle one Library request with Runtime coordination available.
///
/// This bridge keeps publish/share/status content effects Runtime-mediated so
/// Library never gains raw content, Carrier, Kubo/IPFS, or backend authority.
pub async fn handle_object_provider_runtime_request(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    request: &Value,
) -> Value {
    handle_object_provider_runtime_request_with_gateway(
        data_dir,
        registry,
        request,
        None,
        LibraryRequestRoute::UnverifiedCaller,
    )
    .await
}

pub(crate) async fn handle_object_provider_runtime_request_with_gateway(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    request: &Value,
    gateway_authority: Option<(
        &crate::api::gateway::GatewayState,
        &crate::api::gateway::RuntimeWalletAuthority,
    )>,
    route: LibraryRequestRoute,
) -> Value {
    let request = match serde_json::from_value::<ObjectProviderRequest>(request.clone()) {
        Ok(request) => request,
        Err(err) => return provider_error("invalid_request", &err.to_string()),
    };

    let data_dir = data_dir.to_path_buf();
    let marketplace_buy = request.is_marketplace_buy();
    if library_request_touches_webspace(&request) {
        let result = handle_library_webspace_request(&data_dir, &registry, request).await;
        return match result {
            Ok(data) => provider_ok(data),
            Err(err) => provider_error_from("library_error", &err),
        };
    }

    let result = match request {
        ObjectProviderRequest::Publish {
            principal_id,
            uri,
            if_revision,
            protection,
        } => {
            library_publish(
                &data_dir,
                registry,
                &principal_id,
                &uri,
                if_revision.as_deref(),
                protection.map(|protection| *protection),
                gateway_authority,
            )
            .await
        }
        ObjectProviderRequest::PublishProgress { principal_id, uri } => {
            library_publish_progress(&data_dir, &principal_id, &uri)
        }
        ObjectProviderRequest::Unpublish {
            principal_id,
            uri,
            if_revision,
        } => {
            library_unpublish(
                &data_dir,
                registry,
                &principal_id,
                &uri,
                if_revision.as_deref(),
            )
            .await
        }
        ObjectProviderRequest::Repair { principal_id, uri } => {
            library_repair(&data_dir, registry, &principal_id, &uri).await
        }
        request @ (ObjectProviderRequest::ListRuntimeCustody { .. }
        | ObjectProviderRequest::ImportRuntimeCustody { .. }
        | ObjectProviderRequest::DiscardProtection { .. }
        | ObjectProviderRequest::UnfinishedProtections { .. }
        | ObjectProviderRequest::Buy { .. }
        | ObjectProviderRequest::BuyOffer { .. }
        | ObjectProviderRequest::DownloadOwnedCopy { .. }
        | ObjectProviderRequest::OpenViewer { .. }
        | ObjectProviderRequest::ReadViewer { .. }
        | ObjectProviderRequest::CloseViewer { .. }) => {
            handle_runtime_custody_library_request(
                data_dir,
                registry,
                request,
                gateway_authority,
                route,
            )
            .await
        }
        request => handle_library_request_serialized(data_dir, request).await,
    };

    match result {
        Ok(data) => provider_ok(data),
        Err(err) => marketplace_buy_error_from(marketplace_buy, &err),
    }
}

/// A file operation that moves or checks publication records (rename, move,
/// trash, restore, delete) runs under `PUBLICATIONS`, so a publish never
/// writes a record for a file that moved meanwhile.
async fn handle_library_request_serialized(
    data_dir: PathBuf,
    request: ObjectProviderRequest,
) -> anyhow::Result<Value> {
    let touches_records = matches!(
        request,
        ObjectProviderRequest::Rename { .. }
            | ObjectProviderRequest::Move { .. }
            | ObjectProviderRequest::Trash { .. }
            | ObjectProviderRequest::Restore { .. }
            | ObjectProviderRequest::DeletePermanently { .. }
            | ObjectProviderRequest::EmptyTrash { .. }
    );
    let _serialized = match touches_records {
        true => Some(PUBLICATIONS.lock().await),
        false => None,
    };
    tokio::task::spawn_blocking(move || handle_library_request(&data_dir, request))
        .await
        .map_err(|err| anyhow!("object provider task failed: {err}"))
        .and_then(|result| result)
}

async fn handle_library_webspace_request(
    data_dir: &Path,
    registry: &ProviderRegistry,
    request: ObjectProviderRequest,
) -> anyhow::Result<Value> {
    match request {
        ObjectProviderRequest::List { principal_id, uri } => {
            let uri = clean_webspace_uri(uri.as_deref().unwrap_or("localhost://WebSpaces"))?;
            webspace_try_refresh_index_from_adapter(data_dir, registry, &uri).await?;
            let data = webspace_provider_data(
                registry,
                json!({
                    "op": "list",
                    "path": uri,
                    "token": "",
                }),
                "list",
            )
            .await?;
            let entries: Vec<WebSpaceDirEntry> = serde_json::from_value(data)
                .context("webspace-provider list response has invalid entries")?;
            let mut objects = entries
                .into_iter()
                .map(|entry| webspace_entry_object(data_dir, &uri, entry))
                .collect::<anyhow::Result<Vec<_>>>()?;
            if uri == "localhost://WebSpaces" {
                objects.push(localhost_space_pointer_object(data_dir, &principal_id)?);
                sort_spaces_root_objects(&mut objects);
            }
            let object = webspace_stat_object(data_dir, registry, &uri).await?;
            Ok(json!({
                "uri": uri,
                "object": object,
                "objects": objects,
            }))
        }
        ObjectProviderRequest::Stat { uri, .. } => {
            let uri = clean_webspace_uri(&uri)?;
            Ok(json!({
                "object": webspace_stat_object(data_dir, registry, &uri).await?,
            }))
        }
        ObjectProviderRequest::Read { uri, .. } | ObjectProviderRequest::Download { uri, .. } => {
            let uri = clean_webspace_uri(&uri)?;
            let (object, content) = webspace_read_bytes(data_dir, registry, &uri).await?;
            Ok(json!({
                "object": object,
                "encoding": "base64",
                "data": base64::engine::general_purpose::STANDARD.encode(content),
            }))
        }
        ObjectProviderRequest::ArchiveEntries { uri, .. } => {
            let uri = clean_webspace_uri(&uri)?;
            let (object, bytes) = webspace_read_bytes(data_dir, registry, &uri).await?;
            let archive_name = object.name.clone();
            archive_entries_for_object(webspace_archive_object(object), &uri, &archive_name, bytes)
        }
        ObjectProviderRequest::ArchivePreviewEntry {
            uri,
            entry,
            if_revision,
            ..
        } => {
            let uri = clean_webspace_uri(&uri)?;
            let (object, bytes) = webspace_read_bytes(data_dir, registry, &uri).await?;
            check_object_revision(&object, if_revision.as_deref())?;
            let archive_name = object.name.clone();
            archive_preview_entry_for_object(
                data_dir,
                webspace_archive_object(object),
                &uri,
                &archive_name,
                bytes,
                &entry,
            )
        }
        ObjectProviderRequest::ArchiveExtractEntries {
            principal_id,
            uri,
            destination_uri,
            entries,
            conflict_policy,
            if_revision,
            cancel,
        } => {
            let (source_uri, archive_name, bytes) = if is_webspace_uri(uri.as_str()) {
                let uri = clean_webspace_uri(&uri)?;
                let (object, bytes) = webspace_read_bytes(data_dir, registry, &uri).await?;
                check_object_revision(&object, if_revision.as_deref())?;
                let archive_name = object.name.clone();
                (uri, archive_name, bytes)
            } else {
                let target = library_target(data_dir, &principal_id, &uri)?;
                check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
                let archive_name = library_archive_name(&target, "selected extraction")?;
                let bytes = read_library_file_bytes(data_dir, &principal_id, &target)?;
                (target.uri.clone(), archive_name, bytes)
            };
            let request = ArchiveExtractRequest {
                source_uri: &source_uri,
                archive_name: &archive_name,
                destination_uri: &destination_uri,
                entries: &entries,
                conflict_policy: conflict_policy.as_deref(),
                cancel,
            };
            if is_webspace_uri(destination_uri.as_str()) {
                extract_archive_entries_to_webspace_destination(
                    data_dir,
                    registry,
                    &principal_id,
                    bytes,
                    request,
                )
                .await
            } else {
                extract_archive_entries_to_local_destination(
                    data_dir,
                    &principal_id,
                    bytes,
                    request,
                )
            }
        }
        ObjectProviderRequest::Sync { principal_id, uri } => {
            let _ = principal_id;
            let uri = clean_webspace_uri(&uri)?;
            let receipt = webspace_sync_bytes(data_dir, registry, &uri).await?;
            Ok(json!({
                "object": receipt.get("object").cloned().unwrap_or(Value::Null),
                "receipt": receipt,
            }))
        }
        ObjectProviderRequest::Status { uri, .. } => {
            let uri = clean_webspace_uri(&uri)?;
            Ok(json!({
                "object": webspace_stat_object(data_dir, registry, &uri).await?,
                "published": null,
            }))
        }
        ObjectProviderRequest::Write {
            uri,
            data,
            if_revision: _,
            ..
        } => {
            let uri = clean_webspace_uri(&uri)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data.trim())
                .context("library WebSpace write data must be base64")?;
            let receipt = webspace_write_bytes(registry, &uri, &bytes).await?;
            Ok(json!({
                "object": webspace_stat_object(data_dir, registry, &uri).await?,
                "receipt": receipt,
            }))
        }
        ObjectProviderRequest::Mkdir {
            parent_uri, name, ..
        } => {
            let parent_uri = clean_webspace_uri(&parent_uri)?;
            let uri = child_uri(&parent_uri, &name)?;
            let receipt = webspace_mkdir(registry, &uri).await?;
            Ok(json!({
                "object": webspace_stat_object(data_dir, registry, &uri).await?,
                "receipt": receipt,
            }))
        }
        ObjectProviderRequest::DeletePermanently { uri, .. } => {
            let uri = clean_webspace_uri(&uri)?;
            let receipt = webspace_delete_permanently(registry, &uri).await?;
            Ok(json!({
                "deleted_uri": uri,
                "receipt": receipt,
            }))
        }
        _ => Err(anyhow!(
            "Spaces operation is not supported by the current resolver lifecycle model"
        )),
    }
}

fn handle_library_request(
    data_dir: &Path,
    request: ObjectProviderRequest,
) -> anyhow::Result<Value> {
    match request {
        ObjectProviderRequest::DownloadOwnedCopy { .. } => {
            unreachable!("download of an owned copy is handled asynchronously")
        }
        ObjectProviderRequest::Roots { principal_id } => {
            Ok(json!({ "roots": library_roots(data_dir, &principal_id) }))
        }
        ObjectProviderRequest::PublishProgress { principal_id, uri } => {
            library_publish_progress(data_dir, &principal_id, &uri)
        }
        ObjectProviderRequest::List { principal_id, uri } => {
            let root = crate::auth::principal_localhost_root(&principal_id);
            let uri = uri.unwrap_or_else(|| root.clone());
            let target = library_target(data_dir, &principal_id, &uri)?;
            if !target.path.exists() {
                return Ok(json!({ "uri": target.uri, "objects": [] }));
            }
            if !target.path.is_dir() {
                bail!("library list target must be a directory");
            }
            let mut objects = Vec::new();
            for entry in fs::read_dir(&target.path)
                .with_context(|| format!("failed to list {:?}", target.path))?
            {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if target.uri == root && (name == ".AppData" || name == ".Trash") {
                    continue;
                }
                let child_uri = format!("{}/{}", target.uri.trim_end_matches('/'), name);
                objects.push(library_object(data_dir, &principal_id, &child_uri)?);
            }
            objects.sort_by(|a, b| {
                a.kind
                    .cmp(b.kind)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            Ok(json!({ "uri": target.uri, "objects": objects }))
        }
        ObjectProviderRequest::Stat { principal_id, uri } => {
            Ok(json!({ "object": library_object(data_dir, &principal_id, &uri)? }))
        }
        ObjectProviderRequest::Read { principal_id, uri } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            if !target.path.is_file() {
                bail!("library read target must be a file");
            }
            let bytes = read_library_file_bytes(data_dir, &principal_id, &target)?;
            Ok(json!({
                "object": library_object(data_dir, &principal_id, &target.uri)?,
                "encoding": "base64",
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            }))
        }
        ObjectProviderRequest::Download { principal_id, uri } => {
            let (object, filename, bytes) = library_download_object(
                data_dir,
                &principal_id,
                &uri,
                LibraryArchiveFormat::TarGz,
            )?;
            Ok(json!({
                "object": object,
                "encoding": "base64",
                "filename": filename,
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            }))
        }
        ObjectProviderRequest::ExtractArchive {
            principal_id,
            uri,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            let extracted_uri = extract_library_archive(data_dir, &principal_id, &target)?;
            let object = library_object(data_dir, &principal_id, &extracted_uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "extract_archive",
                &extracted_uri,
                json!({
                    "source_uri": target.uri,
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({
                "object": object,
                "source_uri": target.uri,
            }))
        }
        ObjectProviderRequest::ArchiveEntries { principal_id, uri } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            Ok(library_archive_entries(data_dir, &principal_id, &target)?)
        }
        ObjectProviderRequest::ArchivePreviewEntry {
            principal_id,
            uri,
            entry,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            archive_preview_entry(data_dir, &principal_id, &target, &entry)
        }
        ObjectProviderRequest::ArchiveExtractEntries {
            principal_id,
            uri,
            destination_uri,
            entries,
            conflict_policy,
            if_revision,
            cancel,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            extract_library_archive_entries(
                data_dir,
                &principal_id,
                &target,
                &destination_uri,
                &entries,
                conflict_policy.as_deref(),
                cancel,
            )
        }
        ObjectProviderRequest::CompressArchive {
            principal_id,
            uri,
            uris,
            if_revision,
        } => {
            let object = compress_library_archive(
                data_dir,
                &principal_id,
                uri.as_deref(),
                &uris,
                if_revision.as_deref(),
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::Write {
            principal_id,
            uri,
            data,
            mime,
            if_revision,
            create_only,
        } => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data.trim())
                .context("library write data must be base64")?;
            let target = library_target(data_dir, &principal_id, &uri)?;
            if is_trash_uri(&target.localhost_root, &target.uri) {
                bail!("library Trash accepts objects only through delete");
            }
            let object = write_library_file_bytes(
                data_dir,
                &principal_id,
                &target.uri,
                mime.as_deref(),
                if_revision.as_deref(),
                create_only,
                &bytes,
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::Mkdir {
            principal_id,
            parent_uri,
            name,
        } => {
            let parent = library_target(data_dir, &principal_id, &parent_uri)?;
            if parent.path.exists() && !parent.path.is_dir() {
                bail!("library mkdir parent must be a directory");
            }
            if is_trash_uri(&parent.localhost_root, &parent.uri) {
                bail!("library Trash accepts objects only through delete");
            }
            let child_uri = child_uri(&parent.uri, &name)?;
            let child = library_target(data_dir, &principal_id, &child_uri)?;
            StartWalkRule::new(data_dir, &child.localhost_root).folder(&child.uri)?;
            fs::create_dir_all(&child.path)?;
            let object = library_object(data_dir, &principal_id, &child.uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "mkdir",
                &child.uri,
                json!({
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::Rename {
            principal_id,
            uri,
            name,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            if is_trash_uri(&target.localhost_root, &target.uri) {
                bail!("library Trash objects can be restored or deleted permanently");
            }
            let parent_uri = target
                .uri
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .ok_or_else(|| anyhow!("library rename target has no parent"))?;
            let new_uri = child_uri(parent_uri, &name)?;
            move_library_object(data_dir, &principal_id, &target.uri, &new_uri)?;
            let object = library_object(data_dir, &principal_id, &new_uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "rename",
                &new_uri,
                json!({
                    "old_uri": target.uri,
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::Move {
            principal_id,
            uri,
            target_parent_uri,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            let parent = library_target(data_dir, &principal_id, &target_parent_uri)?;
            if parent.path.exists() && !parent.path.is_dir() {
                bail!("library move target parent must be a directory");
            }
            if is_trash_uri(&target.localhost_root, &target.uri)
                || is_trash_uri(&parent.localhost_root, &parent.uri)
            {
                bail!("library Trash objects can be moved only through trash or restore");
            }
            if parent.uri == target.uri || parent.uri.starts_with(&(target.uri.clone() + "/")) {
                bail!("library object cannot be moved inside itself");
            }
            let name = target
                .uri
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow!("library move target has no name"))?;
            let new_uri = unique_child_uri(data_dir, &principal_id, &parent.uri, name)?;
            move_library_object(data_dir, &principal_id, &target.uri, &new_uri)?;
            let object = library_object(data_dir, &principal_id, &new_uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "move",
                &new_uri,
                json!({
                    "old_uri": target.uri,
                    "target_uri": new_uri,
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::Copy {
            principal_id,
            uri,
            target_parent_uri,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            let parent = library_target(data_dir, &principal_id, &target_parent_uri)?;
            if parent.path.exists() && !parent.path.is_dir() {
                bail!("library copy target parent must be a directory");
            }
            if is_trash_uri(&target.localhost_root, &target.uri)
                || is_trash_uri(&parent.localhost_root, &parent.uri)
            {
                bail!("library Trash objects cannot be copied directly");
            }
            if parent.uri == target.uri || parent.uri.starts_with(&(target.uri.clone() + "/")) {
                bail!("library object cannot be copied inside itself");
            }
            let name = target
                .uri
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow!("library copy target has no name"))?;
            let new_uri = unique_child_uri(data_dir, &principal_id, &parent.uri, name)?;
            copy_library_object(data_dir, &principal_id, &target.uri, &new_uri)?;
            let object = library_object(data_dir, &principal_id, &new_uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "copy",
                &new_uri,
                json!({
                    "source_uri": target.uri,
                    "target_uri": new_uri,
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::Trash {
            principal_id,
            uri,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            if is_trash_uri(&target.localhost_root, &target.uri) {
                bail!("library object is already in Trash");
            }
            if is_runtime_private_uri(&target.localhost_root, &target.uri) {
                bail!("runtime-private Library objects cannot be moved to Trash");
            }
            refuse_deleting_published(data_dir, &principal_id, &target.uri)?;
            let name = target
                .uri
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow!("library trash target has no name"))?;
            let trash_root = format!("{}/.Trash", target.localhost_root);
            let trash_uri = unique_child_uri(data_dir, &principal_id, &trash_root, name)?;
            move_library_object(data_dir, &principal_id, &target.uri, &trash_uri)?;
            write_trash_record(
                data_dir,
                &principal_id,
                &LibraryTrashRecord {
                    schema: LIBRARY_TRASH_RECORD_SCHEMA.to_string(),
                    trash_uri: trash_uri.clone(),
                    original_uri: target.uri.clone(),
                    original_name: name.to_string(),
                    trashed_at: now_ts(),
                },
            )?;
            let object = library_object(data_dir, &principal_id, &trash_uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "trash",
                &trash_uri,
                json!({
                    "original_uri": target.uri,
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({
                "object": object,
                "original_uri": target.uri,
            }))
        }
        ObjectProviderRequest::Restore {
            principal_id,
            uri,
            target_uri,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            if !is_trash_child_uri(&target.localhost_root, &target.uri) {
                bail!("library restore target must be in Trash");
            }
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            let trash_record = read_trash_record(data_dir, &principal_id, &target.uri).ok();
            let restore_uri = target_uri
                .as_deref()
                .filter(|uri| !uri.trim().is_empty())
                .map(|uri| clean_library_uri(&target.localhost_root, uri))
                .transpose()?
                .map(Ok)
                .unwrap_or_else(|| {
                    restore_uri_from_trash_record(
                        data_dir,
                        &principal_id,
                        &target,
                        trash_record.as_ref(),
                    )
                })?;
            let restore_target = library_target(data_dir, &principal_id, &restore_uri)?;
            if is_trash_uri(&restore_target.localhost_root, &restore_target.uri) {
                bail!("library restore target cannot be inside Trash");
            }
            move_library_object(data_dir, &principal_id, &target.uri, &restore_target.uri)?;
            remove_trash_record(data_dir, &principal_id, &target.uri)?;
            let object = library_object(data_dir, &principal_id, &restore_target.uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "restore",
                &restore_target.uri,
                json!({
                    "trash_uri": target.uri,
                    "original_uri": trash_record.as_ref().map(|record| record.original_uri.clone()),
                    "object": object.clone(),
                }),
            )?;
            Ok(json!({ "object": object }))
        }
        ObjectProviderRequest::DeletePermanently {
            principal_id,
            uri,
            if_revision,
        } => {
            let target = library_target(data_dir, &principal_id, &uri)?;
            if !is_trash_child_uri(&target.localhost_root, &target.uri) {
                bail!("library delete_permanently target must be in Trash");
            }
            check_revision(data_dir, &principal_id, &target.uri, if_revision.as_deref())?;
            refuse_deleting_published(data_dir, &principal_id, &target.uri)?;
            if target.path.is_dir() {
                fs::remove_dir_all(&target.path)?;
            } else {
                fs::remove_file(&target.path)?;
            }
            remove_trash_record(data_dir, &principal_id, &target.uri)?;
            append_library_event(
                data_dir,
                &principal_id,
                "delete_permanently",
                &target.uri,
                json!({}),
            )?;
            Ok(json!({ "deleted_uri": target.uri }))
        }
        ObjectProviderRequest::EmptyTrash { principal_id } => {
            let root = crate::auth::principal_localhost_root(&principal_id);
            let trash_root = format!("{root}/.Trash");
            let target = library_target(data_dir, &principal_id, &trash_root)?;
            refuse_deleting_published(data_dir, &principal_id, &target.uri)?;
            let mut deleted_uris = Vec::new();
            if target.path.exists() {
                if !target.path.is_dir() {
                    bail!("library Trash root must be a directory");
                }
                for entry in fs::read_dir(&target.path)
                    .with_context(|| format!("failed to list {:?}", target.path))?
                {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().to_string();
                    let child_uri = format!("{}/{}", target.uri, name);
                    let child = library_target(data_dir, &principal_id, &child_uri)?;
                    if child.path.is_dir() {
                        fs::remove_dir_all(&child.path)?;
                    } else {
                        fs::remove_file(&child.path)?;
                    }
                    remove_trash_record(data_dir, &principal_id, &child.uri)?;
                    deleted_uris.push(child.uri);
                }
            }
            let deleted_count = deleted_uris.len();
            append_library_event(
                data_dir,
                &principal_id,
                "empty_trash",
                &target.uri,
                json!({
                    "deleted_count": deleted_uris.len(),
                    "deleted_uris": deleted_uris,
                }),
            )?;
            Ok(json!({ "deleted_count": deleted_count }))
        }
        ObjectProviderRequest::Status { principal_id, uri } => {
            let object = library_object(data_dir, &principal_id, &uri)?;
            let record = read_publish_record(data_dir, &principal_id, &uri).ok();
            Ok(json!({
                "object": object,
                "published": record,
            }))
        }
        ObjectProviderRequest::Sync { principal_id, .. } => {
            let _ = principal_id;
            bail!("library sync is only supported for Spaces objects")
        }
        ObjectProviderRequest::Events {
            principal_id,
            uri,
            since,
            limit,
        } => Ok(json!({
            "schema": "elastos.library.events/v1",
            "events": library_events(data_dir, &principal_id, uri.as_deref(), since, limit)?,
        })),
        ObjectProviderRequest::Share {
            principal_id,
            uri,
            recipients,
            policy,
            key_release_policy,
        } => {
            let object = library_object(data_dir, &principal_id, &uri)?;
            let mut record = read_publish_record(data_dir, &principal_id, &uri)
                .context("library share requires a published object")?;
            if !record_is_published(&record) {
                bail!("library share requires an actively published object");
            }
            if record_is_runtime_custody(&record) {
                bail!(RUNTIME_CUSTODY_SHARE_UNAVAILABLE_MESSAGE);
            }
            let shared_at = now_ts();
            let recipients = normalized_share_recipients(&recipients)?;
            let share_policy = normalized_share_policy(policy.as_deref(), recipients.is_empty())?;
            let key_release = normalized_key_release_policy(key_release_policy.as_deref())?;
            let remote_enforcement = share_remote_enforcement_contract(&share_policy, &key_release);
            record.shared_at = Some(shared_at);
            record.share_policy = Some(share_policy.clone());
            record.share_grants = recipients
                .iter()
                .map(|recipient| {
                    share_grant(
                        recipient,
                        &record.cid,
                        &format!("elastos://{}", record.cid),
                        &share_policy,
                        key_release.clone(),
                        shared_at,
                    )
                })
                .collect();
            write_publish_record(data_dir, &principal_id, &record)?;
            append_library_event(
                data_dir,
                &principal_id,
                "share",
                &uri,
                json!({
                    "cid": record.cid,
                    "policy": share_policy,
                    "key_release": key_release.clone(),
                    "remote_enforcement": remote_enforcement.clone(),
                    "recipients": recipients,
                    "shared_at": record.shared_at,
                }),
            )?;
            Ok(json!({
                "schema": "elastos.library.share/v1",
                "object": library_object(data_dir, &principal_id, &uri)?,
                "uri": format!("elastos://{}", record.cid),
                "cid": record.cid,
                "policy": record.share_policy,
                "content_security": record.content_security,
                "key_release": key_release.clone(),
                "remote_enforcement": remote_enforcement,
                "recipients": recipients,
                "grants": record.share_grants,
                "availability": record.availability,
                "shared_at": record.shared_at,
                "object_uri": object.uri,
            }))
        }
        ObjectProviderRequest::SharedAccess {
            principal_id,
            uri,
            recipient,
            recipient_proof,
        } => {
            let object = library_object(data_dir, &principal_id, &uri)?;
            let record = read_publish_record(data_dir, &principal_id, &uri)
                .context("library shared_access requires a published object")?;
            if !record_is_published(&record) || record.shared_at.is_none() {
                bail!("library shared_access requires an actively shared object");
            }
            if record_is_runtime_custody(&record) {
                bail!(RUNTIME_CUSTODY_SHARE_UNAVAILABLE_MESSAGE);
            }
            let access = match shared_access_receipt(&record, &recipient, recipient_proof.as_ref())
            {
                Ok(access) => access,
                Err(err) => {
                    append_library_event(
                        data_dir,
                        &principal_id,
                        "shared_access",
                        &uri,
                        json!({
                            "cid": record.cid,
                            "recipient": recipient,
                            "policy": record.share_policy,
                            "allowed": false,
                            "reason": err.to_string(),
                        }),
                    )?;
                    return Err(err);
                }
            };
            append_library_event(
                data_dir,
                &principal_id,
                "shared_access",
                &uri,
                json!({
                    "cid": record.cid,
                    "recipient": recipient,
                    "policy": record.share_policy,
                    "allowed": true,
                    "decision": access.get("decision").cloned().unwrap_or(Value::Null),
                    "open": access.get("open").cloned().unwrap_or(Value::Null),
                    "key_release": access.get("key_release").cloned().unwrap_or(Value::Null),
                }),
            )?;
            Ok(json!({
                "schema": "elastos.library.shared-access/v1",
                "object": object,
                "uri": format!("elastos://{}", record.cid),
                "cid": record.cid,
                "access": access,
                "availability": record.availability,
            }))
        }
        ObjectProviderRequest::Publish { .. }
        | ObjectProviderRequest::Unpublish { .. }
        | ObjectProviderRequest::Repair { .. }
        | ObjectProviderRequest::DiscardProtection { .. }
        | ObjectProviderRequest::UnfinishedProtections { .. }
        | ObjectProviderRequest::ListRuntimeCustody { .. }
        | ObjectProviderRequest::ImportRuntimeCustody { .. }
        | ObjectProviderRequest::Buy { .. }
        | ObjectProviderRequest::BuyOffer { .. }
        | ObjectProviderRequest::OpenViewer { .. }
        | ObjectProviderRequest::ReadViewer { .. }
        | ObjectProviderRequest::CloseViewer { .. } => {
            unreachable!("runtime custody library operations are handled asynchronously")
        }
    }
}

async fn handle_runtime_custody_library_request(
    data_dir: PathBuf,
    registry: Arc<ProviderRegistry>,
    request: ObjectProviderRequest,
    gateway_authority: Option<(
        &crate::api::gateway::GatewayState,
        &crate::api::gateway::RuntimeWalletAuthority,
    )>,
    route: LibraryRequestRoute,
) -> anyhow::Result<Value> {
    // Session binding v3 is keyed on `executable_actor`, and only the gateway
    // proxy verifies that field (it discards whatever the client sent and
    // re-inserts the value from the verified home launch token). Refuse the
    // three viewer operations on every other route rather than bind a session
    // to a caller-chosen actor. Note this cannot key off `gateway_authority`:
    // the proxy passes `None` there for viewer ops, since it only builds a
    // Wallet authority for protected `publish`, `buy` and `buy_offer`.
    if matches!(
        request,
        ObjectProviderRequest::OpenViewer { .. }
            | ObjectProviderRequest::ReadViewer { .. }
            | ObjectProviderRequest::CloseViewer { .. }
    ) && route != LibraryRequestRoute::VerifiedGatewayLaunchToken
    {
        anyhow::bail!(RUNTIME_CUSTODY_VIEWER_ROUTE_DENIED_MESSAGE);
    }
    match request {
        ObjectProviderRequest::ListRuntimeCustody { principal_id } => {
            crate::protected_content_runtime::list_runtime_custody_listings(
                &data_dir,
                &principal_id,
            )
        }
        ObjectProviderRequest::DiscardProtection { principal_id, uri } => {
            library_discard_protection(&data_dir, &principal_id, &uri, gateway_authority).await
        }
        ObjectProviderRequest::UnfinishedProtections { principal_id, uri } => {
            library_unfinished_protections(&data_dir, &principal_id, &uri, gateway_authority).await
        }
        ObjectProviderRequest::ImportRuntimeCustody {
            principal_id,
            listing_uri,
        } => {
            crate::protected_content_runtime::import_runtime_custody_listing(
                &data_dir,
                registry,
                &principal_id,
                &listing_uri,
            )
            .await
        }
        ObjectProviderRequest::DownloadOwnedCopy {
            principal_id,
            mint_id,
            item,
        } => {
            let Some((state, authority)) = gateway_authority else {
                anyhow::bail!(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE
                );
            };
            let copy = match (mint_id, item) {
                (Some(mint_id), None) => {
                    crate::protected_content_runtime::RuntimeCustodyOwnedCopy::Mint(mint_id)
                }
                (None, Some(item)) => {
                    crate::protected_content_runtime::RuntimeCustodyOwnedCopy::MarketItem(item)
                }
                _ => anyhow::bail!(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE
                ),
            };
            crate::api::gateway::runtime_custody_download_owned_copy_via_gateway(
                state,
                authority,
                registry,
                crate::protected_content_runtime::RuntimeCustodyDownloadInput {
                    principal_id,
                    copy,
                },
            )
            .await
        }
        ObjectProviderRequest::Buy {
            principal_id,
            mint_id,
        } => {
            let Some((state, authority)) = gateway_authority else {
                anyhow::bail!(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE
                );
            };
            crate::api::gateway::runtime_custody_buy_via_gateway(
                state,
                authority,
                registry,
                crate::protected_content_runtime::RuntimeCustodyBuyInput {
                    principal_id,
                    mint_id,
                },
            )
            .await
        }
        ObjectProviderRequest::BuyOffer {
            principal_id,
            item,
            asset_uri,
            seller,
            agreed,
        } => {
            let Some((state, authority)) = gateway_authority else {
                anyhow::bail!(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE
                );
            };
            crate::api::gateway::runtime_custody_buy_offer_via_gateway(
                state,
                authority,
                registry,
                crate::protected_content_market::RuntimeMarketBuyInput {
                    principal_id,
                    item,
                    asset_uri,
                    seller,
                    agreed,
                },
            )
            .await
        }
        ObjectProviderRequest::OpenViewer {
            principal_id,
            mint_id,
            executable_actor,
            launch_id,
            proof_binding_id,
            session_id,
            grant_id,
        } => {
            crate::protected_content_runtime::open_runtime_custody_viewer(
                &data_dir,
                registry,
                crate::protected_content_runtime::RuntimeCustodyViewerOpenInput {
                    principal_id,
                    mint_id,
                    executable_actor: executable_actor.unwrap_or_default(),
                    launch_id,
                    proof_binding_id,
                    session_id,
                    grant_id,
                },
            )
            .await
        }
        ObjectProviderRequest::ReadViewer {
            principal_id,
            mint_id,
            viewer_session_handle,
            executable_actor,
            launch_id,
            proof_binding_id,
            session_id,
            grant_id,
            segment_index,
            chunk_index,
        } => {
            crate::protected_content_runtime::read_runtime_custody_viewer(
                &data_dir,
                registry,
                &principal_id,
                &mint_id,
                &viewer_session_handle,
                executable_actor.as_deref().unwrap_or_default(),
                launch_id.as_deref(),
                proof_binding_id.as_deref(),
                session_id.as_deref(),
                grant_id.as_deref(),
                segment_index,
                chunk_index,
            )
            .await
        }
        ObjectProviderRequest::CloseViewer {
            principal_id,
            mint_id,
            viewer_session_handle,
            executable_actor,
            launch_id,
            proof_binding_id,
            session_id,
            grant_id,
        } => {
            crate::protected_content_runtime::close_runtime_custody_viewer(
                &data_dir,
                registry,
                &principal_id,
                &mint_id,
                &viewer_session_handle,
                executable_actor.as_deref().unwrap_or_default(),
                launch_id.as_deref(),
                proof_binding_id.as_deref(),
                session_id.as_deref(),
                grant_id.as_deref(),
            )
            .await
        }
        _ => anyhow::bail!("runtime custody library operation is invalid"),
    }
}

/// Start over: set the unfinished attempt to protect one object aside, so
/// protecting it again starts a new attempt with an identity of its own.
///
/// Only an attempt that sent nothing on chain is archived (never deleted), and
/// one with a Wallet approval out only once the decline is confirmed. An
/// attempt whose transaction was sent or mined, or that is listed, is refused
/// with its terms and finished by Resume.
async fn library_discard_protection(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    gateway_authority: Option<(
        &crate::api::gateway::GatewayState,
        &crate::api::gateway::RuntimeWalletAuthority,
    )>,
) -> anyhow::Result<Value> {
    let Some((state, authority)) = gateway_authority else {
        bail!("Runtime custody creator mint requires verified gateway Wallet authority");
    };
    let target = library_target(data_dir, principal_id, uri)?;
    let source_storage = published_source_storage(data_dir, principal_id, &target)?;
    let source = crate::protected_content_runtime::runtime_custody_source_lock(
        data_dir,
        principal_id,
        &target.uri,
        source_storage,
    )?;
    let _source = source.lock().await;
    let outcome = crate::api::gateway::archive_runtime_custody_creator_attempt(
        state,
        authority,
        principal_id,
        &target.uri,
        source_storage,
        crate::protected_content_runtime::RuntimeCustodyAttemptArchiveReason::StartOver,
    )
    .await?;
    // A transaction that was sent or mined keeps its attempt: Resume, not
    // Start over.
    if let Some(refusal) = outcome.kept_refusal(None) {
        return Err(refusal);
    }
    let archived = match outcome {
        crate::api::gateway::RuntimeCustodyAttemptArchiveOutcome::Archived(archived) => {
            Some(archived)
        }
        _ => None,
    };
    Ok(json!({
        "schema": "elastos.library.protection-discarded/v1",
        "uri": target.uri,
        "discarded": archived.is_some(),
        // Which attempt was set aside; the next protect is a new one.
        "archived_attempt": archived.as_ref().map(|archived| archived.attempt()),
    }))
}

/// How many entries of one folder a single look for unfinished mints reads.
/// Creator's folder holds what a person protected by hand; past this the rest
/// waits for the next open rather than making one open slow.
const UNFINISHED_PROTECTIONS_MAX_ENTRIES: usize = 512;

/// The unfinished mints of the files directly in one folder.
///
/// Each one is classified by the single rule in
/// `RuntimeCustodyUnfinishedMintStage::recoverable`: a recoverable attempt is
/// listed for the creator to resume or start over, an unrecoverable one is
/// archived here without asking, and a finished one is not mentioned. One
/// object that cannot be read is skipped rather than failing the whole answer.
async fn library_unfinished_protections(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    gateway_authority: Option<(
        &crate::api::gateway::GatewayState,
        &crate::api::gateway::RuntimeWalletAuthority,
    )>,
) -> anyhow::Result<Value> {
    let Some((state, authority)) = gateway_authority else {
        bail!("Runtime custody creator mint requires verified gateway Wallet authority");
    };
    let folder = library_target(data_dir, principal_id, uri)?;
    // An archive a crash interrupted is finished before anything is classified.
    if let Err(error) = crate::protected_content_runtime::runtime_mint_journal(data_dir)
        .finish_interrupted_archives()
    {
        tracing::warn!(error = ?error, "runtime custody creator mint: an interrupted archive could not be finished");
    }
    let mut unfinished = Vec::new();
    let mut archived = 0usize;
    if folder.path.is_dir() {
        let mut names = fs::read_dir(&folder.path)
            .with_context(|| format!("failed to list {:?}", folder.path))?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        names.sort();
        names.truncate(UNFINISHED_PROTECTIONS_MAX_ENTRIES);
        for name in names {
            let object_uri = format!("{}/{}", folder.uri.trim_end_matches('/'), name);
            // A finished publish is answered from the Library's own record,
            // without reading the mint journal at all.
            if read_publish_record(data_dir, principal_id, &object_uri)
                .is_ok_and(|record| record.listing_uri.is_some())
            {
                continue;
            }
            let outcome = match library_target(data_dir, principal_id, &object_uri)
                .and_then(|target| published_source_storage(data_dir, principal_id, &target))
            {
                Ok(source_storage) => {
                    match crate::protected_content_runtime::runtime_custody_source_lock(
                        data_dir,
                        principal_id,
                        &object_uri,
                        source_storage,
                    ) {
                        // A file whose publish is running right now is in
                        // progress, not unfinished.
                        Ok(source) => match source.try_lock() {
                            Ok(_source) => {
                                crate::api::gateway::runtime_custody_unfinished_mint_via_gateway(
                                    state,
                                    authority,
                                    principal_id,
                                    &object_uri,
                                    source_storage,
                                )
                                .await
                            }
                            Err(_) => continue,
                        },
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            };
            match outcome {
                Ok(crate::api::gateway::RuntimeCustodyUnfinishedMintOutcome::Unfinished(
                    mut entry,
                )) => {
                    entry["uri"] = json!(object_uri);
                    entry["name"] = json!(name);
                    unfinished.push(entry);
                }
                Ok(crate::api::gateway::RuntimeCustodyUnfinishedMintOutcome::Archived) => {
                    archived += 1;
                }
                Ok(crate::api::gateway::RuntimeCustodyUnfinishedMintOutcome::Nothing) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "runtime custody creator mint: skipped an object whose mint could not be read"
                    );
                }
            }
        }
    }
    Ok(json!({
        "schema": "elastos.library.unfinished-protections/v1",
        "uri": folder.uri,
        "unfinished": unfinished,
        "archived": archived,
    }))
}

/// Bind the creator's account and run one runtime-custody publish of `target`:
/// protect, escrow, publish, then the creator tail.
#[allow(
    clippy::too_many_arguments,
    reason = "one publish binds the target, its type, its terms and where they come from"
)]
async fn run_runtime_custody_publish(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    (state, authority): (
        &crate::api::gateway::GatewayState,
        &crate::api::gateway::RuntimeWalletAuthority,
    ),
    principal_id: &str,
    target: &LibraryTarget,
    content_type: &str,
    loaded: &LoadedRuntimeCustodyPublishInput,
    terms_source: crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource,
    source_storage: &str,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    // Plan B S7-lite T7.6: a Home with no pool to mint into is told so
    // before any media is processed.
    crate::protected_content_runtime::load_runtime_custody_mint_pool(
        data_dir,
        Arc::clone(&registry),
        loaded.pool_did.as_deref(),
        Some((principal_id, &target.uri, source_storage)),
    )?;
    let creator_binding = crate::api::gateway::resolve_runtime_custody_creator_publish_binding(
        state,
        authority,
        principal_id,
        &target.uri,
        source_storage,
    )
    .await?;
    // Video/audio keep the existing media-provider transcode path
    // unchanged (D5: audio also transcodes to fMP4). Every other type
    // takes the EPC1 object path, which now runs the SAME creator tail
    // (chain mint, metadata document, portable listing) so an object mint
    // can be bought and opened exactly like a media one.
    if content_type.starts_with("video/") || content_type.starts_with("audio/") {
        let runtime_input = crate::protected_content_runtime::RuntimeCustodyLibrarySourceInput {
            object_uri: target.uri.clone(),
            principal_id: principal_id.to_string(),
            source_file_path: target.path.clone(),
            wallet_account_id: creator_binding.account_id,
            wallet_account_address: creator_binding.address,
            creator_mint_source_digest: creator_binding.source_digest,
            copies: loaded.copies.clone(),
            price: loaded.price.clone(),
            channel: loaded.channel.clone(),
            pay_token: loaded.pay_token.clone(),
            listing: loaded.listing.clone(),
            source_storage: source_storage.to_string(),
            pool_did: loaded.pool_did.clone(),
        };
        crate::api::gateway::runtime_custody_publish_via_gateway(
            state,
            authority,
            registry,
            runtime_input,
            terms_source,
        )
        .await
    } else {
        let clear_plaintext = crate::protected_content_runtime::read_runtime_object_source(
            data_dir,
            principal_id,
            &target.uri,
            &target.path,
        )?;
        let runtime_input =
            crate::protected_content_runtime::RuntimeCustodyLibraryPublishObjectInput {
                object_uri: target.uri.clone(),
                principal_id: principal_id.to_string(),
                content_type: content_type.to_string(),
                wallet_account_id: creator_binding.account_id,
                wallet_account_address: creator_binding.address,
                creator_mint_source_digest: creator_binding.source_digest,
                copies: loaded.copies.clone(),
                price: loaded.price.clone(),
                channel: loaded.channel.clone(),
                pay_token: loaded.pay_token.clone(),
                listing: loaded.listing.clone(),
                clear_plaintext,
                source_storage: source_storage.to_string(),
                pool_did: loaded.pool_did.clone(),
            };

        crate::api::gateway::runtime_custody_publish_object_via_gateway(
            state,
            authority,
            registry,
            runtime_input,
            terms_source,
        )
        .await
    }
}

async fn library_publish(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    uri: &str,
    if_revision: Option<&str>,
    protection: Option<LibraryPublishProtectionRequest>,
    gateway_authority: Option<(
        &crate::api::gateway::GatewayState,
        &crate::api::gateway::RuntimeWalletAuthority,
    )>,
) -> anyhow::Result<Value> {
    let target = library_target(data_dir, principal_id, uri)?;
    if let Some(protection) = protection {
        check_revision(data_dir, principal_id, &target.uri, if_revision)?;
        anyhow::ensure!(
            crate::protected_content_runtime::protected_content_enabled(data_dir),
            "protected content is not available in this release"
        );
        let (loaded, terms_source) = match protection {
            LibraryPublishProtectionRequest::RuntimeCustodyResume {} => (
                resumed_runtime_custody_publish_input(data_dir, principal_id, &target)?,
                crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource::Recorded,
            ),
            protection => (
                validate_runtime_custody_publish_input(
                    data_dir,
                    principal_id,
                    &target,
                    protection,
                )?,
                crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource::Requested,
            ),
        };
        let filename = target
            .uri
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("object.bin");
        let content_type = mime_for_name(filename);
        // Fail closed on an unrecognised type, before any Wallet or custody
        // work. `mime_for_name` returns `application/octet-stream` for
        // everything its table does not know, and minting that as an EPC1
        // object would produce content nothing can open (the object open/read
        // path is deferred) while also burning the source's `same_authority_as`
        // shape, so a later retry as media would be refused as "conflicts with
        // existing authority". A clear refusal before any mint is the only safe
        // answer until object open lands.
        //
        // This refusal set has exactly one member, and Library's "Protect and
        // List" predicate depends on that: it decides whether to offer the
        // action by testing the object's type against this same one value
        // rather than restating the `mime_for_name` table, so that a new
        // extension added above needs no capsule change. Adding a SECOND
        // refused type here therefore silently makes Library offer an action
        // this function will reject. If that ever happens, widen
        // `isRuntimeCustodyProtectable` in
        // `capsules/library/browser/src/model.js` in the same change.
        if content_type == "application/octet-stream" {
            anyhow::bail!(RUNTIME_CUSTODY_PUBLISH_UNSUPPORTED_TYPE_MESSAGE);
        }
        let source_storage = published_source_storage(data_dir, principal_id, &target)?.to_string();
        let Some((state, authority)) = gateway_authority else {
            anyhow::bail!(
                "Runtime custody creator mint requires verified gateway Wallet authority"
            );
        };
        // A new mint of a file never waits on an earlier attempt at it: Creator
        // asks for one explicitly, and whatever attempt is unfinished is set
        // aside first so this one starts with an identity of its own.
        // One publish of a source at a time, and never beside a Start over of
        // it: a request still running after a reload must not write into an
        // attempt that is being moved aside.
        let source = crate::protected_content_runtime::runtime_custody_source_lock(
            data_dir,
            principal_id,
            &target.uri,
            &source_storage,
        )?;
        let _source = source.lock().await;
        // An attempt that was sent or mined is not set aside: the publish goes
        // on, and the tail refuses other terms against it, naming them.
        // Boxed: the custody futures are large, and a plain publish shares
        // this function's state machine.
        if loaded.new_attempt {
            Box::pin(crate::api::gateway::archive_runtime_custody_creator_attempt(
                state,
                authority,
                principal_id,
                &target.uri,
                &source_storage,
                crate::protected_content_runtime::RuntimeCustodyAttemptArchiveReason::NewAttempt,
            ))
            .await?;
        }
        let publish = || {
            Box::pin(run_runtime_custody_publish(
                data_dir,
                Arc::clone(&registry),
                (state, authority),
                principal_id,
                &target,
                content_type,
                &loaded,
                terms_source,
                &source_storage,
            ))
        };
        let facts = match publish().await {
            // The earlier attempt met other terms and was set aside; this
            // publish runs again as the new attempt it now is.
            Err(error)
                if error
                    .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorAttemptArchived>()
                    .is_some() =>
            {
                publish().await
            }
            result => result,
        };
        let facts = match facts {
            Ok(facts) => facts,
            Err(mut error) => {
                // A fail-closed refusal is answered by Start over only when
                // Start over could set the attempt aside.
                if let Some(conflict) = error
                    .downcast_mut::<crate::protected_content_runtime::RuntimeCustodyAttemptConflict>()
                {
                    if conflict.answered_by_start_over() {
                        conflict.set_can_start_over(
                            crate::api::gateway::runtime_custody_attempt_may_start_over(
                                state,
                                authority,
                                principal_id,
                                &target.uri,
                                &source_storage,
                            )
                            .await,
                        );
                    }
                }
                return Err(error);
            }
        };
        let record = LibraryPublishRecord {
            schema: "elastos.library.publish-record/v1".to_string(),
            object_uri: target.uri.clone(),
            cid: facts.content_cid.clone(),
            published_at: now_ts(),
            unpublished_at: None,
            shared_at: None,
            share_policy: None,
            share_grants: Vec::new(),
            content_security: facts.content_security,
            receipt: facts.receipt,
            availability: facts.availability,
            listing_uri: facts.listing_uri,
            revision: None,
            publication_id: None,
            size_bytes: None,
        };
        write_publish_record(data_dir, principal_id, &record)?;
        // The capsule the tail filed for this mint is the openable item, so it
        // is what the publish answers with. The source keeps its own record --
        // which is what stops the Library offering to mint the same bytes a
        // second time -- and stays exactly where the creator put it.
        let capsule_uri = facts.capsule_uri.clone();
        let object = library_object(
            data_dir,
            principal_id,
            capsule_uri.as_deref().unwrap_or(&target.uri),
        )?;
        append_library_event(
            data_dir,
            principal_id,
            "publish",
            &target.uri,
            json!({
                "cid": facts.content_cid,
                "content_id": facts.content_id,
                "mint_id": hex::encode(facts.mint_id.as_bytes()),
                "capsule_uri": capsule_uri,
                "listing_uri": record.listing_uri,
                "availability": record.availability,
                "object": object,
            }),
        )?;
        return Ok(json!({
            "object": object,
            "uri": format!("elastos://{}", record.cid),
            "cid": record.cid,
            "receipt": record.receipt,
            "availability": record.availability,
            "content_security": record.content_security,
            "listing_uri": record.listing_uri,
            "published_at": record.published_at,
        }));
    }
    Ok(
        publish_plain_library_file(data_dir, &registry, principal_id, &target, if_revision)
            .await?
            .data,
    )
}

/// Library Publish and Chat attach share one size cap. An unencrypted file is
/// refused from its size before it is read. An encrypted file's plaintext size
/// is known only once it is decrypted, so its read is bounded by the size an
/// 8 MiB file takes on disk (about 10.7 MiB) and the exact cap is checked
/// right after.
pub(crate) const LIBRARY_PUBLISH_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// The most a file within the cap takes on disk: an encrypted Library file is
/// a small JSON envelope around its base64 AES-GCM ciphertext and 16-byte tag.
const LIBRARY_PUBLISH_MAX_STORED_BYTES: u64 =
    (LIBRARY_PUBLISH_MAX_BYTES + 16).div_ceil(3) * 4 + 64 * 1024;
const PUBLISH_UNAVAILABLE: &str = "Publishing isn't available right now. Try again.";
const PUBLISH_CHANGED_SINCE_PUBLISH: &str =
    "This file changed after it was published. Unpublish it first, then publish it again.";
const PUBLISH_NOT_ALLOWED_HERE: &str = "Only files in your Library places can be published.";
const LIBRARY_RUNTIME_DIR: &str = ".AppData/LocalHost/.Runtime/Library";

/// One Library file published publicly: the Library publish response, and the
/// name, size and CID a Chat post shows.
pub(crate) struct LibraryFilePublication {
    pub(crate) data: Value,
    pub(crate) cid: String,
    pub(crate) name: String,
    pub(crate) size_bytes: u64,
    publication_id: String,
}

/// One lock for every publication record on this Home: publish, unpublish,
/// repair, Chat attach, and the rename, move and delete steps that move or
/// check records never interleave, whoever makes them. A record therefore
/// always follows its file, and the published-CID index always matches the
/// records.
static PUBLICATIONS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The one Library publish operation, shared by Library Publish and Chat
/// attach: a file in one of the principal's Library places is pinned on this
/// Home only and recorded with the revision it shares. A new record takes
/// `publication_id` when given. Caller holds `PUBLICATIONS`.
async fn publish_library_uri_locked(
    data_dir: &Path,
    registry: &ProviderRegistry,
    principal_id: &str,
    uri: &str,
    if_revision: Option<&str>,
    publication_id: Option<String>,
) -> anyhow::Result<LibraryFilePublication> {
    if !uri.trim().starts_with("localhost://") {
        return Err(library_unsupported(
            "not_allowed_here",
            PUBLISH_NOT_ALLOWED_HERE,
        ));
    }
    let target = library_target(data_dir, principal_id, uri)?;
    publish_plain_locked(
        data_dir,
        registry,
        principal_id,
        &target,
        if_revision,
        publication_id,
    )
    .await
}

async fn publish_plain_library_file(
    data_dir: &Path,
    registry: &ProviderRegistry,
    principal_id: &str,
    target: &LibraryTarget,
    if_revision: Option<&str>,
) -> anyhow::Result<LibraryFilePublication> {
    let _serialized = PUBLICATIONS.lock().await;
    publish_plain_locked(data_dir, registry, principal_id, target, if_revision, None).await
}

async fn publish_plain_locked(
    data_dir: &Path,
    registry: &ProviderRegistry,
    principal_id: &str,
    target: &LibraryTarget,
    if_revision: Option<&str>,
    publication_id: Option<String>,
) -> anyhow::Result<LibraryFilePublication> {
    let (bytes, revision) = read_publish_source(data_dir, principal_id, target, if_revision)?;
    let name = target
        .uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("object.bin")
        .to_string();
    let size_bytes = bytes.len() as u64;
    if let Some(record) = read_publish_record(data_dir, principal_id, &target.uri)
        .ok()
        .filter(record_is_published)
    {
        if record_is_runtime_custody(&record) {
            return Err(library_unsupported(
                "protected",
                "This file is protected. Unpublish it first.",
            ));
        }
        if record.revision.as_deref() != Some(revision.as_str()) {
            return Err(library_refusal(
                "changed_since_publish",
                PUBLISH_CHANGED_SINCE_PUBLISH,
            ));
        }
        let object = library_object(data_dir, principal_id, &target.uri)?;
        return Ok(LibraryFilePublication {
            data: publication_response(&record, object),
            publication_id: record_publication_id(&record),
            cid: record.cid,
            name,
            size_bytes,
        });
    }
    let publication_id = publication_id.unwrap_or_else(|| hex::encode(rand::random::<[u8; 16]>()));
    // Pin first, then record. Peers are served only CIDs an active record
    // lists, so a crash in between leaves a pinned CID that is not served,
    // even when the same bytes were published and withdrawn before.
    let publish_request = json!({
        "op": "publish",
        "kind": "file",
        "filename": name,
        "mime": mime_for_name(&name),
        "data": base64::engine::general_purpose::STANDARD.encode(&bytes),
        "pin": true,
        "availability_policy": crate::content::LOCAL_PIN_AVAILABILITY_POLICY,
        "publisher_did": principal_id,
    });
    drop(bytes);
    let response = registry.send_raw("content", &publish_request).await;
    drop(publish_request);
    let data = match response {
        Ok(response) if response.get("status").and_then(Value::as_str) != Some("error") => {
            response.get("data").cloned()
        }
        Ok(response) => {
            tracing::warn!(response = %response, "library publish: content publish refused");
            None
        }
        Err(err) => {
            tracing::warn!(error = %err, "library publish: content provider unavailable");
            None
        }
    };
    let Some((data, cid)) = data.and_then(|data| {
        let cid = data
            .get("cid")
            .and_then(Value::as_str)
            .filter(|cid| !cid.trim().is_empty())?
            .to_string();
        Some((data, cid))
    }) else {
        return Err(library_refusal("unavailable", PUBLISH_UNAVAILABLE));
    };
    let receipt = data
        .get("receipt")
        .cloned()
        .unwrap_or_else(|| json!({"status": "not_provided"}));
    let availability = data
        .get("availability")
        .cloned()
        .unwrap_or_else(|| json!({"status": "unknown"}));
    let content_security = published_content_security(data_dir, principal_id, target)?;
    let record = LibraryPublishRecord {
        schema: "elastos.library.publish-record/v1".to_string(),
        object_uri: target.uri.clone(),
        cid: cid.clone(),
        published_at: now_ts(),
        unpublished_at: None,
        shared_at: None,
        share_policy: None,
        share_grants: Vec::new(),
        content_security,
        receipt,
        availability,
        listing_uri: None,
        revision: Some(revision),
        publication_id: Some(publication_id.clone()),
        size_bytes: Some(size_bytes),
    };
    write_publish_record(data_dir, principal_id, &record)?;
    let object = library_object(data_dir, principal_id, &target.uri)?;
    append_library_event(
        data_dir,
        principal_id,
        "publish",
        &target.uri,
        json!({
            "cid": cid,
            "availability": record.availability,
            "object": object,
        }),
    )?;
    Ok(LibraryFilePublication {
        data: publication_response(&record, object),
        cid,
        name,
        size_bytes,
        publication_id,
    })
}

fn publication_response(record: &LibraryPublishRecord, object: LibraryObject) -> Value {
    json!({
        "object": object,
        "uri": format!("elastos://{}", record.cid),
        "cid": record.cid,
        "receipt": record.receipt,
        "availability": record.availability,
        "content_security": record.content_security,
        "published_at": record.published_at,
    })
}

/// Whether `uri` is in one of the person's visible Library places: under
/// their own root, with no hidden or system folder (`.AppData`, `.Trash`, any
/// segment starting with a dot) on the way.
fn is_publishable_place(localhost_root: &str, uri: &str) -> bool {
    uri.strip_prefix(localhost_root)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|rest| {
            rest.split('/')
                .all(|segment| !segment.is_empty() && !segment.starts_with('.'))
        })
}

/// The file about to be published and its revision, refused in plain words
/// before any oversized read, and when its revision is stale.
fn read_publish_source(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    if_revision: Option<&str>,
) -> anyhow::Result<(Vec<u8>, String)> {
    if !is_publishable_place(&target.localhost_root, &target.uri) {
        return Err(library_unsupported(
            "not_allowed_here",
            PUBLISH_NOT_ALLOWED_HERE,
        ));
    }
    if crate::auth::ensure_no_symlink_components(data_dir, &target.path).is_err() {
        return Err(library_unsupported(
            "not_allowed_here",
            "Links and files in linked folders can't be published.",
        ));
    }
    let metadata = match fs::symlink_metadata(&target.path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(library_refusal(
                "not_found",
                "This file is no longer in your Library.",
            ));
        }
        Err(err) => return Err(err.into()),
    };
    if metadata.is_dir() {
        return Err(library_unsupported("folder", "Folders can't be published."));
    }
    if !metadata.is_file() {
        return Err(library_unsupported(
            "not_allowed_here",
            "Only files can be published.",
        ));
    }
    if metadata.len() > LIBRARY_PUBLISH_MAX_STORED_BYTES {
        return Err(library_refusal(
            "too_large",
            "This file is too large to publish.",
        ));
    }
    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    let revision = format!("rev:{}", hex::encode(Sha256::digest(&bytes)));
    if if_revision.is_some_and(|expected| !expected.trim().is_empty() && expected != revision) {
        return Err(library_refusal(
            "stale_revision",
            "This file changed. Reload and try again.",
        ));
    }
    if bytes.len() as u64 > LIBRARY_PUBLISH_MAX_BYTES {
        return Err(library_refusal(
            "too_large",
            "This file is too large to publish.",
        ));
    }
    if bytes.is_empty() {
        return Err(library_refusal(
            "empty_file",
            "Empty files can't be published.",
        ));
    }
    Ok((bytes, revision))
}

fn record_publication_id(record: &LibraryPublishRecord) -> String {
    record
        .publication_id
        .clone()
        .unwrap_or_else(|| format!("legacy-{}-{}", record.published_at, record.cid))
}

fn remove_runtime_file(data_dir: &Path, uri: &str) -> anyhow::Result<()> {
    let path =
        rooted_localhost_fs_path(data_dir, uri).ok_or_else(|| anyhow!("invalid Library path"))?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn write_runtime_json(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let path =
        rooted_localhost_fs_path(data_dir, uri).ok_or_else(|| anyhow!("invalid Library path"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::auth::write_principal_root_object(
        data_dir,
        principal_id,
        &root,
        uri,
        &path,
        &serde_json::to_vec_pretty(value)?,
    )
}

fn read_runtime_json<T: serde::de::DeserializeOwned>(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
) -> anyhow::Result<T> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let path =
        rooted_localhost_fs_path(data_dir, uri).ok_or_else(|| anyhow!("invalid Library path"))?;
    let bytes = crate::auth::read_principal_root_object(data_dir, principal_id, &root, uri, &path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Every readable `.json` entry of one Runtime Library folder.
fn read_runtime_json_dir<T: serde::de::DeserializeOwned>(
    data_dir: &Path,
    principal_id: &str,
    dir_uri: &str,
) -> Vec<T> {
    let Some(dir) = rooted_localhost_fs_path(data_dir, dir_uri) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.ends_with(".json"))
        .filter_map(|name| {
            read_runtime_json(data_dir, principal_id, &format!("{dir_uri}/{name}")).ok()
        })
        .collect()
}

/// Every publish record of this person, active or not.
fn publish_records(data_dir: &Path, principal_id: &str) -> Vec<LibraryPublishRecord> {
    let root = crate::auth::principal_localhost_root(principal_id);
    read_runtime_json_dir::<LibraryPublishRecord>(
        data_dir,
        principal_id,
        &format!("{root}/{LIBRARY_RUNTIME_DIR}/Published"),
    )
}

/// Every plain (not protected) publish record of this person, active or not.
fn plain_publish_records(data_dir: &Path, principal_id: &str) -> Vec<LibraryPublishRecord> {
    publish_records(data_dir, principal_id)
        .into_iter()
        .filter(|record| !record_is_runtime_custody(record))
        .collect()
}

/// One Chat attach request, saved before anything is published: its
/// `request_id` stays bound to this file and to the publication id it
/// publishes under (or the publication it reused).
#[derive(Serialize, Deserialize)]
struct ChatAttachBinding {
    schema: String,
    request_id: String,
    uri: String,
    #[serde(default)]
    if_revision: Option<String>,
    publication_id: String,
    bound_at: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

fn chat_attach_binding_uri(principal_id: &str, request_id: &str) -> String {
    let root = crate::auth::principal_localhost_root(principal_id);
    let digest = hex::encode(Sha256::digest(request_id.as_bytes()));
    format!("{root}/{LIBRARY_RUNTIME_DIR}/ChatAttach/{digest}.json")
}

/// The publication for one Chat attach request, under the publications lock
/// from the first look at its binding to the last write:
/// - the same `request_id` with another file or revision is refused before
///   anything happens;
/// - the request is bound to its file and to a publication id before
///   anything is published, so a retry always finds what it made;
/// - a publication made or reused by this request is posted as it was,
///   wherever the file is now, and one withdrawn since answers `withdrawn`
///   and is never published again;
/// - a new request passes `check_send_allowed` (the send rate limit) first.
pub(crate) async fn chat_attach_publication(
    data_dir: &Path,
    registry: &ProviderRegistry,
    principal_id: &str,
    request_id: &str,
    uri: &str,
    if_revision: Option<&str>,
    check_send_allowed: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<LibraryFilePublication> {
    let _serialized = PUBLICATIONS.lock().await;
    let uri = uri.trim();
    let binding_uri = chat_attach_binding_uri(principal_id, request_id);
    let saved = read_runtime_json::<ChatAttachBinding>(data_dir, principal_id, &binding_uri).ok();
    if let Some(mut binding) = saved {
        if binding.uri != uri || binding.if_revision.as_deref() != if_revision {
            return Err(library_refusal(
                "request_id_reused",
                "This request was already used for another file.",
            ));
        }
        let by_id = plain_publish_records(data_dir, principal_id)
            .into_iter()
            .find(|record| record_publication_id(record) == binding.publication_id);
        // Interrupted after reusing the file's existing publication, before
        // its id was saved here: that publication is the one for this file
        // and revision, withdrawn since this request began or still active.
        let reused = || {
            read_publish_record(data_dir, principal_id, &binding.uri)
                .ok()
                .filter(|record| !record_is_runtime_custody(record))
                .filter(|record| {
                    if_revision.is_none_or(|revision| record.revision.as_deref() == Some(revision))
                })
                .filter(|record| {
                    record_is_published(record)
                        || record
                            .unpublished_at
                            .is_some_and(|at| at >= binding.bound_at)
                })
        };
        match by_id.or_else(reused) {
            Some(record) if record_is_published(&record) => {
                let publication_id = record_publication_id(&record);
                if binding.publication_id != publication_id || binding.name.is_none() {
                    binding.publication_id = publication_id.clone();
                    binding.name = binding
                        .name
                        .or_else(|| binding.uri.rsplit('/').next().map(str::to_string));
                    binding.size_bytes = binding.size_bytes.or(record.size_bytes);
                    write_runtime_json(data_dir, principal_id, &binding_uri, &binding)?;
                }
                let object = library_object(data_dir, principal_id, &record.object_uri)?;
                return Ok(LibraryFilePublication {
                    data: publication_response(&record, object),
                    name: binding.name.unwrap_or_default(),
                    size_bytes: binding.size_bytes.unwrap_or_default(),
                    cid: record.cid,
                    publication_id,
                });
            }
            Some(_) => return Err(chat_attach_withdrawn()),
            // Bound, but nothing was recorded: publish as a new request.
            None => {}
        }
    }
    check_send_allowed()?;
    let mut binding = ChatAttachBinding {
        schema: "elastos.library.chat-attach/v1".to_string(),
        request_id: request_id.to_string(),
        uri: uri.to_string(),
        if_revision: if_revision.map(str::to_string),
        publication_id: hex::encode(rand::random::<[u8; 16]>()),
        bound_at: now_ts(),
        name: None,
        size_bytes: None,
    };
    write_runtime_json(data_dir, principal_id, &binding_uri, &binding)?;
    let publication = match publish_library_uri_locked(
        data_dir,
        registry,
        principal_id,
        uri,
        if_revision,
        Some(binding.publication_id.clone()),
    )
    .await
    {
        Ok(publication) => publication,
        Err(err) => {
            // A record this request wrote keeps its binding; otherwise
            // nothing was published and nothing stays bound to this id.
            let recorded = plain_publish_records(data_dir, principal_id)
                .iter()
                .any(|record| record_publication_id(record) == binding.publication_id);
            if !recorded {
                if let Err(unbind) = remove_runtime_file(data_dir, &binding_uri) {
                    tracing::warn!(error = %unbind, "chat attach: binding not removed");
                }
            }
            return Err(err);
        }
    };
    binding.publication_id = publication.publication_id.clone();
    binding.name = Some(publication.name.clone());
    binding.size_bytes = Some(publication.size_bytes);
    write_runtime_json(data_dir, principal_id, &binding_uri, &binding)?;
    Ok(publication)
}

fn chat_attach_withdrawn() -> anyhow::Error {
    library_refusal(
        "withdrawn",
        "This file is no longer shared. Publish it again to post it.",
    )
}

/// What the object list and stat report for an active publication.
fn publication_projection(record: &LibraryPublishRecord) -> Value {
    json!({
        "cid": record.cid,
        "uri": format!("elastos://{}", record.cid),
        "published_at": record.published_at,
        "revision": record.revision,
    })
}

/// A Library refusal with a stable code, an optional reason, and a message
/// that is safe to show.
#[derive(Debug)]
pub(crate) struct LibraryRefusal {
    pub(crate) code: &'static str,
    pub(crate) reason: Option<&'static str>,
    message: &'static str,
}

impl std::fmt::Display for LibraryRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for LibraryRefusal {}

fn library_refusal(code: &'static str, message: &'static str) -> anyhow::Error {
    anyhow::Error::new(LibraryRefusal {
        code,
        reason: None,
        message,
    })
}

/// An `unsupported` refusal; `reason` is `folder`, `protected` or
/// `not_allowed_here`.
fn library_unsupported(reason: &'static str, message: &'static str) -> anyhow::Error {
    anyhow::Error::new(LibraryRefusal {
        code: "unsupported",
        reason: Some(reason),
        message,
    })
}

/// The Library refusal anywhere in `error`'s chain.
pub(crate) fn find_library_refusal(error: &anyhow::Error) -> Option<&LibraryRefusal> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<LibraryRefusal>())
}

async fn library_unpublish(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    uri: &str,
    if_revision: Option<&str>,
) -> anyhow::Result<Value> {
    let _serialized = PUBLICATIONS.lock().await;
    let target = library_target(data_dir, principal_id, uri)?;
    check_revision(data_dir, principal_id, &target.uri, if_revision)?;
    let mut record = read_publish_record(data_dir, principal_id, &target.uri)
        .context("library unpublish requires a published object")?;
    if !record_is_published(&record) {
        bail!("library object is not actively published");
    }
    // Sharing follows the record: once it is withdrawn (and out of the
    // published-CID index), peers are no longer served this CID from here.
    // The pin is only local storage, which other publications, received
    // files or models may share, so a plain Unpublish leaves it in place;
    // removing pins no publication needs is a later cleanup. A protected
    // publication keeps its existing withdrawal, which unpins.
    let data = if record_is_runtime_custody(&record) {
        let response = registry
            .send_raw(
                "content",
                &json!({
                    "op": "unpublish",
                    "cid": record.cid,
                    "object_did": target.uri,
                    "publisher_did": principal_id,
                }),
            )
            .await
            .map_err(|err| anyhow!("content provider unavailable: {err}"))?;
        if response.get("status").and_then(Value::as_str) == Some("error") {
            let message = response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("content unpublish failed");
            bail!("content unpublish failed: {message}");
        }
        response
            .get("data")
            .cloned()
            .ok_or_else(|| anyhow!("content unpublish response missing data"))?
    } else {
        json!({
            "availability": {
                "status": "withdrawn",
                "note": "No longer shared from this Home. Copies others downloaded stay with them.",
            },
        })
    };
    record.unpublished_at = Some(now_ts());
    record.shared_at = None;
    record.receipt = data
        .get("receipt")
        .cloned()
        .unwrap_or_else(|| json!({"status": "not_provided"}));
    record.availability = data
        .get("availability")
        .cloned()
        .unwrap_or_else(|| json!({"status": "local_unpinned"}));
    write_publish_record(data_dir, principal_id, &record)?;
    let object = library_object(data_dir, principal_id, &target.uri)?;
    append_library_event(
        data_dir,
        principal_id,
        "unpublish",
        &target.uri,
        json!({
            "cid": record.cid,
            "availability": record.availability,
            "object": object,
        }),
    )?;
    Ok(json!({
        "object": object,
        "uri": format!("elastos://{}", record.cid),
        "cid": record.cid,
        "receipt": record.receipt,
        "availability": record.availability,
        "unpublished_at": record.unpublished_at,
    }))
}

async fn library_repair(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    uri: &str,
) -> anyhow::Result<Value> {
    let _serialized = PUBLICATIONS.lock().await;
    let target = library_target(data_dir, principal_id, uri)?;
    let mut record = read_publish_record(data_dir, principal_id, &target.uri)
        .context("library repair requires a published object")?;
    let mut request = json!({
        "op": "repair",
        "cid": record.cid,
        "object_did": target.uri,
        "publisher_did": principal_id,
    });
    if !record_is_runtime_custody(&record) {
        // A plain publication stays on this Home: Repair pins it here again.
        request["availability_policy"] =
            Value::String(crate::content::LOCAL_PIN_AVAILABILITY_POLICY.to_string());
    }
    let response = registry
        .send_raw("content", &request)
        .await
        .map_err(|err| anyhow!("content provider unavailable: {err}"))?;
    if response.get("status").and_then(Value::as_str) == Some("error") {
        let message = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("content repair failed");
        bail!("content repair failed: {message}");
    }
    let data = response
        .get("data")
        .cloned()
        .ok_or_else(|| anyhow!("content repair response missing data"))?;
    record.unpublished_at = None;
    record.receipt = data
        .get("receipt")
        .cloned()
        .unwrap_or_else(|| json!({"status": "not_provided"}));
    record.availability = data
        .get("availability")
        .cloned()
        .unwrap_or_else(|| json!({"status": "unknown"}));
    write_publish_record(data_dir, principal_id, &record)?;
    let object = library_object(data_dir, principal_id, &target.uri)?;
    append_library_event(
        data_dir,
        principal_id,
        "repair",
        &target.uri,
        json!({
            "cid": record.cid,
            "availability": record.availability,
            "object": object,
        }),
    )?;
    Ok(json!({
        "object": object,
        "uri": format!("elastos://{}", record.cid),
        "cid": record.cid,
        "receipt": record.receipt,
        "availability": record.availability,
    }))
}

struct LibraryTarget {
    localhost_root: String,
    uri: String,
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct WebSpaceDirEntry {
    name: String,
    is_file: bool,
    is_dir: bool,
    size: u64,
    #[serde(default)]
    target_uri: Option<String>,
    #[serde(default)]
    resolver_state: Option<String>,
    #[serde(default)]
    resolver: Option<String>,
    #[serde(default)]
    cache_policy: Option<String>,
    #[serde(default)]
    sync_policy: Option<String>,
    #[serde(default, rename = "kind")]
    webspace_kind: Option<String>,
    #[serde(default)]
    object_id: Option<String>,
    #[serde(default)]
    head_id: Option<String>,
    #[serde(default)]
    cache_state: Option<String>,
    #[serde(default)]
    sync_state: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    readonly: Option<bool>,
    #[serde(default)]
    access_policy: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebSpaceFileStat {
    path: String,
    is_file: bool,
    is_dir: bool,
    size: u64,
    #[serde(default)]
    modified: Option<u64>,
    #[serde(default)]
    created: Option<u64>,
    #[serde(default)]
    target_uri: Option<String>,
    #[serde(default)]
    resolver_state: Option<String>,
    #[serde(default)]
    resolver: Option<String>,
    #[serde(default)]
    cache_policy: Option<String>,
    #[serde(default)]
    sync_policy: Option<String>,
    #[serde(default, rename = "kind")]
    webspace_kind: Option<String>,
    #[serde(default)]
    object_id: Option<String>,
    #[serde(default)]
    head_id: Option<String>,
    #[serde(default)]
    cache_state: Option<String>,
    #[serde(default)]
    sync_state: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    readonly: Option<bool>,
    #[serde(default)]
    access_policy: Option<String>,
}

async fn webspace_provider_data(
    registry: &ProviderRegistry,
    request: Value,
    op: &str,
) -> anyhow::Result<Value> {
    let response = registry
        .send_raw("webspace", &request)
        .await
        .map_err(|err| anyhow!("webspace-provider unavailable: {err}"))?;
    if response.get("status").and_then(Value::as_str) == Some("error") {
        let code = response
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("webspace_error");
        let message = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("webspace-provider request failed");
        bail!("webspace-provider {op} failed [{code}]: {message}");
    }
    response
        .get("data")
        .cloned()
        .ok_or_else(|| anyhow!("webspace-provider {op} response missing data"))
}

async fn webspace_stat_object(
    data_dir: &Path,
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<LibraryObject> {
    let data = webspace_provider_data(
        registry,
        json!({
            "op": "stat",
            "path": uri,
            "token": "",
        }),
        "stat",
    )
    .await?;
    let stat: WebSpaceFileStat =
        serde_json::from_value(data).context("webspace-provider stat response is invalid")?;
    webspace_stat_to_object(data_dir, uri, stat)
}

async fn webspace_download_bytes(
    data_dir: &Path,
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<LibraryDownloadBytes> {
    let uri = clean_webspace_uri(uri)?;
    let (object, bytes) = webspace_read_bytes(data_dir, registry, &uri).await?;
    Ok(LibraryDownloadBytes {
        filename: object.name,
        mime: object.mime,
        bytes,
    })
}

async fn webspace_read_bytes(
    data_dir: &Path,
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<(LibraryObject, Vec<u8>)> {
    let object = webspace_stat_object(data_dir, registry, uri).await?;
    if object.kind != "file" {
        bail!("library read target must be a file");
    }
    if let Some((object, bytes)) =
        webspace_try_cache_bytes_from_adapter(data_dir, registry, &object).await?
    {
        return Ok((object, bytes));
    }
    let content = webspace_read_provider_bytes(registry, uri).await?;
    Ok((object, content))
}

async fn webspace_sync_bytes(
    data_dir: &Path,
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<Value> {
    let object = webspace_stat_object(data_dir, registry, uri).await?;
    if object.kind != "file" {
        bail!("Spaces byte sync target must be a file");
    }
    if webspace_metadata_str(&object, "sync_state") == Some("manual_pending")
        || (webspace_metadata_bool(&object, "readonly") == Some(false)
            && webspace_metadata_str(&object, "sync_state") != Some("manual_synced"))
    {
        return webspace_sync_mutable_file_to_resolver(data_dir, registry, object).await;
    }
    if webspace_metadata_str(&object, "cache_state") == Some("content_cached")
        || webspace_metadata_str(&object, "webspace_kind") == Some("materialized-file")
    {
        let availability_hint = webspace_object_availability_hint(&object);
        return Ok(json!({
            "schema": "elastos.webspace.byte-sync-receipt/v1",
            "action": "already_content_cached",
            "handle_uri": object.uri,
            "content_synced": true,
            "foreground_read": false,
            "bytes_exposed": false,
            "availability_hint": availability_hint,
            "object": object,
            "note": "Resolver bytes are already present in the provider-owned WebSpace cache."
        }));
    }
    let Some((cached_object, bytes)) =
        webspace_try_cache_bytes_from_adapter(data_dir, registry, &object).await?
    else {
        bail!("Spaces byte sync requires a connected resolver adapter with read_bytes");
    };
    let availability_hint = webspace_object_availability_hint(&cached_object);
    Ok(json!({
        "schema": "elastos.webspace.byte-sync-receipt/v1",
        "action": "bytes_cached_from_adapter",
        "handle_uri": cached_object.uri,
        "content_synced": true,
        "foreground_read": false,
        "bytes_exposed": false,
        "bytes_cached": bytes.len(),
        "availability_hint": availability_hint,
        "object": cached_object,
        "note": "Runtime invoked the resolver adapter and stored bytes in the provider-owned WebSpace cache without returning bytes to the caller."
    }))
}

async fn webspace_sync_mutable_file_to_resolver(
    data_dir: &Path,
    registry: &ProviderRegistry,
    object: LibraryObject,
) -> anyhow::Result<Value> {
    let bytes = webspace_read_provider_bytes(registry, &object.uri).await?;
    let Some(adapter) = webspace_adapter_target(registry, &object).await? else {
        return Ok(webspace_resolver_sync_failed_receipt(
            &object,
            "resolver_write_unavailable",
            "No connected resolver adapter is available for this mutable WebSpace object.",
            None,
            None,
        ));
    };
    if !adapter.capabilities.contains("write_bytes") {
        return Ok(webspace_resolver_sync_failed_receipt(
            &object,
            "resolver_write_unavailable",
            "The connected resolver adapter does not advertise write_bytes.",
            Some(adapter.provider),
            None,
        ));
    }
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: "webspace-provider".to_string(),
            target: adapter.provider.clone(),
            op: "write_bytes".to_string(),
            request: json!({
                "op": "write_bytes",
                "schema": "elastos.webspace.adapter.write-bytes-request/v1",
                "mount": adapter.mount.clone(),
                "resolver": adapter.resolver.clone(),
                "handle_uri": object.uri.clone(),
                "target_uri": adapter.target_uri.clone(),
                "data": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "if_head": webspace_metadata_str(&object, "head_id"),
            }),
            transfer: ProviderTransfer::Bytes,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
        .map_err(|err| anyhow!("WebSpace adapter write_bytes failed: {err}"))?;
    if response.get("status").and_then(Value::as_str) == Some("error") {
        let code = response
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("adapter_write_failed")
            .to_string();
        let message = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("resolver adapter write_bytes failed")
            .to_string();
        return Ok(webspace_resolver_sync_failed_receipt(
            &object,
            if code == "conflict" {
                "resolver_write_conflict"
            } else {
                "resolver_write_failed"
            },
            &message,
            Some(adapter.provider),
            Some(response),
        ));
    }
    let data = response_data_object(&response, "write_bytes")?;
    if data.get("schema").and_then(Value::as_str) != Some("elastos.webspace.adapter.write-bytes/v1")
    {
        bail!("WebSpace adapter write_bytes response schema mismatch");
    }
    let provider_sync_receipt = webspace_provider_data(
        registry,
        json!({
            "op": "sync",
            "path": object.uri.clone(),
            "token": "",
        }),
        "sync",
    )
    .await?;
    let synced_object = webspace_stat_object(data_dir, registry, &object.uri).await?;
    let availability_hint = webspace_object_availability_hint(&synced_object);
    Ok(json!({
        "schema": "elastos.webspace.resolver-sync-receipt/v1",
        "action": "resolver_write_synced",
        "handle_uri": synced_object.uri.clone(),
        "target_uri": adapter.target_uri,
        "resolver": adapter.resolver,
        "provider": adapter.provider,
        "resolver_synced": true,
        "content_synced": true,
        "fail_closed": false,
        "conflict": false,
        "bytes_exposed": false,
        "bytes_synced": bytes.len(),
        "availability_hint": availability_hint,
        "object": synced_object,
        "provider_sync_receipt": provider_sync_receipt,
        "adapter_receipt": data.get("receipt").cloned(),
        "runtime_transfer": response.get("_runtime_transfer").cloned(),
    }))
}

fn webspace_resolver_sync_failed_receipt(
    object: &LibraryObject,
    action: &str,
    message: &str,
    provider: Option<String>,
    adapter_response: Option<Value>,
) -> Value {
    json!({
        "schema": "elastos.webspace.resolver-sync-receipt/v1",
        "action": action,
        "handle_uri": object.uri.clone(),
        "target_uri": webspace_metadata_str(object, "target_uri"),
        "resolver": webspace_metadata_str(object, "resolver"),
        "provider": provider,
        "resolver_synced": false,
        "content_synced": false,
        "fail_closed": true,
        "conflict": action == "resolver_write_conflict",
        "bytes_exposed": false,
        "object": object,
        "adapter_response": adapter_response,
        "message": message,
    })
}

#[derive(Debug)]
struct WebSpaceAdapterTarget {
    mount: String,
    resolver: String,
    target_uri: String,
    provider: String,
    capabilities: BTreeSet<String>,
}

async fn webspace_try_refresh_index_from_adapter(
    data_dir: &Path,
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<()> {
    let object = match webspace_stat_object(data_dir, registry, uri).await {
        Ok(object) => object,
        Err(_) => return Ok(()),
    };
    let Some(adapter) = webspace_adapter_target(registry, &object).await? else {
        return Ok(());
    };
    if !adapter.capabilities.contains("metadata_index") {
        return Ok(());
    }
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: "webspace-provider".to_string(),
            target: adapter.provider.clone(),
            op: "metadata_index".to_string(),
            request: json!({
                "op": "metadata_index",
                "schema": "elastos.webspace.adapter.metadata-index-request/v1",
                "mount": adapter.mount.clone(),
                "resolver": adapter.resolver.clone(),
                "handle_uri": object.uri,
                "target_uri": adapter.target_uri.clone(),
            }),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
        .map_err(|err| anyhow!("WebSpace adapter metadata_index failed: {err}"))?;
    let data = response_data_object(&response, "metadata_index")?;
    if data.get("schema").and_then(Value::as_str)
        != Some("elastos.webspace.adapter.metadata-index/v1")
    {
        bail!("WebSpace adapter metadata_index response schema mismatch");
    }
    let entries = data
        .get("entries")
        .cloned()
        .ok_or_else(|| anyhow!("WebSpace adapter metadata_index response missing entries"))?;
    webspace_provider_data(
        registry,
        json!({
            "op": "refresh",
            "path": format!("localhost://WebSpaces/{}", adapter.mount),
            "entries": entries,
            "token": "",
        }),
        "refresh",
    )
    .await?;
    Ok(())
}

async fn webspace_try_cache_bytes_from_adapter(
    data_dir: &Path,
    registry: &ProviderRegistry,
    object: &LibraryObject,
) -> anyhow::Result<Option<(LibraryObject, Vec<u8>)>> {
    if webspace_metadata_str(object, "cache_state") == Some("content_cached")
        || webspace_metadata_str(object, "webspace_kind") == Some("materialized-file")
    {
        return Ok(None);
    }
    let Some(adapter) = webspace_adapter_target(registry, object).await? else {
        return Ok(None);
    };
    if !adapter.capabilities.contains("read_bytes") {
        return Ok(None);
    }
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: "webspace-provider".to_string(),
            target: adapter.provider.clone(),
            op: "read_bytes".to_string(),
            request: json!({
                "op": "read_bytes",
                "schema": "elastos.webspace.adapter.read-bytes-request/v1",
                "mount": adapter.mount.clone(),
                "resolver": adapter.resolver.clone(),
                "handle_uri": object.uri,
                "target_uri": adapter.target_uri.clone(),
            }),
            transfer: ProviderTransfer::Bytes,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
        .map_err(|err| anyhow!("WebSpace adapter read_bytes failed: {err}"))?;
    let data = response_data_object(&response, "read_bytes")?;
    if data.get("schema").and_then(Value::as_str) != Some("elastos.webspace.adapter.read-bytes/v1")
    {
        bail!("WebSpace adapter read_bytes response schema mismatch");
    }
    let encoded = data
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("WebSpace adapter read_bytes response missing data"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("WebSpace adapter read_bytes response has invalid base64 data")?;
    let mime = data
        .get("mime")
        .and_then(Value::as_str)
        .unwrap_or("application/octet-stream");
    let source_receipt = json!({
        "schema": "elastos.webspace.adapter-cache-source/v1",
        "provider": adapter.provider.clone(),
        "resolver": adapter.resolver.clone(),
        "target_uri": adapter.target_uri.clone(),
        "runtime_transfer": response.get("_runtime_transfer").cloned(),
        "adapter_receipt": data.get("receipt").cloned(),
    });
    webspace_provider_data(
        registry,
        json!({
            "op": "cache",
            "path": object.uri,
            "content": bytes,
            "mime": mime,
            "source_receipt": source_receipt,
            "token": "",
        }),
        "cache",
    )
    .await?;
    let cached_object = webspace_stat_object(data_dir, registry, &object.uri).await?;
    Ok(Some((cached_object, bytes)))
}

async fn webspace_adapter_target(
    registry: &ProviderRegistry,
    object: &LibraryObject,
) -> anyhow::Result<Option<WebSpaceAdapterTarget>> {
    let Some(mount) = webspace_metadata_string(object, "mount") else {
        return Ok(None);
    };
    let Some(resolver) = webspace_metadata_string(object, "resolver") else {
        return Ok(None);
    };
    if resolver == "builtin" {
        return Ok(None);
    }
    let Some(target_uri) = webspace_metadata_string(object, "target_uri") else {
        return Ok(None);
    };
    let health = match webspace_provider_data(
        registry,
        json!({
            "op": "health",
            "moniker": mount.clone(),
            "token": "",
        }),
        "health",
    )
    .await
    {
        Ok(health) => health,
        Err(_) => return Ok(None),
    };
    let adapter = health
        .get("mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|mount_health| {
            mount_health.get("moniker").and_then(Value::as_str)
                == webspace_metadata_str(object, "mount")
        })
        .and_then(|mount_health| mount_health.get("adapter"))
        .and_then(Value::as_object);
    let Some(adapter) = adapter else {
        return Ok(None);
    };
    if adapter.get("live").and_then(Value::as_bool) != Some(true)
        || adapter.get("state").and_then(Value::as_str) != Some("connected")
    {
        return Ok(None);
    }
    let Some(provider) = adapter.get("provider").and_then(Value::as_str) else {
        return Ok(None);
    };
    let capabilities = adapter
        .get("capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    Ok(Some(WebSpaceAdapterTarget {
        mount,
        resolver,
        target_uri,
        provider: provider.to_string(),
        capabilities,
    }))
}

fn response_data_object<'a>(response: &'a Value, op: &str) -> anyhow::Result<&'a Value> {
    if response.get("status").and_then(Value::as_str) == Some("error") {
        let message = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("provider request failed");
        bail!("WebSpace adapter {op} failed: {message}");
    }
    response
        .get("data")
        .ok_or_else(|| anyhow!("WebSpace adapter {op} response missing data"))
}

fn webspace_metadata_string(object: &LibraryObject, key: &str) -> Option<String> {
    webspace_metadata_str(object, key).map(str::to_string)
}

fn webspace_metadata_str<'a>(object: &'a LibraryObject, key: &str) -> Option<&'a str> {
    object
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
}

fn webspace_metadata_bool(object: &LibraryObject, key: &str) -> Option<bool> {
    object
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_bool)
}

async fn webspace_read_provider_bytes(
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<Vec<u8>> {
    let data = webspace_provider_data(
        registry,
        json!({
            "op": "read",
            "path": uri,
            "token": "",
            "offset": null,
            "length": null,
        }),
        "read",
    )
    .await?;
    data.get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("webspace-provider read response missing content"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|byte| *byte <= u8::MAX as u64)
                .map(|byte| byte as u8)
                .ok_or_else(|| anyhow!("webspace-provider read response has invalid byte"))
        })
        .collect()
}

async fn webspace_write_bytes(
    registry: &ProviderRegistry,
    uri: &str,
    bytes: &[u8],
) -> anyhow::Result<Value> {
    webspace_provider_data(
        registry,
        json!({
            "op": "write",
            "path": uri,
            "token": "",
            "content": bytes,
            "append": false,
        }),
        "write",
    )
    .await
}

async fn webspace_mkdir(registry: &ProviderRegistry, uri: &str) -> anyhow::Result<Value> {
    webspace_provider_data(
        registry,
        json!({
            "op": "mkdir",
            "path": uri,
            "token": "",
            "parents": false,
        }),
        "mkdir",
    )
    .await
}

async fn webspace_delete_permanently(
    registry: &ProviderRegistry,
    uri: &str,
) -> anyhow::Result<Value> {
    webspace_provider_data(
        registry,
        json!({
            "op": "delete",
            "path": uri,
            "token": "",
            "recursive": true,
        }),
        "delete",
    )
    .await
}

fn webspace_entry_object(
    data_dir: &Path,
    parent_uri: &str,
    entry: WebSpaceDirEntry,
) -> anyhow::Result<LibraryObject> {
    let uri = child_uri(parent_uri, &entry.name)?;
    webspace_stat_to_object(
        data_dir,
        &uri,
        WebSpaceFileStat {
            path: uri.clone(),
            is_file: entry.is_file,
            is_dir: entry.is_dir,
            size: entry.size,
            modified: None,
            created: None,
            target_uri: entry.target_uri,
            resolver_state: entry.resolver_state,
            resolver: entry.resolver,
            cache_policy: entry.cache_policy,
            sync_policy: entry.sync_policy,
            webspace_kind: entry.webspace_kind,
            object_id: entry.object_id,
            head_id: entry.head_id,
            cache_state: entry.cache_state,
            sync_state: entry.sync_state,
            provider: entry.provider,
            readonly: entry.readonly,
            access_policy: entry.access_policy,
        },
    )
}

fn webspace_stat_to_object(
    data_dir: &Path,
    uri: &str,
    stat: WebSpaceFileStat,
) -> anyhow::Result<LibraryObject> {
    let uri = clean_webspace_uri(uri)?;
    let is_dir = stat.is_dir && !stat.is_file;
    let name = if uri == "localhost://WebSpaces" {
        "Spaces".to_string()
    } else {
        uri.rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("Space")
            .to_string()
    };
    let revision = format!(
        "rev:webspace:{}",
        hex::encode(Sha256::digest(format!(
            "{}:{}:{}",
            stat.path,
            stat.size,
            stat.modified.unwrap_or(0)
        )))
    );
    let metadata = webspace_object_metadata(&uri, &stat);
    let availability = webspace_availability_label(&metadata);
    let readonly = stat.readonly.unwrap_or(true);
    let viewers = if is_dir {
        Vec::new()
    } else {
        viewer_options_for_name(data_dir, &name)
    };
    let viewer = viewers.first().map(|viewer| viewer.id.clone());
    let mime = if is_dir {
        "inode/directory".to_string()
    } else if stat.webspace_kind.as_deref() == Some("file-endpoint") {
        "application/json".to_string()
    } else {
        mime_for_name(&name).to_string()
    };
    let capabilities = if is_dir {
        if readonly {
            vec!["open", "list", "properties"]
        } else {
            vec!["open", "list", "new_folder", "write", "properties"]
        }
    } else if readonly {
        vec!["open", "read", "download", "properties"]
    } else {
        vec![
            "open",
            "read",
            "download",
            "write",
            "delete_permanently",
            "properties",
        ]
    };
    let content_cid = if is_dir {
        None
    } else {
        webspace_content_cid_from_metadata(&metadata)
    };
    Ok(LibraryObject {
        schema: LIBRARY_OBJECT_SCHEMA,
        uri,
        name,
        kind: if is_dir { "directory" } else { "file" },
        mime,
        size: stat.size,
        created_at: stat.created.unwrap_or(0),
        modified_at: stat.modified.unwrap_or(0),
        revision,
        viewer,
        viewers,
        thumbnail_uri: None,
        availability,
        blocked_reason: None,
        content_cid,
        published_cid: None,
        metadata: Some(metadata),
        published: false,
        publication: None,
        shared: false,
        capabilities,
    })
}

fn localhost_space_pointer_object(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<LibraryObject> {
    let uri = crate::auth::principal_localhost_root(principal_id);
    let target = library_target(data_dir, principal_id, &uri)?;
    let metadata = fs::metadata(&target.path).ok();
    let modified_at = metadata
        .as_ref()
        .and_then(|metadata| system_time_secs(metadata.modified().ok()))
        .unwrap_or_else(now_ts);
    let created_at = metadata
        .as_ref()
        .and_then(|metadata| system_time_secs(metadata.created().ok()))
        .unwrap_or(modified_at);
    Ok(LibraryObject {
        schema: LIBRARY_OBJECT_SCHEMA,
        uri: uri.clone(),
        name: "Localhost".to_string(),
        kind: "directory",
        mime: "inode/directory".to_string(),
        size: 0,
        created_at,
        modified_at,
        revision: format!("rev:space:{}", hex::encode(Sha256::digest(uri.as_bytes()))),
        viewer: None,
        viewers: Vec::new(),
        thumbnail_uri: None,
        availability: "local-principal".to_string(),
        blocked_reason: None,
        content_cid: None,
        published_cid: None,
        metadata: Some(json!({
            "schema": "elastos.library.space-pointer/v1",
            "space": "localhost",
            "label": "Localhost",
            "target_uri": uri,
            "provider": "object-provider",
            "authority": "signed-principal-root",
            "writable": true,
            "note": "This opens the signed principal's mutable localhost object space. It is not a broad host filesystem grant."
        })),
        published: false,
        publication: None,
        shared: false,
        capabilities: vec!["open", "list", "properties"],
    })
}

fn sort_spaces_root_objects(objects: &mut [LibraryObject]) {
    objects.sort_by(|left, right| {
        spaces_root_rank(left)
            .cmp(&spaces_root_rank(right))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
}

fn spaces_root_rank(object: &LibraryObject) -> u8 {
    match object.name.as_str() {
        "Localhost" => 0,
        "Elastos" => 1,
        _ => 2,
    }
}

fn webspace_content_cid_from_metadata(metadata: &Value) -> Option<String> {
    metadata
        .get("target_uri")
        .and_then(Value::as_str)
        .and_then(|target| target.strip_prefix("elastos://"))
        .map(str::trim)
        .filter(|cid| cid::Cid::try_from(*cid).is_ok())
        .map(str::to_string)
}

fn webspace_object_metadata(uri: &str, stat: &WebSpaceFileStat) -> Value {
    let mount = uri
        .strip_prefix("localhost://WebSpaces/")
        .and_then(|rest| rest.split('/').next())
        .filter(|segment| !segment.is_empty());
    let target_uri = stat
        .target_uri
        .clone()
        .or_else(|| inferred_webspace_target_uri(uri));
    let mut metadata = json!({
        "schema": "elastos.library.webspace-object/v1",
        "handle_uri": uri,
        "mount": mount,
        "resolver_state": stat.resolver_state.as_deref().unwrap_or("resolved"),
        "resolver": stat.resolver.as_deref().unwrap_or("builtin"),
        "cache_policy": stat.cache_policy.as_deref().unwrap_or("metadata-only"),
        "sync_policy": stat.sync_policy.as_deref().unwrap_or("manual"),
        "cache_state": stat.cache_state.as_deref().unwrap_or("metadata_cached"),
        "sync_state": stat.sync_state.as_deref().unwrap_or("manual_idle"),
        "webspace_kind": stat.webspace_kind.as_deref().unwrap_or("webspace-object"),
        "readonly": stat.readonly.unwrap_or(true),
        "access_policy": stat.access_policy.as_deref().unwrap_or("resolver-readonly"),
        "provider": stat.provider.as_deref().unwrap_or("webspace-provider"),
    });
    if let Some(object_id) = stat.object_id.as_deref() {
        metadata["object_id"] = Value::String(object_id.to_string());
    }
    if let Some(head_id) = stat.head_id.as_deref() {
        metadata["head_id"] = Value::String(head_id.to_string());
    }
    if let Some(target_uri) = target_uri {
        metadata["target_uri"] = Value::String(target_uri);
    }
    if let Some(hint) = webspace_availability_hint(uri, stat, metadata.get("target_uri")) {
        metadata["availability_hint"] = hint;
    }
    metadata
}

fn webspace_availability_hint(
    uri: &str,
    stat: &WebSpaceFileStat,
    target_uri: Option<&Value>,
) -> Option<Value> {
    if !stat.is_file {
        return None;
    }
    let resolver = stat.resolver.as_deref().unwrap_or("builtin");
    if resolver == "builtin" || resolver == "local-materialized" {
        return None;
    }
    let target_uri = target_uri.and_then(Value::as_str)?;
    let webspace_kind = stat.webspace_kind.as_deref().unwrap_or("webspace-object");
    let cache_state = stat.cache_state.as_deref().unwrap_or("metadata_cached");
    let sync_state = stat.sync_state.as_deref().unwrap_or("manual_idle");
    let readonly = stat.readonly.unwrap_or(true);
    let status = if !readonly && sync_state == "manual_synced" {
        "resolver_synced"
    } else if readonly && webspace_kind == "materialized-file" && cache_state == "content_cached" {
        "resolver_cached"
    } else {
        return None;
    };
    Some(json!({
        "schema": "elastos.webspace.availability-hint/v1",
        "scope": "resolver",
        "status": status,
        "handle_uri": uri,
        "target_uri": target_uri,
        "resolver": resolver,
        "cache_state": cache_state,
        "sync_state": sync_state,
        "not_content_availability": true,
        "note": "This is a resolver/cache hint only. It is not a SmartWeb content availability receipt and does not prove CID replication."
    }))
}

fn webspace_availability_label(metadata: &Value) -> String {
    match metadata
        .get("availability_hint")
        .and_then(|hint| hint.get("status"))
        .and_then(Value::as_str)
    {
        Some("resolver_synced") => "resolver-synced",
        Some("resolver_cached") => "resolver-cached",
        _ => "resolver-owned",
    }
    .to_string()
}

fn webspace_object_availability_hint(object: &LibraryObject) -> Option<Value> {
    object
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("availability_hint"))
        .cloned()
}

fn inferred_webspace_target_uri(uri: &str) -> Option<String> {
    let cid = uri.strip_prefix("localhost://WebSpaces/Elastos/content/")?;
    let cid = cid.split('/').next()?.trim();
    if cid.is_empty() {
        None
    } else {
        Some(format!("elastos://{cid}"))
    }
}

fn library_target(data_dir: &Path, principal_id: &str, uri: &str) -> anyhow::Result<LibraryTarget> {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let uri = clean_library_uri(&localhost_root, uri)?;
    let rooted = uri
        .strip_prefix("localhost://")
        .ok_or_else(|| anyhow!("library object URI must be localhost://"))?;
    let path = rooted_localhost_fs_path(data_dir, rooted)
        .ok_or_else(|| anyhow!("invalid library object path"))?;
    Ok(LibraryTarget {
        localhost_root,
        uri,
        path,
    })
}

/// Refuses an object reached through a link anywhere from the data root down
/// to the object itself, so a viewer that opens or saves by URI stays inside
/// the principal's own folders.
pub(crate) fn refuse_linked_library_object(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
) -> anyhow::Result<()> {
    let target = library_target(data_dir, principal_id, uri)?;
    crate::auth::ensure_no_symlink_components(data_dir, &target.path).map_err(|_| {
        anyhow!("This file is a link or is in a linked folder, so it is not viewable in Home.")
    })
}

fn clean_library_uri(localhost_root: &str, uri: &str) -> anyhow::Result<String> {
    let uri = uri.trim().trim_end_matches('/').to_string();
    if !uri.starts_with("localhost://") {
        bail!("library object URI must be localhost://");
    }
    let under_root = uri == localhost_root
        || uri
            .strip_prefix(localhost_root)
            .is_some_and(|rest| rest.starts_with('/'));
    if !under_root {
        bail!("library object URI is outside the active principal root");
    }
    if uri.split('/').any(|part| part == ".." || part == ".") {
        bail!("library object URI must not contain traversal segments");
    }
    Ok(uri)
}

/// The start walk's folder-depth rule for Library writes (#449). Home does
/// not start while a protected folder is 16 or more folders below its root,
/// so Library refuses to create such a file or folder, by write, upload,
/// folder, copy, move, rename, Trash, restore or archive extraction.
struct StartWalkRule {
    localhost_root: String,
    inventory: Vec<crate::auth::PrincipalRootProtectedObjectDeclarationV1>,
}

impl StartWalkRule {
    fn new(data_dir: &Path, localhost_root: &str) -> Self {
        Self {
            localhost_root: localhost_root.to_string(),
            inventory: crate::api::auth_gateway::principal_root_protected_object_inventory(
                data_dir,
                localhost_root,
            ),
        }
    }

    fn file(&self, uri: &str) -> anyhow::Result<()> {
        crate::auth::refuse_principal_root_depth_breach(
            &self.localhost_root,
            &self.inventory,
            uri,
            false,
        )
    }

    fn folder(&self, uri: &str) -> anyhow::Result<()> {
        crate::auth::refuse_principal_root_depth_breach(
            &self.localhost_root,
            &self.inventory,
            uri,
            true,
        )
    }

    /// `from` copied or moved to `to_uri`: every file and folder it holds is
    /// checked before anything is written, so a refused copy or move of
    /// ordinary folders changes nothing. This check does not follow a linked
    /// folder; the writers do, and they check each path again as they create
    /// it, which covers a linked folder's contents and a file added to `from`
    /// after this check (those can stop a copy or move partway).
    fn tree(&self, from: &Path, to_uri: &str) -> anyhow::Result<()> {
        if !fs::symlink_metadata(from)?.is_dir() {
            return self.file(to_uri);
        }
        self.folder(to_uri)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            self.tree(&entry.path(), &format!("{to_uri}/{name}"))?;
        }
        Ok(())
    }
}

fn is_webspace_uri(uri: &str) -> bool {
    uri == "localhost://WebSpaces"
        || uri
            .strip_prefix("localhost://WebSpaces/")
            .is_some_and(|rest| !rest.is_empty())
}

fn clean_webspace_uri(uri: &str) -> anyhow::Result<String> {
    let uri = uri.trim().trim_end_matches('/').to_string();
    if !is_webspace_uri(&uri) {
        bail!("Library Spaces URI must be under localhost://WebSpaces");
    }
    if uri.split('/').any(|part| part == ".." || part == ".") {
        bail!("Library Spaces URI must not contain traversal segments");
    }
    Ok(uri)
}

fn library_request_touches_webspace(request: &ObjectProviderRequest) -> bool {
    fn any_webspace(values: &[&str]) -> bool {
        values
            .iter()
            .any(|value| is_webspace_uri(value.trim_end_matches('/')))
    }

    match request {
        // Named for the same reason `Buy` is: it carries a mint, never a URI,
        // so no WebSpace path can be hiding in it.
        ObjectProviderRequest::DownloadOwnedCopy { .. } => false,
        ObjectProviderRequest::List { uri: Some(uri), .. } => any_webspace(&[uri]),
        ObjectProviderRequest::Stat { uri, .. }
        | ObjectProviderRequest::Read { uri, .. }
        | ObjectProviderRequest::Download { uri, .. }
        | ObjectProviderRequest::ExtractArchive { uri, .. }
        | ObjectProviderRequest::ArchiveEntries { uri, .. }
        | ObjectProviderRequest::ArchivePreviewEntry { uri, .. }
        | ObjectProviderRequest::Write { uri, .. }
        | ObjectProviderRequest::Rename { uri, .. }
        | ObjectProviderRequest::Trash { uri, .. }
        | ObjectProviderRequest::DeletePermanently { uri, .. }
        | ObjectProviderRequest::Status { uri, .. }
        | ObjectProviderRequest::Sync { uri, .. }
        | ObjectProviderRequest::Publish { uri, .. }
        | ObjectProviderRequest::Unpublish { uri, .. }
        | ObjectProviderRequest::Repair { uri, .. }
        | ObjectProviderRequest::DiscardProtection { uri, .. }
        | ObjectProviderRequest::UnfinishedProtections { uri, .. }
        | ObjectProviderRequest::Share { uri, .. }
        | ObjectProviderRequest::SharedAccess { uri, .. } => any_webspace(&[uri]),
        ObjectProviderRequest::CompressArchive { uri, uris, .. } => {
            uri.as_deref().is_some_and(|uri| any_webspace(&[uri]))
                || uris
                    .iter()
                    .any(|uri| is_webspace_uri(uri.trim_end_matches('/')))
        }
        ObjectProviderRequest::ArchiveExtractEntries {
            uri,
            destination_uri,
            ..
        } => any_webspace(&[uri, destination_uri]),
        ObjectProviderRequest::Mkdir { parent_uri, .. } => any_webspace(&[parent_uri]),
        ObjectProviderRequest::Move {
            uri,
            target_parent_uri,
            ..
        }
        | ObjectProviderRequest::Copy {
            uri,
            target_parent_uri,
            ..
        } => any_webspace(&[uri, target_parent_uri]),
        ObjectProviderRequest::Restore {
            uri, target_uri, ..
        } => target_uri
            .as_deref()
            .map(|target_uri| any_webspace(&[uri, target_uri]))
            .unwrap_or_else(|| any_webspace(&[uri])),
        ObjectProviderRequest::PublishProgress { .. }
        | ObjectProviderRequest::Roots { .. }
        | ObjectProviderRequest::List { uri: None, .. }
        | ObjectProviderRequest::EmptyTrash { .. }
        | ObjectProviderRequest::Events { .. }
        | ObjectProviderRequest::ListRuntimeCustody { .. }
        | ObjectProviderRequest::ImportRuntimeCustody { .. }
        | ObjectProviderRequest::Buy { .. }
        | ObjectProviderRequest::BuyOffer { .. }
        | ObjectProviderRequest::OpenViewer { .. }
        | ObjectProviderRequest::ReadViewer { .. }
        | ObjectProviderRequest::CloseViewer { .. } => false,
    }
}

fn library_object(data_dir: &Path, principal_id: &str, uri: &str) -> anyhow::Result<LibraryObject> {
    let target = library_target(data_dir, principal_id, uri)?;
    // A place with no directory yet is the empty folder `list` already shows;
    // its times are unknown (0).
    let metadata = match fs::metadata(&target.path) {
        Ok(metadata) => Some(metadata),
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                && library_roots(data_dir, principal_id)
                    .iter()
                    .any(|root| root.uri == target.uri) =>
        {
            None
        }
        Err(err) => return Err(err.into()),
    };
    let is_dir = metadata.as_ref().is_none_or(fs::Metadata::is_dir);
    let file_len = metadata.as_ref().map_or(0, fs::Metadata::len);
    let name = if target.uri == target.localhost_root {
        "Home".to_string()
    } else {
        target
            .uri
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("object")
            .to_string()
    };
    let (modified_at, created_at) = match &metadata {
        Some(metadata) => {
            let modified_at = system_time_secs(metadata.modified().ok()).unwrap_or_else(now_ts);
            let created_at = system_time_secs(metadata.created().ok()).unwrap_or(modified_at);
            (modified_at, created_at)
        }
        None => (0, 0),
    };
    let mut blocked_reason = None;
    let (size, revision, content_cid) = if is_dir {
        (0, directory_revision(&target.path, &target.uri)?, None)
    } else {
        match read_library_file_bytes(data_dir, principal_id, &target) {
            Ok(bytes) => {
                let revision = format!("rev:{}", hex::encode(Sha256::digest(&bytes)));
                let content_cid = raw_sha256_cid(&bytes)?;
                (bytes.len() as u64, revision, Some(content_cid))
            }
            Err(err) if is_unencrypted_principal_root_object(&err) => {
                blocked_reason = Some("protected_principal_root_object_not_encrypted".to_string());
                blocked_object_projection(&target.uri, file_len, modified_at)
            }
            Err(err) if is_damaged_principal_root_object(&err) => {
                blocked_reason = Some("protected_principal_root_object_damaged".to_string());
                blocked_object_projection(&target.uri, file_len, modified_at)
            }
            Err(err) => return Err(err),
        }
    };
    let record = read_publish_record(data_dir, principal_id, &target.uri).ok();
    let active_record = record.as_ref().filter(|record| record_is_published(record));
    let published_cid = active_record.map(|record| record.cid.clone());
    let is_trash_root = is_trash_root_uri(&target.localhost_root, &target.uri);
    let in_trash = is_trash_uri(&target.localhost_root, &target.uri);
    let visibility = library_visibility_metadata(
        &target.localhost_root,
        &target.uri,
        is_dir,
        blocked_reason.as_deref(),
        active_record,
    );
    let mut capabilities = if is_dir {
        let mut capabilities = vec![
            "open",
            "list",
            "rename",
            "move",
            "copy",
            "trash",
            "properties",
        ];
        if target.uri != target.localhost_root
            && !is_runtime_private_uri(&target.localhost_root, &target.uri)
        {
            capabilities.push("download");
            capabilities.push("compress_archive");
        }
        capabilities
    } else {
        let mut capabilities = vec![
            "open",
            "read",
            "download",
            "rename",
            "move",
            "copy",
            "publish",
            "trash",
            "properties",
        ];
        if !is_runtime_private_uri(&target.localhost_root, &target.uri) {
            capabilities.push("compress_archive");
        }
        if active_record.is_some() {
            capabilities.push("unpublish");
            capabilities.push("repair");
            capabilities.push("share");
        }
        if is_extractable_archive_name(&name) {
            capabilities.push("extract_archive");
        }
        if active_record.is_none()
            && crate::protected_content_runtime::protected_content_enabled(data_dir)
        {
            capabilities.push("protect");
        }
        capabilities
    };
    if is_trash_root {
        capabilities = vec!["open", "list", "empty_trash", "properties"];
    } else if in_trash {
        capabilities = vec!["restore", "delete_permanently", "properties"];
    }
    if blocked_reason.is_some() {
        capabilities = vec!["properties"];
    }
    let mut local_metadata = if is_dir {
        json!({
            "schema": "elastos.library.object-metadata/v1",
            "visibility": visibility,
        })
    } else {
        let mut metadata = json!({
            "schema": "elastos.library.object-metadata/v1",
            "visibility": visibility,
            "content_identity": {
                "schema": "elastos.library.content-identity/v1",
                "current_cid": content_cid.clone(),
                "scope": "local-object-head",
                "published_cid": published_cid.clone(),
                "note": "The current CID is the immutable raw-byte CID for this mutable object head. The published CID is set only after content-provider publish."
            }
        });
        if let Some(archive_support) = archive_support_for_name(&name) {
            metadata["archive_support"] = archive_support;
        }
        metadata
    };
    if let Some(protected_content) = active_record
        .and_then(runtime_custody_library_identity_metadata)
        .or_else(|| {
            runtime_custody_capsule_identity_metadata(data_dir, principal_id, &target, &name)
        })
    {
        local_metadata["protected_content"] = protected_content;
    }
    if in_trash && !is_trash_root {
        if let Ok(record) = read_trash_record(data_dir, principal_id, &target.uri) {
            local_metadata["trash"] = json!({
                "schema": LIBRARY_TRASH_RECORD_SCHEMA,
                "trash_uri": record.trash_uri,
                "original_uri": record.original_uri,
                "original_name": record.original_name,
                "trashed_at": record.trashed_at,
            });
        }
    }
    let local_metadata = Some(local_metadata);
    let viewers = viewer_options_for_name(data_dir, uri);
    let viewer = viewers.first().map(|viewer| viewer.id.clone());
    let availability = if blocked_reason.is_some() {
        "blocked".to_string()
    } else {
        record_availability_label(record.as_ref())
    };
    Ok(LibraryObject {
        schema: LIBRARY_OBJECT_SCHEMA,
        uri: target.uri,
        name,
        kind: if is_dir { "directory" } else { "file" },
        mime: if is_dir {
            "inode/directory".to_string()
        } else {
            mime_for_name(uri).to_string()
        },
        size,
        created_at,
        modified_at,
        revision,
        viewer,
        viewers,
        thumbnail_uri: None,
        availability,
        blocked_reason,
        content_cid,
        published_cid,
        metadata: local_metadata,
        published: active_record.is_some(),
        publication: active_record.map(publication_projection),
        shared: active_record.is_some_and(|record| record.shared_at.is_some()),
        capabilities,
    })
}

fn library_visibility_metadata(
    localhost_root: &str,
    uri: &str,
    is_dir: bool,
    blocked_reason: Option<&str>,
    active_record: Option<&LibraryPublishRecord>,
) -> Value {
    let placement = if is_trash_uri(localhost_root, uri) {
        "trash"
    } else if is_runtime_private_uri(localhost_root, uri) {
        "runtime_private"
    } else if is_public_uri(localhost_root, uri) {
        "public_folder"
    } else {
        "private_folder"
    };
    let share_policy = active_record
        .and_then(|record| record.share_policy.as_deref())
        .unwrap_or("not_shared");
    let effective_access = if blocked_reason.is_some() {
        "blocked"
    } else if active_record.is_some_and(|record| record.shared_at.is_some()) {
        match share_policy {
            "recipient_scoped" => "recipient_scoped_link",
            _ => "public_content_link",
        }
    } else if active_record.is_some() {
        "public_content_link"
    } else {
        "principal_private"
    };
    let published_cid = active_record.map(|record| record.cid.clone());

    json!({
        "schema": LIBRARY_VISIBILITY_SCHEMA,
        "placement": placement,
        "placement_label": match placement {
            "public_folder" => "Public folder",
            "trash" => "Trash",
            "runtime_private" => "Runtime private area",
            _ => "Private folder",
        },
        "effective_access": effective_access,
        "published": active_record.is_some(),
        "published_cid": published_cid.clone(),
        "published_link": published_cid.map(|cid| format!("elastos://{cid}")),
        "shared": active_record.is_some_and(|record| record.shared_at.is_some()),
        "share_policy": share_policy,
        "public_folder_policy": "placement_only",
        "publish_required_for_public_link": !is_dir && active_record.is_none(),
        "note": "Public folder placement is a user-facing Library projection. Public network access requires an explicit content-provider publish receipt."
    })
}

fn is_public_uri(localhost_root: &str, uri: &str) -> bool {
    let public_root = format!("{}/Public", localhost_root.trim_end_matches('/'));
    uri == public_root || uri.starts_with(&format!("{public_root}/"))
}

fn raw_sha256_cid(bytes: &[u8]) -> anyhow::Result<String> {
    let digest = Sha256::digest(bytes);
    let multihash = cid::multihash::Multihash::<64>::wrap(0x12, &digest)
        .map_err(|err| anyhow!("failed to build raw content CID: {err}"))?;
    Ok(cid::Cid::new_v1(0x55, multihash).to_string())
}

fn is_unencrypted_principal_root_object(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains(crate::auth::PROTECTED_PRINCIPAL_ROOT_OBJECT_NOT_ENCRYPTED)
    })
}

fn is_damaged_principal_root_object(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains(crate::auth::PROTECTED_PRINCIPAL_ROOT_OBJECT_DAMAGED)
    })
}

/// Size, revision and CID of an item Library lists without opening it.
fn blocked_object_projection(
    uri: &str,
    len: u64,
    modified_at: u64,
) -> (u64, String, Option<String>) {
    let revision_input = format!("{uri}:{len}:{modified_at}");
    (
        len,
        format!(
            "rev:blocked:{}",
            hex::encode(Sha256::digest(revision_input))
        ),
        None,
    )
}

fn read_library_file_bytes(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Vec<u8>> {
    match crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &target.localhost_root,
        &target.uri,
        &target.path,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(err) if is_unencrypted_principal_root_object(&err) => {
            protect_legacy_plaintext_library_file(data_dir, principal_id, target)
        }
        Err(err) => Err(err),
    }
}

fn write_library_file_bytes(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    _mime: Option<&str>,
    if_revision: Option<&str>,
    create_only: bool,
    bytes: &[u8],
) -> anyhow::Result<LibraryObject> {
    let target = library_target(data_dir, principal_id, uri)?;
    if is_trash_uri(&target.localhost_root, &target.uri) {
        bail!("library Trash accepts objects only through delete");
    }
    if create_only && if_revision.is_some_and(|value| !value.trim().is_empty()) {
        bail!("library create-only write does not accept if_revision");
    }
    check_revision(data_dir, principal_id, &target.uri, if_revision)?;
    StartWalkRule::new(data_dir, &target.localhost_root).file(&target.uri)?;
    if let Some(parent) = target.path.parent() {
        fs::create_dir_all(parent)?;
    }
    let write = if create_only {
        crate::auth::create_principal_root_object(
            data_dir,
            principal_id,
            &target.localhost_root,
            &target.uri,
            &target.path,
            bytes,
        )
    } else {
        crate::auth::write_principal_root_object(
            data_dir,
            principal_id,
            &target.localhost_root,
            &target.uri,
            &target.path,
            bytes,
        )
    };
    match write {
        Ok(()) => {}
        Err(err)
            if create_only
                && err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            bail!("library destination already exists");
        }
        Err(err) => return Err(err),
    }
    let object = library_object(data_dir, principal_id, &target.uri)?;
    append_library_event(
        data_dir,
        principal_id,
        "write",
        &target.uri,
        json!({
            "object": object.clone(),
        }),
    )?;
    Ok(object)
}

fn library_download_object(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<(LibraryObject, String, Vec<u8>)> {
    let target = library_target(data_dir, principal_id, uri)?;
    let object = library_object(data_dir, principal_id, &target.uri)?;
    if target.path.is_file() {
        let bytes = read_library_file_bytes(data_dir, principal_id, &target)?;
        let filename = object.name.clone();
        return Ok((object, filename, bytes));
    }
    if !target.path.is_dir() {
        bail!("library download target must be a file or directory");
    }
    let bytes = archive_library_directory(data_dir, principal_id, &target, archive_format)?;
    let filename = format!(
        "{}.{}",
        safe_archive_name(&object.name),
        archive_format.extension()
    );
    let mut archive_object = object;
    archive_object.mime = archive_format.mime().to_string();
    archive_object.size = bytes.len() as u64;
    Ok((archive_object, filename, bytes))
}

fn compress_library_archive(
    data_dir: &Path,
    principal_id: &str,
    uri: Option<&str>,
    uris: &[String],
    if_revision: Option<&str>,
) -> anyhow::Result<LibraryObject> {
    if !uris.is_empty() {
        if uri.is_some() {
            bail!("library compress_archive accepts either uri or uris, not both");
        }
        if if_revision.is_some() {
            bail!("library selected compress_archive does not accept if_revision");
        }
        let (parent_uri, targets) =
            library_selection_archive_targets(data_dir, principal_id, uris)?;
        ensure_library_archive_budget(
            data_dir,
            principal_id,
            &targets,
            LibraryArchiveBudget::Compress,
        )?;
        let bytes = archive_library_selection_zip(data_dir, principal_id, &targets)?;
        let filename = library_selection_archive_filename(&parent_uri, LibraryArchiveFormat::Zip);
        let archive_uri = unique_child_uri(data_dir, principal_id, &parent_uri, &filename)?;
        let object = write_library_file_bytes(
            data_dir,
            principal_id,
            &archive_uri,
            Some(LibraryArchiveFormat::Zip.mime()),
            None,
            false,
            &bytes,
        )?;
        append_library_event(
            data_dir,
            principal_id,
            "compress_archive",
            &archive_uri,
            json!({
                "uris": targets.iter().map(|target| target.uri.clone()).collect::<Vec<_>>(),
                "object": object.clone(),
            }),
        )?;
        return Ok(object);
    }

    let uri = uri.ok_or_else(|| anyhow!("library compress_archive requires uri or uris"))?;
    let target = library_target(data_dir, principal_id, uri)?;
    if target.uri == target.localhost_root {
        bail!("library root compress is not supported; use Recovery Kit for full backups");
    }
    if is_runtime_private_uri(&target.localhost_root, &target.uri) {
        bail!("runtime-private Library folders cannot be compressed");
    }
    if !target.path.is_file() && !target.path.is_dir() {
        bail!("library compress_archive target must be a file or directory");
    }
    // Before the revision check, which reads the whole object.
    ensure_library_archive_budget(
        data_dir,
        principal_id,
        std::slice::from_ref(&target),
        LibraryArchiveBudget::Compress,
    )?;
    check_revision(data_dir, principal_id, &target.uri, if_revision)?;
    let parent_uri = target
        .uri
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .ok_or_else(|| anyhow!("library compress_archive target has no parent"))?;
    let name = target
        .uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("Library");
    let filename = format!("{}.zip", safe_archive_name(name));
    let bytes = archive_library_single_zip(data_dir, principal_id, &target)?;
    let archive_uri = unique_child_uri(data_dir, principal_id, &parent_uri, &filename)?;
    let object = write_library_file_bytes(
        data_dir,
        principal_id,
        &archive_uri,
        Some(LibraryArchiveFormat::Zip.mime()),
        None,
        false,
        &bytes,
    )?;
    append_library_event(
        data_dir,
        principal_id,
        "compress_archive",
        &archive_uri,
        json!({
            "source_uri": target.uri,
            "object": object.clone(),
        }),
    )?;
    Ok(object)
}

fn protect_legacy_plaintext_library_file(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Vec<u8>> {
    crate::auth::protect_legacy_plaintext_principal_root_object(
        data_dir,
        principal_id,
        &target.localhost_root,
        &target.uri,
        &target.path,
    )
}

fn archive_library_directory(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<Vec<u8>> {
    if target.uri == target.localhost_root {
        bail!("library root download is not supported; use Recovery Kit for full backups");
    }
    if is_runtime_private_uri(&target.localhost_root, &target.uri) {
        bail!("runtime-private Library folders cannot be downloaded");
    }
    ensure_library_archive_budget(
        data_dir,
        principal_id,
        std::slice::from_ref(target),
        LibraryArchiveBudget::Download,
    )?;
    match archive_format {
        LibraryArchiveFormat::TarGz => {
            archive_library_directory_tar_gz(data_dir, principal_id, target)
        }
        LibraryArchiveFormat::Zip => archive_library_directory_zip(data_dir, principal_id, target),
    }
}

/// What one archive Library builds in memory may hold (#481). A download
/// holds no more than Home extracts from one archive; Compress, which holds
/// several copies at once, no more than one upload, so its result is never
/// larger than an upload.
#[derive(Debug, Clone, Copy)]
enum LibraryArchiveBudget {
    Download,
    Compress,
}

impl LibraryArchiveBudget {
    fn admits(self, total: u64, largest: u64) -> bool {
        match self {
            Self::Download => {
                total <= MAX_ARCHIVE_EXPANDED_BYTES && largest <= MAX_ARCHIVE_ENTRY_BYTES
            }
            Self::Compress => total <= MAX_ARCHIVE_ENTRY_BYTES,
        }
    }
}

/// A download or Compress refused before any content was read.
#[derive(Debug)]
pub(crate) struct LibraryArchiveTooLarge(LibraryArchiveBudget);

impl std::fmt::Display for LibraryArchiveTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            LibraryArchiveBudget::Download => write!(
                formatter,
                "Too large to download at once (limit {} GB, and no file over {} MB). \
                 Choose fewer or smaller items.",
                MAX_ARCHIVE_EXPANDED_BYTES >> 30,
                MAX_ARCHIVE_ENTRY_BYTES >> 20
            ),
            LibraryArchiveBudget::Compress => write!(
                formatter,
                "Too large to compress at once (limit {} MB). Choose fewer or smaller items.",
                MAX_ARCHIVE_ENTRY_BYTES >> 20
            ),
        }
    }
}

impl std::error::Error for LibraryArchiveTooLarge {}

/// Reads no content: each file counts the most a read of it can return,
/// judged from its head and tail (`principal_root_object_content_bound`).
fn ensure_library_archive_budget(
    data_dir: &Path,
    principal_id: &str,
    targets: &[LibraryTarget],
    budget: LibraryArchiveBudget,
) -> anyhow::Result<()> {
    let Some(localhost_root) = targets.first().map(|target| target.localhost_root.as_str()) else {
        return Ok(());
    };
    let protection =
        crate::auth::load_principal_root_protection(data_dir, principal_id, localhost_root)?;
    let data_key_id = protection
        .as_ref()
        .map(|protection| protection.data_key_id.as_str());
    let (mut total, mut largest) = (0u64, 0u64);
    for target in targets {
        add_library_archive_source_bytes(
            data_dir,
            principal_id,
            data_key_id,
            target,
            &mut total,
            &mut largest,
        )?;
    }
    if !budget.admits(total, largest) {
        return Err(LibraryArchiveTooLarge(budget).into());
    }
    Ok(())
}

fn add_library_archive_source_bytes(
    data_dir: &Path,
    principal_id: &str,
    data_key_id: Option<&str>,
    target: &LibraryTarget,
    total: &mut u64,
    largest: &mut u64,
) -> anyhow::Result<()> {
    if !fs::metadata(&target.path)?.is_dir() {
        let content = crate::auth::principal_root_object_content_bound(
            principal_id,
            &target.localhost_root,
            &target.uri,
            &target.path,
            data_key_id,
        )?;
        *total = total.saturating_add(content);
        *largest = (*largest).max(content);
        return Ok(());
    }
    for entry in fs::read_dir(&target.path)? {
        let name = entry?.file_name().to_string_lossy().to_string();
        let child = library_target(data_dir, principal_id, &format!("{}/{}", target.uri, name))?;
        add_library_archive_source_bytes(
            data_dir,
            principal_id,
            data_key_id,
            &child,
            total,
            largest,
        )?;
    }
    Ok(())
}

fn archive_library_directory_tar_gz(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let archive_root = PathBuf::from(safe_archive_name(
        target
            .uri
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("Library"),
    ));
    append_library_archive_entry(&mut builder, data_dir, principal_id, target, &archive_root)?;
    let encoder = builder.into_inner()?;
    let bytes = encoder.finish()?;
    Ok(bytes)
}

fn archive_library_directory_zip(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let archive_root = PathBuf::from(safe_archive_name(
        target
            .uri
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("Library"),
    ));
    append_library_zip_entry(&mut writer, data_dir, principal_id, target, &archive_root)?;
    Ok(writer.finish()?.into_inner())
}

fn archive_library_selection(
    data_dir: &Path,
    principal_id: &str,
    uris: &[String],
    archive_format: LibraryArchiveFormat,
) -> anyhow::Result<(String, Vec<u8>)> {
    let (parent_uri, targets) = library_selection_archive_targets(data_dir, principal_id, uris)?;
    ensure_library_archive_budget(
        data_dir,
        principal_id,
        &targets,
        LibraryArchiveBudget::Download,
    )?;
    let bytes = match archive_format {
        LibraryArchiveFormat::TarGz => {
            archive_library_selection_tar_gz(data_dir, principal_id, &targets)?
        }
        LibraryArchiveFormat::Zip => {
            archive_library_selection_zip(data_dir, principal_id, &targets)?
        }
    };
    Ok((
        library_selection_archive_filename(&parent_uri, archive_format),
        bytes,
    ))
}

fn library_selection_archive_targets(
    data_dir: &Path,
    principal_id: &str,
    uris: &[String],
) -> anyhow::Result<(String, Vec<LibraryTarget>)> {
    if uris.len() < 2 {
        bail!("library selected archive requires at least two objects");
    }
    let mut seen = BTreeSet::new();
    let mut parent_uri: Option<String> = None;
    let mut targets = Vec::new();
    for uri in uris {
        let target = library_target(data_dir, principal_id, uri)?;
        if !seen.insert(target.uri.clone()) {
            continue;
        }
        if target.uri == target.localhost_root {
            bail!("library root download is not supported; use Recovery Kit for full backups");
        }
        if is_runtime_private_uri(&target.localhost_root, &target.uri) {
            bail!("runtime-private Library folders cannot be downloaded");
        }
        if !target.path.is_file() && !target.path.is_dir() {
            bail!("library selected archive entries must be files or directories");
        }
        let parent = target
            .uri
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_string())
            .ok_or_else(|| anyhow!("library selected archive entry has no parent"))?;
        if parent_uri
            .as_deref()
            .is_some_and(|expected| expected != parent)
        {
            bail!("library selected archive entries must share one parent folder");
        }
        parent_uri = Some(parent);
        targets.push(target);
    }
    if targets.len() < 2 {
        bail!("library selected archive requires at least two unique objects");
    }
    let parent_uri = parent_uri.ok_or_else(|| anyhow!("library selected archive has no parent"))?;
    Ok((parent_uri, targets))
}

fn library_selection_archive_filename(
    parent_uri: &str,
    archive_format: LibraryArchiveFormat,
) -> String {
    let parent_name = parent_uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("Library");
    format!(
        "{} Selection.{}",
        safe_archive_name(parent_name),
        archive_format.extension()
    )
}

fn archive_library_selection_tar_gz(
    data_dir: &Path,
    principal_id: &str,
    targets: &[LibraryTarget],
) -> anyhow::Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for target in targets {
        let name = target
            .uri
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("Library");
        append_library_archive_entry(
            &mut builder,
            data_dir,
            principal_id,
            target,
            &PathBuf::from(safe_archive_name(name)),
        )?;
    }
    let encoder = builder.into_inner()?;
    Ok(encoder.finish()?)
}

fn archive_library_selection_zip(
    data_dir: &Path,
    principal_id: &str,
    targets: &[LibraryTarget],
) -> anyhow::Result<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for target in targets {
        let name = target
            .uri
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("Library");
        append_library_zip_entry(
            &mut writer,
            data_dir,
            principal_id,
            target,
            &PathBuf::from(safe_archive_name(name)),
        )?;
    }
    Ok(writer.finish()?.into_inner())
}

fn archive_library_single_zip(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let name = target
        .uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("Library");
    append_library_zip_entry(
        &mut writer,
        data_dir,
        principal_id,
        target,
        &PathBuf::from(safe_archive_name(name)),
    )?;
    Ok(writer.finish()?.into_inner())
}

fn library_archive_entries(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Value> {
    if !target.path.is_file() {
        bail!("library archive listing target must be a file");
    }
    if is_runtime_private_uri(&target.localhost_root, &target.uri) {
        bail!("runtime-private Library archives cannot be listed");
    }
    let name = library_archive_name(target, "listing")?;
    if !is_extractable_archive_name(&name) {
        bail!("library archive listing only supports .tar, .tar.gz, .tgz, and .zip archives");
    }
    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    archive_entries_for_object(
        library_object(data_dir, principal_id, &target.uri)?,
        &target.uri,
        &name,
        bytes,
    )
}

fn archive_preview_entry(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    entry: &str,
) -> anyhow::Result<Value> {
    if !target.path.is_file() {
        bail!("library archive preview target must be a file");
    }
    if is_runtime_private_uri(&target.localhost_root, &target.uri) {
        bail!("runtime-private Library archives cannot be previewed");
    }
    let name = library_archive_name(target, "preview")?;
    if !is_extractable_archive_name(&name) {
        bail!("library archive preview only supports .tar, .tar.gz, .tgz, and .zip archives");
    }
    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    archive_preview_entry_for_object(
        data_dir,
        library_object(data_dir, principal_id, &target.uri)?,
        &target.uri,
        &name,
        bytes,
        entry,
    )
}

fn archive_entries_for_object(
    object: LibraryObject,
    uri: &str,
    archive_name: &str,
    bytes: Vec<u8>,
) -> anyhow::Result<Value> {
    if !is_extractable_archive_name(archive_name) {
        bail!("library archive listing only supports .tar, .tar.gz, .tgz, and .zip archives");
    }
    let lower_name = archive_name.to_ascii_lowercase();
    let (entries, truncated) = if lower_name.ends_with(".zip") {
        list_zip_archive_entries(bytes)?
    } else {
        list_tar_archive_entries(archive_name, bytes)?
    };
    let returned_entries = entries.len();
    Ok(json!({
        "schema": LIBRARY_ARCHIVE_ENTRIES_SCHEMA,
        "object": object,
        "uri": uri,
        "family": archive_family_for_name(archive_name).unwrap_or("archive"),
        "entries": entries,
        "limits": {
            "max_entries": MAX_ARCHIVE_LIST_ENTRIES,
            "returned_entries": returned_entries,
            "truncated": truncated,
        },
    }))
}

fn archive_preview_entry_for_object(
    data_dir: &Path,
    object: LibraryObject,
    uri: &str,
    archive_name: &str,
    bytes: Vec<u8>,
    entry: &str,
) -> anyhow::Result<Value> {
    if !is_extractable_archive_name(archive_name) {
        bail!("library archive preview only supports .tar, .tar.gz, .tgz, and .zip archives");
    }
    let normalized = normalized_archive_entry_path(entry)?;
    let preview = if archive_name.to_ascii_lowercase().ends_with(".zip") {
        preview_zip_archive_entry(bytes, &normalized)?
    } else {
        preview_tar_archive_entry(archive_name, bytes, &normalized)?
    };
    let mime = mime_for_name(&normalized);
    let text = if is_archive_preview_text_mime(mime) {
        Some(String::from_utf8_lossy(&preview.bytes).to_string())
    } else {
        None
    };
    let entry_name =
        crate::auth::printable_text(normalized.rsplit('/').next().unwrap_or(normalized.as_str()));
    let viewers = viewer_options_for_name(data_dir, &normalized);
    Ok(json!({
        "schema": LIBRARY_ARCHIVE_PREVIEW_ENTRY_SCHEMA,
        "object": object,
        "uri": uri,
        "family": archive_family_for_name(archive_name).unwrap_or("archive"),
        "entry": {
            "display_path": crate::auth::printable_text(&normalized),
            "path": normalized,
            "name": entry_name,
            "kind": "file",
            "size": preview.size,
            "compressed_size": preview.compressed_size,
            "modified_at": preview.modified_at,
            "mime": mime,
            "safety": {
                "status": "safe",
                "reason": Value::Null,
            },
            "viewers": viewers,
        },
        "preview": {
            "encoding": "base64",
            "data": base64::engine::general_purpose::STANDARD.encode(&preview.bytes),
            "text": text,
            "truncated": preview.truncated,
            "max_bytes": MAX_ARCHIVE_PREVIEW_BYTES,
            "mode": "provider_bounded_safe_entry_preview",
        },
    }))
}

struct ArchiveEntryPreview {
    bytes: Vec<u8>,
    size: Option<u64>,
    compressed_size: Option<u64>,
    modified_at: Option<u64>,
    truncated: bool,
}

fn preview_zip_archive_entry(
    bytes: Vec<u8>,
    selected: &str,
) -> anyhow::Result<ArchiveEntryPreview> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|err| anyhow!("invalid ZIP archive: {err}"))?;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?;
        let raw_name = file
            .name()
            .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?
            .into_owned();
        let Ok(normalized) = normalized_archive_entry_path(&raw_name) else {
            continue;
        };
        if normalized != selected {
            continue;
        }
        if file.is_dir() || !file.is_file() {
            bail!("library archive preview only supports safe file entries");
        }
        let declared_size = file.size();
        let mut preview_bytes = Vec::new();
        file.by_ref()
            .take(MAX_ARCHIVE_PREVIEW_BYTES as u64 + 1)
            .read_to_end(&mut preview_bytes)?;
        let truncated = preview_bytes.len() > MAX_ARCHIVE_PREVIEW_BYTES
            || declared_size > MAX_ARCHIVE_PREVIEW_BYTES as u64;
        preview_bytes.truncate(MAX_ARCHIVE_PREVIEW_BYTES);
        return Ok(ArchiveEntryPreview {
            bytes: preview_bytes,
            size: Some(declared_size),
            compressed_size: Some(file.compressed_size()),
            modified_at: None,
            truncated,
        });
    }
    bail!("library archive preview entry not found");
}

fn preview_tar_archive_entry(
    name: &str,
    bytes: Vec<u8>,
    selected: &str,
) -> anyhow::Result<ArchiveEntryPreview> {
    let (mut archive, input) = bounded_tar_archive(name, &bytes);
    let archive_name = crate::auth::printable_text(name);
    let mut expansion = ArchiveExpansion::new(&archive_name);
    for entry in archive.entries()? {
        let mut entry = input.entry(&archive_name, entry)?;
        let Ok(normalized) =
            tar_entry_name(&entry).and_then(|name| normalized_archive_entry_path(&name))
        else {
            expansion.pass_over(entry.size())?;
            continue;
        };
        if normalized != selected {
            expansion.pass_over(entry.size())?;
            continue;
        }
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() || !entry_type.is_file() {
            bail!("library archive preview only supports safe file entries");
        }
        let declared_size = entry.header().size().ok();
        let modified_at = entry.header().mtime().ok();
        let mut preview_bytes = Vec::new();
        entry
            .by_ref()
            .take(MAX_ARCHIVE_PREVIEW_BYTES as u64 + 1)
            .read_to_end(&mut preview_bytes)?;
        let truncated = preview_bytes.len() > MAX_ARCHIVE_PREVIEW_BYTES
            || declared_size.is_some_and(|size| size > MAX_ARCHIVE_PREVIEW_BYTES as u64);
        preview_bytes.truncate(MAX_ARCHIVE_PREVIEW_BYTES);
        return Ok(ArchiveEntryPreview {
            bytes: preview_bytes,
            size: declared_size,
            compressed_size: None,
            modified_at,
            truncated,
        });
    }
    bail!("library archive preview entry not found");
}

fn is_archive_preview_text_mime(mime: &str) -> bool {
    mime == "text/plain" || mime == "application/json" || mime == "text/html"
}

fn library_archive_name(target: &LibraryTarget, action: &str) -> anyhow::Result<String> {
    target
        .uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("library archive {action} target has no name"))
}

fn check_object_revision(object: &LibraryObject, if_revision: Option<&str>) -> anyhow::Result<()> {
    if let Some(expected) = if_revision {
        if expected != object.revision {
            bail!("library object revision mismatch");
        }
    }
    Ok(())
}

fn webspace_archive_object(mut object: LibraryObject) -> LibraryObject {
    if let Some(metadata) = object.metadata.as_mut() {
        redact_resolver_private_fields(metadata);
        if let Some(map) = metadata.as_object_mut() {
            map.insert("resolver_target_redacted".to_string(), Value::Bool(true));
        }
    }
    object
}

fn redact_resolver_private_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("target_uri");
            map.remove("provider_credentials");
            map.remove("endpoint_credentials");
            map.remove("credentials");
            for child in map.values_mut() {
                redact_resolver_private_fields(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                redact_resolver_private_fields(child);
            }
        }
        _ => {}
    }
}

fn redacted_resolver_private_value(mut value: Value) -> Value {
    redact_resolver_private_fields(&mut value);
    value
}

fn list_tar_archive_entries(name: &str, bytes: Vec<u8>) -> anyhow::Result<(Vec<Value>, bool)> {
    let (mut archive, input) = bounded_tar_archive(name, &bytes);
    let archive_name = crate::auth::printable_text(name);
    let mut entries = Vec::new();
    let mut truncated = false;
    // Listing expands every entry it passes over; past the limit the list
    // stops, as it does past MAX_ARCHIVE_LIST_ENTRIES (#449).
    let mut expansion = ArchiveExpansion::new(&archive_name);
    for (index, entry) in archive.entries()?.enumerate() {
        if entries.len() >= MAX_ARCHIVE_LIST_ENTRIES {
            truncated = true;
            break;
        }
        let entry = input.entry(&archive_name, entry)?;
        if expansion.pass_over(entry.size()).is_err() {
            truncated = true;
            break;
        }
        let entry_type = entry.header().entry_type();
        let size = entry.header().size().ok();
        let modified_at = entry.header().mtime().ok();
        let display_path =
            archive_entry_display_name(&String::from_utf8_lossy(&entry.path_bytes()), index);
        let normalized =
            match tar_entry_name(&entry).and_then(|name| normalized_archive_entry_path(&name)) {
                Ok(path) => path,
                Err(err) => {
                    entries.push(blocked_archive_entry_listing(
                        index,
                        display_path,
                        size,
                        None,
                        modified_at,
                        err.to_string(),
                    ));
                    continue;
                }
            };
        let kind = if entry_type.is_dir() {
            "directory"
        } else if entry_type.is_file() {
            "file"
        } else {
            entries.push(blocked_archive_entry_listing(
                index,
                normalized,
                size,
                None,
                modified_at,
                "library archive listing rejects non-file archive entries".to_string(),
            ));
            continue;
        };
        entries.push(safe_archive_entry_listing(
            index,
            normalized,
            kind,
            size,
            None,
            modified_at,
        ));
    }
    Ok((entries, truncated))
}

fn list_zip_archive_entries(bytes: Vec<u8>) -> anyhow::Result<(Vec<Value>, bool)> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|err| anyhow!("invalid ZIP archive: {err}"))?;
    let mut entries = Vec::new();
    let truncated = archive.len() > MAX_ARCHIVE_LIST_ENTRIES;
    for index in 0..archive.len().min(MAX_ARCHIVE_LIST_ENTRIES) {
        let file = archive
            .by_index(index)
            .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?;
        let raw_name = file
            .name()
            .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?
            .into_owned();
        let normalized = match normalized_archive_entry_path(&raw_name) {
            Ok(path) => path,
            Err(err) => {
                entries.push(blocked_archive_entry_listing(
                    index,
                    archive_entry_display_name(&raw_name, index),
                    Some(file.size()),
                    Some(file.compressed_size()),
                    None,
                    err.to_string(),
                ));
                continue;
            }
        };
        let kind = if file.is_dir() {
            "directory"
        } else if file.is_file() {
            "file"
        } else {
            entries.push(blocked_archive_entry_listing(
                index,
                normalized,
                Some(file.size()),
                Some(file.compressed_size()),
                None,
                "library archive listing rejects non-file archive entries".to_string(),
            ));
            continue;
        };
        entries.push(safe_archive_entry_listing(
            index,
            normalized,
            kind,
            Some(file.size()),
            Some(file.compressed_size()),
            None,
        ));
    }
    Ok((entries, truncated))
}

const UNSAFE_ARCHIVE_ENTRY_PATH: &str = "library archive entry path must be relative and safe";

/// The one rule for an archive entry name. Every Library archive reader
/// passes each entry name through it: list, preview, selected extract and
/// whole-archive extract, for ZIP and for tar. The entry names a person asks
/// to preview or to extract go through it too. The rule is the same on every
/// platform. It refuses a name that holds a NUL byte or a `\`, starts with
/// `/` (this includes `//server/share`), starts with a drive letter (`C:/x`,
/// `C:x`), or has a `..` part. `\` is refused everywhere, so `C:\x`,
/// `\\server\share\x` and `..\x` are refused as well. It returns the
/// path with `/` separators and no empty or `.` parts; an empty path is the
/// archive root (for example `./`).
///
/// It is not `Path::components()`: on Linux and macOS that reads `C:/x` as a
/// folder `C:` and `\` as an ordinary character. It is not zip 9
/// `enclosed_name` either: that strips a root or drive prefix and folds `..`,
/// so a hostile entry would be written under another name.
fn archive_entry_path(name: &str) -> anyhow::Result<String> {
    let bytes = name.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if name.starts_with('/') || drive || name.contains(['\\', '\0']) {
        bail!(UNSAFE_ARCHIVE_ENTRY_PATH);
    }
    let mut parts = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => bail!(UNSAFE_ARCHIVE_ENTRY_PATH),
            part => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

/// `archive_entry_path` for a reader that names one entry (list, preview,
/// selected extract): the archive root is not an entry.
fn normalized_archive_entry_path(name: &str) -> anyhow::Result<String> {
    let path = archive_entry_path(name)?;
    if path.is_empty() {
        bail!("library archive entry path must not be empty");
    }
    Ok(path)
}

/// A tar entry name as text (GNU long names and PAX `path` included), before
/// `archive_entry_path`. The raw bytes are read, so the result is the same
/// on every platform.
fn tar_entry_name<R: std::io::Read>(entry: &tar::Entry<'_, R>) -> anyhow::Result<String> {
    String::from_utf8(entry.path_bytes().into_owned())
        .map_err(|_| anyhow!("library archive entry path must be UTF-8"))
}

/// An archive entry name as shown: on one line and in order (#432), so a
/// control, format or bidi character cannot forge a line or reverse a name.
fn archive_entry_display_name(name: &str, index: usize) -> String {
    let display = name.trim();
    if display.is_empty() {
        format!("entry-{index}")
    } else {
        crate::auth::printable_text(display)
    }
}

struct ArchiveEntryListing {
    index: usize,
    path: String,
    kind: &'static str,
    size: Option<u64>,
    compressed_size: Option<u64>,
    modified_at: Option<u64>,
    safety_status: &'static str,
    safety_reason: Option<String>,
}

fn safe_archive_entry_listing(
    index: usize,
    path: String,
    kind: &'static str,
    size: Option<u64>,
    compressed_size: Option<u64>,
    modified_at: Option<u64>,
) -> Value {
    archive_entry_listing(ArchiveEntryListing {
        index,
        path,
        kind,
        size,
        compressed_size,
        modified_at,
        safety_status: "safe",
        safety_reason: None,
    })
}

fn blocked_archive_entry_listing(
    index: usize,
    path: String,
    size: Option<u64>,
    compressed_size: Option<u64>,
    modified_at: Option<u64>,
    safety_reason: String,
) -> Value {
    archive_entry_listing(ArchiveEntryListing {
        index,
        path,
        kind: "blocked",
        size,
        compressed_size,
        modified_at,
        safety_status: "blocked",
        safety_reason: Some(safety_reason),
    })
}

/// `path` is the entry's key, sent back to preview or extract it; the person
/// sees `display_path` and `name`, escaped by `printable_text` (#432).
fn archive_entry_listing(entry: ArchiveEntryListing) -> Value {
    let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
    json!({
        "id": format!("entry:{}", entry.index),
        "display_path": crate::auth::printable_text(&entry.path),
        "name": crate::auth::printable_text(name),
        "path": entry.path,
        "kind": entry.kind,
        "size": entry.size,
        "compressed_size": entry.compressed_size,
        "modified_at": entry.modified_at,
        "safety": {
            "status": entry.safety_status,
            "reason": entry.safety_reason,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveConflictPolicy {
    KeepBoth,
    Replace,
    Skip,
}

impl ArchiveConflictPolicy {
    fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("keep_both")
            .to_ascii_lowercase()
            .replace(' ', "_")
            .as_str()
        {
            "keep_both" => Ok(Self::KeepBoth),
            "replace" => Ok(Self::Replace),
            "skip" => Ok(Self::Skip),
            other => bail!("unsupported archive conflict policy: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::KeepBoth => "keep_both",
            Self::Replace => "replace",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug)]
struct ArchiveExtractOutcome {
    requested: BTreeSet<String>,
    matched: BTreeSet<String>,
    written: Vec<Value>,
    skipped: Vec<Value>,
    blocked: Vec<Value>,
    processed_entries: usize,
}

impl ArchiveExtractOutcome {
    fn new(requested: BTreeSet<String>) -> Self {
        Self {
            requested,
            matched: BTreeSet::new(),
            written: Vec::new(),
            skipped: Vec::new(),
            blocked: Vec::new(),
            processed_entries: 0,
        }
    }

    fn mark_matched(&mut self, normalized_path: &str) {
        for selected in &self.requested {
            if normalized_path == selected
                || normalized_path
                    .strip_prefix(selected)
                    .is_some_and(|rest| rest.starts_with('/'))
            {
                self.matched.insert(selected.clone());
            }
        }
    }

    fn is_selected(&self, normalized_path: &str) -> bool {
        self.requested.iter().any(|selected| {
            normalized_path == selected
                || normalized_path
                    .strip_prefix(selected)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    fn finish_missing(&mut self) {
        for entry in self.requested.difference(&self.matched) {
            self.skipped.push(json!({
                "path": entry,
                "reason": "entry_not_found",
            }));
        }
    }
}

#[derive(Debug)]
enum ArchiveExtractWrite {
    Directory { path: String },
    File { path: String, bytes: Vec<u8> },
}

struct ArchiveExtractRequest<'a> {
    source_uri: &'a str,
    archive_name: &'a str,
    destination_uri: &'a str,
    entries: &'a [String],
    conflict_policy: Option<&'a str>,
    cancel: bool,
}

struct ArchiveExtractResponseInput<'a> {
    destination_object: LibraryObject,
    source_uri: &'a str,
    destination_uri: &'a str,
    archive_name: &'a str,
    policy: ArchiveConflictPolicy,
    status: &'a str,
    outcome: ArchiveExtractOutcome,
    cancel_requested: bool,
}

fn extract_library_archive_entries(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    destination_uri: &str,
    entries: &[String],
    conflict_policy: Option<&str>,
    cancel: bool,
) -> anyhow::Result<Value> {
    if !target.path.is_file() {
        bail!("library archive selected extraction target must be a file");
    }
    if is_runtime_private_uri(&target.localhost_root, &target.uri) {
        bail!("runtime-private Library archives cannot be selectively extracted");
    }
    let name = library_archive_name(target, "selected extraction")?;
    if !is_extractable_archive_name(&name) {
        bail!(
            "library archive selected extraction only supports .tar, .tar.gz, .tgz, and .zip archives"
        );
    }
    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    let request = ArchiveExtractRequest {
        source_uri: &target.uri,
        archive_name: &name,
        destination_uri,
        entries,
        conflict_policy,
        cancel,
    };
    extract_archive_entries_to_local_destination(data_dir, principal_id, bytes, request)
}

fn extract_archive_entries_to_local_destination(
    data_dir: &Path,
    principal_id: &str,
    bytes: Vec<u8>,
    request: ArchiveExtractRequest<'_>,
) -> anyhow::Result<Value> {
    if !is_extractable_archive_name(request.archive_name) {
        bail!(
            "library archive selected extraction only supports .tar, .tar.gz, .tgz, and .zip archives"
        );
    }
    let destination = library_target(data_dir, principal_id, request.destination_uri)?;
    if destination.path.exists() && !destination.path.is_dir() {
        bail!("library archive selected extraction destination must be a directory");
    }
    let policy = ArchiveConflictPolicy::parse(request.conflict_policy)?;
    let selected_entries = selected_archive_entries(request.entries)?;
    let mut outcome = ArchiveExtractOutcome::new(selected_entries);
    if request.cancel {
        let destination_object = library_object(data_dir, principal_id, &destination.uri)?;
        return Ok(archive_extract_entries_response(
            ArchiveExtractResponseInput {
                destination_object,
                source_uri: request.source_uri,
                destination_uri: &destination.uri,
                archive_name: request.archive_name,
                policy,
                status: "cancelled",
                outcome,
                cancel_requested: true,
            },
        ));
    }

    let rule = StartWalkRule::new(data_dir, &destination.localhost_root);
    rule.folder(&destination.uri)?;
    fs::create_dir_all(&destination.path)?;
    // Each selected entry is written as it is read: one file in memory.
    read_selected_archive_entries(
        request.archive_name,
        bytes,
        None,
        &mut outcome,
        &mut |write, outcome| {
            apply_selected_archive_write_to_local(
                data_dir,
                principal_id,
                &destination,
                &rule,
                write,
                policy,
                outcome,
            )
        },
    )?;
    outcome.finish_missing();
    let status = if outcome.blocked.is_empty() {
        "completed"
    } else {
        "completed_with_blocked_entries"
    };
    let destination_object = library_object(data_dir, principal_id, &destination.uri)?;
    let response = archive_extract_entries_response(ArchiveExtractResponseInput {
        destination_object,
        source_uri: request.source_uri,
        destination_uri: &destination.uri,
        archive_name: request.archive_name,
        policy,
        status,
        outcome,
        cancel_requested: false,
    });
    append_library_event(
        data_dir,
        principal_id,
        "archive_extract_entries",
        &destination.uri,
        json!({
            "source_uri": request.source_uri,
            "destination_uri": destination.uri,
            "receipt": response.get("receipt").cloned().unwrap_or(Value::Null),
        }),
    )?;
    Ok(response)
}

fn selected_archive_entries(entries: &[String]) -> anyhow::Result<BTreeSet<String>> {
    let mut selected = BTreeSet::new();
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        selected.insert(normalized_archive_entry_path(entry)?);
    }
    if selected.is_empty() {
        bail!("library archive selected extraction requires at least one entry");
    }
    Ok(selected)
}

/// Receives each selected entry of an archive as it is read.
type SelectedArchiveSink<'a> =
    dyn FnMut(ArchiveExtractWrite, &mut ArchiveExtractOutcome) -> anyhow::Result<()> + 'a;

/// Reads the selected entries of an archive, each bounded by
/// `ArchiveExpansion`, and hands each to `sink` as it is read (#449). A
/// caller that keeps every file passes `keep_budget`, their total.
fn read_selected_archive_entries(
    name: &str,
    bytes: Vec<u8>,
    keep_budget: Option<u64>,
    outcome: &mut ArchiveExtractOutcome,
    sink: &mut SelectedArchiveSink<'_>,
) -> anyhow::Result<()> {
    let archive = crate::auth::printable_text(name);
    let mut expansion = match keep_budget {
        Some(budget) => ArchiveExpansion::with_keep_budget(&archive, budget),
        None => ArchiveExpansion::new(&archive),
    };
    if name.to_ascii_lowercase().ends_with(".zip") {
        read_selected_zip_entries(&mut expansion, bytes, outcome, sink)
    } else {
        // A tar's entry count and sizes are known only by passing over it,
        // so a first pass checks them before anything is written.
        check_selected_tar_entries(name, &archive, &bytes, outcome)?;
        read_selected_tar_entries(name, &mut expansion, &bytes, outcome, sink)
    }
}

/// The entry count and expansion of a selected tar extraction, read without
/// keeping any bytes.
fn check_selected_tar_entries(
    name: &str,
    archive_display: &str,
    bytes: &[u8],
    outcome: &ArchiveExtractOutcome,
) -> anyhow::Result<()> {
    let mut expansion = ArchiveExpansion::new(archive_display);
    let (mut archive, input) = bounded_tar_archive(name, bytes);
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= MAX_ARCHIVE_EXTRACT_ENTRIES {
            return Err(too_many_archive_entries(archive_display));
        }
        let entry = input.entry(archive_display, entry)?;
        let size = entry.size();
        let selected_file = tar_entry_name(&entry)
            .and_then(|name| normalized_archive_entry_path(&name))
            .ok()
            .filter(|path| entry.header().entry_type().is_file() && outcome.is_selected(path));
        match selected_file {
            Some(path) => expansion.admit(&crate::auth::printable_text(&path), size)?,
            None => expansion.pass_over(size)?,
        }
    }
    Ok(())
}

fn read_selected_tar_entries(
    name: &str,
    expansion: &mut ArchiveExpansion<'_>,
    bytes: &[u8],
    outcome: &mut ArchiveExtractOutcome,
    sink: &mut SelectedArchiveSink<'_>,
) -> anyhow::Result<()> {
    let (mut archive, input) = bounded_tar_archive(name, bytes);
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= MAX_ARCHIVE_EXTRACT_ENTRIES {
            return Err(too_many_archive_entries(expansion.archive));
        }
        let mut entry = input.entry(expansion.archive, entry)?;
        // Passing over an entry expands it too, selected or not.
        let size = entry.size();
        let normalized =
            match tar_entry_name(&entry).and_then(|name| normalized_archive_entry_path(&name)) {
                Ok(path) => path,
                Err(err) => {
                    outcome.blocked.push(json!({
                        "path": archive_entry_display_name(
                            &String::from_utf8_lossy(&entry.path_bytes()),
                            outcome.processed_entries,
                        ),
                        "reason": err.to_string(),
                    }));
                    expansion.pass_over(size)?;
                    continue;
                }
            };
        if !outcome.is_selected(&normalized) {
            expansion.pass_over(size)?;
            continue;
        }
        outcome.mark_matched(&normalized);
        outcome.processed_entries += 1;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            expansion.pass_over(size)?;
            sink(ArchiveExtractWrite::Directory { path: normalized }, outcome)?;
            continue;
        }
        if !entry_type.is_file() {
            outcome.blocked.push(json!({
                "path": normalized,
                "reason": "library archive selected extraction rejects non-file archive entries",
            }));
            expansion.pass_over(size)?;
            continue;
        }
        let entry_bytes =
            expansion.read(&crate::auth::printable_text(&normalized), size, &mut entry)?;
        sink(
            ArchiveExtractWrite::File {
                path: normalized,
                bytes: entry_bytes,
            },
            outcome,
        )?;
    }
    Ok(())
}

/// ZIP entries are read by index, so only the selected files expand.
fn read_selected_zip_entries(
    expansion: &mut ArchiveExpansion<'_>,
    bytes: Vec<u8>,
    outcome: &mut ArchiveExtractOutcome,
    sink: &mut SelectedArchiveSink<'_>,
) -> anyhow::Result<()> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|err| anyhow!("invalid ZIP archive: {err}"))?;
    if archive.len() > MAX_ARCHIVE_EXTRACT_ENTRIES {
        return Err(too_many_archive_entries(expansion.archive));
    }
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?;
        let raw_name = file
            .name()
            .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?
            .into_owned();
        let normalized = match normalized_archive_entry_path(&raw_name) {
            Ok(path) => path,
            Err(err) => {
                outcome.blocked.push(json!({
                    "path": archive_entry_display_name(&raw_name, index),
                    "reason": err.to_string(),
                }));
                continue;
            }
        };
        if !outcome.is_selected(&normalized) {
            continue;
        }
        outcome.mark_matched(&normalized);
        outcome.processed_entries += 1;
        if file.is_dir() {
            drop(file);
            sink(ArchiveExtractWrite::Directory { path: normalized }, outcome)?;
            continue;
        }
        if !file.is_file() {
            outcome.blocked.push(json!({
                "path": normalized,
                "reason": "library archive selected extraction rejects non-file archive entries",
            }));
            continue;
        }
        let size = file.size();
        let entry_bytes =
            expansion.read(&crate::auth::printable_text(&normalized), size, &mut file)?;
        drop(file);
        sink(
            ArchiveExtractWrite::File {
                path: normalized,
                bytes: entry_bytes,
            },
            outcome,
        )?;
    }
    Ok(())
}

/// One selected entry lands where the start walk allows; one that would not
/// is listed as blocked, with its path, and nothing is written for it.
fn apply_selected_archive_write_to_local(
    data_dir: &Path,
    principal_id: &str,
    destination: &LibraryTarget,
    rule: &StartWalkRule,
    write: ArchiveExtractWrite,
    policy: ArchiveConflictPolicy,
    outcome: &mut ArchiveExtractOutcome,
) -> anyhow::Result<()> {
    let (path, folder) = match &write {
        ArchiveExtractWrite::Directory { path } => (path, true),
        ArchiveExtractWrite::File { path, .. } => (path, false),
    };
    let uri = archive_entry_uri(&destination.uri, Path::new(path))?;
    let allowed = if folder {
        rule.folder(&uri)
    } else {
        rule.file(&uri)
    };
    if let Err(err) = allowed {
        outcome.blocked.push(json!({
            "path": crate::auth::printable_text(path),
            "reason": err.to_string(),
        }));
        return Ok(());
    }
    match write {
        ArchiveExtractWrite::Directory { path } => {
            create_selected_archive_directory(data_dir, principal_id, destination, &path)?;
            outcome.written.push(json!({
                "path": path,
                "uri": uri,
                "kind": "directory",
            }));
        }
        ArchiveExtractWrite::File { path, bytes } => {
            write_selected_archive_file(
                data_dir,
                principal_id,
                destination,
                &path,
                &bytes,
                policy,
                outcome,
            )?;
        }
    }
    Ok(())
}

async fn extract_archive_entries_to_webspace_destination(
    data_dir: &Path,
    registry: &ProviderRegistry,
    principal_id: &str,
    bytes: Vec<u8>,
    request: ArchiveExtractRequest<'_>,
) -> anyhow::Result<Value> {
    if !is_extractable_archive_name(request.archive_name) {
        bail!(
            "library archive selected extraction only supports .tar, .tar.gz, .tgz, and .zip archives"
        );
    }
    let destination_uri = clean_webspace_uri(request.destination_uri)?;
    let destination_object = webspace_stat_object(data_dir, registry, &destination_uri).await?;
    if destination_object.kind != "directory" {
        bail!("library archive selected extraction WebSpace destination must be a folder");
    }
    ensure_webspace_archive_write_allowed(registry, &destination_object).await?;
    let policy = ArchiveConflictPolicy::parse(request.conflict_policy)?;
    if policy != ArchiveConflictPolicy::Replace {
        bail!("Spaces archive write-back requires conflict_policy=replace until resolver adapters expose existence/conflict APIs");
    }
    let selected_entries = selected_archive_entries(request.entries)?;
    let mut outcome = ArchiveExtractOutcome::new(selected_entries);
    if request.cancel {
        return Ok(archive_extract_entries_response(
            ArchiveExtractResponseInput {
                destination_object: webspace_archive_object(destination_object),
                source_uri: request.source_uri,
                destination_uri: &destination_uri,
                archive_name: request.archive_name,
                policy,
                status: "cancelled",
                outcome,
                cancel_requested: true,
            },
        ));
    }
    // Spaces write-back sends after reading, so it holds the selected files
    // in memory: at most MAX_ARCHIVE_SPACES_WRITE_BACK_BYTES of them, enforced
    // while each file is read.
    let mut writes = Vec::new();
    read_selected_archive_entries(
        request.archive_name,
        bytes,
        Some(MAX_ARCHIVE_SPACES_WRITE_BACK_BYTES),
        &mut outcome,
        &mut |write, _| {
            writes.push(write);
            Ok(())
        },
    )?;
    apply_selected_archive_writes_to_webspace(
        data_dir,
        registry,
        &destination_uri,
        writes,
        &mut outcome,
    )
    .await?;
    outcome.finish_missing();
    let status = if outcome.blocked.is_empty() {
        "completed"
    } else {
        "completed_with_blocked_entries"
    };
    let destination_object = webspace_stat_object(data_dir, registry, &destination_uri).await?;
    let response = archive_extract_entries_response(ArchiveExtractResponseInput {
        destination_object: webspace_archive_object(destination_object),
        source_uri: request.source_uri,
        destination_uri: &destination_uri,
        archive_name: request.archive_name,
        policy,
        status,
        outcome,
        cancel_requested: false,
    });
    append_library_event(
        data_dir,
        principal_id,
        "archive_extract_entries",
        &destination_uri,
        json!({
            "source_uri": request.source_uri,
            "destination_uri": destination_uri,
            "receipt": response.get("receipt").cloned().unwrap_or(Value::Null),
        }),
    )?;
    Ok(response)
}

async fn ensure_webspace_archive_write_allowed(
    registry: &ProviderRegistry,
    destination: &LibraryObject,
) -> anyhow::Result<()> {
    if webspace_metadata_bool(destination, "readonly") != Some(false) {
        bail!("Spaces archive write-back requires a mutable destination Space");
    }
    let Some(adapter) = webspace_adapter_target(registry, destination).await? else {
        bail!("Spaces archive write-back requires a connected resolver adapter");
    };
    if !adapter.capabilities.contains("write_bytes") {
        bail!("Spaces archive write-back requires an adapter with write_bytes capability");
    }
    Ok(())
}

async fn apply_selected_archive_writes_to_webspace(
    data_dir: &Path,
    registry: &ProviderRegistry,
    destination_uri: &str,
    writes: Vec<ArchiveExtractWrite>,
    outcome: &mut ArchiveExtractOutcome,
) -> anyhow::Result<()> {
    for write in writes {
        match write {
            ArchiveExtractWrite::Directory { path } => {
                let uri = archive_entry_uri(destination_uri, Path::new(&path))?;
                let mut receipt = webspace_mkdir(registry, &uri).await?;
                redact_resolver_private_fields(&mut receipt);
                outcome.written.push(json!({
                    "path": path,
                    "uri": uri,
                    "kind": "directory",
                    "webspace": {
                        "write_back": "materialized_directory_handle",
                        "provider_receipt": receipt,
                    },
                }));
            }
            ArchiveExtractWrite::File { path, bytes } => {
                write_selected_archive_webspace_file(
                    data_dir,
                    registry,
                    destination_uri,
                    &path,
                    &bytes,
                    outcome,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn write_selected_archive_webspace_file(
    data_dir: &Path,
    registry: &ProviderRegistry,
    destination_uri: &str,
    normalized_path: &str,
    bytes: &[u8],
    outcome: &mut ArchiveExtractOutcome,
) -> anyhow::Result<()> {
    ensure_webspace_archive_parent_dirs(registry, destination_uri, normalized_path).await?;
    let uri = archive_entry_uri(destination_uri, Path::new(normalized_path))?;
    let mut provider_receipt = webspace_write_bytes(registry, &uri, bytes).await?;
    redact_resolver_private_fields(&mut provider_receipt);
    let sync_receipt = webspace_sync_bytes(data_dir, registry, &uri).await?;
    if sync_receipt
        .get("fail_closed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("Spaces archive write-back failed to sync resolver bytes");
    }
    outcome.written.push(json!({
        "path": normalized_path,
        "uri": uri,
        "kind": "file",
        "size": bytes.len(),
        "webspace": {
            "write_back": "resolver_synced",
            "provider_receipt": provider_receipt,
            "sync_receipt": redacted_resolver_private_value(sync_receipt),
        },
    }));
    Ok(())
}

async fn ensure_webspace_archive_parent_dirs(
    registry: &ProviderRegistry,
    destination_uri: &str,
    normalized_path: &str,
) -> anyhow::Result<()> {
    let mut uri = destination_uri.trim_end_matches('/').to_string();
    let mut components = normalized_path.split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        uri = child_uri(&uri, component)?;
        let _ = webspace_mkdir(registry, &uri).await?;
    }
    Ok(())
}

fn create_selected_archive_directory(
    data_dir: &Path,
    principal_id: &str,
    destination: &LibraryTarget,
    normalized_path: &str,
) -> anyhow::Result<()> {
    let uri = archive_entry_uri(&destination.uri, Path::new(normalized_path))?;
    let target = library_target(data_dir, principal_id, &uri)?;
    fs::create_dir_all(&target.path)?;
    Ok(())
}

fn write_selected_archive_file(
    data_dir: &Path,
    principal_id: &str,
    destination: &LibraryTarget,
    normalized_path: &str,
    bytes: &[u8],
    policy: ArchiveConflictPolicy,
    outcome: &mut ArchiveExtractOutcome,
) -> anyhow::Result<()> {
    let candidate_uri = archive_entry_uri(&destination.uri, Path::new(normalized_path))?;
    let target_uri = selected_archive_conflict_uri(
        data_dir,
        principal_id,
        &candidate_uri,
        normalized_path,
        policy,
        outcome,
    )?;
    let Some(target_uri) = target_uri else {
        return Ok(());
    };
    let target = library_target(data_dir, principal_id, &target_uri)?;
    if let Some(parent) = target.path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::auth::write_principal_root_object(
        data_dir,
        principal_id,
        &target.localhost_root,
        &target.uri,
        &target.path,
        bytes,
    )?;
    outcome.written.push(json!({
        "path": normalized_path,
        "uri": target.uri,
        "kind": "file",
        "size": bytes.len(),
    }));
    Ok(())
}

fn selected_archive_conflict_uri(
    data_dir: &Path,
    principal_id: &str,
    candidate_uri: &str,
    normalized_path: &str,
    policy: ArchiveConflictPolicy,
    outcome: &mut ArchiveExtractOutcome,
) -> anyhow::Result<Option<String>> {
    let target = library_target(data_dir, principal_id, candidate_uri)?;
    if !target.path.exists() {
        return Ok(Some(candidate_uri.to_string()));
    }
    match policy {
        ArchiveConflictPolicy::Skip => {
            outcome.skipped.push(json!({
                "path": normalized_path,
                "uri": candidate_uri,
                "reason": "conflict_skipped",
            }));
            Ok(None)
        }
        ArchiveConflictPolicy::Replace => {
            if target.path.is_dir() {
                fs::remove_dir_all(&target.path)?;
            } else {
                fs::remove_file(&target.path)?;
            }
            Ok(Some(candidate_uri.to_string()))
        }
        ArchiveConflictPolicy::KeepBoth => {
            let (parent_uri, name) = candidate_uri
                .rsplit_once('/')
                .ok_or_else(|| anyhow!("archive selected extraction target has no parent"))?;
            unique_child_uri(data_dir, principal_id, parent_uri, name).map(Some)
        }
    }
}

fn archive_extract_entries_response(input: ArchiveExtractResponseInput<'_>) -> Value {
    let ArchiveExtractResponseInput {
        destination_object,
        source_uri,
        destination_uri,
        archive_name,
        policy,
        status,
        outcome,
        cancel_requested,
    } = input;
    let requested_entries = outcome.requested.len();
    let written_entries = outcome.written.len();
    let skipped_entries = outcome.skipped.len();
    let blocked_entries = outcome.blocked.len();
    json!({
        "schema": LIBRARY_ARCHIVE_EXTRACT_ENTRIES_SCHEMA,
        "object": destination_object,
        "source_uri": source_uri,
        "destination_uri": destination_uri,
        "family": archive_family_for_name(archive_name).unwrap_or("archive"),
        "conflict_policy": policy.as_str(),
        "written": outcome.written,
        "skipped": outcome.skipped,
        "blocked": outcome.blocked,
        "receipt": {
            "schema": "elastos.library.archive-extract-entries.receipt/v1",
            "status": status,
            "progress": {
                "requested_entries": requested_entries,
                "processed_entries": outcome.processed_entries,
                "written_entries": written_entries,
                "skipped_entries": skipped_entries,
                "blocked_entries": blocked_entries,
            },
            "cancel": {
                "supported": true,
                "requested": cancel_requested,
                "status": if cancel_requested { "cancelled_before_write" } else { "not_requested" },
                "mode": "bounded_synchronous_provider_operation",
            },
        },
    })
}

fn extract_library_archive(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<String> {
    if !target.path.is_file() {
        bail!("library archive extraction target must be a file");
    }
    if is_runtime_private_uri(&target.localhost_root, &target.uri) {
        bail!("runtime-private Library archives cannot be extracted");
    }
    let name = target
        .uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("library archive extraction target has no name"))?;
    if !is_extractable_archive_name(name) {
        bail!("library archive extraction only supports .tar, .tar.gz, .tgz, and .zip archives");
    }
    let parent_uri = target
        .uri
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or_else(|| anyhow!("library archive extraction target has no parent"))?;
    let destination_name = archive_extract_folder_name(name);
    let destination_uri = unique_child_uri(data_dir, principal_id, parent_uri, &destination_name)?;
    let destination = library_target(data_dir, principal_id, &destination_uri)?;
    let rule = StartWalkRule::new(data_dir, &destination.localhost_root);
    rule.folder(&destination.uri)?;

    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    let archive_display =
        crate::auth::principal_root_home_relative_path(&destination.localhost_root, &target.uri);
    let archive = WholeArchiveExtract {
        data_dir,
        principal_id,
        archive: &archive_display,
        destination: &destination,
        rule: &rule,
    };
    // The first pass checks every entry against every rule (name, kind,
    // depth, count, expanded size) and writes nothing, so a refused archive
    // writes nothing.
    archive.run(name, &bytes, false)?;
    #[cfg(test)]
    if let Some(hook) = EXTRACT_BEFORE_WRITE_HOOK.with(|hook| hook.borrow_mut().take()) {
        hook(&destination.path);
    }
    // The second pass writes, into a folder it creates now and only if it
    // does not exist, so it never writes into a folder another request made
    // meanwhile. A read or write failure in it (a damaged entry, a file where
    // a folder is needed) stops the extraction; what was extracted before
    // stays, as removing it could remove what another request saved in the
    // folder meanwhile.
    if let Err(err) = fs::create_dir(&destination.path) {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            bail!(
                "{} appeared while the archive was being checked, so nothing was extracted. \
                 Try again.",
                crate::auth::principal_root_home_relative_path(
                    &destination.localhost_root,
                    &destination.uri,
                ),
            );
        }
        return Err(err.into());
    }
    if let Err(err) = archive.run(name, &bytes, true) {
        bail!(
            "Extraction stopped: {}. Files extracted before this stay in {}.",
            err.to_string().trim_end_matches('.'),
            crate::auth::principal_root_home_relative_path(
                &destination.localhost_root,
                &destination.uri,
            ),
        );
    }
    Ok(destination.uri)
}

#[cfg(test)]
type ExtractBeforeWriteHook = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
thread_local! {
    /// Runs once between the checking pass and the writing pass of a whole
    /// extraction, with the destination folder's path.
    static EXTRACT_BEFORE_WRITE_HOOK: std::cell::RefCell<Option<ExtractBeforeWriteHook>> =
        std::cell::RefCell::new(None);
}

/// One whole-archive extraction into a new Library folder. Each entry passes
/// the entry-name rule, is a file or folder, lands where the start walk
/// allows, the archive holds at most `MAX_ARCHIVE_EXTRACT_ENTRIES` entries,
/// and it expands within `ArchiveExpansion` (#449). A refusal names the entry
/// or the archive.
struct WholeArchiveExtract<'a> {
    data_dir: &'a Path,
    principal_id: &'a str,
    /// Printable, for refusals.
    archive: &'a str,
    destination: &'a LibraryTarget,
    rule: &'a StartWalkRule,
}

impl WholeArchiveExtract<'_> {
    fn run(&self, name: &str, bytes: &[u8], write: bool) -> anyhow::Result<()> {
        if name.to_ascii_lowercase().ends_with(".zip") {
            self.zip(bytes, write)
        } else {
            self.tar(name, bytes, write)
        }
    }

    fn tar(&self, name: &str, bytes: &[u8], write: bool) -> anyhow::Result<()> {
        let (mut archive, input) = bounded_tar_archive(name, bytes);
        let mut expansion = ArchiveExpansion::new(self.archive);
        for (index, entry) in archive.entries()?.enumerate() {
            if index >= MAX_ARCHIVE_EXTRACT_ENTRIES {
                return Err(too_many_archive_entries(self.archive));
            }
            let mut entry = input.entry(self.archive, entry)?;
            let raw_name = tar_entry_name(&entry)?;
            let entry_type = entry.header().entry_type();
            let kind = if entry_type.is_dir() {
                ArchiveEntryKind::Folder
            } else if entry_type.is_file() {
                ArchiveEntryKind::File
            } else {
                ArchiveEntryKind::Other
            };
            let size = entry.size();
            self.entry(&mut expansion, &raw_name, kind, size, &mut entry, write)?;
        }
        Ok(())
    }

    fn zip(&self, bytes: &[u8], write: bool) -> anyhow::Result<()> {
        let mut archive = ZipArchive::new(Cursor::new(bytes))
            .map_err(|err| anyhow!("invalid ZIP archive: {err}"))?;
        if archive.len() > MAX_ARCHIVE_EXTRACT_ENTRIES {
            return Err(too_many_archive_entries(self.archive));
        }
        let mut expansion = ArchiveExpansion::new(self.archive);
        for index in 0..archive.len() {
            let mut file = archive
                .by_index(index)
                .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?;
            let raw_name = file
                .name()
                .map_err(|err| anyhow!("invalid ZIP archive entry: {err}"))?
                .into_owned();
            let kind = if file.is_dir() {
                ArchiveEntryKind::Folder
            } else if file.is_file() {
                ArchiveEntryKind::File
            } else {
                ArchiveEntryKind::Other
            };
            let size = file.size();
            self.entry(&mut expansion, &raw_name, kind, size, &mut file, write)?;
        }
        Ok(())
    }

    /// One entry: every rule, then, when `write`, its folder or file. A file
    /// is admitted by its declared size before any byte is read.
    fn entry(
        &self,
        expansion: &mut ArchiveExpansion<'_>,
        raw_name: &str,
        kind: ArchiveEntryKind,
        size: u64,
        reader: &mut impl std::io::Read,
        write: bool,
    ) -> anyhow::Result<()> {
        let Some(entry_target) = self.entry_target(raw_name, kind)? else {
            return expansion.pass_over(size);
        };
        let shown = crate::auth::printable_text(raw_name);
        match kind {
            ArchiveEntryKind::Folder => {
                expansion.pass_over(size)?;
                if write {
                    fs::create_dir_all(&entry_target.path)?;
                }
            }
            _ if !write => expansion.admit(&shown, size)?,
            _ => {
                let entry_bytes = expansion.read(&shown, size, reader)?;
                if let Some(parent) = entry_target.path.parent() {
                    fs::create_dir_all(parent)?;
                }
                crate::auth::write_principal_root_object(
                    self.data_dir,
                    self.principal_id,
                    &entry_target.localhost_root,
                    &entry_target.uri,
                    &entry_target.path,
                    &entry_bytes,
                )?;
            }
        }
        Ok(())
    }

    /// Where an entry is written, after every rule; `None` for the archive
    /// root itself.
    fn entry_target(
        &self,
        raw_name: &str,
        kind: ArchiveEntryKind,
    ) -> anyhow::Result<Option<LibraryTarget>> {
        let entry_path = archive_entry_path(raw_name)?;
        let entry_uri = archive_entry_uri(&self.destination.uri, Path::new(&entry_path))?;
        if entry_uri == self.destination.uri {
            return Ok(None);
        }
        match kind {
            ArchiveEntryKind::Folder => self.rule.folder(&entry_uri)?,
            ArchiveEntryKind::File => self.rule.file(&entry_uri)?,
            ArchiveEntryKind::Other => {
                bail!("library archive extraction rejects non-file archive entries")
            }
        }
        library_target(self.data_dir, self.principal_id, &entry_uri).map(Some)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveEntryKind {
    File,
    Folder,
    Other,
}

/// `archive` is already printable.
fn too_many_archive_entries(archive: &str) -> anyhow::Error {
    anyhow!(
        "{archive} holds more than {MAX_ARCHIVE_EXTRACT_ENTRIES} entries; Library extracts from \
         archives of up to {MAX_ARCHIVE_EXTRACT_ENTRIES} entries."
    )
}

/// What one archive expands to while a reader passes over it (#449): each
/// file kept is at most `MAX_ARCHIVE_ENTRY_BYTES`, and every entry passed
/// over or kept adds up to at most `MAX_ARCHIVE_EXPANDED_BYTES`. Sizes are
/// checked as the archive declares them, before any byte is read, and again
/// as bytes arrive, so a size that lies cannot allocate more.
struct ArchiveExpansion<'a> {
    /// Printable, for refusals.
    archive: &'a str,
    bytes: u64,
    /// Bytes the kept files may still add up to, when the caller holds
    /// every kept file in memory (Spaces write-back).
    keep_left: Option<u64>,
}

impl<'a> ArchiveExpansion<'a> {
    fn new(archive: &'a str) -> Self {
        Self {
            archive,
            bytes: 0,
            keep_left: None,
        }
    }

    /// Kept files add up to at most `budget`; it is enforced while reading.
    fn with_keep_budget(archive: &'a str, budget: u64) -> Self {
        Self {
            keep_left: Some(budget),
            ..Self::new(archive)
        }
    }

    /// Bytes the reader expands to pass over an entry it does not keep.
    fn pass_over(&mut self, size: u64) -> anyhow::Result<()> {
        self.bytes = self.bytes.saturating_add(size);
        if self.bytes > MAX_ARCHIVE_EXPANDED_BYTES {
            return Err(archive_too_large(self.archive));
        }
        Ok(())
    }

    /// A file entry to be kept, by its declared size. `entry` is printable.
    fn admit(&mut self, entry: &str, declared: u64) -> anyhow::Result<()> {
        if declared > MAX_ARCHIVE_ENTRY_BYTES {
            return Err(self.entry_too_large(entry));
        }
        if self.keep_left.is_some_and(|left| declared > left) {
            return Err(self.kept_too_large());
        }
        self.pass_over(declared)
    }

    /// Reads a kept file entry: admitted by its declared size first, then
    /// read at most one byte past the entry limit or the remaining keep
    /// budget, whichever is smaller.
    fn read(
        &mut self,
        entry: &str,
        declared: u64,
        reader: &mut impl std::io::Read,
    ) -> anyhow::Result<Vec<u8>> {
        self.admit(entry, declared)?;
        let limit = MAX_ARCHIVE_ENTRY_BYTES.min(self.keep_left.unwrap_or(u64::MAX));
        let mut bytes = Vec::new();
        reader.take(limit + 1).read_to_end(&mut bytes)?;
        let actual = bytes.len() as u64;
        if actual > MAX_ARCHIVE_ENTRY_BYTES {
            return Err(self.entry_too_large(entry));
        }
        if let Some(left) = self.keep_left {
            if actual > left {
                return Err(self.kept_too_large());
            }
            self.keep_left = Some(left - actual);
        }
        self.pass_over(actual.saturating_sub(declared))?;
        Ok(bytes)
    }

    fn entry_too_large(&self, entry: &str) -> anyhow::Error {
        anyhow!(
            "{entry} in {} would be more than {} MiB once extracted; Library extracts files of up \
             to {} MiB from an archive.",
            self.archive,
            MAX_ARCHIVE_ENTRY_BYTES / (1024 * 1024),
            MAX_ARCHIVE_ENTRY_BYTES / (1024 * 1024),
        )
    }

    fn kept_too_large(&self) -> anyhow::Error {
        anyhow!(
            "The files selected in {} are more than {} MiB; Spaces takes up to {} MiB from one \
             archive at a time. Select fewer files.",
            self.archive,
            MAX_ARCHIVE_SPACES_WRITE_BACK_BYTES / (1024 * 1024),
            MAX_ARCHIVE_SPACES_WRITE_BACK_BYTES / (1024 * 1024),
        )
    }
}

/// `archive` is printable.
fn archive_too_large(archive: &str) -> anyhow::Error {
    anyhow!(
        "{archive} would be more than {} MiB once extracted; Library extracts up to {} MiB from \
         one archive.",
        MAX_ARCHIVE_EXPANDED_BYTES / (1024 * 1024),
        MAX_ARCHIVE_EXPANDED_BYTES / (1024 * 1024),
    )
}

/// Header bytes a tar reader may expand between two entries: the next
/// entry's header block with its GNU long name, long link and PAX records.
/// The tar crate reads those records whole into memory before it yields the
/// entry, so the decompressed input itself is bounded (#449).
const MAX_TAR_ENTRY_HEADER_BYTES: u64 = 1024 * 1024;
/// Header bytes a tar reader may expand in one archive, on top of
/// `MAX_ARCHIVE_EXPANDED_BYTES` of entry contents.
const MAX_TAR_HEADER_BYTES: u64 = 64 * 1024 * 1024;

/// A tar archive over input that stops at its limits.
fn bounded_tar_archive<'a>(
    name: &str,
    bytes: &'a [u8],
) -> (
    tar::Archive<BoundedTarInput<'a>>,
    std::rc::Rc<TarInputBudget>,
) {
    let inner: Box<dyn std::io::Read + 'a> = if name.to_ascii_lowercase().ends_with(".tar") {
        Box::new(Cursor::new(bytes))
    } else {
        Box::new(GzDecoder::new(Cursor::new(bytes)))
    };
    let budget = std::rc::Rc::new(TarInputBudget {
        entry_left: std::cell::Cell::new(MAX_TAR_ENTRY_HEADER_BYTES),
        total_left: std::cell::Cell::new(MAX_ARCHIVE_EXPANDED_BYTES + MAX_TAR_HEADER_BYTES),
        reached: std::cell::Cell::new(None),
    });
    let input = BoundedTarInput {
        inner,
        budget: budget.clone(),
    };
    (tar::Archive::new(input), budget)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TarInputLimit {
    Header,
    Archive,
}

/// What a tar reader may still expand: until the next entry (its body,
/// padded to whole blocks, and the next header), and in all.
struct TarInputBudget {
    entry_left: std::cell::Cell<u64>,
    total_left: std::cell::Cell<u64>,
    reached: std::cell::Cell<Option<TarInputLimit>>,
}

impl TarInputBudget {
    /// An entry from the archive's iterator. A yielded entry opens the
    /// budget for its body and the next header; an error at a limit is
    /// replaced by the named refusal. A sparse entry, GNU (`S`) or PAX
    /// (`GNU.sparse.*` attributes), is refused: its size is not the bytes the
    /// archive stores, and this reader does not rebuild its contents.
    /// `archive` is printable.
    fn entry<'e, T>(
        &self,
        archive: &str,
        entry: std::io::Result<tar::Entry<'e, T>>,
    ) -> anyhow::Result<tar::Entry<'e, T>>
    where
        T: std::io::Read,
    {
        match entry {
            Ok(mut entry) => {
                // Inspecting a global PAX entry reads its body here, so
                // those bytes are charged to the allowance set below.
                let before = self.total_left.get();
                let sparse = is_sparse_tar_entry(&mut entry)
                    .map_err(|err| self.limit_error(archive).unwrap_or(err))?;
                if sparse {
                    bail!(
                        "{archive} holds a sparse file entry; Library does not open archives \
                         like that."
                    );
                }
                let inspected = before - self.total_left.get();
                self.entry_left.set(
                    entry
                        .size()
                        .div_ceil(512)
                        .saturating_mul(512)
                        .saturating_add(MAX_TAR_ENTRY_HEADER_BYTES)
                        .saturating_sub(inspected),
                );
                Ok(entry)
            }
            Err(err) => Err(self.limit_error(archive).unwrap_or_else(|| err.into())),
        }
    }

    /// The named refusal when a read stopped at a limit. `archive` is
    /// printable.
    fn limit_error(&self, archive: &str) -> Option<anyhow::Error> {
        Some(match self.reached.get()? {
            TarInputLimit::Archive => archive_too_large(archive),
            TarInputLimit::Header => anyhow!(
                "{archive} holds an entry name or header of more than {} MiB; Library does not \
                 open archives like that.",
                MAX_TAR_ENTRY_HEADER_BYTES / (1024 * 1024),
            ),
        })
    }
}

fn is_sparse_tar_entry<T: std::io::Read>(entry: &mut tar::Entry<'_, T>) -> anyhow::Result<bool> {
    if entry.header().entry_type().is_gnu_sparse() {
        return Ok(true);
    }
    let Some(extensions) = entry.pax_extensions()? else {
        return Ok(false);
    };
    for extension in extensions {
        if extension?.key_bytes().starts_with(b"GNU.sparse.") {
            return Ok(true);
        }
    }
    Ok(false)
}

struct BoundedTarInput<'a> {
    inner: Box<dyn std::io::Read + 'a>,
    budget: std::rc::Rc<TarInputBudget>,
}

impl std::io::Read for BoundedTarInput<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let entry_left = self.budget.entry_left.get();
        let total_left = self.budget.total_left.get();
        let left = entry_left.min(total_left);
        if left == 0 && !buf.is_empty() {
            self.budget.reached.set(Some(if total_left == 0 {
                TarInputLimit::Archive
            } else {
                TarInputLimit::Header
            }));
            return Err(std::io::Error::other("archive expansion limit reached"));
        }
        let max = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buf[..max])?;
        self.budget.entry_left.set(entry_left - read as u64);
        self.budget.total_left.set(total_left - read as u64);
        Ok(read)
    }
}

fn archive_entry_uri(destination_uri: &str, path: &Path) -> anyhow::Result<String> {
    let mut uri = destination_uri.trim_end_matches('/').to_string();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| anyhow!("library archive entry path must be UTF-8"))?;
                uri = child_uri(&uri, name)?;
            }
            _ => bail!("library archive entry path must be relative and safe"),
        }
    }
    Ok(uri)
}

fn is_extractable_archive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".tar")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".zip")
}

fn archive_family_for_name(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some("tar.gz")
    } else if name.ends_with(".tar") {
        Some("tar")
    } else if name.ends_with(".zip") {
        Some("zip")
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        Some("tar.xz")
    } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        Some("tar.bz2")
    } else if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
        Some("tar.zst")
    } else if name.ends_with(".rar") {
        Some("rar")
    } else if name.ends_with(".7z") {
        Some("7z")
    } else if name.ends_with(".xz") {
        Some("xz")
    } else if name.ends_with(".bz2") {
        Some("bz2")
    } else if name.ends_with(".zst") {
        Some("zst")
    } else if name.ends_with(".lz4") {
        Some("lz4")
    } else if name.ends_with(".gz") {
        Some("gzip")
    } else {
        None
    }
}

fn archive_support_for_name(name: &str) -> Option<Value> {
    let family = archive_family_for_name(name)?;
    let extractable = is_extractable_archive_name(name);
    Some(json!({
        "schema": "elastos.library.archive-support/v1",
        "family": family,
        "status": if extractable {
            "extractable"
        } else {
            "policy_gated_unsupported_archive_family"
        },
        "implemented": {
            "download_formats": ["zip", "tar.gz"],
            "compress_to_library": ["zip"],
            "extract_formats": ["zip", "tar", "tar.gz", "tgz"],
            "safety": "relative UTF-8 file paths only; non-file archive entries are rejected"
        },
        "policy_gate": if extractable {
            Value::Null
        } else {
            json!({
                "required": true,
                "reason": "generic archive support needs dependency and release-policy review before enabling",
                "blocked_formats": ["7z", "rar", "tar.xz", "tar.bz2", "tar.zst", "xz", "bz2", "zst", "lz4", "gzip"]
            })
        }
    }))
}

fn archive_extract_folder_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let stem = if lower.ends_with(".tar.gz") {
        &name[..name.len().saturating_sub(".tar.gz".len())]
    } else if lower.ends_with(".tgz") {
        &name[..name.len().saturating_sub(".tgz".len())]
    } else if lower.ends_with(".tar") {
        &name[..name.len().saturating_sub(".tar".len())]
    } else if lower.ends_with(".zip") {
        &name[..name.len().saturating_sub(".zip".len())]
    } else {
        name
    };
    let stem = stem.trim().trim_matches('.');
    if stem.is_empty() {
        "Extracted Archive".to_string()
    } else {
        stem.to_string()
    }
}

fn append_library_archive_entry(
    builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    archive_path: &Path,
) -> anyhow::Result<()> {
    let metadata = fs::metadata(&target.path)?;
    if metadata.is_dir() {
        builder.append_dir(archive_path, &target.path)?;
        for entry in fs::read_dir(&target.path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let child_uri = format!("{}/{}", target.uri, name);
            let child_target = library_target(data_dir, principal_id, &child_uri)?;
            let child_archive_path = archive_path.join(safe_archive_name(&name));
            append_library_archive_entry(
                builder,
                data_dir,
                principal_id,
                &child_target,
                &child_archive_path,
            )?;
        }
        return Ok(());
    }
    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    if let Some(modified) = system_time_secs(metadata.modified().ok()) {
        header.set_mtime(modified);
    }
    header.set_cksum();
    let mut data = bytes.as_slice();
    builder.append_data(&mut header, archive_path, &mut data)?;
    Ok(())
}

fn append_library_zip_entry(
    writer: &mut ZipWriter<Cursor<Vec<u8>>>,
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    archive_path: &Path,
) -> anyhow::Result<()> {
    let metadata = fs::metadata(&target.path)?;
    if metadata.is_dir() {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.add_directory(zip_archive_entry_name(archive_path, true)?, options)?;
        for entry in fs::read_dir(&target.path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let child_uri = format!("{}/{}", target.uri, name);
            let child_target = library_target(data_dir, principal_id, &child_uri)?;
            let child_archive_path = archive_path.join(safe_archive_name(&name));
            append_library_zip_entry(
                writer,
                data_dir,
                principal_id,
                &child_target,
                &child_archive_path,
            )?;
        }
        return Ok(());
    }
    let bytes = read_library_file_bytes(data_dir, principal_id, target)?;
    let options = zip_file_options_for_entry(archive_path, bytes.len());
    writer.start_file(zip_archive_entry_name(archive_path, false)?, options)?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn zip_file_options_for_entry(path: &Path, size: usize) -> zip::write::SimpleFileOptions {
    let method = if should_store_zip_entry(path, size) {
        zip::CompressionMethod::Stored
    } else {
        zip::CompressionMethod::Deflated
    };
    zip::write::SimpleFileOptions::default().compression_method(method)
}

fn should_store_zip_entry(path: &Path, size: usize) -> bool {
    if size < 1024 {
        return true;
    }
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "zip"
            | "gz"
            | "tgz"
            | "7z"
            | "rar"
            | "xz"
            | "bz2"
            | "zst"
            | "lz4"
            | "mp4"
            | "mov"
            | "mkv"
            | "webm"
            | "mp3"
            | "aac"
            | "ogg"
            | "flac"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "avif"
            | "pdf"
    )
}

fn zip_archive_entry_name(path: &Path, directory: bool) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| anyhow!("library ZIP archive entry path must be UTF-8"))?;
                if !name.is_empty() {
                    parts.push(name);
                }
            }
            Component::CurDir => {}
            _ => bail!("library ZIP archive entry path must be relative and safe"),
        }
    }
    let mut name = parts.join("/");
    if name.is_empty() {
        bail!("library ZIP archive entry path must not be empty");
    }
    if directory && !name.ends_with('/') {
        name.push('/');
    }
    Ok(name)
}

fn safe_archive_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '\0' => '_',
            _ => ch,
        })
        .collect();
    let sanitized = sanitized.trim().trim_matches('.').to_string();
    if sanitized.is_empty() {
        "Library".to_string()
    } else {
        sanitized
    }
}

fn is_runtime_private_uri(localhost_root: &str, uri: &str) -> bool {
    uri == format!("{localhost_root}/.AppData")
        || uri
            .strip_prefix(&format!("{localhost_root}/.AppData/"))
            .is_some()
        || is_trash_uri(localhost_root, uri)
}

pub(crate) fn principal_root_protected_object_inventory(
    localhost_root: &str,
) -> Vec<crate::auth::PrincipalRootProtectedObjectDeclarationV1> {
    [
        "Desktop",
        "Documents",
        "Pictures",
        "Videos",
        "Music",
        "Downloads",
        "Public",
        ".Trash",
        ".AppData/LocalHost/.Runtime/Library",
    ]
    .into_iter()
    .map(|relative| {
        crate::auth::PrincipalRootProtectedObjectDeclarationV1::root(format!(
            "{localhost_root}/{relative}"
        ))
    })
    .collect()
}

fn record_is_published(record: &LibraryPublishRecord) -> bool {
    record.unpublished_at.is_none()
        && record
            .availability
            .get("status")
            .and_then(Value::as_str)
            .map(|status| status != "local_unpinned")
            .unwrap_or(true)
}

fn default_publish_content_security() -> Value {
    json!({
        "schema": "elastos.library.published-content-security/v1",
        "source_storage": "unknown",
        "published_payload": "plain_content",
        "key_release_required": false,
        "status": "plain_published_content",
        "protected_content": "runtime_custody_publish_only",
    })
}

fn default_share_key_release() -> Value {
    json!({
        "schema": "elastos.library.key-release/v1",
        "required": false,
        "status": "not_required_for_plain_published_content",
        "protected_content": "runtime_custody_publish_only",
        "next": "Library share carries plain published content. Protected content is published through Runtime custody and opened in the viewer, not shared through a key-release policy."
    })
}

/// Reports how far this object's publish has got, without disturbing it.
///
/// The publish itself is one long blocking request, so this is the only way
/// the page can learn which stage it is in while that request is still open.
/// It reads the mint journal and nothing else: no provider call, no wallet
/// authority, no write. An object that was never protected simply has no
/// progress to report, which is not an error.
fn library_publish_progress(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
) -> anyhow::Result<Value> {
    let target = library_target(data_dir, principal_id, uri)?;
    let source_storage = published_source_storage(data_dir, principal_id, &target)?.to_string();
    let progress = crate::protected_content_runtime::runtime_custody_publish_progress(
        data_dir,
        principal_id,
        &target.uri,
        &source_storage,
    )?;
    Ok(json!({
        "uri": target.uri,
        "progress": progress,
    }))
}

fn published_source_storage(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<&'static str> {
    if crate::auth::load_principal_root_protection(data_dir, principal_id, &target.localhost_root)?
        .is_some()
    {
        Ok("protected_principal_root")
    } else {
        Ok("plain_localhost_root")
    }
}

fn record_is_runtime_custody(record: &LibraryPublishRecord) -> bool {
    record
        .content_security
        .get("published_payload")
        .and_then(Value::as_str)
        == Some(RUNTIME_CUSTODY_PUBLISHED_PAYLOAD)
}

/// The Library folder a freshly minted protected item is filed under, so it
/// lands where the shelf for its kind already is: images in Pictures, video in
/// Videos, audio in Music, and everything else -- PDF, text, EPUB, 3D, source
/// -- in Documents.
///
/// Placement keys off the ORIGINAL asset mime, never off the on-disk name: the
/// item written is a `.ddrm` capsule whose own extension says nothing about
/// what it protects. Every folder named here must also be a `library_roots`
/// entry, or the item lands somewhere the sidebar cannot reach.
/// A capsule is a JSON document; its `.ddrm` suffix names the kind of item it
/// is, not a media type the Library can render on its own.
const RUNTIME_CUSTODY_CAPSULE_MIME: &str = "application/json";
/// How many names a capsule tries before giving up, so a collision suffixes
/// rather than overwrites and a pathological loop still terminates.
const RUNTIME_CUSTODY_CAPSULE_NAME_ATTEMPTS: usize = 64;
/// A capsule is a small JSON document. Anything larger is not one, and is not
/// read into memory to find out.
const RUNTIME_CUSTODY_CAPSULE_MAX_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn library_folder_for_mime(mime: &str) -> &'static str {
    let mime = mime.trim().to_ascii_lowercase();
    if mime.starts_with("image/") {
        "Pictures"
    } else if mime.starts_with("video/") {
        "Videos"
    } else if mime.starts_with("audio/") {
        "Music"
    } else {
        "Documents"
    }
}

/// The Library name for a minted capsule: the source object's name with its
/// original extension dropped, since the capsule carries the real MIME in its
/// record and its own `.ddrm` suffix is what names the kind of file it is.
fn runtime_custody_capsule_base_name(display_name: &str) -> String {
    // `file_stem` drops the source extension and, on anything that still looks
    // like a path, keeps only the final segment -- so a name can never walk out
    // of the folder the capsule is being filed into.
    let stem = Path::new(display_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let cleaned = stem
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '/' | '\\' | ':') {
                '-'
            } else {
                ch
            }
        })
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() || cleaned.chars().all(|ch| ch == '.') {
        "protected-content".to_string()
    } else {
        cleaned
    }
}

/// Write the minted asset into the Library as a `.ddrm` capsule, filed on the
/// shelf its kind belongs to, and answer the URI it landed at.
///
/// The capsule is the openable item: it carries the mint identity the viewer
/// binds a session to, and it names the encrypted content by CID rather than
/// carrying any of it, so no plaintext and no second copy of the ciphertext
/// comes to rest here. The creator's original file is left exactly where it
/// was -- publishing is not a reason to move or delete someone's file.
///
/// A name already taken is suffixed rather than overwritten, so minting the
/// same source twice produces two items instead of silently replacing one.
/// Write an owned protected item into the Library as a `.ddrm` capsule, filed
/// on the shelf its kind belongs to, and answer the URI it landed at.
///
/// The capsule is the openable item and describes itself: the caller builds the
/// document (see `runtime_custody_capsule_document`), and this places it. Which
/// shelf is decided by what the capsule protects, never by its own `.ddrm`
/// extension, which says nothing about whether it holds a film or a PDF.
///
/// Whatever the item was made from is left alone -- acquiring an asset is not a
/// reason to move or delete someone's file. A name already taken is suffixed
/// rather than overwritten, so owning the same asset twice produces two items
/// instead of silently replacing one.
/// Every shelf a capsule can be filed on, which is every folder
/// `library_folder_for_mime` can answer.
///
/// The trash is deliberately not among them: a capsule the person threw away
/// is not one to resurrect and rewrite in place. Owning that asset again puts
/// a fresh item back on a shelf, which is what throwing it away asked for.
const RUNTIME_CUSTODY_CAPSULE_SHELVES: [&str; 4] = ["Pictures", "Videos", "Music", "Documents"];

/// Where this mint's capsule is already filed, if it is.
///
/// Reads each candidate's own identity rather than guessing from its name: a
/// capsule's file name comes from the source object, so two different assets
/// can share one, and the same asset can be filed under a name that no longer
/// matches anything. The mint id inside the document is what actually says
/// "this is that asset".
fn runtime_custody_capsule_uri_for_mint(
    data_dir: &Path,
    principal_id: &str,
    mint_id: &str,
) -> Option<String> {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    for folder in RUNTIME_CUSTODY_CAPSULE_SHELVES {
        let folder_uri = format!("{localhost_root}/{folder}");
        let Ok(folder_target) = library_target(data_dir, principal_id, &folder_uri) else {
            continue;
        };
        let Ok(entries) = fs::read_dir(&folder_target.path) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.to_ascii_lowercase().ends_with(".ddrm") {
                continue;
            }
            let uri = format!("{folder_uri}/{name}");
            let Ok(target) = library_target(data_dir, principal_id, &uri) else {
                continue;
            };
            let Some(identity) =
                runtime_custody_capsule_identity_metadata(data_dir, principal_id, &target, &name)
            else {
                continue;
            };
            if identity.get("mint_id").and_then(Value::as_str) == Some(mint_id) {
                return Some(uri);
            }
        }
    }
    None
}

pub(crate) fn write_runtime_custody_capsule(
    data_dir: &Path,
    principal_id: &str,
    display_name: &str,
    content_type: &str,
    capsule: &Value,
) -> anyhow::Result<String> {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let folder = library_folder_for_mime(content_type);
    let base = runtime_custody_capsule_base_name(display_name);
    let bytes = serde_json::to_vec_pretty(capsule)?;
    // Owning the same asset again is the same item, not a second one. The
    // repair path re-files a capsule for an asset that already has one, and
    // suffixing there leaves the person with two files where only one is
    // current -- and the ownership record pointing at whichever was written
    // last. Rewrite the capsule already filed for this mint instead.
    if let Some(mint_id) = capsule
        .get("mintId")
        .and_then(Value::as_str)
        .filter(|mint_id| !mint_id.is_empty())
    {
        if let Some(existing) =
            runtime_custody_capsule_uri_for_mint(data_dir, principal_id, mint_id)
        {
            write_library_file_bytes(
                data_dir,
                principal_id,
                &existing,
                Some(RUNTIME_CUSTODY_CAPSULE_MIME),
                None,
                false,
                &bytes,
            )?;
            return Ok(existing);
        }
    }
    let mut last_error = None;
    for attempt in 1..=RUNTIME_CUSTODY_CAPSULE_NAME_ATTEMPTS {
        let name = if attempt == 1 {
            format!("{base}.ddrm")
        } else {
            format!("{base} ({attempt}).ddrm")
        };
        let uri = format!("{localhost_root}/{folder}/{name}");
        match write_library_file_bytes(
            data_dir,
            principal_id,
            &uri,
            Some(RUNTIME_CUSTODY_CAPSULE_MIME),
            None,
            true,
            &bytes,
        ) {
            Ok(_) => return Ok(uri),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("library could not write the protected capsule")))
}

/// What a `.ddrm` says about itself.
///
/// A capsule is the item for an owned protected asset however it was acquired,
/// and a buyer never publishes anything -- so there is no publish record to
/// read this from, and inventing one would assert a publish that never
/// happened. The capsule is self-describing instead, which is also what lets an
/// asset be repaired by writing its file.
///
/// Nothing here is trusted as authority. It decides which viewer opens and what
/// the Library shows; whether this principal may open it at all is the
/// entitlement check, which answers from the chain. A hand-written capsule
/// therefore buys nothing: it can only name a mint whose open is refused.
fn runtime_custody_capsule_identity_metadata(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    name: &str,
) -> Option<Value> {
    if !name.to_ascii_lowercase().ends_with(".ddrm") {
        return None;
    }
    let metadata = fs::metadata(&target.path).ok()?;
    if !metadata.is_file() || metadata.len() > RUNTIME_CUSTODY_CAPSULE_MAX_BYTES {
        return None;
    }
    // Read it the way the Library reads any of its files: what is on disk is a
    // principal-root object carrying the document, not the document itself.
    let capsule: Value =
        serde_json::from_slice(&read_library_file_bytes(data_dir, principal_id, target).ok()?)
            .ok()?;
    if capsule.get("schema").and_then(Value::as_str)
        != Some(crate::protected_content_runtime::RUNTIME_CUSTODY_CAPSULE_SCHEMA_V1)
    {
        return None;
    }
    // Capsules written before the metadata document was embedded spell these
    // in snake_case. They are on real disks and must keep opening, so both
    // spellings are read rather than migrating every file to find out.
    let field = |camel: &str, snake: &str| {
        capsule
            .get(camel)
            .or_else(|| capsule.get(snake))
            .cloned()
            .unwrap_or(Value::Null)
    };
    Some(json!({
        "schema": "elastos.library.protected-content-identity/v1",
        "content_id": field("contentId", "content_id"),
        "mint_id": field("mintId", "mint_id"),
        "kid": field("kid", "kid"),
        "token_id": field("tokenId", "token_id"),
        "ledger": field("ledger", "ledger"),
        "authority": field("authority", "authority"),
        "asset_mime": field("contentType", "asset_mime"),
        "acquisition": field("acquisition", "acquisition"),
        "published_cid": field("contentCid", "content_cid"),
    }))
}

fn runtime_custody_library_identity_metadata(record: &LibraryPublishRecord) -> Option<Value> {
    record_is_runtime_custody(record).then(|| {
        json!({
            "schema": "elastos.library.protected-content-identity/v1",
            "content_id": record.content_security.get("content_id"),
            "mint_id": record.content_security.get("mint_id"),
            "published_cid": record.cid,
            "availability": record.availability,
        })
    })
}

fn published_content_security(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<Value> {
    Ok(json!({
        "schema": "elastos.library.published-content-security/v1",
        "object_uri": target.uri,
        "source_storage": published_source_storage(data_dir, principal_id, target)?,
        "published_payload": "plain_content",
        "key_release_required": false,
        "status": "plain_published_content",
        "protected_content": "runtime_custody_publish_only",
        "next": "Publishing materializes a plain content payload through content-provider. Protected content is published through Runtime custody publish."
    }))
}

fn validate_runtime_custody_publish_input(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
    protection: LibraryPublishProtectionRequest,
) -> anyhow::Result<LoadedRuntimeCustodyPublishInput> {
    let LibraryPublishProtectionRequest::RuntimeCustody {
        copies,
        price,
        channel,
        pay_token,
        listing,
        new_attempt,
        pool_did,
    } = protection
    else {
        bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
    };
    // The channel is the creator's choice and there is no default to fall back
    // on. Publishing into whichever channel a deployment happens to name is
    // the behaviour this replaces, so a mint that names none is refused here
    // rather than quietly settling somewhere.
    let channel = channel.trim().to_ascii_lowercase();
    if !is_evm_address(&channel) {
        bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
    }
    let pay_token = match pay_token.as_deref().map(str::trim) {
        None | Some("") => String::new(),
        Some(pay_token) => {
            let pay_token = pay_token.to_ascii_lowercase();
            if !is_evm_address(&pay_token) {
                bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
            }
            pay_token
        }
    };
    let target_metadata = fs::symlink_metadata(&target.path)
        .map_err(|_| anyhow!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE))?;
    if target_metadata.file_type().is_symlink() || !target_metadata.is_file() {
        bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
    }
    let _ = (data_dir, principal_id);
    let listing = listing.map(validate_runtime_custody_listing).transpose()?;
    let pool_did = pool_did
        .map(|did| did.trim().to_string())
        .filter(|did| !did.is_empty());
    if pool_did.as_deref().is_some_and(|did| {
        elastos_protected_content_contracts::PoolDidV1::parse_did_key(did).is_err()
    }) {
        bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
    }
    Ok(LoadedRuntimeCustodyPublishInput {
        copies,
        price,
        channel,
        pay_token,
        listing,
        new_attempt,
        pool_did,
    })
}

/// The publish input a resume runs with, read from the mint's own record.
///
/// The creator tail takes its terms from the record when resuming and reads
/// none of these; they are filled from it only so that every stage before the
/// tail sees the same terms the record holds rather than blanks.
fn resumed_runtime_custody_publish_input(
    data_dir: &Path,
    principal_id: &str,
    target: &LibraryTarget,
) -> anyhow::Result<LoadedRuntimeCustodyPublishInput> {
    let source_storage = published_source_storage(data_dir, principal_id, target)?;
    let recorded = crate::protected_content_runtime::runtime_custody_recorded_creator_terms(
        data_dir,
        principal_id,
        &target.uri,
        source_storage,
    )?;
    Ok(LoadedRuntimeCustodyPublishInput {
        copies: recorded.copies().to_string(),
        price: recorded.price().to_string(),
        channel: recorded.ledger().to_string(),
        pay_token: recorded.pay_token().to_string(),
        listing: None,
        new_attempt: false,
        // A resume keeps the pool its intent recorded (S7-lite T7.6).
        pool_did: None,
    })
}

/// `0x` followed by exactly 40 hex digits.
fn is_evm_address(value: &str) -> bool {
    let Some(body) = value.strip_prefix("0x") else {
        return false;
    };
    body.len() == 40 && body.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Validate creator-supplied listing terms, failing closed on each rule.
///
/// Every one of these is a claim the listing will make publicly, so an invalid
/// one is refused rather than normalised: a silently corrected royalty split or
/// a dropped over-size thumbnail produces a listing that says something the
/// creator did not ask for. Nothing here is logged — it is the creator's own
/// title, description and payees.
fn validate_runtime_custody_listing(
    listing: LibraryPublishListingRequest,
) -> anyhow::Result<RuntimeCustodyListingTerms> {
    let title = listing.title.trim().to_string();
    if title.is_empty() {
        bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
    }

    let thumbnail = match listing.thumbnail {
        None => None,
        Some(thumbnail) => {
            let mime = thumbnail.mime.trim().to_ascii_lowercase();
            if !mime.starts_with("image/") {
                bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(thumbnail.bytes_base64.trim())
                .map_err(|_| anyhow!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE))?;
            if bytes.is_empty() || bytes.len() > RUNTIME_CUSTODY_THUMBNAIL_MAX_BYTES {
                bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
            }
            Some(RuntimeCustodyListingThumbnail { mime, bytes })
        }
    };

    // An empty split is not "no royalties": it is a caller that did not say.
    // Absent stays absent; present must be exactly what the chain applies.
    let mut royalties = Vec::with_capacity(listing.royalties.len());
    if !listing.royalties.is_empty() {
        let mut total: u32 = 0;
        for royalty in listing.royalties {
            let address = royalty.address.trim().to_ascii_lowercase();
            // 0x + 40 lowercase hex. Kept local rather than reaching into the
            // gateway's wallet module: this validates a creator-supplied payee
            // for a metadata document, not a wallet the Runtime will act on.
            if !is_evm_address(&address) {
                bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
            }
            if royalty.units == 0 {
                bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
            }
            total = total
                .checked_add(royalty.units)
                .ok_or_else(|| anyhow!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE))?;
            royalties.push(RuntimeCustodyListingRoyalty {
                address,
                units: royalty.units,
            });
        }
        if total != RUNTIME_CUSTODY_ROYALTY_TOTAL_UNITS {
            bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
        }
    }

    let access_method = match listing.access_method.as_deref().map(str::trim) {
        None | Some("") | Some("buy_once") => {
            elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce
        }
        Some("free") => elastos_protected_content_runtime::RuntimeMintAccessMethod::Free,
        Some("buy_and_resell") => {
            elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyAndResell
        }
        Some(_) => bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE),
    };
    // The cut belongs to exactly one method. Anywhere else it would be
    // accepted and then never encoded; on resale its absence shifts the ABI
    // layout the operative factory decodes positionally.
    match (access_method, listing.reseller_cut) {
        (elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyAndResell, Some(cut))
            if cut <= elastos_protected_content_runtime::RUNTIME_MINT_RESELLER_CUT_MAX => {}
        (_, None)
            if access_method
                != elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyAndResell => {}
        _ => bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE),
    }
    // A free mint creates no operative, so it has no royalty share to split.
    if !access_method.is_paid() && !royalties.is_empty() {
        bail!(RUNTIME_CUSTODY_PUBLISH_INPUT_INVALID_MESSAGE);
    }

    Ok(RuntimeCustodyListingTerms {
        title,
        description: listing.description.trim().to_string(),
        category: listing.category.trim().to_string(),
        tags: listing
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        thumbnail,
        royalties,
        access_method,
        reseller_cut: listing.reseller_cut,

        adult: listing.adult,
        licensing: listing.licensing,
        legal_attestation: listing.legal_attestation,
    })
}

fn normalized_key_release_policy(policy: Option<&str>) -> anyhow::Result<Value> {
    match policy
        .map(str::trim)
        .filter(|policy| !policy.is_empty())
        .unwrap_or("auto")
    {
        "auto" | "none" | "plain_published_content" => Ok(default_share_key_release()),
        "recipient_key_release" | "protected_content" | "encrypted_recipient" => bail!(
            "protected content is published through Runtime custody publish; it is not a Library share key-release policy"
        ),
        _ => bail!("unsupported library key_release_policy"),
    }
}

fn record_availability_label(record: Option<&LibraryPublishRecord>) -> String {
    let Some(record) = record else {
        return "local-only".to_string();
    };
    record
        .availability
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or(if record_is_published(record) {
            "published"
        } else {
            "local_unpinned"
        })
        .to_string()
}

fn normalized_share_recipients(recipients: &[String]) -> anyhow::Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for recipient in recipients {
        let recipient = recipient.trim();
        if recipient.is_empty() {
            continue;
        }
        if recipient.len() > 256 || recipient.chars().any(char::is_control) {
            bail!("library share recipient is invalid");
        }
        if !(recipient.starts_with("did:")
            || recipient.starts_with("person:")
            || recipient.starts_with("principal:")
            || recipient.contains('@'))
        {
            bail!("library share recipient must be a DID, principal/person id, or address");
        }
        normalized.insert(recipient.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn normalized_share_policy(policy: Option<&str>, public_link: bool) -> anyhow::Result<String> {
    let default_policy = if public_link {
        "public_link"
    } else {
        "recipient_scoped"
    };
    let policy = policy
        .map(str::trim)
        .filter(|policy| !policy.is_empty())
        .unwrap_or(default_policy);
    match policy {
        "public_link" if public_link => Ok(policy.to_string()),
        "recipient_scoped" if !public_link => Ok(policy.to_string()),
        "public_link" => bail!("public_link share policy must not include recipients"),
        "recipient_scoped" => bail!("recipient_scoped share policy requires recipients"),
        _ => bail!("unsupported library share policy"),
    }
}

fn share_remote_enforcement_contract(policy: &str, key_release: &Value) -> Value {
    let recipient_proof_required = policy == "recipient_scoped";
    json!({
        "schema": "elastos.library.remote-access-policy/v1",
        "policy": policy,
        "provider_gate": "object-provider shared_access",
        "recipient_proof_required": recipient_proof_required,
        "key_release_required": false,
        "key_release_status": key_release
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("not_required_for_plain_published_content"),
        "plain_content_fetch": true,
        "status": if recipient_proof_required {
            "recipient_proof_enforced_by_runtime"
        } else {
            "public_link_ready"
        },
        "next": if recipient_proof_required {
            "Remote recipients must present a Runtime recipient proof before object-provider returns the shared open contract."
        } else {
            "Published plain content is available to holders of the content URI."
        }
    })
}

fn share_grant(
    recipient: &str,
    cid: &str,
    uri: &str,
    policy: &str,
    key_release: Value,
    created_at: u64,
) -> LibraryShareGrant {
    let digest = Sha256::digest(format!("{recipient}:{cid}:{policy}:{created_at}"));
    LibraryShareGrant {
        schema: "elastos.library.share-grant/v1".to_string(),
        grant_id: format!("share:{}", hex::encode(&digest[..16])),
        recipient: recipient.to_string(),
        uri: uri.to_string(),
        cid: cid.to_string(),
        policy: policy.to_string(),
        key_release,
        created_at,
    }
}

fn shared_access_receipt(
    record: &LibraryPublishRecord,
    recipient: &str,
    recipient_proof: Option<&Value>,
) -> anyhow::Result<Value> {
    let policy = record.share_policy.as_deref().unwrap_or("public_link");
    match policy {
        "public_link" => Ok(json!({
            "schema": "elastos.library.shared-access.receipt/v1",
            "policy": "public_link",
            "recipient": recipient.trim(),
            "grant_id": null,
            "content_security": record.content_security.clone(),
            "key_release": default_share_key_release(),
            "recipient_proof": shared_access_recipient_proof_state(recipient.trim(), false, "not_required_for_public_link", None, None),
            "decision": shared_access_decision("public_link", recipient.trim(), None, true, "public_link"),
            "open": shared_access_open_contract(record, "public_link", recipient.trim(), None, &default_share_key_release(), false)
        })),
        "recipient_scoped" => {
            let normalized = normalized_share_recipients(&[recipient.to_string()])?;
            let recipient = normalized
                .first()
                .ok_or_else(|| anyhow!("library shared_access recipient is required"))?;
            let grant = record
                .share_grants
                .iter()
                .find(|grant| grant.recipient == *recipient && grant.policy == "recipient_scoped")
                .ok_or_else(|| anyhow!("library shared_access recipient is not authorized"))?;
            let proof_state = validate_shared_access_recipient_proof(recipient, recipient_proof)?;
            Ok(json!({
                "schema": "elastos.library.shared-access.receipt/v1",
                "policy": "recipient_scoped",
                "recipient": recipient,
                "grant_id": grant.grant_id,
                "content_security": record.content_security.clone(),
                "key_release": grant.key_release.clone(),
                "recipient_proof": proof_state,
                "decision": shared_access_decision("recipient_scoped", recipient, Some(&grant.grant_id), true, "recipient grant and Runtime recipient proof matched"),
                "open": shared_access_open_contract(record, "recipient_scoped", recipient, Some(&grant.grant_id), &grant.key_release, true)
            }))
        }
        other => bail!("unsupported library share policy: {other}"),
    }
}

fn validate_shared_access_recipient_proof(
    recipient: &str,
    proof: Option<&Value>,
) -> anyhow::Result<Value> {
    let proof = proof.ok_or_else(|| {
        anyhow!(
            "library shared_access requires Runtime recipient_proof for recipient_scoped policy"
        )
    })?;
    let schema = proof
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("library shared_access recipient_proof requires schema"))?;
    if schema != "elastos.library.recipient-proof/v1" {
        bail!("library shared_access recipient_proof schema is unsupported");
    }
    let source = proof
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if source != "runtime-launch-grant" {
        bail!("library shared_access recipient_proof source is unsupported");
    }
    let proof_binding_id = proof
        .get("proof_binding_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!("library shared_access recipient_proof requires proof_binding_id")
        })?;
    if !proof_binding_id.starts_with("proof:passkey:") {
        bail!("library shared_access recipient_proof requires passkey proof binding");
    }
    let claimed = proof
        .get("recipient")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("library shared_access recipient_proof requires recipient"))?;
    let normalized_requested = normalized_share_recipients(&[recipient.to_string()])?;
    let normalized_claimed = normalized_share_recipients(&[claimed.to_string()])?;
    if normalized_requested.first() != normalized_claimed.first() {
        bail!("library shared_access recipient_proof recipient mismatch");
    }
    let session_id = proof
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    Ok(shared_access_recipient_proof_state(
        normalized_requested
            .first()
            .map(String::as_str)
            .unwrap_or(recipient),
        true,
        source,
        Some(proof_binding_id),
        session_id,
    ))
}

fn shared_access_recipient_proof_state(
    recipient: &str,
    verified: bool,
    source: &str,
    proof_binding_id: Option<&str>,
    session_id: Option<&str>,
) -> Value {
    json!({
        "schema": "elastos.library.recipient-proof-state/v1",
        "recipient": recipient,
        "verified": verified,
        "source": source,
        "proof_binding_id": proof_binding_id,
        "session_id": session_id,
    })
}

fn shared_access_decision(
    policy: &str,
    recipient: &str,
    grant_id: Option<&str>,
    allowed: bool,
    reason: &str,
) -> Value {
    json!({
        "schema": "elastos.library.access-decision/v1",
        "policy": policy,
        "recipient": recipient,
        "grant_id": grant_id,
        "allowed": allowed,
        "reason": reason,
    })
}

fn shared_access_open_contract(
    record: &LibraryPublishRecord,
    policy: &str,
    recipient: &str,
    grant_id: Option<&str>,
    key_release: &Value,
    recipient_proof_verified: bool,
) -> Value {
    json!({
        "schema": "elastos.library.shared-open/v1",
        "uri": format!("elastos://{}", record.cid),
        "cid": record.cid,
        "policy": policy,
        "recipient": recipient,
        "grant_id": grant_id,
        "provider": "content-provider",
        "transport": "runtime-provider-fetch",
        "published_payload": record
            .content_security
            .get("published_payload")
            .and_then(Value::as_str)
            .unwrap_or("plain_content"),
        "recipient_proof_verified": recipient_proof_verified,
        "key_release_required": false,
        "status": "ready_for_plain_content_fetch",
        "remote_enforcement": share_remote_enforcement_contract(policy, key_release),
    })
}

fn library_roots(data_dir: &Path, principal_id: &str) -> Vec<LibraryRoot> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let mut roots: Vec<_> = [
        ("home", "Home", root.clone(), "principal-root"),
        ("desktop", "Desktop", format!("{root}/Desktop"), "directory"),
        (
            "documents",
            "Documents",
            format!("{root}/Documents"),
            "directory",
        ),
        (
            "pictures",
            "Pictures",
            format!("{root}/Pictures"),
            "directory",
        ),
        ("videos", "Videos", format!("{root}/Videos"), "directory"),
        ("music", "Music", format!("{root}/Music"), "directory"),
        (
            "downloads",
            "Downloads",
            format!("{root}/Downloads"),
            "directory",
        ),
        ("public", "Public", format!("{root}/Public"), "directory"),
        (
            "webspaces",
            "Spaces",
            "localhost://WebSpaces".to_string(),
            "webspace-root",
        ),
    ]
    .into_iter()
    .map(|(id, label, uri, kind)| {
        // The Public place says whether it holds items, so Library can list
        // it only while it does.
        let metadata = (id == "public").then(|| {
            let (empty, item_count) = root_item_state(data_dir, principal_id, &uri);
            json!({
                "schema": "elastos.library.public-root/v1",
                "empty": empty,
                "item_count": item_count,
            })
        });
        LibraryRoot {
            schema: LIBRARY_ROOT_SCHEMA,
            id,
            label,
            uri,
            kind,
            metadata,
        }
    })
    .collect();
    let trash_uri = format!("{root}/.Trash");
    let (empty, item_count) = root_item_state(data_dir, principal_id, &trash_uri);
    roots.push(LibraryRoot {
        schema: LIBRARY_ROOT_SCHEMA,
        id: "trash",
        label: "Trash",
        uri: trash_uri,
        kind: "directory",
        metadata: Some(json!({
            "schema": "elastos.library.trash-root/v1",
            "empty": empty,
            "item_count": item_count,
        })),
    });
    roots
}

fn root_item_state(data_dir: &Path, principal_id: &str, uri: &str) -> (bool, usize) {
    let Ok(target) = library_target(data_dir, principal_id, uri) else {
        return (true, 0);
    };
    let Ok(entries) = fs::read_dir(&target.path) else {
        return (true, 0);
    };
    let count = entries.filter_map(Result::ok).count();
    (count == 0, count)
}

fn move_library_object(
    data_dir: &Path,
    principal_id: &str,
    from_uri: &str,
    to_uri: &str,
) -> anyhow::Result<()> {
    let from = library_target(data_dir, principal_id, from_uri)?;
    let to = library_target(data_dir, principal_id, to_uri)?;
    if !from.path.exists() {
        bail!("library source object not found");
    }
    if to.path.exists() {
        bail!("library destination already exists");
    }
    let rule = StartWalkRule::new(data_dir, &to.localhost_root);
    rule.tree(&from.path, &to.uri)?;
    if from.path.is_dir() {
        move_library_directory(data_dir, principal_id, &rule, &from, &to)?;
    } else {
        move_library_file(data_dir, principal_id, &rule, &from, &to)?;
    }
    Ok(())
}

fn copy_library_object(
    data_dir: &Path,
    principal_id: &str,
    from_uri: &str,
    to_uri: &str,
) -> anyhow::Result<()> {
    let from = library_target(data_dir, principal_id, from_uri)?;
    let to = library_target(data_dir, principal_id, to_uri)?;
    if !from.path.exists() {
        bail!("library source object not found");
    }
    if to.path.exists() {
        bail!("library destination already exists");
    }
    let rule = StartWalkRule::new(data_dir, &to.localhost_root);
    rule.tree(&from.path, &to.uri)?;
    if from.path.is_dir() {
        copy_library_directory(data_dir, principal_id, &rule, &from, &to)?;
    } else {
        copy_library_file(data_dir, principal_id, &rule, &from, &to)?;
    }
    Ok(())
}

/// The copy and move writers check every path they create with `rule`, so a
/// file or folder added to the source after `StartWalkRule::tree` cannot land
/// deeper than Home starts with (#449).
fn copy_library_directory(
    data_dir: &Path,
    principal_id: &str,
    rule: &StartWalkRule,
    from: &LibraryTarget,
    to: &LibraryTarget,
) -> anyhow::Result<()> {
    rule.folder(&to.uri)?;
    fs::create_dir_all(&to.path)?;
    for entry in fs::read_dir(&from.path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let child_from_uri = format!("{}/{}", from.uri, name);
        let child_to_uri = format!("{}/{}", to.uri, name);
        let child_from = library_target(data_dir, principal_id, &child_from_uri)?;
        let child_to = library_target(data_dir, principal_id, &child_to_uri)?;
        if child_from.path.is_dir() {
            copy_library_directory(data_dir, principal_id, rule, &child_from, &child_to)?;
        } else {
            copy_library_file(data_dir, principal_id, rule, &child_from, &child_to)?;
        }
    }
    Ok(())
}

fn copy_library_file(
    data_dir: &Path,
    principal_id: &str,
    rule: &StartWalkRule,
    from: &LibraryTarget,
    to: &LibraryTarget,
) -> anyhow::Result<()> {
    rule.file(&to.uri)?;
    let bytes = read_library_file_bytes(data_dir, principal_id, from)?;
    if let Some(parent) = to.path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::auth::write_principal_root_object(
        data_dir,
        principal_id,
        &to.localhost_root,
        &to.uri,
        &to.path,
        &bytes,
    )?;
    Ok(())
}

fn move_library_directory(
    data_dir: &Path,
    principal_id: &str,
    rule: &StartWalkRule,
    from: &LibraryTarget,
    to: &LibraryTarget,
) -> anyhow::Result<()> {
    rule.folder(&to.uri)?;
    fs::create_dir_all(&to.path)?;
    for entry in fs::read_dir(&from.path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let child_from_uri = format!("{}/{}", from.uri, name);
        let child_to_uri = format!("{}/{}", to.uri, name);
        let child_from = library_target(data_dir, principal_id, &child_from_uri)?;
        let child_to = library_target(data_dir, principal_id, &child_to_uri)?;
        if child_from.path.is_dir() {
            move_library_directory(data_dir, principal_id, rule, &child_from, &child_to)?;
        } else {
            move_library_file(data_dir, principal_id, rule, &child_from, &child_to)?;
        }
    }
    fs::remove_dir(&from.path)?;
    Ok(())
}

fn move_library_file(
    data_dir: &Path,
    principal_id: &str,
    rule: &StartWalkRule,
    from: &LibraryTarget,
    to: &LibraryTarget,
) -> anyhow::Result<()> {
    rule.file(&to.uri)?;
    let bytes = read_library_file_bytes(data_dir, principal_id, from)?;
    if let Some(parent) = to.path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::auth::write_principal_root_object(
        data_dir,
        principal_id,
        &to.localhost_root,
        &to.uri,
        &to.path,
        &bytes,
    )?;
    fs::remove_file(&from.path)?;
    move_publish_record(data_dir, principal_id, &from.uri, &to.uri)
}

fn check_revision(
    data_dir: &Path,
    principal_id: &str,
    uri: &str,
    expected: Option<&str>,
) -> anyhow::Result<()> {
    let Some(expected) = expected.filter(|value| !value.trim().is_empty()) else {
        return Ok(());
    };
    let object = library_object(data_dir, principal_id, uri)?;
    if object.revision != expected {
        bail!("library object revision precondition failed");
    }
    Ok(())
}

fn child_uri(parent_uri: &str, name: &str) -> anyhow::Result<String> {
    let name = clean_object_name(name)?;
    Ok(format!("{}/{}", parent_uri.trim_end_matches('/'), name))
}

fn unique_child_uri(
    data_dir: &Path,
    principal_id: &str,
    parent_uri: &str,
    name: &str,
) -> anyhow::Result<String> {
    let mut candidate = child_uri(parent_uri, name)?;
    if !library_target(data_dir, principal_id, &candidate)?
        .path
        .exists()
    {
        return Ok(candidate);
    }
    let timestamp = now_ts();
    let (stem, ext) = name.rsplit_once('.').unwrap_or((name, ""));
    for index in 0..1_000 {
        let suffix = if index == 0 {
            timestamp.to_string()
        } else {
            format!("{timestamp}-{index}")
        };
        let fallback = if ext.is_empty() {
            format!("{stem} ({suffix})")
        } else {
            format!("{stem} ({suffix}).{ext}")
        };
        candidate = child_uri(parent_uri, &fallback)?;
        if !library_target(data_dir, principal_id, &candidate)?
            .path
            .exists()
        {
            return Ok(candidate);
        }
    }
    bail!("failed to allocate unique Library object name")
}

fn clean_object_name(name: &str) -> anyhow::Result<&str> {
    let name = name.trim();
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name == "."
        || name == ".."
    {
        bail!("invalid library object name");
    }
    Ok(name)
}

fn library_uri_parent(uri: &str) -> anyhow::Result<&str> {
    uri.rsplit_once('/')
        .map(|(parent, _)| parent)
        .filter(|parent| !parent.is_empty())
        .ok_or_else(|| anyhow!("library object URI has no parent"))
}

fn is_trash_uri(localhost_root: &str, uri: &str) -> bool {
    is_trash_root_uri(localhost_root, uri) || is_trash_child_uri(localhost_root, uri)
}

fn is_trash_root_uri(localhost_root: &str, uri: &str) -> bool {
    uri == format!("{localhost_root}/.Trash")
}

fn is_trash_child_uri(localhost_root: &str, uri: &str) -> bool {
    uri.strip_prefix(&format!("{localhost_root}/.Trash/"))
        .is_some_and(|rest| !rest.is_empty())
}

fn restore_uri_from_trash_record(
    data_dir: &Path,
    principal_id: &str,
    trash_target: &LibraryTarget,
    trash_record: Option<&LibraryTrashRecord>,
) -> anyhow::Result<String> {
    let record =
        trash_record.ok_or_else(|| anyhow!("library Trash restore metadata is missing"))?;
    let original_uri = clean_library_uri(&trash_target.localhost_root, &record.original_uri)?;
    let parent_uri = library_uri_parent(&original_uri)?;
    let name = original_uri
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(record.original_name.as_str());
    unique_child_uri(data_dir, principal_id, parent_uri, name)
}

fn trash_record_uri(localhost_root: &str, trash_uri: &str) -> String {
    let digest = hex::encode(Sha256::digest(trash_uri.as_bytes()));
    format!("{localhost_root}/.AppData/LocalHost/.Runtime/Library/Trash/{digest}.json")
}

fn read_trash_record(
    data_dir: &Path,
    principal_id: &str,
    trash_uri: &str,
) -> anyhow::Result<LibraryTrashRecord> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let record_uri = trash_record_uri(&root, trash_uri);
    let record_path = rooted_localhost_fs_path(data_dir, &record_uri)
        .ok_or_else(|| anyhow!("invalid library Trash record path"))?;
    let bytes = crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &root,
        &record_uri,
        &record_path,
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_trash_record(
    data_dir: &Path,
    principal_id: &str,
    record: &LibraryTrashRecord,
) -> anyhow::Result<()> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let record_uri = trash_record_uri(&root, &record.trash_uri);
    let record_path = rooted_localhost_fs_path(data_dir, &record_uri)
        .ok_or_else(|| anyhow!("invalid library Trash record path"))?;
    if let Some(parent) = record_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(record)?;
    crate::auth::write_principal_root_object(
        data_dir,
        principal_id,
        &root,
        &record_uri,
        &record_path,
        &bytes,
    )
}

fn remove_trash_record(data_dir: &Path, principal_id: &str, trash_uri: &str) -> anyhow::Result<()> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let record_uri = trash_record_uri(&root, trash_uri);
    let record_path = rooted_localhost_fs_path(data_dir, &record_uri)
        .ok_or_else(|| anyhow!("invalid library Trash record path"))?;
    match fs::remove_file(record_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn publish_record_uri(localhost_root: &str, object_uri: &str) -> String {
    let digest = hex::encode(Sha256::digest(object_uri.as_bytes()));
    format!("{localhost_root}/.AppData/LocalHost/.Runtime/Library/Published/{digest}.json")
}

fn read_publish_record(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
) -> anyhow::Result<LibraryPublishRecord> {
    let root = crate::auth::principal_localhost_root(principal_id);
    read_runtime_json(
        data_dir,
        principal_id,
        &publish_record_uri(&root, object_uri),
    )
}

fn write_publish_record(
    data_dir: &Path,
    principal_id: &str,
    record: &LibraryPublishRecord,
) -> anyhow::Result<()> {
    // Serving follows the index. A publication that ends leaves the index
    // before its record changes, and one that starts joins it after: a crash
    // in between serves less, never more.
    let active = record_is_published(record);
    if !active {
        set_published_index_entry(data_dir, principal_id, record, false)?;
    }
    let root = crate::auth::principal_localhost_root(principal_id);
    write_runtime_json(
        data_dir,
        principal_id,
        &publish_record_uri(&root, &record.object_uri),
        record,
    )?;
    if active {
        set_published_index_entry(data_dir, principal_id, record, true)?;
    }
    Ok(())
}

const PUBLISHED_INDEX_SCHEMA: &str = "elastos.library.published-cids/v1";

/// This Home's active publications, by every person, as the CIDs each one
/// shares and who may read them: the only thing a peer read of an ordinary
/// Home is served on. Keys are opaque digests of person and publication; the
/// records stay the source of truth and the index is reconciled from them at
/// start.
#[derive(Default, Serialize, Deserialize)]
struct PublishedIndex {
    schema: String,
    #[serde(default)]
    publications: std::collections::BTreeMap<String, PublishedEntry>,
}

#[derive(Serialize, Deserialize)]
struct PublishedEntry {
    /// The person who published: a plain publication is for their contacts.
    principal_id: String,
    cids: BTreeSet<String>,
    /// A protected listing's sealed payload, readable by any peer: opening it
    /// needs the key release a purchase grants.
    #[serde(default)]
    any_peer: bool,
}

impl PublishedEntry {
    fn of(data_dir: &Path, principal_id: &str, record: &LibraryPublishRecord) -> Self {
        Self {
            principal_id: principal_id.to_string(),
            cids: record_shared_cids(data_dir, record),
            any_peer: record_is_runtime_custody(record),
        }
    }
}

static PUBLISHED_INDEX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn published_index_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("ElastOS")
        .join("SystemServices")
        .join("Library")
        .join("published-cids.json")
}

fn load_published_index(data_dir: &Path) -> anyhow::Result<PublishedIndex> {
    match fs::read(published_index_path(data_dir)) {
        Ok(bytes) => {
            let index: PublishedIndex = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                index.schema == PUBLISHED_INDEX_SCHEMA,
                "published CID index has an unknown schema"
            );
            Ok(index)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(PublishedIndex {
            schema: PUBLISHED_INDEX_SCHEMA.to_string(),
            publications: Default::default(),
        }),
        Err(err) => Err(err.into()),
    }
}

fn update_published_index(
    data_dir: &Path,
    change: impl FnOnce(&mut PublishedIndex),
) -> anyhow::Result<()> {
    let _guard = PUBLISHED_INDEX_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = load_published_index(data_dir)?;
    change(&mut index);
    crate::auth::atomic_write(
        &published_index_path(data_dir),
        &serde_json::to_vec_pretty(&index)?,
    )
}

fn published_index_key(principal_id: &str, record: &LibraryPublishRecord) -> String {
    hex::encode(Sha256::digest(format!(
        "{principal_id}\n{}",
        record_publication_id(record)
    )))
}

/// The CIDs one publication shares: a protected publication's artifact set,
/// or a Library publication's content. A protected publication whose listing
/// this Home cannot read shares its content and listing, as it always did.
fn record_shared_cids(data_dir: &Path, record: &LibraryPublishRecord) -> BTreeSet<String> {
    if let Some(artifacts) = ProtectedListingArtifacts::of(data_dir, record) {
        return artifacts.cids();
    }
    let mut cids = BTreeSet::from([record.cid.clone()]);
    if let Some(listing_cid) = record_listing_cid(record) {
        cids.insert(listing_cid.to_string());
    }
    cids
}

/// The CID of the listing package a protected publication names.
fn record_listing_cid(record: &LibraryPublishRecord) -> Option<&str> {
    record
        .listing_uri
        .as_deref()
        .and_then(|uri| uri.strip_prefix("elastos://"))
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .filter(|cid| !cid.is_empty())
}

/// What a protected publication shares with any peer: the sealed payload,
/// the listing package, and the tokenURI metadata folder the listing names.
/// The folder is public by nature -- it is the on-chain tokenURI, and the
/// public metadata store publishes the same folder -- and a buyer's listing
/// read starts from it, so its creator's Home serves it with the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedListingArtifacts {
    content_cid: String,
    listing_cid: String,
    metadata_cid: String,
}

impl ProtectedListingArtifacts {
    /// The artifact set of `record`, from the creator listing it names:
    /// `None` for a Library publication, and for a protected one whose
    /// listing this Home cannot read or that names another publication.
    fn of(data_dir: &Path, record: &LibraryPublishRecord) -> Option<Self> {
        if !record_is_runtime_custody(record) {
            return None;
        }
        let listing_uri = record.listing_uri.as_deref()?;
        let listing_cid = record_listing_cid(record)?;
        let mint_id = record
            .content_security
            .get("mint_id")
            .and_then(Value::as_str)
            .and_then(|mint_id| {
                crate::protected_content_runtime::parse_mint_id_hex(mint_id).ok()
            })?;
        let listing = match crate::protected_content_runtime::load_runtime_custody_listing(
            data_dir, mint_id,
        ) {
            Ok(Some(listing)) => listing,
            Ok(None) => {
                tracing::warn!(
                    cid = %record.cid,
                    "library: a protected publication has no listing; its metadata folder is not shared"
                );
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    cid = %record.cid,
                    %error,
                    "library: a protected publication's listing is unreadable; its metadata folder is not shared"
                );
                return None;
            }
        };
        if listing.origin.listing_uri() != Some(listing_uri)
            || listing.package.content_cid != record.cid
        {
            tracing::warn!(
                cid = %record.cid,
                "library: a protected publication's listing names another publication; its metadata folder is not shared"
            );
            return None;
        }
        Some(Self {
            content_cid: record.cid.clone(),
            listing_cid: listing_cid.to_string(),
            metadata_cid: listing.package.metadata_cid,
        })
    }

    fn cids(self) -> BTreeSet<String> {
        BTreeSet::from([self.content_cid, self.listing_cid, self.metadata_cid])
    }
}

fn set_published_index_entry(
    data_dir: &Path,
    principal_id: &str,
    record: &LibraryPublishRecord,
    active: bool,
) -> anyhow::Result<()> {
    let key = published_index_key(principal_id, record);
    update_published_index(data_dir, |index| {
        if active {
            index
                .publications
                .insert(key, PublishedEntry::of(data_dir, principal_id, record));
        } else {
            index.publications.remove(&key);
        }
    })
}

/// Who may read `cid` from this Home: `None` when no active publication
/// lists it, or the index cannot be read.
pub(crate) struct PublishedAudience {
    pub(crate) any_peer: bool,
    /// The people whose publications list it; their contacts may read it.
    pub(crate) principals: BTreeSet<String>,
}

pub(crate) fn published_cid_audience(data_dir: &Path, cid: &str) -> Option<PublishedAudience> {
    let _guard = PUBLISHED_INDEX_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let index = load_published_index(data_dir).ok()?;
    let mut audience = PublishedAudience {
        any_peer: false,
        principals: BTreeSet::new(),
    };
    for entry in index
        .publications
        .values()
        .filter(|entry| entry.cids.contains(cid))
    {
        audience.any_peer |= entry.any_peer;
        audience.principals.insert(entry.principal_id.clone());
    }
    (!audience.principals.is_empty()).then_some(audience)
}

#[cfg(test)]
pub(crate) fn cid_is_published_here(data_dir: &Path, cid: &str) -> bool {
    published_cid_audience(data_dir, cid).is_some()
}

/// Rewrites `object_uri`'s publish record as alpha.25 withdrew it after an
/// Undo: withdrawn, without the publication id it never knew, and with the
/// index left as it was.
#[cfg(test)]
pub(crate) fn withdraw_as_alpha25_for_test(data_dir: &Path, principal_id: &str, object_uri: &str) {
    let mut record = read_publish_record(data_dir, principal_id, object_uri).unwrap();
    record.publication_id = None;
    record.unpublished_at = Some(record.published_at + 1);
    let root = crate::auth::principal_localhost_root(principal_id);
    write_runtime_json(
        data_dir,
        principal_id,
        &publish_record_uri(&root, object_uri),
        &record,
    )
    .unwrap();
}

/// Rebuilds the index at start from the publish records alone: an entry
/// stays only while an active record backs it, whatever wrote it. A record
/// an earlier release rewrote (for example a withdrawal after Undo, which
/// drops the publication id) therefore can't leave its old entry behind, and
/// a record this Runtime cannot read is not served until it can.
pub fn reconcile_published_cids(data_dir: &Path) {
    let principals: BTreeSet<String> = crate::auth::list_passkey_principals(data_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|principal| principal.principal_id)
        .collect();
    let mut publications = std::collections::BTreeMap::new();
    for principal in &principals {
        for record in publish_records(data_dir, principal) {
            if record_is_published(&record) {
                publications.insert(
                    published_index_key(principal, &record),
                    PublishedEntry::of(data_dir, principal, &record),
                );
            }
        }
    }
    if let Err(err) = update_published_index(data_dir, |index| {
        index.publications = publications;
    }) {
        tracing::warn!(error = %err, "library: published CID index not reconciled");
    }
}

/// Lists `cid` as published on this Home for any peer, as a test fixture's
/// holder does.
#[cfg(test)]
pub(crate) fn publish_cid_for_test(data_dir: &Path, cid: &str) {
    update_published_index(data_dir, |index| {
        index.publications.insert(
            format!("test:{cid}"),
            PublishedEntry {
                principal_id: "test".to_string(),
                cids: BTreeSet::from([cid.to_string()]),
                any_peer: true,
            },
        );
    })
    .unwrap();
}

/// Lists `cid` as `principal_id`'s Library publication, for their contacts.
#[cfg(test)]
pub(crate) fn publish_cid_for_contacts_for_test(data_dir: &Path, principal_id: &str, cid: &str) {
    update_published_index(data_dir, |index| {
        index.publications.insert(
            format!("test:{cid}"),
            PublishedEntry {
                principal_id: principal_id.to_string(),
                cids: BTreeSet::from([cid.to_string()]),
                any_peer: false,
            },
        );
    })
    .unwrap();
}

/// Withdraws what `publish_cid_for_test` listed.
#[cfg(test)]
pub(crate) fn withdraw_cid_for_test(data_dir: &Path, cid: &str) {
    update_published_index(data_dir, |index| {
        index.publications.remove(&format!("test:{cid}"));
    })
    .unwrap();
}

fn remove_publish_record(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
) -> anyhow::Result<()> {
    let root = crate::auth::principal_localhost_root(principal_id);
    remove_runtime_file(data_dir, &publish_record_uri(&root, object_uri))
}

/// A plain publication moves with its file on rename and move, so Unpublish
/// keeps control of it. Protected publications keep their records as before.
fn move_publish_record(
    data_dir: &Path,
    principal_id: &str,
    from_uri: &str,
    to_uri: &str,
) -> anyhow::Result<()> {
    let Ok(mut record) = read_publish_record(data_dir, principal_id, from_uri) else {
        return Ok(());
    };
    if record_is_runtime_custody(&record) {
        return Ok(());
    }
    record.object_uri = to_uri.to_string();
    if let Some(object_uri) = record.content_security.get_mut("object_uri") {
        *object_uri = Value::String(to_uri.to_string());
    }
    write_publish_record(data_dir, principal_id, &record)?;
    remove_publish_record(data_dir, principal_id, from_uri)
}

/// Refuses to delete `uri` (a file, or a folder and everything in it) while it
/// holds an active plain publication: Unpublish withdraws it first.
fn refuse_deleting_published(data_dir: &Path, principal_id: &str, uri: &str) -> anyhow::Result<()> {
    let folder = format!("{uri}/");
    for record in plain_publish_records(data_dir, principal_id) {
        if !record_is_published(&record) {
            continue;
        }
        if record.object_uri == uri {
            return Err(library_refusal(
                "published_withdraw_first",
                "Unpublish this file before deleting it.",
            ));
        }
        if record.object_uri.starts_with(&folder) {
            return Err(library_refusal(
                "published_withdraw_first",
                "This folder has published files. Unpublish them before deleting it.",
            ));
        }
    }
    Ok(())
}

fn library_events(
    data_dir: &Path,
    principal_id: &str,
    uri_filter: Option<&str>,
    since: Option<u64>,
    limit: Option<usize>,
) -> anyhow::Result<Vec<LibraryEvent>> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let uri_filter = uri_filter
        .map(|uri| clean_library_uri(&root, uri))
        .transpose()?;
    let limit = limit.unwrap_or(64).clamp(1, MAX_LIBRARY_EVENTS);
    let mut events = read_library_events(data_dir, principal_id)?;
    events.retain(|event| {
        since.map(|since| event.at > since).unwrap_or(true)
            && uri_filter
                .as_deref()
                .map(|uri| library_event_matches_uri(event, uri))
                .unwrap_or(true)
    });
    if events.len() > limit {
        let keep_from = events.len() - limit;
        events.drain(0..keep_from);
    }
    Ok(events)
}

fn append_library_event(
    data_dir: &Path,
    principal_id: &str,
    op: &str,
    uri: &str,
    details: Value,
) -> anyhow::Result<LibraryEvent> {
    let mut events = read_library_events(data_dir, principal_id)?;
    let event = LibraryEvent {
        schema: LIBRARY_EVENT_SCHEMA.to_string(),
        event_id: library_event_id(op, uri, &details),
        op: op.to_string(),
        uri: uri.to_string(),
        at: now_ts(),
        details,
    };
    events.push(event.clone());
    if events.len() > MAX_LIBRARY_EVENTS {
        let keep_from = events.len() - MAX_LIBRARY_EVENTS;
        events.drain(0..keep_from);
    }
    write_library_events(data_dir, principal_id, &events)?;
    library_event_notifier().notify_waiters();
    Ok(event)
}

fn read_library_events(data_dir: &Path, principal_id: &str) -> anyhow::Result<Vec<LibraryEvent>> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let event_uri = library_event_log_uri(&root);
    let event_path = rooted_localhost_fs_path(data_dir, &event_uri)
        .ok_or_else(|| anyhow!("invalid library event log path"))?;
    if !event_path.exists() {
        return Ok(Vec::new());
    }
    let bytes = crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &root,
        &event_uri,
        &event_path,
    )?;
    let text = String::from_utf8(bytes).context("library event log must be utf-8 jsonl")?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("invalid library event entry"))
        .collect()
}

fn write_library_events(
    data_dir: &Path,
    principal_id: &str,
    events: &[LibraryEvent],
) -> anyhow::Result<()> {
    let root = crate::auth::principal_localhost_root(principal_id);
    let event_uri = library_event_log_uri(&root);
    let event_path = rooted_localhost_fs_path(data_dir, &event_uri)
        .ok_or_else(|| anyhow!("invalid library event log path"))?;
    if let Some(parent) = event_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event)?;
        bytes.push(b'\n');
    }
    crate::auth::write_principal_root_object(
        data_dir,
        principal_id,
        &root,
        &event_uri,
        &event_path,
        &bytes,
    )
}

fn library_event_log_uri(localhost_root: &str) -> String {
    format!("{localhost_root}/.AppData/LocalHost/.Runtime/Library/events.jsonl")
}

fn library_event_id(op: &str, uri: &str, details: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(now_nanos().to_be_bytes());
    hasher.update(op.as_bytes());
    hasher.update(uri.as_bytes());
    hasher.update(details.to_string().as_bytes());
    let digest = hasher.finalize();
    format!("library:event:{}", hex::encode(&digest[..16]))
}

fn library_event_matches_uri(event: &LibraryEvent, uri: &str) -> bool {
    uri_matches_filter(&event.uri, uri)
        || [
            "old_uri",
            "original_uri",
            "source_uri",
            "trash_uri",
            "target_uri",
        ]
        .into_iter()
        .any(|field| {
            event
                .details
                .get(field)
                .and_then(Value::as_str)
                .map(|value| uri_matches_filter(value, uri))
                .unwrap_or(false)
        })
        || event
            .details
            .get("object")
            .and_then(|object| object.get("uri"))
            .and_then(Value::as_str)
            .map(|value| uri_matches_filter(value, uri))
            .unwrap_or(false)
}

fn uri_matches_filter(uri: &str, filter: &str) -> bool {
    uri == filter
        || uri
            .strip_prefix(filter.trim_end_matches('/'))
            .is_some_and(|rest| rest.starts_with('/'))
}

fn directory_revision(path: &Path, uri: &str) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(uri.as_bytes());
    if path.exists() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            hasher.update(entry.file_name().to_string_lossy().as_bytes());
            let metadata = entry.metadata()?;
            hasher.update(metadata.len().to_be_bytes());
            if let Some(modified) = system_time_secs(metadata.modified().ok()) {
                hasher.update(modified.to_be_bytes());
            }
        }
    }
    Ok(format!("rev:{}", hex::encode(hasher.finalize())))
}

fn system_time_secs(time: Option<SystemTime>) -> Option<u64> {
    time.and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Content type for one Library object name.
///
/// The `video/*` and `audio/*` arms are load-bearing beyond metadata: they are
/// the dispatch gate `library_publish` uses to route protected publishing to
/// the ffmpeg-backed media provider instead of the EPC1 object path, so a
/// media container missing here would be sealed as an object rather than
/// transcoded (and, until the object open/read path lands, could not be opened
/// at all). The media extensions are therefore taken from the provider's own
/// accepted input rather than guessed: `capsules/media-provider/src/lib.rs`
/// imposes no container restriction of its own (it runs `ffprobe`/`ffmpeg`
/// over a generic `-i input.bin` and only requires a video stream), so the set
/// below is ffmpeg's own container registry — the "Common extensions" line of
/// `ffmpeg -h demuxer=<name>` / `ffmpeg -h muxer=<name>` (ffmpeg 7.1.1) for the
/// A/V container formats. Image-only extensions that ffmpeg's `mov` demuxer
/// also claims (`avif`, `heic`, `heif`) are deliberately NOT treated as media.
fn mime_for_name(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    // Two-part suffix: checked before the single-extension table below.
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        return "application/gzip";
    }
    let Some((_, extension)) = lower.rsplit_once('.') else {
        return "application/octet-stream";
    };
    match extension {
        "md" | "txt" => "text/plain",
        "html" => "text/html",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "tar" => "application/x-tar",
        "zip" => "application/zip",
        // Video containers (ffmpeg demuxers: mov, m4v, matroska, webm, ogg,
        // avi, flv, mpeg, mpegts, asf, vob).
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "3gp" | "3g2" => "video/3gpp",
        "mkv" | "mk3d" => "video/x-matroska",
        "webm" => "video/webm",
        // `ogv` is ffmpeg's `ogg` demuxer, the same one `ogg`/`oga` below
        // already route to the media path; it was publishable before the
        // media allowlist landed and is restored here.
        "ogv" => "video/ogg",
        // `asf` is ffmpeg's `asf` demuxer -- literally the same demuxer
        // `wmv` below already routes to the media path, so the provider
        // demonstrably handles it.
        "asf" => "video/x-ms-asf",
        "avi" => "video/x-msvideo",
        "flv" | "f4v" => "video/x-flv",
        "mpg" | "mpeg" | "vob" => "video/mpeg",
        "ts" | "m2t" | "m2ts" | "mts" => "video/mp2t",
        "wmv" => "video/x-ms-wmv",
        // Audio containers (ffmpeg demuxers: mp3, mov, aac, wav, flac, ogg,
        // opus, oga, matroska, asf). Audio follows the media path too: it is
        // transcoded to an fMP4 audio rendition rather than sealed as an
        // object.
        "mp3" | "mp2" | "m2a" | "mpa" => "audio/mpeg",
        "m4a" | "m4b" => "audio/mp4",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "mka" => "audio/x-matroska",
        "wma" => "audio/x-ms-wma",
        _ => "application/octet-stream",
    }
}

fn viewer_options_for_name(data_dir: &Path, name: &str) -> Vec<LibraryViewerOption> {
    viewer_ids_for_name(name)
        .into_iter()
        .filter_map(|id| installed_viewer_option(data_dir, id))
        .collect()
}

fn viewer_ids_for_name(name: &str) -> Vec<&'static str> {
    let lower = name.to_lowercase();
    if archive_family_for_name(&lower).is_some() {
        vec!["archive-manager"]
    } else if lower.ends_with(".md") || lower.ends_with(".txt") {
        vec!["documents"]
    } else if lower.ends_with(".gba") {
        vec!["gba-emulator"]
    } else {
        Vec::new()
    }
}

fn installed_viewer_option(data_dir: &Path, id: &str) -> Option<LibraryViewerOption> {
    crate::api::browser_capsules::list_launchable_browser_capsules(data_dir)
        .into_iter()
        .find(|capsule| capsule.name == id && capsule.role == elastos_common::CapsuleRole::Viewer)
        .map(|capsule| LibraryViewerOption {
            id: capsule.name.clone(),
            label: viewer_label(&capsule.name).to_string(),
            description: capsule.description,
            default: true,
        })
}

fn viewer_label(id: &str) -> &str {
    match id {
        "documents" => "Documents",
        "gba-emulator" => "GBA Emulator",
        "archive-manager" => "Archive",
        _ => id,
    }
}

fn provider_ok(data: Value) -> Value {
    json!({
        "status": "ok",
        "data": data,
    })
}

fn provider_error(code: &str, message: &str) -> Value {
    json!({
        "status": "error",
        "code": code,
        "message": message,
    })
}

/// Error envelope for a failed provider request: `message` stays the stable,
/// app-facing sentence (the outermost error), and `detail` carries the cause
/// chain beneath it (fail-closed site, provider verdict, RPC revert data) so
/// an operator or driver can see why without the runtime log.
///
/// A refusal that carries its reason as data adds a typed, versioned field of
/// its own. That field — not the sentence — is what an app branches on: reading
/// English to decide what to offer is how a recoverable state once reached a
/// dead end in the apps.
fn provider_error_from(code: &str, error: &anyhow::Error) -> Value {
    let refusal = find_library_refusal(error);
    let mut response = provider_error_with_detail(
        refusal.map_or(code, |refusal| refusal.code),
        error,
        bounded_error_detail(error_cause_chain(error)),
    );
    if let Some(reason) = refusal.and_then(|refusal| refusal.reason) {
        response["reason"] = Value::String(reason.to_string());
    }
    response
}

/// The error envelope a library request answers with, for tests that assert
/// the typed fields an app reads.
#[cfg(test)]
pub(crate) fn provider_error_from_for_test(error: &anyhow::Error) -> Value {
    provider_error_from("library_error", error)
}

/// [`provider_error_from`] with `detail` already built, so a caller that has
/// to rewrite the cause chain does so before it is bounded (R42).
fn provider_error_with_detail(code: &str, error: &anyhow::Error, detail: String) -> Value {
    let mut response = provider_error(code, &error.to_string());
    if !detail.is_empty() {
        response["detail"] = Value::String(detail);
    }
    if let Some(blocked) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked>()
    {
        response["creator_mint"] = blocked.as_json();
    }
    // An attempt that cannot continue as it stands. Refused, and answered by
    // Start over: the field is what tells an app to offer it.
    if let Some(conflict) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyAttemptConflict>()
    {
        response["attempt_conflict"] = conflict.as_json();
    }
    if let Some(unusable) = error
        .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyWalletDefaultUnusable>(
    ) {
        response["wallet_default"] = unusable.as_json();
    }
    // A mint bound to an account the wallet no longer defaults to. Its own key,
    // not `wallet_default`: the default here is fine, and an app that conflated
    // the two would tell the creator to set a default they have already set.
    if let Some(drift) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorWalletDrift>()
    {
        response["wallet_drift"] = drift.as_json();
    }
    // A waiting state, not a failure. Carried as data so an app stops deciding
    // control flow by matching the word "pending" in a sentence written for a
    // person to read.
    if let Some(pending) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyEffectPending>()
    {
        response["effect_pending"] = pending.as_json();
    }
    // The buy twin of `open_progress`. A purchase is a sequence of waits, and
    // an app has to tell "approve this in your wallet" from "the network is
    // confirming it" from "you declined". All three arrived as one sentence
    // that Marketplace then dropped, so a purchase in progress read as a
    // purchase that had failed.
    if let Some(progress) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyBuyProgress>()
    {
        response["buy_progress"] = progress.as_json();
    }
    // A market buy refused before anything was raised (§5.3). Its typed code
    // replaces the generic one: `code` is the field Marketplace branches on,
    // and `terms_changed` carries the offer the buyer has to decide on anew.
    if let Some(refusal) = error.downcast_ref::<crate::api::gateway::RuntimeMarketBuyRefusal>() {
        refusal.project_onto(&mut response);
    }
    // An item whose pool this Home cannot reach (Plan B T4.7): the page says
    // so from `code` rather than reporting a failure.
    if crate::protected_content_runtime::RuntimeCustodyElsewhere::is(error) {
        response["code"] = Value::String(
            crate::protected_content_runtime::RuntimeCustodyElsewhere::CODE.to_string(),
        );
    }
    // Plan B T4.5 (C3): a pool session at its end. The Player or Reader
    // keeps its place and runs the open once, from `code`.
    if crate::protected_content_runtime::RuntimeCustodyPoolSessionRenewalRequired::is(error) {
        response["code"] = Value::String(
            crate::protected_content_runtime::RuntimeCustodyPoolSessionRenewalRequired::CODE
                .to_string(),
        );
    }
    // OPEN-LOOP F2: a pool open that failed after the Wallet signed. The
    // Player or Reader offers Retry and opens nothing on its own, from `code`.
    if crate::protected_content_runtime::RuntimeCustodyPoolContentUnavailable::is(error) {
        response["code"] = Value::String(
            crate::protected_content_runtime::RuntimeCustodyPoolContentUnavailable::CODE
                .to_string(),
        );
    }
    // A download refused for a reason a person can act on: the page says
    // what is missing from `code`.
    if let Some(refusal) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyDownloadRefusal>()
    {
        response["code"] = Value::String(refusal.code().to_string());
    }
    // The opposite of pending: an approval that is finished and did not
    // succeed. Its own key, so an app polling for completion can tell "stop
    // waiting" from "keep waiting" without reading either sentence.
    if let Some(closed) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyApprovalClosed>()
    {
        response["approval_closed"] = closed.as_json();
    }
    // How far an open has got. A viewer reads `resumable` here to choose
    // between waiting for the person's Wallet approval and offering them a
    // retry, so that choice stops depending on the words in `message`.
    if let Some(progress) =
        error.downcast_ref::<crate::protected_content_runtime::RuntimeCustodyOpenProgress>()
    {
        response["open_progress"] = progress.as_json();
    }
    // A mint whose metadata did not reach the public IPFS store, so no
    // approval was raised: the typed code says why, and its progress names
    // the `public_metadata` stage that failed.
    if let Some(failure) =
        error.downcast_ref::<crate::public_metadata_publisher::PublicMetadataFailure>()
    {
        response["public_metadata"] = failure.as_json();
    }
    response
}

/// The error envelope for any object request; for a Marketplace buy (`buy`,
/// `buy_offer`) with every account address taken out of the text (R31).
fn marketplace_buy_error_from(marketplace_buy: bool, error: &anyhow::Error) -> Value {
    if !marketplace_buy {
        return provider_error_from("library_error", error);
    }
    // R42: the whole cause chain is redacted before it is bounded, so the
    // bound can never cut an address into a run too short to be recognised.
    let detail = bounded_error_detail(redact_evm_address_runs(&error_cause_chain(error)));
    let mut response = provider_error_with_detail("library_error", error, detail);
    redact_account_addresses(&mut response);
    response
}

/// D14 for a Marketplace buy (R31): the page never learns this Home's account.
/// A node's own sentence can name it ("insufficient funds ... address 0x…"),
/// and `detail` carries such sentences, so every `0x` + 40-hex run in `message`
/// and `detail` becomes `0x…`. Typed fields (`code`, `current`,
/// `buy_progress`) are left exactly as they are: they are built to carry no
/// account, and `current` names a seller the page was already shown.
fn redact_account_addresses(response: &mut Value) {
    for key in ["message", "detail"] {
        if let Some(Value::String(text)) = response.get_mut(key) {
            *text = redact_evm_address_runs(text);
        }
    }
}

/// Replace every `0x` followed by at least 40 hex digits with `0x…`.
fn redact_evm_address_runs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let is_prefix = bytes[index] == b'0' && matches!(bytes.get(index + 1), Some(b'x' | b'X'));
        if is_prefix {
            let digits = bytes[index + 2..]
                .iter()
                .take_while(|byte| byte.is_ascii_hexdigit())
                .count();
            if digits >= 40 {
                out.push_str("0x\u{2026}");
                index += 2 + digits;
                continue;
            }
        }
        let ch = text[index..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// The cause chain beneath the outermost error, outermost first.
fn error_cause_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .skip(1)
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(" <- ")
}

/// `detail` bounded to 1024 bytes, cut on a character boundary.
fn bounded_error_detail(mut detail: String) -> String {
    const MAX_DETAIL_BYTES: usize = 1024;
    if detail.len() > MAX_DETAIL_BYTES {
        detail.truncate(detail.floor_char_boundary(MAX_DETAIL_BYTES));
    }
    detail
}

#[cfg(test)]
mod tests {
    /// A minted item must land on the shelf its own kind lives on, and every
    /// shelf named here must be reachable from the sidebar -- an item filed
    /// into a folder that is not a Library root is an item the creator cannot
    /// get to.
    #[test]
    fn minted_items_are_filed_by_kind_onto_reachable_shelves() {
        for (mime, expected) in [
            ("image/png", "Pictures"),
            ("IMAGE/JPEG", "Pictures"),
            ("video/mp4", "Videos"),
            ("audio/mpeg", "Music"),
            ("  audio/aac  ", "Music"),
            ("application/pdf", "Documents"),
            ("text/plain", "Documents"),
            ("", "Documents"),
        ] {
            let folder = super::library_folder_for_mime(mime);
            assert_eq!(folder, expected, "mime={mime}");
            let roots = super::library_roots(std::path::Path::new("/tmp"), "person:local:shelf");
            assert!(
                roots
                    .iter()
                    .any(|root| root.uri.ends_with(&format!("/{folder}"))),
                "{folder} must be a Library root, or a {mime} mint lands out of reach"
            );
        }
    }

    /// The capsule drops the source extension (its own `.ddrm` names the kind
    /// of item it is) and never lets a name escape its folder.
    #[test]
    fn capsule_names_drop_the_source_extension_and_cannot_traverse() {
        for (display_name, expected) in [
            ("holiday.jpeg", "holiday"),
            ("report.final.pdf", "report.final"),
            ("no-extension", "no-extension"),
            ("../../etc/passwd", "passwd"),
            ("..", "protected-content"),
            (".hidden", ".hidden"),
            ("", "protected-content"),
        ] {
            let base = super::runtime_custody_capsule_base_name(display_name);
            assert_eq!(base, expected, "display_name={display_name}");
            assert!(!base.contains('/'), "display_name={display_name}");
        }
    }

    #[test]
    fn viewer_ids_for_name_only_names_installed_capsule_ids() {
        for name in ["clip.mp4", "photo.png", "photo.jpg", "art.gif", "song.mp3"] {
            assert!(
                super::viewer_ids_for_name(name).is_empty(),
                "{name} must not name a phantom viewer"
            );
        }
        assert_eq!(super::viewer_ids_for_name("notes.md"), vec!["documents"]);
        // Documents edits text only; a PDF is offered as a download.
        assert!(super::viewer_ids_for_name("paper.pdf").is_empty());
        assert_eq!(super::viewer_ids_for_name("game.gba"), vec!["gba-emulator"]);
        assert_eq!(
            super::viewer_ids_for_name("bundle.zip"),
            vec!["archive-manager"]
        );
    }

    #[test]
    fn marketplace_buy_errors_redact_every_account_address() {
        let address = "0x19E7e376E7C213B7E7e7e46cc70A5dD086DAff2A";
        let error = anyhow::anyhow!("insufficient funds: address {address} have 0")
            .context("Runtime custody purchase is unavailable");
        let redacted = super::marketplace_buy_error_from(true, &error);
        assert_eq!(
            redacted["detail"],
            "insufficient funds: address 0x\u{2026} have 0"
        );
        assert_eq!(
            redacted["message"],
            "Runtime custody purchase is unavailable"
        );
        // Another op's envelope is left exactly as it was.
        let plain = super::marketplace_buy_error_from(false, &error);
        assert!(plain["detail"].as_str().unwrap().contains(address));
        // Short hex (a quantity, a code) is not an address; a longer run (a
        // transaction hash) is redacted all the same.
        assert_eq!(
            super::redact_evm_address_runs("value 0x2710 code 0x3 é"),
            "value 0x2710 code 0x3 é"
        );
        assert_eq!(
            super::redact_evm_address_runs(&format!("tx 0x{} done", "ab".repeat(32))),
            "tx 0x\u{2026} done"
        );
    }

    /// R42 (m1): the bound on `detail` never cuts an address into a run too
    /// short to be recognised. The whole cause chain is redacted first, and
    /// only then bounded.
    #[test]
    fn marketplace_buy_errors_redact_an_address_the_detail_bound_would_cut() {
        let address = "0x19E7e376E7C213B7E7e7e46cc70A5dD086DAff2A";
        for pad in [1000, 1010, 1020, 1023] {
            let error = anyhow::anyhow!("{} {address} have 0", "n".repeat(pad))
                .context("Runtime custody purchase is unavailable");
            let redacted = super::marketplace_buy_error_from(true, &error);
            let detail = redacted["detail"].as_str().unwrap();
            assert!(detail.len() <= 1024, "pad {pad}: {} bytes", detail.len());
            assert!(
                !detail.contains("0x19"),
                "pad {pad}: part of the address survived: {detail:?}"
            );
        }
    }

    /// The bound on `detail` lands on a character boundary, whatever the text.
    #[test]
    fn error_detail_bound_keeps_multibyte_text_whole() {
        // One ASCII byte first, so byte 1024 falls inside a two-byte 'é'.
        let error = anyhow::anyhow!("a{}", "é".repeat(700)).context("outer");
        for marketplace_buy in [false, true] {
            let value = super::marketplace_buy_error_from(marketplace_buy, &error);
            let detail = value["detail"].as_str().unwrap();
            assert!(detail.len() <= 1024);
            assert!(detail.chars().skip(1).all(|ch| ch == 'é'));
        }
    }

    #[test]
    fn provider_error_from_keeps_the_stable_message_and_exposes_the_cause_chain() {
        let error = anyhow::anyhow!("(400, \"upstream_rpc_error: reverted\")")
            .context("gateway_provider_proxy.rs:1")
            .context("Runtime custody purchase is unavailable");
        let value = super::provider_error_from("library_error", &error);
        assert_eq!(value["status"], "error");
        assert_eq!(value["code"], "library_error");
        assert_eq!(value["message"], "Runtime custody purchase is unavailable");
        assert_eq!(
            value["detail"],
            "gateway_provider_proxy.rs:1 <- (400, \"upstream_rpc_error: reverted\")"
        );
        let plain = super::provider_error_from("library_error", &anyhow::anyhow!("only"));
        assert!(plain.get("detail").is_none());
    }

    /// A refusal that carries its reason as data must reach the caller as data.
    /// Apps decide what to offer from this field; the sentence is only a
    /// fallback, and matching patterns against it is what once turned a
    /// recoverable state into a dead end.
    #[test]
    fn provider_error_from_carries_the_typed_creator_mint_refusal() {
        let recorded = elastos_protected_content_runtime::RuntimeMintCreatorState::new(
            elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
                "wallet-account-1",
                "0xa",
                "0xf4240",
                Vec::new(),
                elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
                None,
                String::new(),
                String::new(),
            )
            .unwrap(),
            "bafycreatorcid",
            "ipfs://bafymetadata/metadata.json",
        )
        .unwrap();
        let blocked = crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked::new(
            elastos_protected_content_contracts::Digest32::new([0x11; 32]),
            &recorded,
        );
        let sentence = blocked.to_string();
        let value = super::provider_error_from("library_error", &anyhow::Error::new(blocked));

        assert_eq!(value["status"], "error");
        assert_eq!(value["message"], sentence);
        assert_eq!(value["creator_mint"]["state"], "recorded_only");
        assert_eq!(value["creator_mint"]["recorded_copies"], "0xa");
        assert_eq!(value["creator_mint"]["recorded_price"], "0xf4240");
        assert_eq!(value["creator_mint"]["can_start_over"], false);

        // Every other failure keeps the envelope it always had.
        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("creator_mint").is_none());
    }

    /// Each fail-closed refusal of an unfinished attempt keeps its sentence and
    /// adds the code Creator answers with Start over.
    #[test]
    fn provider_error_from_carries_the_typed_attempt_conflict() {
        use crate::protected_content_runtime::{
            RuntimeCustodyAttemptConflict, RuntimeCustodyAttemptConflictReason,
        };
        for (reason, wire, sentence) in [
            (
                RuntimeCustodyAttemptConflictReason::SourceChanged,
                "source_changed",
                "Runtime custody media preparation conflicts with existing authority",
            ),
            (
                RuntimeCustodyAttemptConflictReason::AuthorityChanged,
                "authority_changed",
                "Runtime custody mint intent conflicts with existing authority",
            ),
            (
                RuntimeCustodyAttemptConflictReason::DispatchUncertain,
                "dispatch_uncertain",
                "Runtime custody mint requires cleanup reconciliation",
            ),
        ] {
            let value = super::provider_error_from(
                "library_error",
                &RuntimeCustodyAttemptConflict::error(reason).context("outer"),
            );
            assert_eq!(value["attempt_conflict"]["reason"], wire);
            // Start over is offered only once the gateway has asked whether
            // the attempt could be set aside.
            assert_eq!(value["attempt_conflict"]["can_start_over"], false);
            let mut error = RuntimeCustodyAttemptConflict::error(reason);
            error
                .downcast_mut::<RuntimeCustodyAttemptConflict>()
                .unwrap()
                .set_can_start_over(true);
            let value = super::provider_error_from("library_error", &error);
            assert_eq!(value["attempt_conflict"]["can_start_over"], true);
            assert_eq!(value["message"], sentence);
        }
        // The two refusals that need the Wallet or an operator are never
        // answered by Start over.
        for reason in [
            RuntimeCustodyAttemptConflictReason::ApprovalOpen,
            RuntimeCustodyAttemptConflictReason::ListingUnreadable,
        ] {
            let mut error = RuntimeCustodyAttemptConflict::error(reason);
            error
                .downcast_mut::<RuntimeCustodyAttemptConflict>()
                .unwrap()
                .set_can_start_over(true);
            let value = super::provider_error_from("library_error", &error);
            assert_eq!(value["attempt_conflict"]["can_start_over"], false);
        }
        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("attempt_conflict").is_none());
    }

    /// The wallet-default refusal is additive: the opaque sentence every caller
    /// already matches on stays the `message`, and the typed field beneath it
    /// says which of the five conditions failed and names the network, so an
    /// app can offer "link your wallet" rather than "unavailable".
    #[test]
    fn provider_error_from_carries_the_typed_wallet_default_refusal() {
        let unusable =
            crate::protected_content_runtime::RuntimeCustodyWalletDefaultUnusable::new(
                crate::protected_content_runtime::RuntimeCustodyWalletDefaultReason::DefaultAccountSigningUnavailable,
                "eip155:8453",
            );
        let actionable = unusable.to_string();
        let value = super::provider_error_from(
            "library_error",
            &anyhow::Error::new(unusable).context("Runtime custody creator mint is unavailable"),
        );

        assert_eq!(value["status"], "error");
        assert_eq!(
            value["message"],
            "Runtime custody creator mint is unavailable"
        );
        assert_eq!(
            value["wallet_default"]["schema"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_WALLET_DEFAULT_UNUSABLE_SCHEMA_V1
        );
        assert_eq!(
            value["wallet_default"]["reason"],
            "default_account_signing_unavailable"
        );
        assert_eq!(value["wallet_default"]["chain_namespace"], "eip155:8453");

        // The actionable sentence rides in the cause chain, never displacing
        // the stable one, and it names the way out rather than the cause only.
        assert_eq!(value["detail"], actionable);
        assert!(actionable.contains("eip155:8453"));
        assert!(actionable.contains("link it in Wallet"));

        // Nothing sensitive travels: the answer is a reason and a network.
        let fields = value["wallet_default"]
            .as_object()
            .expect("the typed answer must be an object");
        assert_eq!(fields.len(), 3);

        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("wallet_default").is_none());
    }

    /// Wallet drift gets its own key, not `wallet_default`. The default is
    /// perfectly usable in this case -- it is simply not the account the mint
    /// already started on -- so an app that read this as a default problem
    /// would tell the creator to set a default they have already set.
    #[test]
    fn provider_error_from_carries_the_typed_wallet_drift_refusal() {
        let bound = "0x7ba979fa244b930c01bdc84de851e5bca64b9f81";
        let current_default = "0xab5028bdbb0826ad6f1885478e421db677b0001a";
        let drift = crate::protected_content_runtime::RuntimeCustodyCreatorWalletDrift::new(
            "eip155:8453",
            bound,
            current_default,
        );
        let actionable = drift.to_string();
        let value = super::provider_error_from(
            "library_error",
            &anyhow::Error::new(drift).context("Runtime custody creator mint is unavailable"),
        );

        assert_eq!(value["status"], "error");
        assert_eq!(
            value["message"],
            "Runtime custody creator mint is unavailable"
        );
        assert_eq!(
            value["wallet_drift"]["schema"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_CREATOR_WALLET_DRIFT_SCHEMA_V1
        );
        assert_eq!(
            value["wallet_drift"]["reason"],
            "creator_mint_bound_account_is_not_the_transaction_default"
        );
        assert_eq!(value["wallet_drift"]["chain_namespace"], "eip155:8453");

        // Both accounts travel, and they are the point: a refusal that says
        // "these two differ" without naming them leaves an app nothing to show.
        assert_eq!(value["wallet_drift"]["bound_address"], bound);
        assert_eq!(value["wallet_drift"]["default_address"], current_default);

        // The sentence names both ways out, not just the cause.
        assert_eq!(value["detail"], actionable);
        assert!(actionable.contains(bound), "{actionable}");
        assert!(actionable.contains(current_default), "{actionable}");
        assert!(
            actionable.contains("discard the recorded terms"),
            "{actionable}"
        );

        // Drift is not a default problem; the two answers stay separate so an
        // app branching on one never sees the other.
        assert!(value.get("wallet_default").is_none());
        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("wallet_drift").is_none());
    }

    /// A waiting state carried as data. The distinction the typed answer adds
    /// over the old shared sentence is `awaits_person`: one of these needs the
    /// creator to go and approve something, and the other needs them to do
    /// nothing at all.
    #[test]
    fn provider_error_from_carries_the_typed_effect_pending_state() {
        let external =
            crate::protected_content_runtime::RuntimeCustodyEffectPending::awaiting_wallet_approval(
                true,
                Some("metamask"),
            );
        assert!(external.awaits_person());
        let actionable = external.to_string();
        let value = super::provider_error_from(
            "library_error",
            &anyhow::Error::new(external).context(
                "Runtime custody creator mint is pending exact Wallet or Chain settlement",
            ),
        );
        assert_eq!(
            value["message"],
            "Runtime custody creator mint is pending exact Wallet or Chain settlement"
        );
        assert_eq!(
            value["effect_pending"]["schema"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_EFFECT_PENDING_SCHEMA_V1
        );
        assert_eq!(value["effect_pending"]["reason"], "wallet_approval");
        assert_eq!(value["effect_pending"]["awaits_person"], true);
        assert_eq!(value["effect_pending"]["connector_id"], "metamask");
        // Names where to go, not merely that something is pending.
        assert_eq!(value["detail"], actionable);
        assert!(actionable.contains("metamask"), "{actionable}");

        // A managed approval is outstanding too, but nobody has to act on it.
        let managed =
            crate::protected_content_runtime::RuntimeCustodyEffectPending::awaiting_wallet_approval(
                false, None,
            );
        assert!(!managed.awaits_person());
        let value = super::provider_error_from("library_error", &anyhow::Error::new(managed));
        assert_eq!(value["effect_pending"]["awaits_person"], false);

        // A chain wait states no signer at all: the signer already did their
        // part, and the site that raises it has no account in hand to describe.
        let chain = crate::protected_content_runtime::RuntimeCustodyEffectPending::
            awaiting_chain_settlement();
        assert!(!chain.awaits_person());
        let value = super::provider_error_from("library_error", &anyhow::Error::new(chain));
        assert_eq!(value["effect_pending"]["reason"], "chain_settlement");
        assert_eq!(value["effect_pending"]["awaits_person"], false);
        assert!(value["effect_pending"].get("external_signer").is_none());
        assert!(value["effect_pending"].get("connector_id").is_none());

        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("effect_pending").is_none());
    }

    /// How far an open has got, carried as data. The fact a viewer needs is
    /// `resumable`: one of these means "ask again once the person answers the
    /// Wallet" and another means "asking again answers the same". Both used to
    /// arrive as one sentence, so the viewer showed the sentence and stopped --
    /// which turned the ordinary first open of every protected item into a dead
    /// end, because every first rights-signature request needs an approval.
    #[test]
    fn provider_error_from_carries_the_typed_open_progress_state() {
        let external =
            crate::protected_content_runtime::RuntimeCustodyOpenProgress::awaiting_rights_approval(
                true,
                Some("metamask"),
                "approval-7",
                1_700_000_290,
            );
        assert!(external.awaits_person());
        assert_eq!(external.stage_label(), "rights_approval");
        let actionable = external.to_string();
        let value = super::provider_error_from(
            "library_error",
            &anyhow::Error::new(external)
                .context("Runtime custody viewer release is pending exact Wallet approval"),
        );
        assert_eq!(
            value["message"],
            "Runtime custody viewer release is pending exact Wallet approval"
        );
        assert_eq!(
            value["open_progress"]["schema"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_OPEN_PROGRESS_SCHEMA_V1
        );
        assert_eq!(value["open_progress"]["stage"], "rights_approval");
        assert_eq!(value["open_progress"]["resumable"], true);
        assert_eq!(value["open_progress"]["awaits_person"], true);
        assert_eq!(value["open_progress"]["connector_id"], "metamask");
        // The exact approval the person answers, as data. It already reached
        // callers inside the cause chain; a viewer can now name it without
        // parsing it back out of a sentence.
        assert_eq!(value["open_progress"]["approval_request_id"], "approval-7");
        assert_eq!(value["open_progress"]["expires_at"], 1_700_000_290u64);
        // Names where to go, not merely that something is pending.
        assert_eq!(value["detail"], actionable);
        assert!(actionable.contains("metamask"), "{actionable}");

        // A managed approval is outstanding too, and nobody has to act on it.
        // The open still resumes, so the viewer keeps waiting either way.
        let managed =
            crate::protected_content_runtime::RuntimeCustodyOpenProgress::awaiting_rights_approval(
                false,
                None,
                "approval-8",
                1_700_000_290,
            );
        assert!(!managed.awaits_person());
        let value = super::provider_error_from("library_error", &anyhow::Error::new(managed));
        assert_eq!(value["open_progress"]["awaits_person"], false);
        assert_eq!(value["open_progress"]["resumable"], true);
        assert_eq!(
            value["open_progress"]["connector_id"],
            serde_json::Value::Null
        );

        // Absent for now: the same open can succeed later, and nobody is being
        // waited on, so no approval is described.
        let unavailable =
            crate::protected_content_runtime::RuntimeCustodyOpenProgress::unavailable();
        let value = super::provider_error_from("library_error", &anyhow::Error::new(unavailable));
        assert_eq!(value["open_progress"]["stage"], "unavailable");
        assert_eq!(value["open_progress"]["resumable"], true);
        assert_eq!(value["open_progress"]["awaits_person"], false);
        assert!(value["open_progress"].get("approval_request_id").is_none());
        assert!(value["open_progress"].get("expires_at").is_none());

        // Refused: this is the one a viewer must not keep asking about.
        let denied = crate::protected_content_runtime::RuntimeCustodyOpenProgress::denied();
        let value = super::provider_error_from("library_error", &anyhow::Error::new(denied));
        assert_eq!(value["open_progress"]["stage"], "denied");
        assert_eq!(value["open_progress"]["resumable"], false);
        assert_eq!(value["open_progress"]["awaits_person"], false);

        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("open_progress").is_none());
    }

    /// How far a purchase has got, carried as data. A buyer's three waits look
    /// the same from the outside and mean different things: one asks them to
    /// answer their wallet, one asks nothing while the network confirms, and
    /// one is their own refusal. All three used to arrive as the same sentence,
    /// which Marketplace then dropped for containing the word "Runtime", so a
    /// purchase that was proceeding normally read as one that had failed.
    #[test]
    fn provider_error_from_carries_the_typed_buy_progress_state() {
        use crate::protected_content_runtime::{RuntimeCustodyBuyProgress, RuntimeCustodyBuyStage};

        let external = RuntimeCustodyBuyProgress::awaiting_approval(
            RuntimeCustodyBuyStage::PurchaseApproval,
            true,
            Some("wallet-metamask"),
        );
        assert!(external.awaits_person());
        assert_eq!(external.stage_label(), "purchase_approval");
        let actionable = external.to_string();
        let value = super::provider_error_from(
            "library_error",
            &anyhow::Error::new(external).context(
                crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE,
            ),
        );
        assert_eq!(
            value["message"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE,
            "the sentence older callers match on stays outermost"
        );
        assert_eq!(
            value["buy_progress"]["schema"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_BUY_PROGRESS_SCHEMA_V1
        );
        assert_eq!(value["buy_progress"]["stage"], "purchase_approval");
        assert_eq!(value["buy_progress"]["resumable"], true);
        assert_eq!(value["buy_progress"]["awaits_person"], true);
        assert_eq!(value["buy_progress"]["connector_id"], "wallet-metamask");
        // Names where to go, not merely that something is pending.
        assert_eq!(value["detail"], actionable);
        assert!(actionable.contains("wallet-metamask"), "{actionable}");

        // An allowance is a different approval from the purchase, and a buyer
        // asked for two in a row needs to know which one they are answering.
        let allowance = RuntimeCustodyBuyProgress::awaiting_approval(
            RuntimeCustodyBuyStage::AllowanceApproval,
            true,
            None,
        );
        assert!(allowance.to_string().contains("Allow the payment"));
        let value = super::provider_error_from("library_error", &anyhow::Error::new(allowance));
        assert_eq!(value["buy_progress"]["stage"], "allowance_approval");
        assert_eq!(value["buy_progress"]["awaits_person"], true);

        // A managed account has an approval outstanding too, and nobody has to
        // act on it.
        let managed = RuntimeCustodyBuyProgress::awaiting_approval(
            RuntimeCustodyBuyStage::PurchaseApproval,
            false,
            None,
        );
        assert!(!managed.awaits_person());
        let value = super::provider_error_from("library_error", &anyhow::Error::new(managed));
        assert_eq!(value["buy_progress"]["awaits_person"], false);
        assert_eq!(value["buy_progress"]["resumable"], true);

        // Two waits that name nobody: the chain, and the right becoming
        // readable. The signer has already done everything asked of them.
        for (stage, wire) in [
            (RuntimeCustodyBuyStage::ChainSettlement, "chain_settlement"),
            (RuntimeCustodyBuyStage::AccessEvidence, "access_evidence"),
        ] {
            let waiting = RuntimeCustodyBuyProgress::waiting(stage);
            assert!(!waiting.awaits_person());
            let value = super::provider_error_from("library_error", &anyhow::Error::new(waiting));
            assert_eq!(value["buy_progress"]["stage"], wire);
            assert_eq!(value["buy_progress"]["resumable"], true);
            assert!(value["buy_progress"].get("external_signer").is_none());
            assert!(value["buy_progress"].get("connector_id").is_none());
        }

        // Declining is an answer, and asking again cannot change it. That is
        // what stops an app polling a purchase that will never settle.
        let declined = RuntimeCustodyBuyProgress::declined();
        assert!(!declined.awaits_person());
        assert_eq!(declined.stage_label(), "declined");
        let value = super::provider_error_from("library_error", &anyhow::Error::new(declined));
        assert_eq!(value["buy_progress"]["stage"], "declined");
        assert_eq!(value["buy_progress"]["resumable"], false);

        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("buy_progress").is_none());
    }

    fn listing_request(json: serde_json::Value) -> super::LibraryPublishListingRequest {
        serde_json::from_value(json).expect("fixture must parse")
    }

    fn valid_listing_json() -> serde_json::Value {
        json!({
            "title": "  My asset  ",
            "description": " What it is ",
            "category": "art",
            "tags": ["one", "  ", "two"],
            "royalties": [
                { "address": "0xAB5028BDBB0826AD6F1885478E421DB677B0001A", "units": 900 },
                { "address": "0x7ba979fa244b930c01bdc84de851e5bca64b9f81", "units": 50 }
            ],
            "adult": false
        })
    }

    /// Listing terms are claims the listing makes publicly, so each rule fails
    /// closed rather than normalising: a silently corrected royalty split or a
    /// dropped over-size cover produces a listing that says something the
    /// creator never asked for.
    #[test]
    fn listing_terms_are_normalised_and_accepted_when_every_rule_holds() {
        let terms = super::validate_runtime_custody_listing(listing_request(valid_listing_json()))
            .expect("a complete, consistent listing must be accepted");
        assert_eq!(terms.title, "My asset");
        assert_eq!(terms.description, "What it is");
        // Blank tags are dropped, real ones trimmed and kept in order.
        assert_eq!(terms.tags, vec!["one".to_string(), "two".to_string()]);
        // Addresses are lowercased so two spellings of one payee cannot read
        // as two payees downstream.
        assert_eq!(
            terms.royalties[0].address,
            "0xab5028bdbb0826ad6f1885478e421db677b0001a"
        );
        assert_eq!(terms.royalties.len(), 2);
    }

    #[test]
    fn listing_terms_require_a_title() {
        for title in ["", "   "] {
            let mut value = valid_listing_json();
            value["title"] = json!(title);
            super::validate_runtime_custody_listing(listing_request(value))
                .expect_err("a listing with no title must fail closed");
        }
    }

    #[test]
    fn listing_royalties_must_total_exactly_the_creator_share() {
        // The chain applies 9500 to the creator and 500 to the protocol. A
        // split that does not total 9500 is not one the chain can honour, so
        // showing it would describe a payout that will not happen.
        for total in [949_u32, 951, 1000] {
            let mut value = valid_listing_json();
            value["royalties"] = json!([
                { "address": "0xab5028bdbb0826ad6f1885478e421db677b0001a", "units": total }
            ]);
            super::validate_runtime_custody_listing(listing_request(value))
                .expect_err("a split that does not total the creator share must fail closed");
        }
        let mut value = valid_listing_json();
        value["royalties"] = json!([
            { "address": "0xab5028bdbb0826ad6f1885478e421db677b0001a", "units": 950 }
        ]);
        super::validate_runtime_custody_listing(listing_request(value))
            .expect("a split totalling exactly the creator share is accepted");
    }

    #[test]
    fn listing_royalties_reject_a_malformed_payee_or_an_empty_share() {
        for address in [
            "0xnothex",
            "ab5028bdbb0826ad6f1885478e421db677b0001a",
            "0xab50",
            "",
        ] {
            let mut value = valid_listing_json();
            value["royalties"] = json!([
                { "address": address, "units": 950 }
            ]);
            super::validate_runtime_custody_listing(listing_request(value))
                .expect_err("a malformed payee address must fail closed");
        }
        // A zero share is a payee who is owed nothing: almost certainly a
        // mistake, and never something to encode on chain.
        let mut value = valid_listing_json();
        value["royalties"] = json!([
            { "address": "0xab5028bdbb0826ad6f1885478e421db677b0001a", "units": 950 },
            { "address": "0x7ba979fa244b930c01bdc84de851e5bca64b9f81", "units": 0 }
        ]);
        super::validate_runtime_custody_listing(listing_request(value))
            .expect_err("a zero-share payee must fail closed");
    }

    #[test]
    fn listing_royalties_may_be_omitted_entirely() {
        // Absent is not the same as an invalid split: a caller that says
        // nothing gets the chain's own default, and nothing is claimed.
        let mut value = valid_listing_json();
        value["royalties"] = json!([]);
        let terms = super::validate_runtime_custody_listing(listing_request(value))
            .expect("an absent split is not an invalid one");
        assert!(terms.royalties.is_empty());
    }

    #[test]
    fn listing_thumbnail_must_be_an_image_within_the_byte_cap() {
        use base64::Engine as _;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

        let mut value = valid_listing_json();
        value["thumbnail"] = json!({ "mime": "image/png", "bytes_base64": encode(b"cover") });
        let terms = super::validate_runtime_custody_listing(listing_request(value))
            .expect("a small image cover is accepted");
        assert_eq!(terms.thumbnail.as_ref().unwrap().mime, "image/png");
        assert_eq!(terms.thumbnail.as_ref().unwrap().bytes, b"cover");

        // Not an image: the cover is published, so its type is a claim too.
        let mut value = valid_listing_json();
        value["thumbnail"] = json!({ "mime": "application/pdf", "bytes_base64": encode(b"x") });
        super::validate_runtime_custody_listing(listing_request(value))
            .expect_err("a non-image cover must fail closed");

        // Empty, unparseable, and over the cap.
        for bad in [
            json!({ "mime": "image/png", "bytes_base64": "" }),
            json!({ "mime": "image/png", "bytes_base64": "!!not base64!!" }),
        ] {
            let mut value = valid_listing_json();
            value["thumbnail"] = bad;
            super::validate_runtime_custody_listing(listing_request(value))
                .expect_err("an unusable cover must fail closed");
        }
        let mut value = valid_listing_json();
        value["thumbnail"] = json!({
            "mime": "image/png",
            "bytes_base64": encode(&vec![0u8; super::RUNTIME_CUSTODY_THUMBNAIL_MAX_BYTES + 1]),
        });
        super::validate_runtime_custody_listing(listing_request(value))
            .expect_err("a cover past the byte cap must fail closed");
    }

    /// A caller that sends a field this build does not understand is asking
    /// for something it will not get; dropping it silently is how a listing
    /// ends up claiming terms nobody applied.
    #[test]
    fn listing_terms_reject_an_unknown_field() {
        let mut value = valid_listing_json();
        value["resale_royalty_percent"] = json!(10);
        serde_json::from_value::<super::LibraryPublishListingRequest>(value)
            .expect_err("an unknown listing field must be refused, not ignored");
    }

    /// A publish with no listing block keeps the pre-listing behaviour, so an
    /// existing caller is unaffected.
    #[test]
    fn a_publish_without_listing_terms_still_parses() {
        let request: super::LibraryPublishProtectionRequest = serde_json::from_value(json!({
            "mode": "runtime_custody",
            "copies": "0x1",
            "price": "0x1"
        }))
        .expect("the pre-listing shape must still parse");
        let super::LibraryPublishProtectionRequest::RuntimeCustody { listing, .. } = request else {
            panic!("a runtime custody publish must parse as one");
        };
        assert!(listing.is_none());
    }

    /// A resume names no terms, and cannot be made to: the record supplies
    /// them, so a resume that also carried some would be asking for terms it
    /// will not get.
    #[test]
    fn a_resume_carries_no_terms() {
        let request: super::LibraryPublishProtectionRequest =
            serde_json::from_value(json!({ "mode": "runtime_custody_resume" }))
                .expect("a resume parses");
        assert!(matches!(
            request,
            super::LibraryPublishProtectionRequest::RuntimeCustodyResume {}
        ));
        assert!(
            serde_json::from_value::<super::LibraryPublishProtectionRequest>(json!({
                "mode": "runtime_custody_resume",
                "copies": "0x1"
            }))
            .is_err()
        );
    }

    /// The opposite of pending, and it used to be indistinguishable from it: a
    /// declined transaction answered "transaction approval is not completed",
    /// exactly like one the person simply had not got to, so anything polling
    /// for completion waited on it forever.
    #[test]
    fn provider_error_from_carries_a_closed_wallet_approval() {
        for (reason, wire, expected_words) in [
            (
                crate::protected_content_runtime::RuntimeCustodyApprovalClosedReason::Rejected,
                "approval_rejected",
                "declined",
            ),
            (
                crate::protected_content_runtime::RuntimeCustodyApprovalClosedReason::Expired,
                "approval_expired",
                "expired",
            ),
        ] {
            let closed =
                crate::protected_content_runtime::RuntimeCustodyApprovalClosed::new(reason);
            let actionable = closed.to_string();
            let value = super::provider_error_from(
                "library_error",
                &anyhow::Error::new(closed).context("Runtime custody creator mint is unavailable"),
            );
            assert_eq!(
                value["approval_closed"]["schema"],
                crate::protected_content_runtime::RUNTIME_CUSTODY_APPROVAL_CLOSED_SCHEMA_V1
            );
            assert_eq!(value["approval_closed"]["reason"], wire);
            assert_eq!(value["detail"], actionable);
            assert!(actionable.contains(expected_words), "{actionable}");
            // Terminal and pending are separate answers, so an app polling for
            // completion can stop on one without parsing the other.
            assert!(value.get("effect_pending").is_none());
        }

        let plain = super::provider_error_from("library_error", &anyhow!("only"));
        assert!(plain.get("approval_closed").is_none());
    }

    use super::*;

    /// The media families the ffmpeg-backed media provider accepts must be
    /// recognised as `video/*`/`audio/*`, because `library_publish` uses that
    /// prefix to keep protected publishing on the media transcode path. Before
    /// this table was widened only `.mp4`/`.mp3` were, so every other
    /// container silently fell through to the EPC1 object path — a real
    /// regression that no test caught, since every protected-content test uses
    /// `.mp4` or `.mp3` filenames.
    #[test]
    fn mime_for_name_routes_every_media_family_to_the_media_path() {
        for name in [
            "clip.mov",
            "CLIP.MOV",
            "clip.mkv",
            "clip.webm",
            "clip.m4v",
            "clip.mp4",
            "clip.avi",
            "clip.3gp",
            "clip.flv",
            "clip.mpg",
            "clip.mpeg",
            "clip.ts",
            "clip.m2ts",
            "clip.wmv",
            "clip.vob",
        ] {
            let mime = mime_for_name(name);
            assert!(
                mime.starts_with("video/"),
                "{name} must stay on the media path, got {mime}"
            );
        }
        for name in [
            "song.mp3",
            "song.m4a",
            "song.aac",
            "song.wav",
            "song.flac",
            "song.ogg",
            "song.oga",
            "song.opus",
            "song.mka",
            "song.wma",
        ] {
            let mime = mime_for_name(name);
            assert!(
                mime.starts_with("audio/"),
                "{name} must stay on the media path, got {mime}"
            );
        }
    }

    /// Non-media names must NOT leak onto the media path, and anything the
    /// table does not know must stay `application/octet-stream` so
    /// `library_publish` refuses it instead of minting an un-openable object.
    /// `avif`/`heic`/`heif` matter specifically: ffmpeg's `mov` demuxer claims
    /// them, so a naive "whatever ffmpeg reads is media" list would capture
    /// still images.
    #[test]
    fn mime_for_name_keeps_non_media_off_the_media_path() {
        for (name, expected) in [
            ("notes.md", "text/plain"),
            ("notes.txt", "text/plain"),
            ("page.html", "text/html"),
            ("data.json", "application/json"),
            ("shot.png", "image/png"),
            ("shot.jpg", "image/jpeg"),
            ("shot.jpeg", "image/jpeg"),
            ("shot.gif", "image/gif"),
            ("book.pdf", "application/pdf"),
            ("bundle.tar", "application/x-tar"),
            ("bundle.tar.gz", "application/gzip"),
            ("bundle.tgz", "application/gzip"),
            ("bundle.zip", "application/zip"),
            ("shot.avif", "application/octet-stream"),
            ("shot.heic", "application/octet-stream"),
            ("shot.heif", "application/octet-stream"),
            ("model.glb", "application/octet-stream"),
            ("noextension", "application/octet-stream"),
        ] {
            assert_eq!(mime_for_name(name), expected, "{name}");
        }
    }

    /// The three protected viewer operations bind a session to
    /// `executable_actor`, which only the gateway proxy verifies. On the raw
    /// provider route every request field is caller-supplied, so they must be
    /// refused there rather than trust it.
    #[tokio::test]
    async fn raw_object_provider_route_refuses_protected_viewer_operations() {
        let registry = Arc::new(ProviderRegistry::new());
        let temp = tempfile::tempdir().unwrap();
        let provider = ObjectProvider::new(temp.path().to_path_buf(), Arc::downgrade(&registry));
        for request in [
            json!({
                "op": "open_viewer",
                "principal_id": "person:local:raw-viewer",
                "mint_id": "00".repeat(32),
                "executable_actor": "elacity-player",
            }),
            json!({
                "op": "read_viewer",
                "principal_id": "person:local:raw-viewer",
                "mint_id": "00".repeat(32),
                "viewer_session_handle": "00".repeat(32),
                "executable_actor": "elacity-player",
            }),
            json!({
                "op": "close_viewer",
                "principal_id": "person:local:raw-viewer",
                "mint_id": "00".repeat(32),
                "viewer_session_handle": "00".repeat(32),
                "executable_actor": "elacity-player",
            }),
        ] {
            let response = provider.send_raw(&request).await.unwrap();
            assert_eq!(response["status"], "error", "{request}");
            assert_eq!(
                response["message"], RUNTIME_CUSTODY_VIEWER_ROUTE_DENIED_MESSAGE,
                "{request}"
            );
        }
    }

    /// `chunk_index` is now a DECLARED and honoured selector on `read_viewer`
    /// (it names the object chunk to decrypt), so a request carrying one must
    /// no longer be refused as an unknown field — it must reach the ordinary
    /// viewer-route gate, which still refuses viewer operations on the raw
    /// provider route. An undeclared selector must still be a request error,
    /// which is what keeps a future third selector from being accepted and
    /// silently ignored.
    #[tokio::test]
    async fn raw_object_provider_route_parses_a_chunk_index_selector_and_denies_the_route() {
        let registry = Arc::new(ProviderRegistry::new());
        let temp = tempfile::tempdir().unwrap();
        let provider = ObjectProvider::new(temp.path().to_path_buf(), Arc::downgrade(&registry));
        let response = provider
            .send_raw(&json!({
                "op": "read_viewer",
                "principal_id": "person:local:raw-viewer",
                "mint_id": "00".repeat(32),
                "viewer_session_handle": "00".repeat(32),
                "executable_actor": "elacity-reader",
                "chunk_index": 0,
            }))
            .await
            .unwrap();
        assert_eq!(response["status"], "error", "{response}");
        assert_eq!(
            response["message"], RUNTIME_CUSTODY_VIEWER_ROUTE_DENIED_MESSAGE,
            "{response}"
        );

        let unknown_selector = provider
            .send_raw(&json!({
                "op": "read_viewer",
                "principal_id": "person:local:raw-viewer",
                "mint_id": "00".repeat(32),
                "viewer_session_handle": "00".repeat(32),
                "executable_actor": "elacity-reader",
                "frame_index": 0,
            }))
            .await
            .unwrap();
        assert_eq!(unknown_selector["status"], "error");
        assert_eq!(unknown_selector["code"], "invalid_request");
        assert!(
            unknown_selector["message"]
                .as_str()
                .unwrap_or_default()
                .contains("frame_index"),
            "{unknown_selector}"
        );
    }

    #[test]
    fn object_provider_exposes_object_scheme_only() {
        let registry = Arc::new(ProviderRegistry::new());
        let provider = ObjectProvider::new(PathBuf::new(), Arc::downgrade(&registry));
        let schemes = provider.schemes();

        assert!(schemes.contains(&"object"));
        assert!(!schemes.contains(&"library"));
        assert_eq!(provider.name(), "object-provider");
    }

    #[tokio::test]
    #[ignore = "requires ELASTOS_LIVE_IPFS_PROVIDER_BIN and ELASTOS_LIVE_IPFS_DATA_DIR"]
    async fn library_live_ipfs_publish_provider_route_smoke() {
        let Ok(ipfs_provider_bin) = std::env::var("ELASTOS_LIVE_IPFS_PROVIDER_BIN") else {
            eprintln!("skipping live Library publish smoke: ELASTOS_LIVE_IPFS_PROVIDER_BIN unset");
            return;
        };
        let Ok(ipfs_data_dir) = std::env::var("ELASTOS_LIVE_IPFS_DATA_DIR") else {
            eprintln!("skipping live Library publish smoke: ELASTOS_LIVE_IPFS_DATA_DIR unset");
            return;
        };
        let ipfs_provider_bin = PathBuf::from(ipfs_provider_bin);
        let ipfs_data_dir = PathBuf::from(ipfs_data_dir);
        assert!(
            ipfs_provider_bin.is_file(),
            "ipfs-provider missing: {}",
            ipfs_provider_bin.display()
        );
        assert!(
            ipfs_data_dir.is_dir(),
            "IPFS data dir missing: {}",
            ipfs_data_dir.display()
        );

        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        let ipfs_config = elastos_runtime::provider::BridgeProviderConfig {
            base_path: ipfs_data_dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let bridge = Arc::new(
            elastos_runtime::provider::ProviderBridge::spawn(&ipfs_provider_bin, ipfs_config)
                .await
                .expect("spawn live ipfs-provider"),
        );
        let ipfs_provider: Arc<dyn Provider> = Arc::new(
            elastos_runtime::provider::CapsuleProvider::with_scheme(Arc::clone(&bridge), "ipfs"),
        );
        registry
            .register_sub_provider("ipfs", ipfs_provider)
            .await
            .unwrap();
        let content_provider = Arc::new(crate::content::ContentProvider::new(
            dir.path().to_path_buf(),
            Arc::downgrade(&registry),
        ));
        registry.register(content_provider.clone()).await;
        registry
            .register_sub_provider("content", content_provider)
            .await
            .unwrap();

        let principal_id = "did:key:z6MklibraryLiveIpfsSmoke";
        let roots = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "roots",
                "principal_id": principal_id,
            }),
        )
        .await;
        assert_eq!(roots["status"], "ok", "{roots}");
        let public_uri = roots["data"]["roots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|root| root["id"] == "public")
            .and_then(|root| root["uri"].as_str())
            .expect("public Library root")
            .to_string();

        let body = format!("Library live IPFS provider route smoke {}\n", now_ts());
        let file_uri = format!("{public_uri}/library-live-ipfs-provider-smoke.txt");
        let write = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "write",
                "principal_id": principal_id,
                "uri": file_uri,
                "mime": "text/plain",
                "data": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
            }),
        )
        .await;
        assert_eq!(write["status"], "ok", "{write}");
        let revision = write["data"]["object"]["revision"]
            .as_str()
            .expect("write revision")
            .to_string();

        let publish = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "publish",
                "principal_id": principal_id,
                "uri": file_uri,
                "if_revision": revision,
            }),
        )
        .await;
        assert_eq!(publish["status"], "ok", "{publish}");
        let cid = publish["data"]["cid"].as_str().expect("publish cid");
        assert!(!cid.trim().is_empty());
        assert_eq!(publish["data"]["uri"], format!("elastos://{cid}"));
        assert_eq!(publish["data"]["availability"]["status"], "local_pinned");
        assert_eq!(publish["data"]["object"]["published_cid"], cid);

        let status = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "status",
                "principal_id": principal_id,
                "uri": file_uri,
            }),
        )
        .await;
        assert_eq!(status["status"], "ok", "{status}");
        assert_eq!(status["data"]["published"]["cid"], cid);

        bridge
            .shutdown()
            .await
            .expect("shutdown live ipfs-provider");
        println!("library live IPFS provider route cid={cid}");
    }

    #[tokio::test]
    async fn create_only_write_preserves_existing_file_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        let principal_id = "did:key:z6MkCreateOnlyExisting";
        let file_uri = format!(
            "{}/Documents/Notes.txt",
            crate::auth::principal_localhost_root(principal_id)
        );
        let original = b"original bytes";
        let replacement = b"replacement bytes";

        let write = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "write",
                "principal_id": principal_id,
                "uri": file_uri,
                "mime": "text/plain",
                "data": base64::engine::general_purpose::STANDARD.encode(original),
            }),
        )
        .await;
        assert_eq!(write["status"], "ok", "{write}");

        let create_only = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "write",
                "principal_id": principal_id,
                "uri": file_uri,
                "mime": "text/plain",
                "create_only": true,
                "data": base64::engine::general_purpose::STANDARD.encode(replacement),
            }),
        )
        .await;
        assert_eq!(create_only["status"], "error", "{create_only}");
        assert_eq!(
            create_only["message"], "library destination already exists",
            "{create_only}"
        );

        let read = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "read",
                "principal_id": principal_id,
                "uri": file_uri,
            }),
        )
        .await;
        assert_eq!(read["status"], "ok", "{read}");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(read["data"]["data"].as_str().unwrap())
                .unwrap(),
            original
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_only_write_is_atomic_for_concurrent_new_file_requests() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        let principal_id = "did:key:z6MkCreateOnlyConcurrent";
        let file_uri = format!(
            "{}/Documents/Concurrent.txt",
            crate::auth::principal_localhost_root(principal_id)
        );
        let first_payload = base64::engine::general_purpose::STANDARD.encode(b"first");
        let second_payload = base64::engine::general_purpose::STANDARD.encode(b"second");
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let first_request = json!({
            "op": "write",
            "principal_id": principal_id,
            "uri": file_uri,
            "mime": "text/plain",
            "create_only": true,
            "data": first_payload,
        });
        let second_request = json!({
            "op": "write",
            "principal_id": principal_id,
            "uri": file_uri,
            "mime": "text/plain",
            "create_only": true,
            "data": second_payload,
        });
        let first_task = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            let registry = Arc::clone(&registry);
            let data_dir = dir.path().to_path_buf();
            async move {
                barrier.wait().await;
                handle_object_provider_runtime_request(&data_dir, registry, &first_request).await
            }
        });
        let second_task = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            let registry = Arc::clone(&registry);
            let data_dir = dir.path().to_path_buf();
            async move {
                barrier.wait().await;
                handle_object_provider_runtime_request(&data_dir, registry, &second_request).await
            }
        });
        barrier.wait().await;

        let (first, second) = tokio::join!(async { first_task.await.unwrap() }, async {
            second_task.await.unwrap()
        },);
        let outcomes = [first, second];
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| value["status"] == "ok")
                .count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| value["message"] == "library destination already exists")
                .count(),
            1,
            "{outcomes:?}"
        );
        let winning_bytes = if outcomes[0]["status"] == "ok" {
            b"first".as_slice()
        } else if outcomes[1]["status"] == "ok" {
            b"second".as_slice()
        } else {
            panic!("missing successful create_only write: {outcomes:?}");
        };

        let read = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "read",
                "principal_id": principal_id,
                "uri": file_uri,
            }),
        )
        .await;
        assert_eq!(read["status"], "ok", "{read}");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(read["data"]["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, winning_bytes);
    }

    #[tokio::test]
    async fn create_only_write_rejects_if_revision() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        let principal_id = "did:key:z6MkCreateOnlyIfRevision";
        let file_uri = format!(
            "{}/Documents/Notes.txt",
            crate::auth::principal_localhost_root(principal_id)
        );

        let write = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "write",
                "principal_id": principal_id,
                "uri": file_uri,
                "mime": "text/plain",
                "if_revision": "rev:existing",
                "create_only": true,
                "data": base64::engine::general_purpose::STANDARD.encode(b"blocked"),
            }),
        )
        .await;
        assert_eq!(write["status"], "error", "{write}");
        assert_eq!(
            write["message"], "library create-only write does not accept if_revision",
            "{write}"
        );
        assert!(!library_target(dir.path(), principal_id, &file_uri)
            .unwrap()
            .path
            .exists());
    }

    #[tokio::test]
    async fn revisioned_write_still_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        let principal_id = "did:key:z6MkRevisionedWrite";
        let file_uri = format!(
            "{}/Documents/Notes.txt",
            crate::auth::principal_localhost_root(principal_id)
        );

        let write = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "write",
                "principal_id": principal_id,
                "uri": file_uri,
                "mime": "text/plain",
                "data": base64::engine::general_purpose::STANDARD.encode(b"original"),
            }),
        )
        .await;
        assert_eq!(write["status"], "ok", "{write}");
        let revision = write["data"]["object"]["revision"].as_str().unwrap();

        let replacement = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "write",
                "principal_id": principal_id,
                "uri": file_uri,
                "mime": "text/plain",
                "if_revision": revision,
                "data": base64::engine::general_purpose::STANDARD.encode(b"updated"),
            }),
        )
        .await;
        assert_eq!(replacement["status"], "ok", "{replacement}");

        let read = handle_object_provider_runtime_request(
            dir.path(),
            Arc::clone(&registry),
            &json!({
                "op": "read",
                "principal_id": principal_id,
                "uri": file_uri,
            }),
        )
        .await;
        assert_eq!(read["status"], "ok", "{read}");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(read["data"]["data"].as_str().unwrap())
                .unwrap(),
            b"updated"
        );
    }

    /// Documents edits text: a name routes to it only when its manifest
    /// accepts that extension, so a PDF or other binary never opens as text.
    #[test]
    fn documents_is_offered_only_for_extensions_its_manifest_accepts() {
        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../capsules/documents/capsule.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let accepted: Vec<String> = manifest["interfaces"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|interface| interface["methods"].as_array().unwrap().iter())
            .filter(|method| method["id"] == "document.open")
            .flat_map(|method| method["input_schema"]["accepts"].as_array().unwrap().iter())
            .flat_map(|accept| accept["extensions"].as_array().unwrap().iter())
            .map(|extension| extension.as_str().unwrap().to_string())
            .collect();
        assert!(!accepted.is_empty());
        for name in [
            "note.md",
            "note.txt",
            "letter.pdf",
            "photo.png",
            "bundle.zip",
            "clip.mp4",
            "song.mp3",
            "data.json",
            "page.html",
            "game.gba",
            "blob.bin",
        ] {
            let routed = super::viewer_ids_for_name(name).contains(&"documents");
            let accepts = accepted
                .iter()
                .any(|extension| name.ends_with(extension.as_str()));
            assert_eq!(
                routed, accepts,
                "{name}: Documents routing must match its manifest"
            );
        }
    }

    /// #449: a folder added to a copy or move source after the tree check
    /// is refused by the writer itself.
    #[test]
    fn copy_and_move_writers_refuse_a_folder_added_after_the_tree_check() {
        let dir = tempfile::tempdir().unwrap();
        let principal_id = "person:local:library-late-child";
        let root = crate::auth::principal_localhost_root(principal_id);
        let rule = StartWalkRule::new(dir.path(), &root);
        let mut parent = format!("{root}/Documents");
        for level in 1..=14 {
            parent.push_str(&format!("/{level}"));
        }
        for writer in ["copy", "move"] {
            let from = library_target(
                dir.path(),
                principal_id,
                &format!("{root}/Documents/Source-{writer}"),
            )
            .unwrap();
            let to =
                library_target(dir.path(), principal_id, &format!("{parent}/{writer}")).unwrap();
            fs::create_dir_all(&from.path).unwrap();
            // The empty source lands 15 folders deep: allowed.
            rule.tree(&from.path, &to.uri).unwrap();
            // A folder added now would land 16 deep.
            fs::create_dir(from.path.join("late")).unwrap();
            let result = if writer == "copy" {
                copy_library_directory(dir.path(), principal_id, &rule, &from, &to)
            } else {
                move_library_directory(dir.path(), principal_id, &rule, &from, &to)
            };
            let message = result.unwrap_err().to_string();
            assert!(
                message.ends_with(&format!(
                    "{writer}/late was not saved: it would be more than 16 folders deep in \
                     Documents, and Home does not start with folders that deep. Save it fewer \
                     folders down."
                )),
                "{writer}: {message}"
            );
            assert!(!to.path.join("late").exists(), "{writer}");
            assert!(from.path.join("late").is_dir(), "{writer}");
        }
    }

    /// #449: an entry larger than its declared size is read at most one byte
    /// past the limit, then refused.
    #[test]
    fn archive_expansion_stops_reading_an_entry_larger_than_it_declares() {
        let mut expansion = ArchiveExpansion::new("Lies.zip");
        let mut body = std::io::Read::take(std::io::repeat(0), MAX_ARCHIVE_ENTRY_BYTES + 10);
        let message = expansion
            .read("lie.bin", 1, &mut body)
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "lie.bin in Lies.zip would be more than 100 MiB once extracted; Library extracts \
             files of up to 100 MiB from an archive."
        );
        assert_eq!(body.limit(), 9);
    }

    /// #449: the Spaces keep budget is enforced while a file is read: the
    /// read stops one byte past what is left.
    #[test]
    fn archive_keep_budget_stops_reading_at_what_is_left() {
        let mut expansion = ArchiveExpansion::with_keep_budget("Pack.zip", 10);
        let mut first = std::io::Read::take(std::io::repeat(1), 4);
        assert_eq!(expansion.read("a", 4, &mut first).unwrap().len(), 4);
        // Declares 4, holds 1 MiB: 6 bytes are left, so 7 are read.
        let mut second = std::io::Read::take(std::io::repeat(1), 1024 * 1024);
        let message = expansion.read("b", 4, &mut second).unwrap_err().to_string();
        assert_eq!(
            message,
            "The files selected in Pack.zip are more than 256 MiB; Spaces takes up to 256 MiB \
             from one archive at a time. Select fewer files."
        );
        assert_eq!(second.limit(), 1024 * 1024 - 7);
        // A declared size over what is left is refused before any read.
        let mut third = std::io::Read::take(std::io::repeat(1), 100);
        assert!(expansion.read("c", 100, &mut third).is_err());
        assert_eq!(third.limit(), 100);
    }

    /// #449: a tar whose long name or PAX record is over 1 MiB is refused by
    /// every tar reader before the record is held in memory.
    #[test]
    fn tar_readers_refuse_an_oversized_name_or_header_record() {
        const RECORD: u64 = 2 * 1024 * 1024;
        let refusal = "Big.tar.gz holds an entry name or header of more than 1 MiB; Library \
                       does not open archives like that.";
        for kind in [tar::EntryType::GNULongName, tar::EntryType::XHeader] {
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(RECORD);
            header.set_mode(0o644);
            header.as_gnu_mut().unwrap().name[..13].copy_from_slice(b"././@LongLink");
            header.set_cksum();
            builder
                .append(&header, std::io::Read::take(std::io::repeat(b'a'), RECORD))
                .unwrap();
            let mut file = tar::Header::new_gnu();
            file.set_size(1);
            file.set_mode(0o644);
            builder.append_data(&mut file, "x.txt", &b"x"[..]).unwrap();
            let bytes = builder.into_inner().unwrap().finish().unwrap();

            let listed = list_tar_archive_entries("Big.tar.gz", bytes.clone());
            assert_eq!(listed.unwrap_err().to_string(), refusal, "{kind:?}");
            let previewed = preview_tar_archive_entry("Big.tar.gz", bytes.clone(), "x.txt");
            assert_eq!(previewed.err().unwrap().to_string(), refusal, "{kind:?}");
            let mut outcome = ArchiveExtractOutcome::new(BTreeSet::from(["x.txt".to_string()]));
            let mut written = 0;
            let selected = read_selected_archive_entries(
                "Big.tar.gz",
                bytes,
                None,
                &mut outcome,
                &mut |_, _| {
                    written += 1;
                    Ok(())
                },
            );
            assert_eq!(selected.unwrap_err().to_string(), refusal, "{kind:?}");
            assert_eq!(written, 0, "{kind:?}");
        }
    }

    /// #449: a GNU sparse entry is refused by every tar reader before the
    /// reader goes on, so its logical size cannot open room for a large
    /// long name after it.
    #[test]
    fn tar_readers_refuse_a_sparse_entry_before_a_large_long_name() {
        const LOGICAL: u64 = 512 * 1024 * 1024;
        const RECORD: u64 = 2 * 1024 * 1024;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        // A sparse file of 512 MiB that stores no bytes.
        let mut sparse = tar::Header::new_gnu();
        sparse.set_entry_type(tar::EntryType::GNUSparse);
        sparse.set_path("hole.bin").unwrap();
        sparse.set_size(0);
        sparse.set_mode(0o644);
        let gnu = sparse.as_gnu_mut().unwrap();
        gnu.set_real_size(LOGICAL);
        gnu.sparse[0].set_offset(LOGICAL);
        gnu.sparse[0].set_length(0);
        sparse.set_cksum();
        builder.append(&sparse, std::io::empty()).unwrap();
        let mut long_name = tar::Header::new_gnu();
        long_name.set_entry_type(tar::EntryType::GNULongName);
        long_name.set_size(RECORD);
        long_name.set_mode(0o644);
        long_name.as_gnu_mut().unwrap().name[..13].copy_from_slice(b"././@LongLink");
        long_name.set_cksum();
        builder
            .append(
                &long_name,
                std::io::Read::take(std::io::repeat(b'a'), RECORD),
            )
            .unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_size(1);
        file.set_mode(0o644);
        builder.append_data(&mut file, "x.txt", &b"x"[..]).unwrap();
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        let refusal =
            "Sparse.tar.gz holds a sparse file entry; Library does not open archives like that.";

        let listed = list_tar_archive_entries("Sparse.tar.gz", bytes.clone());
        assert_eq!(listed.unwrap_err().to_string(), refusal);
        let previewed = preview_tar_archive_entry("Sparse.tar.gz", bytes.clone(), "x.txt");
        assert_eq!(previewed.err().unwrap().to_string(), refusal);
        let mut outcome = ArchiveExtractOutcome::new(BTreeSet::from(["x.txt".to_string()]));
        let mut written = 0;
        let selected = read_selected_archive_entries(
            "Sparse.tar.gz",
            bytes,
            None,
            &mut outcome,
            &mut |_, _| {
                written += 1;
                Ok(())
            },
        );
        assert_eq!(selected.unwrap_err().to_string(), refusal);
        assert_eq!(written, 0);
    }

    /// #449: a PAX sparse entry (a regular file header with `GNU.sparse.*`
    /// attributes) is refused by every tar reader, as a GNU sparse one is.
    #[test]
    fn tar_readers_refuse_a_pax_sparse_entry() {
        let pax_record = |key: &str, value: &str| {
            let body = format!(" {key}={value}\n");
            let mut len = body.len() + 1;
            while format!("{len}{body}").len() != len {
                len += 1;
            }
            format!("{len}{body}")
        };
        let records = [
            pax_record("GNU.sparse.major", "1"),
            pax_record("GNU.sparse.minor", "0"),
            pax_record("GNU.sparse.name", "hole.bin"),
            pax_record("GNU.sparse.realsize", "1048576"),
        ]
        .concat();
        let mut builder = tar::Builder::new(Vec::new());
        let mut pax = tar::Header::new_ustar();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_path("PaxHeaders/hole.bin").unwrap();
        pax.set_size(records.len() as u64);
        pax.set_mode(0o644);
        pax.set_cksum();
        builder.append(&pax, records.as_bytes()).unwrap();
        let mut file = tar::Header::new_ustar();
        file.set_path("GNUSparseFile.0/hole.bin").unwrap();
        file.set_size(4);
        file.set_mode(0o644);
        file.set_cksum();
        builder.append(&file, &b"0\n\n\n"[..]).unwrap();
        let bytes = builder.into_inner().unwrap();
        let refusal =
            "Pax.tar holds a sparse file entry; Library does not open archives like that.";

        let listed = list_tar_archive_entries("Pax.tar", bytes.clone());
        assert_eq!(listed.unwrap_err().to_string(), refusal);
        let previewed =
            preview_tar_archive_entry("Pax.tar", bytes.clone(), "GNUSparseFile.0/hole.bin");
        assert_eq!(previewed.err().unwrap().to_string(), refusal);
        let mut outcome =
            ArchiveExtractOutcome::new(BTreeSet::from(["GNUSparseFile.0/hole.bin".to_string()]));
        let mut written = 0;
        let selected = read_selected_archive_entries(
            "Pax.tar",
            bytes.clone(),
            None,
            &mut outcome,
            &mut |_, _| {
                written += 1;
                Ok(())
            },
        );
        assert_eq!(selected.unwrap_err().to_string(), refusal);
        assert_eq!(written, 0);

        let dir = tempfile::tempdir().unwrap();
        let principal_id = "person:local:library-pax-sparse";
        let root = crate::auth::principal_localhost_root(principal_id);
        let archive_uri = format!("{root}/Documents/Pax.tar");
        write_library_file_bytes(
            dir.path(),
            principal_id,
            &archive_uri,
            None,
            None,
            false,
            &bytes,
        )
        .unwrap();
        let target = library_target(dir.path(), principal_id, &archive_uri).unwrap();
        let whole = extract_library_archive(dir.path(), principal_id, &target);
        assert_eq!(
            whole.unwrap_err().to_string(),
            "Documents/Pax.tar holds a sparse file entry; Library does not open archives like \
             that."
        );
    }

    /// A tar of a PAX global header with `global` bytes of records, an
    /// optional local PAX header with `local` bytes, and one file `x.txt`.
    fn tar_with_pax_headers(global: usize, local: Option<usize>) -> Vec<u8> {
        let record = |len: usize| {
            // "<len> comment=<value>\n", exactly `len` bytes.
            let digits = len.to_string().len();
            format!("{len} comment={}\n", "a".repeat(len - digits - 10))
        };
        let mut builder = tar::Builder::new(Vec::new());
        for (kind, len) in [
            (tar::EntryType::XGlobalHeader, Some(global)),
            (tar::EntryType::XHeader, local),
        ] {
            let Some(len) = len else { continue };
            let body = record(len);
            assert_eq!(body.len(), len);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(kind);
            header.set_path("pax_global_header").unwrap();
            header.set_size(len as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, body.as_bytes()).unwrap();
        }
        let mut file = tar::Header::new_ustar();
        file.set_path("x.txt").unwrap();
        file.set_size(1);
        file.set_mode(0o644);
        file.set_cksum();
        builder.append(&file, &b"x"[..]).unwrap();
        builder.into_inner().unwrap()
    }

    /// #449: bytes a reader reads while inspecting a global PAX header are
    /// charged to the header allowance, so a 512 KiB global header cannot
    /// let a 1.25 MiB local one through.
    #[test]
    fn tar_readers_charge_a_global_pax_header_to_the_header_allowance() {
        const KIB: usize = 1024;
        let bytes = tar_with_pax_headers(512 * KIB, Some(1280 * KIB));
        let refusal = "Global.tar holds an entry name or header of more than 1 MiB; Library \
                       does not open archives like that.";
        let listed = list_tar_archive_entries("Global.tar", bytes.clone());
        assert_eq!(listed.unwrap_err().to_string(), refusal);
        let previewed = preview_tar_archive_entry("Global.tar", bytes.clone(), "x.txt");
        assert_eq!(previewed.err().unwrap().to_string(), refusal);
        let mut outcome = ArchiveExtractOutcome::new(BTreeSet::from(["x.txt".to_string()]));
        let mut written = 0;
        let selected =
            read_selected_archive_entries("Global.tar", bytes, None, &mut outcome, &mut |_, _| {
                written += 1;
                Ok(())
            });
        assert_eq!(selected.unwrap_err().to_string(), refusal);
        assert_eq!(written, 0);
    }

    /// #449: a small global PAX header, as `git archive` writes, still
    /// lists and previews.
    #[test]
    fn tar_readers_accept_a_git_archive_global_pax_header() {
        let bytes = tar_with_pax_headers(52, None);
        let (rows, truncated) = list_tar_archive_entries("Git.tar", bytes.clone()).unwrap();
        assert!(!truncated);
        assert!(
            rows.iter()
                .any(|row| row["path"] == "x.txt" && row["safety"]["status"] == "safe"),
            "{rows:?}"
        );
        let preview = preview_tar_archive_entry("Git.tar", bytes, "x.txt").unwrap();
        assert_eq!(preview.bytes, b"x");
    }

    /// #449: a folder made at the extraction's destination by another
    /// request after the check refuses the extraction; nothing is written
    /// and the other request's file stays.
    #[test]
    fn whole_extraction_refuses_a_destination_made_after_the_check() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let principal_id = "person:local:library-destination-race";
        let root = crate::auth::principal_localhost_root(principal_id);
        let archive_uri = format!("{root}/Documents/Pack.zip");
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file("ok.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"extracted").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        write_library_file_bytes(
            dir.path(),
            principal_id,
            &archive_uri,
            None,
            None,
            false,
            &bytes,
        )
        .unwrap();
        let target = library_target(dir.path(), principal_id, &archive_uri).unwrap();

        EXTRACT_BEFORE_WRITE_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|destination: &Path| {
                fs::create_dir(destination).unwrap();
                fs::write(destination.join("ok.txt"), b"theirs").unwrap();
            }));
        });
        let message = extract_library_archive(dir.path(), principal_id, &target)
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "Documents/Pack appeared while the archive was being checked, so nothing was \
             extracted. Try again."
        );
        let theirs = library_target(
            dir.path(),
            principal_id,
            &format!("{root}/Documents/Pack/ok.txt"),
        )
        .unwrap();
        assert_eq!(fs::read(&theirs.path).unwrap(), b"theirs");
    }

    #[test]
    fn archive_entry_path_refuses_root_drive_and_climb_on_every_platform() {
        let refused = [
            "/a.txt",
            "\\a.txt",
            "C:\\a.txt",
            "C:/a.txt",
            "C:a.txt",
            "c:",
            "\\\\server\\share\\a.txt",
            "//server/share/a.txt",
            "\\\\?\\C:\\a.txt",
            "\\\\.\\C:\\a.txt",
            "../a.txt",
            "..\\a.txt",
            "Nested/../../a.txt",
            "Nested/../a.txt",
            "Nested\\..\\..\\a.txt",
            "a\0.txt",
        ];
        let accepted: Vec<&str> = refused
            .into_iter()
            .filter(|name| archive_entry_path(name).is_ok())
            .collect();
        assert!(accepted.is_empty(), "accepted hostile names: {accepted:?}");

        for (name, path) in [
            ("a.txt", "a.txt"),
            ("./a.txt", "a.txt"),
            ("Nested/a.txt", "Nested/a.txt"),
            ("Nested/", "Nested"),
            ("Nested/C:a.txt", "Nested/C:a.txt"),
            ("./", ""),
        ] {
            assert_eq!(archive_entry_path(name).unwrap(), path, "{name:?}");
        }
    }

    /// The list, preview and selected-extract readers, called directly (past
    /// the check on the entry a person asks for): an entry whose name is
    /// rooted, has a drive or UNC prefix, or climbs is shown as blocked and is
    /// never matched, previewed or written, in ZIP and in tar.
    #[test]
    fn archive_readers_block_root_drive_unc_and_climb_entry_names() {
        use std::io::Write as _;

        let reason = "library archive entry path must be relative and safe";
        let mut failures = Vec::new();
        for entry_name in [
            "C:/drive-slash-escape.txt",
            "C:\\drive-backslash-escape.txt",
            "\\\\server\\share\\unc-escape.txt",
            "/etc/absolute-escape.txt",
            "../dotdot-escape.txt",
        ] {
            let leaf = entry_name.rsplit(['/', '\\']).next().unwrap();
            for archive_name in ["Case.zip", "Case.tar"] {
                let label = format!("{archive_name} {entry_name:?}");
                let bytes = if archive_name.ends_with(".zip") {
                    let options = zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored);
                    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
                    writer.start_file(entry_name, options).unwrap();
                    writer.write_all(b"escape").unwrap();
                    writer.start_file("safe.txt", options).unwrap();
                    writer.write_all(b"safe").unwrap();
                    writer.finish().unwrap().into_inner()
                } else {
                    // `tar::Builder` refuses these names, so write the header
                    // name byte for byte.
                    let mut builder = tar::Builder::new(Vec::new());
                    for (name, body) in [(entry_name, b"escape".as_slice()), ("safe.txt", b"safe")]
                    {
                        let mut header = tar::Header::new_gnu();
                        header.as_gnu_mut().unwrap().name[..name.len()]
                            .copy_from_slice(name.as_bytes());
                        header.set_entry_type(tar::EntryType::Regular);
                        header.set_size(body.len() as u64);
                        header.set_mode(0o644);
                        header.set_cksum();
                        builder.append(&header, body).unwrap();
                    }
                    builder.into_inner().unwrap()
                };
                let zip = archive_name.ends_with(".zip");

                let (rows, _) = if zip {
                    list_zip_archive_entries(bytes.clone())
                } else {
                    list_tar_archive_entries(archive_name, bytes.clone())
                }
                .unwrap();
                let hostile_rows: Vec<&Value> = rows
                    .iter()
                    .filter(|row| row["path"] != "safe.txt")
                    .collect();
                if hostile_rows.len() != 1
                    || hostile_rows[0]["kind"] != "blocked"
                    || hostile_rows[0]["safety"]["reason"] != reason
                {
                    failures.push(format!("{label} list: {hostile_rows:?}"));
                }

                for selected in [entry_name, leaf] {
                    let preview = if zip {
                        preview_zip_archive_entry(bytes.clone(), selected)
                    } else {
                        preview_tar_archive_entry(archive_name, bytes.clone(), selected)
                    };
                    if let Ok(preview) = preview {
                        failures.push(format!(
                            "{label} preview {selected:?}: {:?}",
                            String::from_utf8_lossy(&preview.bytes)
                        ));
                    }
                }

                let requested = BTreeSet::from([entry_name.to_string(), leaf.to_string()]);
                let mut outcome = ArchiveExtractOutcome::new(requested);
                let mut writes = Vec::new();
                read_selected_archive_entries(
                    archive_name,
                    bytes,
                    None,
                    &mut outcome,
                    &mut |write, _| {
                        writes.push(write);
                        Ok(())
                    },
                )
                .unwrap();
                if !writes.is_empty()
                    || outcome.blocked.len() != 1
                    || outcome.blocked[0]["reason"] != reason
                {
                    failures.push(format!(
                        "{label} selected: writes={writes:?} blocked={:?}",
                        outcome.blocked
                    ));
                }
            }
            if selected_archive_entries(&[entry_name.to_string()]).is_ok() {
                failures.push(format!("selection {entry_name:?} accepted"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} reader checks failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[cfg(test)]
mod publish_tests {
    use super::*;
    use elastos_runtime::provider::{Provider, ProviderError, ResourceRequest, ResourceResponse};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// This Home's Content: records each request; a publish answers the same
    /// CID for the same bytes.
    #[derive(Default)]
    struct RecordingContent {
        requests: Mutex<Vec<Value>>,
        down: AtomicBool,
    }

    #[async_trait::async_trait]
    impl Provider for RecordingContent {
        async fn handle(
            &self,
            _request: ResourceRequest,
        ) -> Result<ResourceResponse, ProviderError> {
            Err(ProviderError::Provider("raw requests only".into()))
        }
        fn schemes(&self) -> Vec<&'static str> {
            Vec::new()
        }
        fn name(&self) -> &'static str {
            "recording-content"
        }
        async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
            self.requests.lock().unwrap().push(request.clone());
            // A real Content call takes time; another request can run meanwhile.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if self.down.load(Ordering::SeqCst) {
                return Err(ProviderError::Provider("content is down".into()));
            }
            let cid = match request["op"].as_str() {
                Some("publish") => {
                    let digest = Sha256::digest(request["data"].as_str().unwrap_or_default());
                    format!("bafytest{}", &hex::encode(digest)[..16])
                }
                _ => request["cid"].as_str().unwrap_or_default().to_string(),
            };
            let status = if request["op"] == "unpublish" {
                "local_unpinned"
            } else {
                "local_pinned"
            };
            Ok(json!({ "status": "ok", "data": {
                "cid": cid,
                "availability": { "status": status },
                "receipt": { "status": status },
            }}))
        }
    }

    struct Home {
        dir: tempfile::TempDir,
        registry: Arc<ProviderRegistry>,
        content: Arc<RecordingContent>,
        principal: &'static str,
        root: String,
    }

    async fn home(principal: &'static str) -> Home {
        let registry = Arc::new(ProviderRegistry::new());
        let content = Arc::new(RecordingContent::default());
        registry
            .register_sub_provider("content", content.clone())
            .await
            .unwrap();
        Home {
            dir: tempfile::tempdir().unwrap(),
            registry,
            content,
            principal,
            root: crate::auth::principal_localhost_root(principal),
        }
    }

    impl Home {
        async fn call(&self, op: &str, mut body: Value) -> Value {
            body["op"] = json!(op);
            body["principal_id"] = json!(self.principal);
            // Boxed: the request future is large, and a test that awaits many
            // calls would otherwise hold one copy per await in its own frame.
            Box::pin(handle_object_provider_runtime_request(
                self.dir.path(),
                self.registry.clone(),
                &body,
            ))
            .await
        }

        fn uri(&self, path: &str) -> String {
            format!("{}/{path}", self.root)
        }

        fn path(&self, path: &str) -> PathBuf {
            library_target(self.dir.path(), self.principal, &self.uri(path))
                .unwrap()
                .path
        }

        async fn write(&self, path: &str, bytes: &[u8]) -> Value {
            let write = self
                .call(
                    "write",
                    json!({
                        "uri": self.uri(path),
                        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                    }),
                )
                .await;
            assert_eq!(write["status"], "ok", "{write}");
            write["data"]["object"].clone()
        }

        async fn publish(&self, path: &str) -> Value {
            self.call("publish", json!({ "uri": self.uri(path) })).await
        }

        async fn stat(&self, path: &str) -> Value {
            let stat = self.call("stat", json!({ "uri": self.uri(path) })).await;
            assert_eq!(stat["status"], "ok", "{stat}");
            stat["data"]["object"].clone()
        }

        fn requests(&self, op: &str) -> Vec<Value> {
            self.content
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["op"] == op)
                .cloned()
                .collect()
        }
    }

    fn assert_refused(response: &Value, code: &str) {
        assert_eq!(response["status"], "error", "{response}");
        assert_eq!(response["code"], code, "{response}");
    }

    #[tokio::test]
    async fn publish_and_repair_pin_on_this_home_only() {
        let home = home("did:key:z6MkPublishLocalPin").await;
        let object = home.write("Documents/notes.txt", b"hello").await;
        let revision = object["revision"].as_str().unwrap().to_string();

        let publish = home
            .call(
                "publish",
                json!({ "uri": home.uri("Documents/notes.txt"), "if_revision": revision }),
            )
            .await;
        assert_eq!(publish["status"], "ok", "{publish}");
        let cid = publish["data"]["cid"].as_str().unwrap().to_string();
        assert_eq!(publish["data"]["uri"], format!("elastos://{cid}"));
        let requests = home.requests("publish");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]["availability_policy"],
            crate::content::LOCAL_PIN_AVAILABILITY_POLICY
        );
        let publication = &publish["data"]["object"]["publication"];
        assert_eq!(publication["cid"], cid);
        assert_eq!(publication["uri"], format!("elastos://{cid}"));
        assert_eq!(publication["revision"], revision);
        assert_eq!(publication["published_at"], publish["data"]["published_at"]);

        // Publishing the same bytes again reuses the publication.
        let again = home.publish("Documents/notes.txt").await;
        assert_eq!(again["status"], "ok", "{again}");
        assert_eq!(again["data"]["cid"], cid);
        assert_eq!(
            again["data"]["published_at"],
            publish["data"]["published_at"]
        );
        assert_eq!(home.requests("publish").len(), 1);

        let unpublish = home
            .call(
                "unpublish",
                json!({ "uri": home.uri("Documents/notes.txt") }),
            )
            .await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        assert!(
            home.requests("unpublish").is_empty(),
            "withdrawal never unpins"
        );
        assert!(home.stat("Documents/notes.txt").await["publication"].is_null());

        let repair = home
            .call("repair", json!({ "uri": home.uri("Documents/notes.txt") }))
            .await;
        assert_eq!(repair["status"], "ok", "{repair}");
        let repairs = home.requests("repair");
        assert_eq!(
            repairs[0]["availability_policy"],
            crate::content::LOCAL_PIN_AVAILABILITY_POLICY
        );
        assert_eq!(
            home.stat("Documents/notes.txt").await["publication"]["cid"],
            cid
        );
    }

    #[tokio::test]
    async fn protected_publications_keep_their_repair_and_unpublish_requests() {
        let home = home("did:key:z6MkPublishProtectedKept").await;
        home.write("Documents/film.mp4", b"sealed source").await;
        let uri = home.uri("Documents/film.mp4");
        let mut content_security = default_publish_content_security();
        content_security["published_payload"] = json!(RUNTIME_CUSTODY_PUBLISHED_PAYLOAD);
        write_publish_record(
            home.dir.path(),
            home.principal,
            &LibraryPublishRecord {
                schema: "elastos.library.publish-record/v1".to_string(),
                object_uri: uri.clone(),
                cid: "bafyprotected".to_string(),
                published_at: 1,
                unpublished_at: None,
                shared_at: None,
                share_policy: None,
                share_grants: Vec::new(),
                content_security,
                receipt: json!({}),
                availability: json!({ "status": "local_pinned" }),
                listing_uri: Some("elastos://bafylisting".to_string()),
                revision: None,
                publication_id: None,
                size_bytes: None,
            },
        )
        .unwrap();

        let repair = home.call("repair", json!({ "uri": uri })).await;
        assert_eq!(repair["status"], "ok", "{repair}");
        let unpublish = home.call("unpublish", json!({ "uri": uri })).await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        for request in home
            .requests("repair")
            .iter()
            .chain(&home.requests("unpublish"))
        {
            assert!(request.get("availability_policy").is_none(), "{request}");
        }
        // A plain publish never replaces a protected publication.
        home.call("repair", json!({ "uri": uri })).await;
        let protected = home.publish("Documents/film.mp4").await;
        assert_refused(&protected, "unsupported");
        assert_eq!(protected["reason"], "protected");
        assert!(home.requests("publish").is_empty());
        // Buyers fetch the sealed payload and listing from any Home: an
        // active protected publication is served to any peer.
        for cid in ["bafyprotected", "bafylisting"] {
            let audience = published_cid_audience(home.dir.path(), cid).unwrap();
            assert!(audience.any_peer, "{cid}");
        }
    }

    const SEALED_CID: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    const FOLDER_CID: &str = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    const LISTING_CID: &str = "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354";

    /// A minted film: its creator's listing names the three artifacts, and
    /// the Library publication record names the payload and the listing.
    #[cfg(unix)]
    async fn minted_film(home: &Home) -> String {
        home.write("Documents/film.mp4", b"sealed source").await;
        let uri = home.uri("Documents/film.mp4");
        let mint_id = elastos_protected_content_contracts::Digest32::new([0x4d; 32]);
        crate::protected_content_runtime::tests::persist_creator_listing_for_test(
            home.dir.path(),
            home.principal,
            mint_id,
            SEALED_CID,
            FOLDER_CID,
            LISTING_CID,
        );
        let mut content_security = default_publish_content_security();
        content_security["published_payload"] = json!(RUNTIME_CUSTODY_PUBLISHED_PAYLOAD);
        content_security["mint_id"] = json!(hex::encode(mint_id.as_bytes()));
        write_publish_record(
            home.dir.path(),
            home.principal,
            &LibraryPublishRecord {
                schema: "elastos.library.publish-record/v1".to_string(),
                object_uri: uri.clone(),
                cid: SEALED_CID.to_string(),
                published_at: 1,
                unpublished_at: None,
                shared_at: None,
                share_policy: None,
                share_grants: Vec::new(),
                content_security,
                receipt: json!({}),
                availability: json!({ "status": "local_pinned" }),
                listing_uri: Some(format!("elastos://{LISTING_CID}")),
                revision: None,
                publication_id: None,
                size_bytes: None,
            },
        )
        .unwrap();
        uri
    }

    /// Whether a peer that is no contact of anyone here may read `cid`.
    async fn any_peer_reads(home: &Home, cid: &str) -> bool {
        let stranger = iroh::PublicKey::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        crate::carrier::admit_carrier_peer_content_fetch(
            home.dir.path(),
            None,
            &stranger,
            &json!({ "cid": cid }),
        )
        .await
        .is_ok()
    }

    /// A protected publication shares its whole artifact set with any peer:
    /// the sealed payload, the listing package, and the tokenURI metadata
    /// folder a buyer's listing read starts from. Unpublish stops all three.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_protected_publication_serves_its_metadata_folder_to_any_peer() {
        let home = home("did:key:z6MkPublishProtectedFolder").await;
        let uri = minted_film(&home).await;
        for cid in [SEALED_CID, LISTING_CID, FOLDER_CID] {
            assert!(any_peer_reads(&home, cid).await, "{cid}");
        }

        let unpublish = home.call("unpublish", json!({ "uri": uri })).await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        for cid in [SEALED_CID, LISTING_CID, FOLDER_CID] {
            assert!(!any_peer_reads(&home, cid).await, "{cid}");
        }
    }

    /// A Library publication shares only its file, and only with the
    /// publisher's contacts, as before.
    #[tokio::test]
    async fn a_library_publication_shares_only_its_file_with_contacts() {
        let home = home("did:key:z6MkPublishLibraryUnchanged").await;
        home.write("Documents/notes.txt", b"hello").await;
        let publish = home.publish("Documents/notes.txt").await;
        assert_eq!(publish["status"], "ok", "{publish}");
        let cid = publish["data"]["cid"].as_str().unwrap();

        let audience = published_cid_audience(home.dir.path(), cid).unwrap();
        assert!(!audience.any_peer);
        assert_eq!(
            audience.principals,
            BTreeSet::from([home.principal.to_string()])
        );
        let index = load_published_index(home.dir.path()).unwrap();
        let shared: Vec<_> = index
            .publications
            .values()
            .map(|entry| entry.cids.clone())
            .collect();
        assert_eq!(shared, vec![BTreeSet::from([cid.to_string()])]);
    }

    #[tokio::test]
    async fn publish_refuses_empty_oversized_stale_folder_and_missing_in_plain_words() {
        let home = home("did:key:z6MkPublishRefusals").await;

        home.write("Documents/empty.txt", b"").await;
        let empty = home.publish("Documents/empty.txt").await;
        assert_refused(&empty, "empty_file");
        assert_eq!(empty["message"], "Empty files can't be published.");

        let cap = LIBRARY_PUBLISH_MAX_BYTES as usize;
        home.write("Documents/at-cap.bin", &vec![7; cap]).await;
        home.write("Documents/over-cap.bin", &vec![7; cap + 1])
            .await;
        let over = home.publish("Documents/over-cap.bin").await;
        assert_refused(&over, "too_large");
        assert_eq!(over["message"], "This file is too large to publish.");
        // Far over the cap is refused from its size on disk, before reading.
        std::fs::write(
            home.path("Documents/huge.bin"),
            vec![0; LIBRARY_PUBLISH_MAX_STORED_BYTES as usize + 1],
        )
        .unwrap();
        assert_refused(&home.publish("Documents/huge.bin").await, "too_large");
        assert!(home.requests("publish").is_empty());
        let at_cap = home.publish("Documents/at-cap.bin").await;
        assert_eq!(at_cap["status"], "ok", "{at_cap}");
        assert_eq!(home.requests("publish").len(), 1);

        home.write("Documents/stale.txt", b"one").await;
        let stale = home
            .call(
                "publish",
                json!({ "uri": home.uri("Documents/stale.txt"), "if_revision": "rev:old" }),
            )
            .await;
        assert_refused(&stale, "stale_revision");

        let mkdir = home
            .call(
                "mkdir",
                json!({ "parent_uri": home.uri("Documents"), "name": "Folder" }),
            )
            .await;
        assert_eq!(mkdir["status"], "ok", "{mkdir}");
        let folder = home.publish("Documents/Folder").await;
        assert_refused(&folder, "unsupported");
        assert_eq!(folder["message"], "Folders can't be published.");
        assert_eq!(folder["reason"], "folder");
        assert_refused(&home.publish("Documents/gone.txt").await, "not_found");

        home.content.down.store(true, Ordering::SeqCst);
        let down = home.publish("Documents/stale.txt").await;
        assert_refused(&down, "unavailable");
        assert_eq!(
            down["message"],
            "Publishing isn't available right now. Try again."
        );
        assert!(home.stat("Documents/stale.txt").await["publication"].is_null());
    }

    #[tokio::test]
    async fn publish_refuses_traversal_other_roots_and_links() {
        let home = home("did:key:z6MkPublishPaths").await;
        home.write("Documents/mine.txt", b"mine").await;
        let other_root = crate::auth::principal_localhost_root("did:key:z6MkSomeoneElse");
        for uri in [
            format!("{}/Documents/../Documents/mine.txt", home.root),
            format!("{other_root}/Documents/mine.txt"),
            "file:///etc/passwd".to_string(),
        ] {
            let refused = home.call("publish", json!({ "uri": uri })).await;
            assert_eq!(refused["status"], "error", "{uri}: {refused}");
        }
        let refused = publish_library_uri_locked(
            home.dir.path(),
            &home.registry,
            home.principal,
            "file:///etc/passwd",
            None,
            None,
        )
        .await
        .err()
        .unwrap();
        let refused = find_library_refusal(&refused).unwrap();
        assert_eq!(refused.code, "unsupported");
        assert_eq!(refused.reason, Some("not_allowed_here"));

        #[cfg(unix)]
        {
            let outside = home.dir.path().join("outside.txt");
            std::fs::write(&outside, b"outside").unwrap();
            std::os::unix::fs::symlink(&outside, home.path("Documents/link.txt")).unwrap();
            assert_refused(&home.publish("Documents/link.txt").await, "unsupported");
            std::fs::create_dir_all(home.dir.path().join("elsewhere")).unwrap();
            std::fs::write(home.dir.path().join("elsewhere/inner.txt"), b"inner").unwrap();
            std::os::unix::fs::symlink(
                home.dir.path().join("elsewhere"),
                home.path("Documents/linked"),
            )
            .unwrap();
            assert_refused(
                &home.publish("Documents/linked/inner.txt").await,
                "unsupported",
            );
        }
        assert!(home.requests("publish").is_empty());
    }

    #[tokio::test]
    async fn publish_allows_only_the_visible_library_places() {
        let home = home("did:key:z6MkPublishPlaces").await;
        // Runtime-held files, such as the Profile authority bundle, and any
        // hidden folder are never published, whatever their bytes.
        for hidden in [
            ".AppData/ElastOS/Profile/profile-authority.json",
            ".AppData/LocalHost/.Runtime/Library/Published/x.json",
            ".Trash/old.txt",
            "Documents/.secret/notes.txt",
            ".hidden.txt",
        ] {
            let path = home.path(hidden);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"{\"profile_signing_seed_hex\":\"00\"}").unwrap();
            let refused = home.publish(hidden).await;
            assert_refused(&refused, "unsupported");
            assert_eq!(refused["reason"], "not_allowed_here", "{hidden}");
            let refused = publish_library_uri_locked(
                home.dir.path(),
                &home.registry,
                home.principal,
                &home.uri(hidden),
                None,
                None,
            )
            .await
            .err()
            .unwrap();
            assert_eq!(find_library_refusal(&refused).unwrap().code, "unsupported");
        }
        assert!(home.requests("publish").is_empty());

        home.write("notes.txt", b"in Home").await;
        home.write("Projects/plan.txt", b"in a folder of Home")
            .await;
        for visible in ["notes.txt", "Projects/plan.txt"] {
            let published = home.publish(visible).await;
            assert_eq!(published["status"], "ok", "{visible}: {published}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_publishes_of_one_file_make_one_publication() {
        let home = home("did:key:z6MkPublishConcurrent").await;
        home.write("Documents/race.txt", b"race").await;
        let (first, second) = tokio::join!(
            home.publish("Documents/race.txt"),
            home.publish("Documents/race.txt")
        );
        assert_eq!(first["status"], "ok", "{first}");
        assert_eq!(second["status"], "ok", "{second}");
        assert_eq!(
            first["data"]["published_at"],
            second["data"]["published_at"]
        );
        assert_eq!(home.requests("publish").len(), 1);
    }

    #[tokio::test]
    async fn withdrawing_one_of_two_publications_of_the_same_bytes_keeps_the_other_served() {
        let home = home("did:key:z6MkPublishSameBytes").await;
        home.write("Documents/a.txt", b"same bytes").await;
        home.write("Pictures/b.txt", b"same bytes").await;
        let a = home.publish("Documents/a.txt").await;
        let b = home.publish("Pictures/b.txt").await;
        assert_eq!(a["data"]["cid"], b["data"]["cid"]);
        let cid = a["data"]["cid"].as_str().unwrap().to_string();
        assert!(cid_is_published_here(home.dir.path(), &cid));

        let first = home
            .call("unpublish", json!({ "uri": home.uri("Documents/a.txt") }))
            .await;
        assert_eq!(first["status"], "ok", "{first}");
        assert_eq!(first["data"]["availability"]["status"], "withdrawn");
        assert!(home.stat("Documents/a.txt").await["publication"].is_null());
        assert!(
            cid_is_published_here(home.dir.path(), &cid),
            "b still served"
        );

        let last = home
            .call("unpublish", json!({ "uri": home.uri("Pictures/b.txt") }))
            .await;
        assert_eq!(last["status"], "ok", "{last}");
        assert!(!cid_is_published_here(home.dir.path(), &cid));
        // Withdrawal never unpins: the pin is only local storage.
        assert!(home.requests("unpublish").is_empty());
    }

    #[tokio::test]
    async fn another_persons_unpublish_never_affects_a_publication_it_cannot_see_or_read() {
        // Neither person is in the passkey list, and Alma's record is
        // unreadable by the time Bruno withdraws.
        let alma = home("did:key:z6MkAlmaUnlisted").await;
        let bruno_id = "did:key:z6MkBrunoUnlisted";
        alma.write("Documents/same.txt", b"shared bytes").await;
        let published = alma.publish("Documents/same.txt").await;
        let cid = published["data"]["cid"].as_str().unwrap().to_string();
        let bruno_uri = format!(
            "{}/Documents/same.txt",
            crate::auth::principal_localhost_root(bruno_id)
        );
        let as_bruno = |op: &str, mut body: Value| {
            body["op"] = json!(op);
            body["principal_id"] = json!(bruno_id);
            let (dir, registry) = (alma.dir.path().to_path_buf(), alma.registry.clone());
            async move { handle_object_provider_runtime_request(&dir, registry, &body).await }
        };
        let write = as_bruno(
            "write",
            json!({
                "uri": bruno_uri,
                "data": base64::engine::general_purpose::STANDARD.encode(b"shared bytes"),
            }),
        )
        .await;
        assert_eq!(write["status"], "ok", "{write}");
        let bruno = as_bruno("publish", json!({ "uri": bruno_uri })).await;
        assert_eq!(bruno["data"]["cid"], cid.as_str());

        let record_path = rooted_localhost_fs_path(
            alma.dir.path(),
            &publish_record_uri(&alma.root, &alma.uri("Documents/same.txt")),
        )
        .unwrap();
        std::fs::write(&record_path, b"unreadable").unwrap();

        let unpublish = as_bruno("unpublish", json!({ "uri": bruno_uri })).await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        assert!(
            cid_is_published_here(alma.dir.path(), &cid),
            "Alma's stays served"
        );
        // A restart serves only what a readable active record backs.
        reconcile_published_cids(alma.dir.path());
        assert!(
            !cid_is_published_here(alma.dir.path(), &cid),
            "an unreadable record is not served after a restart"
        );
    }

    #[tokio::test]
    async fn an_interrupted_publish_serves_nothing_even_for_bytes_shared_before() {
        let home = home("did:key:z6MkPublishCrashes").await;
        home.write("Documents/c.txt", b"crash").await;
        let first = home.publish("Documents/c.txt").await;
        let cid = first["data"]["cid"].as_str().unwrap().to_string();
        let unpublish = home
            .call("unpublish", json!({ "uri": home.uri("Documents/c.txt") }))
            .await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        assert!(!cid_is_published_here(home.dir.path(), &cid));

        // Publishing the same bytes again stops after the pin, before the
        // record: the old link stays unserved and Library shows no publication.
        home.registry
            .send_raw(
                "content",
                &json!({
                    "op": "publish",
                    "kind": "file",
                    "data": base64::engine::general_purpose::STANDARD.encode(b"crash"),
                    "pin": true,
                }),
            )
            .await
            .unwrap();
        assert!(!cid_is_published_here(home.dir.path(), &cid));
        assert!(home.stat("Documents/c.txt").await["publication"].is_null());

        let again = home.publish("Documents/c.txt").await;
        assert_eq!(again["status"], "ok", "{again}");
        assert!(cid_is_published_here(home.dir.path(), &cid));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rename_racing_a_publish_keeps_the_record_with_the_file() {
        let home = home("did:key:z6MkPublishRenameRace").await;
        home.write("Documents/a.txt", b"race").await;
        let (publish, rename) = tokio::join!(
            home.publish("Documents/a.txt"),
            home.call(
                "rename",
                json!({ "uri": home.uri("Documents/a.txt"), "name": "b.txt" })
            )
        );
        assert_eq!(rename["status"], "ok", "{rename}");
        // Whichever ran first, no publication is left at a missing path.
        for record in plain_publish_records(home.dir.path(), home.principal) {
            assert_eq!(record.object_uri, home.uri("Documents/b.txt"), "{publish}");
        }
        if publish["status"] == "ok" {
            assert_eq!(
                home.stat("Documents/b.txt").await["publication"]["cid"],
                publish["data"]["cid"]
            );
        }
    }

    #[tokio::test]
    async fn a_chat_attach_interrupted_after_its_record_posts_it_or_answers_withdrawn() {
        let home = home("did:key:z6MkAttachInterrupted").await;
        home.write("Documents/post.txt", b"post me").await;
        let uri = home.uri("Documents/post.txt");
        let bind = |request_id: &str, publication_id: &str| {
            write_runtime_json(
                home.dir.path(),
                home.principal,
                &chat_attach_binding_uri(home.principal, request_id),
                &ChatAttachBinding {
                    schema: "elastos.library.chat-attach/v1".to_string(),
                    request_id: request_id.to_string(),
                    uri: uri.clone(),
                    if_revision: None,
                    publication_id: publication_id.to_string(),
                    bound_at: now_ts(),
                    name: None,
                    size_bytes: None,
                },
            )
            .unwrap();
        };
        let attach = |request_id: &'static str| {
            chat_attach_publication(
                home.dir.path(),
                &home.registry,
                home.principal,
                request_id,
                &uri,
                None,
                || Ok(()),
            )
        };
        // Bound and recorded under its own id; the binding was not updated.
        bind("chat-attach:cut", "intended-id");
        let recorded = {
            let _serialized = PUBLICATIONS.lock().await;
            publish_library_uri_locked(
                home.dir.path(),
                &home.registry,
                home.principal,
                &uri,
                None,
                Some("intended-id".to_string()),
            )
            .await
            .unwrap()
        };
        let resumed = attach("chat-attach:cut").await.unwrap();
        assert_eq!(resumed.cid, recorded.cid);
        assert_eq!(resumed.name, "post.txt");
        assert_eq!(resumed.size_bytes, 7);
        // A second request bound before it reused that publication.
        bind("chat-attach:reuse", "never-recorded");
        let reused = attach("chat-attach:reuse").await.unwrap();
        assert_eq!(reused.cid, recorded.cid);
        assert_eq!(home.requests("publish").len(), 1);

        let unpublish = home.call("unpublish", json!({ "uri": uri })).await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        for request_id in ["chat-attach:cut", "chat-attach:reuse"] {
            let replay = attach(request_id).await.err().unwrap();
            assert_eq!(find_library_refusal(&replay).unwrap().code, "withdrawn");
        }
        assert_eq!(home.requests("publish").len(), 1);
    }

    #[tokio::test]
    async fn changed_bytes_need_unpublish_before_a_new_publication() {
        let home = home("did:key:z6MkPublishChanged").await;
        home.write("Documents/draft.txt", b"first").await;
        let first = home.publish("Documents/draft.txt").await;
        let first_cid = first["data"]["cid"].as_str().unwrap().to_string();

        home.write("Documents/draft.txt", b"second").await;
        // The listing still names the published CID, not the new bytes.
        assert_eq!(
            home.stat("Documents/draft.txt").await["publication"]["cid"],
            first_cid
        );
        let changed = home.publish("Documents/draft.txt").await;
        assert_refused(&changed, "changed_since_publish");
        assert_eq!(home.requests("publish").len(), 1);

        let unpublish = home
            .call(
                "unpublish",
                json!({ "uri": home.uri("Documents/draft.txt") }),
            )
            .await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        let second = home.publish("Documents/draft.txt").await;
        assert_eq!(second["status"], "ok", "{second}");
        assert_ne!(second["data"]["cid"], first_cid);
        assert_eq!(home.requests("publish").len(), 2);
    }

    #[tokio::test]
    async fn rename_and_move_carry_the_publication_and_trash_waits_for_unpublish() {
        let home = home("did:key:z6MkPublishMoves").await;
        home.write("Documents/Shared/a.txt", b"carried").await;
        let publish = home.publish("Documents/Shared/a.txt").await;
        let cid = publish["data"]["cid"].as_str().unwrap().to_string();

        let rename = home
            .call(
                "rename",
                json!({ "uri": home.uri("Documents/Shared/a.txt"), "name": "b.txt" }),
            )
            .await;
        assert_eq!(rename["status"], "ok", "{rename}");
        assert_eq!(rename["data"]["object"]["publication"]["cid"], cid);

        home.write("Documents/Other/keep.txt", b"keep").await;
        let moved = home
            .call(
                "move",
                json!({
                    "uri": home.uri("Documents/Shared/b.txt"),
                    "target_parent_uri": home.uri("Documents/Other"),
                }),
            )
            .await;
        assert_eq!(moved["status"], "ok", "{moved}");
        assert_eq!(moved["data"]["object"]["publication"]["cid"], cid);

        // A folder rename carries the publications inside it.
        let folder = home
            .call(
                "rename",
                json!({ "uri": home.uri("Documents/Other"), "name": "Moved" }),
            )
            .await;
        assert_eq!(folder["status"], "ok", "{folder}");
        assert_eq!(
            home.stat("Documents/Moved/b.txt").await["publication"]["cid"],
            cid
        );
        // Nothing published is left behind at the old places.
        home.write("Documents/Shared/a.txt", b"new file").await;
        assert!(home.stat("Documents/Shared/a.txt").await["publication"].is_null());

        for uri in ["Documents/Moved/b.txt", "Documents/Moved"] {
            let trash = home.call("trash", json!({ "uri": home.uri(uri) })).await;
            assert_refused(&trash, "published_withdraw_first");
        }
        assert!(home.path("Documents/Moved/b.txt").is_file());

        let unpublish = home
            .call(
                "unpublish",
                json!({ "uri": home.uri("Documents/Moved/b.txt") }),
            )
            .await;
        assert_eq!(unpublish["status"], "ok", "{unpublish}");
        assert!(!cid_is_published_here(home.dir.path(), &cid));
        let trash = home
            .call("trash", json!({ "uri": home.uri("Documents/Moved") }))
            .await;
        assert_eq!(trash["status"], "ok", "{trash}");
    }
}
