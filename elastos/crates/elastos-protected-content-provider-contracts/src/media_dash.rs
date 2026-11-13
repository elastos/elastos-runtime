//! Protected media format v2 (DASH/CENC): the fixed-size identity head, the
//! RFC 6962 Merkle root per rendition, the incremental ciphertext-stream digest,
//! and the per-rendition session layout whose segment authority is that root.
//!
//! The head never grows with duration: per-segment integrity is one Merkle root
//! per rendition, and its leaves are the (sha256, size) pairs the content object
//! manifest already lists.

use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, ContractError, Digest32, EncryptedContentIdentityV1,
    MAX_ENCRYPTED_CONTENT_BYTES,
};
use sha2::{Digest as _, Sha256};

use crate::media::{
    canonical_cursor, canonical_prefix, finish_canonical, push_bytes, push_string, read_bytes,
    read_fixed_32, read_string, read_u16, read_u64, validate_visible_ascii,
    CencDashRenditionKindV2, ValidatedCencDashInitV2, ValidatedCencFmp4SegmentLayoutV1,
    ValidatedFmp4RenditionV2, CENC_DASH_MEDIA_SUITE_ID_V2, MAX_MEDIA_DECLARATION_BYTES_V1,
};
use crate::protection_system::{
    CustodyProtectionHeader, ProtectionContext, ProtectionSystemId, PROTECTION,
};

const CIPHERTEXT_STREAM_IDENTITY_DOMAIN_V1: &[u8] =
    b"elastos.protected-content.cenc-fmp4-ciphertext-stream/v1";
const CENC_DASH_MEDIA_IDENTITY_DOMAIN_V2: &str =
    "elastos.protected-content.cenc-dash-media-identity/v2";
const CENC_DASH_MANIFEST_ROOT_DOMAIN_V2: &[u8] =
    b"elastos.protected-content.cenc-dash-manifest-root/v2";
const CENC_DASH_SEGMENT_LEAF_DOMAIN_V2: &[u8] =
    b"elastos.protected-content.cenc-dash-segment-leaf/v2";

/// Structural bound of the head for any duration (at most 2 renditions).
pub const MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2: usize = 4 * 1024;
/// Deepest audit path a proof may carry (trees of up to 2^32 leaves).
pub const MAX_CENC_DASH_AUDIT_PATH_V2: usize = 32;
/// Video and audio segment counts may differ by at most this much.
const MAX_SEGMENT_COUNT_SKEW_V2: u32 = 1;

/// The only (mime type, codecs) pair each kind may declare.
pub const fn pinned_declaration_v2(kind: CencDashRenditionKindV2) -> (&'static str, &'static str) {
    match kind {
        CencDashRenditionKindV2::Video => ("video/mp4", "avc1.640028"),
        CencDashRenditionKindV2::Audio => ("audio/mp4", "mp4a.40.2"),
    }
}

/// The ciphertext-stream digest of v1, fed incrementally: the same domain and
/// bytes (`domain ‖ u32 count ‖ (u64 len ‖ bytes)*`), without holding the
/// segments. Segments must arrive in order, each declared with its length first.
#[derive(Debug, Clone)]
pub struct CiphertextStreamHasher {
    hasher: Sha256,
    segments_left: u32,
    open_bytes_left: u64,
    total_bytes: u64,
}

impl CiphertextStreamHasher {
    pub fn new(segment_count: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CIPHERTEXT_STREAM_IDENTITY_DOMAIN_V1);
        hasher.update(segment_count.to_be_bytes());
        Self {
            hasher,
            segments_left: segment_count,
            open_bytes_left: 0,
            total_bytes: 0,
        }
    }

    /// Opens the next segment, which will carry exactly `len` bytes.
    pub fn begin_segment(&mut self, len: u64) -> Result<(), ContractError> {
        if self.open_bytes_left != 0 || self.segments_left == 0 {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(len)
            .ok_or(ContractError::InvalidField("total_encrypted_bytes"))?;
        self.segments_left -= 1;
        self.open_bytes_left = len;
        self.hasher.update(len.to_be_bytes());
        Ok(())
    }

    /// Feeds bytes of the open segment.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), ContractError> {
        let len = bytes.len() as u64;
        if len > self.open_bytes_left {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        self.open_bytes_left -= len;
        self.hasher.update(bytes);
        Ok(())
    }

    /// Feeds one whole segment.
    pub fn push_segment(&mut self, segment: &[u8]) -> Result<(), ContractError> {
        self.begin_segment(segment.len() as u64)?;
        self.update(segment)
    }

    pub fn finish(self) -> Result<EncryptedContentIdentityV1, ContractError> {
        if self.open_bytes_left != 0 || self.segments_left != 0 {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        EncryptedContentIdentityV1::new(
            Digest32::new(self.hasher.finalize().into()),
            self.total_bytes,
        )
    }
}

fn hash_leaf_input(input: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(input);
    Digest32::new(hasher.finalize().into())
}

fn hash_node(left: &Digest32, right: &Digest32) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Digest32::new(hasher.finalize().into())
}

/// The Merkle leaf hash of segment `index`: `SHA-256(0x00 ‖ domain ‖ kind ‖ u32
/// index ‖ sha256(segment) ‖ u64 len)`.
pub fn cenc_dash_segment_leaf_hash(
    kind: CencDashRenditionKindV2,
    index: u32,
    segment_sha256: Digest32,
    segment_bytes: u64,
) -> Digest32 {
    let mut input = Vec::with_capacity(CENC_DASH_SEGMENT_LEAF_DOMAIN_V2.len() + 45);
    input.extend_from_slice(CENC_DASH_SEGMENT_LEAF_DOMAIN_V2);
    input.push(kind.code());
    input.extend_from_slice(&index.to_be_bytes());
    input.extend_from_slice(segment_sha256.as_bytes());
    input.extend_from_slice(&segment_bytes.to_be_bytes());
    hash_leaf_input(&input)
}

/// The RFC 6962 Merkle tree hash of `leaves` (already leaf-hashed).
pub fn cenc_dash_merkle_root(leaves: &[Digest32]) -> Result<Digest32, ContractError> {
    let mut builder = CencDashMerkleRootBuilderV2::new();
    for leaf in leaves {
        builder.push_leaf(*leaf);
    }
    builder.finish()
}

fn subtree_root(leaves: &[Digest32]) -> Digest32 {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = largest_power_of_two_below(leaves.len());
    hash_node(
        &subtree_root(&leaves[..split]),
        &subtree_root(&leaves[split..]),
    )
}

fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// The audit path of leaf `index` (RFC 6962 §2.1.1), root side last.
pub fn cenc_dash_merkle_audit_path(
    leaves: &[Digest32],
    index: usize,
) -> Result<Vec<Digest32>, ContractError> {
    if index >= leaves.len() {
        return Err(ContractError::InvalidField("segment_index"));
    }
    let mut path = Vec::new();
    let (mut slice, mut index) = (leaves, index);
    while slice.len() > 1 {
        let split = largest_power_of_two_below(slice.len());
        if index < split {
            path.push(subtree_root(&slice[split..]));
            slice = &slice[..split];
        } else {
            path.push(subtree_root(&slice[..split]));
            slice = &slice[split..];
            index -= split;
        }
    }
    path.reverse();
    if path.len() > MAX_CENC_DASH_AUDIT_PATH_V2 {
        return Err(ContractError::FieldTooLong("segment_proof"));
    }
    Ok(path)
}

/// The audit path of every leaf at once, in `O(n log n)` hashes and space,
/// instead of `O(n)` per leaf. `result[i]` equals
/// `cenc_dash_merkle_audit_path(leaves, i)`.
pub fn cenc_dash_merkle_audit_paths(
    leaves: &[Digest32],
) -> Result<Vec<Vec<Digest32>>, ContractError> {
    fn fill(leaves: &[Digest32], offset: usize, paths: &mut [Vec<Digest32>]) -> Digest32 {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let split = largest_power_of_two_below(leaves.len());
        let left = fill(&leaves[..split], offset, paths);
        let right = fill(&leaves[split..], offset + split, paths);
        for path in &mut paths[offset..offset + split] {
            path.push(right);
        }
        for path in &mut paths[offset + split..offset + leaves.len()] {
            path.push(left);
        }
        hash_node(&left, &right)
    }
    if leaves.is_empty() {
        return Err(ContractError::InvalidField("segment_index"));
    }
    let mut paths = vec![Vec::new(); leaves.len()];
    fill(leaves, 0, &mut paths);
    if paths
        .iter()
        .any(|path| path.len() > MAX_CENC_DASH_AUDIT_PATH_V2)
    {
        return Err(ContractError::FieldTooLong("segment_proof"));
    }
    Ok(paths)
}

/// Checks `path` takes the leaf at `index` of a `count`-leaf tree to `root`
/// (RFC 9162 §2.1.3.2).
pub fn cenc_dash_verify_audit_path(
    leaf: Digest32,
    index: u64,
    count: u64,
    path: &[Digest32],
    root: Digest32,
) -> bool {
    if index >= count || path.len() > MAX_CENC_DASH_AUDIT_PATH_V2 {
        return false;
    }
    let (mut fnode, mut snode) = (index, count - 1);
    let mut computed = leaf;
    for sibling in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            computed = hash_node(sibling, &computed);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            computed = hash_node(&computed, sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && computed == root
}

/// Streaming Merkle root: keeps the roots of the complete subtrees only.
#[derive(Debug, Clone, Default)]
pub struct CencDashMerkleRootBuilderV2 {
    stack: Vec<(Digest32, u64)>,
}

impl CencDashMerkleRootBuilderV2 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_leaf(&mut self, leaf: Digest32) {
        self.stack.push((leaf, 1));
        while let [.., (left, left_size), (right, right_size)] = self.stack[..] {
            if left_size != right_size {
                break;
            }
            self.stack.truncate(self.stack.len() - 2);
            self.stack
                .push((hash_node(&left, &right), left_size + right_size));
        }
    }

    pub fn finish(self) -> Result<Digest32, ContractError> {
        let mut nodes = self.stack.into_iter().rev().map(|(node, _)| node);
        let mut root = nodes
            .next()
            .ok_or(ContractError::InvalidField("segments_root"))?;
        for left in nodes {
            root = hash_node(&left, &root);
        }
        Ok(root)
    }
}

/// One rendition's entry in the head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CencDashRenditionIdentityV2 {
    kind: CencDashRenditionKindV2,
    mime_type: String,
    codecs: String,
    timescale: u32,
    init_segment_sha256: Digest32,
    init_segment_bytes: u64,
    segment_count: u32,
    segments_root: Digest32,
}

impl CencDashRenditionIdentityV2 {
    pub const fn kind(&self) -> CencDashRenditionKindV2 {
        self.kind
    }

    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    pub fn codecs(&self) -> &str {
        &self.codecs
    }

    pub const fn timescale(&self) -> u32 {
        self.timescale
    }

    pub const fn init_segment_sha256(&self) -> Digest32 {
        self.init_segment_sha256
    }

    pub const fn init_segment_bytes(&self) -> u64 {
        self.init_segment_bytes
    }

    pub const fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub const fn segments_root(&self) -> Digest32 {
        self.segments_root
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_visible_ascii(&self.mime_type, "mime_type", MAX_MEDIA_DECLARATION_BYTES_V1)?;
        validate_visible_ascii(&self.codecs, "codecs", MAX_MEDIA_DECLARATION_BYTES_V1)?;
        let (mime_type, codecs) = pinned_declaration_v2(self.kind);
        if self.mime_type != mime_type || self.codecs != codecs {
            return Err(ContractError::InvalidField("codecs"));
        }
        if self.timescale == 0 {
            return Err(ContractError::InvalidField("timescale"));
        }
        if self.init_segment_bytes == 0 || self.init_segment_bytes > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        if self.segment_count == 0 {
            return Err(ContractError::InvalidField("segment_count"));
        }
        Ok(())
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), ContractError> {
        bytes.push(self.kind.code());
        push_string(bytes, &self.mime_type)?;
        push_string(bytes, &self.codecs)?;
        bytes.extend_from_slice(&self.timescale.to_be_bytes());
        bytes.extend_from_slice(self.init_segment_sha256.as_bytes());
        bytes.extend_from_slice(&self.init_segment_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.segment_count.to_be_bytes());
        bytes.extend_from_slice(self.segments_root.as_bytes());
        Ok(())
    }
}

/// What the builder is told about a rendition before its segments arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CencDashRenditionDeclV2 {
    pub kind: CencDashRenditionKindV2,
    pub mime_type: String,
    pub codecs: String,
    pub timescale: u32,
    pub init_segment_sha256: Digest32,
    pub init_segment_bytes: u64,
    pub segment_count: u32,
}

impl CencDashRenditionDeclV2 {
    /// A declaration for `protected_init` with the pinned mime/codecs of `kind`.
    pub fn from_init(
        kind: CencDashRenditionKindV2,
        timescale: u32,
        protected_init: &[u8],
        segment_count: u32,
    ) -> Self {
        let (mime_type, codecs) = pinned_declaration_v2(kind);
        Self {
            kind,
            mime_type: mime_type.to_string(),
            codecs: codecs.to_string(),
            timescale,
            init_segment_sha256: Digest32::new(Sha256::digest(protected_init).into()),
            init_segment_bytes: protected_init.len() as u64,
            segment_count,
        }
    }
}

/// A rendition held in memory, for [`CencDashMediaIdentityV2::new_from_bytes`].
#[derive(Debug, Clone, Copy)]
pub struct CencDashRenditionBytesV2<'a> {
    pub kind: CencDashRenditionKindV2,
    pub timescale: u32,
    pub init_segment: &'a [u8],
    pub segments: &'a [Vec<u8>],
}

/// The v2 identity head (`identity.bin`): fixed size for any duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CencDashMediaIdentityV2 {
    encrypted_content: EncryptedContentIdentityV1,
    media_manifest_root: Digest32,
    default_kid: ContentAccessIdV1,
    renditions: Vec<CencDashRenditionIdentityV2>,
}

impl CencDashMediaIdentityV2 {
    pub fn new_from_bytes(
        default_kid: ContentAccessIdV1,
        renditions: &[CencDashRenditionBytesV2<'_>],
    ) -> Result<Self, ContractError> {
        let decls = renditions
            .iter()
            .map(|rendition| {
                Ok(CencDashRenditionDeclV2::from_init(
                    rendition.kind,
                    rendition.timescale,
                    rendition.init_segment,
                    u32::try_from(rendition.segments.len())
                        .map_err(|_| ContractError::FieldTooLong("segment_count"))?,
                ))
            })
            .collect::<Result<Vec<_>, ContractError>>()?;
        let mut builder = CencDashIdentityBuilderV2::new(default_kid, decls)?;
        for rendition in renditions {
            for segment in rendition.segments {
                builder.push_segment(segment)?;
            }
        }
        builder.finish()
    }

    pub const fn encrypted_content(&self) -> &EncryptedContentIdentityV1 {
        &self.encrypted_content
    }

    pub const fn media_manifest_root(&self) -> Digest32 {
        self.media_manifest_root
    }

    pub const fn default_kid(&self) -> ContentAccessIdV1 {
        self.default_kid
    }

    pub fn renditions(&self) -> &[CencDashRenditionIdentityV2] {
        &self.renditions
    }

    pub const fn suite_id(&self) -> &'static str {
        CENC_DASH_MEDIA_SUITE_ID_V2
    }

    fn validate_renditions(
        renditions: &[CencDashRenditionIdentityV2],
    ) -> Result<(), ContractError> {
        if renditions.is_empty() || renditions.len() > 2 {
            return Err(ContractError::InvalidField("representation_count"));
        }
        for rendition in renditions {
            rendition.validate()?;
        }
        if let [first, second] = renditions {
            if first.kind != CencDashRenditionKindV2::Video
                || second.kind != CencDashRenditionKindV2::Audio
            {
                return Err(ContractError::InvalidField("representation_kind"));
            }
            if first.segment_count.abs_diff(second.segment_count) > MAX_SEGMENT_COUNT_SKEW_V2 {
                return Err(ContractError::InvalidField("segment_count"));
            }
        }
        Ok(())
    }

    /// The fields before the manifest root, in head order.
    fn encode_leading(
        encrypted_content: &EncryptedContentIdentityV1,
    ) -> Result<Vec<u8>, ContractError> {
        let mut bytes = Vec::new();
        push_string(&mut bytes, CENC_DASH_MEDIA_SUITE_ID_V2)?;
        push_bytes(
            &mut bytes,
            "encrypted_content",
            &encrypted_content.canonical_bytes()?,
        )?;
        Ok(bytes)
    }

    /// The fields after the manifest root, in head order.
    fn encode_trailing(
        default_kid: ContentAccessIdV1,
        renditions: &[CencDashRenditionIdentityV2],
    ) -> Result<Vec<u8>, ContractError> {
        let mut bytes = default_kid.as_bytes().to_vec();
        bytes.push(
            u8::try_from(renditions.len())
                .map_err(|_| ContractError::InvalidField("representation_count"))?,
        );
        for rendition in renditions {
            rendition.encode(&mut bytes)?;
        }
        Ok(bytes)
    }

    fn compute_media_manifest_root(
        encrypted_content: &EncryptedContentIdentityV1,
        default_kid: ContentAccessIdV1,
        renditions: &[CencDashRenditionIdentityV2],
    ) -> Result<Digest32, ContractError> {
        let mut hasher = Sha256::new();
        hasher.update(CENC_DASH_MANIFEST_ROOT_DOMAIN_V2);
        hasher.update(Self::encode_leading(encrypted_content)?);
        hasher.update(Self::encode_trailing(default_kid, renditions)?);
        Ok(Digest32::new(hasher.finalize().into()))
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.encrypted_content
            .canonical_bytes()
            .map_err(|_| ContractError::InvalidField("encrypted_content"))?;
        Self::validate_renditions(&self.renditions)?;
        if self.media_manifest_root
            != Self::compute_media_manifest_root(
                &self.encrypted_content,
                self.default_kid,
                &self.renditions,
            )?
        {
            return Err(ContractError::InvalidField("media_manifest_root"));
        }
        Ok(())
    }
}

impl CanonicalContract for CencDashMediaIdentityV2 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut bytes = canonical_prefix(CENC_DASH_MEDIA_IDENTITY_DOMAIN_V2);
        bytes.extend(Self::encode_leading(&self.encrypted_content)?);
        bytes.extend_from_slice(self.media_manifest_root.as_bytes());
        bytes.extend(Self::encode_trailing(self.default_kid, &self.renditions)?);
        if bytes.len() > MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2 {
            return Err(ContractError::FieldTooLong("media_identity"));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2 {
            return Err(ContractError::FieldTooLong("media_identity"));
        }
        let mut cursor = canonical_cursor(bytes, CENC_DASH_MEDIA_IDENTITY_DOMAIN_V2)?;
        let suite = read_string(
            bytes,
            &mut cursor,
            "suite_id",
            MAX_MEDIA_DECLARATION_BYTES_V1,
        )?;
        if suite != CENC_DASH_MEDIA_SUITE_ID_V2 {
            return Err(ContractError::InvalidField("suite_id"));
        }
        let encrypted_content = EncryptedContentIdentityV1::from_canonical_bytes(&read_bytes(
            bytes,
            &mut cursor,
            "encrypted_content",
            u16::MAX as usize,
        )?)?;
        let media_manifest_root = Digest32::new(read_fixed_32(bytes, &mut cursor)?);
        let default_kid = ContentAccessIdV1::new(read_array::<16>(bytes, &mut cursor)?)?;
        let count = usize::from(read_u8(bytes, &mut cursor)?);
        if count == 0 || count > 2 {
            return Err(ContractError::InvalidField("representation_count"));
        }
        let mut renditions = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = CencDashRenditionKindV2::from_code(read_u8(bytes, &mut cursor)?)
                .ok_or(ContractError::InvalidField("representation_kind"))?;
            renditions.push(CencDashRenditionIdentityV2 {
                kind,
                mime_type: read_string(
                    bytes,
                    &mut cursor,
                    "mime_type",
                    MAX_MEDIA_DECLARATION_BYTES_V1,
                )?,
                codecs: read_string(bytes, &mut cursor, "codecs", MAX_MEDIA_DECLARATION_BYTES_V1)?,
                timescale: read_u32(bytes, &mut cursor)?,
                init_segment_sha256: Digest32::new(read_fixed_32(bytes, &mut cursor)?),
                init_segment_bytes: read_u64(bytes, &mut cursor)?,
                segment_count: read_u32(bytes, &mut cursor)?,
                segments_root: Digest32::new(read_fixed_32(bytes, &mut cursor)?),
            });
        }
        finish_canonical(bytes, cursor)?;
        let value = Self {
            encrypted_content,
            media_manifest_root,
            default_kid,
            renditions,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ContractError::InvalidField("non-canonical encoding"));
        }
        Ok(value)
    }
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], ContractError> {
    let end = cursor.checked_add(N).ok_or(ContractError::UnexpectedEnd)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ContractError::UnexpectedEnd)?
        .try_into()
        .map_err(|_| ContractError::UnexpectedEnd)?;
    *cursor = end;
    Ok(value)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ContractError> {
    Ok(read_array::<1>(bytes, cursor)?[0])
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ContractError> {
    let high = u32::from(read_u16(bytes, cursor)?);
    Ok(high << 16 | u32::from(read_u16(bytes, cursor)?))
}

/// Builds the head while the Runtime streams the protected segments: every
/// segment of rendition 0, then every segment of rendition 1. Memory is the
/// open Merkle subtrees (logarithmic), whatever the duration.
#[derive(Debug, Clone)]
pub struct CencDashIdentityBuilderV2 {
    default_kid: ContentAccessIdV1,
    decls: Vec<CencDashRenditionDeclV2>,
    roots: Vec<Digest32>,
    stream: CiphertextStreamHasher,
    merkle: CencDashMerkleRootBuilderV2,
    rendition: usize,
    pushed: u32,
}

impl CencDashIdentityBuilderV2 {
    pub fn new(
        default_kid: ContentAccessIdV1,
        decls: Vec<CencDashRenditionDeclV2>,
    ) -> Result<Self, ContractError> {
        // Validate the declarations now, with placeholder roots.
        let probe = decls
            .iter()
            .map(|decl| decl.identity_with_root(Digest32::new([0; 32])))
            .collect::<Vec<_>>();
        CencDashMediaIdentityV2::validate_renditions(&probe)?;
        let total = decls.iter().try_fold(0u32, |sum, decl| {
            sum.checked_add(decl.segment_count)
                .ok_or(ContractError::FieldTooLong("segment_count"))
        })?;
        Ok(Self {
            default_kid,
            decls,
            roots: Vec::new(),
            stream: CiphertextStreamHasher::new(total),
            merkle: CencDashMerkleRootBuilderV2::new(),
            rendition: 0,
            pushed: 0,
        })
    }

    /// Feeds the next protected segment in stream order.
    pub fn push_segment(&mut self, segment: &[u8]) -> Result<(), ContractError> {
        let decl = self
            .decls
            .get(self.rendition)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        if segment.is_empty() || segment.len() as u64 > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(ContractError::InvalidField("ciphertext_bytes"));
        }
        let leaf = cenc_dash_segment_leaf_hash(
            decl.kind,
            self.pushed,
            Digest32::new(Sha256::digest(segment).into()),
            segment.len() as u64,
        );
        self.stream.push_segment(segment)?;
        self.merkle.push_leaf(leaf);
        self.pushed += 1;
        if self.pushed == decl.segment_count {
            let merkle = std::mem::take(&mut self.merkle);
            self.roots.push(merkle.finish()?);
            self.rendition += 1;
            self.pushed = 0;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<CencDashMediaIdentityV2, ContractError> {
        if self.rendition != self.decls.len() {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        let encrypted_content = self.stream.finish()?;
        let renditions = self
            .decls
            .iter()
            .zip(self.roots)
            .map(|(decl, root)| decl.identity_with_root(root))
            .collect::<Vec<_>>();
        let media_manifest_root = CencDashMediaIdentityV2::compute_media_manifest_root(
            &encrypted_content,
            self.default_kid,
            &renditions,
        )?;
        let value = CencDashMediaIdentityV2 {
            encrypted_content,
            media_manifest_root,
            default_kid: self.default_kid,
            renditions,
        };
        value.validate()?;
        Ok(value)
    }
}

impl CencDashRenditionDeclV2 {
    fn identity_with_root(&self, segments_root: Digest32) -> CencDashRenditionIdentityV2 {
        CencDashRenditionIdentityV2 {
            kind: self.kind,
            mime_type: self.mime_type.clone(),
            codecs: self.codecs.clone(),
            timescale: self.timescale,
            init_segment_sha256: self.init_segment_sha256,
            init_segment_bytes: self.init_segment_bytes,
            segment_count: self.segment_count,
            segments_root,
        }
    }
}

/// One rendition's session layout: its protected init validated against the
/// head, and the head's Merkle root as the only authority for its segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCencDashRenditionSessionV2 {
    rendition_index: usize,
    kind: CencDashRenditionKindV2,
    segment_count: u32,
    segments_root: Digest32,
    init: ValidatedCencDashInitV2,
}

impl ValidatedCencDashRenditionSessionV2 {
    /// Binds rendition `rendition_index` of `head` to `protected_init_segment`.
    /// The init must hash to the head's entry, validate under V2, be of the
    /// declared kind and timescale, and carry the head's KID.
    pub fn new(
        head: &CencDashMediaIdentityV2,
        rendition_index: usize,
        protected_init_segment: &[u8],
    ) -> Result<Self, ContractError> {
        Self::new_in(&PROTECTION, head, rendition_index, protected_init_segment)
    }

    /// [`Self::new`] under an explicit protection context: the decrypt-open seam.
    pub(crate) fn new_in(
        ctx: &ProtectionContext<'_>,
        head: &CencDashMediaIdentityV2,
        rendition_index: usize,
        protected_init_segment: &[u8],
    ) -> Result<Self, ContractError> {
        head.validate()?;
        let entry = head
            .renditions
            .get(rendition_index)
            .ok_or(ContractError::InvalidField("rendition_index"))?;
        let init = ValidatedCencDashInitV2::new_in(
            ctx,
            protected_init_segment,
            entry.init_segment_sha256,
            entry.init_segment_bytes,
        )?;
        // A V2 init may legally lack the Elastos pssh, but nothing that needs a
        // key or custody binding may be built on one.
        if init.protection_header().is_none() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        if init.rendition().kind() != entry.kind
            || init.rendition().timescale() != entry.timescale
            || init.content_access_id() != head.default_kid
        {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        Ok(Self {
            rendition_index,
            kind: entry.kind,
            segment_count: entry.segment_count,
            segments_root: entry.segments_root,
            init,
        })
    }

    pub const fn rendition_index(&self) -> usize {
        self.rendition_index
    }

    pub const fn kind(&self) -> CencDashRenditionKindV2 {
        self.kind
    }

    pub const fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub const fn segments_root(&self) -> Digest32 {
        self.segments_root
    }

    pub const fn rendition(&self) -> &ValidatedFmp4RenditionV2 {
        self.init.rendition()
    }

    pub fn content_access_id(&self) -> ContentAccessIdV1 {
        self.init.content_access_id()
    }

    pub fn protection_header(&self) -> Option<&CustodyProtectionHeader> {
        self.init.protection_header()
    }

    /// The protection system that carried [`Self::protection_header`].
    pub fn protection_system(&self) -> Option<ProtectionSystemId> {
        self.init.protection_system()
    }

    /// Whether the init's custody box was written by the active encoder.
    pub fn protected_by_active_encoder(&self) -> bool {
        self.protected_by_active_encoder_in(&PROTECTION)
    }

    pub(crate) fn protected_by_active_encoder_in(&self, ctx: &ProtectionContext<'_>) -> bool {
        self.protection_system() == Some(ctx.writer().id)
    }

    pub fn rewrite_clear_init(
        &self,
        protected_init_segment: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        self.init.rewrite_clear_init(protected_init_segment)
    }

    /// Validates segment `segment_index`: `proof` must take its leaf to the
    /// rendition's root, and the bytes must be a valid V2 protected segment.
    pub fn validate_proven_segment(
        &self,
        segment_index: u32,
        encrypted_segment: &[u8],
        proof: &[Digest32],
    ) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
        if segment_index >= self.segment_count || encrypted_segment.is_empty() {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        let leaf = cenc_dash_segment_leaf_hash(
            self.kind,
            segment_index,
            Digest32::new(Sha256::digest(encrypted_segment).into()),
            encrypted_segment.len() as u64,
        );
        if !cenc_dash_verify_audit_path(
            leaf,
            u64::from(segment_index),
            u64::from(self.segment_count),
            proof,
            self.segments_root,
        ) {
            return Err(ContractError::InvalidField("segment_proof"));
        }
        self.init.validate_segment(encrypted_segment)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn all_audit_paths_equal_the_per_leaf_paths() {
        for count in 1..=40usize {
            let leaves: Vec<Digest32> = (0..count)
                .map(|index| Digest32::new([index as u8 + 1; 32]))
                .collect();
            let all = cenc_dash_merkle_audit_paths(&leaves).unwrap();
            assert_eq!(all.len(), count);
            for (index, path) in all.iter().enumerate() {
                assert_eq!(
                    path,
                    &cenc_dash_merkle_audit_path(&leaves, index).unwrap(),
                    "{count}/{index}"
                );
            }
        }
        assert!(cenc_dash_merkle_audit_paths(&[]).is_err());
    }

    use super::*;
    use crate::media::v2_tests::{
        protect, protect_in, protected_init_without_elastos, A, KID, TIMESCALE, V,
    };

    const SEGMENT_COUNT: usize = 3;

    fn kid() -> ContentAccessIdV1 {
        ContentAccessIdV1::new(KID).unwrap()
    }

    fn digest(bytes: &[u8]) -> Digest32 {
        Digest32::new(Sha256::digest(bytes).into())
    }

    struct Package {
        video_init: Vec<u8>,
        video: Vec<Vec<u8>>,
        audio_init: Vec<u8>,
        audio: Vec<Vec<u8>>,
    }

    fn package(video_segments: usize, audio_segments: usize) -> Package {
        let video = protect(V, &[]);
        let audio = protect(A, &[]);
        Package {
            video_init: video.init,
            video: vec![video.segment; video_segments],
            audio_init: audio.init,
            audio: vec![audio.segment; audio_segments],
        }
    }

    fn head(package: &Package) -> CencDashMediaIdentityV2 {
        CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[
                CencDashRenditionBytesV2 {
                    kind: V,
                    timescale: TIMESCALE,
                    init_segment: &package.video_init,
                    segments: &package.video,
                },
                CencDashRenditionBytesV2 {
                    kind: A,
                    timescale: TIMESCALE,
                    init_segment: &package.audio_init,
                    segments: &package.audio,
                },
            ],
        )
        .unwrap()
    }

    fn leaves(kind: CencDashRenditionKindV2, segments: &[Vec<u8>]) -> Vec<Digest32> {
        segments
            .iter()
            .enumerate()
            .map(|(index, segment)| {
                cenc_dash_segment_leaf_hash(
                    kind,
                    index as u32,
                    digest(segment),
                    segment.len() as u64,
                )
            })
            .collect()
    }

    fn hex(digest: Digest32) -> String {
        digest
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    // ----- ciphertext-stream hasher -----

    /// The v1 stream digest written out by hand, independent of the hasher.
    fn v1_stream_digest(segments: &[Vec<u8>]) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(b"elastos.protected-content.cenc-fmp4-ciphertext-stream/v1");
        hasher.update((segments.len() as u32).to_be_bytes());
        for segment in segments {
            hasher.update((segment.len() as u64).to_be_bytes());
            hasher.update(segment);
        }
        Digest32::new(hasher.finalize().into())
    }

    #[test]
    fn stream_hasher_is_the_v1_digest_however_it_is_fed() {
        let segments = vec![vec![1u8; 100], vec![2u8; 7], vec![3u8; 4096]];
        let whole = {
            let mut hasher = CiphertextStreamHasher::new(3);
            for segment in &segments {
                hasher.push_segment(segment).unwrap();
            }
            hasher.finish().unwrap()
        };
        assert_eq!(whole.ciphertext_sha256(), v1_stream_digest(&segments));
        assert_eq!(whole.ciphertext_bytes(), 100 + 7 + 4096);

        let mut chunked = CiphertextStreamHasher::new(3);
        for segment in &segments {
            chunked.begin_segment(segment.len() as u64).unwrap();
            for piece in segment.chunks(13) {
                chunked.update(piece).unwrap();
            }
        }
        assert_eq!(chunked.finish().unwrap(), whole);
    }

    #[test]
    fn v1_identity_still_uses_the_same_stream_digest() {
        let package = package(2, 0);
        let v1 = crate::media::CencFmp4MediaIdentityV1::new_from_bytes(
            &package.video_init,
            &package.video,
            "video/mp4",
            "avc1.640028",
        );
        // V2 inits are refused by V1; the digest itself is checked on raw bytes.
        assert!(v1.is_err());
        let segments = vec![vec![9u8; 31], vec![8u8; 17]];
        let mut hasher = CiphertextStreamHasher::new(2);
        for segment in &segments {
            hasher.push_segment(segment).unwrap();
        }
        assert_eq!(
            hasher.finish().unwrap().ciphertext_sha256(),
            v1_stream_digest(&segments)
        );
    }

    #[test]
    fn stream_hasher_refuses_misuse() {
        let mut hasher = CiphertextStreamHasher::new(2);
        hasher.begin_segment(4).unwrap();
        assert!(hasher.update(&[0; 5]).is_err(), "more than declared");
        hasher.update(&[0; 3]).unwrap();
        assert!(hasher.begin_segment(1).is_err(), "previous still open");
        hasher.update(&[0; 1]).unwrap();
        assert!(hasher.clone().finish().is_err(), "second segment missing");
        hasher.push_segment(&[7]).unwrap();
        assert!(hasher.push_segment(&[7]).is_err(), "third segment");
        assert!(hasher.finish().is_ok());

        let mut short = CiphertextStreamHasher::new(1);
        short.begin_segment(4).unwrap();
        short.update(&[0; 3]).unwrap();
        assert!(short.finish().is_err(), "open segment unfinished");
        assert!(CiphertextStreamHasher::new(0).finish().is_err(), "empty");
    }

    // ----- Merkle tree -----

    #[test]
    fn merkle_root_matches_the_rfc6962_test_vectors() {
        // The Certificate Transparency reference leaves and roots.
        let data: [&[u8]; 8] = [
            b"",
            &[0x00],
            &[0x10],
            &[0x20, 0x21],
            &[0x30, 0x31],
            &[0x40, 0x41, 0x42, 0x43],
            &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            &[
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                0x6e, 0x6f,
            ],
        ];
        let leaves: Vec<Digest32> = data.iter().map(|d| hash_leaf_input(d)).collect();
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (count, expected) in roots.iter().enumerate() {
            assert_eq!(
                hex(cenc_dash_merkle_root(&leaves[..=count]).unwrap()),
                *expected,
                "{} leaves",
                count + 1
            );
            assert_eq!(hex(subtree_root(&leaves[..=count])), *expected);
        }
        assert!(cenc_dash_merkle_root(&[]).is_err());
    }

    fn numbered_leaves(count: usize) -> Vec<Digest32> {
        (0..count)
            .map(|index| hash_leaf_input(&(index as u32).to_be_bytes()))
            .collect()
    }

    #[test]
    fn every_audit_path_verifies_and_only_for_its_own_leaf() {
        for count in 1..=40usize {
            let leaves = numbered_leaves(count);
            let root = cenc_dash_merkle_root(&leaves).unwrap();
            for index in 0..count {
                let path = cenc_dash_merkle_audit_path(&leaves, index).unwrap();
                let verify = |leaf, i, n, path: &[Digest32]| {
                    cenc_dash_verify_audit_path(leaf, i as u64, n as u64, path, root)
                };
                assert!(
                    verify(leaves[index], index, count, &path),
                    "{index}/{count}"
                );
                // Another leaf, another index, an index at the count, a longer or a
                // shorter path, a flipped sibling: all refused.
                assert!(!verify(leaves[(index + 1) % count], index, count, &path) || count == 1);
                assert!(!verify(leaves[index], index + 1, count, &path));
                assert!(
                    !verify(leaves[index], count, count, &path),
                    "index == count"
                );
                let mut longer = path.clone();
                longer.push(leaves[0]);
                assert!(!verify(leaves[index], index, count, &longer));
                if !path.is_empty() {
                    assert!(!verify(leaves[index], index, count, &path[1..]));
                    let mut flipped = path.clone();
                    flipped[0] = leaves[(index + 1) % count];
                    if flipped[0] != path[0] {
                        assert!(!verify(leaves[index], index, count, &flipped));
                    }
                }
            }
        }
    }

    #[test]
    fn audit_path_bounds_and_depth() {
        let leaves = numbered_leaves(5);
        assert!(cenc_dash_merkle_audit_path(&leaves, 5).is_err());
        assert!(cenc_dash_merkle_audit_path(&[], 0).is_err());
        assert!(cenc_dash_merkle_audit_path(&leaves[..1], 0)
            .unwrap()
            .is_empty());
        // A 2^32-leaf tree has 32-entry paths; 33 entries never verify.
        let root = cenc_dash_merkle_root(&leaves).unwrap();
        let long = vec![leaves[0]; MAX_CENC_DASH_AUDIT_PATH_V2 + 1];
        assert!(!cenc_dash_verify_audit_path(leaves[0], 0, 5, &long, root));
    }

    #[test]
    fn streaming_root_builder_equals_the_recursive_root() {
        for count in 1..=70usize {
            let leaves = numbered_leaves(count);
            let mut builder = CencDashMerkleRootBuilderV2::new();
            for leaf in &leaves {
                builder.push_leaf(*leaf);
            }
            assert_eq!(builder.finish().unwrap(), subtree_root(&leaves), "{count}");
        }
        assert!(CencDashMerkleRootBuilderV2::new().finish().is_err());
    }

    #[test]
    fn leaf_hash_binds_kind_index_digest_and_length() {
        let base = cenc_dash_segment_leaf_hash(V, 0, digest(b"a"), 10);
        assert_ne!(base, cenc_dash_segment_leaf_hash(A, 0, digest(b"a"), 10));
        assert_ne!(base, cenc_dash_segment_leaf_hash(V, 1, digest(b"a"), 10));
        assert_ne!(base, cenc_dash_segment_leaf_hash(V, 0, digest(b"b"), 10));
        assert_ne!(base, cenc_dash_segment_leaf_hash(V, 0, digest(b"a"), 11));
        // SHA-256(0x00 ‖ domain ‖ kind ‖ u32 index ‖ sha256 ‖ u64 len), by hand.
        let mut input = vec![0u8];
        input.extend_from_slice(b"elastos.protected-content.cenc-dash-segment-leaf/v2");
        input.push(1);
        input.extend_from_slice(&0u32.to_be_bytes());
        input.extend_from_slice(digest(b"a").as_bytes());
        input.extend_from_slice(&10u64.to_be_bytes());
        assert_eq!(base, digest(&input));
    }

    // ----- head -----

    #[test]
    fn head_round_trips_and_stays_small() {
        let package = package(SEGMENT_COUNT, SEGMENT_COUNT);
        let head = head(&package);
        let bytes = head.canonical_bytes().unwrap();
        assert!(bytes.len() < 500, "{} bytes", bytes.len());
        assert!(bytes.len() <= MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2);
        assert!(bytes.starts_with(b"elastos.protected-content.cenc-dash-media-identity/v2\0"));
        assert_eq!(
            CencDashMediaIdentityV2::from_canonical_bytes(&bytes).unwrap(),
            head
        );
        assert_eq!(head.suite_id(), "cenc-dash-aes128ctr/v2");
        assert_eq!(head.default_kid(), kid());
        let [video, audio] = head.renditions() else {
            panic!("two renditions")
        };
        assert_eq!(video.kind(), V);
        assert_eq!(audio.kind(), A);
        assert_eq!(video.mime_type(), "video/mp4");
        assert_eq!(audio.codecs(), "mp4a.40.2");
        assert_eq!(video.timescale(), TIMESCALE);
        assert_eq!(video.segment_count(), SEGMENT_COUNT as u32);
        assert_eq!(video.init_segment_sha256(), digest(&package.video_init));
        assert_eq!(video.init_segment_bytes(), package.video_init.len() as u64);
        assert_eq!(
            video.segments_root(),
            cenc_dash_merkle_root(&leaves(V, &package.video)).unwrap()
        );
        assert_eq!(
            audio.segments_root(),
            cenc_dash_merkle_root(&leaves(A, &package.audio)).unwrap()
        );
        // The stream digest runs over video first, then audio.
        let stream: Vec<Vec<u8>> = package
            .video
            .iter()
            .chain(&package.audio)
            .cloned()
            .collect();
        assert_eq!(
            head.encrypted_content().ciphertext_sha256(),
            v1_stream_digest(&stream)
        );
        assert_eq!(
            head.encrypted_content().ciphertext_bytes(),
            stream.iter().map(|s| s.len() as u64).sum::<u64>()
        );
    }

    #[test]
    fn head_size_does_not_grow_with_the_segment_count() {
        let small = head(&package(2, 2)).canonical_bytes().unwrap().len();
        let large = head(&package(300, 301)).canonical_bytes().unwrap().len();
        assert_eq!(small, large);
    }

    #[test]
    fn head_supports_video_only_and_audio_only() {
        let package = package(2, 2);
        for (kind, init, segments) in [
            (V, &package.video_init, &package.video),
            (A, &package.audio_init, &package.audio),
        ] {
            let head = CencDashMediaIdentityV2::new_from_bytes(
                kid(),
                &[CencDashRenditionBytesV2 {
                    kind,
                    timescale: TIMESCALE,
                    init_segment: init,
                    segments,
                }],
            )
            .unwrap();
            assert_eq!(head.renditions().len(), 1);
            let bytes = head.canonical_bytes().unwrap();
            assert_eq!(
                CencDashMediaIdentityV2::from_canonical_bytes(&bytes).unwrap(),
                head
            );
        }
    }

    #[test]
    fn head_refuses_bad_renditions() {
        let package = package(2, 2);
        let rendition = |kind, init, segments| CencDashRenditionBytesV2 {
            kind,
            timescale: TIMESCALE,
            init_segment: init,
            segments,
        };
        let video = rendition(V, &package.video_init[..], &package.video[..]);
        let audio = rendition(A, &package.audio_init[..], &package.audio[..]);
        let build = |renditions: &[CencDashRenditionBytesV2<'_>]| {
            CencDashMediaIdentityV2::new_from_bytes(kid(), renditions)
        };
        assert!(build(&[video, audio]).is_ok());
        assert!(build(&[]).is_err(), "no rendition");
        assert!(build(&[audio, video]).is_err(), "audio first");
        assert!(build(&[video, video]).is_err(), "kinds not unique");
        assert!(build(&[audio, audio]).is_err(), "kinds not unique");
        let no_segments: Vec<Vec<u8>> = Vec::new();
        assert!(build(&[rendition(V, &package.video_init, &no_segments)]).is_err());
        let zero_timescale = CencDashRenditionBytesV2 {
            timescale: 0,
            ..video
        };
        assert!(build(&[zero_timescale]).is_err());
        let empty_init = rendition(V, &[], &package.video);
        assert!(build(&[empty_init]).is_err());
        let with_empty_segment = [package.video[0].clone(), Vec::new()];
        assert!(build(&[rendition(V, &package.video_init, &with_empty_segment)]).is_err());
    }

    #[test]
    fn head_allows_a_count_skew_of_one_and_no_more() {
        let build = |video, audio| {
            let package = package(video, audio);
            CencDashMediaIdentityV2::new_from_bytes(
                kid(),
                &[
                    CencDashRenditionBytesV2 {
                        kind: V,
                        timescale: TIMESCALE,
                        init_segment: &package.video_init,
                        segments: &package.video,
                    },
                    CencDashRenditionBytesV2 {
                        kind: A,
                        timescale: TIMESCALE,
                        init_segment: &package.audio_init,
                        segments: &package.audio,
                    },
                ],
            )
        };
        assert!(build(5, 5).is_ok());
        assert!(build(5, 6).is_ok());
        assert!(build(6, 5).is_ok());
        assert!(build(5, 7).is_err());
        assert!(build(7, 5).is_err());
    }

    #[test]
    fn head_decoding_refuses_every_tamper() {
        let bytes = head(&package(SEGMENT_COUNT, SEGMENT_COUNT))
            .canonical_bytes()
            .unwrap();
        let decode = CencDashMediaIdentityV2::from_canonical_bytes;
        assert!(decode(&bytes).is_ok());
        assert!(decode(&[]).is_err());
        assert!(decode(&bytes[..bytes.len() - 1]).is_err(), "truncated");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err(), "trailing byte");
        let mut oversized = bytes.clone();
        oversized.resize(MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2 + 1, 0);
        assert!(decode(&oversized).is_err(), "over the structural cap");
        let mut wrong_domain = bytes.clone();
        wrong_domain[10] ^= 1;
        assert!(decode(&wrong_domain).is_err());
        // Any single flipped byte after the domain fails: the manifest root
        // covers every other field, and the encoding is canonical.
        let start = b"elastos.protected-content.cenc-dash-media-identity/v2\0".len();
        for index in start..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[index] ^= 0x01;
            assert!(decode(&flipped).is_err(), "byte {index} flipped");
        }
    }

    #[test]
    fn manifest_root_commits_to_every_other_field() {
        let package = package(SEGMENT_COUNT, SEGMENT_COUNT);
        let reference = head(&package);
        let mut other_kid = package_head_with_kid(&package, [0x56; 16]);
        assert_ne!(
            reference.media_manifest_root(),
            other_kid.media_manifest_root()
        );
        other_kid = package_head_with_kid(&package, KID);
        assert_eq!(reference, other_kid);
        let fewer = head(&crate::media_dash::tests::package(2, 2));
        assert_ne!(reference.media_manifest_root(), fewer.media_manifest_root());
    }

    fn package_head_with_kid(package: &Package, kid: [u8; 16]) -> CencDashMediaIdentityV2 {
        CencDashMediaIdentityV2::new_from_bytes(
            ContentAccessIdV1::new(kid).unwrap(),
            &[
                CencDashRenditionBytesV2 {
                    kind: V,
                    timescale: TIMESCALE,
                    init_segment: &package.video_init,
                    segments: &package.video,
                },
                CencDashRenditionBytesV2 {
                    kind: A,
                    timescale: TIMESCALE,
                    init_segment: &package.audio_init,
                    segments: &package.audio,
                },
            ],
        )
        .unwrap()
    }

    // ----- builder -----

    #[test]
    fn streaming_builder_equals_new_from_bytes() {
        let package = package(4, 3);
        let expected = head(&package);
        let decls = vec![
            CencDashRenditionDeclV2::from_init(V, TIMESCALE, &package.video_init, 4),
            CencDashRenditionDeclV2::from_init(A, TIMESCALE, &package.audio_init, 3),
        ];
        let mut builder = CencDashIdentityBuilderV2::new(kid(), decls).unwrap();
        for segment in package.video.iter().chain(&package.audio) {
            builder.push_segment(segment).unwrap();
        }
        assert_eq!(builder.finish().unwrap(), expected);
    }

    #[test]
    fn streaming_builder_refuses_wrong_counts_and_bad_declarations() {
        let package = package(2, 2);
        let decl = |kind, init: &[u8], count| {
            CencDashRenditionDeclV2::from_init(kind, TIMESCALE, init, count)
        };
        let video = decl(V, &package.video_init, 2);
        let mut builder = CencDashIdentityBuilderV2::new(kid(), vec![video.clone()]).unwrap();
        builder.push_segment(&package.video[0]).unwrap();
        assert!(builder.clone().finish().is_err(), "one segment short");
        builder.push_segment(&package.video[1]).unwrap();
        assert!(
            builder.clone().push_segment(&package.video[1]).is_err(),
            "one too many"
        );
        let mut empty = CencDashIdentityBuilderV2::new(kid(), vec![video.clone()]).unwrap();
        assert!(empty.push_segment(&[]).is_err(), "empty segment");

        assert!(CencDashIdentityBuilderV2::new(kid(), Vec::new()).is_err());
        assert!(
            CencDashIdentityBuilderV2::new(kid(), vec![decl(V, &package.video_init, 0)]).is_err()
        );
        let mut wrong_pair = video;
        wrong_pair.codecs = "mp4a.40.2".to_string();
        assert!(CencDashIdentityBuilderV2::new(kid(), vec![wrong_pair]).is_err());
        assert!(CencDashIdentityBuilderV2::new(
            kid(),
            vec![
                decl(V, &package.video_init, 2),
                decl(A, &package.audio_init, 4)
            ]
        )
        .is_err());
    }

    // ----- session layout (Merkle authority) -----

    #[test]
    fn session_validates_a_segment_only_with_its_proof() {
        let package = package(5, 4);
        let head = head(&package);
        let video =
            ValidatedCencDashRenditionSessionV2::new(&head, 0, &package.video_init).unwrap();
        let audio =
            ValidatedCencDashRenditionSessionV2::new(&head, 1, &package.audio_init).unwrap();
        assert_eq!(video.kind(), V);
        assert_eq!(audio.kind(), A);
        assert_eq!(video.segment_count(), 5);
        assert_eq!(audio.rendition_index(), 1);
        assert_eq!(video.content_access_id(), kid());
        assert!(video.protection_header().is_some());
        assert_eq!(video.rendition().kind(), V);

        for (session, kind, segments) in [(&video, V, &package.video), (&audio, A, &package.audio)]
        {
            let tree = leaves(kind, segments);
            for (index, segment) in segments.iter().enumerate() {
                let proof = cenc_dash_merkle_audit_path(&tree, index).unwrap();
                let layout = session
                    .validate_proven_segment(index as u32, segment, &proof)
                    .unwrap();
                assert!(layout.timeline().is_some());

                // Wrong index, wrong proof, other bytes: all refused.
                let other = (index + 1) % segments.len();
                assert!(session
                    .validate_proven_segment(other as u32, segment, &proof)
                    .is_err());
                let other_proof = cenc_dash_merkle_audit_path(&tree, other).unwrap();
                assert!(session
                    .validate_proven_segment(index as u32, segment, &other_proof)
                    .is_err());
                let mut tampered = segment.clone();
                *tampered.last_mut().unwrap() ^= 1;
                assert!(session
                    .validate_proven_segment(index as u32, &tampered, &proof)
                    .is_err());
                assert!(session
                    .validate_proven_segment(index as u32, segment, &[])
                    .is_err());
            }
            assert!(session
                .validate_proven_segment(segments.len() as u32, &segments[0], &[])
                .is_err());
        }
        // A video proof does not authorise an audio segment.
        let video_tree = leaves(V, &package.video);
        let proof = cenc_dash_merkle_audit_path(&video_tree, 0).unwrap();
        assert!(audio
            .validate_proven_segment(0, &package.audio[0], &proof)
            .is_err());
    }

    #[test]
    fn a_proven_segment_must_still_be_a_valid_protected_segment() {
        let package = package(1, 1);
        let garbage = vec![vec![0xeeu8; 64]];
        let head = CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[CencDashRenditionBytesV2 {
                kind: V,
                timescale: TIMESCALE,
                init_segment: &package.video_init,
                segments: &garbage,
            }],
        )
        .unwrap();
        let session =
            ValidatedCencDashRenditionSessionV2::new(&head, 0, &package.video_init).unwrap();
        assert!(session
            .validate_proven_segment(0, &garbage[0], &[])
            .is_err());
        // An audio segment under a video rendition's real proof is refused too.
        let mixed = CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[CencDashRenditionBytesV2 {
                kind: V,
                timescale: TIMESCALE,
                init_segment: &package.video_init,
                segments: &package.audio,
            }],
        )
        .unwrap();
        let session =
            ValidatedCencDashRenditionSessionV2::new(&mixed, 0, &package.video_init).unwrap();
        assert!(session
            .validate_proven_segment(0, &package.audio[0], &[])
            .is_err());
    }

    #[test]
    fn session_binds_the_init_to_the_head() {
        let package = package(2, 2);
        let head = head(&package);
        let new = |index, init: &[u8]| ValidatedCencDashRenditionSessionV2::new(&head, index, init);
        assert!(new(0, &package.video_init).is_ok());
        assert!(
            new(0, &package.audio_init).is_err(),
            "other rendition's init"
        );
        assert!(new(1, &package.video_init).is_err());
        assert!(new(2, &package.video_init).is_err(), "no such rendition");
        let mut tampered = package.video_init.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(new(0, &tampered).is_err());
        assert!(new(0, &[]).is_err());

        // A head that declares another timescale or KID than the init refuses it.
        let wrong_timescale = CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[CencDashRenditionBytesV2 {
                kind: V,
                timescale: TIMESCALE + 1,
                init_segment: &package.video_init,
                segments: &package.video,
            }],
        )
        .unwrap();
        assert!(
            ValidatedCencDashRenditionSessionV2::new(&wrong_timescale, 0, &package.video_init)
                .is_err()
        );
        let wrong_kid = package_head_with_kid(&package, [0x56; 16]);
        assert!(
            ValidatedCencDashRenditionSessionV2::new(&wrong_kid, 0, &package.video_init).is_err()
        );
        // A head that calls the video init audio is refused.
        let wrong_kind = CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[CencDashRenditionBytesV2 {
                kind: A,
                timescale: TIMESCALE,
                init_segment: &package.video_init,
                segments: &package.video,
            }],
        )
        .unwrap();
        assert!(
            ValidatedCencDashRenditionSessionV2::new(&wrong_kind, 0, &package.video_init).is_err()
        );
    }

    #[test]
    fn session_rewrites_the_clear_init_like_the_full_layout() {
        let video = protect(V, &[]);
        let package = Package {
            video_init: video.init.clone(),
            video: vec![video.segment],
            audio_init: Vec::new(),
            audio: Vec::new(),
        };
        let head = CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[CencDashRenditionBytesV2 {
                kind: V,
                timescale: TIMESCALE,
                init_segment: &package.video_init,
                segments: &package.video,
            }],
        )
        .unwrap();
        let session =
            ValidatedCencDashRenditionSessionV2::new(&head, 0, &package.video_init).unwrap();
        assert_eq!(
            session.rewrite_clear_init(&package.video_init).unwrap(),
            video.clear_init
        );
        assert!(session.rewrite_clear_init(&video.clear_init).is_err());
    }

    #[test]
    fn session_refuses_an_init_without_the_custody_binding() {
        let package = package(1, 1);
        let bare = protected_init_without_elastos(V);
        let head = CencDashMediaIdentityV2::new_from_bytes(
            kid(),
            &[CencDashRenditionBytesV2 {
                kind: V,
                timescale: TIMESCALE,
                init_segment: &bare,
                segments: &package.video,
            }],
        )
        .unwrap();
        // The init is a valid V2 protected init, so the refusal is the missing pssh.
        assert!(ValidatedCencDashInitV2::new_in(
            &PROTECTION,
            &bare,
            digest(&bare),
            bare.len() as u64
        )
        .is_ok());
        assert!(ValidatedCencDashRenditionSessionV2::new(&head, 0, &bare).is_err());
    }

    /// A test-local custody system added to the registry and made the writer, with
    /// no edit to the validators, the MPD builder or the decrypt-open path.
    mod fake_system {
        use super::*;
        use crate::mpd::{build_cenc_dash_mpd_v2_in, CencDashMpdRenditionV2, CencDashMpdSegmentV2};
        use crate::protection_system::conformance::run_over;
        use crate::protection_system::custody_data_v1;
        use crate::protection_system::{
            ProtectionRegistry, ProtectionRole, ProtectionSystem, COMMON, ELASTOS_CUSTODY_LEGACY,
            ELASTOS_CUSTODY_POOL,
        };
        use crate::Fmp4SegmentTimelineV2;

        const FAKE_SCHEME: &str = "cenc:test-fake-custody";

        fn fake_encode(
            id: ProtectionSystemId,
            header: &CustodyProtectionHeader,
        ) -> Result<Vec<u8>, ContractError> {
            custody_data_v1::encode(id, FAKE_SCHEME, header)
        }

        fn fake_decode(pssh_box: &[u8]) -> Result<CustodyProtectionHeader, ContractError> {
            custody_data_v1::decode(pssh_box, &[FAKE_SCHEME])
        }

        const FAKE: ProtectionSystem = ProtectionSystem {
            id: ProtectionSystemId::from_bytes([0xfa; 16]),
            scheme: FAKE_SCHEME,
            listed: true,
            role: ProtectionRole::Custody {
                encode: Some(fake_encode),
                decode: fake_decode,
            },
        };

        fn head_of(init: &[u8], segment: &[u8]) -> CencDashMediaIdentityV2 {
            CencDashMediaIdentityV2::new_from_bytes(
                kid(),
                &[CencDashRenditionBytesV2 {
                    kind: V,
                    timescale: TIMESCALE,
                    init_segment: init,
                    segments: std::slice::from_ref(&segment.to_vec()),
                }],
            )
            .unwrap()
        }

        #[test]
        fn a_registered_writer_system_flows_through_writers_validators_open_and_mpd() {
            // The pool system is retired from this registry: only FAKE encodes.
            let systems = [COMMON, ELASTOS_CUSTODY_LEGACY, FAKE];
            let ctx = ProtectionContext::new(ProtectionRegistry::new(&systems), &FAKE);

            // (i) The writers emit FAKE boxes that re-validate under the context.
            let video = protect_in(&ctx, V, &[]);
            assert!(video
                .init
                .windows(16)
                .any(|window| window == FAKE.id.as_bytes()));
            assert!(!video
                .init
                .windows(16)
                .any(|window| window == ELASTOS_CUSTODY_POOL.id.as_bytes()));

            // (ii) Under the production registry FAKE is a foreign box: kept
            // verbatim, no custody header, so nothing that needs the binding opens.
            let head = head_of(&video.init, &video.segment);
            let layout = crate::media::validate_cenc_fmp4_media_structure_v1(
                &video.init,
                std::slice::from_ref(&video.segment),
                crate::CencLayoutProfile::V2,
            )
            .unwrap();
            assert!(layout.protection_header().is_none());
            assert!(ValidatedCencDashRenditionSessionV2::new(&head, 0, &video.init).is_err());

            // A V1 init written under the context is refused under the production one.
            let clear_v1 =
                crate::media::v2_tests::init(&crate::media::v2_tests::InitSpec::clear(V));
            let v1_init = crate::ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_v1)
                .unwrap()
                .rewrite_protected_init_in(
                    &ctx,
                    &clear_v1,
                    &crate::protection_system::conformance::sample_header(
                        crate::CencMediaSuite::Fmp4V1,
                    ),
                )
                .unwrap();
            let v1_segments = [crate::media::v2_tests::v1_segment()];
            assert!(crate::media::validate_cenc_fmp4_media_structure_in(
                &ctx,
                &v1_init,
                &v1_segments,
                crate::CencLayoutProfile::V1
            )
            .is_ok());
            assert!(crate::media::validate_cenc_fmp4_media_structure_v1(
                &v1_init,
                &v1_segments,
                crate::CencLayoutProfile::V1
            )
            .is_err());

            // (iii) The decrypt-open path under the context accepts it and reads.
            let session =
                ValidatedCencDashRenditionSessionV2::new_in(&ctx, &head, 0, &video.init).unwrap();
            assert_eq!(session.protection_system(), Some(FAKE.id));
            assert!(session.protected_by_active_encoder_in(&ctx));
            assert!(!session.protected_by_active_encoder());
            assert_eq!(
                session.rewrite_clear_init(&video.init).unwrap(),
                video.clear_init
            );
            let leaves = [cenc_dash_segment_leaf_hash(
                V,
                0,
                Digest32::new(Sha256::digest(&video.segment).into()),
                video.segment.len() as u64,
            )];
            let proof = cenc_dash_merkle_audit_path(&leaves, 0).unwrap();
            assert!(session
                .validate_proven_segment(0, &video.segment, &proof)
                .is_ok());

            // (iv) The MPD names the fake scheme.
            let mpd = build_cenc_dash_mpd_v2_in(
                &ctx,
                &[CencDashMpdRenditionV2 {
                    protected_init: &video.init,
                    segments: &[CencDashMpdSegmentV2 {
                        timeline: Fmp4SegmentTimelineV2 {
                            decode_time: 0,
                            duration: u64::from(TIMESCALE),
                        },
                        bytes: video.segment.len() as u64,
                    }],
                }],
            )
            .unwrap();
            assert!(mpd.contains("value=\"cenc:test-fake-custody\""), "{mpd}");

            // (v) The conformance suite passes for FAKE and for every other system.
            run_over(&ctx);
        }

        #[test]
        fn active_encoder_is_true_for_a_fresh_mint_and_false_for_a_legacy_id_item() {
            let video = protect(V, &[]);
            let fresh = head_of(&video.init, &video.segment);
            let session = ValidatedCencDashRenditionSessionV2::new(&fresh, 0, &video.init).unwrap();
            assert!(session.protected_by_active_encoder());

            let mut legacy = video.init.clone();
            let at = legacy
                .windows(16)
                .position(|w| w == ELASTOS_CUSTODY_POOL.id.as_bytes())
                .unwrap();
            legacy[at..at + 16].copy_from_slice(ELASTOS_CUSTODY_LEGACY.id.as_bytes());
            let head = head_of(&legacy, &video.segment);
            let session = ValidatedCencDashRenditionSessionV2::new(&head, 0, &legacy).unwrap();
            assert_eq!(session.protection_system(), Some(ELASTOS_CUSTODY_LEGACY.id));
            assert!(!session.protected_by_active_encoder());
        }

        #[test]
        fn the_suite_refuses_a_registry_where_a_non_writer_encodes() {
            let systems = [COMMON, ELASTOS_CUSTODY_POOL, ELASTOS_CUSTODY_LEGACY, FAKE];
            let ctx =
                ProtectionContext::new(ProtectionRegistry::new(&systems), &ELASTOS_CUSTODY_POOL);
            let refused = std::panic::catch_unwind(|| {
                let systems = [COMMON, ELASTOS_CUSTODY_POOL, ELASTOS_CUSTODY_LEGACY, FAKE];
                let ctx = ProtectionContext::new(
                    ProtectionRegistry::new(&systems),
                    &ELASTOS_CUSTODY_POOL,
                );
                crate::protection_system::conformance::check_registry_invariants(&ctx);
            });
            assert!(refused.is_err(), "FAKE encodes but is not the writer");
            let _ = ctx;
        }

        /// The invariants are checked when the registry or context is built.
        #[test]
        fn a_registry_or_context_that_breaks_an_invariant_does_not_build() {
            let panics = |build: fn()| std::panic::catch_unwind(build).is_err();
            assert!(panics(|| {
                let systems = [COMMON, ELASTOS_CUSTODY_POOL, ELASTOS_CUSTODY_LEGACY];
                let _ = ProtectionContext::new(
                    ProtectionRegistry::new(&systems),
                    &ELASTOS_CUSTODY_LEGACY,
                );
            }));
            assert!(panics(|| {
                let systems = [COMMON, ELASTOS_CUSTODY_POOL, ELASTOS_CUSTODY_LEGACY];
                let _ = ProtectionContext::new(ProtectionRegistry::new(&systems), &FAKE);
            }));
            assert!(panics(|| {
                let _ =
                    ProtectionRegistry::new(&[COMMON, ELASTOS_CUSTODY_POOL, ELASTOS_CUSTODY_POOL]);
            }));
            assert!(panics(|| {
                let _ = ProtectionRegistry::new(&[ELASTOS_CUSTODY_POOL]);
            }));
            assert!(panics(|| {
                let other_common = ProtectionSystem {
                    id: ProtectionSystemId::from_bytes([0xfb; 16]),
                    scheme: "cenc:other-common",
                    ..COMMON
                };
                let _ = ProtectionRegistry::new(&[COMMON, other_common, ELASTOS_CUSTODY_POOL]);
            }));
        }
    }
}
