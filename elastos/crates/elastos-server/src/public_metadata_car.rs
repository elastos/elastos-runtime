//! Validation of a public metadata CAR before any byte of it reaches the
//! public IPFS store.
//!
//! The private store exports the metadata folder and the cover as CARv1
//! (`dag export`). Each CAR is admitted only when it is exactly the DAG of
//! its one expected root: every block hashes to its CID, every block is
//! reachable from the root, nothing the root links to is missing, and the
//! shape is the one this Runtime publishes. A folder is one flat UnixFS
//! directory of the known public files; a cover is one UnixFS file. So a CAR
//! cannot carry a stowaway block, such as the protected content the folder
//! names by CID, into the public store on the strength of a valid root.
//!
//! The decoders are hand-written and minimal (no CAR, dag-cbor or dag-pb crate
//! is a dependency): the CARv1 header as dag-cbor, dag-pb `PBNode`/`PBLink`,
//! and the UnixFS `Data.Type` field. Codecs are dag-pb and raw; the hash is
//! sha2-256; CIDv0 and CIDv1 are both accepted.

use std::collections::{HashMap, HashSet};

use sha2::Digest;

use crate::protected_content_elacity_metadata::{ACCESS_TOKEN_FILE, ROYALTY_SHARE_FILE};

const DAG_PB: u64 = 0x70;
const RAW: u64 = 0x55;
const SHA2_256: u64 = 0x12;
const SHA2_256_LEN: usize = 32;

const UNIXFS_RAW: u64 = 0;
const UNIXFS_DIRECTORY: u64 = 1;
const UNIXFS_FILE: u64 = 2;
const UNIXFS_HAMT_SHARD: u64 = 5;

/// The only names a public metadata folder may contain: the Elacity files
/// `elacity_metadata_files` writes, the Runtime's own `manifest.json`, and
/// the content object manifest.
pub(crate) const PUBLIC_FOLDER_FILES: &[&str] = &[
    "metadata.json",
    "content.json",
    "contract.json",
    ACCESS_TOKEN_FILE,
    ROYALTY_SHARE_FILE,
    "manifest.json",
    crate::content::CONTENT_OBJECT_MANIFEST_PATH,
];

/// What the expected root must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicRootKind {
    /// The metadata folder: one flat directory of [`PUBLIC_FOLDER_FILES`].
    Folder,
    /// The cover: one file, single- or multi-block.
    File,
}

/// A CAR that passed validation, with the bytes to hand to the public store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedCar {
    pub(crate) root: cid::Cid,
    pub(crate) bytes: Vec<u8>,
    pub(crate) blocks: usize,
}

/// Why a CAR was refused. Every refusal is final for these bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CarRefusal {
    /// Larger than the cap; checked before any parsing.
    TooLarge,
    /// Not a well-formed CARv1, dag-pb or UnixFS encoding, or a shape this
    /// Runtime does not publish. The text names the rule.
    Malformed(&'static str),
    /// The header root is not the expected root.
    RootMismatch,
    /// A block's bytes do not hash to its CID.
    HashMismatch,
    /// A CID with a codec other than dag-pb or raw, or a hash other than
    /// sha2-256.
    UnsupportedCodec,
    /// A block the root does not reach.
    Unreachable,
    /// A block the DAG links to is not in the CAR.
    Missing,
    /// A folder entry whose name is not a public folder file.
    DisallowedEntry(String),
    /// A folder entry that is itself a directory.
    SubFolder,
    /// The cover root is not a file.
    NotAFile,
}

/// Validate `bytes` as the CARv1 export of exactly the DAG of `expected_root`.
///
/// `expected_root` must be in canonical text form for its version (CIDv0
/// base58btc, CIDv1 base32 lowercase), as the store reported it. It is then
/// compared with the CAR's header root as a CID (version, codec and
/// multihash), not as text.
pub(crate) fn validate_public_metadata_car(
    bytes: &[u8],
    expected_root: &str,
    kind: PublicRootKind,
    max_bytes: usize,
) -> Result<ValidatedCar, CarRefusal> {
    if bytes.len() > max_bytes {
        return Err(CarRefusal::TooLarge);
    }
    let expected = parse_expected_root(expected_root)?;

    let mut input = bytes;
    let root = read_car_header(&mut input)?;
    require_supported(&root)?;
    if root != expected {
        return Err(CarRefusal::RootMismatch);
    }
    let blocks = read_car_blocks(input)?;
    let reached = walk(&root, kind, &blocks)?;
    if reached != blocks.len() {
        return Err(CarRefusal::Unreachable);
    }
    Ok(ValidatedCar {
        root,
        bytes: bytes.to_vec(),
        blocks: blocks.len(),
    })
}

fn parse_expected_root(text: &str) -> Result<cid::Cid, CarRefusal> {
    let cid = cid::Cid::try_from(text)
        .map_err(|_| CarRefusal::Malformed("expected root is not a CID"))?;
    // The canonical form for the CID's version: one CID has one text, so a
    // second spelling of the root is refused rather than interpreted.
    if cid.to_string() != text {
        return Err(CarRefusal::Malformed(
            "expected root is not in canonical form",
        ));
    }
    require_supported(&cid)?;
    Ok(cid)
}

fn require_supported(cid: &cid::Cid) -> Result<(), CarRefusal> {
    let hash = cid.hash();
    if !matches!(cid.codec(), DAG_PB | RAW)
        || hash.code() != SHA2_256
        || hash.digest().len() != SHA2_256_LEN
    {
        return Err(CarRefusal::UnsupportedCodec);
    }
    Ok(())
}

/// Read an unsigned LEB128 varint (multiformats and protobuf share it).
fn read_varint(input: &mut &[u8], what: &'static str) -> Result<u64, CarRefusal> {
    let mut value: u64 = 0;
    for index in 0..10 {
        let (&byte, rest) = input.split_first().ok_or(CarRefusal::Malformed(what))?;
        *input = rest;
        let bits = u64::from(byte & 0x7f);
        if index == 9 && bits > 1 {
            return Err(CarRefusal::Malformed(what));
        }
        value |= bits << (7 * index);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(CarRefusal::Malformed(what))
}

/// Take `len` bytes off the front of `input`.
fn take<'a>(input: &mut &'a [u8], len: u64, what: &'static str) -> Result<&'a [u8], CarRefusal> {
    let len = usize::try_from(len).map_err(|_| CarRefusal::Malformed(what))?;
    if len > input.len() {
        return Err(CarRefusal::Malformed(what));
    }
    let (head, rest) = input.split_at(len);
    *input = rest;
    Ok(head)
}

/// Read a binary CID that must fill `bytes` exactly.
fn read_exact_cid(bytes: &[u8], what: &'static str) -> Result<cid::Cid, CarRefusal> {
    let mut cursor = bytes;
    let cid = cid::Cid::read_bytes(&mut cursor).map_err(|_| CarRefusal::Malformed(what))?;
    if !cursor.is_empty() {
        return Err(CarRefusal::Malformed(what));
    }
    Ok(cid)
}

// ---- CARv1 ------------------------------------------------------------------

const CBOR_UINT: u8 = 0;
const CBOR_BYTES: u8 = 2;
const CBOR_TEXT: u8 = 3;
const CBOR_ARRAY: u8 = 4;
const CBOR_MAP: u8 = 5;
const CBOR_TAG: u8 = 6;
const CBOR_TAG_CID: u64 = 42;

/// One CBOR item head: major type and argument. Indefinite lengths and
/// reserved encodings are refused.
fn read_cbor_head(input: &mut &[u8]) -> Result<(u8, u64), CarRefusal> {
    const WHAT: &str = "CAR header is not dag-cbor";
    let (&initial, rest) = input.split_first().ok_or(CarRefusal::Malformed(WHAT))?;
    *input = rest;
    let major = initial >> 5;
    let width = match initial & 0x1f {
        small @ 0..=23 => return Ok((major, u64::from(small))),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(CarRefusal::Malformed(WHAT)),
    };
    let argument = take(input, width, WHAT)?
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    Ok((major, argument))
}

fn expect_cbor_head(input: &mut &[u8], major: u8, what: &'static str) -> Result<u64, CarRefusal> {
    match read_cbor_head(input)? {
        (found, argument) if found == major => Ok(argument),
        _ => Err(CarRefusal::Malformed(what)),
    }
}

/// Read the CARv1 header `{"roots":[CID],"version":1}` and return its one root.
fn read_car_header(input: &mut &[u8]) -> Result<cid::Cid, CarRefusal> {
    let length = read_varint(input, "CAR header length")?;
    if length == 0 {
        return Err(CarRefusal::Malformed("CAR header length"));
    }
    let mut header = take(input, length, "CAR header length")?;
    if expect_cbor_head(&mut header, CBOR_MAP, "CAR header is not a map")? != 2 {
        return Err(CarRefusal::Malformed(
            "CAR header must have exactly roots and version",
        ));
    }
    let mut root = None;
    let mut version = None;
    for _ in 0..2 {
        let key_len = expect_cbor_head(&mut header, CBOR_TEXT, "CAR header key is not text")?;
        match take(&mut header, key_len, "CAR header key")? {
            b"roots" if root.is_none() => {
                if expect_cbor_head(&mut header, CBOR_ARRAY, "CAR roots is not an array")? != 1 {
                    return Err(CarRefusal::Malformed(
                        "CAR header must name exactly one root",
                    ));
                }
                if expect_cbor_head(&mut header, CBOR_TAG, "CAR root is not a CID")? != CBOR_TAG_CID
                {
                    return Err(CarRefusal::Malformed("CAR root is not a CID"));
                }
                let cid_len = expect_cbor_head(&mut header, CBOR_BYTES, "CAR root is not a CID")?;
                let cid_bytes = take(&mut header, cid_len, "CAR root is not a CID")?;
                // dag-cbor CIDs carry the identity multibase prefix 0x00.
                let Some((0x00, cid_bytes)) = cid_bytes.split_first().map(|(p, r)| (*p, r)) else {
                    return Err(CarRefusal::Malformed("CAR root is not a CID"));
                };
                root = Some(read_exact_cid(cid_bytes, "CAR root is not a CID")?);
            }
            b"version" if version.is_none() => {
                version = Some(expect_cbor_head(
                    &mut header,
                    CBOR_UINT,
                    "CAR version is not 1",
                )?);
            }
            _ => {
                return Err(CarRefusal::Malformed(
                    "CAR header must have exactly roots and version",
                ))
            }
        }
    }
    if version != Some(1) {
        return Err(CarRefusal::Malformed("CAR version is not 1"));
    }
    if !header.is_empty() {
        return Err(CarRefusal::Malformed("CAR header has trailing bytes"));
    }
    root.ok_or(CarRefusal::Malformed(
        "CAR header must name exactly one root",
    ))
}

/// Read every section, verifying each block against its CID.
fn read_car_blocks(mut input: &[u8]) -> Result<HashMap<cid::Cid, &[u8]>, CarRefusal> {
    let mut blocks = HashMap::new();
    while !input.is_empty() {
        let length = read_varint(&mut input, "CAR section length")?;
        let section = take(&mut input, length, "CAR section length")?;
        let mut data = section;
        let cid = cid::Cid::read_bytes(&mut data)
            .map_err(|_| CarRefusal::Malformed("CAR section CID"))?;
        require_supported(&cid)?;
        if sha2::Sha256::digest(data).as_slice() != cid.hash().digest() {
            return Err(CarRefusal::HashMismatch);
        }
        if blocks.insert(cid, data).is_some() {
            return Err(CarRefusal::Malformed("CAR carries a block twice"));
        }
    }
    Ok(blocks)
}

// ---- dag-pb and UnixFS ------------------------------------------------------

struct PbLink<'a> {
    cid: cid::Cid,
    name: Option<&'a str>,
}

struct PbNode<'a> {
    links: Vec<PbLink<'a>>,
    data: Option<&'a [u8]>,
}

const WIRE_VARINT: u64 = 0;
const WIRE_FIXED64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_FIXED32: u64 = 5;

/// Decode a dag-pb `PBNode{Links(2) repeated, Data(1) optional}` strictly:
/// links first, at most one Data after them, no other field.
fn decode_pb_node(mut input: &[u8]) -> Result<PbNode<'_>, CarRefusal> {
    const WHAT: &str = "dag-pb node";
    let mut node = PbNode {
        links: Vec::new(),
        data: None,
    };
    while !input.is_empty() {
        let key = read_varint(&mut input, WHAT)?;
        if key & 7 != WIRE_LEN || node.data.is_some() {
            return Err(CarRefusal::Malformed(WHAT));
        }
        let length = read_varint(&mut input, WHAT)?;
        let field = take(&mut input, length, WHAT)?;
        match key >> 3 {
            2 => node.links.push(decode_pb_link(field)?),
            1 => node.data = Some(field),
            _ => return Err(CarRefusal::Malformed(WHAT)),
        }
    }
    Ok(node)
}

/// Decode a `PBLink{Hash(1), Name(2), Tsize(3)}`: Hash required, fields in
/// order, each at most once.
fn decode_pb_link(mut input: &[u8]) -> Result<PbLink<'_>, CarRefusal> {
    const WHAT: &str = "dag-pb link";
    let mut cid = None;
    let mut name = None;
    let mut last_field = 0;
    while !input.is_empty() {
        let key = read_varint(&mut input, WHAT)?;
        let field = key >> 3;
        if field <= last_field {
            return Err(CarRefusal::Malformed(WHAT));
        }
        last_field = field;
        match (field, key & 7) {
            (1, WIRE_LEN) => {
                let length = read_varint(&mut input, WHAT)?;
                cid = Some(read_exact_cid(take(&mut input, length, WHAT)?, WHAT)?);
            }
            (2, WIRE_LEN) => {
                let length = read_varint(&mut input, WHAT)?;
                let bytes = take(&mut input, length, WHAT)?;
                name = Some(std::str::from_utf8(bytes).map_err(|_| CarRefusal::Malformed(WHAT))?);
            }
            (3, WIRE_VARINT) => {
                read_varint(&mut input, WHAT)?;
            }
            _ => return Err(CarRefusal::Malformed(WHAT)),
        }
    }
    Ok(PbLink {
        cid: cid.ok_or(CarRefusal::Malformed(WHAT))?,
        name,
    })
}

/// The UnixFS `Data.Type(1)` of a dag-pb node's Data; other fields skipped.
fn unixfs_type(data: Option<&[u8]>) -> Result<u64, CarRefusal> {
    const WHAT: &str = "UnixFS data";
    let mut input = data.ok_or(CarRefusal::Malformed(WHAT))?;
    let mut kind = None;
    while !input.is_empty() {
        let key = read_varint(&mut input, WHAT)?;
        match (key >> 3, key & 7) {
            (1, WIRE_VARINT) if kind.is_none() => kind = Some(read_varint(&mut input, WHAT)?),
            (1, _) => return Err(CarRefusal::Malformed(WHAT)),
            (_, WIRE_VARINT) => {
                read_varint(&mut input, WHAT)?;
            }
            (_, WIRE_FIXED64) => {
                take(&mut input, 8, WHAT)?;
            }
            (_, WIRE_LEN) => {
                let length = read_varint(&mut input, WHAT)?;
                take(&mut input, length, WHAT)?;
            }
            (_, WIRE_FIXED32) => {
                take(&mut input, 4, WHAT)?;
            }
            _ => return Err(CarRefusal::Malformed(WHAT)),
        }
    }
    kind.ok_or(CarRefusal::Malformed(WHAT))
}

// ---- DAG walk ---------------------------------------------------------------

/// Where in the published shape a block was reached.
#[derive(Clone, Copy)]
enum Role {
    FolderRoot,
    CoverRoot,
    FolderEntry,
    FileChunk,
}

/// Walk the DAG from `root` over the CAR's blocks, checking each block's
/// shape for the role it was reached in. Returns how many distinct blocks
/// were reached; a block reached twice (a shared chunk) is checked once.
fn walk(
    root: &cid::Cid,
    kind: PublicRootKind,
    blocks: &HashMap<cid::Cid, &[u8]>,
) -> Result<usize, CarRefusal> {
    let root_role = match kind {
        PublicRootKind::Folder => Role::FolderRoot,
        PublicRootKind::File => Role::CoverRoot,
    };
    let mut visited = HashSet::new();
    let mut pending = vec![(*root, root_role)];
    while let Some((cid, role)) = pending.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let bytes = *blocks.get(&cid).ok_or(CarRefusal::Missing)?;
        if cid.codec() == RAW {
            match role {
                Role::FolderRoot => {
                    return Err(CarRefusal::Malformed("folder root is not a directory"))
                }
                // A raw block is file bytes.
                Role::CoverRoot | Role::FolderEntry | Role::FileChunk => continue,
            }
        }
        let node = decode_pb_node(bytes)?;
        match (role, unixfs_type(node.data)?) {
            (Role::FolderRoot, UNIXFS_DIRECTORY) => {
                let mut names = HashSet::new();
                for link in &node.links {
                    let name = link
                        .name
                        .ok_or(CarRefusal::Malformed("folder entry without a name"))?;
                    if !PUBLIC_FOLDER_FILES.contains(&name) {
                        return Err(CarRefusal::DisallowedEntry(name.to_string()));
                    }
                    if !names.insert(name) {
                        return Err(CarRefusal::Malformed("folder names an entry twice"));
                    }
                }
                pending.extend(node.links.iter().map(|link| (link.cid, Role::FolderEntry)));
            }
            (Role::FolderRoot, _) => {
                return Err(CarRefusal::Malformed("folder root is not a directory"))
            }
            (_, UNIXFS_FILE | UNIXFS_RAW) => {
                for link in &node.links {
                    if link.name.is_some_and(|name| !name.is_empty()) {
                        return Err(CarRefusal::Malformed("file chunk link has a name"));
                    }
                }
                pending.extend(node.links.iter().map(|link| (link.cid, Role::FileChunk)));
            }
            (Role::CoverRoot, _) => return Err(CarRefusal::NotAFile),
            (Role::FolderEntry, UNIXFS_DIRECTORY | UNIXFS_HAMT_SHARD) => {
                return Err(CarRefusal::SubFolder)
            }
            (Role::FolderEntry | Role::FileChunk, _) => {
                return Err(CarRefusal::Malformed("not a UnixFS file"))
            }
        }
    }
    Ok(visited.len())
}

#[cfg(test)]
mod tests {
    use super::test_car_builder::*;
    use super::*;

    const KUBO_FOLDER_ROOT: &str = "bafybeibafe7oi52uk6xjyuigvo3mel5hs6kdb4kvbb3odkepyn6o5xd4qu";
    const KUBO_COVER_SMALL_ROOT: &str = "QmUBeVrKj3MNuuRLnx4Pae5PA31uLoXDJMTo1ee3x3uGJm";
    const KUBO_COVER_MULTI_ROOT: &str = "QmPyhtWWrYyPNrnB3GzECpy4JrH8pd55BPN3C1sr4KEBtJ";
    const KUBO_FOLDER_CAR: &[u8] = include_bytes!("testdata/public_metadata/folder.car");
    const KUBO_COVER_SMALL_CAR: &[u8] = include_bytes!("testdata/public_metadata/cover-small.car");
    const KUBO_COVER_MULTI_CAR: &[u8] = include_bytes!("testdata/public_metadata/cover-multi.car");
    const CAP: usize = 4 * 1024 * 1024;

    fn validate(
        car: &[u8],
        root: &cid::Cid,
        kind: PublicRootKind,
    ) -> Result<ValidatedCar, CarRefusal> {
        validate_public_metadata_car(car, &root.to_string(), kind, CAP)
    }

    /// A metadata folder as the private store adds it: a CIDv1 dag-pb
    /// directory whose entries are CIDv1 raw leaves.
    fn folder(entries: &[(&str, &[u8])]) -> (cid::Cid, Vec<Block>) {
        let mut blocks = Vec::new();
        let mut links = Vec::new();
        for (name, bytes) in entries {
            let leaf = raw_block(bytes);
            links.push(Link::named(leaf.0, name, bytes.len() as u64));
            blocks.push(leaf);
        }
        let root = dag_pb_block_v1(&links, Some(&unixfs(UNIXFS_DIRECTORY, None)));
        blocks.insert(0, root.clone());
        (root.0, blocks)
    }

    /// A cover as Kubo adds it by default and above one chunk: a CIDv0 root
    /// File linking two CIDv0 dag-pb File leaves.
    fn multi_block_cover() -> (cid::Cid, Vec<Block>) {
        let first = dag_pb_block_v0(&[], Some(&unixfs(UNIXFS_FILE, Some(b"first chunk"))));
        let second = dag_pb_block_v0(&[], Some(&unixfs(UNIXFS_FILE, Some(b"second"))));
        let root = dag_pb_block_v0(
            &[
                Link::unnamed(first.0, first.1.len() as u64),
                Link::unnamed(second.0, second.1.len() as u64),
            ],
            Some(&unixfs(UNIXFS_FILE, None)),
        );
        (root.0, vec![root, first, second])
    }

    #[test]
    fn accepts_folder_with_raw_leaves() {
        let (root, blocks) = folder(&[
            ("metadata.json", br#"{"name":"a"}"#),
            ("content.json", br#"{"c":1}"#),
            ("manifest.json", br#"{"m":1}"#),
        ]);
        let bytes = car(&[root], &blocks);
        let validated = validate(&bytes, &root, PublicRootKind::Folder).unwrap();
        assert_eq!(validated.root, root);
        assert_eq!(validated.blocks, 4);
        assert_eq!(validated.bytes, bytes);
    }

    #[test]
    fn accepts_every_public_folder_file() {
        let entries: Vec<(&str, &[u8])> = PUBLIC_FOLDER_FILES
            .iter()
            .map(|name| (*name, name.as_bytes()))
            .collect();
        let (root, blocks) = folder(&entries);
        let validated = validate(&car(&[root], &blocks), &root, PublicRootKind::Folder).unwrap();
        assert_eq!(validated.blocks, PUBLIC_FOLDER_FILES.len() + 1);
    }

    #[test]
    fn accepts_single_block_cover_v0() {
        let block = dag_pb_block_v0(&[], Some(&unixfs(UNIXFS_FILE, Some(b"\x89PNG tiny"))));
        assert_eq!(block.0.version(), cid::Version::V0);
        let validated = validate(
            &car(&[block.0], std::slice::from_ref(&block)),
            &block.0,
            PublicRootKind::File,
        )
        .unwrap();
        assert_eq!(validated.root, block.0);
        assert_eq!(validated.blocks, 1);
    }

    #[test]
    fn accepts_multi_block_cover_v0() {
        let (root, blocks) = multi_block_cover();
        let validated = validate(&car(&[root], &blocks), &root, PublicRootKind::File).unwrap();
        assert_eq!(validated.blocks, 3);
    }

    #[test]
    fn refuses_two_roots() {
        let (root, blocks) = multi_block_cover();
        let other = blocks[1].0;
        assert!(matches!(
            validate(&car(&[root, other], &blocks), &root, PublicRootKind::File),
            Err(CarRefusal::Malformed(_))
        ));
        assert!(matches!(
            validate(&car(&[], &blocks), &root, PublicRootKind::File),
            Err(CarRefusal::Malformed(_))
        ));
    }

    #[test]
    fn refuses_root_mismatch() {
        let (root, blocks) = multi_block_cover();
        let other = blocks[1].0;
        assert_eq!(
            validate(&car(&[root], &blocks), &other, PublicRootKind::File).unwrap_err(),
            CarRefusal::RootMismatch
        );
        // The same multihash under another CID version is another root.
        let v1 = cid::Cid::new_v1(DAG_PB, *root.hash());
        assert_eq!(
            validate(&car(&[root], &blocks), &v1, PublicRootKind::File).unwrap_err(),
            CarRefusal::RootMismatch
        );
    }

    #[test]
    fn refuses_non_canonical_expected_root() {
        let (root, blocks) = folder(&[("metadata.json", b"{}")]);
        let bytes = car(&[root], &blocks);
        let base58 = root
            .to_string_of_base(cid::multibase::Base::Base58Btc)
            .unwrap();
        let upper = root
            .to_string_of_base(cid::multibase::Base::Base32Upper)
            .unwrap();
        for text in [
            base58,
            upper,
            format!("/ipfs/{root}"),
            "not a cid".to_string(),
        ] {
            assert!(
                matches!(
                    validate_public_metadata_car(&bytes, &text, PublicRootKind::Folder, CAP),
                    Err(CarRefusal::Malformed(_))
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn refuses_tampered_block() {
        let (root, mut blocks) = multi_block_cover();
        let last = blocks[2].1.len() - 1;
        blocks[2].1[last] ^= 0x01;
        assert_eq!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::File).unwrap_err(),
            CarRefusal::HashMismatch
        );
    }

    #[test]
    fn refuses_extra_unreachable_block() {
        let (root, mut blocks) = multi_block_cover();
        blocks.push(raw_block(b"stowaway"));
        assert_eq!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::File).unwrap_err(),
            CarRefusal::Unreachable
        );
    }

    #[test]
    fn refuses_missing_linked_block() {
        let (root, mut blocks) = multi_block_cover();
        blocks.remove(2);
        assert_eq!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::File).unwrap_err(),
            CarRefusal::Missing
        );
        let (folder_root, mut folder_blocks) = folder(&[("metadata.json", b"{}")]);
        folder_blocks.truncate(1);
        assert_eq!(
            validate(
                &car(&[folder_root], &folder_blocks),
                &folder_root,
                PublicRootKind::Folder
            )
            .unwrap_err(),
            CarRefusal::Missing
        );
    }

    #[test]
    fn refuses_duplicate_block() {
        let (root, mut blocks) = multi_block_cover();
        blocks.push(blocks[1].clone());
        assert!(matches!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::File),
            Err(CarRefusal::Malformed(_))
        ));
    }

    #[test]
    fn refuses_disallowed_filename() {
        let (root, blocks) = folder(&[("metadata.json", b"{}"), ("x.json", b"[]")]);
        assert_eq!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::Folder).unwrap_err(),
            CarRefusal::DisallowedEntry("x.json".to_string())
        );
    }

    /// Two entries with the same bytes share one block, as Kubo exports it:
    /// the block is carried and counted once.
    #[test]
    fn accepts_shared_leaf_once() {
        let leaf = raw_block(b"{}");
        let root = dag_pb_block_v1(
            &[
                Link::named(leaf.0, "content.json", 2),
                Link::named(leaf.0, "metadata.json", 2),
            ],
            Some(&unixfs(UNIXFS_DIRECTORY, None)),
        );
        let validated = validate(
            &car(&[root.0], &[root.clone(), leaf]),
            &root.0,
            PublicRootKind::Folder,
        )
        .unwrap();
        assert_eq!(validated.blocks, 2);
    }

    #[test]
    fn refuses_duplicate_entry_name() {
        let (root, blocks) = folder(&[("metadata.json", b"{}"), ("metadata.json", b"[]")]);
        assert!(matches!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::Folder),
            Err(CarRefusal::Malformed(_))
        ));
    }

    #[test]
    fn refuses_subfolder() {
        let (inner, inner_blocks) = folder(&[("metadata.json", b"{}")]);
        let root = dag_pb_block_v1(
            &[Link::named(inner, "content.json", 0)],
            Some(&unixfs(UNIXFS_DIRECTORY, None)),
        );
        let mut blocks = vec![root.clone()];
        blocks.extend(inner_blocks);
        assert_eq!(
            validate(&car(&[root.0], &blocks), &root.0, PublicRootKind::Folder).unwrap_err(),
            CarRefusal::SubFolder
        );
    }

    #[test]
    fn refuses_folder_as_cover() {
        let (root, blocks) = folder(&[("metadata.json", b"{}")]);
        assert_eq!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::File).unwrap_err(),
            CarRefusal::NotAFile
        );
    }

    #[test]
    fn refuses_cover_as_folder() {
        let (root, blocks) = multi_block_cover();
        assert!(matches!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::Folder),
            Err(CarRefusal::Malformed(_))
        ));
    }

    #[test]
    fn refuses_over_cap() {
        // Not a CAR at all: the size is refused before a byte is parsed.
        let bytes = vec![0xffu8; 64];
        let (root, _) = multi_block_cover();
        assert_eq!(
            validate_public_metadata_car(&bytes, &root.to_string(), PublicRootKind::File, 63)
                .unwrap_err(),
            CarRefusal::TooLarge
        );
    }

    #[test]
    fn refuses_sha1_cid() {
        use sha1::Digest;
        let bytes = b"sha1 leaf";
        let digest = sha1::Sha1::digest(bytes);
        let hash = cid::multihash::Multihash::wrap(0x11, &digest).unwrap();
        let block = (cid::Cid::new_v1(RAW, hash), bytes.to_vec());
        assert_eq!(
            validate(
                &car(&[block.0], std::slice::from_ref(&block)),
                &block.0,
                PublicRootKind::File
            )
            .unwrap_err(),
            CarRefusal::UnsupportedCodec
        );
        // A sha2-256 root whose linked block is sha1 is refused the same way.
        let root = dag_pb_block_v1(
            &[Link::unnamed(block.0, bytes.len() as u64)],
            Some(&unixfs(UNIXFS_FILE, None)),
        );
        assert_eq!(
            validate(
                &car(&[root.0], &[root.clone(), block]),
                &root.0,
                PublicRootKind::File
            )
            .unwrap_err(),
            CarRefusal::UnsupportedCodec
        );
    }

    #[test]
    fn refuses_dag_cbor_block() {
        let bytes = b"\xa0".to_vec();
        let block = (sha256_cid_v1(0x71, &bytes), bytes);
        assert_eq!(
            validate(
                &car(&[block.0], std::slice::from_ref(&block)),
                &block.0,
                PublicRootKind::File
            )
            .unwrap_err(),
            CarRefusal::UnsupportedCodec
        );
    }

    /// The folder's `metadata.json` names the protected content by CID, as
    /// the real one does. A CAR that carries that content block beside the
    /// folder is refused: the content is not part of the folder's DAG, so it
    /// can never ride into the public store on the folder's validation.
    #[test]
    fn folder_naming_content_cid_never_reaches_it() {
        let content = raw_block(b"ciphertext that must stay private");
        let metadata = format!(r#"{{"media":{{"uri":"ipfs://{}"}}}}"#, content.0);
        let (root, mut blocks) = folder(&[("metadata.json", metadata.as_bytes())]);
        let validated = validate(&car(&[root], &blocks), &root, PublicRootKind::Folder).unwrap();
        assert_eq!(validated.blocks, 2);
        blocks.push(content);
        assert_eq!(
            validate(&car(&[root], &blocks), &root, PublicRootKind::Folder).unwrap_err(),
            CarRefusal::Unreachable
        );
    }

    #[test]
    fn accepts_kubo_exported_folder() {
        let validated = validate_public_metadata_car(
            KUBO_FOLDER_CAR,
            KUBO_FOLDER_ROOT,
            PublicRootKind::Folder,
            CAP,
        )
        .unwrap();
        assert_eq!(validated.root.to_string(), KUBO_FOLDER_ROOT);
        assert_eq!(validated.blocks, 7);
        assert_eq!(validated.bytes, KUBO_FOLDER_CAR);
        assert_eq!(
            validate_public_metadata_car(
                KUBO_FOLDER_CAR,
                KUBO_FOLDER_ROOT,
                PublicRootKind::File,
                CAP
            )
            .unwrap_err(),
            CarRefusal::NotAFile
        );
    }

    #[test]
    fn accepts_kubo_exported_covers() {
        let small = validate_public_metadata_car(
            KUBO_COVER_SMALL_CAR,
            KUBO_COVER_SMALL_ROOT,
            PublicRootKind::File,
            CAP,
        )
        .unwrap();
        assert_eq!(small.blocks, 1);
        let multi = validate_public_metadata_car(
            KUBO_COVER_MULTI_CAR,
            KUBO_COVER_MULTI_ROOT,
            PublicRootKind::File,
            CAP,
        )
        .unwrap();
        assert_eq!(multi.blocks, 3);
        assert_eq!(
            validate_public_metadata_car(
                KUBO_COVER_MULTI_CAR,
                KUBO_COVER_SMALL_ROOT,
                PublicRootKind::File,
                CAP
            )
            .unwrap_err(),
            CarRefusal::RootMismatch
        );
    }

    #[test]
    fn refuses_kubo_folder_with_one_byte_flipped() {
        // The last byte belongs to the last raw leaf's data.
        let mut bytes = KUBO_FOLDER_CAR.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            validate_public_metadata_car(&bytes, KUBO_FOLDER_ROOT, PublicRootKind::Folder, CAP)
                .unwrap_err(),
            CarRefusal::HashMismatch
        );
    }

    /// Real Kubo end to end, offline: the private flags add a folder and Kubo
    /// defaults add a multi-block cover; `dag export` CARs pass this validator
    /// and import into a second repo, where an offline pin then succeeds
    /// (it would have to fetch, and fail, if any block were missing).
    #[test]
    #[ignore = "requires explicit ELASTOS_TEST_KUBO_PATH (Kubo 0.40.1); runs offline"]
    fn kubo_export_validate_import_pin() {
        use std::path::{Path, PathBuf};
        use std::process::Command;

        let kubo = PathBuf::from(
            std::env::var_os("ELASTOS_TEST_KUBO_PATH")
                .expect("explicit prerequisite required; skipped test is not proof"),
        );
        assert!(kubo.is_absolute() && kubo.is_file());
        let root = tempfile::tempdir().unwrap();
        let kubo_run = |repo: &Path, args: &[&str]| -> Vec<u8> {
            let output = Command::new(&kubo)
                .env("IPFS_PATH", repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "kubo {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap().trim().to_string();
        assert_eq!(
            text(kubo_run(root.path(), &["version", "--number"])),
            "0.40.1"
        );

        let source = root.path().join("source");
        let target = root.path().join("target");
        kubo_run(&source, &["init", "--profile=test"]);
        kubo_run(&target, &["init", "--profile=test"]);

        let folder_dir = root.path().join("folder");
        std::fs::create_dir(&folder_dir).unwrap();
        for name in PUBLIC_FOLDER_FILES {
            std::fs::write(folder_dir.join(name), format!(r#"{{"file":"{name}"}}"#)).unwrap();
        }
        let cover = root.path().join("cover.bin");
        let cover_bytes: Vec<u8> = (0..300 * 1024u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        std::fs::write(&cover, cover_bytes).unwrap();

        let folder_root = text(kubo_run(
            &source,
            &[
                "add",
                "--offline",
                "-r",
                "-Q",
                "--cid-version=1",
                "--raw-leaves",
                "--chunker=size-262144",
                folder_dir.to_str().unwrap(),
            ],
        ));
        let cover_root = text(kubo_run(
            &source,
            &["add", "--offline", "-Q", cover.to_str().unwrap()],
        ));
        assert!(cover_root.starts_with("Qm"), "{cover_root}");

        for (cid, kind) in [
            (&folder_root, PublicRootKind::Folder),
            (&cover_root, PublicRootKind::File),
        ] {
            let exported = kubo_run(&source, &["dag", "export", "--offline", cid]);
            let validated = validate_public_metadata_car(&exported, cid, kind, CAP).unwrap();
            assert_eq!(&validated.root.to_string(), cid);
            let car_path = root.path().join(format!("{cid}.car"));
            std::fs::write(&car_path, &validated.bytes).unwrap();
            kubo_run(
                &target,
                &[
                    "dag",
                    "import",
                    "--offline",
                    "--pin-roots=false",
                    car_path.to_str().unwrap(),
                ],
            );
            kubo_run(&target, &["pin", "add", "--offline", cid]);
            let pins = text(kubo_run(
                &target,
                &["pin", "ls", "--offline", "--type=recursive", "-q"],
            ));
            assert!(pins.lines().any(|line| line == cid), "{pins}");
        }
    }
}

#[cfg(test)]
pub(crate) mod test_car_builder {
    //! Encodes dag-pb, UnixFS, raw blocks and CARv1 independently of the
    //! decoders under test, so a test can describe exactly the bytes it means.

    use sha2::Digest;

    use super::{DAG_PB, RAW};

    pub(crate) type Block = (cid::Cid, Vec<u8>);

    pub(crate) struct Link {
        cid: cid::Cid,
        name: Option<String>,
        tsize: u64,
    }

    impl Link {
        pub(crate) fn named(cid: cid::Cid, name: &str, tsize: u64) -> Self {
            Self {
                cid,
                name: Some(name.to_string()),
                tsize,
            }
        }

        /// A file chunk link, written as Kubo writes it: an empty name.
        pub(crate) fn unnamed(cid: cid::Cid, tsize: u64) -> Self {
            Self {
                cid,
                name: Some(String::new()),
                tsize,
            }
        }
    }

    fn sha256(bytes: &[u8]) -> cid::multihash::Multihash<64> {
        cid::multihash::Multihash::wrap(0x12, &sha2::Sha256::digest(bytes)).unwrap()
    }

    pub(crate) fn sha256_cid_v1(codec: u64, bytes: &[u8]) -> cid::Cid {
        cid::Cid::new_v1(codec, sha256(bytes))
    }

    pub(crate) fn raw_block(bytes: &[u8]) -> Block {
        (sha256_cid_v1(RAW, bytes), bytes.to_vec())
    }

    pub(crate) fn dag_pb_block_v1(links: &[Link], data: Option<&[u8]>) -> Block {
        let bytes = dag_pb(links, data);
        (sha256_cid_v1(DAG_PB, &bytes), bytes)
    }

    pub(crate) fn dag_pb_block_v0(links: &[Link], data: Option<&[u8]>) -> Block {
        let bytes = dag_pb(links, data);
        (cid::Cid::new_v0(sha256(&bytes)).unwrap(), bytes)
    }

    fn varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn length_delimited(out: &mut Vec<u8>, key: u8, bytes: &[u8]) {
        out.push(key);
        varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    /// UnixFS `Data{Type(1), Data(2)}`.
    pub(crate) fn unixfs(kind: u64, data: Option<&[u8]>) -> Vec<u8> {
        let mut out = vec![0x08];
        varint(&mut out, kind);
        if let Some(data) = data {
            length_delimited(&mut out, 0x12, data);
            out.push(0x18);
            varint(&mut out, data.len() as u64);
        }
        out
    }

    /// Canonical dag-pb: every `PBNode.Links(2)`, then `PBNode.Data(1)`.
    fn dag_pb(links: &[Link], data: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        for link in links {
            let mut encoded = Vec::new();
            length_delimited(&mut encoded, 0x0a, &link.cid.to_bytes());
            if let Some(name) = &link.name {
                length_delimited(&mut encoded, 0x12, name.as_bytes());
            }
            encoded.push(0x18);
            varint(&mut encoded, link.tsize);
            length_delimited(&mut out, 0x12, &encoded);
        }
        if let Some(data) = data {
            length_delimited(&mut out, 0x0a, data);
        }
        out
    }

    /// CARv1: header `{"roots":[tag 42 CID...],"version":1}` in dag-cbor,
    /// then one `varint | CID | block` section per block.
    pub(crate) fn car(roots: &[cid::Cid], blocks: &[Block]) -> Vec<u8> {
        let mut header = vec![0xa2, 0x65];
        header.extend_from_slice(b"roots");
        assert!(roots.len() < 24);
        header.push(0x80 | roots.len() as u8);
        for root in roots {
            let mut cid_bytes = vec![0x00];
            cid_bytes.extend_from_slice(&root.to_bytes());
            header.extend_from_slice(&[0xd8, 0x2a, 0x58, cid_bytes.len() as u8]);
            header.extend_from_slice(&cid_bytes);
        }
        header.push(0x67);
        header.extend_from_slice(b"version");
        header.push(0x01);

        let mut out = Vec::new();
        varint(&mut out, header.len() as u64);
        out.extend_from_slice(&header);
        for (cid, bytes) in blocks {
            let cid_bytes = cid.to_bytes();
            varint(&mut out, (cid_bytes.len() + bytes.len()) as u64);
            out.extend_from_slice(&cid_bytes);
            out.extend_from_slice(bytes);
        }
        out
    }
}
