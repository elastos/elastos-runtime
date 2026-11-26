//! Persist the finalized rights policy without changing the provisional mint identity.
//! A settled mint can reuse the same seal after a restart. The content key,
//! envelope, and existing custody shares are independent of this policy record.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use elastos_protected_content_contracts::{
    CanonicalContract, Digest32, EvmContractAddressV1, RightsExpectedItemV1, RightsPolicyBodyV1,
    RightsPolicyIdentityV1, WalletAddress,
};
use nix::unistd::geteuid;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::mint_journal::{
    create_owner_only_directory, open_owner_only_file_for_read,
    open_owner_only_temp_file_for_write, sync_directory, validate_owner_only_directory,
};
use crate::{
    ExclusiveFileLock, PersistedRuntimeMint, RuntimeMintCreatorState,
    RuntimeMintCreatorTerminalEvidence, RuntimeMintDraft,
};

const SEAL_MAGIC: &[u8; 8] = b"epc-sp01";
const SEAL_DIGEST_DOMAIN: &[u8] = b"elastos/protected-content/runtime-policy-seal/v1";
const SEAL_LOCK_FILE: &str = "runtime-policy-seal.lock";
const MAX_SEAL_FILE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimePolicySealError {
    #[error("runtime policy seal: the mint has not settled on chain")]
    NotMinted,
    #[error("runtime policy seal: the minted item is invalid")]
    InvalidItem,
    #[error("runtime policy seal: the policy is not the one this mint provisioned")]
    PolicyMismatch,
    #[error("runtime policy seal: the sealed policy names another item")]
    ItemMismatch,
    #[error("runtime policy seal: the provisional policy is already sealed")]
    AlreadySealed,
    #[error("runtime policy seal: only the creator who minted may seal")]
    NotCreator,
    #[error("runtime policy seal store is unavailable")]
    Unavailable,
    #[error("runtime policy seal record is corrupt")]
    Corrupt,
    #[error("runtime policy seal record conflicts with an existing seal")]
    Conflict,
}

/// The item a settled creator mint names: its chain, channel (ledger), token
/// id and creator, as the creator terminal recorded them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeMintedItemV1 {
    chain_id: u64,
    expected_item: RightsExpectedItemV1,
}

impl RuntimeMintedItemV1 {
    pub fn from_creator_terminal(
        terminal: &RuntimeMintCreatorTerminalEvidence,
    ) -> Result<Self, RuntimePolicySealError> {
        Self::from_parts(
            terminal.chain_namespace(),
            terminal.ledger(),
            terminal.token_id(),
            terminal.seller(),
        )
    }

    pub fn from_parts(
        chain_namespace: &str,
        ledger: &str,
        token_id: &str,
        creator: &str,
    ) -> Result<Self, RuntimePolicySealError> {
        let chain_id = chain_namespace
            .strip_prefix("eip155:")
            .and_then(|id| id.parse::<u64>().ok())
            .filter(|id| *id != 0)
            .ok_or(RuntimePolicySealError::InvalidItem)?;
        let channel = EvmContractAddressV1::new(parse_address(ledger)?)
            .map_err(|_| RuntimePolicySealError::InvalidItem)?;
        let creator = WalletAddress::new(parse_address(creator)?);
        let expected_item = RightsExpectedItemV1::new(channel, parse_token_id(token_id)?, creator)
            .map_err(|_| RuntimePolicySealError::InvalidItem)?;
        Ok(Self {
            chain_id,
            expected_item,
        })
    }

    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub const fn expected_item(&self) -> RightsExpectedItemV1 {
        self.expected_item
    }
}

/// One mint's sealed policy: the object reference that replaces the
/// provisional v1 identity for buyers. The provisional identity is kept, so a
/// node that still serves v1 policies keeps opening the old reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSealedRightsPolicyV1 {
    mint_id: Digest32,
    provisional: RightsPolicyIdentityV1,
    sealed: RightsPolicyBodyV1,
}

impl RuntimeSealedRightsPolicyV1 {
    pub const fn mint_id(&self) -> Digest32 {
        self.mint_id
    }

    pub fn provisional_identity(&self) -> &RightsPolicyIdentityV1 {
        &self.provisional
    }

    pub fn sealed_policy(&self) -> &RightsPolicyBodyV1 {
        &self.sealed
    }

    pub fn sealed_identity(&self) -> Result<RightsPolicyIdentityV1, RuntimePolicySealError> {
        self.sealed
            .policy_identity()
            .map_err(|_| RuntimePolicySealError::Corrupt)
    }

    fn validate(&self) -> Result<(), RuntimePolicySealError> {
        let unsealed = self
            .sealed
            .unsealed()
            .policy_identity()
            .map_err(|_| RuntimePolicySealError::Corrupt)?;
        if self.sealed.expected_item().is_none() || unsealed != self.provisional {
            return Err(RuntimePolicySealError::Corrupt);
        }
        Ok(())
    }
}

/// Seals a settled mint: a fresh one right after its mint is final, or an
/// object minted and published under v1 before MINT-V2 (the re-seal). The
/// caller passes the provisional policy the mint was drafted under and the
/// policy its chain plane sealed for the minted item; the creator's wallet is
/// the authority, and must be the account the mint settled for.
pub fn seal_persisted_mint_rights_policy(
    mint: &PersistedRuntimeMint,
    creator_wallet_address: &str,
    provisional: &RightsPolicyBodyV1,
    sealed_by_chain_plane: &RightsPolicyBodyV1,
) -> Result<RuntimeSealedRightsPolicyV1, RuntimePolicySealError> {
    seal_minted_rights_policy(
        mint.draft(),
        mint.creator_state()
            .and_then(RuntimeMintCreatorState::terminal),
        creator_wallet_address,
        provisional,
        sealed_by_chain_plane,
    )
}

/// The checks behind [`seal_persisted_mint_rights_policy`]. Fails closed with
/// `NotMinted` while the mint has no settled terminal: there is no token id to
/// name yet.
pub fn seal_minted_rights_policy(
    draft: &RuntimeMintDraft,
    terminal: Option<&RuntimeMintCreatorTerminalEvidence>,
    creator_wallet_address: &str,
    provisional: &RightsPolicyBodyV1,
    sealed_by_chain_plane: &RightsPolicyBodyV1,
) -> Result<RuntimeSealedRightsPolicyV1, RuntimePolicySealError> {
    let provisional_identity = provisional
        .policy_identity()
        .map_err(|_| RuntimePolicySealError::PolicyMismatch)?;
    if provisional_identity != *draft.policy()
        || provisional.content_access_id() != draft.content_access_id()
        || provisional.encrypted_content() != draft.encrypted_content()
    {
        return Err(RuntimePolicySealError::PolicyMismatch);
    }
    if provisional.expected_item().is_some() {
        return Err(RuntimePolicySealError::AlreadySealed);
    }
    let terminal = terminal.ok_or(RuntimePolicySealError::NotMinted)?;
    if !terminal
        .seller()
        .eq_ignore_ascii_case(creator_wallet_address)
    {
        return Err(RuntimePolicySealError::NotCreator);
    }
    let item = RuntimeMintedItemV1::from_creator_terminal(terminal)?;
    if item.chain_id() != provisional.chain_id() {
        return Err(RuntimePolicySealError::ItemMismatch);
    }
    if sealed_by_chain_plane.unsealed() != *provisional {
        return Err(RuntimePolicySealError::PolicyMismatch);
    }
    if sealed_by_chain_plane.expected_item() != Some(item.expected_item()) {
        return Err(RuntimePolicySealError::ItemMismatch);
    }
    Ok(RuntimeSealedRightsPolicyV1 {
        mint_id: draft.mint_id(),
        provisional: provisional_identity,
        sealed: sealed_by_chain_plane.clone(),
    })
}

/// Owner-only store of sealed policies, one record per mint id. A record is
/// written once; an exact replay is accepted and a different seal for the same
/// mint is a `Conflict`.
#[derive(Clone)]
pub struct RuntimeSealedPolicyStoreV1 {
    root_dir: PathBuf,
    lock_path: PathBuf,
}

impl std::fmt::Debug for RuntimeSealedPolicyStoreV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeSealedPolicyStoreV1")
            .field("root_dir", &"[redacted]")
            .finish()
    }
}

impl RuntimeSealedPolicyStoreV1 {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root_dir = root_dir.into();
        Self {
            lock_path: root_dir.join(SEAL_LOCK_FILE),
            root_dir,
        }
    }

    pub fn persist(
        &self,
        sealed: &RuntimeSealedRightsPolicyV1,
    ) -> Result<RuntimeSealedRightsPolicyV1, RuntimePolicySealError> {
        sealed.validate()?;
        let _lock = self.lock()?;
        let path = self.record_path(sealed.mint_id);
        match self.read_path(&path, sealed.mint_id)? {
            Some(existing) if existing == *sealed => return Ok(existing),
            Some(_) => return Err(RuntimePolicySealError::Conflict),
            None => {}
        }
        let bytes = encode_record(sealed)?;
        let temp = self
            .root_dir
            .join(format!("{}.tmp", hex::encode(sealed.mint_id.as_bytes())));
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RuntimePolicySealError::Unavailable),
        }
        let mut file = open_owner_only_temp_file_for_write(&temp).map_err(unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| RuntimePolicySealError::Unavailable)?;
        drop(file);
        fs::rename(&temp, &path).map_err(|_| RuntimePolicySealError::Unavailable)?;
        sync_directory(&self.root_dir).map_err(unavailable)?;
        Ok(sealed.clone())
    }

    pub fn load(
        &self,
        mint_id: Digest32,
    ) -> Result<Option<RuntimeSealedRightsPolicyV1>, RuntimePolicySealError> {
        let _lock = self.lock()?;
        self.read_path(&self.record_path(mint_id), mint_id)
    }

    /// Reload a previously written policy against the current mint journal.
    /// A successful replay requires no fresh chain observation.
    pub fn load_for_mint(
        &self,
        mint: &PersistedRuntimeMint,
        creator_wallet_address: &str,
    ) -> Result<Option<RuntimeSealedRightsPolicyV1>, RuntimePolicySealError> {
        self.load_for_draft(
            mint.draft(),
            mint.creator_state()
                .and_then(RuntimeMintCreatorState::terminal),
            creator_wallet_address,
        )
    }

    fn load_for_draft(
        &self,
        draft: &RuntimeMintDraft,
        terminal: Option<&RuntimeMintCreatorTerminalEvidence>,
        creator_wallet_address: &str,
    ) -> Result<Option<RuntimeSealedRightsPolicyV1>, RuntimePolicySealError> {
        self.load(draft.mint_id())?
            .map(|record| {
                seal_minted_rights_policy(
                    draft,
                    terminal,
                    creator_wallet_address,
                    &record.sealed.unsealed(),
                    &record.sealed,
                )?;
                Ok(record)
            })
            .transpose()
    }

    fn lock(&self) -> Result<ExclusiveFileLock, RuntimePolicySealError> {
        create_owner_only_directory(&self.root_dir).map_err(unavailable)?;
        validate_owner_only_directory(&self.root_dir).map_err(unavailable)?;
        ExclusiveFileLock::acquire(&self.lock_path).map_err(unavailable)
    }

    fn record_path(&self, mint_id: Digest32) -> PathBuf {
        self.root_dir
            .join(format!("{}.seal", hex::encode(mint_id.as_bytes())))
    }

    fn read_path(
        &self,
        path: &Path,
        mint_id: Digest32,
    ) -> Result<Option<RuntimeSealedRightsPolicyV1>, RuntimePolicySealError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RuntimePolicySealError::Unavailable),
        };
        validate_owner_only_record(&metadata)?;
        let mut bytes = Vec::new();
        open_owner_only_file_for_read(path)
            .map_err(unavailable)?
            .take(MAX_SEAL_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RuntimePolicySealError::Unavailable)?;
        let sealed = decode_record(&bytes)?;
        if sealed.mint_id != mint_id {
            return Err(RuntimePolicySealError::Corrupt);
        }
        Ok(Some(sealed))
    }
}

fn unavailable(_: crate::RuntimeMintJournalError) -> RuntimePolicySealError {
    RuntimePolicySealError::Unavailable
}

fn validate_owner_only_record(metadata: &fs::Metadata) -> Result<(), RuntimePolicySealError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RuntimePolicySealError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(RuntimePolicySealError::Unavailable);
        }
    }
    Ok(())
}

fn encode_record(sealed: &RuntimeSealedRightsPolicyV1) -> Result<Vec<u8>, RuntimePolicySealError> {
    let provisional = sealed
        .provisional
        .canonical_bytes()
        .map_err(|_| RuntimePolicySealError::Corrupt)?;
    let policy = sealed
        .sealed
        .canonical_bytes()
        .map_err(|_| RuntimePolicySealError::Corrupt)?;
    let mut bytes = Vec::with_capacity(8 + 32 + 8 + provisional.len() + policy.len() + 32);
    bytes.extend_from_slice(SEAL_MAGIC);
    bytes.extend_from_slice(sealed.mint_id.as_bytes());
    for part in [&provisional, &policy] {
        let length = u32::try_from(part.len()).map_err(|_| RuntimePolicySealError::Corrupt)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let digest = record_digest(&bytes);
    bytes.extend_from_slice(&digest);
    if bytes.len() > MAX_SEAL_FILE_BYTES {
        return Err(RuntimePolicySealError::Corrupt);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<RuntimeSealedRightsPolicyV1, RuntimePolicySealError> {
    if bytes.len() > MAX_SEAL_FILE_BYTES || bytes.len() < 8 + 32 + 8 + 32 {
        return Err(RuntimePolicySealError::Corrupt);
    }
    let (payload, digest) = bytes.split_at(bytes.len() - 32);
    if record_digest(payload) != digest || &payload[..8] != SEAL_MAGIC {
        return Err(RuntimePolicySealError::Corrupt);
    }
    let mint_id = Digest32::new(
        payload[8..40]
            .try_into()
            .map_err(|_| RuntimePolicySealError::Corrupt)?,
    );
    let mut offset = 40;
    let mut part = || -> Result<&[u8], RuntimePolicySealError> {
        let length = payload
            .get(offset..offset + 4)
            .and_then(|raw| raw.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(RuntimePolicySealError::Corrupt)? as usize;
        let value = payload
            .get(offset + 4..offset + 4 + length)
            .ok_or(RuntimePolicySealError::Corrupt)?;
        offset += 4 + length;
        Ok(value)
    };
    let provisional = RightsPolicyIdentityV1::from_canonical_bytes(part()?)
        .map_err(|_| RuntimePolicySealError::Corrupt)?;
    let sealed = RightsPolicyBodyV1::from_canonical_bytes(part()?)
        .map_err(|_| RuntimePolicySealError::Corrupt)?;
    if offset != payload.len() {
        return Err(RuntimePolicySealError::Corrupt);
    }
    let record = RuntimeSealedRightsPolicyV1 {
        mint_id,
        provisional,
        sealed,
    };
    record.validate()?;
    Ok(record)
}

fn record_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEAL_DIGEST_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

fn parse_address(value: &str) -> Result<[u8; 20], RuntimePolicySealError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(RuntimePolicySealError::InvalidItem)?;
    if raw.len() != 40 {
        return Err(RuntimePolicySealError::InvalidItem);
    }
    hex::decode(raw)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RuntimePolicySealError::InvalidItem)
}

/// A canonical hex quantity (`0x` + at most 64 digits, no leading zero) as the
/// uint256 big-endian word.
fn parse_token_id(value: &str) -> Result<[u8; 32], RuntimePolicySealError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(RuntimePolicySealError::InvalidItem)?;
    if raw.is_empty()
        || raw.len() > 64
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(RuntimePolicySealError::InvalidItem);
    }
    let padded = format!("{raw:0>64}");
    hex::decode(padded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RuntimePolicySealError::InvalidItem)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
        CustodyPoolFailureDomainIdV1, CustodyPoolIdentityV1, CustodyPoolOperatorIdV1,
        EvmFunctionSelectorV1, EvmRightsMethodAbiV1, KeyEnvelopeIdentityV1, NodePublicKey,
        NodeSetV1, RightsActionV1, RightsObservationFinalityV1, RightsSubjectSourceV1, ThresholdV1,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::test_object;
    use crate::{RuntimeContentIdentityV1, RuntimeMintNodeBinding};

    const CREATOR: &str = "0x5151515151515151515151515151515151515151";
    const CHANNEL: &str = "0x2222222222222222222222222222222222222222";
    const CHAIN_ID: u64 = 8453;

    fn digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn provisional_policy(kid: u8) -> RightsPolicyBodyV1 {
        RightsPolicyBodyV1::new(
            test_object::object_identity(0x51)
                .encrypted_content()
                .clone(),
            ContentAccessIdV1::new([kid; 16]).unwrap(),
            RightsActionV1::View,
            RightsSubjectSourceV1::WalletAddress,
            CHAIN_ID,
            EvmContractAddressV1::new([0x01; 20]).unwrap(),
            EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
            EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
            RightsObservationFinalityV1::finalized(),
        )
        .unwrap()
    }

    fn node(seed: u8) -> RuntimeMintNodeBinding {
        RuntimeMintNodeBinding::new(
            NodePublicKey::new(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            CustodyPoolOperatorIdV1::new([0x80 + seed; 32]),
            CustodyPoolFailureDomainIdV1::new([0x90 + seed; 32]),
            digest(0xa0 + seed),
        )
        .unwrap()
    }

    /// A mint drafted under `policy`: the identity it provisioned and published.
    fn draft_under(policy: &RightsPolicyBodyV1) -> RuntimeMintDraft {
        let nodes = vec![node(1), node(2), node(3)];
        let threshold = ThresholdV1::new(2, 3).unwrap();
        let object = test_object::object_identity(0x51);
        let node_set = NodeSetV1::new(
            threshold,
            nodes
                .iter()
                .map(RuntimeMintNodeBinding::node_public_key)
                .collect(),
        )
        .unwrap();
        let key_envelope = KeyEnvelopeIdentityV1::new(
            object.encrypted_content().clone(),
            digest(0x22),
            512,
            node_set.node_set_id().unwrap(),
            threshold,
            CustodyPoolIdentityV1::new(digest(0x35), 512).unwrap(),
            CustodyEpochIdentityV1::new(digest(0x33), 512).unwrap(),
            CustodyCommitteeAuthorizationIdentityV1::new(digest(0x36), 512).unwrap(),
        )
        .unwrap();
        RuntimeMintDraft::new_from_identity(
            RuntimeContentIdentityV1::Object(object),
            policy.content_access_id(),
            key_envelope,
            policy.policy_identity().unwrap(),
            digest(0x19),
            threshold,
            nodes,
        )
        .unwrap()
    }

    fn terminal(
        seller: &str,
        chain_namespace: &str,
        token_id: &str,
    ) -> RuntimeMintCreatorTerminalEvidence {
        RuntimeMintCreatorTerminalEvidence::new(
            "bafybeifcreatorstatecid4m3z6kz3h6e57u4zylg66szavqixxkzh6g5zk3y",
            "ipfs://bafybeifcreatorstatecid4m3z6kz3h6e57u4zylg66szavqixxkzh6g5zk3y/metadata.json",
            seller,
            chain_namespace,
            "base-mainnet",
            CHANNEL,
            token_id,
            "0x3333333333333333333333333333333333333333",
            "0x2",
            "0x5",
            "0x4444444444444444444444444444444444444444",
            None,
            "0x5555555555555555555555555555555555555555555555555555555555555555",
            123,
        )
        .unwrap()
    }

    fn settled() -> RuntimeMintCreatorTerminalEvidence {
        terminal(CREATOR, "eip155:8453", "0x7")
    }

    fn item(channel: u8, token_id: u8, creator: u8) -> RightsExpectedItemV1 {
        let mut token = [0u8; 32];
        token[31] = token_id;
        RightsExpectedItemV1::new(
            EvmContractAddressV1::new([channel; 20]).unwrap(),
            token,
            WalletAddress::new([creator; 20]),
        )
        .unwrap()
    }

    /// What the chain plane answers once the binding to `item` is final.
    fn chain_sealed(kid: u8, sealed_item: RightsExpectedItemV1) -> RightsPolicyBodyV1 {
        provisional_policy(kid)
            .sealed_for_item(sealed_item)
            .unwrap()
    }

    /// Positive control: a settled mint seals the v2 policy naming exactly the
    /// item it minted, and the record survives a restart.
    #[test]
    fn a_settled_mint_seals_the_v2_policy_naming_its_minted_item() {
        let provisional = provisional_policy(0x41);
        let draft = draft_under(&provisional);
        let sealed = seal_minted_rights_policy(
            &draft,
            Some(&settled()),
            CREATOR,
            &provisional,
            &chain_sealed(0x41, item(0x22, 7, 0x51)),
        )
        .unwrap();
        assert_eq!(sealed.mint_id(), draft.mint_id());
        assert_eq!(sealed.provisional_identity(), draft.policy());
        assert_eq!(
            sealed.sealed_policy().expected_item(),
            Some(item(0x22, 7, 0x51))
        );
        assert!(sealed
            .sealed_policy()
            .canonical_bytes()
            .unwrap()
            .starts_with(b"elastos.protected-content.rights-policy-body/v2\0"));
        assert_ne!(&sealed.sealed_identity().unwrap(), draft.policy());

        let temp = tempdir().unwrap();
        let root = temp.path().join("runtime-policy-seal");
        assert_eq!(
            RuntimeSealedPolicyStoreV1::new(&root).load(draft.mint_id()),
            Ok(None)
        );
        RuntimeSealedPolicyStoreV1::new(&root)
            .persist(&sealed)
            .unwrap();
        assert_eq!(
            RuntimeSealedPolicyStoreV1::new(&root).load(draft.mint_id()),
            Ok(Some(sealed))
        );
    }

    /// Must refuse: before the mint has settled there is no token id, and no
    /// policy is sealed (fail closed). Control: the same inputs seal once it has.
    #[test]
    fn sealing_fails_closed_before_the_mint_settles() {
        let provisional = provisional_policy(0x41);
        let draft = draft_under(&provisional);
        let answer = chain_sealed(0x41, item(0x22, 7, 0x51));
        assert_eq!(
            seal_minted_rights_policy(&draft, None, CREATOR, &provisional, &answer),
            Err(RuntimePolicySealError::NotMinted)
        );
        assert!(seal_minted_rights_policy(
            &draft,
            Some(&settled()),
            CREATOR,
            &provisional,
            &answer
        )
        .is_ok());
    }

    /// Must refuse, one input at a time: another token id, channel or creator in
    /// the sealed answer, a policy for another object, a caller other than the
    /// creator, a terminal on another chain, and an already sealed provisional.
    #[test]
    fn sealing_refuses_another_item_object_creator_or_chain() {
        let provisional = provisional_policy(0x41);
        let draft = draft_under(&provisional);
        let seal = |terminal: &RuntimeMintCreatorTerminalEvidence,
                    caller: &str,
                    provisional: &RightsPolicyBodyV1,
                    answer: &RightsPolicyBodyV1| {
            seal_minted_rights_policy(&draft, Some(terminal), caller, provisional, answer)
        };
        for (other, expected) in [
            (item(0x22, 8, 0x51), RuntimePolicySealError::ItemMismatch),
            (item(0x23, 7, 0x51), RuntimePolicySealError::ItemMismatch),
            (item(0x22, 7, 0x52), RuntimePolicySealError::ItemMismatch),
        ] {
            assert_eq!(
                seal(
                    &settled(),
                    CREATOR,
                    &provisional,
                    &chain_sealed(0x41, other)
                ),
                Err(expected)
            );
        }
        let good = chain_sealed(0x41, item(0x22, 7, 0x51));
        assert_eq!(
            seal(
                &settled(),
                CREATOR,
                &provisional,
                &chain_sealed(0x42, item(0x22, 7, 0x51))
            ),
            Err(RuntimePolicySealError::PolicyMismatch)
        );
        assert_eq!(
            seal(&settled(), CREATOR, &provisional_policy(0x42), &good),
            Err(RuntimePolicySealError::PolicyMismatch)
        );
        assert_eq!(
            seal(
                &settled(),
                "0x6161616161616161616161616161616161616161",
                &provisional,
                &good
            ),
            Err(RuntimePolicySealError::NotCreator)
        );
        assert_eq!(
            seal(
                &terminal(CREATOR, "eip155:20", "0x7"),
                CREATOR,
                &provisional,
                &good
            ),
            Err(RuntimePolicySealError::ItemMismatch)
        );
        for bad in ["0x07", "7", "0x"] {
            assert_eq!(
                seal(
                    &terminal(CREATOR, "eip155:8453", bad),
                    CREATOR,
                    &provisional,
                    &good
                ),
                Err(RuntimePolicySealError::InvalidItem)
            );
        }
        let v2_draft = draft_under(&good);
        assert_eq!(
            seal_minted_rights_policy(&v2_draft, Some(&settled()), CREATOR, &good, &good),
            Err(RuntimePolicySealError::AlreadySealed)
        );
        // Same object (kid and content), other terms: not the policy this mint
        // provisioned, even when the chain answer is sealed from it.
        let other_terms = RightsPolicyBodyV1::new(
            provisional.encrypted_content().clone(),
            provisional.content_access_id(),
            RightsActionV1::Stream,
            RightsSubjectSourceV1::WalletAddress,
            CHAIN_ID,
            EvmContractAddressV1::new([0x01; 20]).unwrap(),
            EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
            EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
            RightsObservationFinalityV1::finalized(),
        )
        .unwrap();
        assert_eq!(
            seal(
                &settled(),
                CREATOR,
                &other_terms,
                &other_terms.sealed_for_item(item(0x22, 7, 0x51)).unwrap()
            ),
            Err(RuntimePolicySealError::PolicyMismatch)
        );
        // Control: the creator's own wallet, any hex case, seals.
        assert!(seal(
            &settled(),
            &CREATOR.to_ascii_uppercase().replace("0X", "0x"),
            &provisional,
            &good
        )
        .is_ok());
    }

    /// The re-seal of an object published under v1 before MINT-V2: the record
    /// keeps the v1 identity buyers already hold (v1 nodes keep opening it),
    /// is written once, and a different seal for the same mint is refused.
    #[test]
    fn reseal_of_a_v1_object_keeps_its_v1_identity_and_is_written_once() {
        let provisional = provisional_policy(0x41);
        let draft = draft_under(&provisional);
        let resealed = seal_minted_rights_policy(
            &draft,
            Some(&settled()),
            CREATOR,
            &provisional,
            &chain_sealed(0x41, item(0x22, 7, 0x51)),
        )
        .unwrap();
        assert_eq!(
            resealed.provisional_identity(),
            &provisional.policy_identity().unwrap()
        );
        assert_eq!(resealed.sealed_policy().unsealed(), provisional);

        let temp = tempdir().unwrap();
        let store = RuntimeSealedPolicyStoreV1::new(temp.path().join("seal"));
        store.persist(&resealed).unwrap();
        assert_eq!(store.persist(&resealed), Ok(resealed.clone()));
        let other = RuntimeSealedRightsPolicyV1 {
            sealed: chain_sealed(0x41, item(0x22, 9, 0x51)),
            ..resealed.clone()
        };
        assert_eq!(store.persist(&other), Err(RuntimePolicySealError::Conflict));
        let reopened = RuntimeSealedPolicyStoreV1::new(temp.path().join("seal"));
        assert_eq!(
            reopened.load_for_draft(&draft, Some(&settled()), CREATOR),
            Ok(Some(resealed))
        );
        assert_eq!(
            reopened.load_for_draft(&draft, None, CREATOR),
            Err(RuntimePolicySealError::NotMinted)
        );
        assert_eq!(
            reopened.load_for_draft(
                &draft,
                Some(&terminal(CREATOR, "eip155:8453", "0x9")),
                CREATOR,
            ),
            Err(RuntimePolicySealError::ItemMismatch)
        );
    }

    /// Must refuse: a tampered record, or one another user could have written.
    #[test]
    fn a_corrupt_or_loose_seal_record_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let provisional = provisional_policy(0x41);
        let draft = draft_under(&provisional);
        let sealed = seal_minted_rights_policy(
            &draft,
            Some(&settled()),
            CREATOR,
            &provisional,
            &chain_sealed(0x41, item(0x22, 7, 0x51)),
        )
        .unwrap();
        let temp = tempdir().unwrap();
        let root = temp.path().join("seal");
        let store = RuntimeSealedPolicyStoreV1::new(&root);
        store.persist(&sealed).unwrap();
        let path = root.join(format!("{}.seal", hex::encode(draft.mint_id().as_bytes())));

        let mut bytes = fs::read(&path).unwrap();
        // The last byte of the sealed token id: the record still decodes as a
        // valid v2 policy (for token 6), so only the record digest refuses it.
        let token_byte = bytes.len() - 32 - 21;
        assert_eq!(bytes[token_byte], 7);
        for at in [bytes.len() / 2, token_byte] {
            bytes[at] ^= 1;
            fs::write(&path, &bytes).unwrap();
            assert_eq!(
                store.load(draft.mint_id()),
                Err(RuntimePolicySealError::Corrupt)
            );
            bytes[at] ^= 1;
        }
        fs::write(&path, &bytes).unwrap();
        assert_eq!(store.load(draft.mint_id()), Ok(Some(sealed)));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.load(draft.mint_id()),
            Err(RuntimePolicySealError::Unavailable)
        );
    }
}
