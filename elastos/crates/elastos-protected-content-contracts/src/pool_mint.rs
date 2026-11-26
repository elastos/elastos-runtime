//! Plan B POOL-MINT: a Home mints into a pool it uses.
//!
//! A Home that uses a pool (its own, or one added under "Pools this Home
//! uses") seals its own content locally and provisions one share to each
//! node of the pool's epoch. With each share it sends a
//! [`SignedPoolMintShareV1`]: its Runtime issuer's signature over the pool,
//! the epoch, the item's key envelope and its content access id (the KID).
//! A member stores the signed statement with the share, so the share keeps
//! its minter and KID for every later release (ADV-02), and the same signed
//! statement tells every Home that the item was minted through the pool.
//!
//! The statement has no clock: the runtime provisioning statement it travels
//! with keeps the 60 s freshness rule.

use ed25519_dalek::Signature;

use crate::canonical::{CanonicalBody, ContractError, Decoder, Encoder};
use crate::identity::validate_ed25519_public_key;
use crate::{
    CanonicalContract, ContentAccessIdV1, CustodyEpochIdentityV1, KeyEnvelopeIdentityV1,
    PoolContractError, PoolDidV1, RuntimeOperationIssuerKeyV1,
};

const ED25519_SIGNATURE_BYTES: usize = 64;

/// What the minting Home signs, once for all of an item's node shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMintShareStatementV1 {
    pool: PoolDidV1,
    epoch: CustodyEpochIdentityV1,
    minter_runtime_issuer: RuntimeOperationIssuerKeyV1,
    key_envelope: KeyEnvelopeIdentityV1,
    content_access_id: ContentAccessIdV1,
}

impl PoolMintShareStatementV1 {
    pub fn new(
        pool: PoolDidV1,
        minter_runtime_issuer: RuntimeOperationIssuerKeyV1,
        key_envelope: KeyEnvelopeIdentityV1,
        content_access_id: ContentAccessIdV1,
    ) -> Result<Self, ContractError> {
        let value = Self {
            pool,
            // The epoch is the one the item's key envelope names (L3).
            epoch: key_envelope.custody_epoch(),
            minter_runtime_issuer,
            key_envelope,
            content_access_id,
        };
        CanonicalBody::validate(&value)?;
        Ok(value)
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.pool
    }

    pub const fn epoch(&self) -> CustodyEpochIdentityV1 {
        self.epoch
    }

    pub const fn minter_runtime_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.minter_runtime_issuer
    }

    pub fn key_envelope(&self) -> &KeyEnvelopeIdentityV1 {
        &self.key_envelope
    }

    pub const fn content_access_id(&self) -> ContentAccessIdV1 {
        self.content_access_id
    }
}

impl CanonicalBody for PoolMintShareStatementV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-mint-share-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        crate::CustodyEpochIssuerKeyV1::new(*self.pool.issuer().as_bytes())?;
        RuntimeOperationIssuerKeyV1::new(*self.minter_runtime_issuer.as_bytes())?;
        self.key_envelope.canonical_bytes()?;
        ContentAccessIdV1::new(*self.content_access_id.as_bytes())?;
        if self.key_envelope.custody_epoch() != self.epoch {
            return Err(ContractError::InvalidField("pool_mint_share.epoch"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.pool.issuer().as_bytes());
        encoder.nested(&self.epoch)?;
        encoder.fixed(self.minter_runtime_issuer.as_bytes());
        encoder.nested(&self.key_envelope)?;
        encoder.fixed(self.content_access_id.as_bytes());
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::from_issuer(crate::CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?);
        let epoch: CustodyEpochIdentityV1 = decoder.nested("pool_mint_share.epoch")?;
        let value = Self {
            pool,
            epoch,
            minter_runtime_issuer: RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?,
            key_envelope: decoder.nested("pool_mint_share.key_envelope")?,
            content_access_id: ContentAccessIdV1::new(decoder.fixed()?)?,
        };
        CanonicalBody::validate(&value)?;
        Ok(value)
    }
}

/// The statement with the minting Home's Runtime signature over its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolMintShareV1 {
    statement: PoolMintShareStatementV1,
    runtime_signature: Vec<u8>,
}

impl SignedPoolMintShareV1 {
    pub fn new(
        statement: PoolMintShareStatementV1,
        runtime_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            runtime_signature,
        };
        CanonicalBody::validate(&value)?;
        Ok(value)
    }

    pub fn statement(&self) -> &PoolMintShareStatementV1 {
        &self.statement
    }

    pub fn runtime_signature(&self) -> &[u8] {
        &self.runtime_signature
    }

    /// The minting Home's signature over the statement, with no clock.
    pub fn verify_signature(&self) -> Result<&PoolMintShareStatementV1, PoolContractError> {
        let statement_bytes = self.statement.canonical_bytes()?;
        let key = validate_ed25519_public_key(
            *self.statement.minter_runtime_issuer.as_bytes(),
            "minter_runtime_issuer",
        )
        .map_err(|_| PoolContractError::Signature)?;
        let signature = Signature::from_slice(&self.runtime_signature)
            .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(&statement_bytes, &signature)
            .map_err(|_| PoolContractError::Signature)?;
        Ok(&self.statement)
    }

    /// The signature, and that the statement names exactly this item: its
    /// key envelope (so its epoch) and its KID.
    pub fn verify_for_item(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
        content_access_id: ContentAccessIdV1,
    ) -> Result<&PoolMintShareStatementV1, PoolContractError> {
        let statement = self.verify_signature()?;
        if &statement.key_envelope != key_envelope {
            return Err(ContractError::InvalidField("pool_mint_share.key_envelope").into());
        }
        if statement.content_access_id != content_access_id {
            return Err(ContractError::InvalidField("pool_mint_share.content_access_id").into());
        }
        Ok(statement)
    }
}

impl CanonicalBody for SignedPoolMintShareV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-mint-share/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.statement.canonical_bytes()?;
        if self.runtime_signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ContractError::InvalidField("runtime_signature"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.runtime_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_mint_share_statement")?,
            decoder.bytes("runtime_signature", ED25519_SIGNATURE_BYTES)?,
        )
    }
}
