//! The typed value both directions of a protection system share: what a custody
//! `pssh` box declares, independent of which system carries it and of its data
//! schema version.

use elastos_protected_content_contracts::{
    ContentAccessIdV1, ContractError, CustodyCommitteeAuthorizationIdentityV1,
    CustodyEpochIdentityV1, CustodyPoolIdentityV1, ProtectedContentBindingV1,
};

use crate::media::{CENC_DASH_MEDIA_SUITE_ID_V2, CENC_FMP4_MEDIA_SUITE_ID_V1};
use crate::wire::ProviderFailureCodeV1;

/// The sample-encryption profile of the media itself. It tells a consumer how to
/// apply the key once it has one; each media layout profile pins its own value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CencMediaSuite {
    Fmp4V1,
    DashV2,
}

impl CencMediaSuite {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fmp4V1 => CENC_FMP4_MEDIA_SUITE_ID_V1,
            Self::DashV2 => CENC_DASH_MEDIA_SUITE_ID_V2,
        }
    }

    pub fn parse(text: &str) -> Result<Self, ContractError> {
        match text {
            CENC_FMP4_MEDIA_SUITE_ID_V1 => Ok(Self::Fmp4V1),
            CENC_DASH_MEDIA_SUITE_ID_V2 => Ok(Self::DashV2),
            _ => Err(ContractError::InvalidField("pssh_content_encryption")),
        }
    }
}

/// What a custody protection box declares: the content access id (the KID), the
/// custody pool, epoch and committee-authorization identities that say which
/// quorum can answer, and the media suite. No key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyProtectionHeader {
    content_access_id: ContentAccessIdV1,
    custody_pool: CustodyPoolIdentityV1,
    custody_epoch: CustodyEpochIdentityV1,
    custody_committee_authorization: CustodyCommitteeAuthorizationIdentityV1,
    media_suite: CencMediaSuite,
}

impl CustodyProtectionHeader {
    pub fn new(
        content_access_id: ContentAccessIdV1,
        custody_pool: &CustodyPoolIdentityV1,
        custody_epoch: &CustodyEpochIdentityV1,
        custody_committee_authorization: &CustodyCommitteeAuthorizationIdentityV1,
        media_suite: CencMediaSuite,
    ) -> Self {
        Self {
            content_access_id,
            custody_pool: *custody_pool,
            custody_epoch: *custody_epoch,
            custody_committee_authorization: *custody_committee_authorization,
            media_suite,
        }
    }

    pub const fn content_access_id(&self) -> ContentAccessIdV1 {
        self.content_access_id
    }

    pub const fn media_suite(&self) -> CencMediaSuite {
        self.media_suite
    }

    pub const fn custody_pool(&self) -> &CustodyPoolIdentityV1 {
        &self.custody_pool
    }

    pub const fn custody_epoch(&self) -> &CustodyEpochIdentityV1 {
        &self.custody_epoch
    }

    pub const fn custody_committee_authorization(
        &self,
    ) -> &CustodyCommitteeAuthorizationIdentityV1 {
        &self.custody_committee_authorization
    }
}

/// Plan B T3.5: an item's Elastos header names the release it is opened
/// under. The header's KID must be the release policy's content access id,
/// and its custody pool, epoch and committee authorization must be the ones
/// the release binding's key envelope names. A decrypt provider runs this
/// before any key work, so a header that names another item or pool consumes
/// nothing.
pub fn require_protection_header_matches_release(
    header: &CustodyProtectionHeader,
    binding: &ProtectedContentBindingV1,
    content_access_id: ContentAccessIdV1,
) -> Result<(), ProviderFailureCodeV1> {
    let key_envelope = binding.key_envelope();
    if header.content_access_id() != content_access_id
        || *header.custody_pool() != key_envelope.custody_pool()
        || *header.custody_epoch() != key_envelope.custody_epoch()
        || *header.custody_committee_authorization()
            != key_envelope.custody_committee_authorization()
    {
        return Err(ProviderFailureCodeV1::BindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
        CustodyPoolIdentityV1, Digest32, ProtectedContentBindingV1,
    };

    use super::{
        require_protection_header_matches_release, CencMediaSuite, CustodyProtectionHeader,
    };
    use crate::test_support::{
        custody_envelope_for_media, make_signed_runtime_release_operation_for_envelope_and_seed,
    };
    use crate::ProviderFailureCodeV1;

    const KID: [u8; 16] = [0x44; 16];

    fn binding() -> ProtectedContentBindingV1 {
        make_signed_runtime_release_operation_for_envelope_and_seed(
            0x42,
            &custody_envelope_for_media(0x11),
        )
        .statement()
        .release_request()
        .binding()
        .clone()
    }

    /// A header naming the binding's committee, with one identity replaced.
    fn header(
        binding: &ProtectedContentBindingV1,
        pool: Option<CustodyPoolIdentityV1>,
        epoch: Option<CustodyEpochIdentityV1>,
        authorization: Option<CustodyCommitteeAuthorizationIdentityV1>,
    ) -> CustodyProtectionHeader {
        let envelope = binding.key_envelope();
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new(KID).unwrap(),
            &pool.unwrap_or(envelope.custody_pool()),
            &epoch.unwrap_or(envelope.custody_epoch()),
            &authorization.unwrap_or(envelope.custody_committee_authorization()),
            CencMediaSuite::Fmp4V1,
        )
    }

    #[test]
    fn a_header_naming_the_release_committee_and_kid_matches() {
        let binding = binding();
        assert_eq!(
            require_protection_header_matches_release(
                &header(&binding, None, None, None),
                &binding,
                ContentAccessIdV1::new(KID).unwrap(),
            ),
            Ok(())
        );
    }

    #[test]
    fn guard_a_header_naming_another_item_or_committee_is_a_binding_mismatch() {
        let binding = binding();
        let kid = ContentAccessIdV1::new(KID).unwrap();
        let other_pool = CustodyPoolIdentityV1::new(Digest32::new([0x91; 32]), 512).unwrap();
        let other_epoch = CustodyEpochIdentityV1::new(Digest32::new([0x92; 32]), 512).unwrap();
        let other_authorization =
            CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x93; 32]), 512).unwrap();
        for header in [
            header(&binding, Some(other_pool), None, None),
            header(&binding, None, Some(other_epoch), None),
            header(&binding, None, None, Some(other_authorization)),
        ] {
            assert_eq!(
                require_protection_header_matches_release(&header, &binding, kid),
                Err(ProviderFailureCodeV1::BindingMismatch)
            );
        }
        // Another item's KID.
        assert_eq!(
            require_protection_header_matches_release(
                &header(&binding, None, None, None),
                &binding,
                ContentAccessIdV1::new([0x45; 16]).unwrap(),
            ),
            Err(ProviderFailureCodeV1::BindingMismatch)
        );
    }
}
