//! Protection systems: the CENC `pssh` systems this crate writes and reads, each
//! one an adapter (strategy) behind one registry.
//!
//! An adapter carries its system id, its scheme name (the MPD
//! `ContentProtection@value`), its role, and, for a custody system, its own
//! encoder and decoder. Nobody else builds or parses a system's data:
//!
//! - producers encode only through the [`ProtectionContext`] writer binding;
//! - every reader decodes only through the [`ProtectionRegistry`].
//!
//! Adding a system is one adapter file plus one line in `REGISTERED`; making it the
//! one that is written changes one argument of [`PROTECTION`].
//!
//! The media-format axis (`CencLayoutProfile`) decides the box layout and which
//! media suite a header must declare; this module decides what is inside a box. The
//! format layer calls this layer and never the reverse.

use std::fmt;

use elastos_protected_content_contracts::ContractError;

use crate::pssh::PsshBoxV1;

mod common;
pub(crate) mod custody_data_v1;
mod elastos_legacy_v0;
mod elastos_pool_v1;
mod header;

#[cfg(test)]
pub(crate) mod conformance;

pub use header::{
    require_protection_header_matches_release, CencMediaSuite, CustodyProtectionHeader,
};

/// A DRM system id: the 16 bytes at offset 12 of a `pssh` box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectionSystemId([u8; 16]);

impl ProtectionSystemId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Canonical lowercase `8-4-4-4-12` UUID text.
impl fmt::Display for ProtectionSystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub type CustodyEncodeFn =
    fn(ProtectionSystemId, &CustodyProtectionHeader) -> Result<Vec<u8>, ContractError>;
/// Reads a whole `pssh` box. The registry has already matched its system id.
pub type CustodyDecodeFn = fn(&[u8]) -> Result<CustodyProtectionHeader, ContractError>;

#[derive(Clone, Copy)]
pub enum ProtectionRole {
    /// W3C Common: a KID list and no data.
    CommonKidList,
    /// Elastos custody. `encode: None` means decode-only (retired for writing).
    Custody {
        encode: Option<CustodyEncodeFn>,
        decode: CustodyDecodeFn,
    },
}

/// The adapter. Equality is by `id` only: function pointers are never compared, so
/// there is deliberately no derived `PartialEq`.
#[derive(Clone, Copy)]
pub struct ProtectionSystem {
    pub id: ProtectionSystemId,
    /// The MPD `ContentProtection@value`.
    pub scheme: &'static str,
    /// Whether a marketplace listing naming `scheme` is verified and adoptable.
    /// A retired system keeps reading its items but its listings are not
    /// verified (the earlier dKMS-era `-v0` entries stay "unverified").
    pub listed: bool,
    pub role: ProtectionRole,
}

impl fmt::Debug for ProtectionSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectionSystem")
            .field("id", &self.id)
            .field("scheme", &self.scheme)
            .field("can_encode", &self.can_encode())
            .finish()
    }
}

impl ProtectionSystem {
    pub const fn is_custody(&self) -> bool {
        matches!(self.role, ProtectionRole::Custody { .. })
    }

    pub const fn can_encode(&self) -> bool {
        matches!(
            self.role,
            ProtectionRole::Custody {
                encode: Some(_),
                ..
            }
        )
    }

    /// The complete `pssh` box for `header`. Refused for a system that is not a
    /// custody system or is decode-only.
    pub fn encode(&self, header: &CustodyProtectionHeader) -> Result<Vec<u8>, ContractError> {
        match self.role {
            ProtectionRole::Custody {
                encode: Some(encode),
                ..
            } => encode(self.id, header),
            _ => Err(ContractError::InvalidField("pssh_system_encode")),
        }
    }

    /// The header a whole `pssh` box declares. Refused for a system that is not a
    /// custody system, or when the box carries another system id.
    pub fn decode(&self, pssh_box: &[u8]) -> Result<CustodyProtectionHeader, ContractError> {
        let ProtectionRole::Custody { decode, .. } = self.role else {
            return Err(ContractError::InvalidField("pssh_system_id"));
        };
        if box_system_id(pssh_box) != Some(self.id) {
            return Err(ContractError::InvalidField("pssh_system_id"));
        }
        decode(pssh_box)
    }

    /// The Common `pssh` v1 box listing `kid`. Common system only.
    pub fn encode_kid_list(&self, kid: &[u8; 16]) -> Result<Vec<u8>, ContractError> {
        match self.role {
            ProtectionRole::CommonKidList => {
                Ok(crate::pssh::build_pssh_v1(self.id.as_bytes(), &[*kid], &[]))
            }
            ProtectionRole::Custody { .. } => Err(ContractError::InvalidField("pssh_system_id")),
        }
    }

    /// A Common box of version 1 must list `kid`; version 0 has no list. Common
    /// system only.
    pub fn check_kid_list(
        &self,
        version: u8,
        parsed: &PsshBoxV1,
        kid: &[u8; 16],
    ) -> Result<(), ContractError> {
        match self.role {
            ProtectionRole::CommonKidList => {
                if version == 1 && !parsed.kids.contains(kid) {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                Ok(())
            }
            ProtectionRole::Custody { .. } => Err(ContractError::InvalidField("pssh_system_id")),
        }
    }
}

fn box_system_id(pssh_box: &[u8]) -> Option<ProtectionSystemId> {
    let bytes: [u8; 16] = pssh_box.get(12..28)?.try_into().ok()?;
    Some(ProtectionSystemId(bytes))
}

/// How the registry sees a system id. An unregistered id is `Foreign`: opaque and
/// kept verbatim.
pub enum ProtectionClass<'r> {
    Common(&'r ProtectionSystem),
    Custody(&'r ProtectionSystem),
    Foreign,
}

const fn ids_equal(a: &ProtectionSystemId, b: &ProtectionSystemId) -> bool {
    let mut i = 0;
    while i < 16 {
        if a.0[i] != b.0[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn strs_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[derive(Clone, Copy)]
pub struct ProtectionRegistry<'a> {
    systems: &'a [ProtectionSystem],
}

impl<'a> ProtectionRegistry<'a> {
    /// Panics (at compile time for a `const`/`static`) on a duplicate id or scheme,
    /// or unless exactly one system is the Common one.
    pub const fn new(systems: &'a [ProtectionSystem]) -> Self {
        let mut commons = 0;
        let mut i = 0;
        while i < systems.len() {
            if matches!(systems[i].role, ProtectionRole::CommonKidList) {
                commons += 1;
            }
            let mut j = i + 1;
            while j < systems.len() {
                if ids_equal(&systems[i].id, &systems[j].id) {
                    panic!("duplicate protection system id");
                }
                if strs_equal(systems[i].scheme, systems[j].scheme) {
                    panic!("duplicate protection system scheme");
                }
                j += 1;
            }
            i += 1;
        }
        if commons != 1 {
            panic!("a protection registry needs exactly one Common system");
        }
        Self { systems }
    }

    pub fn systems(&self) -> &'a [ProtectionSystem] {
        self.systems
    }

    pub fn lookup(&self, id: &[u8; 16]) -> Option<&'a ProtectionSystem> {
        self.systems
            .iter()
            .find(|system| system.id.as_bytes() == id)
    }

    /// The system registered under an MPD / metadata `scheme` name.
    pub fn lookup_by_scheme(&self, scheme: &str) -> Option<&'a ProtectionSystem> {
        self.systems.iter().find(|system| system.scheme == scheme)
    }

    /// Whether `scheme` names a registered custody system whose listings are
    /// verified and adoptable.
    pub fn is_listed_scheme(&self, scheme: &str) -> bool {
        self.lookup_by_scheme(scheme)
            .is_some_and(|system| system.is_custody() && system.listed)
    }

    pub fn classify(&self, id: &[u8; 16]) -> ProtectionClass<'a> {
        match self.lookup(id) {
            Some(system) if system.is_custody() => ProtectionClass::Custody(system),
            Some(system) => ProtectionClass::Common(system),
            None => ProtectionClass::Foreign,
        }
    }

    pub fn common(&self) -> &'a ProtectionSystem {
        self.systems
            .iter()
            .find(|system| matches!(system.role, ProtectionRole::CommonKidList))
            .expect("the constructor guarantees one Common system")
    }

    /// The system id of `pssh_box` must be a registered custody system; then its
    /// decoder runs on the whole box.
    pub fn decode_custody(
        &self,
        pssh_box: &[u8],
    ) -> Result<(ProtectionSystemId, CustodyProtectionHeader), ContractError> {
        let id = box_system_id(pssh_box).ok_or(ContractError::InvalidField("pssh_box"))?;
        match self.classify(id.as_bytes()) {
            ProtectionClass::Custody(system) => Ok((id, system.decode(pssh_box)?)),
            _ => Err(ContractError::InvalidField("pssh_system_id")),
        }
    }
}

/// A registry plus the writer binding: the single injectable dependency of the
/// format layer.
#[derive(Clone, Copy)]
pub struct ProtectionContext<'a> {
    registry: ProtectionRegistry<'a>,
    writer: &'a ProtectionSystem,
}

impl<'a> ProtectionContext<'a> {
    /// Panics unless `writer` is registered, a custody system and able to encode.
    pub const fn new(registry: ProtectionRegistry<'a>, writer: &'a ProtectionSystem) -> Self {
        let mut registered = false;
        let mut i = 0;
        while i < registry.systems.len() {
            if ids_equal(&registry.systems[i].id, &writer.id) {
                registered = true;
            }
            i += 1;
        }
        if !registered {
            panic!("the writer is not a registered protection system");
        }
        if !writer.can_encode() {
            panic!("the writer must be a custody system that can encode");
        }
        Self { registry, writer }
    }

    pub fn registry(&self) -> ProtectionRegistry<'a> {
        self.registry
    }

    pub fn writer(&self) -> &'a ProtectionSystem {
        self.writer
    }

    /// The `pssh` box the writer binding encodes for `header`.
    pub fn encode_custody(
        &self,
        header: &CustodyProtectionHeader,
    ) -> Result<Vec<u8>, ContractError> {
        self.writer.encode(header)
    }
}

static REGISTERED: [ProtectionSystem; 3] = [
    common::COMMON,
    elastos_pool_v1::ELASTOS_CUSTODY_POOL,
    elastos_legacy_v0::ELASTOS_CUSTODY_LEGACY,
];

/// THE production context: one registry, one active encoder.
pub static PROTECTION: ProtectionContext<'static> = ProtectionContext::new(
    ProtectionRegistry::new(&REGISTERED),
    &elastos_pool_v1::ELASTOS_CUSTODY_POOL,
);

#[cfg(test)]
pub(crate) use common::COMMON;
/// The legacy system's adapter, for tests in this crate that build a legacy item.
#[cfg(test)]
pub(crate) use elastos_legacy_v0::ELASTOS_CUSTODY_LEGACY;
#[cfg(test)]
pub(crate) use elastos_pool_v1::ELASTOS_CUSTODY_POOL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemes_resolve_to_their_registered_system() {
        let registry = PROTECTION.registry();
        for system in registry.systems() {
            assert_eq!(
                registry
                    .lookup_by_scheme(system.scheme)
                    .map(|found| found.id),
                Some(system.id)
            );
        }
        assert!(registry.lookup_by_scheme("cenc:not-registered").is_none());
        assert!(!registry.is_listed_scheme("cenc:not-registered"));
        assert!(registry.is_listed_scheme(PROTECTION.writer().scheme));
        // Retired systems and the Common one are never verified in a listing.
        assert!(!registry.is_listed_scheme(registry.common().scheme));
        for system in registry.systems().iter().filter(|s| !s.can_encode()) {
            assert!(!registry.is_listed_scheme(system.scheme), "{}", system.id);
        }
        assert!(registry.lookup_by_scheme("").is_none());
        assert_eq!(
            registry
                .lookup_by_scheme(PROTECTION.writer().scheme)
                .map(|s| s.id),
            Some(PROTECTION.writer().id)
        );
    }
}
