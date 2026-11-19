//! Durable signed replies for completed remote seals.
//!
//! The receiver calls this after publication verification and node signing.
//! Publication indexing and the lifetimes of live upload sessions are owned
//! separately. This store grants no content or key access.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, SignedMintRequestV1, SignedPoolDescriptorAnyV1, SignedSealCompletedV1,
    SignedSealSessionAttestationV1,
};
use elastos_protected_content_provider_contracts::RemoteSealSessionFieldsV1;
use elastos_protected_content_runtime::PoolSessionSource;
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "elastos.protected-content.sealer-completion/v1";
const MAX_RECORD_BYTES: u64 = 768 * 1024;
static COMMIT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredCompletion {
    schema: String,
    owner: String,
    session: String,
    request: String,
    descriptor: String,
    attestation: String,
    completion: String,
}

/// Receipts owned by the same authenticated Carrier endpoint as the upload.
pub struct SealerCompletionStore {
    root: PathBuf,
}

impl SealerCompletionStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir
                .join("protected-content")
                .join("custody-sealed-completions"),
        }
    }

    /// Save the exact reply before sending it. The caller must derive
    /// `owner` from the live session which produced the published output.
    pub fn commit(
        &self,
        owner: &PoolSessionSource,
        descriptor: &SignedPoolDescriptorAnyV1,
        request: &SignedMintRequestV1,
        attestation: &SignedSealSessionAttestationV1,
        completion: &SignedSealCompletedV1,
        now: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(authenticated_remote(owner), "invalid remote seal owner");
        let session = attestation.session_id();
        let node = attestation.sealer_node_public_key();
        attestation.verify_for_upload(request, descriptor, node, session, now)?;
        completion.verify_for_request_at(descriptor, request, node, now)?;
        let value = StoredCompletion {
            schema: SCHEMA.into(),
            owner: owner.endpoint_did.clone(),
            session: hex::encode(session),
            request: encode(request)?,
            descriptor: encode(descriptor)?,
            attestation: encode(attestation)?,
            completion: encode(completion)?,
        };
        let bytes = serde_json::to_vec(&value)?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "remote seal completion record exceeds its bound"
        );
        let _guard = COMMIT_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("remote seal completion lock unavailable"))?;
        let path = self.path(session);
        if let Some(previous) = self.read(session)? {
            anyhow::ensure!(
                previous == value,
                "remote seal completion conflicts with the stored reply"
            );
            // An earlier attempt may have renamed successfully then failed
            // while syncing its parent.
            #[cfg(unix)]
            fs::File::open(&self.root)?.sync_all()?;
            return Ok(());
        }
        crate::protected_content_runtime::write_owner_only_bytes(&path, &bytes)
    }

    /// Recheck the original bindings at the caller's clock before replying.
    /// Another endpoint receives the same outcome as an unknown session.
    pub fn replay(
        &self,
        owner: &PoolSessionSource,
        session: [u8; 16],
        now: u64,
    ) -> anyhow::Result<Option<SignedSealCompletedV1>> {
        if !authenticated_remote(owner) {
            return Ok(None);
        }
        let _guard = COMMIT_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("remote seal completion lock unavailable"))?;
        let Some(stored) = self.read(session)? else {
            return Ok(None);
        };
        if stored.owner != owner.endpoint_did {
            return Ok(None);
        }
        let request: SignedMintRequestV1 = decode(&stored.request)?;
        let descriptor: SignedPoolDescriptorAnyV1 = decode(&stored.descriptor)?;
        let attestation: SignedSealSessionAttestationV1 = decode(&stored.attestation)?;
        let completion: SignedSealCompletedV1 = decode(&stored.completion)?;
        let node = attestation.sealer_node_public_key();
        if attestation
            .verify_for_upload(&request, &descriptor, node, session, now)
            .is_err()
            || completion
                .verify_for_request_at(&descriptor, &request, node, now)
                .is_err()
        {
            return Ok(None);
        }
        #[cfg(unix)]
        fs::File::open(&self.root)?.sync_all()?;
        Ok(Some(completion))
    }

    /// Decode the finalize arguments after the custody service's Carrier
    /// admission and return the same data shape as a fresh completion.
    pub fn replay_finalize(
        &self,
        source: &PoolSessionSource,
        frame: &[u8],
        now: u64,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        anyhow::ensure!(frame.len() <= 128, "invalid seal finalize request size");
        let fields: RemoteSealSessionFieldsV1 = serde_json::from_slice(frame)?;
        let mut id = [0; 16];
        hex::decode_to_slice(&fields.seal_session_id, &mut id)?;
        anyhow::ensure!(
            id != [0; 16] && hex::encode(id) == fields.seal_session_id,
            "invalid seal session id"
        );
        self.replay(source, id, now)?
            .map(|completion| Ok(serde_json::json!({ "seal_completed": encode(&completion)? })))
            .transpose()
    }

    fn path(&self, session: [u8; 16]) -> PathBuf {
        self.root.join(format!("{}.json", hex::encode(session)))
    }

    fn read(&self, session: [u8; 16]) -> anyhow::Result<Option<StoredCompletion>> {
        match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(metadata) if metadata.is_dir() => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.uid() == nix::unistd::geteuid().as_raw()
                            && metadata.mode() & 0o777 == 0o700,
                        "unsafe remote seal completion directory permissions"
                    );
                }
            }
            Ok(_) => anyhow::bail!("invalid remote seal completion directory"),
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = match options.open(self.path(session)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() <= MAX_RECORD_BYTES,
            "invalid remote seal completion file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            anyhow::ensure!(
                metadata.uid() == nix::unistd::geteuid().as_raw()
                    && metadata.mode() & 0o777 == 0o600
                    && metadata.nlink() == 1,
                "unsafe remote seal completion file permissions"
            );
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "remote seal completion record exceeds its bound"
        );
        let stored: StoredCompletion = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            stored.schema == SCHEMA && stored.session == hex::encode(session),
            "invalid remote seal completion identity"
        );
        Ok(Some(stored))
    }
}

fn authenticated_remote(source: &PoolSessionSource) -> bool {
    !source.local
        && crate::carrier::did_to_public_key(&source.endpoint_did)
            .and_then(|key| crate::carrier::public_key_to_did(&key).ok())
            .is_some_and(|did| did == source.endpoint_did)
}

fn encode<T: CanonicalContract>(contract: &T) -> anyhow::Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(contract.canonical_bytes()?))
}

fn decode<T: CanonicalContract>(text: &str) -> anyhow::Result<T> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(text)?;
    Ok(T::from_canonical_bytes(&bytes)?)
}
