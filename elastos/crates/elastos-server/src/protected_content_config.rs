//! Offline operator provisioning for the protected-content installed
//! prerequisites: the policy authority key, per-host custody node state,
//! the signed owner-only 2-of-3 custody composition, and the private
//! Chain provider configuration.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use base64::Engine as _;
use clap::Subcommand;
use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_contracts::{
    CanonicalContract, CustodyApprovedSuitesV1, CustodyCommitteeAuthorizationStatementV1,
    CustodyEpochIssuerKeyV1, CustodyEpochStatementV1, CustodyNodeIdentityV1,
    CustodyPoolFailureDomainIdV1, CustodyPoolMemberStateV1, CustodyPoolMemberV1,
    CustodyPoolOperatorIdV1, CustodyPoolStatementV1, NodeCustodyPublicKeyV1, NodePublicKey,
    RuntimeOperationIssuerKeyV1, ShareCoordinateV1, SignedCustodyCommitteeAuthorizationV1,
    SignedCustodyEpochV1, SignedCustodyPoolV1, ThresholdV1, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use elastos_protected_content_provider_contracts::{
    parse_and_verify_provisioning_output, ProvisionedCustodyProviderPublicKeys,
    ProvisioningOutputError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::collaboration_config::{create_owner_only_file, read_owner_only_file, write_receipt};
use crate::custody_node_card::{encode_node_card, fingerprint};
use crate::protected_content_runtime::{
    decode_canonical_peer_did, inactive_custody_state_root, protected_content_root,
    runtime_custody_composition_config_path, validate_owner_only_directory,
    RuntimeCustodyCompositionConfigFile, RuntimeCustodyRouteBindingConfig,
    RuntimeCustodyRouteTransportConfig, CUSTODY_COMPOSITION_SCHEMA_V1,
};

const POLICY_AUTHORITY_KEY_RECEIPT_SCHEMA: &str =
    "elastos.protected-content.policy-authority-key-created/v1";
const CUSTODY_NODE_PROVISION_RECEIPT_SCHEMA: &str =
    "elastos.protected-content.custody-node-provisioned/v1";
pub(crate) const CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1: &str =
    "elastos.protected-content.custody-node-descriptor/v1";
const CUSTODY_COMPOSITION_RECEIPT_SCHEMA: &str =
    "elastos.protected-content.custody-composition-generated/v1";
const CUSTODY_COMPOSITION_VERIFIED_RECEIPT_SCHEMA: &str =
    "elastos.protected-content.custody-composition-verified/v1";
const RUNTIME_ISSUER_RECEIPT_SCHEMA: &str = "elastos.protected-content.runtime-issuer/v1";
const NODE_CARD_EXPORTED_RECEIPT_SCHEMA: &str =
    "elastos.protected-content.custody-node-card-exported/v1";
/// Mirrors the Runtime loader's byte cap for the composition file.
pub(crate) const MAX_CUSTODY_COMPOSITION_FILE_BYTES: usize = 64 * 1024;
const CUSTODY_OPERATOR_ID_DOMAIN: &str = "elastos.protected-content.custody-operator-id/v1";
const CUSTODY_FAILURE_DOMAIN_ID_DOMAIN: &str =
    "elastos.protected-content.custody-failure-domain-id/v1";
const MAX_CUSTODY_NODE_LABEL_BYTES: usize = 64;
pub(crate) const MAX_CUSTODY_NODE_DESCRIPTOR_BYTES: usize = 8 * 1024;
const CUSTODY_NODE_DESCRIPTOR_FILE: &str = "custody-node.descriptor.json";
const MAX_CUSTODY_PROVIDER_PROVISION_OUTPUT_BYTES: usize = 8 * 1024;
const CUSTODY_PROVIDER_PROVISION_TIMEOUT: Duration = Duration::from_secs(5);
/// The composition validators hard-code a 2-of-3 committee; the ceremony keeps
/// the threshold in one place so a future k-of-n only changes this pair.
pub(crate) const CUSTODY_THRESHOLD_REQUIRED: u8 = 2;
pub(crate) const CUSTODY_THRESHOLD_TOTAL: u8 = 3;
const CHAIN_CONFIG_RECEIPT_SCHEMA: &str =
    "elastos.protected-content.chain-provider-config-generated/v1";
/// Facts proven in the deployment review for Base (chain id 8453); see
/// docs/CHAIN_PROVIDER.md ("has_access_by_content_id") and docs/PROTECTED_CONTENT.md.
const PROVEN_BASE_AUTHORITY_GATEWAY: &str = "0x09dbe796f40eceffeaccf243c3d758c4c1d8d87d";
const PROVEN_HAS_ACCESS_SELECTOR: &str = "0x54d42821";
/// Evidence corroboration needs 2..=5 independent sources; documented as the
/// product contract in docs/PROTECTED_CONTENT.md and enforced again by the
/// chain-provider capsule at Init.
const MIN_EVIDENCE_RPC_SOURCES: usize = 2;
const MAX_EVIDENCE_RPC_SOURCES: usize = 5;

#[derive(Debug, Subcommand)]
pub enum ProtectedContentConfigCommand {
    /// Create a new dedicated 32-byte protected-content policy authority key.
    CreatePolicyAuthorityKey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Provision this host's custody provider state root and export its
    /// custody node descriptor for the composition ceremony.
    ProvisionCustodyNode {
        #[arg(long)]
        data_dir: PathBuf,
        /// Runtime operation issuer this custody node will trust (0x + 64 lowercase hex).
        #[arg(long)]
        trusted_runtime_issuer: String,
        /// Operator label for this node (distinct across the three nodes).
        #[arg(long)]
        operator: String,
        /// Failure-domain label for this node (distinct across the three nodes).
        #[arg(long)]
        failure_domain: String,
        /// Carrier peer DID route to this node; omit for the single local route.
        #[arg(long)]
        transport_peer_did: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export this custody node's card: the one line of text its operator
    /// hands to the pool owner.
    ExportNodeCard {
        #[arg(long)]
        descriptor: PathBuf,
        /// Carrier connect ticket that reaches this node.
        #[arg(long)]
        ticket: String,
        /// Provider targets this node hosts (comma-separated), e.g. custody,chain,ipfs.
        #[arg(long, value_delimiter = ',')]
        provides: Vec<String>,
        /// kubo libp2p PeerID of this node; required with ipfs.
        #[arg(long)]
        ipfs_peer_id: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Assemble and sign the owner-only 2-of-3 custody composition from three
    /// custody node descriptors, installing it into the Runtime data dir.
    GenerateCustodyComposition {
        #[arg(long)]
        authority_key: PathBuf,
        /// Custody node descriptor path; pass exactly three.
        #[arg(long = "node")]
        nodes: Vec<PathBuf>,
        #[arg(long)]
        data_dir: PathBuf,
        /// Days the pool members stay active from now.
        #[arg(long, default_value_t = 365)]
        valid_days: u16,
    },
    /// Purely verify the installed custody composition through the Runtime loader.
    VerifyCustodyComposition {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Print the Runtime operation issuer custody nodes must trust for this data dir.
    ShowRuntimeIssuer {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Install the private multi-source Chain provider configuration for the
    /// protected-content rights, mint, and market methods.
    GenerateChainConfig {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "base-mainnet")]
        id: String,
        #[arg(long, default_value = "Base")]
        display_name: String,
        #[arg(long, default_value_t = 8453)]
        chain_id: u64,
        #[arg(long, default_value = "ETH")]
        native_symbol: String,
        #[arg(long, default_value_t = true)]
        mainnet: bool,
        /// Primary JSON-RPC endpoint for transactions and reads.
        #[arg(long)]
        rpc_url: String,
        /// Independent evidence JSON-RPC endpoint (repeat 2..=5 times, distinct origins).
        #[arg(long = "evidence-rpc-url")]
        evidence_rpc_urls: Vec<String>,
        /// Rights gateway contract proven for this deployment.
        #[arg(long, default_value = PROVEN_BASE_AUTHORITY_GATEWAY)]
        rights_contract: String,
        /// has_access_by_content_id selector proven for this deployment.
        #[arg(long, default_value = PROVEN_HAS_ACCESS_SELECTOR)]
        rights_selector: String,
        #[arg(long, default_value = PROVEN_BASE_AUTHORITY_GATEWAY)]
        authority_gateway_contract: String,
        #[arg(long)]
        mint_ledger: String,
        #[arg(long)]
        mint_pay_token: String,
        #[arg(long)]
        mint_asset_created_emitter: String,
    },
}

#[derive(Serialize)]
struct PolicyAuthorityKeyReceipt {
    schema: &'static str,
    created: bool,
}

#[derive(Serialize)]
struct CustodyNodeProvisionReceipt {
    schema: &'static str,
    node_public_key_hex: String,
    descriptor_sha256: String,
    created: bool,
}

#[derive(Serialize)]
struct NodeCardExportedReceipt {
    schema: &'static str,
    fingerprint: String,
}

#[derive(Serialize)]
struct CustodyCompositionReceipt {
    schema: &'static str,
    node_public_key_hexes: Vec<String>,
    config_sha256: String,
    created: bool,
}

#[derive(Serialize)]
struct CustodyCompositionVerifiedReceipt {
    schema: &'static str,
    node_public_key_hexes: Vec<String>,
    config_sha256: String,
    verified: bool,
}

#[derive(Serialize)]
struct RuntimeIssuerReceipt {
    schema: &'static str,
    trusted_runtime_issuer: String,
}

#[derive(Serialize)]
struct ChainConfigReceipt {
    schema: &'static str,
    network_id: String,
    chain_id: u64,
    evidence_rpc_sources: usize,
    config_sha256: String,
    created: bool,
}

/// One custody node's public identity plus its operator-declared placement,
/// produced on the custody host and consumed by the composition ceremony.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyNodeDescriptorV1 {
    pub(crate) schema: String,
    pub(crate) node_public_key_hex: String,
    pub(crate) node_custody_public_key_hex: String,
    pub(crate) operator: String,
    pub(crate) failure_domain: String,
    pub(crate) transport: CustodyNodeDescriptorTransportV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CustodyNodeDescriptorTransportV1 {
    Local,
    CarrierPeerDid { peer_did: String },
}

pub async fn run_protected_content_config_command(
    command: ProtectedContentConfigCommand,
) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    run_protected_content_config_command_with_writer(command, &mut output).await
}

async fn run_protected_content_config_command_with_writer(
    command: ProtectedContentConfigCommand,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    match command {
        ProtectedContentConfigCommand::CreatePolicyAuthorityKey { key } => {
            create_policy_authority_key(&key)?;
            write_receipt(
                output,
                &PolicyAuthorityKeyReceipt {
                    schema: POLICY_AUTHORITY_KEY_RECEIPT_SCHEMA,
                    created: true,
                },
            )
        }
        ProtectedContentConfigCommand::ProvisionCustodyNode {
            data_dir,
            trusted_runtime_issuer,
            operator,
            failure_domain,
            transport_peer_did,
            output: output_path,
        } => {
            let provisioned = provision_custody_node(
                &data_dir,
                &trusted_runtime_issuer,
                &operator,
                &failure_domain,
                transport_peer_did.as_deref(),
            )
            .await?;
            // Only a Carrier route is ever dialed for its card; a local route
            // is this Home's own node and keeps no node card.
            if transport_peer_did.is_some() {
                store_custody_node_descriptor(&data_dir, &provisioned.descriptor_bytes)?;
            }
            create_owner_only_file(
                &output_path,
                &provisioned.descriptor_bytes,
                "custody node descriptor",
            )?;
            write_receipt(
                output,
                &CustodyNodeProvisionReceipt {
                    schema: CUSTODY_NODE_PROVISION_RECEIPT_SCHEMA,
                    node_public_key_hex: provisioned.node_public_key_hex,
                    descriptor_sha256: provisioned.descriptor_sha256,
                    created: true,
                },
            )
        }
        ProtectedContentConfigCommand::ExportNodeCard {
            descriptor,
            ticket,
            provides,
            ipfs_peer_id,
            output: output_path,
        } => {
            let node_bytes = read_owner_only_file(
                &descriptor,
                MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
                "custody node descriptor",
            )?;
            let card =
                encode_node_card(&node_bytes, &ticket, &provides, ipfs_peer_id.as_deref())
                    .map_err(|refusal| anyhow::anyhow!("node card refused: {}", refusal.code()))?;
            create_owner_only_file(&output_path, format!("{card}\n").as_bytes(), "node card")?;
            write_receipt(
                output,
                &NodeCardExportedReceipt {
                    schema: NODE_CARD_EXPORTED_RECEIPT_SCHEMA,
                    fingerprint: fingerprint(&node_bytes),
                },
            )
        }
        ProtectedContentConfigCommand::GenerateCustodyComposition {
            authority_key,
            nodes,
            data_dir,
            valid_days,
        } => {
            let descriptors = read_distinct_custody_node_descriptors(&nodes)?;
            let installed =
                install_custody_composition(&data_dir, &authority_key, descriptors, valid_days)?;
            write_receipt(
                output,
                &CustodyCompositionReceipt {
                    schema: CUSTODY_COMPOSITION_RECEIPT_SCHEMA,
                    node_public_key_hexes: installed.node_public_key_hexes,
                    config_sha256: installed.config_sha256,
                    created: true,
                },
            )
        }
        ProtectedContentConfigCommand::VerifyCustodyComposition { data_dir } => {
            let installed = verify_installed_custody_composition(&data_dir)?;
            write_receipt(
                output,
                &CustodyCompositionVerifiedReceipt {
                    schema: CUSTODY_COMPOSITION_VERIFIED_RECEIPT_SCHEMA,
                    node_public_key_hexes: installed.node_public_key_hexes,
                    config_sha256: installed.config_sha256,
                    verified: true,
                },
            )
        }
        ProtectedContentConfigCommand::ShowRuntimeIssuer { data_dir } => write_receipt(
            output,
            &RuntimeIssuerReceipt {
                schema: RUNTIME_ISSUER_RECEIPT_SCHEMA,
                trusted_runtime_issuer: runtime_issuer_hex(&data_dir)?,
            },
        ),
        ProtectedContentConfigCommand::GenerateChainConfig {
            data_dir,
            id,
            display_name,
            chain_id,
            native_symbol,
            mainnet,
            rpc_url,
            evidence_rpc_urls,
            rights_contract,
            rights_selector,
            authority_gateway_contract,
            mint_ledger,
            mint_pay_token,
            mint_asset_created_emitter,
        } => {
            let spec = ChainProviderConfigSpec {
                id,
                display_name,
                chain_id,
                native_symbol,
                mainnet,
                rpc_url,
                evidence_rpc_urls,
                rights_contract,
                rights_selector,
                authority_gateway_contract,
                mint_ledger,
                // The operator names one pay token; offering it alone keeps the
                // config this command wrote before pay tokens were a list.
                mint_pay_tokens: Vec::new(),
                mint_pay_token,
                mint_asset_created_emitter,
            };
            let config_bytes = install_chain_provider_config(&data_dir, &spec)?;
            write_receipt(
                output,
                &ChainConfigReceipt {
                    schema: CHAIN_CONFIG_RECEIPT_SCHEMA,
                    network_id: spec.id,
                    chain_id: spec.chain_id,
                    evidence_rpc_sources: spec.evidence_rpc_urls.len(),
                    config_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes))),
                    created: true,
                },
            )
        }
    }
}

/// A provisioned custody node's descriptor, exactly as the ceremony consumes it.
pub(crate) struct ProvisionedCustodyNode {
    pub(crate) descriptor_bytes: Vec<u8>,
    pub(crate) node_public_key_hex: String,
    pub(crate) descriptor_sha256: String,
}

/// The installed custody composition, as its receipts report it.
pub(crate) struct InstalledCustodyComposition {
    pub(crate) config_sha256: String,
    pub(crate) node_public_key_hexes: Vec<String>,
}

pub(crate) fn create_policy_authority_key(path: &Path) -> anyhow::Result<()> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .context("OS randomness unavailable for protected-content policy authority key")?;
    create_owner_only_file(path, &bytes, "protected-content policy authority key")
}

pub(crate) fn runtime_issuer_hex(data_dir: &Path) -> anyhow::Result<String> {
    let device_key_path = elastos_identity::device_key_path(data_dir);
    if std::fs::symlink_metadata(&device_key_path).is_err() {
        anyhow::bail!(
            "Runtime device key is missing at {}; start the Runtime on this data dir once, then retry",
            device_key_path.display()
        );
    }
    let device_key = elastos_identity::load_or_create_device_key(data_dir)?;
    let issuer =
        crate::protected_content_runtime::derive_protected_content_runtime_issuer(&device_key)?;
    Ok(format!("0x{}", hex::encode(issuer.as_bytes())))
}

/// Provision this host's custody provider state root and return its canonical
/// descriptor bytes; the caller decides where the descriptor goes.
pub(crate) async fn provision_custody_node(
    data_dir: &Path,
    trusted_runtime_issuer: &str,
    operator: &str,
    failure_domain: &str,
    transport_peer_did: Option<&str>,
) -> anyhow::Result<ProvisionedCustodyNode> {
    provision_custody_node_at(
        data_dir,
        custody_provider::CUSTODY_INACTIVE_ROOT_PATH,
        trusted_runtime_issuer,
        operator,
        failure_domain,
        transport_peer_did,
    )
    .await
}

/// Plan B T2.2: provision the custody root at `root_path` (`inactive` or
/// `pools/<hex>`) under the custody-provider folder.
pub(crate) async fn provision_custody_node_at(
    data_dir: &Path,
    root_path: &str,
    trusted_runtime_issuer: &str,
    operator: &str,
    failure_domain: &str,
    transport_peer_did: Option<&str>,
) -> anyhow::Result<ProvisionedCustodyNode> {
    let issuer = parse_runtime_issuer_hex(trusted_runtime_issuer)?;
    let operator = validated_custody_node_label(operator, "operator")?;
    let failure_domain = validated_custody_node_label(failure_domain, "failure domain")?;
    let transport = match transport_peer_did {
        None => CustodyNodeDescriptorTransportV1::Local,
        Some(peer_did) => CustodyNodeDescriptorTransportV1::CarrierPeerDid {
            peer_did: decode_canonical_peer_did(peer_did)?,
        },
    };
    let root = provisioned_custody_root(data_dir, root_path)
        .map_err(|_| anyhow::anyhow!("custody provider state root is unavailable or unsafe"))?;
    let provisioned =
        provision_custody_node_with_installed_provider(data_dir, &root, issuer).await?;
    let descriptor = CustodyNodeDescriptorV1 {
        schema: CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1.to_string(),
        node_public_key_hex: format!("0x{}", hex::encode(provisioned.node_public_key.as_bytes())),
        node_custody_public_key_hex: format!(
            "0x{}",
            hex::encode(provisioned.node_custody_public_key.as_bytes())
        ),
        operator,
        failure_domain,
        transport,
    };
    let descriptor_bytes = serde_json::to_vec(&serde_json::to_value(&descriptor)?)?;
    let descriptor_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&descriptor_bytes)));
    Ok(ProvisionedCustodyNode {
        descriptor_bytes,
        node_public_key_hex: descriptor.node_public_key_hex,
        descriptor_sha256,
    })
}

/// Where a provisioned custody node keeps its own descriptor, to answer its
/// pool owner's card request over Carrier: the `inactive` root's, at the
/// path Homes already use.
pub(crate) fn custody_node_descriptor_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(CUSTODY_NODE_DESCRIPTOR_FILE)
}

/// Plan B T2.2 (user decision 2026-11-12 10:35): one node descriptor file per
/// root. The `inactive` root keeps its existing path; a `pools/<hex>` root
/// keeps its file in its own folder, so stopping that root takes its file.
pub(crate) fn custody_node_descriptor_path_for(data_dir: &Path, root_path: &str) -> PathBuf {
    if root_path == custody_provider::CUSTODY_INACTIVE_ROOT_PATH {
        custody_node_descriptor_path(data_dir)
    } else {
        crate::protected_content_runtime::custody_root_dir(data_dir, root_path)
            .join(CUSTODY_NODE_DESCRIPTOR_FILE)
    }
}

/// Keep the descriptor of the `inactive` root's node.
pub(crate) fn store_custody_node_descriptor(
    data_dir: &Path,
    descriptor_bytes: &[u8],
) -> anyhow::Result<()> {
    store_custody_node_descriptor_at(
        data_dir,
        custody_provider::CUSTODY_INACTIVE_ROOT_PATH,
        descriptor_bytes,
    )
}

/// Keep the descriptor on the node. Provisioning again with the same labels
/// yields the same bytes; new labels would change the card an owner may
/// already hold for this node, so they are refused.
pub(crate) fn store_custody_node_descriptor_at(
    data_dir: &Path,
    root_path: &str,
    descriptor_bytes: &[u8],
) -> anyhow::Result<()> {
    let path = custody_node_descriptor_path_for(data_dir, root_path);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_owner_only_file(&path, descriptor_bytes, "custody node details")
        }
        Err(error) => Err(error).context("failed to inspect custody node details"),
        Ok(_) => {
            let stored = read_owner_only_file(
                &path,
                MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
                "custody node details",
            )?;
            if stored != descriptor_bytes {
                anyhow::bail!("custody node details already exist with different labels");
            }
            Ok(())
        }
    }
}

/// Sign the composition and install it create-only, then prove it through the
/// Runtime loader, removing the file if the loader refuses it.
pub(crate) fn install_custody_composition(
    data_dir: &Path,
    authority_key: &Path,
    descriptors: Vec<ValidatedCustodyNodeDescriptor>,
    valid_days: u16,
) -> anyhow::Result<InstalledCustodyComposition> {
    let authority = read_policy_authority_key(authority_key)?;
    let config = signed_custody_composition_config(&authority, descriptors, valid_days)?;
    let config_bytes = serde_json::to_vec(&serde_json::to_value(&config)?)?;

    validate_existing_data_dir(data_dir)?;
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    let config_path = runtime_custody_composition_config_path(data_dir);
    create_owner_only_file(&config_path, &config_bytes, "custody composition")?;

    // The Runtime loader is the single validation authority; prove the
    // installed file end to end before reporting success.
    if let Err(error) = crate::protected_content_runtime::load_runtime_custody_composition(
        data_dir,
        std::sync::Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
    ) {
        let _ = std::fs::remove_file(&config_path);
        return Err(error.context("generated custody composition failed loader validation"));
    }

    installed_custody_composition(&config, &config_bytes)
}

pub(crate) fn verify_installed_custody_composition(
    data_dir: &Path,
) -> anyhow::Result<InstalledCustodyComposition> {
    crate::protected_content_runtime::load_runtime_custody_composition(
        data_dir,
        std::sync::Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
    )?
    .context("custody composition is missing; generate and install it first")?;
    let config_bytes = read_owner_only_file(
        &runtime_custody_composition_config_path(data_dir),
        MAX_CUSTODY_COMPOSITION_FILE_BYTES,
        "custody composition",
    )?;
    let config: RuntimeCustodyCompositionConfigFile = serde_json::from_slice(&config_bytes)?;
    installed_custody_composition(&config, &config_bytes)
}

fn installed_custody_composition(
    config: &RuntimeCustodyCompositionConfigFile,
    config_bytes: &[u8],
) -> anyhow::Result<InstalledCustodyComposition> {
    Ok(InstalledCustodyComposition {
        config_sha256: format!("sha256:{}", hex::encode(Sha256::digest(config_bytes))),
        node_public_key_hexes: config
            .routes
            .iter()
            .map(|route| {
                Ok(format!(
                    "0x{}",
                    hex::encode(decode_standard_base64(&route.node_public_key_base64)?)
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    })
}

/// One pay token a creator may price a sale in, as the Chain provider reads it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChainProviderPayToken {
    symbol: &'static str,
    address: &'static str,
    decimals: u8,
}

/// Everything the private Chain provider configuration states for one network.
///
/// The operator command fills it from flags. `base_mainnet` is the proven Base
/// deployment, which a Home installs on its own when protected content is
/// enabled and no configuration exists yet: none of it is specific to a person
/// or a wallet, so nothing has to wait for one.
#[derive(Debug, Clone)]
pub(crate) struct ChainProviderConfigSpec {
    id: String,
    display_name: String,
    chain_id: u64,
    native_symbol: String,
    mainnet: bool,
    rpc_url: String,
    evidence_rpc_urls: Vec<String>,
    rights_contract: String,
    rights_selector: String,
    authority_gateway_contract: String,
    mint_ledger: String,
    mint_pay_token: String,
    mint_pay_tokens: Vec<ChainProviderPayToken>,
    mint_asset_created_emitter: String,
}

/// Facts of the proven Base deployment beyond the rights gateway above; see
/// docs/PROTECTED_CONTENT.md ("Identity and rights").
const BASE_MAINNET_RPC_URL: &str = "https://mainnet.base.org";
const BASE_MAINNET_EVIDENCE_RPC_URLS: [&str; 4] = [
    "https://base-rpc.publicnode.com",
    "https://base-mainnet.public.blastapi.io",
    "https://base.gateway.tenderly.co",
    "https://base.drpc.org",
];
const PROVEN_BASE_MINT_LEDGER: &str = "0x0ebac909d31ef0074495e752c0cf4ea49ba13c41";
const PROVEN_BASE_ASSET_CREATED_EMITTER: &str = "0x5a694a6d988354dca491fe0f6db7a6ef46b656c2";
const NATIVE_PAY_TOKEN: &str = "0x0000000000000000000000000000000000000000";
const BASE_MAINNET_USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

impl ChainProviderConfigSpec {
    pub(crate) fn base_mainnet() -> Self {
        Self {
            id: "base-mainnet".to_string(),
            display_name: "Base".to_string(),
            chain_id: 8453,
            native_symbol: "ETH".to_string(),
            mainnet: true,
            rpc_url: BASE_MAINNET_RPC_URL.to_string(),
            evidence_rpc_urls: BASE_MAINNET_EVIDENCE_RPC_URLS
                .iter()
                .map(|url| (*url).to_string())
                .collect(),
            rights_contract: PROVEN_BASE_AUTHORITY_GATEWAY.to_string(),
            rights_selector: PROVEN_HAS_ACCESS_SELECTOR.to_string(),
            authority_gateway_contract: PROVEN_BASE_AUTHORITY_GATEWAY.to_string(),
            mint_ledger: PROVEN_BASE_MINT_LEDGER.to_string(),
            mint_pay_token: NATIVE_PAY_TOKEN.to_string(),
            // The first is the default a creator is offered.
            mint_pay_tokens: vec![
                ChainProviderPayToken {
                    symbol: "USDC",
                    address: BASE_MAINNET_USDC,
                    decimals: 6,
                },
                ChainProviderPayToken {
                    symbol: "ETH",
                    address: NATIVE_PAY_TOKEN,
                    decimals: 18,
                },
            ],
            mint_asset_created_emitter: PROVEN_BASE_ASSET_CREATED_EMITTER.to_string(),
        }
    }

    /// The validated configuration file body.
    fn config_bytes(&self) -> anyhow::Result<Vec<u8>> {
        validate_private_rpc_url(&self.rpc_url, "rpc url")?;
        validate_evidence_rpc_urls(&self.evidence_rpc_urls)?;
        let rights_contract = validated_contract_address(&self.rights_contract, "rights contract")?;
        let authority_gateway_contract = validated_contract_address(
            &self.authority_gateway_contract,
            "authority gateway contract",
        )?;
        let mint_ledger = validated_contract_address(&self.mint_ledger, "mint ledger")?;
        let mint_pay_token = validated_contract_address(&self.mint_pay_token, "mint pay token")?;
        let mint_asset_created_emitter = validated_contract_address(
            &self.mint_asset_created_emitter,
            "mint asset-created emitter",
        )?;
        validated_selector(&self.rights_selector)?;
        for token in &self.mint_pay_tokens {
            validated_contract_address(token.address, "mint pay token")?;
        }

        let mut creator_mint = serde_json::json!({
            "ledger": mint_ledger,
            "pay_token": mint_pay_token,
            "asset_created_emitter": mint_asset_created_emitter,
            "abi": "elacity_mint_v1",
        });
        if !self.mint_pay_tokens.is_empty() {
            creator_mint["pay_tokens"] = serde_json::to_value(&self.mint_pay_tokens)?;
        }
        let network = serde_json::json!({
            "id": self.id,
            "display_name": self.display_name,
            "kind": "evm_json_rpc",
            "chain_id": self.chain_id,
            "native_symbol": self.native_symbol,
            "provider": "operator",
            "mainnet": self.mainnet,
            "explorer_url": null,
            "rpc_url": self.rpc_url,
            "rights_methods": [{
                "id": "has_access_by_content_id",
                "contract": rights_contract,
                "abi": "has_access_by_content_id_address_bytes16",
                "selector": self.rights_selector,
                "protected_content_policies": [{
                    "action": "view",
                    "evidence_rpc_urls": self.evidence_rpc_urls,
                }],
            }],
            "protected_content_creator_mint": creator_mint,
            "protected_content_market": {
                "authority_gateway_contract": authority_gateway_contract,
                "evidence_rpc_urls": self.evidence_rpc_urls,
            },
        });
        Ok(serde_json::to_vec(&serde_json::json!({
            "schema": crate::protected_content_runtime::PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1,
            "protected_content_network": network,
        }))?)
    }
}

/// Install `spec` as this data dir's owner-only Chain provider configuration.
///
/// Refuses to replace an existing file, and removes what it wrote unless the
/// Runtime loader accepts it. The chain-provider capsule re-validates the
/// network body at Init and stays the live admission authority.
pub(crate) fn install_chain_provider_config(
    data_dir: &Path,
    spec: &ChainProviderConfigSpec,
) -> anyhow::Result<Vec<u8>> {
    let config_bytes = spec.config_bytes()?;
    validate_existing_data_dir(data_dir)?;
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    let config_path = protected_content_root(data_dir).join("chain-provider.json");
    create_owner_only_file(
        &config_path,
        &config_bytes,
        "protected-content chain config",
    )?;
    if let Err(error) =
        crate::protected_content_runtime::load_runtime_protected_content_chain_provider_config(
            data_dir,
        )
    {
        let _ = std::fs::remove_file(&config_path);
        return Err(error.context("generated chain config failed loader validation"));
    }
    Ok(config_bytes)
}

/// Give a Home with protected content enabled the proven Base configuration
/// when it has none, so Creator and the market work without an operator step.
///
/// An existing file, valid or not, is the operator's and is left alone, and a
/// Home with protected content off gets nothing. Answers whether a file was
/// installed.
pub fn ensure_default_chain_provider_config(data_dir: &Path) -> anyhow::Result<bool> {
    if !crate::protected_content_runtime::protected_content_enabled(data_dir) {
        return Ok(false);
    }
    let config_path = protected_content_root(data_dir).join("chain-provider.json");
    match std::fs::symlink_metadata(&config_path) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(
                anyhow::Error::new(error).context("protected-content chain config is unavailable")
            )
        }
    }
    install_chain_provider_config(data_dir, &ChainProviderConfigSpec::base_mainnet())?;
    Ok(true)
}

/// Doc-backed shape rule for private chain endpoints (see the chain-provider
/// capsule's admission checks): https, or http against loopback only, and no
/// credentials in the URL.
fn validate_private_rpc_url(value: &str, label: &str) -> anyhow::Result<url::Url> {
    let parsed = url::Url::parse(value).with_context(|| format!("{label} is not a valid URL"))?;
    let loopback_http = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1") | Some("localhost"));
    if parsed.scheme() != "https" && !loopback_http {
        anyhow::bail!("{label} must use https (or http against 127.0.0.1/localhost)");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("{label} must not embed credentials");
    }
    Ok(parsed)
}

fn validate_evidence_rpc_urls(urls: &[String]) -> anyhow::Result<()> {
    if !(MIN_EVIDENCE_RPC_SOURCES..=MAX_EVIDENCE_RPC_SOURCES).contains(&urls.len()) {
        anyhow::bail!(
            "evidence corroboration requires {MIN_EVIDENCE_RPC_SOURCES}..={MAX_EVIDENCE_RPC_SOURCES} independent evidence RPC sources"
        );
    }
    let mut seen_urls = std::collections::BTreeSet::new();
    let mut seen_origins = std::collections::BTreeSet::new();
    for value in urls {
        let parsed = validate_private_rpc_url(value, "evidence rpc url")?;
        if !seen_urls.insert(parsed.to_string()) {
            anyhow::bail!("evidence RPC sources must be distinct URLs");
        }
        if !seen_origins.insert(parsed.origin().ascii_serialization()) {
            anyhow::bail!("evidence RPC sources must come from distinct origins");
        }
    }
    Ok(())
}

fn validated_contract_address(value: &str, label: &str) -> anyhow::Result<String> {
    let hex_part = value
        .strip_prefix("0x")
        .with_context(|| format!("{label} must start with 0x"))?;
    if hex_part.len() != 40 || !hex_part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{label} must be 0x plus 40 hex characters");
    }
    // Accept EIP-55 mixed-case input; store canonical lowercase so every
    // downstream comparison and serialized config sees one form.
    Ok(format!("0x{}", hex_part.to_ascii_lowercase()))
}

fn validated_selector(value: &str) -> anyhow::Result<()> {
    let hex_part = value
        .strip_prefix("0x")
        .context("selector must start with 0x")?;
    if hex_part.len() != 8
        || !hex_part
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        anyhow::bail!("selector must be 0x plus 8 lowercase hex characters");
    }
    Ok(())
}

pub(crate) struct ValidatedCustodyNodeDescriptor {
    pub(crate) node_public_key: NodePublicKey,
    pub(crate) custody_public_key: NodeCustodyPublicKeyV1,
    pub(crate) operator: String,
    pub(crate) failure_domain: String,
    pub(crate) transport: RuntimeCustodyRouteTransportConfig,
}

fn read_policy_authority_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = read_owner_only_file(path, 32, "protected-content policy authority key")?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("protected-content policy authority key must contain exactly 32 bytes")
    })?;
    Ok(SigningKey::from_bytes(&key))
}

/// The policy authority's signature over `message`, so callers sign the pool
/// descriptor (Plan B T3.3) without holding the secret.
pub(crate) fn policy_authority_signature(path: &Path, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(read_policy_authority_key(path)?
        .sign(message)
        .to_bytes()
        .to_vec())
}

/// The policy authority's public key, so callers can show the key without
/// holding the secret.
pub(crate) fn policy_authority_public_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    Ok(read_policy_authority_key(path)?.verifying_key().to_bytes())
}

fn read_distinct_custody_node_descriptors(
    paths: &[PathBuf],
) -> anyhow::Result<Vec<ValidatedCustodyNodeDescriptor>> {
    if paths.len() != usize::from(CUSTODY_THRESHOLD_TOTAL) {
        anyhow::bail!(
            "custody composition requires exactly {CUSTODY_THRESHOLD_TOTAL} --node descriptors"
        );
    }
    distinct_custody_node_descriptors(
        paths
            .iter()
            .map(|path| read_custody_node_descriptor(path))
            .collect::<anyhow::Result<Vec<_>>>()?,
    )
}

/// The committee rules every descriptor set must meet, in the canonical order
/// the signed composition uses.
pub(crate) fn distinct_custody_node_descriptors(
    mut descriptors: Vec<ValidatedCustodyNodeDescriptor>,
) -> anyhow::Result<Vec<ValidatedCustodyNodeDescriptor>> {
    if descriptors.len() != usize::from(CUSTODY_THRESHOLD_TOTAL) {
        anyhow::bail!(
            "custody composition requires exactly {CUSTODY_THRESHOLD_TOTAL} --node descriptors"
        );
    }
    require_distinct(
        descriptors
            .iter()
            .map(|d| d.node_public_key.as_bytes().to_vec()),
        "node public keys",
    )?;
    require_distinct(
        descriptors
            .iter()
            .map(|d| d.custody_public_key.as_bytes().to_vec()),
        "node custody public keys",
    )?;
    require_distinct(
        descriptors.iter().map(|d| d.operator.clone().into_bytes()),
        "operator labels",
    )?;
    require_distinct(
        descriptors
            .iter()
            .map(|d| d.failure_domain.clone().into_bytes()),
        "failure-domain labels",
    )?;
    let local_routes = descriptors
        .iter()
        .filter(|d| matches!(d.transport, RuntimeCustodyRouteTransportConfig::Local))
        .count();
    if local_routes > 1 {
        anyhow::bail!("custody composition allows at most one local transport route");
    }
    require_distinct(
        descriptors.iter().filter_map(|d| match &d.transport {
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } => {
                Some(peer_did.clone().into_bytes())
            }
            RuntimeCustodyRouteTransportConfig::Local => None,
        }),
        "carrier peer DIDs",
    )?;
    // The epoch statement orders nodes by node public key; keep every derived
    // artifact (members, routes) in that one canonical order.
    descriptors.sort_by(|a, b| {
        a.node_public_key
            .as_bytes()
            .cmp(b.node_public_key.as_bytes())
    });
    Ok(descriptors)
}

fn read_custody_node_descriptor(path: &Path) -> anyhow::Result<ValidatedCustodyNodeDescriptor> {
    let bytes = read_owner_only_file(
        path,
        MAX_CUSTODY_NODE_DESCRIPTOR_BYTES,
        "custody node descriptor",
    )?;
    validated_custody_node_descriptor(&bytes, &path.display().to_string())
}

/// Validate descriptor bytes from any carrier; `source` names where they came
/// from in errors.
pub(crate) fn validated_custody_node_descriptor(
    bytes: &[u8],
    source: &str,
) -> anyhow::Result<ValidatedCustodyNodeDescriptor> {
    if bytes.len() > MAX_CUSTODY_NODE_DESCRIPTOR_BYTES {
        anyhow::bail!("custody node descriptor at {source} exceeds its byte limit");
    }
    let descriptor: CustodyNodeDescriptorV1 = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid custody node descriptor at {source}"))?;
    if serde_json::to_vec(&serde_json::to_value(&descriptor)?)? != bytes {
        anyhow::bail!("custody node descriptor at {source} is not canonical JSON");
    }
    if descriptor.schema != CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1 {
        anyhow::bail!("custody node descriptor at {source} carries an unsupported schema");
    }
    let node_public_key = NodePublicKey::new(parse_prefixed_hex::<32>(
        &descriptor.node_public_key_hex,
        "node public key",
    )?)
    .map_err(|error| anyhow::anyhow!("custody node public key is invalid: {error:?}"))?;
    let custody_public_key = NodeCustodyPublicKeyV1::new(parse_prefixed_hex::<
        PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
    >(
        &descriptor.node_custody_public_key_hex,
        "node custody public key",
    )?)
    .map_err(|error| anyhow::anyhow!("custody node custody public key is invalid: {error:?}"))?;
    let operator = validated_custody_node_label(&descriptor.operator, "operator")?;
    let failure_domain =
        validated_custody_node_label(&descriptor.failure_domain, "failure domain")?;
    let transport = match descriptor.transport {
        CustodyNodeDescriptorTransportV1::Local => RuntimeCustodyRouteTransportConfig::Local,
        CustodyNodeDescriptorTransportV1::CarrierPeerDid { peer_did } => {
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: decode_canonical_peer_did(&peer_did)?,
            }
        }
    };
    Ok(ValidatedCustodyNodeDescriptor {
        node_public_key,
        custody_public_key,
        operator,
        failure_domain,
        transport,
    })
}

fn signed_custody_composition_config(
    authority: &SigningKey,
    descriptors: Vec<ValidatedCustodyNodeDescriptor>,
    valid_days: u16,
) -> anyhow::Result<RuntimeCustodyCompositionConfigFile> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let threshold = ThresholdV1::new(CUSTODY_THRESHOLD_REQUIRED, CUSTODY_THRESHOLD_TOTAL)
        .map_err(|error| anyhow::anyhow!("custody threshold is invalid: {error:?}"))?;
    signed_custody_composition_config_at(authority, descriptors, valid_days, threshold, now)
}

/// The signed composition for `descriptors` under `threshold`, active from a
/// minute before `now`. The epoch numbers shares in node public key order,
/// whatever the descriptors' order. Install uses the Runtime's threshold;
/// any other is for measuring compositions only.
pub(crate) fn signed_custody_composition_config_at(
    authority: &SigningKey,
    descriptors: Vec<ValidatedCustodyNodeDescriptor>,
    valid_days: u16,
    threshold: ThresholdV1,
    now: u64,
) -> anyhow::Result<RuntimeCustodyCompositionConfigFile> {
    let issuer = CustodyEpochIssuerKeyV1::new(authority.verifying_key().to_bytes())
        .map_err(|error| anyhow::anyhow!("policy authority key is invalid: {error:?}"))?;
    let suites = CustodyApprovedSuitesV1::new(
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    )
    .map_err(|error| anyhow::anyhow!("approved custody suites are invalid: {error:?}"))?;

    let node_identities = descriptors
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let coordinate = ShareCoordinateV1::new(u8::try_from(index + 1)?)
                .map_err(|error| anyhow::anyhow!("share coordinate is invalid: {error:?}"))?;
            CustodyNodeIdentityV1::new(
                descriptor.node_public_key,
                descriptor.custody_public_key,
                coordinate,
            )
            .map_err(|error| anyhow::anyhow!("custody node identity is invalid: {error:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let epoch_statement =
        CustodyEpochStatementV1::new(issuer, suites.clone(), threshold, node_identities)
            .map_err(|error| anyhow::anyhow!("custody epoch statement is invalid: {error:?}"))?;
    let signed_epoch = SignedCustodyEpochV1::new(
        epoch_statement.clone(),
        authority
            .sign(&epoch_statement.canonical_bytes().map_err(|error| {
                anyhow::anyhow!("custody epoch statement cannot be encoded: {error:?}")
            })?)
            .to_bytes()
            .to_vec(),
    )
    .map_err(|error| anyhow::anyhow!("signed custody epoch is invalid: {error:?}"))?;

    let active_window = (
        now.saturating_sub(60),
        now.checked_add(u64::from(valid_days) * 86_400)
            .context("custody validity window overflows")?,
    );
    let members = descriptors
        .iter()
        .map(|descriptor| {
            CustodyPoolMemberV1::new(
                descriptor.node_public_key,
                descriptor.custody_public_key,
                CustodyPoolOperatorIdV1::new(custody_label_id(
                    CUSTODY_OPERATOR_ID_DOMAIN,
                    &descriptor.operator,
                )),
                CustodyPoolFailureDomainIdV1::new(custody_label_id(
                    CUSTODY_FAILURE_DOMAIN_ID_DOMAIN,
                    &descriptor.failure_domain,
                )),
                suites.clone(),
                active_window,
                CustodyPoolMemberStateV1::Active,
            )
            .map_err(|error| anyhow::anyhow!("custody pool member is invalid: {error:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let pool_statement = CustodyPoolStatementV1::new(issuer, members)
        .map_err(|error| anyhow::anyhow!("custody pool statement is invalid: {error:?}"))?;
    let signed_pool = SignedCustodyPoolV1::new(
        pool_statement.clone(),
        authority
            .sign(&pool_statement.canonical_bytes().map_err(|error| {
                anyhow::anyhow!("custody pool statement cannot be encoded: {error:?}")
            })?)
            .to_bytes()
            .to_vec(),
    )
    .map_err(|error| anyhow::anyhow!("signed custody pool is invalid: {error:?}"))?;

    let authorization_statement = CustodyCommitteeAuthorizationStatementV1::new(
        issuer,
        signed_pool
            .pool_identity()
            .map_err(|error| anyhow::anyhow!("custody pool identity is invalid: {error:?}"))?,
        signed_epoch
            .epoch_identity()
            .map_err(|error| anyhow::anyhow!("custody epoch identity is invalid: {error:?}"))?,
    )
    .map_err(|error| {
        anyhow::anyhow!("custody committee authorization statement is invalid: {error:?}")
    })?;
    let signed_authorization = SignedCustodyCommitteeAuthorizationV1::new(
        authorization_statement.clone(),
        authority
            .sign(&authorization_statement.canonical_bytes().map_err(|error| {
                anyhow::anyhow!("committee authorization cannot be encoded: {error:?}")
            })?)
            .to_bytes()
            .to_vec(),
    )
    .map_err(|error| anyhow::anyhow!("signed committee authorization is invalid: {error:?}"))?;

    let routes = descriptors
        .iter()
        .map(|descriptor| {
            Ok(RuntimeCustodyRouteBindingConfig {
                node_public_key_base64: encode_standard_base64(
                    descriptor.node_public_key.as_bytes(),
                ),
                owner_state_root_base64: encode_standard_base64(&random_owner_state_root()?),
                transport: descriptor.transport.clone(),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(RuntimeCustodyCompositionConfigFile {
        schema: CUSTODY_COMPOSITION_SCHEMA_V1.to_string(),
        expected_policy_authority_base64: encode_standard_base64(
            &authority.verifying_key().to_bytes(),
        ),
        expected_committee_authorization_identity_base64: canonical_contract_base64(
            &signed_authorization
                .authorization_identity()
                .map_err(|error| {
                    anyhow::anyhow!("committee authorization identity is invalid: {error:?}")
                })?,
        )?,
        signed_pool_base64: canonical_contract_base64(&signed_pool)?,
        signed_epoch_base64: canonical_contract_base64(&signed_epoch)?,
        signed_committee_authorization_base64: canonical_contract_base64(&signed_authorization)?,
        routes,
    })
}

fn require_distinct(values: impl Iterator<Item = Vec<u8>>, label: &str) -> anyhow::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            anyhow::bail!("custody composition requires distinct {label} across nodes");
        }
    }
    Ok(())
}

fn custody_label_id(domain: &str, label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn random_owner_state_root() -> anyhow::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).context("OS randomness unavailable for owner state root")?;
    if bytes == [0u8; 32] {
        anyhow::bail!("owner state root randomness returned all zeroes");
    }
    Ok(bytes)
}

fn parse_prefixed_hex<const LEN: usize>(value: &str, label: &str) -> anyhow::Result<[u8; LEN]> {
    let hex_part = value
        .strip_prefix("0x")
        .with_context(|| format!("{label} must start with 0x"))?;
    if hex_part.len() != LEN * 2
        || !hex_part
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        anyhow::bail!(
            "{label} must be 0x plus {} lowercase hex characters",
            LEN * 2
        );
    }
    hex::decode(hex_part)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must encode {LEN} bytes"))
}

fn encode_standard_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_standard_base64(value: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("invalid base64 value")
}

fn canonical_contract_base64<T: CanonicalContract>(value: &T) -> anyhow::Result<String> {
    Ok(encode_standard_base64(&value.canonical_bytes().map_err(
        |error| anyhow::anyhow!("canonical contract encoding failed: {error:?}"),
    )?))
}

/// Create (if missing) and validate the owner-only directory chain that must
/// exist before the custody provider state root can be provisioned or
/// registered at boot.
/// The folder of the custody root `root_path`, with its parents made
/// owner-only. The `pools` folder is made with the first root of any kind: it
/// records that `inactive` was used, so `inactive` is never handed out again
/// (Plan B T2.2, user decision 2026-11-12 10:35).
fn provisioned_custody_root(data_dir: &Path, root_path: &str) -> anyhow::Result<PathBuf> {
    if !custody_provider::is_custody_root_path(root_path) {
        anyhow::bail!("custody root path is not a root");
    }
    validate_existing_data_dir(data_dir)?;
    let protected_root = protected_content_root(data_dir);
    ensure_owner_only_dir(&protected_root, "protected-content root")?;
    let inactive_root = inactive_custody_state_root(data_dir);
    let custody_dir = inactive_root
        .parent()
        .context("custody provider state root has no parent directory")?;
    ensure_owner_only_dir(custody_dir, "custody provider root")?;
    ensure_owner_only_dir(
        &custody_dir.join(custody_provider::CUSTODY_POOL_ROOTS_DIR),
        "custody pool roots",
    )?;
    Ok(custody_dir.join(root_path))
}

/// The Runtime enforces owner-only modes from `protected-content` down; the
/// data root itself only needs to be a real directory.
fn validate_existing_data_dir(data_dir: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(data_dir)
        .with_context(|| format!("data dir {} is unavailable", data_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("data dir {} must be a real directory", data_dir.display());
    }
    Ok(())
}

pub(crate) fn ensure_owner_only_dir(path: &Path, label: &str) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .with_context(|| format!("failed to create {label}"))?;
            }
            #[cfg(not(unix))]
            anyhow::bail!("{label} provisioning requires a Unix host");
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {label}"));
        }
        Ok(_) => {}
    }
    validate_owner_only_directory(path, label)
}

async fn provision_custody_node_with_installed_provider(
    data_dir: &Path,
    inactive_root: &Path,
    issuer: RuntimeOperationIssuerKeyV1,
) -> anyhow::Result<ProvisionedCustodyProviderPublicKeys> {
    let Some(binary) = crate::binaries::resolve_verified_native_provider_binary_with_data_dir(
        data_dir,
        "custody-provider",
    )
    .map_err(|_| anyhow::anyhow!("verified custody provider binary is unavailable"))?
    else {
        anyhow::bail!("verified custody provider binary is unavailable");
    };
    let issuer_hex = format!("0x{}", hex::encode(issuer.as_bytes()));
    let mut child = tokio::process::Command::new(binary)
        .arg("provision")
        .arg("--base-path")
        .arg(inactive_root)
        .arg("--trusted-runtime-issuer")
        .arg(&issuer_hex)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| anyhow::anyhow!("verified custody provider binary is unavailable"))?;
    let output_result = tokio::time::timeout(CUSTODY_PROVIDER_PROVISION_TIMEOUT, async {
        use tokio::io::AsyncReadExt as _;

        let Some(stdout_handle) = child.stdout.take() else {
            terminate_provision_child(&mut child).await;
            anyhow::bail!("custody provider state provisioning failed");
        };
        let mut stdout = Vec::new();
        if stdout_handle
            .take((MAX_CUSTODY_PROVIDER_PROVISION_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut stdout)
            .await
            .is_err()
        {
            terminate_provision_child(&mut child).await;
            anyhow::bail!("custody provider state provisioning failed");
        }
        if stdout.len() > MAX_CUSTODY_PROVIDER_PROVISION_OUTPUT_BYTES {
            terminate_provision_child(&mut child).await;
            anyhow::bail!("custody provider provisioning output is invalid");
        }
        let status = match child.wait().await {
            Ok(status) => status,
            Err(_) => {
                terminate_provision_child(&mut child).await;
                anyhow::bail!("custody provider state provisioning failed");
            }
        };
        Ok::<_, anyhow::Error>((stdout, status))
    })
    .await;
    let (stdout, status) = match output_result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            terminate_provision_child(&mut child).await;
            anyhow::bail!("custody provider state provisioning failed");
        }
    };
    if !status.success() {
        anyhow::bail!("custody provider state provisioning failed");
    }
    let value: serde_json::Value = serde_json::from_slice(&stdout)
        .map_err(|_| anyhow::anyhow!("custody provider provisioning output is invalid"))?;
    parse_and_verify_provisioning_output(&value, issuer).map_err(|error| match error {
        ProvisioningOutputError::InvalidOutput => {
            anyhow::anyhow!("custody provider provisioning output is invalid")
        }
        ProvisioningOutputError::InvalidReceipt => {
            anyhow::anyhow!("custody provider provisioning receipt is invalid")
        }
    })
}

async fn terminate_provision_child(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn parse_runtime_issuer_hex(value: &str) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    let hex_part = value
        .strip_prefix("0x")
        .context("trusted runtime issuer must start with 0x")?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        anyhow::bail!("trusted runtime issuer must be 0x plus 64 lowercase hex characters");
    }
    let bytes: [u8; 32] = hex::decode(hex_part)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("trusted runtime issuer must encode 32 bytes"))?;
    RuntimeOperationIssuerKeyV1::new(bytes)
        .map_err(|_| anyhow::anyhow!("trusted runtime issuer is not a valid operation issuer key"))
}

pub(crate) fn validated_custody_node_label(value: &str, label: &str) -> anyhow::Result<String> {
    if value.is_empty() || value.trim() != value || value.len() > MAX_CUSTODY_NODE_LABEL_BYTES {
        anyhow::bail!(
            "custody node {label} label must be 1..={MAX_CUSTODY_NODE_LABEL_BYTES} bytes without surrounding whitespace"
        );
    }
    Ok(value.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn contract_address_accepts_mixed_case_and_normalizes_to_lowercase() {
        let checksummed = "0x5a694A6d988354dca491fe0F6db7a6ef46b656c2";
        let normalized = validated_contract_address(checksummed, "mint pay token").unwrap();
        assert_eq!(normalized, "0x5a694a6d988354dca491fe0f6db7a6ef46b656c2");

        let lowercase = "0x0000000000000000000000000000000000000033";
        assert_eq!(
            validated_contract_address(lowercase, "mint pay token").unwrap(),
            lowercase
        );

        for bad in [
            "0x123",
            "5a694a6d988354dca491fe0f6db7a6ef46b656c2",
            "0x5a694a6d988354dca491fe0f6db7a6ef46b656gg",
        ] {
            assert!(
                validated_contract_address(bad, "mint pay token").is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn create_policy_authority_key_creates_owner_only_key_and_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("policy-authority.key");
        let mut out = Vec::new();

        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::CreatePolicyAuthorityKey {
                key: key_path.clone(),
            },
            &mut out,
        )
        .await
        .unwrap();

        let metadata = std::fs::symlink_metadata(&key_path).unwrap();
        assert_eq!(metadata.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.policy-authority-key-created/v1"
        );
        assert_eq!(receipt["created"], true);
    }

    #[cfg(unix)]
    pub(crate) fn owner_only_dir(path: &std::path::Path) {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }

    /// Custody provisioning validates every ancestor's owner and mode, and the
    /// std temp root is structurally unsafe on some hosts (see
    /// `safe_ancestor_tempdir` in the protected-content runtime tests); anchor
    /// fixtures under the build target dir instead.
    #[cfg(unix)]
    pub(crate) fn safe_ancestor_tempdir() -> tempfile::TempDir {
        let root = option_env!("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target")));
        let base = root.join("protected-content-config-test-fixtures");
        std::fs::create_dir_all(&base).unwrap();
        // Custody provisioning also rejects `..` path components, so hand it a
        // canonical base.
        tempfile::tempdir_in(base.canonicalize().unwrap()).unwrap()
    }

    #[cfg(unix)]
    fn test_runtime_issuer_hex() -> String {
        use elastos_runtime::signature::SigningKey;
        let key = SigningKey::from_bytes(&[0x42; 32]);
        format!("0x{}", hex::encode(key.verifying_key().to_bytes()))
    }

    #[cfg(unix)]
    fn current_platform() -> &'static str {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-amd64",
            ("linux", "aarch64") => "linux-arm64",
            ("macos", "aarch64") => "darwin-arm64",
            (os, arch) => panic!("unsupported test platform {os}-{arch}"),
        }
    }

    #[cfg(unix)]
    fn install_verified_custody_provider(data_dir: &Path, script: &[u8]) -> PathBuf {
        let bin_dir = data_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let binary = bin_dir.join("custody-provider");
        crate::test_support::write_from_child(&binary, script, 0o700);
        let checksum = format!("sha256:{}", hex::encode(Sha256::digest(script)));
        std::fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "external": {
                    "custody-provider": {
                        "install_path": "bin/custody-provider",
                        "provider_runtime": {
                            "role": "provider",
                            "substrate": "native",
                            "runtime_abi": "elastos.provider-stdio/v1",
                            "execution": "native-provider",
                            "provides": "custody",
                            "runtime_only": true
                        },
                        "platforms": {
                            current_platform(): {
                                "checksum": checksum,
                                "install_path": "bin/custody-provider"
                            }
                        }
                    }
                },
                "capsules": {},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();
        binary
    }

    #[cfg(unix)]
    fn provisioned_template(
        dir: &Path,
        issuer_hex: &str,
        seed: u8,
    ) -> (PathBuf, serde_json::Value) {
        use x_wing::kem::Decapsulator as _;
        use x_wing::KeyExport as _;

        let template_root = dir.join(format!("template-{seed}"));
        owner_only_dir(&template_root);
        let issuer = parse_runtime_issuer_hex(issuer_hex).unwrap();
        let node_signing_key = SigningKey::from_bytes(&[seed; 32]);
        let node_public_key =
            NodePublicKey::new(node_signing_key.verifying_key().to_bytes()).unwrap();
        let node_custody_secret = [seed ^ 0x11; x_wing::DECAPSULATION_KEY_SIZE];
        let node_custody_public_key = NodeCustodyPublicKeyV1::new(
            x_wing::DecapsulationKey::from(node_custody_secret)
                .encapsulation_key()
                .to_bytes()
                .into(),
        )
        .unwrap();
        let receipt = elastos_protected_content_provider_contracts::provisioning_receipt(
            issuer,
            node_public_key,
            node_custody_public_key,
        );
        let output = serde_json::json!({
            "status": "ok",
            "data": {
                "schema": elastos_protected_content_provider_contracts::CUSTODY_PROVIDER_PROVISIONING_RECEIPT_SCHEMA_V1,
                "provider": elastos_protected_content_provider_contracts::CUSTODY_PROVIDER_PROVISIONING_RECEIPT_PROVIDER_ID_V1,
                "node_public_key": format!("0x{}", hex::encode(node_public_key.as_bytes())),
                "node_custody_public_key": format!("0x{}", hex::encode(node_custody_public_key.as_bytes())),
                "receipt": format!("0x{}", hex::encode(receipt)),
            }
        });
        std::fs::write(
            template_root.join("trusted-runtime-issuer"),
            format!("0x{}\n", hex::encode(issuer.as_bytes())),
        )
        .unwrap();
        std::fs::write(
            template_root.join("node-signing-key"),
            format!("0x{}\n", hex::encode(node_signing_key.to_bytes())),
        )
        .unwrap();
        std::fs::write(
            template_root.join("node-custody-secret"),
            format!("0x{}\n", hex::encode(node_custody_secret)),
        )
        .unwrap();
        owner_only_dir(&template_root.join("data"));
        (template_root, output)
    }

    #[cfg(unix)]
    pub(crate) fn install_successful_provision_script(
        dir: &Path,
        data_dir: &Path,
        issuer_hex: &str,
        seed: u8,
    ) -> serde_json::Value {
        let (template_root, output) = provisioned_template(dir, issuer_hex, seed);
        let output_json = serde_json::to_string(&output).unwrap();
        let script = format!(
            "#!/bin/sh\nset -eu\nif [ \"$#\" -ne 5 ] || [ \"$1\" != \"provision\" ] || [ \"$2\" != \"--base-path\" ] || [ \"$4\" != \"--trusted-runtime-issuer\" ] || [ \"$5\" != \"{issuer_hex}\" ]; then\n  exit 73\nfi\nmkdir -p \"$3\"\ncp -R '{template_root}/.' \"$3/\"\nchmod 700 \"$3\" \"$3/data\"\nchmod 600 \"$3/trusted-runtime-issuer\" \"$3/node-signing-key\" \"$3/node-custody-secret\"\nprintf '%s\\n' '{output_json}'\n",
            template_root = template_root.display(),
        );
        install_verified_custody_provider(data_dir, script.as_bytes());
        output
    }

    #[cfg(unix)]
    async fn run_provision_custody_node_for_test(
        data_dir: PathBuf,
        output_path: PathBuf,
        trusted_runtime_issuer: String,
    ) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::ProvisionCustodyNode {
                data_dir,
                trusted_runtime_issuer,
                operator: "operator-a".to_string(),
                failure_domain: "failure-domain-a".to_string(),
                transport_peer_did: None,
                output: output_path,
            },
            &mut out,
        )
        .await?;
        Ok(out)
    }

    #[cfg(unix)]
    fn write_test_custody_node_descriptor(
        dir: &Path,
        index: usize,
        issuer_hex: &str,
        transport_peer_did: Option<String>,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        use x_wing::kem::Decapsulator as _;
        use x_wing::KeyExport as _;

        let _issuer = parse_runtime_issuer_hex(issuer_hex).unwrap();
        let node_signing_key = SigningKey::from_bytes(&[(index as u8) + 1; 32]);
        let node_public_key =
            NodePublicKey::new(node_signing_key.verifying_key().to_bytes()).unwrap();
        let node_custody_secret = [((index as u8) ^ 0x51) + 1; x_wing::DECAPSULATION_KEY_SIZE];
        let node_custody_public_key = NodeCustodyPublicKeyV1::new(
            x_wing::DecapsulationKey::from(node_custody_secret)
                .encapsulation_key()
                .to_bytes()
                .into(),
        )
        .unwrap();
        let descriptor_path = dir.join(format!("node-{index}.descriptor.json"));
        let descriptor = CustodyNodeDescriptorV1 {
            schema: CUSTODY_NODE_DESCRIPTOR_SCHEMA_V1.to_string(),
            node_public_key_hex: format!("0x{}", hex::encode(node_public_key.as_bytes())),
            node_custody_public_key_hex: format!(
                "0x{}",
                hex::encode(node_custody_public_key.as_bytes())
            ),
            operator: format!("operator-{index}"),
            failure_domain: format!("failure-domain-{index}"),
            transport: match transport_peer_did {
                None => CustodyNodeDescriptorTransportV1::Local,
                Some(peer_did) => CustodyNodeDescriptorTransportV1::CarrierPeerDid { peer_did },
            },
        };
        let descriptor_bytes =
            serde_json::to_vec(&serde_json::to_value(&descriptor).unwrap()).unwrap();
        std::fs::write(&descriptor_path, descriptor_bytes).unwrap();
        std::fs::set_permissions(&descriptor_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        descriptor_path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_provisions_inactive_root_and_writes_descriptor() {
        use std::os::unix::fs::PermissionsExt;

        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        let expected = install_successful_provision_script(
            dir.path(),
            &data_dir,
            &test_runtime_issuer_hex(),
            0x41,
        );
        let descriptor_path = dir.path().join("node-a.descriptor.json");
        let out = run_provision_custody_node_for_test(
            data_dir.clone(),
            descriptor_path.clone(),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap();

        let inactive_root = data_dir.join("protected-content/custody-provider/inactive");
        let metadata = std::fs::symlink_metadata(&inactive_root).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert!(inactive_root.join("trusted-runtime-issuer").is_file());
        assert!(inactive_root.join("node-signing-key").is_file());
        assert!(inactive_root.join("node-custody-secret").is_file());
        assert!(inactive_root.join("data").is_dir());

        let descriptor_bytes = std::fs::read(&descriptor_path).unwrap();
        let descriptor: serde_json::Value = serde_json::from_slice(&descriptor_bytes).unwrap();
        assert_eq!(
            descriptor["schema"],
            "elastos.protected-content.custody-node-descriptor/v1"
        );
        let node_public_key = descriptor["node_public_key_hex"].as_str().unwrap();
        assert_eq!(node_public_key.len(), 2 + 64);
        assert!(node_public_key.starts_with("0x"));
        let custody_public_key = descriptor["node_custody_public_key_hex"].as_str().unwrap();
        assert_eq!(custody_public_key.len(), 2 + 1216 * 2);
        assert_eq!(descriptor["operator"], "operator-a");
        assert_eq!(descriptor["failure_domain"], "failure-domain-a");
        assert_eq!(descriptor["transport"]["kind"], "local");
        assert_eq!(
            descriptor["node_public_key_hex"],
            expected["data"]["node_public_key"]
        );
        assert_eq!(
            descriptor["node_custody_public_key_hex"],
            expected["data"]["node_custody_public_key"]
        );

        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.custody-node-provisioned/v1"
        );
        assert_eq!(receipt["node_public_key_hex"], node_public_key);
        assert_eq!(receipt["created"], true);
    }

    /// The Runtime validates owner-only modes from `protected-content` down,
    /// not on the data root itself; a 0755 data dir must stay provisionable.
    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_accepts_a_group_readable_data_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        install_successful_provision_script(
            dir.path(),
            &data_dir,
            &test_runtime_issuer_hex(),
            0x42,
        );

        run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("node.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap();

        let protected_root = data_dir.join("protected-content");
        let metadata = std::fs::symlink_metadata(&protected_root).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_reprovision_keeps_the_same_node_identity() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        let issuer = test_runtime_issuer_hex();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x43);

        let first_out = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("first.descriptor.json"),
            issuer.clone(),
        )
        .await
        .unwrap();

        let second_out = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("second.descriptor.json"),
            issuer,
        )
        .await
        .unwrap();

        let first: serde_json::Value = serde_json::from_slice(&first_out).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&second_out).unwrap();
        assert_eq!(first["node_public_key_hex"], second["node_public_key_hex"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_stores_node_local_descriptor_and_refuses_relabel() {
        use std::os::unix::fs::PermissionsExt;

        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        let issuer = test_runtime_issuer_hex();
        install_successful_provision_script(dir.path(), &data_dir, &issuer, 0x44);
        let peer_did = test_peer_did(7);
        let provision_route = |operator: &str, output: &str, transport_peer_did: Option<String>| {
            ProtectedContentConfigCommand::ProvisionCustodyNode {
                data_dir: data_dir.clone(),
                trusted_runtime_issuer: issuer.clone(),
                operator: operator.to_string(),
                failure_domain: "failure-domain-a".to_string(),
                transport_peer_did,
                output: dir.path().join(output),
            }
        };
        let provision = |operator: &str, output: &str| {
            provision_route(operator, output, Some(peer_did.clone()))
        };
        let stored_path = custody_node_descriptor_path(&data_dir);

        // A local route is never dialed for its card, so it keeps none.
        run_protected_content_config_command_with_writer(
            provision_route("operator-a", "local.descriptor.json", None),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert!(dir.path().join("local.descriptor.json").exists());
        assert!(!stored_path.exists());

        run_protected_content_config_command_with_writer(
            provision("operator-a", "first.descriptor.json"),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            stored_path,
            data_dir.join("protected-content/custody-node.descriptor.json")
        );
        let stored = std::fs::read(&stored_path).unwrap();
        assert_eq!(
            stored,
            std::fs::read(dir.path().join("first.descriptor.json")).unwrap()
        );
        assert_eq!(
            std::fs::metadata(&stored_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // The same labels give the same bytes: provisioning again succeeds.
        run_protected_content_config_command_with_writer(
            provision("operator-a", "again.descriptor.json"),
            &mut Vec::new(),
        )
        .await
        .unwrap();

        // New labels would hand the owner a different card for the same node.
        let error = run_protected_content_config_command_with_writer(
            provision("operator-b", "relabel.descriptor.json"),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("custody node details already exist with different labels"),
            "{error:#}"
        );
        assert!(!dir.path().join("relabel.descriptor.json").exists());
        assert_eq!(std::fs::read(&stored_path).unwrap(), stored);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_rejects_missing_or_unverified_provider_binary() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        let missing_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("missing.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            missing_error.to_string(),
            "verified custody provider binary is unavailable"
        );
        assert!(!missing_error
            .to_string()
            .contains(&data_dir.display().to_string()));

        install_verified_custody_provider(&data_dir, b"#!/bin/sh\nexit 0\n");
        std::fs::write(data_dir.join("bin/custody-provider"), b"tampered").unwrap();

        let unverified_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("unverified.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            unverified_error.to_string(),
            "verified custody provider binary is unavailable"
        );
        assert!(!unverified_error
            .to_string()
            .contains(&data_dir.display().to_string()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_rejects_nonzero_exit_invalid_output_and_invalid_receipt() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        install_verified_custody_provider(&data_dir, b"#!/bin/sh\nexit 61\n");
        let exit_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("exit.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            exit_error.to_string(),
            "custody provider state provisioning failed"
        );

        install_verified_custody_provider(
            &data_dir,
            b"#!/bin/sh\nprintf '%s\\n' '{\"status\":\"ok\"}'\n",
        );
        let invalid_output_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("invalid-output.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            invalid_output_error.to_string(),
            "custody provider provisioning output is invalid"
        );

        let (_, mut wrong_receipt) =
            provisioned_template(dir.path(), &test_runtime_issuer_hex(), 0x44);
        wrong_receipt["data"]["receipt"] =
            serde_json::json!(format!("0x{}", hex::encode([0x66; 32])));
        let wrong_receipt_json = serde_json::to_string(&wrong_receipt).unwrap();
        let script = format!("#!/bin/sh\nprintf '%s\\n' '{wrong_receipt_json}'\n");
        install_verified_custody_provider(&data_dir, script.as_bytes());
        let invalid_receipt_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("invalid-receipt.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            invalid_receipt_error.to_string(),
            "custody provider provisioning receipt is invalid"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_rejects_oversized_output_and_kills_timed_out_provider() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        install_verified_custody_provider(
            &data_dir,
            b"#!/bin/sh\nawk 'BEGIN { printf \"{\\\"status\\\":\\\"ok\\\",\\\"data\\\":\\\"\"; for (i = 0; i < 9000; i++) printf \"a\"; printf \"\\\"}\" }'\n",
        );
        let oversized_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("oversized.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            oversized_error.to_string(),
            "custody provider provisioning output is invalid"
        );

        let pid_path = dir.path().join("timeout.pid");
        let timeout_script = format!(
            "#!/bin/sh\nprintf '%s' $$ > '{}'\nexec sleep 30\n",
            pid_path.display()
        );
        install_verified_custody_provider(&data_dir, timeout_script.as_bytes());
        let timeout_error = run_provision_custody_node_for_test(
            data_dir.clone(),
            dir.path().join("timeout.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            timeout_error.to_string(),
            "custody provider state provisioning failed"
        );
        let pid: i32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provision_custody_node_rejects_unsafe_data_dir_before_provider_start() {
        use std::os::unix::fs::symlink;

        let dir = safe_ancestor_tempdir();
        let real_data_dir = dir.path().join("real-data");
        owner_only_dir(&real_data_dir);
        let symlinked_data_dir = dir.path().join("data");
        symlink(&real_data_dir, &symlinked_data_dir).unwrap();

        let error = run_provision_custody_node_for_test(
            symlinked_data_dir,
            dir.path().join("unsafe.descriptor.json"),
            test_runtime_issuer_hex(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "custody provider state root is unavailable or unsafe"
        );
    }

    /// Provision three distinct custody hosts and return their descriptor paths.
    #[cfg(unix)]
    async fn provision_three_node_descriptors(
        dir: &std::path::Path,
        issuer_hex: &str,
        transports: [Option<String>; 3],
    ) -> Vec<PathBuf> {
        transports
            .into_iter()
            .enumerate()
            .map(|(index, transport_peer_did)| {
                write_test_custody_node_descriptor(dir, index, issuer_hex, transport_peer_did)
            })
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn validated_descriptor_from_bytes_matches_file_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path =
            write_test_custody_node_descriptor(dir.path(), 0, &test_runtime_issuer_hex(), None);
        let bytes = std::fs::read(&path).unwrap();

        let from_bytes = validated_custody_node_descriptor(&bytes, "test descriptor").unwrap();
        let from_file = read_custody_node_descriptor(&path).unwrap();
        assert_eq!(
            from_bytes.node_public_key.as_bytes(),
            from_file.node_public_key.as_bytes()
        );

        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let non_canonical = serde_json::to_vec_pretty(&value).unwrap();
        let error = validated_custody_node_descriptor(&non_canonical, "test descriptor")
            .err()
            .expect("non-canonical descriptor bytes must be refused");
        assert!(
            error.to_string().contains("not canonical JSON"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validated_descriptor_refuses_oversized_bytes() {
        let oversized = vec![b' '; MAX_CUSTODY_NODE_DESCRIPTOR_BYTES + 1];
        let error = validated_custody_node_descriptor(&oversized, "test descriptor")
            .err()
            .expect("oversized descriptor bytes must be refused");
        assert!(
            error.to_string().contains("exceeds its byte limit"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    fn test_peer_did(seed: u8) -> String {
        use elastos_runtime::signature::SigningKey;
        crate::crypto::encode_did_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key()).unwrap()
    }

    #[test]
    fn export_node_card_parses_the_custody_host_harness_arguments() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(subcommand)]
            command: ProtectedContentConfigCommand,
        }

        let cli = <Cli as clap::Parser>::try_parse_from([
            "protected-content-config",
            "export-node-card",
            "--descriptor",
            "shared/did.descriptor.json",
            "--ticket",
            "ticket",
            "--provides",
            "custody,chain,ipfs",
            "--ipfs-peer-id",
            "12D3KooW",
            "--output",
            "shared/did.node-card",
        ])
        .unwrap();
        let ProtectedContentConfigCommand::ExportNodeCard {
            provides,
            ipfs_peer_id,
            ..
        } = cli.command
        else {
            panic!("expected export-node-card");
        };
        assert_eq!(provides, ["custody", "chain", "ipfs"]);
        assert_eq!(ipfs_peer_id.as_deref(), Some("12D3KooW"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn export_node_card_writes_an_owner_only_card_and_receipt() {
        use elastos_runtime::signature::SigningKey;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let peer_did = test_peer_did(7);
        let descriptor = write_test_custody_node_descriptor(
            dir.path(),
            0,
            &test_runtime_issuer_hex(),
            Some(peer_did),
        );
        let device_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let ticket = data_encoding::BASE32_NOPAD
            .encode(
                &serde_json::to_vec(&serde_json::json!({
                    "topic": null,
                    "endpoints": [{
                        "id": hex::encode(device_key.to_bytes()),
                        "addrs": [{ "Ip": "127.0.0.1:14431" }],
                    }],
                }))
                .unwrap(),
            )
            .to_ascii_lowercase();
        let export =
            |provides: &[&str], output: PathBuf| ProtectedContentConfigCommand::ExportNodeCard {
                descriptor: descriptor.clone(),
                ticket: ticket.clone(),
                provides: provides.iter().map(|target| target.to_string()).collect(),
                ipfs_peer_id: None,
                output,
            };

        let card_path = dir.path().join("node.node-card");
        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            export(&["custody", "chain"], card_path.clone()),
            &mut out,
        )
        .await
        .unwrap();

        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.custody-node-card-exported/v1"
        );
        let mode = std::fs::metadata(&card_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let card = crate::custody_node_card::parse_node_card(
            &std::fs::read_to_string(&card_path).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["fingerprint"], card.fingerprint);
        assert_eq!(card.node_bytes, std::fs::read(&descriptor).unwrap());

        let error = run_protected_content_config_command_with_writer(
            export(&["custody", "chain"], card_path.clone()),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error}");

        let refused_path = dir.path().join("storage.node-card");
        let error = run_protected_content_config_command_with_writer(
            export(&["custody", "chain", "ipfs"], refused_path.clone()),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("storage_without_id"), "{error}");
        assert!(!refused_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generate_custody_composition_output_passes_the_runtime_loader() {
        use elastos_runtime::provider::ProviderRegistry;
        use std::sync::Arc;

        let dir = safe_ancestor_tempdir();
        let runtime_data_dir = dir.path().join("runtime/data");
        std::fs::create_dir_all(runtime_data_dir.parent().unwrap()).unwrap();
        owner_only_dir(&runtime_data_dir);

        let authority_key_path = dir.path().join("policy-authority.key");
        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::CreatePolicyAuthorityKey {
                key: authority_key_path.clone(),
            },
            &mut out,
        )
        .await
        .unwrap();

        let descriptors = provision_three_node_descriptors(
            dir.path(),
            &test_runtime_issuer_hex(),
            [None, Some(test_peer_did(0x51)), Some(test_peer_did(0x52))],
        )
        .await;

        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::GenerateCustodyComposition {
                authority_key: authority_key_path,
                nodes: descriptors,
                data_dir: runtime_data_dir.clone(),
                valid_days: 365,
            },
            &mut out,
        )
        .await
        .unwrap();

        // The loader's [_; 3] node array plus signature validation make this
        // the whole done-check: parse, canonical bytes, trust anchors, routes.
        crate::protected_content_runtime::load_runtime_custody_composition(
            &runtime_data_dir,
            Arc::new(ProviderRegistry::new()),
        )
        .unwrap()
        .expect("generated composition must load");

        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.custody-composition-generated/v1"
        );
        assert_eq!(receipt["created"], true);
        assert_eq!(
            receipt["node_public_key_hexes"].as_array().unwrap().len(),
            3
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generate_custody_composition_rejects_duplicate_operator_labels() {
        let dir = safe_ancestor_tempdir();
        let runtime_data_dir = dir.path().join("runtime/data");
        std::fs::create_dir_all(runtime_data_dir.parent().unwrap()).unwrap();
        owner_only_dir(&runtime_data_dir);

        let authority_key_path = dir.path().join("policy-authority.key");
        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::CreatePolicyAuthorityKey {
                key: authority_key_path.clone(),
            },
            &mut out,
        )
        .await
        .unwrap();

        let descriptors = provision_three_node_descriptors(
            dir.path(),
            &test_runtime_issuer_hex(),
            [None, Some(test_peer_did(0x51)), Some(test_peer_did(0x52))],
        )
        .await;
        // Rewrite the third descriptor with the first one's operator label.
        let mut third: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&descriptors[2]).unwrap()).unwrap();
        third["operator"] = serde_json::Value::String("operator-0".to_string());
        std::fs::write(&descriptors[2], serde_json::to_vec(&third).unwrap()).unwrap();

        let mut out = Vec::new();
        let error = run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::GenerateCustodyComposition {
                authority_key: authority_key_path,
                nodes: descriptors,
                data_dir: runtime_data_dir.clone(),
                valid_days: 365,
            },
            &mut out,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("distinct"), "{error}");
        assert!(!runtime_data_dir
            .join("protected-content/custody-composition.json")
            .exists());
    }

    #[cfg(unix)]
    async fn generate_test_composition(dir: &tempfile::TempDir) -> PathBuf {
        let runtime_data_dir = dir.path().join("runtime/data");
        std::fs::create_dir_all(runtime_data_dir.parent().unwrap()).unwrap();
        owner_only_dir(&runtime_data_dir);
        let authority_key_path = dir.path().join("policy-authority.key");
        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::CreatePolicyAuthorityKey {
                key: authority_key_path.clone(),
            },
            &mut out,
        )
        .await
        .unwrap();
        let descriptors = provision_three_node_descriptors(
            dir.path(),
            &test_runtime_issuer_hex(),
            [None, Some(test_peer_did(0x51)), Some(test_peer_did(0x52))],
        )
        .await;
        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::GenerateCustodyComposition {
                authority_key: authority_key_path,
                nodes: descriptors,
                data_dir: runtime_data_dir.clone(),
                valid_days: 365,
            },
            &mut out,
        )
        .await
        .unwrap();
        runtime_data_dir
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_custody_composition_reports_the_installed_composition() {
        let dir = safe_ancestor_tempdir();
        let runtime_data_dir = generate_test_composition(&dir).await;

        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::VerifyCustodyComposition {
                data_dir: runtime_data_dir,
            },
            &mut out,
        )
        .await
        .unwrap();

        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.custody-composition-verified/v1"
        );
        assert_eq!(receipt["verified"], true);
        assert_eq!(
            receipt["node_public_key_hexes"].as_array().unwrap().len(),
            3
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_custody_composition_fails_closed_when_the_composition_is_missing() {
        let dir = safe_ancestor_tempdir();
        let runtime_data_dir = dir.path().join("runtime/data");
        std::fs::create_dir_all(runtime_data_dir.parent().unwrap()).unwrap();
        owner_only_dir(&runtime_data_dir);

        let mut out = Vec::new();
        let error = run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::VerifyCustodyComposition {
                data_dir: runtime_data_dir,
            },
            &mut out,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("missing"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn show_runtime_issuer_prints_the_derived_issuer_for_an_existing_device_key() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        let device_key = elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let expected =
            crate::protected_content_runtime::derive_protected_content_runtime_issuer(&device_key)
                .unwrap();

        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::ShowRuntimeIssuer {
                data_dir: data_dir.clone(),
            },
            &mut out,
        )
        .await
        .unwrap();

        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.runtime-issuer/v1"
        );
        assert_eq!(
            receipt["trusted_runtime_issuer"],
            format!("0x{}", hex::encode(expected.as_bytes()))
        );
    }

    #[cfg(unix)]
    fn chain_config_command(
        data_dir: &std::path::Path,
        evidence_rpc_urls: Vec<String>,
    ) -> ProtectedContentConfigCommand {
        ProtectedContentConfigCommand::GenerateChainConfig {
            data_dir: data_dir.to_path_buf(),
            id: "base-mainnet".to_string(),
            display_name: "Base".to_string(),
            chain_id: 8453,
            native_symbol: "ETH".to_string(),
            mainnet: true,
            rpc_url: "https://private-primary.example.invalid".to_string(),
            evidence_rpc_urls,
            rights_contract: "0x09dbe796f40eceffeaccf243c3d758c4c1d8d87d".to_string(),
            rights_selector: "0x54d42821".to_string(),
            authority_gateway_contract: "0x09dbe796f40eceffeaccf243c3d758c4c1d8d87d".to_string(),
            mint_ledger: "0x0000000000000000000000000000000000000022".to_string(),
            mint_pay_token: "0x0000000000000000000000000000000000000033".to_string(),
            mint_asset_created_emitter: "0x0000000000000000000000000000000000000044".to_string(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generate_chain_config_installs_a_loadable_owner_only_config() {
        use std::os::unix::fs::PermissionsExt;

        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        let mut out = Vec::new();
        run_protected_content_config_command_with_writer(
            chain_config_command(
                &data_dir,
                vec![
                    "https://evidence-a.example.invalid".to_string(),
                    "https://evidence-b.example.invalid".to_string(),
                ],
            ),
            &mut out,
        )
        .await
        .unwrap();

        let loaded =
            crate::protected_content_runtime::load_runtime_protected_content_chain_provider_config(
                &data_dir,
            )
            .unwrap()
            .expect("generated chain config must load");
        let network = loaded.protected_content_network();
        assert_eq!(network["chain_id"], 8453);
        assert_eq!(network["rights_methods"][0]["selector"], "0x54d42821");
        assert_eq!(
            network["rights_methods"][0]["protected_content_policies"][0]["evidence_rpc_urls"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let path = data_dir.join("protected-content/chain-provider.json");
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            receipt["schema"],
            "elastos.protected-content.chain-provider-config-generated/v1"
        );
        assert_eq!(receipt["created"], true);
    }

    /// A fresh Home has no operator to run `generate-chain-config`, so Creator
    /// could not find a mint source and listed no channels. With protected
    /// content on, the Home installs the proven Base deployment itself.
    #[cfg(unix)]
    #[test]
    fn default_chain_config_installs_the_proven_base_deployment_once() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        std::fs::write(data_dir.join("config.toml"), "protected_content = true\n").unwrap();

        assert!(ensure_default_chain_provider_config(&data_dir).unwrap());

        let loaded =
            crate::protected_content_runtime::load_runtime_protected_content_chain_provider_config(
                &data_dir,
            )
            .unwrap()
            .expect("the default chain config must load");
        let network = loaded.protected_content_network();
        assert_eq!(network["chain_id"], 8453);
        let mint = &network["protected_content_creator_mint"];
        assert_eq!(mint["ledger"], PROVEN_BASE_MINT_LEDGER);
        assert_eq!(
            mint["asset_created_emitter"],
            PROVEN_BASE_ASSET_CREATED_EMITTER
        );
        assert_eq!(mint["pay_tokens"][0]["symbol"], "USDC");
        assert_eq!(mint["pay_tokens"][0]["decimals"], 6);
        assert_eq!(
            network["protected_content_market"]["evidence_rpc_urls"]
                .as_array()
                .unwrap()
                .len(),
            BASE_MAINNET_EVIDENCE_RPC_URLS.len()
        );

        // The installed file is the operator's from now on.
        let path = data_dir.join("protected-content/chain-provider.json");
        let installed = std::fs::read(&path).unwrap();
        assert!(!ensure_default_chain_provider_config(&data_dir).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), installed);
    }

    #[cfg(unix)]
    #[test]
    fn default_chain_config_leaves_a_home_with_protected_content_off_alone() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        assert!(!ensure_default_chain_provider_config(&data_dir).unwrap());
        assert!(!data_dir.join("protected-content").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generate_chain_config_rejects_a_single_evidence_source() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        let mut out = Vec::new();
        let error = run_protected_content_config_command_with_writer(
            chain_config_command(
                &data_dir,
                vec!["https://evidence-a.example.invalid".to_string()],
            ),
            &mut out,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("evidence"), "{error}");
        assert!(!data_dir
            .join("protected-content/chain-provider.json")
            .exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generate_chain_config_rejects_duplicate_evidence_origins() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        let mut out = Vec::new();
        let error = run_protected_content_config_command_with_writer(
            chain_config_command(
                &data_dir,
                vec![
                    "https://evidence-a.example.invalid/one".to_string(),
                    "https://evidence-a.example.invalid/two".to_string(),
                ],
            ),
            &mut out,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("origin"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn show_runtime_issuer_fails_closed_without_a_device_key() {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);

        let mut out = Vec::new();
        let error = run_protected_content_config_command_with_writer(
            ProtectedContentConfigCommand::ShowRuntimeIssuer { data_dir },
            &mut out,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("device key"), "{error}");
    }
}
