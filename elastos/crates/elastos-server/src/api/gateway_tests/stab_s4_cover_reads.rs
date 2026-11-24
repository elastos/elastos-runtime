//! STAB-REPRO S4 (red, no fix): Explore cards and the offer sheet on Home-7
//! show no cover for an item minted on Home-4.
//!
//! Live state (2026-11-17, mint 9672d187…, "1717998-uhd_3840_2160_25fps"):
//! the item's metadata folder `bafybeigvtuy…` names its cover as
//! `ipfs://QmQRymQv…`. Home-7's own store holds neither; Home-4 holds both;
//! pool members Home-5/6 hold the folder but not the cover. Every cover read
//! the Marketplace page makes is `GET /content/<cid>[/metadata.json]`.
//!
//! Two independent restrictions each keep the cover off Home-7:
//! 1. the gateway's `/content` route reads this Home's own store only
//!    (`fetch_file_inline` -> `local_only`), never a Carrier holder, so a
//!    folder or cover another Home holds is a 404 to this Home's own app --
//!    although the `/listing` route reads the very same folder from holders;
//! 2. a protected publication shares exactly {payload, listing, metadata
//!    folder} with any peer (`ProtectedListingArtifacts`), so the creator's
//!    Home refuses the cover itself to every other Home ("this Home does not
//!    share this content").

use super::*;

/// The live item's CIDs.
const SEALED_CID: &str = "bafybeidcjypaytlw5c6265hxjqphnua5glqnzk743asslaph3vmybdznrq";
const FOLDER_CID: &str = "bafybeigvtuy27jmb57vy6xx2r7f2dvyflumi62yvnb7jjnn6vgjclqal6m";
const LISTING_CID: &str = "bafybeigvnnulsmbnexrvyspkzpem6qjcgsbu4zjkefisghju6vuo7c7rs4";
const COVER_CID: &str = "QmQRymQvJvzZQmsWurAjabCFENe44BsRneqtrUnxd9hUhM";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR cover bytes";

fn metadata_json() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "name": "1717998-uhd_3840_2160_25fps",
        "image": format!("ipfs://{COVER_CID}"),
        "kid": "0x06f43ec34034dfdc313f283181a8edb0",
    }))
    .unwrap()
}

/// The content plane of a Home that holds nothing of the item, beside a
/// Carrier holder that serves it: a `local_only` read misses, any other read
/// reaches the holder and answers the bytes.
#[derive(Default)]
struct HolderServesContent {
    requests: std::sync::Mutex<Vec<Value>>,
    local_metadata: bool,
}

impl HolderServesContent {
    fn file(cid: &str, path: &str) -> Option<Vec<u8>> {
        match (cid, path) {
            (COVER_CID, "") => Some(PNG.to_vec()),
            (FOLDER_CID, "metadata.json") => Some(metadata_json()),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl Provider for HolderServesContent {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw requests only".into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["content"]
    }

    fn name(&self) -> &'static str {
        "stab-s4-holder-content"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        if request.get("op").and_then(Value::as_str) == Some("pin_status") {
            return Ok(json!({ "status": "ok", "data": { "pinned": true } }));
        }
        let cid = request["cid"].as_str().unwrap_or_default();
        let path = request["path"].as_str().unwrap_or_default();
        if request.get("local_only") == Some(&Value::Bool(true))
            && !(self.local_metadata && cid == FOLDER_CID && path == "metadata.json")
        {
            return Ok(json!({
                "status": "error",
                "code": "not_found",
                "message": "content fetch failed: block not found locally",
            }));
        }
        Ok(match Self::file(cid, path) {
            Some(bytes) => json!({
                "status": "ok",
                "data": { "data": base64::engine::general_purpose::STANDARD.encode(bytes) }
            }),
            None => json!({ "status": "error", "code": "not_found", "message": "not_found" }),
        })
    }
}

struct ReaderHome {
    _dir: tempfile::TempDir,
    app: axum::Router,
    token: String,
    content: Arc<HolderServesContent>,
}

/// Home-7: the Marketplace app signed in, its own store empty of the item.
async fn reader_home() -> ReaderHome {
    let dir = tempfile::tempdir().unwrap();
    seed_test_browser_capsules(dir.path());
    let content = Arc::new(HolderServesContent::default());
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", content.clone())
        .await
        .unwrap();
    let state = GatewayState {
        provider_registry: Some(registry),
        collaboration_chat_product_port: None,
        collaboration_presence_product_port: None,
        carrier_endpoint: None,
        collaboration_discovery_service: None,
        browser_internet: Default::default(),
        identity_manager: Arc::new(std::sync::OnceLock::new()),
        cache_dir: dir.path().to_path_buf(),
        data_dir: dir.path().to_path_buf(),
    };
    let authority = passkey_authority_with_profile(dir.path(), "reader");
    let token = app_token_for_authority(dir.path(), MARKETPLACE_CAPSULE_ID, &authority);
    ReaderHome {
        _dir: dir,
        app: gateway_router(state),
        token,
        content,
    }
}

impl ReaderHome {
    /// What `src/content-reads.js` asks: the route with the app's token.
    async fn read(&self, route: &str) -> (StatusCode, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .uri(route)
                    .header("x-elastos-home-token", &self.token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    }

    fn assert_local_then_known_holders(&self, cid: &str, path: Option<&str>) {
        let requests = self.content.requests.lock().unwrap();
        let reads: Vec<_> = requests
            .iter()
            .filter(|request| request["op"] == "fetch")
            .collect();
        let [local, holder] = reads.as_slice() else {
            panic!("expected one local fetch and one holder fetch, got {reads:?}");
        };
        assert_eq!(local["cid"], cid);
        assert_eq!(holder["cid"], cid);
        assert_eq!(local["path"].as_str(), path);
        assert_eq!(holder["path"].as_str(), path);
        assert_eq!(local["local_only"], true);
        assert_eq!(local["whole_max_bytes"], MAX_GATEWAY_FILE_SIZE);
        assert_eq!(holder["known_holders_only"], true);
        assert_eq!(holder["range"], json!({"start": 0, "end": 4 * 1024 * 1024}));
    }
}

/// The offer sheet's (and a card's) cover read: `GET /content/<cover>`.
#[tokio::test]
async fn stab_s4_content_route_reads_a_cover_that_a_carrier_holder_serves() {
    let home = reader_home().await;
    let (status, bytes) = home.read(&format!("/content/{COVER_CID}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a cover another Home serves must reach this Home's own Marketplace app; \
         the /content route asked only this Home's store (local_only) and answered {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    home.assert_local_then_known_holders(COVER_CID, None);
    assert_eq!(bytes, PNG);
}

/// An Explore card learns its cover from the item's `metadata.json`, read as
/// `GET /content/<folder>/metadata.json` -- the same folder the `/listing`
/// route already reads from holders.
#[tokio::test]
async fn stab_s4_content_route_reads_the_metadata_document_that_a_carrier_holder_serves() {
    let home = reader_home().await;
    let (status, bytes) = home
        .read(&format!("/content/{FOLDER_CID}/metadata.json"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an Explore card's metadata document another Home serves must reach this Home's \
         own Marketplace app; /content asked only this Home's store and answered {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    home.assert_local_then_known_holders(FOLDER_CID, Some("metadata.json"));
    assert_eq!(bytes, metadata_json());
}

/// Home-4's side: the creator's Home serves a protected item's payload,
/// listing and metadata folder to any peer, but refuses the cover the
/// folder's `metadata.json` names -- so no other Home can fetch it from the
/// creator even when it asks.
#[cfg(unix)]
#[tokio::test]
async fn stab_s4_protected_publication_serves_its_cover_to_any_peer() {
    let dir = tempfile::tempdir().unwrap();
    let authority = passkey_authority_with_profile(dir.path(), "creator");
    let principal = authority.principal_id.as_str();
    let mint_id = elastos_protected_content_contracts::Digest32::new([0x96; 32]);
    crate::protected_content_runtime::tests::persist_creator_listing_for_test(
        dir.path(),
        principal,
        mint_id,
        SEALED_CID,
        FOLDER_CID,
        LISTING_CID,
    );
    // The protected publication record the mint writes (as on Home-4).
    let root = crate::auth::principal_localhost_root(principal);
    let object_uri = format!("{root}/Videos/1717998-uhd_3840_2160_25fps.mp4");
    let record_uri = format!(
        "{root}/.AppData/LocalHost/.Runtime/Library/Published/{}.json",
        hex::encode(Sha256::digest(object_uri.as_bytes()))
    );
    let record_path =
        elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &record_uri).unwrap();
    std::fs::create_dir_all(record_path.parent().unwrap()).unwrap();
    let record = json!({
        "schema": "elastos.library.publish-record/v1",
        "object_uri": object_uri,
        "cid": SEALED_CID,
        "published_at": 1,
        "content_security": {
            "published_payload": "runtime_custody_encrypted",
            "mint_id": hex::encode(mint_id.as_bytes()),
        },
        "receipt": {},
        "availability": { "status": "local_pinned" },
        "listing_uri": format!("elastos://{LISTING_CID}"),
    });
    crate::auth::write_principal_root_object(
        dir.path(),
        principal,
        &root,
        &record_uri,
        &record_path,
        &serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    crate::library::reconcile_published_cids(dir.path());

    let registry = ProviderRegistry::new();
    let content = Arc::new(HolderServesContent {
        local_metadata: true,
        ..Default::default()
    });
    registry
        .register_sub_provider("content", content.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("ipfs", content.clone())
        .await
        .unwrap();
    let stranger = iroh::PublicKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&[0x57; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let any_peer_reads = |cid: &'static str| {
        let (registry, dir) = (&registry, dir.path());
        async move {
            crate::carrier::admit_carrier_peer_content_fetch(
                crate::carrier::CarrierPeerContentFetch {
                    registry,
                    data_dir: dir,
                    network: None,
                    source: &stranger,
                    request: &json!({ "cid": cid }),
                    count_read: true,
                },
            )
            .await
        }
    };

    // Precondition: the live artifact set, as Home-4's published-cids.json
    // lists it for this mint.
    for cid in [SEALED_CID, LISTING_CID, FOLDER_CID] {
        assert!(
            any_peer_reads(cid).await.is_ok(),
            "precondition: {cid} is served"
        );
    }
    let cover = any_peer_reads(COVER_CID).await;
    assert!(
        cover.is_ok(),
        "the cover a protected item's metadata.json names must be served to any peer, \
         like the folder that names it; refused: {cover:?}"
    );
}
