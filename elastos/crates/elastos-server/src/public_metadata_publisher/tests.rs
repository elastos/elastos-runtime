//! Publisher tests: roots, phase order and the failure codes against fake
//! `ipfs` and `public-ipfs` providers on the real registry, a withdrawal
//! racing an awaited provide, and a Kubo that dies between phases.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;

use base64::Engine as _;
use elastos_runtime::provider::{Provider, ProviderError, ResourceRequest, ResourceResponse};

use super::*;
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::public_ipfs_store::tests::{record_consent, FakeBridge, FakeStore};
use crate::public_ipfs_store::{complete_withdrawal, StopOutcome, PUBLIC_IPFS_TARGET};
use crate::public_metadata_car::test_car_builder::{
    car, dag_pb_block_v0, dag_pb_block_v1, raw_block, unixfs, Block, Link,
};
use crate::public_metadata_consent::{
    acquire_public_state_lock, create_withdrawal_marker, read_consent, read_withdrawal_marker,
    ConsentState, STATE_LOCK_BUDGET,
};

const UNIXFS_DIRECTORY: u64 = 1;
const UNIXFS_FILE: u64 = 2;

// ── Fixtures ────────────────────────────────────────────────────────

struct Home {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    registry: Arc<ProviderRegistry>,
}

async fn home() -> Home {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    owner_only_dir(&data_dir);
    // A5: these tests run on a Home that offers sharing.
    crate::public_metadata_consent::tests::open_public_metadata_gate(&data_dir);
    record_consent(&data_dir, ConsentState::Enabled).await;
    Home {
        _dir: dir,
        data_dir,
        registry: Arc::new(ProviderRegistry::new()),
    }
}

/// One mint's public roots as the private store holds them: a CIDv1 folder
/// of raw leaves whose `metadata.json` names the cover and, as a string, the
/// protected content; a CIDv0 single-block cover; and the content itself.
struct MintRoots {
    roots: PublishRoots,
    cars: HashMap<String, Vec<u8>>,
    content: String,
}

fn mint_roots(with_cover: bool) -> MintRoots {
    let content = raw_block(b"ciphertext that must stay private");
    let cover = dag_pb_block_v0(&[], Some(&unixfs(UNIXFS_FILE, Some(b"cover image bytes"))));
    let image = if with_cover {
        format!("ipfs://{}", cover.0)
    } else {
        String::new()
    };
    let metadata = json!({
        "name": "public mint",
        "image": image,
        "media": {"uri": format!("ipfs://{}", content.0)},
    })
    .to_string();
    let (folder, blocks) = folder(&[
        ("metadata.json", metadata.as_bytes()),
        ("content.json", br#"{"c":1}"#),
    ]);
    let mut cars = HashMap::from([(folder.to_string(), car(&[folder], &blocks))]);
    cars.insert(
        content.0.to_string(),
        car(&[content.0], std::slice::from_ref(&content)),
    );
    let cover_root = with_cover.then(|| {
        cars.insert(
            cover.0.to_string(),
            car(&[cover.0], std::slice::from_ref(&cover)),
        );
        cover.0.to_string()
    });
    let roots = public_metadata_roots(&folder.to_string(), metadata.as_bytes()).unwrap();
    assert_eq!(roots.cover, cover_root);
    MintRoots {
        roots,
        cars,
        content: content.0.to_string(),
    }
}

pub(crate) fn folder(entries: &[(&str, &[u8])]) -> (cid::Cid, Vec<Block>) {
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

/// The private store: exports the CAR it holds for a root, and records every
/// export it is asked for.
#[derive(Default)]
pub(crate) struct FakePrivateIpfs {
    pub(crate) cars: StdMutex<HashMap<String, Vec<u8>>>,
    pub(crate) exports: StdMutex<Vec<String>>,
    /// Runs while an export is answered (the A5 gate-closure tests).
    pub(crate) on_export: StdMutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[async_trait::async_trait]
impl Provider for FakePrivateIpfs {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "fake private ipfs is raw only".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![]
    }

    fn name(&self) -> &'static str {
        "public-metadata-fake-private-ipfs"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        if request["op"] != "runtime_export_car" {
            return Err(ProviderError::Provider("unsupported".into()));
        }
        let cid = request["cid"].as_str().unwrap_or_default().to_string();
        self.exports.lock().unwrap().push(cid.clone());
        let hook = self.on_export.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook();
        }
        Ok(match self.cars.lock().unwrap().get(&cid) {
            Some(car) => json!({"status":"ok","data":{
                "car_base64": base64::engine::general_purpose::STANDARD.encode(car)}}),
            None => json!({"status":"error","code":"not_found","message":"not here"}),
        })
    }
}

/// The public store: records `(op, cid)` for every op, answers each op with
/// a scripted refusal when one is set, and stands for a Kubo that can die.
pub(crate) struct FakePublicIpfs {
    pub(crate) calls: StdMutex<Vec<(String, String)>>,
    pub(crate) refusals: StdMutex<HashMap<String, Value>>,
    pub(crate) alive: AtomicBool,
    /// Kubo dies when this op arrives, before answering it.
    pub(crate) dies_at: StdMutex<Option<String>>,
}

impl FakePublicIpfs {
    pub(crate) fn new() -> Self {
        Self {
            calls: StdMutex::new(Vec::new()),
            refusals: StdMutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            dies_at: StdMutex::new(None),
        }
    }

    pub(crate) fn refuse(&self, op: &str, code: &str) {
        self.refusals.lock().unwrap().insert(
            op.into(),
            json!({"status":"error","code":code,"message":format!("scripted {code}")}),
        );
    }

    /// The publication ops, in order, without status and peers reads.
    pub(crate) fn publication(&self) -> Vec<(String, String)> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(op, _)| op.starts_with("runtime_public_") && op != "runtime_public_peers")
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl Provider for FakePublicIpfs {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "fake public ipfs is raw only".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![]
    }

    fn name(&self) -> &'static str {
        "public-metadata-fake-public-ipfs"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let op = request["op"].as_str().unwrap_or_default().to_string();
        let cid = request["cid"]
            .as_str()
            .or(request["root"].as_str())
            .unwrap_or_default()
            .to_string();
        self.calls.lock().unwrap().push((op.clone(), cid));
        if self.dies_at.lock().unwrap().as_deref() == Some(op.as_str()) {
            self.alive.store(false, Ordering::SeqCst);
        }
        let alive = self.alive.load(Ordering::SeqCst);
        Ok(match op.as_str() {
            "ensure_started" => {
                self.alive.store(true, Ordering::SeqCst);
                *self.dies_at.lock().unwrap() = None;
                json!({"status":"ok","data":{"state":"ready"}})
            }
            "status" if alive => json!({"status":"ok","data":{
                "state":"ready","api_endpoint":"http://127.0.0.1:5001"}}),
            "status" => json!({"status":"ok","data":{"state":"cold","api_endpoint":null}}),
            _ if !alive => json!({"status":"error","code":"not_ready","message":"kubo is gone"}),
            "runtime_public_peers" => json!({"status":"ok","data":{"peers":2}}),
            op => self
                .refusals
                .lock()
                .unwrap()
                .get(op)
                .cloned()
                .unwrap_or_else(|| json!({"status":"ok","data":{}})),
        })
    }
}

async fn register_stores(
    home: &Home,
    mint: &MintRoots,
) -> (Arc<FakePrivateIpfs>, Arc<FakePublicIpfs>) {
    let private = Arc::new(FakePrivateIpfs::default());
    *private.cars.lock().unwrap() = mint.cars.clone();
    home.registry
        .register_sub_provider("ipfs", private.clone())
        .await
        .unwrap();
    let public = Arc::new(FakePublicIpfs::new());
    home.registry
        .register_runtime_provider_target(PUBLIC_IPFS_TARGET, public.clone())
        .await
        .unwrap();
    (private, public)
}

fn calls(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(op, cid)| (op.to_string(), cid.to_string()))
        .collect()
}

/// A cover as the private store adds a small one: one CIDv0 dag-pb UnixFS
/// file block, and its CAR.
pub(crate) fn cover_car(bytes: &[u8]) -> (String, Vec<u8>) {
    let block = dag_pb_block_v0(&[], Some(&unixfs(UNIXFS_FILE, Some(bytes))));
    (block.0.to_string(), car(&[block.0], &[block]))
}

/// A metadata folder as the private store adds it, and its CAR.
pub(crate) fn folder_car(entries: &[(&str, &[u8])]) -> (String, Vec<u8>) {
    let (root, blocks) = folder(entries);
    (root.to_string(), car(&[root], &blocks))
}

// ── Roots ───────────────────────────────────────────────────────────

const FOLDER: &str = "bafybeibafe7oi52uk6xjyuigvo3mel5hs6kdb4kvbb3odkepyn6o5xd4qu";
const COVER: &str = "QmUBeVrKj3MNuuRLnx4Pae5PA31uLoXDJMTo1ee3x3uGJm";

#[test]
fn public_roots_with_cover() {
    let roots = public_metadata_roots(
        FOLDER,
        format!(r#"{{"image":"ipfs://{COVER}"}}"#).as_bytes(),
    )
    .unwrap();
    assert_eq!(
        roots,
        PublishRoots {
            folder: FOLDER.into(),
            cover: Some(COVER.into()),
        }
    );
}

#[test]
fn public_roots_without_cover() {
    let roots = public_metadata_roots(FOLDER, br#"{"name":"a","image":""}"#).unwrap();
    assert_eq!(
        roots,
        PublishRoots {
            folder: FOLDER.into(),
            cover: None,
        }
    );
}

#[test]
fn public_roots_refuse_other_scheme() {
    for document in [
        format!(r#"{{"image":"https://example.com/{COVER}"}}"#),
        format!(r#"{{"image":"ipns://{COVER}"}}"#),
        format!(r#"{{"image":"ipfs://{COVER}/cover.png"}}"#),
        r#"{"image":"ipfs://not-a-cid"}"#.to_string(),
        // A CIDv1 written in base58 is a second spelling of a CID: refused.
        r#"{"image":"ipfs://zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA"}"#.to_string(),
        r#"{"image":42}"#.to_string(),
        r#"{"name":"no image"}"#.to_string(),
        "not json".to_string(),
    ] {
        assert!(
            public_metadata_roots(FOLDER, document.as_bytes()).is_err(),
            "{document}"
        );
    }
}

// ── Phases ──────────────────────────────────────────────────────────

#[tokio::test]
async fn public_publish_runs_phases_in_order() {
    let home = home().await;
    let mint = mint_roots(true);
    let (private, public) = register_stores(&home, &mint).await;
    publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap();
    let (folder, cover) = (
        mint.roots.folder.as_str(),
        mint.roots.cover.as_deref().unwrap(),
    );
    assert_eq!(*private.exports.lock().unwrap(), [folder, cover]);
    assert_eq!(
        public.publication(),
        calls(&[
            ("runtime_public_import_car", folder),
            ("runtime_public_import_car", cover),
            ("runtime_public_pin", folder),
            ("runtime_public_pin", cover),
            ("runtime_public_provide", folder),
            ("runtime_public_provide", cover),
        ])
    );
    // Readiness came first, before anything was exported or imported.
    assert_eq!(public.calls.lock().unwrap()[0].0, "status");
}

#[tokio::test]
async fn public_publish_exports_only_folder_and_cover() {
    for with_cover in [true, false] {
        let home = home().await;
        let mint = mint_roots(with_cover);
        let (private, public) = register_stores(&home, &mint).await;
        publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
            .await
            .unwrap();
        let expected: Vec<String> = std::iter::once(mint.roots.folder.clone())
            .chain(mint.roots.cover.clone())
            .collect();
        assert_eq!(*private.exports.lock().unwrap(), expected);
        assert!(!private.exports.lock().unwrap().contains(&mint.content));
        assert!(public
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, cid)| cid != &mint.content));
    }
}

#[tokio::test]
async fn public_publish_refuses_invalid_car_and_never_imports() {
    let home = home().await;
    let mint = mint_roots(true);
    let (private, public) = register_stores(&home, &mint).await;
    // The cover's export carries a stowaway block: the protected content.
    let cover = mint.roots.cover.clone().unwrap();
    let mut stowaway = private.cars.lock().unwrap()[&cover].clone();
    let content = raw_block(b"ciphertext that must stay private");
    let cid_bytes = content.0.to_bytes();
    let mut section = Vec::new();
    let mut length = (cid_bytes.len() + content.1.len()) as u64;
    while length >= 0x80 {
        section.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    section.push(length as u8);
    section.extend_from_slice(&cid_bytes);
    section.extend_from_slice(&content.1);
    stowaway.extend_from_slice(&section);
    private.cars.lock().unwrap().insert(cover, stowaway);

    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::InvalidCar);
    assert!(
        public.publication().is_empty(),
        "{:?}",
        public.publication()
    );
}

#[tokio::test]
async fn public_publish_import_failure_is_import_failed() {
    let home = home().await;
    let mint = mint_roots(true);
    let (_, public) = register_stores(&home, &mint).await;
    public.refuse("runtime_public_import_car", "import_failed");
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::ImportFailed);
    assert_eq!(
        public.publication(),
        calls(&[("runtime_public_import_car", &mint.roots.folder)])
    );
}

#[tokio::test]
async fn public_provide_failure_is_announce_failed() {
    let home = home().await;
    let mint = mint_roots(false);
    let (_, public) = register_stores(&home, &mint).await;
    public.refuse("runtime_public_provide", "provide_failed");
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::AnnounceFailed);
}

#[tokio::test]
async fn public_publish_not_ready_or_disabled_does_nothing() {
    // Disabled consent: refused before the status read.
    let home = home().await;
    let mint = mint_roots(true);
    let (private, public) = register_stores(&home, &mint).await;
    record_consent(&home.data_dir, ConsentState::Disabled).await;
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::Disabled);
    assert!(public.calls.lock().unwrap().is_empty());
    assert!(private.exports.lock().unwrap().is_empty());

    // No store registered: not ready, nothing exported.
    let home = self::home().await;
    let private = Arc::new(FakePrivateIpfs::default());
    home.registry
        .register_sub_provider("ipfs", private.clone())
        .await
        .unwrap();
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    assert!(private.exports.lock().unwrap().is_empty());
}

/// Review Focus 2: Kubo dies between import and pin. The pin fails with
/// `not_ready` (a Retry); the supervisor's restart of the daemon (start on a
/// Ready registration sends EnsureStarted) brings it back, and the next
/// attempt publishes every phase again and succeeds.
#[tokio::test]
async fn public_kubo_gone_between_phases_then_retry_succeeds() {
    let home = home().await;
    let mint = mint_roots(true);
    let (_, public) = register_stores(&home, &mint).await;
    *public.dies_at.lock().unwrap() = Some("runtime_public_pin".into());
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    let pins = |public: &FakePublicIpfs| {
        public
            .publication()
            .iter()
            .filter(|(op, _)| op == "runtime_public_pin")
            .count()
    };
    assert_eq!(pins(&public), 1, "nothing after the failed pin");

    // While Kubo is gone, an attempt reads not ready and does nothing.
    let before = public.publication().len();
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    assert_eq!(public.publication().len(), before);

    {
        let guard = acquire_public_state_lock(&home.data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
            .await
            .unwrap();
    }
    publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap();
    let publication = public.publication();
    let folder = mint.roots.folder.as_str();
    let cover = mint.roots.cover.as_deref().unwrap();
    assert_eq!(
        publication[before..],
        calls(&[
            ("runtime_public_import_car", folder),
            ("runtime_public_import_car", cover),
            ("runtime_public_pin", folder),
            ("runtime_public_pin", cover),
            ("runtime_public_provide", folder),
            ("runtime_public_provide", cover),
        ])
    );
}

/// A withdrawal while the folder's provide is awaited: the disable route's
/// steps (the marker, then the detached completion) run concurrently, the
/// Stop force-reaps the busy provider, and the blocked provide fails. Then
/// consent is Disabled, the store is stopped, the marker is gone, and no
/// further phase ran: neither the cover's provide nor the approval phase.
#[tokio::test(start_paused = true)]
async fn public_withdrawal_during_awaited_provide_aborts_next_phase() {
    let home = home().await;
    let mint = mint_roots(true);
    let store = FakeStore::install(
        &home.data_dir,
        Arc::new(|fake: &FakeBridge| {
            fake.hold("runtime_public_provide");
        }),
    );
    {
        let guard = acquire_public_state_lock(&home.data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
            .await
            .unwrap();
    }
    let private = Arc::new(FakePrivateIpfs::default());
    *private.cars.lock().unwrap() = mint.cars.clone();
    home.registry
        .register_sub_provider("ipfs", private)
        .await
        .unwrap();
    let fake = store.last();
    let provides = |fake: &FakeBridge| {
        fake.ops()
            .iter()
            .filter(|op| *op == "runtime_public_provide")
            .count()
    };

    let publish = {
        let (registry, data_dir, roots) = (
            home.registry.clone(),
            home.data_dir.clone(),
            mint.roots.clone(),
        );
        tokio::spawn(async move {
            publish_public_metadata(&registry, &data_dir, &roots).await?;
            // The approval phase, as the creator tail runs it next.
            approval_phase_allowed(&data_dir)?;
            Ok::<_, PublicMetadataError>("approval raised")
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while provides(&fake) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the provide never began"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Disable, as the route does.
    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    let completion = {
        let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
        tokio::spawn(async move { complete_withdrawal(&registry, &data_dir).await })
    };
    let outcome = completion.await.unwrap();
    let published = publish.await.unwrap();

    assert_eq!(outcome, StopOutcome::Stopped);
    assert!(published.is_err(), "{published:?}");
    assert_eq!(
        read_consent(&home.data_dir).unwrap().unwrap().state,
        ConsentState::Disabled
    );
    assert!(
        !home
            .registry
            .has_ready_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
    );
    assert!(read_withdrawal_marker(&home.data_dir).unwrap().is_none());
    assert_eq!(provides(&fake), 1, "the cover's provide never ran");
    assert_eq!(
        approval_phase_allowed(&home.data_dir).unwrap_err().code(),
        PublicMetadataErrorCode::Disabled
    );
}

// ── A5: the gate closes while a mint publishes (A45-F1) ─────────────

/// The gate closes while the folder is exported: no import follows, and
/// the attempt answers the typed `disabled`.
#[tokio::test]
async fn public_gate_closes_during_export_then_no_import() {
    let home = home().await;
    let mint = mint_roots(true);
    let (private, public) = register_stores(&home, &mint).await;
    let data_dir = home.data_dir.clone();
    *private.on_export.lock().unwrap() = Some(Arc::new(move || {
        crate::public_metadata_consent::tests::close_public_metadata_gate(&data_dir);
    }));
    let error = publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::Disabled);
    assert_eq!(
        *private.exports.lock().unwrap(),
        std::slice::from_ref(&mint.roots.folder),
        "the cover is not exported after the gate closed"
    );
    assert!(public.publication().is_empty(), "no import");
}

/// The gate closes while the folder's provide is awaited: the op ends when
/// the closed-gate Stop reaps the provider, no further phase runs, and the
/// approval phase is refused.
#[tokio::test(start_paused = true)]
async fn public_gate_closes_during_provide_then_no_approval() {
    let home = home().await;
    let mint = mint_roots(true);
    let store = FakeStore::install(
        &home.data_dir,
        Arc::new(|fake: &FakeBridge| {
            fake.hold("runtime_public_provide");
        }),
    );
    {
        let guard = acquire_public_state_lock(&home.data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
            .await
            .unwrap();
    }
    let private = Arc::new(FakePrivateIpfs::default());
    *private.cars.lock().unwrap() = mint.cars.clone();
    home.registry
        .register_sub_provider("ipfs", private)
        .await
        .unwrap();
    let fake = store.last();
    let provides = |fake: &FakeBridge| {
        fake.ops()
            .iter()
            .filter(|op| *op == "runtime_public_provide")
            .count()
    };
    let publish = {
        let (registry, data_dir, roots) = (
            home.registry.clone(),
            home.data_dir.clone(),
            mint.roots.clone(),
        );
        tokio::spawn(async move {
            publish_public_metadata(&registry, &data_dir, &roots).await?;
            approval_phase_allowed(&data_dir)?;
            Ok::<_, PublicMetadataError>("approval raised")
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while provides(&fake) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the provide never began"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    crate::public_metadata_consent::tests::close_public_metadata_gate(&home.data_dir);
    // The closed-gate Stop the supervisor runs.
    let outcome = {
        let guard = acquire_public_state_lock(&home.data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        PublicIpfsStore::stop(&home.registry, &home.data_dir, &guard).await
    };
    let published = publish.await.unwrap();
    assert_eq!(outcome, StopOutcome::Stopped);
    assert!(published.is_err(), "{published:?}");
    assert_eq!(provides(&fake), 1, "the cover's provide never ran");
    let refused = approval_phase_allowed(&home.data_dir).unwrap_err();
    assert_eq!(refused.code(), PublicMetadataErrorCode::Disabled);
    // Paused, not withdrawn: the consent is untouched.
    assert_eq!(
        read_consent(&home.data_dir).unwrap().unwrap().state,
        ConsentState::Enabled
    );
}
