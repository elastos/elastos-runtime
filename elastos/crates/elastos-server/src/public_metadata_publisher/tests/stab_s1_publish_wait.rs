//! STAB-REPRO S1 (STAB-01, fixed under D1): the Creator's "Publish metadata
//! on IPFS" step held the mint's wallet approval until the public Kubo had
//! finished a DHT `routing/provide` for every root, one root after the
//! other. Now the step ends once the roots are pinned, and the announce runs
//! in the background, bounded and logged.
//!
//! Live (Home-4, 2026-11-17, mint 9672d187…): the public blocks were imported
//! at 07:32:55Z, the bridge warned "provider request still pending
//! op=runtime_public_provide elapsed_secs=30" at 07:33:26Z, and the approval
//! was created at 07:34:29Z: about 90 s of announce before the approval.
//! The Home's previous mints (consent was not yet enabled) went from the
//! availability check to the approval in 1–3 s.
//!
//! The fake store is the public-ipfs `FakeBridge` (one request at a time on
//! its I/O, as the real bridge), started through the real
//! `PublicIpfsStore::start`, on the real registry. Time is paused, so the
//! durations below cost nothing to run.

use super::*;

/// One DHT announce as long as the live folder provide (between 30 s and
/// 60 s, by the bridge's 30 s warning interval).
const LIVE_PROVIDE: Duration = Duration::from_secs(45);

/// A Home whose public store runs on a fake bridge configured by
/// `configure`, and whose private store holds `mint`'s CARs.
async fn started_store(
    home: &Home,
    mint: &MintRoots,
    configure: crate::public_ipfs_store::tests::Configure,
) -> (FakeStore, Arc<FakeBridge>) {
    let store = FakeStore::install(&home.data_dir, configure);
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
    (store, fake)
}

/// The step's wait is the SUM of one DHT announce per root: with a cover,
/// a mint waits two announces before its approval. Red today: the step
/// takes 2 x 45 s = 90 s, which is the live gap.
#[tokio::test(start_paused = true)]
async fn stab_s1_publish_metadata_waits_one_dht_provide_per_root_in_turn() {
    let home = home().await;
    let mint = mint_roots(true);
    let (_store, fake) = started_store(
        &home,
        &mint,
        Arc::new(|fake: &FakeBridge| {
            fake.delay("runtime_public_provide", LIVE_PROVIDE);
        }),
    )
    .await;

    let began = tokio::time::Instant::now();
    publish_public_metadata(&home.registry, &home.data_dir, &mint.roots)
        .await
        .unwrap();
    let took = began.elapsed();

    let provides = fake
        .ops()
        .iter()
        .filter(|op| *op == "runtime_public_provide")
        .count();
    assert!(
        took < LIVE_PROVIDE * 2,
        "Publish metadata took {took:?}: {provides} awaited runtime_public_provide \
         (Kubo routing/provide) calls of {LIVE_PROVIDE:?} each ran one after the \
         other before the step returned and the wallet approval could be raised"
    );
}

/// What the step waits on, and that the Runtime sets no bound of its own:
/// with the folder's DHT announce never answering, the mint stays in
/// "Publish metadata" with its approval not raised. Red today: still
/// waiting after 600 s, although the metadata was already imported and
/// pinned on the public store.
#[tokio::test(start_paused = true)]
async fn stab_s1_publish_metadata_holds_the_approval_on_the_dht_announce() {
    let home = home().await;
    let mint = mint_roots(true);
    let (_store, fake) = started_store(
        &home,
        &mint,
        Arc::new(|fake: &FakeBridge| {
            fake.hold("runtime_public_provide");
        }),
    )
    .await;

    let step = {
        let (registry, data_dir, roots) = (
            home.registry.clone(),
            home.data_dir.clone(),
            mint.roots.clone(),
        );
        tokio::spawn(async move {
            publish_public_metadata(&registry, &data_dir, &roots).await?;
            // The creator tail's next phase, right before the approval.
            approval_phase_allowed(&data_dir)?;
            Ok::<_, PublicMetadataError>("approval raised")
        })
    };
    let window = Duration::from_secs(600);
    let outcome = tokio::time::timeout(window, step).await;

    let ops = fake.ops();
    let done_before_provide: Vec<_> = ops
        .iter()
        .filter(|op| {
            matches!(
                op.as_str(),
                "runtime_public_import_car" | "runtime_public_pin"
            )
        })
        .collect();
    assert!(
        outcome.is_ok(),
        "after {window:?} the approval is still not raised: the step awaits \
         runtime_public_provide with no Runtime deadline, although the metadata \
         was already on the public store ({done_before_provide:?}); public ops = {ops:?}"
    );
}
