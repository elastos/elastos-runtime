//! AUDIT-REPRO J4 (coll-journey-audit-20261117.md J4-F1, journey-audit A2-F2):
//! red tests only, no fix. A pool server that cannot read the item still
//! answers `session.prepare`; the failure comes at `session.open`, after the
//! Wallet signed and the release ran.

use super::*;

/// A server with no copy of the item: every stage fails, as the content
/// plane port answers when no holder serves the CID.
#[derive(Clone, Default)]
struct NoCopyContent {
    staged: Arc<Mutex<Vec<PoolSessionIdV1>>>,
}

#[async_trait::async_trait]
impl PoolSessionContentPort for NoCopyContent {
    async fn stage(
        &self,
        session_id: PoolSessionIdV1,
        _content: &PoolSessionContentRefV1,
        _binding: &ProtectedContentBindingV1,
    ) -> Result<PoolStagedContentV1, PoolSessionRefusal> {
        self.staged.lock().unwrap().push(session_id);
        Err(PoolSessionRefusal::ContentUnavailable)
    }

    async fn part(
        &self,
        _staged: &PoolStagedContentV1,
        _part: &ViewerPartIndexV1,
    ) -> Result<PoolStagedPartV1, PoolSessionRefusal> {
        Err(PoolSessionRefusal::ContentUnavailable)
    }

    fn discard(&self, _session_id: PoolSessionIdV1) {}
}

/// J4-F1 / A2-F2: `prepare` must refuse before the Wallet is asked when this
/// server cannot read the item, so the reader fails over to the next server.
#[tokio::test]
async fn audit_j4_f1_a_server_without_the_content_refuses_prepare_before_approval() {
    let content = NoCopyContent::default();
    let policy = FakePolicy {
        descriptor: descriptor(ServePolicyV1::DEFAULT, None),
        own_node: node_public_key(SERVER_NODE),
        own_issuer: runtime_issuer(OWN_ISSUER_SEED),
        ready: Arc::new(AtomicBool::new(true)),
        host_trusted: Arc::new(AtomicBool::new(true)),
    };
    let mut next = 0u8;
    let server = PoolSessionServer::new(
        policy,
        FakeDecrypt::default(),
        content.clone(),
        FakeAttest::default(),
    )
    .with_session_ids(Box::new(move || {
        next = next.wrapping_add(1);
        [next; 16]
    }))
    .with_node_budget(64);
    let item = item(PoolSessionContentKindV1::DashV2, 0x4a);

    let prepared = server
        .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(1), PREPARE_AT)
        .await;
    let Ok(prepared) = prepared else {
        // The fixed behaviour: refused before any approval.
        assert_eq!(
            content.staged.lock().unwrap().len(),
            1,
            "prepare staged once"
        );
        return;
    };
    // Today: prepare answered without reading the item. The open, which in
    // production comes after the Wallet signature and the key release,
    // is the first point that reads it, and it fails there.
    let opened = server
        .open(open_request(&item, &prepared), &source(1), OPEN_AT)
        .await;
    panic!(
        "J4-F1: a server that cannot read the item answered session.prepare \
         (session {:02x?}, content stages at prepare: 0); its session.open after the \
         approval then answered {opened:?} (stages tried: {})",
        prepared.session_id,
        content.staged.lock().unwrap().len()
    );
}
