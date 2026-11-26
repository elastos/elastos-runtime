//! AUDIT-REPRO J1 (coll-journey-audit-20261117.md J1-F6): red test only, no
//! fix. One lost reply from a pool node during a mint.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

/// A pool node whose first answer is lost on the way back (Carrier dropped
/// the reply), and which answers every later request as a healthy node.
struct LostFirstReplyPoolNode {
    node: FakePoolNode,
    lost: AtomicBool,
}

#[async_trait::async_trait]
impl RuntimeCustodyProvider for LostFirstReplyPoolNode {
    async fn release_contribution(
        &self,
        request: &CustodyProviderRequestV1,
    ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
        self.node.release_contribution(request).await
    }

    async fn provision_node_share(
        &self,
        request: &CustodyProviderRequestV1,
    ) -> Result<CustodyProviderResponseV1, RuntimeProviderCallError> {
        self.node.provision_node_share(request).await
    }

    async fn release_pool_contribution(
        &self,
        request: &PoolCustodyRequestV1,
    ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
        self.node.release_pool_contribution(request).await
    }

    async fn provision_pool_node_share(
        &self,
        request: &PoolCustodyRequestV1,
    ) -> Result<PoolCustodyResponseV1, RuntimeProviderCallError> {
        let answer = self.node.provision_pool_node_share(request).await;
        if !self.lost.swap(true, Ordering::SeqCst) {
            return Err(RuntimeProviderCallError::NoExactResult);
        }
        answer
    }
}

/// J1-F6: the pool node stored the share but its reply was lost once. The
/// mint aborts at once (`AbortedPartialProvision`) instead of resending the
/// identical request while its statement is valid.
#[tokio::test]
async fn audit_j1_f6_a_lost_pool_reply_is_retried_exactly_before_the_mint_aborts() {
    let temp = tempdir().unwrap();
    let journal_root = owner_only_journal_root(&temp);
    let envelope = envelope();
    let draft = draft_for(&envelope);
    let node1 = FakePoolNode::new(1, false);
    let node2 = LostFirstReplyPoolNode {
        node: FakePoolNode::new(2, false),
        lost: AtomicBool::new(false),
    };
    let node3 = FakePoolNode::new(3, false);
    let coordinator = coordinator_with(
        RuntimeMintJournal::new(&journal_root),
        vec![
            RuntimeMintSelectedNode::new(binding(1), &node1),
            RuntimeMintSelectedNode::new(binding(2), &node2),
            RuntimeMintSelectedNode::new(binding(3), &node3),
        ],
    )
    .with_pool_provisioning(pool_provisioning(draft.content_access_id()));

    let outcome = coordinator
        .provision(&draft, &envelope, NOW + 10)
        .await
        .unwrap();

    let sent = node2.node.requests();
    assert_eq!(
        outcome,
        RuntimeMintCoordinatorOutcome::CustodyProvisioned {
            mint_id: draft.mint_id()
        },
        "J1-F6: one lost reply from pool node 2 aborts the mint ({} request(s) sent to it)",
        sent.len()
    );
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].to_json_vec().unwrap(),
        sent[1].to_json_vec().unwrap(),
        "the retry is the identical request"
    );
}
