//! AUDIT-REPRO J3-F1, server twin (red, no fix).
//!
//! At rights expiry the Player reopens and asks the *same* segment it was
//! reading on the new session (player.js:948-953; pinned green by
//! `renewal_required_reopens_and_resumes_at_the_same_position`). The new
//! server session counts its read-ahead from segment 0
//! (`highest.unwrap_or(0) + read_ahead`, pool_session.rs:1211-1224), so a
//! renewal past segment `read_ahead` is refused `Bound("read_ahead")` and the
//! playback stops at the renewal.

use super::*;

#[tokio::test]
async fn audit_j3_f1_a_renewed_session_may_start_mid_item() {
    let h = harness();
    h.content.0.part_bytes.store(1, Ordering::SeqCst);
    let item = item(PoolSessionContentKindV1::DashV2, 0x31);
    // The renewed session: a fresh prepare and open for the same item.
    let renewed = h.opened(&item, &source(1)).await;
    let read_ahead = u32::from(ServePolicyV1::DEFAULT.bounds.read_ahead_segments);
    // The old session ended while the viewer was at this segment.
    let resume_at = read_ahead + 1;
    let first = h
        .read(
            renewed.session_id,
            ViewerPartIndexV1::DashSegment {
                rendition: 0,
                index: resume_at,
            },
            &source(1),
            READ_AT,
        )
        .await;
    assert!(
        first.is_ok(),
        "a renewed session's first read is the segment the old one ended at \
         ({resume_at}); it was refused: {first:?}"
    );
}
