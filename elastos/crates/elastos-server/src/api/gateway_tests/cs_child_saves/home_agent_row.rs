//! `cs_*` row for the Home Agent workspace. Entry:
//! `save_home_agent_workspace`, which `home_agent_workspace_put` calls after
//! the token is verified. See the fixture's module comment
//! (`gateway_tests/cs_child_saves.rs`) for what stands in for a real child.

use super::super::gateway_tests::cs_child_saves::{
    answer, parent_person, refusal, report_person_files, KEPT_ELSEWHERE, ROOT_DIR,
};
use super::*;

fn put_request() -> HomeAgentWorkspacePutRequest {
    serde_json::from_value(serde_json::json!({
        "schema": HOME_AGENT_WORKSPACE_SCHEMA,
        "if_revision": 0,
        "document": {"draft": "cs child draft"}
    }))
    .unwrap()
}

/// On the CHILD, with the person's verified Home Agent context, the save is
/// refused because the person's record is kept on the parent, and leaves no
/// file and no folder.
#[test]
fn cs_child_home_agent_workspace_save_for_the_parent_person() {
    const ROW: &str = "cs_child_home_agent_workspace_save_for_the_parent_person";
    let person = parent_person(HOME_AGENT_CAPSULE_ID);
    let child = person.child.path();
    let saved = refusal(save_home_agent_workspace(
        child,
        &person.on_child.context,
        put_request(),
    ));
    answer(
        ROW,
        "save_home_agent_workspace",
        format!("refusal: {saved:?}"),
    );
    report_person_files(ROW, "child", child);
    assert_eq!(saved.as_deref(), Some(KEPT_ELSEWHERE));
    person.assert_child_holds_only(ROW, &[]);
    assert!(!person.parent.path().join(ROOT_DIR).exists());
}
