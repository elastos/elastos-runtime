//! `cs_*` rows for the Home saves. Each row calls private save
//! functions of this file with the context of a person who signed in on the
//! parent with a passkey and has root protection there. The appearance saves
//! are the calls `system_background_image_update`,
//! `system_background_overlay_update` and the two
//! `*_appearance_preferences_update` routes make after they have verified the
//! launch token. See the fixture's module
//! comment (`gateway_tests/cs_child_saves.rs`) for what stands in for a real
//! child and where it differs.

use super::super::gateway_tests::cs_child_saves::{
    answer, assert_kept_elsewhere, assert_stored_protected, parent_person, person_folders_left,
    refusal, report_person_files, tree, ROOT_DIR,
};
use super::*;

const IMAGE: &[u8] = b"cs background image bytes, as the person uploaded them";
const IMAGE_FILE: &str = ".AppData/ElastOS/Home/Appearance/background-image.png";
const OVERLAY_FILE: &str = ".AppData/ElastOS/Home/Appearance/background-overlay.json";
const PREFERENCES_FILE: &str = ".AppData/ElastOS/Home/Appearance/preferences.json";
const OVERLAY_PLAIN: &str = "{\n  \"enabled\": true,\n  \"opacity\": 0.4\n}";
const PREFERENCES_PLAIN: &str = "{\n  \"schema\": \"elastos.home.appearance.preferences/v1\",\n  \"revision\": 1,\n  \"theme\": \"dark\",\n  \"accent\": \"blue\",\n  \"accent_custom\": \"#c0ffee\",\n  \"dock_auto_hide\": false,\n  \"sounds\": false,\n  \"focus_mode\": false\n}";
/// The image URL a summary names for this person, up to the file's version.
const IMAGE_URL_START: &str =
    "/api/apps/home/appearance/background-image?scope=c2ee6e1b81f244f4&v=";

fn preferences_update() -> HomeAppearancePreferencesUpdate {
    serde_json::from_value(serde_json::json!({"accent_custom": "#C0FFEE"})).unwrap()
}

/// A save's result as one line: the summary as JSON with the image URL's
/// version (the file's modification time) replaced by `<version>`, or the
/// refusal text.
fn appearance_result(result: anyhow::Result<HomeAppearanceSummary>) -> String {
    match result {
        Ok(summary) => {
            let mut value = serde_json::to_value(&summary).unwrap();
            if let Some(url) = summary.background_image_url.as_deref() {
                let version = url.strip_prefix(IMAGE_URL_START).unwrap_or("?");
                let shown = if !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()) {
                    format!("{IMAGE_URL_START}<version>")
                } else {
                    url.to_string()
                };
                value["background_image_url"] = serde_json::Value::String(shown);
            }
            format!("Ok {value}")
        }
        Err(error) => format!("Err {error:#}"),
    }
}

/// The three appearance saves, in the order image, overlay, preferences, in
/// `dir` with `context`. Returns each result as `appearance_result` shows it.
fn save_appearance(
    row: &str,
    dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> [String; 3] {
    let image = appearance_result(home_save_background_image(
        dir,
        context,
        "background-image.png",
        IMAGE.to_vec(),
    ));
    answer(row, "home_save_background_image", &image);
    let overlay = appearance_result(home_save_background_overlay(dir, context, true, 0.4));
    answer(row, "home_save_background_overlay", &overlay);
    let preferences = appearance_result(home_save_appearance_preferences(
        dir,
        context,
        preferences_update(),
    ));
    answer(row, "home_save_appearance_preferences", &preferences);
    [image, overlay, preferences]
}

/// What the three saves answer on the parent.
const APPEARANCE_RESULTS: [&str; 3] = [
    "Ok {\"accent\":\"blue\",\"accent_custom\":\"#4f7fff\",\"background_image_url\":\"/api/apps/home/appearance/background-image?scope=c2ee6e1b81f244f4&v=<version>\",\"background_overlay_enabled\":false,\"background_overlay_opacity\":0.55,\"dock_auto_hide\":false,\"focus_mode\":false,\"revision\":0,\"schema\":\"elastos.home.appearance/v1\",\"sounds\":false,\"theme\":\"dark\"}",
    "Ok {\"accent\":\"blue\",\"accent_custom\":\"#4f7fff\",\"background_image_url\":\"/api/apps/home/appearance/background-image?scope=c2ee6e1b81f244f4&v=<version>\",\"background_overlay_enabled\":true,\"background_overlay_opacity\":0.4,\"dock_auto_hide\":false,\"focus_mode\":false,\"revision\":0,\"schema\":\"elastos.home.appearance/v1\",\"sounds\":false,\"theme\":\"dark\"}",
    "Ok {\"accent\":\"blue\",\"accent_custom\":\"#c0ffee\",\"background_image_url\":\"/api/apps/home/appearance/background-image?scope=c2ee6e1b81f244f4&v=<version>\",\"background_overlay_enabled\":true,\"background_overlay_opacity\":0.4,\"dock_auto_hide\":false,\"focus_mode\":false,\"revision\":1,\"schema\":\"elastos.home.appearance/v1\",\"sounds\":false,\"theme\":\"dark\"}",
];

/// Control. On the PARENT, where the person has root protection, the three
/// appearance saves pass and each file on disk is an encrypted envelope for
/// the person and the object: it is not the plain input, its bytes show none
/// of the pieces of the input the row lists, and the parent's own read opens
/// it to the input.
#[test]
fn cs_parent_home_appearance_save_is_stored_protected() {
    const ROW: &str = "cs_parent_home_appearance_save_is_stored_protected";
    let person = parent_person(HOME_CAPSULE_ID);
    let parent = person.parent.path();
    let results = save_appearance(ROW, parent, &person.on_parent.context);
    report_person_files(ROW, "parent", parent);
    assert_eq!(results, APPEARANCE_RESULTS);
    assert_eq!(
        tree(&parent.join(ROOT_DIR)),
        [IMAGE_FILE, OVERLAY_FILE, PREFERENCES_FILE]
    );
    assert_stored_protected(parent, IMAGE_FILE, IMAGE, &["cs background image"]);
    assert_stored_protected(
        parent,
        OVERLAY_FILE,
        OVERLAY_PLAIN.as_bytes(),
        &["enabled", "opacity"],
    );
    assert_stored_protected(
        parent,
        PREFERENCES_FILE,
        PREFERENCES_PLAIN.as_bytes(),
        &["accent_custom", "#c0ffee", "revision"],
    );
    // Nothing was written into the child.
    person.assert_child_holds_only(ROW, &[]);
}

/// On the CHILD, with the same person's verified context, each of the three
/// saves is refused: the person's record is kept on the parent and the child
/// holds no protection for their root, so it writes no file. The child's
/// sign-in state stores no record, protection or session for the person
/// before or after.
#[test]
fn cs_child_home_appearance_saves_for_the_parent_person() {
    const ROW: &str = "cs_child_home_appearance_saves_for_the_parent_person";
    let person = parent_person(HOME_CAPSULE_ID);
    let child = person.child.path();
    person.assert_child_holds_only(ROW, &[]);
    let results = save_appearance(ROW, child, &person.on_child.context);
    report_person_files(ROW, "child", child);
    for (save, shown) in ["image", "overlay", "preferences"].iter().zip(&results) {
        assert_kept_elsewhere(save, shown);
    }
    let left = person_folders_left(child);
    let left: Vec<&str> = left.iter().map(String::as_str).collect();
    person.assert_child_holds_only(ROW, &left);
    // The parent holds nothing under the person's root either.
    assert!(!person.parent.path().join(ROOT_DIR).exists());
}

/// On the CHILD, with the same person's verified context: the Home browser
/// state save (a layout note and a Home Agent note in the session), the
/// Services selection save and the Services requests save. Each is refused,
/// because the person's record is kept on the parent, and none writes a file.
#[test]
fn cs_child_home_state_saves_for_the_parent_person() {
    const ROW: &str = "cs_child_home_state_saves_for_the_parent_person";
    let person = parent_person(HOME_CAPSULE_ID);
    let child = person.child.path();
    let context = &person.on_child.context;
    person.assert_child_holds_only(ROW, &[]);

    // Entry: `home_save_browser_state`, which `home_browser_state_update`
    // calls after the token is verified.
    let update: HomeBrowserStateUpdate = serde_json::from_value(serde_json::json!({
        "layout": {"csLayoutNote": "cs child layout note"},
        "session": {"agent": {"note": "cs child agent note"}},
    }))
    .unwrap();
    let browser = match home_save_browser_state(child, context, update) {
        Ok(state) => format!("Ok {}", serde_json::to_value(&state).unwrap()),
        Err(error) => format!("Err {error:#}"),
    };
    answer(ROW, "home_save_browser_state", &browser);

    // Entry: `home_save_services_selection_state`, which the
    // `services_offer_update` route calls after the token is verified.
    let mut selection = home_services_default_selection_state(context);
    selection.updated_at = 1_700_000_001;
    selection
        .remote_offer_ids
        .insert("cs-remote-offer".to_string());
    let selection_saved = refusal(home_save_services_selection_state(
        child, context, &selection,
    ));
    answer(
        ROW,
        "home_save_services_selection_state",
        format!("refusal: {selection_saved:?}"),
    );

    // Entry: `home_save_services_requests_state`, which
    // `home_services_sync_access_requests` calls.
    let mut requests = home_services_default_requests_state(context);
    requests.updated_at = 1_700_000_002;
    requests
        .catalog_last_response_at
        .insert("cs-peer".to_string(), 1_700_000_003);
    let requests_saved = refusal(home_save_services_requests_state(child, context, &requests));
    answer(
        ROW,
        "home_save_services_requests_state",
        format!("refusal: {requests_saved:?}"),
    );
    report_person_files(ROW, "child", child);

    assert_kept_elsewhere("home_save_browser_state", &browser);
    assert_kept_elsewhere(
        "home_save_services_selection_state",
        selection_saved.as_deref().unwrap_or("passed"),
    );
    assert_kept_elsewhere(
        "home_save_services_requests_state",
        requests_saved.as_deref().unwrap_or("passed"),
    );
    let left = person_folders_left(child);
    let left: Vec<&str> = left.iter().map(String::as_str).collect();
    person.assert_child_holds_only(ROW, &left);
    assert!(!person.parent.path().join(ROOT_DIR).exists());
}

/// Every file under `dir` with its bytes and modification time.
fn snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
    tree(dir)
        .into_iter()
        .filter(|relative| !relative.ends_with('/'))
        .map(|relative| {
            let path = dir.join(&relative);
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            (relative, std::fs::read(&path).unwrap(), modified)
        })
        .collect()
}

/// On the CHILD, for a principal whose record is on the parent but whose root
/// has no protection there either, the save is not refused: the child writes
/// it as the parent would.
#[test]
fn cs_child_save_for_a_parent_principal_without_protection_is_not_refused() {
    const ROW: &str = "cs_child_save_for_a_parent_principal_without_protection_is_not_refused";
    let person = parent_person(HOME_CAPSULE_ID);
    crate::auth::mutate_auth_state_for_test(person.parent.path(), |state| {
        state.principal_root_protections.clear()
    });
    let child = person.child.path();
    let saved = home_save_background_overlay(child, &person.on_child.context, true, 0.4);
    answer(
        ROW,
        "home_save_background_overlay",
        format!("{:?}", saved.as_ref().err()),
    );
    assert!(saved.is_ok(), "{:?}", saved.err());
    assert!(child
        .join(ROOT_DIR)
        .join(".AppData/ElastOS/Home/Appearance/background-overlay.json")
        .is_file());
}

/// On the CHILD, a copy of the person's record in the child's own sign-in
/// state does not change the answer: the protection is on the parent, so the
/// save is refused and no file is written.
#[test]
fn cs_child_save_is_refused_when_the_child_also_holds_the_record() {
    const ROW: &str = "cs_child_save_is_refused_when_the_child_also_holds_the_record";
    let person = parent_person(HOME_CAPSULE_ID);
    let record = crate::auth::load_auth_state(person.parent.path())
        .unwrap()
        .principals[0]
        .clone();
    let child = person.child.path();
    crate::auth::mutate_auth_state_for_test(child, |state| state.principals.push(record));
    let saved = refusal(home_save_background_overlay(
        child,
        &person.on_child.context,
        true,
        0.4,
    ));
    answer(
        ROW,
        "home_save_background_overlay",
        format!("refusal: {saved:?}"),
    );
    assert_kept_elsewhere(
        "home_save_background_overlay",
        saved.as_deref().unwrap_or("passed"),
    );
    person_folders_left(child);
}

/// A refused save on the CHILD changes nothing in the parent's folder: every
/// file there keeps its bytes and its modification time.
#[test]
fn cs_child_refusal_leaves_the_parent_folder_unchanged() {
    const ROW: &str = "cs_child_refusal_leaves_the_parent_folder_unchanged";
    let person = parent_person(HOME_CAPSULE_ID);
    let parent = person.parent.path();
    let before = snapshot(parent);
    std::thread::sleep(std::time::Duration::from_millis(20));
    let results = save_appearance(ROW, person.child.path(), &person.on_child.context);
    for (save, shown) in ["image", "overlay", "preferences"].iter().zip(&results) {
        assert_kept_elsewhere(save, shown);
    }
    let after = snapshot(parent);
    let changed: Vec<&str> = before
        .iter()
        .zip(&after)
        .filter(|(a, b)| a != b)
        .map(|(a, _)| a.0.as_str())
        .collect();
    assert_eq!(
        before.len(),
        after.len(),
        "files appeared or went in the parent"
    );
    assert!(changed.is_empty(), "changed in the parent: {changed:?}");
}

#[test]
fn cs_child_save_refuses_unreadable_parent_state() {
    for read_failure in [false, true] {
        let person = parent_person(HOME_CAPSULE_ID);
        let parent_state = crate::auth::auth_state_path(person.parent.path()).unwrap();
        assert!(parent_state.is_file());
        let before = if read_failure {
            let before = std::fs::read(&parent_state).unwrap();
            std::fs::rename(&parent_state, parent_state.with_extension("saved")).unwrap();
            std::fs::create_dir(&parent_state).unwrap();
            before
        } else {
            std::fs::write(&parent_state, b"unreadable JSON").unwrap();
            std::fs::read(&parent_state).unwrap()
        };
        let saved =
            home_save_background_overlay(person.child.path(), &person.on_child.context, true, 0.4)
                .unwrap_err();
        assert!(
            saved.is::<crate::auth::ProtectedRecordKeptElsewhere>(),
            "{saved:#}"
        );
        person_folders_left(person.child.path());
        if read_failure {
            assert!(parent_state.is_dir());
            assert_eq!(
                std::fs::read(parent_state.with_extension("saved")).unwrap(),
                before
            );
        } else {
            assert_eq!(std::fs::read(parent_state).unwrap(), before);
        }
    }
}
