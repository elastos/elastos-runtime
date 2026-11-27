// Passed directly to Playwright Frame.evaluate; keep this observer self-contained.
export function readSystemUpdateState() {
  const field = (name) => document.querySelector(`[data-field="${name}"]`);
  const text = (node) => node?.textContent?.trim() || "";
  const apply = document.querySelector("#runtime-update-apply");
  return {
    frame: true,
    shown: document.querySelector("#runtime-update")?.hidden === false,
    status: text(document.querySelector("#runtime-update-status")),
    offer: field("update-offer")?.hidden === false,
    can_apply: Boolean(apply && !apply.hidden && !apply.disabled),
    current_version: text(field("runtime-status")),
    // The published baseline uses version fields; this candidate names the target in its heading.
    new_version: text(field("update-heading")).match(/^Updat(?:e|ing) to (?:ElastOS )?(.+)$/)?.[1]
      || text(field("update-new-version")),
    changes: field("update-changes")?.hidden === false ? text(field("update-changes")) : "",
    installed_version: text(field("source-installed-version")),
    // Set before an approval: true while the same System window stays open.
    same_window: window.__elastosUpdateWindowMarker === true,
  };
}
