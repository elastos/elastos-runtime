import { formatBytes, formatBytesOf } from "./byte-format.js";

// Native progress supplies keyboard-independent, screen-reader progress semantics.
export function createTransferProgress(completed, total, label = "Download progress", doc = document) {
  const root = doc.createElement("div");
  root.className = "transfer-progress";
  const bar = doc.createElement("progress");
  bar.setAttribute("aria-label", label);
  const detail = doc.createElement("span");
  const known = Number.isFinite(total) && total > 0;
  const done = Number.isFinite(completed) ? Math.max(0, completed) : 0;
  if (known) {
    bar.max = total;
    bar.value = Math.min(done, total);
    const percent = Math.floor(bar.value * 100 / total);
    detail.textContent = `${formatBytesOf(done, total)} · ${percent}%`;
    bar.setAttribute("aria-valuetext", detail.textContent);
  } else {
    detail.textContent = done > 0 ? `${formatBytes(done)} received` : "Waiting for size…";
    bar.setAttribute("aria-valuetext", detail.textContent);
  }
  root.append(bar, detail);
  return root;
}

// Keep this region outside a consumer's replaced rows. Announce five-percent
// milestones; the visible numbers and native bar can update more often.
export function announceTransferProgress(host, completed, total, label = "Download") {
  if (!host) return;
  let live = host.querySelector(":scope > .transfer-announcement");
  if (!live) {
    live = host.ownerDocument.createElement("span");
    live.className = "transfer-announcement";
    live.setAttribute("role", "status");
    live.setAttribute("aria-live", "polite");
    live.setAttribute("aria-atomic", "true");
    host.append(live);
  }
  const known = Number.isFinite(total) && total > 0;
  const percent = known ? Math.floor(Math.min(Math.max(0, completed || 0), total) * 100 / total) : null;
  const key = completed == null ? "" : `${label}:${total}:${known ? Math.floor(percent / 5) : "unknown"}`;
  if (live.dataset.progressKey === key) return;
  live.dataset.progressKey = key;
  live.textContent = completed == null ? "" : known
    ? `${label}: ${formatBytesOf(completed, total)}, ${percent}%.`
    : `${label} in progress. Total size is unknown.`;
}
