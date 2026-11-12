import { createTransferProgress, announceTransferProgress } from "../transfer-progress.js";
import { escapeHtml } from "./model.js";

export function createLibraryUploads({ container, perf, state }) {
  let uploadRenderFrame = 0;

  function cancelUploadRender() {
    if (!uploadRenderFrame) return;
    window.cancelAnimationFrame(uploadRenderFrame);
    uploadRenderFrame = 0;
  }

  function scheduleUploadRender() {
    if (uploadRenderFrame) return;
    perf.uploadRenderScheduledCount += 1;
    uploadRenderFrame = window.requestAnimationFrame(() => {
      uploadRenderFrame = 0;
      renderUploads();
    });
  }

  function renderUploads() {
    cancelUploadRender();
    perf.uploadRenderCount += 1;
    if (!state.uploads.length) {
      container.classList.add("hidden");
      container.innerHTML = "";
      announceTransferProgress(container.parentElement, null, null, "File upload");
      return;
    }
    container.classList.remove("hidden");
    container.innerHTML = state.uploads.map((upload) => `
      <div class="upload-row">
        <div>
          <div class="upload-name">${escapeHtml(upload.name)}</div>
          <div>${escapeHtml(upload.status)}</div>
        </div>
        <div class="upload-meter"></div>
      </div>
    `).join("");
    const active = state.uploads.filter(upload => upload.total_bytes !== 0 && ["Queued", "Preparing", "Uploading", "Saving"].includes(upload.status));
    announceTransferProgress(container.parentElement, active.length ? active.reduce((sum, upload) => sum + (upload.completed_bytes || 0), 0) : null,
      active.every(upload => Number.isFinite(upload.total_bytes)) ? active.reduce((sum, upload) => sum + upload.total_bytes, 0) : null, "File upload");
    container.querySelectorAll(".upload-meter").forEach((meter, index) => {
      const upload = state.uploads[index];
      const active = ["Queued", "Preparing", "Uploading", "Saving"].includes(upload.status);
      meter.hidden = !active || upload.total_bytes === 0;
      if (!meter.hidden) meter.append(createTransferProgress(upload.completed_bytes, upload.total_bytes, "Upload progress"));
    });
  }

  function setUploadProgress(id, patch) {
    const upload = state.uploads.find((entry) => entry.id === id);
    if (!upload) return;
    Object.assign(upload, patch);
    scheduleUploadRender();
  }

  return {
    renderUploads,
    setUploadProgress,
  };
}
