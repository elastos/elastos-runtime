export async function navigateBrowserAddress(state, value) {
  if (!state.browserInternetAllowed) return state.requestInternetNavigation(value);
  const nextUrl = state.normalizeUrl(value);
  const currentUrl = state.currentBrowserUrl();
  const crossStreamTarget = !state.sameBrowserStreamTarget(currentUrl, nextUrl);
  state.clearAddressDraft();
  if (!state.currentPage?.page_id) {
    return state.requestRuntimeOpen(nextUrl);
  }
  if (state.browserInternetInterrupted) return state.requestRuntimeOpen(nextUrl);
  if (state.selectedBrowserEngineId !== state.currentBrowserEngineId) {
    return state.requestRuntimeOpen(nextUrl);
  }
  if (state.selectedRemoteExitId !== state.currentRemoteExitId) {
    return state.requestRuntimeOpen(nextUrl);
  }
  if (state.isBrowserErrorUrl(currentUrl)) {
    state.showStatus(`Recovering ${state.visibleAddressForUrl(nextUrl)} in a fresh Browser session...`, {
      sticky: true,
    });
    return state.requestRuntimeOpen(nextUrl);
  }
  state.addressInput.value = nextUrl;
  state.addressInput.blur();
  state.setLoading(true);
  state.showStatus(`Opening ${state.visibleAddressForUrl(nextUrl)}...`, { sticky: true });
  const openingStatus = state.statusNode.firstChild;
  try {
    const response = await state.sendBrowserInput(
      { type: "browser_command", command: "navigate", url: nextUrl },
      { history: "push" },
    );
    if (response?.accepted === true && state.statusNode.firstChild === openingStatus) {
      state.window.clearTimeout(state.statusTimer);
      state.statusNode.dataset.visible = "false";
    }
    state.startPageStatusPolling();
  } catch (error) {
    if (crossStreamTarget) {
      state.showStatus(`Reopening ${state.visibleAddressForUrl(nextUrl)} in a fresh Browser session...`, {
        sticky: true,
      });
      return state.requestRuntimeOpen(nextUrl);
    }
    state.showStatus(state.friendlyOpenError(error), { sticky: true });
    throw error;
  } finally {
    state.setLoading(false);
  }
}
