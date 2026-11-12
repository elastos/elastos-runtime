// Startup reads live window state across asynchronous permission and ownership checks.
export function startBrowser(state) {
  const requestedStartupUrl = state.params.get("url");
  const initialUrl = requestedStartupUrl || state.DEFAULT_URL;
  state.addressInput.value = initialUrl;
  state.setLoading(true);
  state.showStatus("Browser is checking its Engine. Wait, or reopen Browser from Home to retry.", { sticky: true });
  return state.checkBrowserInternet(initialUrl).then(granted => {
    if (state.browserInternetPollingActive) state.watchInternetPermission();
    return granted ? state.fetchBrowserSummary({ remoteServices: false }) : null;
  })
    .then(async (summary) => {
      if (!summary || !state.browserInternetPollingActive || state.homeWindowCloseInFlight || state.homeWindowTerminalCloseConfirmed) return;
      if (await state.restoreRuntimePageViewer(summary)) {
        return state.continueRestoredInternetNavigation();
      }
      if (!state.browserInternetPollingActive || state.homeWindowCloseInFlight || state.homeWindowTerminalCloseConfirmed) return;
      if (!state.internetContinuationUrl && !state.explicitBrowserOpen) {
        state.setLoading(false);
        state.showStatus("Type a website address to open it.");
        return;
      }
      const url = state.internetContinuationUrl || initialUrl;
      state.internetContinuationUrl = null;
      return state.requestRuntimeOpen(url, { history: "replace" });
    })
    .catch((error) => {
      if (state.unloadCleanupStarted || state.homeWindowCloseInFlight || state.homeWindowTerminalCloseConfirmed) return;
      if (state.isAuthoritySessionError(error) && state.requestHomeRelaunch(state.friendlyOpenError(error))) {
        return;
      }
      state.setLoading(false);
      state.showStatus(state.friendlyOpenError(error), { sticky: true });
    });
}
