import {
  DISPLAY_CURRENCY_STORAGE_KEY,
  readStoredBoolean,
  readStoredValue,
  storeValue,
} from "./wallet-format.js?v=wallet-20260720k";

export function createWalletPreferences({
  closeModal,
  fetchJson,
  getHomeToken,
  modalButton,
  notifyHomeSummaryChanged,
  openFlowModal,
  renderAll,
  requestPasskeyStepUp,
  refreshWalletState,
  shellHeaders,
  showStatus,
}) {
  const homeParentOrigin = new URLSearchParams(window.location.search).get("home_origin") || "";
  const privacyButton = document.querySelector("#wallet-privacy");
  const settingsDrawerNode = document.querySelector("#wallet-settings-drawer");
  const activityDrawerNode = document.querySelector("#wallet-activity-drawer");
  const drawerBackdropNode = document.querySelector("#wallet-drawer-backdrop");
  const settingsOpenButton = document.querySelector("#wallet-settings-open");

  let privacyMode = readStoredBoolean("wallet.privacy");
  let displayCurrency = readStoredValue(DISPLAY_CURRENCY_STORAGE_KEY, "btc", ["btc", "usd", "ela"]);
  let activeDrawer = "";
  let drawerCloseTimer = 0;
  const DRAWER_MS = 320;

  function bindPreferenceEvents() {
    privacyButton?.addEventListener("click", onTogglePrivacy);
    settingsOpenButton?.addEventListener("click", () => openDrawer("settings"));
    drawerBackdropNode?.addEventListener("click", closeDrawers);
    document.querySelectorAll("[data-wallet-currency]").forEach((button) => {
      button.addEventListener("click", () => setDisplayCurrency(button.dataset.walletCurrency));
    });
    document.querySelectorAll("[data-wallet-close-drawer]").forEach((button) => {
      button.addEventListener("click", closeDrawers);
    });
  }

  function prefersReducedMotion() {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function drawerFor(name) {
    if (name === "settings") {
      return settingsDrawerNode;
    }
    if (name === "activity") {
      return activityDrawerNode;
    }
    return null;
  }

  function openDrawer(name) {
    window.clearTimeout(drawerCloseTimer);
    const next = drawerFor(name);
    if (!next) {
      return;
    }
    // Swap drawers without animating the previous closed mid-flight.
    for (const node of [settingsDrawerNode, activityDrawerNode]) {
      if (node && node !== next) {
        node.classList.remove("is-open");
        node.hidden = true;
      }
    }
    activeDrawer = name;
    next.hidden = false;
    if (drawerBackdropNode) {
      drawerBackdropNode.hidden = false;
    }
    void next.offsetWidth;
    void drawerBackdropNode?.offsetWidth;
    next.classList.add("is-open");
    drawerBackdropNode?.classList.add("is-open");
  }

  function closeDrawers() {
    window.clearTimeout(drawerCloseTimer);
    activeDrawer = "";
    settingsDrawerNode?.classList.remove("is-open");
    activityDrawerNode?.classList.remove("is-open");
    drawerBackdropNode?.classList.remove("is-open");
    const finish = () => {
      if (settingsDrawerNode) {
        settingsDrawerNode.hidden = true;
      }
      if (activityDrawerNode) {
        activityDrawerNode.hidden = true;
      }
      if (drawerBackdropNode) {
        drawerBackdropNode.hidden = true;
      }
    };
    if (prefersReducedMotion()) {
      finish();
      return;
    }
    drawerCloseTimer = window.setTimeout(finish, DRAWER_MS);
  }

  function onTogglePrivacy() {
    privacyMode = !privacyMode;
    storeValue("wallet.privacy", privacyMode ? "1" : "0");
    applyPrivacyState();
    renderAll();
  }

  function setDisplayCurrency(currency) {
    if (!["usd", "ela", "btc"].includes(currency)) {
      return;
    }
    displayCurrency = currency;
    storeValue(DISPLAY_CURRENCY_STORAGE_KEY, currency);
    applyCurrencySelection();
    renderAll();
  }

  function applyCurrencySelection() {
    document.querySelectorAll("[data-wallet-currency]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.walletCurrency === displayCurrency);
    });
  }

  function applyPrivacyState() {
    const label = privacyMode ? "Show balances" : "Hide balances";
    const short = privacyMode ? "Show" : "Hide";
    const eyeSvg = privacyMode
      ? '<svg class="wallet-nav-icon-svg" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M2.25 2.25l11.5 11.5" /><path d="M6.6 6.7A1.75 1.75 0 0 0 9.3 9.4" /><path d="M4.2 4.55C2.85 5.55 1.75 8 1.75 8s2.5 3.75 6.25 3.75c1.05 0 2-.3 2.8-.75" /><path d="M7.1 4.35c.3-.05.6-.1.9-.1 3.75 0 6.25 3.75 6.25 3.75a12.4 12.4 0 0 1-1.55 1.7" /></svg>'
      : '<svg class="wallet-nav-icon-svg" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M1.75 8s2.5-3.75 6.25-3.75S14.25 8 14.25 8s-2.5 3.75-6.25 3.75S1.75 8 1.75 8Z" /><circle cx="8" cy="8" r="1.75" /></svg>';
    if (privacyButton) {
      privacyButton.innerHTML = `${eyeSvg}<span>${short}</span>`;
      privacyButton.setAttribute("aria-label", label);
      privacyButton.setAttribute("aria-pressed", privacyMode ? "true" : "false");
      privacyButton.title = label;
      privacyButton.classList.toggle("is-active", privacyMode);
    }
    if (window.parent !== window) {
      // Parent is the opaque-sandboxed GUI frame ("null" origin): post with
      // "*" — a boolean chrome hint, no secrets cross the boundary.
      window.parent.postMessage(
        {
          type: "wallet:privacy-state",
          privacyMode,
        },
        "*",
      );
    }
  }

  function togglePrivacy() {
    onTogglePrivacy();
  }

  function openApprovalMethod(target) {
    const activeHomeToken = getHomeToken();
    if (!target || !activeHomeToken || !homeParentOrigin || window.top === window) {
      return;
    }
    // Host-owned connector launch: exact keys only. Home launches the
    // connector and attaches it — Wallet does not pick the surface.
    window.top.postMessage({
      type: "home:open-target",
      target,
      homeToken: activeHomeToken,
    }, homeParentOrigin);
  }

  return {
    applyCurrencySelection,
    applyPrivacyState,
    bindPreferenceEvents,
    closeDrawers,
    getDisplayCurrency: () => displayCurrency,
    getPrivacyMode: () => privacyMode,
    openApprovalMethod,
    openDrawer,
    togglePrivacy,
  };
}
