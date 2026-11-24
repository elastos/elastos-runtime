import {
  DISPLAY_CURRENCY_STORAGE_KEY,
  METHOD_MONOGRAMS,
  shortAddress,
  namesForMethod,
  readStoredBoolean,
  readStoredValue,
  storeValue,
  isPasskeyManagedAccount,
  walletDisplay,
  accountDisplayName,
} from "./wallet-format.js?v=wallet-20260720k";
import {
  actionButton,
  methodMark,
  walletDisplayMark,
  textNode,
} from "./wallet-render.js?v=wallet-20260720k";

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
  getSigninChooser = () => null,
}) {
  const homeParentOrigin = new URLSearchParams(window.location.search).get("home_origin") || "";
  const privacyButton = document.querySelector("#wallet-privacy");
  const settingsDrawerNode = document.querySelector("#wallet-settings-drawer");
  const activityDrawerNode = document.querySelector("#wallet-activity-drawer");
  const drawerBackdropNode = document.querySelector("#wallet-drawer-backdrop");
  const settingsOpenButton = document.querySelector("#wallet-settings-open");
  const methodsNode = document.querySelector("#wallet-methods");

  let signinRowsKey;
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
    methodsNode?.addEventListener("click", onMethodClick);
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

  function renderMethods(accounts, approvalMethods = {}) {
    if (!methodsNode) {
      return;
    }
    const signin = getSigninChooser();
    if (signin) {
      const key=JSON.stringify([signin.requestId,signin.stage,signin.methods]);
      // A focus refresh can finish between pointer-down and pointer-up.
      // Preserve the controls while their state is unchanged so click completes.
      if(signinRowsKey===key)return;
      signinRowsKey=key;
      methodsNode.replaceChildren();
      for (const method of signin.methods||[]) {
        const {connector}=method,label=method.label||({metamask:'MetaMask',unisat:'UniSat',walletconnect:'WalletConnect'}[connector]),mark=connector==='unisat'?'btc':connector==='walletconnect'?'wc':method.providerId&&method.providerId!=='io.metamask'?'unknown':'metamask';
        const choice=method.providerId?`${connector}:${method.providerId}`:connector;
        const row=document.createElement('article');row.className='wallet-method wallet-method-head';
        row.append(methodMark(mark,METHOD_MONOGRAMS[mark]||label.slice(0,1),true,''));
        const copy=document.createElement('div');copy.append(textNode('strong',connector==='walletconnect'&&signin.walletName?signin.walletName:label));
        const used=method?.used===true;
        if(used)copy.append(textNode('span','Already signs in'));
        else if(connector==='walletconnect')copy.append(textNode('span',signin.walletName?'WalletConnect':"Connects through a relay that can see this computer's internet address."));
        row.append(copy);
        const button=actionButton('Choose','walletSigninChoose',choice,true);
        button.disabled=used||signin.stage!=='options';
        button.onclick=()=>signin.act(choice);row.append(button);methodsNode.append(row);
      }
      return;
    }
    signinRowsKey=undefined;
    methodsNode.replaceChildren();
    const walletConnectConnected = namesForMethod(accounts, "wc");
    const walletConnectAvailable = approvalMethods.walletconnect?.available === true;
    const methods = [
      { id: "passkey", label: "Built-in addresses", hint: "Passkey-controlled · Wallet Send", connected: namesForMethod(accounts, "passkey") },
      { id: "metamask", label: "MetaMask", hint: "MetaMask or another wallet in this browser", connected: namesForMethod(accounts, "metamask"), target: "wallet-metamask", addLabel: "Connect", openLabel: "Add address" },
      { id: "btc", label: "UniSat", hint: "Connect with UniSat", connected: namesForMethod(accounts, "btc"), target: "wallet-unisat", addLabel: "Connect", openLabel: "Add address" },
      {
        id: "wc",
        label: "WalletConnect",
        hint: walletConnectAvailable ? "Connect with your wallet" : "WalletConnect connection is unavailable",
        connected: walletConnectConnected,
        target: walletConnectAvailable ? "wallet-walletconnect" : "",
        addLabel: "Connect",
        openLabel: "Add address",
      },
    ].filter((method) => method.id !== "wc" || walletConnectAvailable || method.connected.length > 0);

    const passkey = methods.find((method) => method.id === "passkey");
    const connectors = methods.filter((method) => method.id !== "passkey");
    if (passkey) {
      methodsNode.append(methodGroup(
        passkey,
        accounts.filter((account) => account.method === "passkey"),
      ));
    }
    for (const method of connectors) {
      methodsNode.append(methodGroup(
        method,
        accounts.filter((account) => account.method === method.id),
      ));
    }
  }

  function methodGroup(method, methodAccounts) {
    const group = document.createElement("section");
    group.className = "wallet-method-group";
    group.setAttribute("aria-label", method.label);
    group.append(methodRow(method));
    for (const account of methodAccounts) {
      group.append(methodAccountRow(account));
    }
    return group;
  }

  function methodRow(method) {
    const row = document.createElement("article");
    row.className = "wallet-method wallet-method-head";
    row.append(methodMark(method.id, METHOD_MONOGRAMS[method.id], true, ""));
    const body = document.createElement("div");
    const subtitle = method.connected.length > 0
      ? method.id === "passkey"
        ? `Passkey (${method.connected.length})`
        : `(${method.connected.length})`
      : method.hint;
    body.append(
      textNode("strong", method.label),
      textNode("span", subtitle),
    );
    row.append(body);
    if (method.target) {
      const label = method.connected.length > 0
        ? method.openLabel || "Open"
        : method.addLabel || "Add";
      row.append(actionButton(label, "walletOpenMethod", method.target, true));
    } else if (method.connected.length > 0 || method.id === "passkey") {
      row.append(textNode("span", "Connected", "wallet-method-chip"));
    }
    return row;
  }

  function methodAccountRow(account) {
    const row = document.createElement("article");
    row.className = "wallet-method wallet-method-account";
    const monogram = accountMonogram(account);
    const body = document.createElement("div");
    const name = textNode("strong", accountDisplayName(account), "wallet-card-name");
    name.dir = "auto";
    body.append(name, textNode("span", `${account.network} · ${shortAddress(account.address)}`));
    const display = walletDisplay(account);
    if (!isPasskeyManagedAccount(account) && display.name !== accountDisplayName(account)) {
      const walletName = textNode("span", display.name, "wallet-display-name");
      walletName.dir = "auto";
      body.append(walletName);
    }
    row.append(
      isPasskeyManagedAccount(account)
        ? methodMark(account.method || "unknown", monogram, true, account.chain_namespace)
        : walletDisplayMark(display.mark),
      body,
    );
    const remove = actionButton("Remove", "walletRemoveAccount", account.account_id, true);
    remove.dataset.walletAccountName = account.name;
    remove.dataset.walletDisplayName = accountDisplayName(account);
    remove.dataset.walletAccountManaged = String(isPasskeyManagedAccount(account));
    remove.dataset.walletAccountDescription = `${account.network} · ${shortAddress(account.address)}`;
    row.append(remove);
    return row;
  }

  function accountMonogram(account) {
    const fromName = String(account?.name || "")
      .trim()
      .charAt(0)
      .toUpperCase();
    if (fromName) {
      return fromName;
    }
    return METHOD_MONOGRAMS[account?.method] || "?";
  }

  function onMethodClick(event) {
    const remove = event.target && event.target.closest("[data-wallet-remove-account]");
    if (!remove) {
      return;
    }
    const accountId = readStoredValueFromDataset(remove.dataset.walletRemoveAccount);
    if (!accountId) {
      return;
    }
    const name = readStoredValueFromDataset(remove.dataset.walletAccountName) || "address";
    const displayName = readStoredValueFromDataset(remove.dataset.walletDisplayName) || name;
    // Keep peer identity separate from the trusted confirmation sentence.
    const heading = textNode("h2", "");
    const identity = textNode("bdi", displayName);
    identity.dir = "auto";
    identity.style.unicodeBidi = "isolate";
    heading.append("Remove ", identity, "?");
    // In-window confirm sheet (same modal the flows use); the passkey prompt
    // that follows remains the real authority gate.
    openFlowModal(
      `Remove ${displayName}?`,
      remove.dataset.walletAccountManaged === "true"
        ? "Built-in addresses require their Wallet recovery key to restore later. Passkey confirmation is required."
        : "Remove this address from Wallet. Your funds stay unchanged. This does not cancel a transaction in your wallet. Removing the last address connected through your wallet also clears Home's saved connection. Confirm with your passkey to remove the address.",
      [textNode("p", remove.dataset.walletAccountDescription || "", "wallet-state")],
      [
        modalButton("Cancel", closeModal, true),
        modalButton("Remove", () => removeAccount(remove, accountId, name), false, true),
      ],
      { surface: "modal", headingNode: heading },
    );
  }

  async function removeAccount(remove, accountId, name) {
    closeModal();
    remove.disabled = true;
    try {
      const stepUpToken = await requestPasskeyStepUp(
        "wallet.account.delete",
        { account_id: accountId },
      );
      await fetchJson(`/api/apps/wallet/wallet/accounts/${encodeURIComponent(accountId)}`, {
        method: "DELETE",
        headers: shellHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ step_up_token: stepUpToken }),
      });
      showStatus(`${name} removed.`, "success");
      notifyHomeSummaryChanged();
      await refreshWalletState();
    } catch (error) {
      showStatus(String(error.message || error), "error");
    } finally {
      remove.disabled = false;
    }
  }

  function readStoredValueFromDataset(value) {
    return typeof value === "string" ? value.trim() : "";
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
    renderMethods,
    togglePrivacy,
  };
}
