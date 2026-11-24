import { pendingRequests } from "./wallet-activity.js?v=wallet-20261115a";
import {
  isBitcoinProofRequest,
  isManagedRequest,
  readText,
  requestTiming,
  requestTitle,
  shortAddress,
  chainLabel,
  requestingAppName,
} from "./wallet-format.js?v=wallet-20260523a";
import { actionButton, setBusy, textNode } from "./wallet-render.js?v=wallet-20260523a";

export function createWalletRequests({
  fetchJson,
  notifyHomeSummaryChanged,
  openApprovalMethod,
  requestPasskeyStepUp,
  refreshWalletState,
  requestsNode,
  requestsPanelNode,
  shellHeaders,
  showStatus,
  clearRequestSelection = () => {},
}) {
  let acknowledgement = null;
  let focusAcknowledgement = false;
  let lastFocusedRequestId = "";
  // Acknowledgements last until the person works outside that request.
  function clearAcknowledgementOutside(event) {
    if (!acknowledgement || event.target?.closest?.("[data-wallet-request-id]")?.dataset.walletRequestId === acknowledgement.request_id) return;
    const id = acknowledgement.request_id;
    acknowledgement = null;
    for (const card of requestsNode?.children || []) {
      if (card.dataset.walletRequestId === id) card.remove();
    }
    if (requestsNode && !requestsNode.children.length) {
      requestsNode.hidden = true;
      if (requestsPanelNode) requestsPanelNode.hidden = true;
    }
  }
  globalThis.document?.addEventListener?.("pointerdown", clearAcknowledgementOutside, true);
  globalThis.document?.addEventListener?.("focusin", clearAcknowledgementOutside);
  const decisions = new Map();
  let visibleRequests = [];

  function renderRequests(requests, focusRequestId = "") {
    if (!requestsNode) {
      return false;
    }
    requestsNode.replaceChildren();
    visibleRequests = requests;
    const displayed = acknowledgement
      ? [...requests.filter(r => readText(r.request_id) !== acknowledgement.request_id), acknowledgement]
      : requests;
    if (requestsPanelNode) {
      requestsPanelNode.hidden = displayed.length === 0;
    }
    requestsNode.hidden = displayed.length === 0;
    let focused = null;
    for (const request of displayed) {
      const card = requestCard(request, readText(request.request_id) === focusRequestId);
      if (readText(request.request_id) === focusRequestId) {
        focused = card;
      }
      requestsNode.append(card);
    }
    if (acknowledgement && focusAcknowledgement) {
      focusAcknowledgement = false;
      const result = requestsNode.querySelector?.('[role="status"]');
      result?.focus({ preventScroll: true });
      result?.closest?.(".wallet-request")?.scrollIntoView({ block: "nearest" });
    }
    if (focused && focusRequestId !== lastFocusedRequestId) {
      window.setTimeout(() => focused.scrollIntoView({ behavior: "smooth", block: "center" }), 0);
    }
    lastFocusedRequestId = focusRequestId;
    return Boolean(focused);
  }

  function requestCard(request, focused = false) {
    const requestId = readText(request.request_id);
    const approvedTransaction = request.status === "approved" && request.intent === "transaction_intent";
    const accountAccess = readText(request.intent) === "browser_account_access";
    const accountAccessReview = accountAccess ? requestAccountAccessReview(request.review) : null;
    const answered = typeof request.localAcknowledgement === "string";
    const card = document.createElement("article");
    card.className = "wallet-request";
    card.classList.toggle("wallet-request-focused", focused);
    card.dataset.walletRequestId = requestId;
    const main = document.createElement("div");
    main.className = "wallet-request-main";
    const purpose = requestTitle(request);
    const detail = accountAccess ? "A site in Browser asks to see your account address." : readText(request.reason) || "Approval requested.";
    main.append(
      textNode("strong", purpose),
      textNode("span", `${requestingAppName(request)} · ${shortAddress(request.address)} · ${chainLabel(readText(request.chain_namespace).slice(0, 64))}`),
    );
    if (detail !== purpose) main.append(textNode("small", detail));
    const site = readText(request.capsule_id) === "browser" ? requestSite(request.requesting_origin) : null;
    if (site) main.append(site);
    if (!answered) main.append(textNode("small", requestTiming(request), "wallet-request-time"));
    if (accountAccessReview) {
      main.append(accountAccessReview);
    }
    if (approvedTransaction && !answered) {
      main.append(textNode("small", "This transaction may already have been sent. Check your wallet before sending again. Dismiss closes this request but does not cancel the transaction in your wallet."));
    }
    card.append(main);

    const actions = document.createElement("div");
    actions.className = "wallet-request-actions";
    if (answered) {
      const outcome = textNode("p", request.localAcknowledgement, "wallet-request-outcome");
      outcome.setAttribute?.("role", "status");
      outcome.setAttribute?.("tabindex", "-1");
      actions.append(outcome);
      card.append(actions);
      return card;
    }
    const connectorId = readText(request.connector_id);
    if (approvedTransaction) {
      // Keep an unfinished external send visible without offering another handoff.
    } else if (isManagedRequest(request) && (!accountAccess || accountAccessReview)) {
      const approve = actionButton(
        accountAccess ? "Allow" : "Approve",
        "walletRequestManagedApprove",
        requestId,
      );
      approve.dataset.walletRequestIntent = readText(request.intent);
      actions.append(approve);
    } else if (isBitcoinProofRequest(request)) {
      actions.append(actionButton("Open UniSat", "walletOpenMethod", "wallet-unisat"));
    } else if (connectorId === "wallet-metamask") {
      actions.append(actionButton("Open MetaMask", "walletOpenMethod", connectorId));
    }
    const reject = actionButton(approvedTransaction ? "Dismiss" : "Reject", "walletRequestReject", requestId, true);
    if (approvedTransaction) reject.dataset.walletApprovedTransaction = "true";
    actions.append(reject);
    card.append(actions);
    return card;
  }

  function requestAccountAccessReview(review) {
    if (!review || typeof review !== "object" || readText(review.kind) !== "account_access") {
      return null;
    }
    const details = document.createElement("section");
    details.className = "wallet-request-review";
    details.append(textNode("h3", "Account access"));
    const fields = document.createElement("dl");
    const appendField = (label, value) => {
      const text = Array.isArray(value)
        ? value.join(", ")
        : typeof value === "number"
        ? String(value)
        : readText(value);
      if (!text) return;
      fields.append(textNode("dt", label), textNode("dd", text));
    };
    appendField("Permission", review.permission);
    appendField("Account", review.account_id);
    appendField("Address", review.address);
    appendField("Requested network", review.requested_chain_namespace);
    appendField("Allowed networks", review.chain_namespaces);
    appendField("Access expires", review.grant_expires_at);
    details.append(fields);
    return details;
  }

  function requestSite(origin) {
    if (typeof origin !== "string" || origin.length > 512
      || !/^https?:\/\/[!-~]+$/.test(origin) || /[\/?#@\\]/.test(origin.slice(origin.indexOf("//") + 2))) return null;
    try { if (new URL(origin).origin !== origin) return null; } catch (_) { return null; }
    const row = document.createElement("div");
    row.className = "wallet-request-site";
    const value = textNode("span", origin, "wallet-request-origin");
    value.dir = "auto";
    // Assignment remains compatible with the lightweight DOM used by unit tests.
    value.setAttribute?.("dir", "auto");
    row.append(textNode("small", "Site in Browser"), value);
    return row;
  }

  function requestsWithDecisions(requests) {
    if (!decisions.size) return requests;
    const merged = [...requests];
    for (const [id, decision] of decisions) {
      const known = { ...decision };
      delete known.localAcknowledgement;
      const index = merged.findIndex(request => readText(request.request_id) === id);
      if (index < 0) merged.push(known);
      else if (!merged[index].transaction_hash && !["completed", "rejected"].includes(merged[index].status)) merged[index] = known;
    }
    return merged;
  }

  function openPendingReview() {
    (requestsNode || requestsPanelNode)?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function onRequestClick(event) {
    const managedApprove = event.target && event.target.closest("[data-wallet-request-managed-approve]");
    if (managedApprove) {
      await approveManagedRequest(managedApprove);
      return;
    }
    const reject = event.target && event.target.closest("[data-wallet-request-reject]");
    if (reject) {
      await rejectRequest(reject);
      return;
    }
    const openMethod = event.target && event.target.closest("[data-wallet-open-method]");
    if (openMethod) {
      event.stopPropagation();
      openApprovalMethod(readText(openMethod.dataset.walletOpenMethod));
    }
  }

  async function approveManagedRequest(button) {
    const requestId = readText(button.dataset.walletRequestManagedApprove);
    if (!requestId) {
      return;
    }
    const accountAccess = readText(button.dataset.walletRequestIntent) === "browser_account_access";
    setBusy(button, true);
    showStatus(
      accountAccess
        ? "Confirm with your passkey to allow account access."
        : "Confirm with your passkey to sign.",
      "muted",
    );
    try {
      const intent = { request_id: requestId, reason: "Approved in Wallet" };
      const stepUpToken = await requestPasskeyStepUp("wallet.approve", intent);
      await fetchJson(`/api/apps/wallet/wallet/managed-approvals/${encodeURIComponent(requestId)}/approve`, {
        method: "POST",
        headers: shellHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ reason: intent.reason, step_up_token: stepUpToken }),
      });
      showStatus(accountAccess ? "Account access allowed." : "Request signed.", "success");
      notifyHomeSummaryChanged();
      await refreshWalletState();
    } catch (error) {
      showStatus(String(error.message || error), "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function rejectRequest(button) {
    const requestId = readText(button.dataset.walletRequestReject);
    if (!requestId) {
      return;
    }
    const request = visibleRequests.find(r => readText(r.request_id) === requestId);
    setBusy(button, true);
    showStatus(button.dataset.walletApprovedTransaction === "true" ? "Dismissing request." : "Rejecting request.", "muted");
    try {
      const result = await fetchJson(`/api/apps/wallet/wallet/approvals/${encodeURIComponent(requestId)}/reject`, {
        method: "POST",
        headers: shellHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ reason: button.dataset.walletApprovedTransaction === "true" ? "Dismissed in Wallet" : "Rejected in Wallet" }),
      });
      const message = result?.receipt_status === "dismissed"
        ? "Request dismissed. This does not cancel the transaction in your wallet. Check your wallet before making a new request."
        : "Request rejected.";
      if (request) {
        acknowledgement = { ...request, request_id: requestId, status:"rejected",
          localDecisionKind:result?.receipt_status === "dismissed" ? "dismissed" : "rejected", localAcknowledgement:message };
        decisions.set(requestId, acknowledgement);
        focusAcknowledgement = true;
        renderRequests(visibleRequests.filter(r => readText(r.request_id) !== requestId));
      }
      clearRequestSelection();
      notifyHomeSummaryChanged();
      try {
        await refreshWalletState();
      } catch (_) {
        showStatus("Wallet could not refresh other requests.", "error");
        return;
      }
      showStatus(acknowledgement ? "" : message, "success");
    } catch (error) {
      showStatus(String(error.message || error), "error");
    } finally {
      setBusy(button, false);
    }
  }

  return {
    onRequestClick,
    openPendingReview,
    requestsWithDecisions,
    pendingWalletRequests: requests => pendingRequests(requestsWithDecisions(requests)),
    renderRequests,
  };
}
