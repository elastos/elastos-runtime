#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const parentOrigin = "http://localhost:61180";
let messageListener = null;
let delegatedRequest = null;
const parent = {
  postMessage(message, origin) {
    delegatedRequest = { message, origin };
    queueMicrotask(() => messageListener({
      source: parent,
      origin: parentOrigin,
      data: {
        type: "elastos.home.passkey-step-up.result/v1",
        requestId: message.requestId,
        stepUpToken: "fresh-wallet-step-up-token",
      },
    }));
  },
};

globalThis.document = { referrer: `${parentOrigin}/apps/home/` };
globalThis.window = {
  location: {
    origin: "null",
    search: `?home_origin=${encodeURIComponent(parentOrigin)}`,
  },
  parent,
  top: parent,
  crypto: { randomUUID: () => "fresh-authority-request" },
  setTimeout,
  clearTimeout,
  addEventListener(type, listener) {
    if (type === "message") messageListener = listener;
  },
  removeEventListener(type, listener) {
    if (type === "message" && messageListener === listener) messageListener = null;
  },
};

const { createWalletApi } = await import("../capsules/wallet/browser/wallet-api.js");
const walletApi = createWalletApi({ getHomeToken: () => "existing-wallet-token" });
const stepUpToken = await walletApi.requestPasskeyStepUp(
  "wallet.send",
  { account_id: "wallet:test", to: "0x1", amount: "1" },
);

assert.equal(stepUpToken, "fresh-wallet-step-up-token");
assert.equal(delegatedRequest.origin, parentOrigin);
assert.equal(delegatedRequest.message.homeToken, "existing-wallet-token");
assert.equal(
  walletApi.shellHeaders()["x-elastos-home-token"],
  "existing-wallet-token",
  "ordinary Wallet requests must retain their launch authority",
);
assert.equal(
  walletApi.shellHeaders()["x-elastos-home-token"],
  "existing-wallet-token",
  "the passkey-bound operation must preserve its original launch authority",
);

const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
// Every awaited call is enumerated in source order, including conditional calls.
const freshOperations = [
  ['capsules/wallet/browser/wallet-send-flow.js', [['"wallet.send"','body']]],
  ['capsules/wallet/browser/wallet-account-actions.js', [['"wallet.account.delete"','body'], ['"wallet.recovery-key.export"','body']]],
  ['capsules/wallet/browser/wallet-create-account-flow.js', [['"wallet.recovery-key.import"','body']]],
  ['capsules/wallet/browser/wallet.js', [['"wallet.account.delete"','body']]],
  ['capsules/wallet/browser/wallet-requests.js', [['"wallet.approve"','body']]],
  ['capsules/system/browser/system.js', [
    ['"auth.account.guest-registration"','header'],
    ['"community.presence.grant"','header'],
    ['operation','header'], // auth.account.promote/demote/remove, auth.passkey.remove
    ['"auth.full-recovery-bundle.export"','body'],
    ['"system.source.switch-channel"','body'],
    ['"system.update.apply"','pending-body'],
  ]],
  ['capsules/inbox/browser/inbox.js', [
    ['"inbox.approve"','fields'],
    ['`${service}.internet.grant`','inbox-action'], // walletconnect and browser
    ['"walletconnect.internet.revoke"','inbox-action'],
    ['"browser.internet.revoke"','inbox-action'],
    ['"wallet.approve"','inbox-action'],
    ['"inspect.approve"','inbox-action'],
  ]],
];
for (const [path, operations] of freshOperations) {
  const code = source(path);
  const calls = [...code.matchAll(/\bawait\s+requestPasskeyStepUp\s*\(/g)];
  assert.equal(calls.length, operations.length, `${path} must enumerate every fresh-passkey call`);
  calls.forEach((call,index)=>{
    const segment = code.slice(call.index, calls[index+1]?.index ?? code.length);
    const [operation,transport] = operations[index];
    assert.equal(segment.match(/requestPasskeyStepUp\s*\(\s*([^,]+),/)[1].trim(),operation,`${path} call ${index+1}`);
    if(transport==='header') {
      assert.match(segment, /headers:\s*shellHeaders\(\{[\s\S]*?"x-elastos-step-up-token": stepUpToken/, `${path} ${operation} binds proof in its header`);
    } else {
      assert.match(segment, transport==='pending-body' ? /step_up_token:\s*pending\.stepUpToken/ : /step_up_token:\s*stepUpToken/, `${path} ${operation} binds proof in its body`);
      if(transport==='body'||transport==='pending-body')assert.match(segment,/headers:\s*shellHeaders\(\{\s*"content-type":\s*"application\/json"\s*}\)/,`${path} ${operation} keeps launch authority`);
      if(transport==='inbox-action')assert.match(segment,/inboxAction\([\s\S]{0,300}?step_up_token:\s*stepUpToken/,`${path} ${operation} uses the Inbox action`);
      if(transport==='fields')assert.match(segment,/fields = \{ \.\.\.fields, step_up_token: stepUpToken \}/);
    }
  });
}
const system = source('capsules/system/browser/system.js');
for(const operation of ['auth.account.promote','auth.account.demote','auth.account.remove','auth.passkey.remove'])assert(system.includes(`"${operation}"`),operation);
console.log('[home-passkey-step-up] PASS (all 6 System and 6 Inbox calls enumerated)');
