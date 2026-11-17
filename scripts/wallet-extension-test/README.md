# Recorded wallet test tools

These tools run only in tests. They replay MetaMask 13.57.0, UniSat 1.7.4 and
Rabby 0.94.16 observations. The original capture's SHA-256, release versions,
and selected raw cases are in `../fixtures/wallet-extension-replay.json`.
`scenarios.mjs` lists each scenario and its recording case IDs.

Install the provider before loading Home or a test page:

```js
import { installScriptedExtension, replayInput } from './wallet-extension-test/index.mjs';

await page.addInitScript(installScriptedExtension,
  await replayInput('metamask-connect-late'));
await page.goto(homeUrl);
// Press the real Home control. Its recorded provider call stays pending.
await page.evaluate(() => __walletReplay.person('does nothing'));
await page.evaluate(() => __walletReplay.advance(77_000));
await page.evaluate(() => __walletReplay.person('approves'));
await page.evaluate(() => __walletReplay.advance(1000));
const asked = await page.evaluate(() => __walletReplay.requests.map(
  ({ caseId, provider, method, params, state }) => ({ caseId, provider, method, params, state })));
```

`replayInput` accepts only names in `scenarios`. Each scenario lists a finite
sequence per provider. A call with an unrecorded method, parameter, or extra
request fails. JSON object key order is immaterial; array order and values
are exact. Tests supply the recorded message/transaction parameters. This tool
does not sign a new Runtime challenge or validate a link. The Runtime lane
must use a matching recorded proof fixture for a joined link test.

`metamask-silent-check` supplies recorded account and chain reads. Keep the
required-method test passing when changing scenarios: a provider fact needs
both its account read and its network read. Scenario parity alone checks only
the cases that were selected and cannot detect an omitted method.

The person controls are `approves`, `declines`, `closes the prompt`,
`does nothing`, `unlocks`, `switches account`, and `removes access`.
An optional second argument selects the recording case ID when calls overlap.
Only actions listed in the scenario are allowed. Locked scenarios require
unlock followed by approval. `closes side panel` leaves the measured MetaMask
side-panel call pending; `closes the prompt` is the recorded native notification
close. A pending-only recording stays pending for all virtual time. The queued
signature recordings establish waiting, not an eventual signature response.

`advance(ms)` drives wallet time only. If the test uses Playwright's page
clock for Home deadlines, advance that clock as well. An approval releases the
recorded response at its call-relative elapsed time, or immediately if that
time has already passed. Human waiting time in a recording is not a wallet
timeout. The replay preserves observed event payloads and their order within
the call interval. Negative `since_call_ms` values are earlier page history;
later unrelated actions in a snapshot are also outside that interval. The
account-switch and access-removal scenarios replay their specified history
suffix only when the person performs the action.

Discovery is one finite recorded history per page. Dispatch
`eip6963:requestProvider`, then advance time by 1000 ms to replay its
announcements, with original metadata, duplicates, relative spacing and object
identity. Extra discovery requests supply no invented announcements. The Rabby
legacy object is distinct from the announced objects and claims `isMetaMask`.
The stale-disabled scenario still announces MetaMask but its request stays
pending. A fresh disabled page announces Rabby only. Close the page/context to
discard the replay, or call `dispose()` in a unit-test surface.

The capture records error constructor, numeric code, message, data and property
names. A missing `data` property stays absent. Some MetaMask errors list a
`stack` property without its value; the replay keeps that property with
`undefined`, and makes no claim about stack text or property descriptors.

Use `../fixtures/wallet-connector-v2-messages.json` for N1/N2 messages,
stage/dispatch examples, N1 query rows, N4 identity-field additions, and N7
private summaries. Every lane imports this one JSON file (Rust uses
`include_str!` and `serde_json`). Receiver labels assume prior source, origin,
token, registration and lifetime checks. N4 entries describe additions to a
verified body, rather than a substitute for proof. N7 invalid display fields
are omitted while the underlying request remains intact. The fixture's N1/N2
messages still await human security review. Both contract digests are pinned;
text changes fail the conformance check until the integrator reviews the data.

Run the small checks:

```sh
node --test scripts/wallet-connector-v2-messages.test.mjs scripts/wallet-extension-replay.test.mjs
WALLET_EXTENSION_RAW=/path/to/original/recordings.json node --test scripts/wallet-extension-replay.test.mjs
elastos-heavy node --test scripts/wallet-extension-page.test.mjs
```

All three test files are also found by the repository behaviour suite's
`scripts/*.test.mjs` glob. The raw-file check is skipped when its explicit input
is absent; the bundled parity checks still run. To regenerate the bounded
excerpts, run `node scripts/wallet-extension-test/import-recordings.mjs
/path/to/original/recordings.json`, then review the diff and run the raw check.

## Recording limits and lane gates

Configured Brave Wallet discovery and silent reads have no recording. This
tool therefore supplies only the observed unconfigured Brave absence, and
rejects a configured-Brave scenario name. `n2_real_brave_discovery_and_silent_check_recording`,
Brave alternatives in `n2_recorded_provider_facts`, and Brave compatibility in
`n4_old_record_and_reopened_window` wait for that recording. The Brave enum in
the message file is a contract example, not provider acceptance.

Successful sends and receipts now have imported evidence for
`n2_real_transaction_hash_and_late_receipt_recording`; consumers can build
`n2_one_deadline_stop_late_reply` transaction branches and
`n2_transaction_completion_after_frame_close` against it. The clean UniSat
unlock case now supplies `n2_real_unisat_link_after_unlock_recording` input to
`n2_empty_accounts_prompt_on_send`; a complete link still requires the recorded
signature and real Runtime verification. These imports prove the fixture,
rather than those future product tests.

The capture supplies no mobile WalletConnect behavior, extension-update
behavior, general lock classifier, malformed UniSat chain reply, unrecorded
transaction error, or post-84-second signature-queue settlement. Tests may
exercise structural contract refusal with the shared message file; they may
claim recorded-provider acceptance only for the imported cases. Installed Home,
desktop app, phone trials and network behavior remain with their product lanes.
