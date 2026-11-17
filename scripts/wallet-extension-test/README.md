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
await page.evaluate(() => __walletReplay.assertNoViolations());
```

`replayInput` accepts only names in `scenarios`. Each scenario lists a finite
sequence per provider. Every test ends with `await page.evaluate(() => __walletReplay.assertNoViolations())`
before closing its page. In a unit test, use `control.assertNoViolations()`.
An unrecorded method, parameter, extra request or wrong call order is added to
`control.violations` before it throws. Product code can catch the exception;
the final helper still fails the test. Violations carry method/case metadata,
rather than untrusted request parameters. JSON object key order is immaterial; array order and values
are exact. Tests supply the recorded message/transaction parameters. This tool
does not sign a new Runtime challenge or validate a link. The Runtime lane
must use a matching recorded proof fixture for a joined link test.

`metamask-silent-check` supplies recorded account and chain reads. Keep the
required-method test passing when changing scenarios: a provider fact needs
both its account read and its network read. Scenario parity alone checks only
the cases that were selected and cannot detect an omitted method.
Each rejection is bound to its recording case through the generated pin.
The raw check also compares the complete recorded rejection set; the test has
no fixed shape count. `metamask-transaction-revoked` replays the captured
permission-revocation cleanup error from MM-8-confirm. Its `removes access`
control represents that cleanup, rather than a native Cancel-button trial.
Receipt scenarios require the recorded send to return its hash before the
receipt call. Preserve cross-call dependencies as well as per-call replies;
the raw clocks and the early-receipt refusal tests check this order.

The person controls are `approves`, `declines`, `closes the prompt`,
`does nothing`, `unlocks`, `switches account`, and `removes access`.
An optional second argument selects the recording case ID when calls overlap.
Only actions listed in the scenario are allowed. The importer checks every
approval, decline, native close, unlock and account event against its case.
A switch/removal event must match the account read that follows it. Locked scenarios require
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
account-switch and access-removal scenarios replay their specified recorded event
indices only when the person performs the action.

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

The same file contains the current draft's nullable safety facts, the unchanged
six-key v1 handoff, proposed NB1 settlement bodies/private operation data and
acknowledgements, selected-result read selectors, and trusted Accounts
close-return delivery. The MetaMask-to-WalletConnect row includes the complete
new-link selection/safety predicate; UniSat has no such row. Context fields
such as `selection`, `samePrincipal` and `delivery` are test preconditions,
rather than wire fields or evidence of authority. The contract commit and
both document digests identify the text these examples follow.

`oldHomeSource` pins the real v2.0.1 tag object, peeled commit, module path and
source digest. Its `.js.txt` artifact preserves that entire module byte for
byte, including in shallow checkouts. Its check proves provenance and the draft envelope shape only.
Runtime/navigation still owns `n2_old_home_transaction_handoff_compatible`,
which runs that unchanged module through a real Runtime handoff, send, hash and
completion, including a late answer. The new settlement, selected-result,
close-return and host safety tests also wait for their human gate and product
owners. A fixture PASS establishes neither the gate nor those joined journeys.
If review selects the NB1 fallback, remove valid no-hash producer/operation
examples before the consumers run; the file models only the proposed default.

Run the small checks:

```sh
node --test scripts/wallet-connector-v2-messages.test.mjs scripts/wallet-extension-replay.test.mjs scripts/wallet-extension-review.test.mjs
WALLET_EXTENSION_RAW=/path/to/original/recordings.json node --test scripts/wallet-extension-replay.test.mjs
elastos-heavy node --test scripts/wallet-extension-page.test.mjs
```

All four test files are also found by the repository behaviour suite's
`scripts/*.test.mjs` glob. The raw-file check is skipped when its explicit input
is absent; the bundled parity checks still run. To regenerate the bounded
excerpts and their independent pin, run:

```sh
node scripts/wallet-extension-test/import-recordings.mjs /path/to/original/recordings.json
WALLET_EXTENSION_RAW=/path/to/original/recordings.json node --test scripts/wallet-extension-replay.test.mjs
```

The importer accepts only the approved raw SHA-256. It validates provider names,
source actions and account-event bindings before writing the fixture and
`recording-pin.json`. That pin binds the exact fixture bytes, the compiled
scenario mapping and each rejection's case ID. Refresh it only through the
importer with the raw check, then review both diffs. The default run checks the
pin even when the private raw file is absent. Raw capture changes require a
reviewed source-digest update by the integrator.

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

The stale disabled MetaMask capture contains a pending account prompt, not a
direct silent-read timeout. `n2_stale_provider_check_and_reload_guidance` can
use that pending call and Home's cached-busy check. A branch that asserts a
direct stale `eth_accounts` timeout needs its own recording first.

## Measured surfaces and simulation differences

UniSat's own keys and public method list come from US-10-presence. Its event
methods live on the stand-in prototype, so the own-key list stays exact. The
legacy Rabby own-key list comes from R2-BOTH-legacy-shape. Unknown internal
values remain undefined, and unrecorded method calls fail through the violation
list. The capture has no complete MetaMask or announced-Rabby key inventory,
nor complete prototype/private-member types. Those stand-ins implement the
measured request/event interface and recorded flags only. A passing test proves
neither complete object reflection nor private API compatibility.

| Difference | What a lane may conclude |
| --- | --- |
| Round-1 MetaMask records presence and announcements, but no isMetaMask flag or legacy/announced identity | Use the announced provider. The round-1 legacy object has no scripted RPC case; a pass proves neither a legacy fallback nor reference identity. |
| Announcements occur once, after a request and only on virtual time; there is no unsolicited load/connect event | A pass covers the captured history, not real startup races or repeated/unprompted discovery. |
| Early approval or decline still settles at the recorded total time; a later action settles immediately | A pass covers response order and recorded waits, not actual response latency or cancellation of a wallet prompt. |
| Every new document/frame receives a fresh independent stand-in | A pass proves neither persistent extension state nor the stale-extension reload/reinjection journey. Record and model that journey before accepting it. |
| removes access in metamask-transaction-revoked represents the page's wallet_revokePermissions cleanup, with actor:page in the scenario | A pass proves the measured cleanup rejection, not a person using MetaMask's Disconnect control. |

A second MetaMask connect uses its recorded -32002 only while the first call
is still pending. Calls after that precondition ends are scenario violations,
rather than fabricated wallet errors. Legacy window.ethereum events reach the
legacy object. An unmapped provider name stops import; parity never drops a
recorded event because a recipient is missing.
