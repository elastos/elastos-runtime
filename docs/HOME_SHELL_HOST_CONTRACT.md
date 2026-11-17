# Home Shell Host Contract

Status: unmarked sections describe **today**. The N1 and N2 sections mark
**today** separately from **after this work**. Their future requirements are
contracts for the build, not claims of installed support.

Home has one small trusted browser host and two selectable shells:

| Identity | Purpose | Browser origin |
| --- | --- | --- |
| `home` | Front door, sign-in, shell lifecycle, and recovery | Home origin |
| `home-gui` | Desktop and window projection | Opaque sandboxed frame |
| `home-cli` | Terminal and TUI projection | Opaque sandboxed frame |

`home` is not a selectable shell. It does not render the desktop or terminal.
Runtime state selects either `home-gui` or `home-cli`, and the host mounts that
shell as the single root view.

The host lifecycle is:

`unlock -> read Runtime shell state -> launch one root shell -> route validated intents -> recover`

## Equal Shells

`home-gui` and `home-cli` are sibling shell capsules. They have the same:

- trust class and origin isolation;
- signed-in principal and Runtime-derived facts;
- launch-token validation;
- shell lifecycle and recovery rules;
- ability to request allowed capsule launches, unlock, sign-out, and an
  explicit shell change;
- prohibition on direct provider, network, wallet, storage, or Carrier
  authority.

They are not identical renderers. `home-gui` owns desktop windows and web
projections. `home-cli` owns the Runtime-owned PTY terminal and TUI projections. A
CLI action uses a CLI projection when one exists. Opening a GUI-only projection
from CLI is an explicit `switch shell and open` action; it never happens as a
side effect of running a normal CLI command.

The PTY contract uses explicit start/events/input/resize/close routes. Runtime
owns the process and stream lifecycle; `home-cli` renders bytes and sends input
or dimensions through those scoped routes.

Both shell manifests expose the common `capsule.open` and `shell.switch`
methods. Projection-specific methods such as `desktop.render` and
`facts.search` describe presentation, not additional authority.

## Origin Boundary

The Home DOM is a trusted host surface. Neither shell nor an app shares Home's
effective origin. Runtime serves every browser projection under the same
`/apps/<capsule>/` host and Home mounts it in a sandbox without
`allow-same-origin`. The browser therefore gives each frame a unique opaque
origin. This requires no wildcard DNS, extra certificate, or reverse-proxy
rule.

Opaque frames cannot read Home's DOM, session cookie, passkey surface, browser
storage, or sibling frames. Capsule state that must survive a frame belongs in
the principal-scoped Runtime namespace, not ambient browser storage. Static
assets and token-authenticated API calls may cross the opaque boundary through
the gateway's narrow `Origin: null` CORS policy; unrelated web origins remain
denied.

Home keeps one bounded `browser:<32 lowercase hexadecimal digits>` correlation
identifier in its trusted top-level browser profile. It uses browser
`crypto.getRandomValues`; there is no weak or opaque-frame fallback. After the
active `home-gui` frame sends `home:shell-ready`, Home checks the exact source
WindowProxy, opaque origin, active target, and launch token before handing that
identifier to the frame. The identifier only correlates an encrypted
principal-scoped GUI session with the same browser profile. It is not a
capability, proof, launch fact, routing input, or authorization decision, and it
is not added as a Runtime Home summary fact. The existing browser-state session
payload remains presentation state in the single encrypted principal file. The
GUI neither reads nor writes browser storage and will not restore or persist a
window session until this checked handoff succeeds.

Runtime-generated browser routes carry a scoped launch token in the URL
fragment. Its contract is `elastos.home.launch-token/v4`. The fragment is
removed from visible history after bootstrap and is never sent as an HTTP
referrer. Runtime signs the v4 payload under the matching
`elastos.home.launch.v4` domain, including a collision-resistant launch id, the
selected resource, executable actor, authorizing actor, principal, session,
proof binding, grant, issue/expiry times, non-delegation flag, and any exact
operation/request digest. A direct launch uses the executable actor as its
authorizing actor. A Home-created child launch records `home` as the authorizing
actor and cannot delegate again. A viewer is therefore the actor for selected
content, not a replacement identity for that content. Browser API calls from
capsules require one valid Host and exactly
`Origin: null`; direct Home calls require same-origin browser provenance from an
exact destination Origin or Referer, or `Sec-Fetch-Site: same-origin`. Internal
shell launch-grant transfer uses a separate non-browser validation path. Runtime
rejects missing or conflicting provenance, v2, v3, mixed-shape, expired, and
substituted tokens. A Home session cookie alone cannot mint an app token.

The Home session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` on HTTPS.
Capsule responses use CSP, referrer, content-type, and resource-policy headers
appropriate to their document or asset role.

## Host Responsibilities

The Home host may:

- show the passkey or guest sign-in surface;
- read the Runtime-owned Home summary;
- launch exactly one trusted root shell;
- validate child source, origin, target, and launch token before accepting a
  message;
- retain and hand the non-authoritative browser-profile correlation only to an
  accepted active `home-gui` ready message;
- mint target-scoped routes through Runtime using host-held authority;
- route Runtime events and approved payloads to their registered child frame;
- show a minimal reload, Desktop, or sign-out recovery surface;
- ask for a reload, never reload by itself, when a summary reports a Runtime
  version other than the one that served the page: after an update the page,
  the shell and open windows keep their old code until the page reloads, and
  a reload would drop what open windows have not saved.

The Home host must not:

- contain desktop, taskbar, launcher, window, or terminal implementation;
- infer authority from iframe placement or a manifest role;
- expose its session cookie or passkey result to an arbitrary frame;
- let an app or shell address a sibling frame directly;
- keep an inactive shell alive behind CSS;
- switch shells because an ordinary app-open intent was received.

## Shell Messages

Shell messages are a local browser adapter for typed Runtime intent. Every
message must come from the active shell frame, its opaque origin, and its
current launch token.

Common shell messages are:

| Message | Result |
| --- | --- |
| `home:shell-ready` | For accepted `home-gui`, Home first sends the profile correlation, then the current Runtime summary. Other shells receive only the summary. |
| `home:shell-context` | Home sends the bounded non-authoritative profile correlation to the accepted active GUI frame. |
| `home:refresh-summary` | Home refreshes Runtime facts. |
| `home:launch-target` | Runtime returns a target-scoped launch route. |
| `home:request-unlock` | Home displays its host-owned sign-in surface. |
| `home:sign-out` | Home revokes the active session and reloads the front door. |
| `home:close-self` | Home closes the active root shell through Runtime state. |

`home:switch-shell-and-open-target` is the explicit CLI-to-GUI transition for a
GUI-only target. Home validates the target, persists `home-gui` through the
Runtime shell route, launches the GUI shell, and then asks that shell to open
the target. A plain `home:open-target` from `home-cli` cannot trigger this
transition.

New active-shell writes accept only Runtime-approved `home-gui` and `home-cli`
candidates. A manifest declaring `role: shell` does not grant shell authority.

## App Messages

Apps post directly to the top-level Home host. Home registers a child only when
its source window, opaque origin, target id, and launch token all match a route
that Home obtained from Runtime.

Allowed app intents are source-scoped. Examples include opening a known target,
opening a supported object URI, delivering a typed payload to an installed
viewer, closing the current app, and requesting a fresh passkey proof for an
approved high-risk operation. Home rejects unknown sources, origins, targets,
tokens, payload shapes, and operations.

The GUI shell receives only presentation commands such as opening or closing a
window. It does not receive another capsule's authority token. App-to-app work
remains a Runtime-gated intent and, for off-box effects, follows the provider and
Carrier path described in [Capsule Interface Contract](CAPSULE_INTERFACE_CONTRACT.md).

### First-party Clipboard edge

First-party capsule Clipboard access terminates in the trusted top-level Home
document. This is one closed browser edge adapter shared by Browser, Wallet,
MetaMask, UniSat, WalletConnect, Library, and Documents. It is not an ESP
capability, generic app message, provider RPC, shell method, audit event, or new
source of Home authority. `home-gui` only projects opaque capsule iframes and
does not receive `clipboard-read` or `clipboard-write` permission. No opaque
first-party capsule calls `navigator.clipboard` or keeps a direct or fallback
Clipboard path.

The canonical request is `elastos.home.clipboard.request/v1`. Home derives the
app target from the launch record it received from Runtime; a capsule never
asserts its target in request JSON. Home accepts a request only from that
launch's exact opaque `WindowProxy`, `Origin: null`, parent origin, app-bound
Home token, random lifecycle generation, bounded random request id, operation,
purpose, MIME type, and payload bound. Each frame may have at most one request
in flight. Home keeps only bounded, expiring replay ids and text-free in-flight
metadata. Concurrent, replayed, substituted, malformed, oversized, stale,
retired, and timed-out requests fail closed. A Home page whose code predates a
purpose answers it as `malformed` with purpose `invalid`; the client reports
that as `unknown_purpose`, so the app can ask for a Home reload.

The purpose policy is closed. Browser may read or write bounded `text/plain`
for `browser.text`. Wallet may write addresses and Wallet Recovery Keys.
MetaMask, UniSat, and WalletConnect may write linked Wallet addresses.
WalletConnect may also write a pairing link, bounded to 2048 UTF-8 bytes, for
opening a wallet on the same computer. Home confirms that write through its
own Clipboard prompt. Library
may write resource URIs and bounded technical identifiers under separate
purposes; Documents may write resource URIs. No non-Browser target may read
the OS Clipboard, and no caller-supplied purpose widens its target's policy.

Every OS Clipboard read or write requires a new click on the visible,
top-level, Home-owned Clipboard prompt. Only that prompt continuation invokes
`navigator.clipboard.readText()` or `navigator.clipboard.writeText()`. The
prompt identifies the operation and purpose without displaying Clipboard
payload. A Wallet Recovery Key prompt explicitly identifies secret material
but never displays, logs, persists, or audits the secret. A Library identifier
prompt identifies technical identifier material without displaying it. Home
never persists, logs, audits, or sends Clipboard text to any other capsule,
shell, provider, or Runtime route. It returns read text only to the exact
requesting Browser frame and returns write success only after the OS Clipboard
operation completes.

Guest Clipboard output is inert unless the local user first performs an
explicit copy action in Browser. Browser binds the next strict, bounded,
canonical `text/plain` guest response to that exact pending request before
asking Home to write it. Unsolicited remote Clipboard messages cannot change the
host Clipboard. Browser paste comes either from an explicit `ClipboardEvent`
carrying `text/plain` or from the closed Home read action, and guest input still
travels through the existing Runtime-mediated Browser input route.

The shared limit remains 65,536 UTF-8 bytes. Canonical base64, chunk size,
chunk-count, assembly timeout, and teardown checks remain on guest Clipboard
messages. Home and each client clear text-bearing and in-flight state on
completion, rejection, timeout, frame retirement, sign-out, or root-shell
replacement. Copy UI reports success only after the matching Home result
succeeds.

### Injected wallet connector effects (N2)

**Today.** Opaque MetaMask/Brave and UniSat frames ask the trusted top-level
Home page to use injected providers. `home:wallet-connector-effect` with schema
`elastos.home.wallet-connector-effect/v1` accepts exactly `link` or `approve`
with `approvalRequestId`. The host checks the registered frame and connector
launch token. Runtime separately validates Home's same-origin authority and the
carried connector token for the same principal, session, proof and grant.
Runtime issues challenges, consumes handoffs and verifies completion through
the private Wallet Bus. WalletConnect uses its own configured capsule adapter;
this extension edge does not run its SDK.

**Today.** The host prefers the unique `io.metamask` EIP-6963 provider, then the
unique `com.brave.wallet` provider. Discovery is capped at 32 entries and
conflicting identities fail closed. UniSat comes from top-level `window.unisat`.
The host returns error text, has frame-local busy state, and consumes approval
before account/network checks. The windows have separate 60-second timers.
Provider-state events, silent checks, progress and local stop are build work.

#### N2 closed messages

**After this work.** Only `wallet-metamask` and `wallet-unisat` may use this
edge. Keep the effect message type and use schema
`elastos.home.wallet-connector-effect/v2`. Its exact keys are `type`, `schema`,
`requestId`, `connectorId`, `connectorToken`, `parentOrigin`, `generation`,
`action`. Reject extra keys, arrays in place of objects and unbounded values.
`connectorId` must equal the Runtime launch record, not select an actor.
`connectorToken` must equal that record's current token. `parentOrigin` must
match Home's origin. A fresh, unpredictable generation belongs to one frame
registration and changes on retirement/replacement. Request IDs and generations
are 16 to 128 ASCII characters from `[A-Za-z0-9_-]`, generated with browser
crypto. Each accepted request ID is used once in that generation.

| Status | Exact action | Allowed effect and reported stages |
| --- | --- | --- |
| After this work | `{kind:"check"}` | Silent discovery and bounded account/network reads; `checking`, then `finished`. It opens neither an account prompt nor a signing prompt, creates no challenge and consumes no request. During a busy call it returns the last snapshot with `busy:true` without calling the provider. |
| After this work | `{kind:"link"}` | On the person's explicit action: `checking`, `choosing_account`, `waiting_signature`, `verifying`, `finished`. Home requests site accounts and signs only Runtime's single-use ownership challenge. |
| After this work | `{kind:"approve",approvalRequestId:id}` | `checking`, optionally `choosing_account` or `choosing_network`, `waiting_signature` or `waiting_transaction`, `verifying`, `finished`. Runtime selects the stored request and exact payload. |
| After this work | `{kind:"stop",effectRequestId:id}` | Ends only this frame generation's matching local wait. Returns `finished`; the target wait receives `stopped`. It has no extension revoke, disconnect, request rejection or transaction cancellation effect. A missing/already-ended target returns `request_unavailable`. |

**After this work.** `approvalRequestId` uses the N1 request-ID rule below;
`effectRequestId` uses the effect request-ID rule. No action accepts a provider
method, RPC parameters, network configuration, message, transaction, signature
or caller-selected deadline. Home accepts messages only from the registered
opaque `WindowProxy`, with `Origin: null`, the live generation and matching
launch context. Runtime checks current capabilities at each effect endpoint,
including completion; a browser check does not replace this validation. The
same validation applies to check and stop. Unregistered messages are ignored.
A registered caller with an invalid envelope receives only a fixed failure.

**After this work.** On validated frame readiness Home sends
`home:wallet-connector-ready`, schema `elastos.home.wallet-connector-ready/v2`,
with exactly `type`, `schema`, `connectorId`, `generation`. Results use type
`home:wallet-connector-effect-result`, schema
`elastos.home.wallet-connector-effect-result/v2`, and exactly `type`, `schema`,
`connectorId`, `generation`, `requestId`, `stage`, `deadlineAt`, `snapshot`,
`outcome`, `waitEnd`, `dispatch`. Progress has `outcome:null`; a final result
has `stage:"finished"` and one outcome below. `waitEnd` is `null`, `user` or
`deadline`; `dispatch` is `not_sent`, `handed_off`, `sent` or `unknown`.
`sent` means the provider call was made, not that the wallet accepted it.
Only Runtime completion can establish link/approval success. `deadlineAt` is a
positive safe integer while a timed effect is active, otherwise `null`. A
rejected request returns the empty snapshot (`null` provider/network, empty
accounts/alternatives, `unknown` availability/access, `busy:false`) rather than
reading a provider. Clients validate all fields,
the exact Home source/origin, generation and request ID before rendering.

**After this work.** A snapshot has exactly `providerId`, `alternatives`,
`availability`, `accounts`, `network`, `access`, `busy`. `providerId` is
`io.metamask`, `com.brave.wallet`, `unisat` or `null`; alternatives contain only
the other eligible stable identifier for that same connector, at most one.
UniSat has no alternative in this set. The stable identifier,
not EIP-6963's reload-dependent UUID, names the wallet. UUID and object identity
remain page-local conflict checks. Announced identity is self-asserted, not
extension authentication. Conflicts, duplicate identities and discovery
overflow return `failed`; Home does not silently choose another provider.
A vanished provider is checked again before another effect. Re-announcement
cannot prove that a disabled/re-enabled extension reinjected into the page.
Brave's configured-wallet behavior still requires real-wallet evidence.

**After this work.** `availability` is `found`, `absent`, `unavailable` or
`unknown`. `unavailable` requires a positive host fact that this enclosing
window cannot run these extensions, such as the native desktop wrapper's
fixed WebView configuration. A missing provider alone yields `absent`, with
one recovery instruction covering installation, disabled access and private
windows. An unclassified host remains `unknown`. Host classification takes an
explicit platform/host input owned by Home; a capsule cannot supply it.
The bare WebKit absence recording proves absence, not this classification.
Check again uses `check`; installing in Home's Browser cannot equip the
browser enclosing Home. WalletConnect navigation uses N1.

**After this work.** `accounts` is a validated list of at most 32 canonical
addresses, each at most 128 ASCII bytes; overflow or malformed data fails the
snapshot. EVM comparison is case-insensitive; Bitcoin comparison follows the
address encoding. `network` is a canonical `eip155:<positive decimal chain id>` with a safe-integer
chain ID,
Bitcoin's mainnet BIP-122 namespace, or `null` for unknown/unsupported values.
UniSat must identify `getChain().enum === "BITCOIN_MAINNET"`; `livenet` alone
is insufficient. Testnet and Fractal remain unsupported. EVM network changes
are facts; a supported change alone is not an error. `access` is `unknown`,
`available`, `empty` or `lost`. `lost` means a previously nonempty site-account
list became empty in this page, not a proven cause of that change.

**After this work.** Home forwards only these typed, validated facts and fixed
codes. It never forwards extension error text, announced names/icons, error
`data`, arbitrary strings, provider objects, signatures or payloads. Display
names and marks come from [N4](WALLET_PROVIDER.md#n4-wallet-name-and-mark).
Site-permitted EVM accounts are not the wallet's global selection. For approval,
Home uses the requested address if it is in the site's permitted list; for a
new link it uses the first returned permitted address and shows that choice.
An account switch does not change a stored link. Empty accounts cannot prove
lock or revocation. The recordings establish no reliable lock classifier;
the window may instruct the person to unlock/check the wallet while waiting,
but may not assert a `locked` fact.

| Status | Closed final outcome | Meaning / producer |
| --- | --- | --- |
| After this work | `done` | Check completed, or Runtime verified link/approval completion. A stop acknowledges its local effect only. |
| After this work | `declined` | The active provider call returned numeric `4001`; Home reports decline without inferring a native close-button action. |
| After this work | `account_not_authorized` | The active wallet call returned numeric `4100`: the site lacks this account's permission. |
| After this work | `account_mismatch` | The request's address is absent from a nonempty permitted-account list, or the signer changed before dispatch/verification. |
| After this work | `unknown_network` | An unresolved numeric `4902` after the fixed Runtime-configured switch/add sequence, an unsupported UniSat chain, or a network Home cannot safely identify/configure. |
| After this work | `wallet_busy` | This provider already has a Home call in flight, or the active call returned numeric `-32002`. Signing queues and UniSat's concurrent-connect anomaly are prevented by serialization, not assumed to return that code. |
| After this work | `no_wallet` | No usable allowed provider was found here; installation/disable/private causes remain unknown. |
| After this work | `extensions_unavailable` | Positive enclosing-host fact as specified above. |
| After this work | `stopped` | Home ended the local wait by user action or its deadline. An extension prompt may remain open. |
| After this work | `access_removed` | Previously available site accounts became empty. The window explains that access is no longer available and asks the person to check the wallet; lock and removal remain possible causes. |
| After this work | `unsupported_request` | The stored intent has no supported typed effect on this connector; leave it available for rejection in Wallet. |
| After this work | `request_expired`, `request_unavailable` | Runtime says expiry passed, or the selected request/stop target is absent, answered, consumed or outside this context. |
| After this work | `invalid_request`, `denied`, `replay`, `retired` | Exact shape/bounds, authority, used ID, or frame lifecycle check failed respectively. |
| After this work | `unsupported_kind`, `unsupported_version` | A valid registered caller asked for an unknown action kind or schema. No provider/Runtime mutation is made. |
| After this work | `failed` | All other failures, including malformed provider output, disconnected-provider codes or an unclassified error. Fixed local wording; no guessed insufficient-funds cause. |

#### N2 ordering, deadlines and lifetime

**After this work.** Home serializes all calls to a selected wallet provider
across connector frames in this Home page, including silent reads. It sends one
call at a time. There is one effect per frame; stop remains available during
that effect. A rejected concurrent attempt is not queued. Another Home tab or
browser has its own page state; Runtime's one-shot handoff still arbitrates the
same request. Home cannot promise a cross-tab extension mutex.

**After this work.** Before consuming approval, Home reads the canonical request
with `POST /api/apps/home/wallet-connector/approvals/:request_id/preflight`.
This is a fixed read adapter within N2's existing authority, not another capsule
kind or capability. Its exact body is the existing Runtime envelope: `schema`
(`elastos.home.wallet-connector.effect.request/v1`), `connector_id`,
`connector_token`. It uses the same Home-plus-connector validation as handoff.
The exact response keys are `schema`
(`elastos.home.wallet-connector.effect.result/v1`), `action`
(`approval_preflight`), `connector_id`, `request_id`, `request`, `evm_chains`.
`request` has exactly `request_id`, `status`, `intent`, `account_id`, `address`,
`chain_namespace`, `payload_hash`, `expires_at`. Runtime resolves the principal,
session, proof and grant internally and returns only that connector's matching
request. The hash is the same hash that handoff will bind; expiry is epoch
seconds. `evm_chains` uses the existing bounded Runtime chain-configuration
shape. This response stays in Home; the frame gets only its typed progress and
snapshot. The read creates no challenge, consumes nothing and returns no
signing payload. Unavailable, answered, expired and wrong-connector requests
produce a fixed failure before any provider prompt.

**After this work.** Home checks supported intent, site-permitted account and
network before handoff. An explicit Send may request account access or the
existing Runtime-selected EVM switch/add sequence first; check never prompts.
Network configuration comes only from Runtime. Re-read account/network after
any prompt, then recheck request state and bindings at atomic handoff. Empty
accounts, decline, mismatches, unsupported networks and preflight timeout leave
the request pending while its TTL allows. Home rechecks the typed handoff
against the preflight snapshot before the one signing or send call; a race
after handoff is an uncertain consumed request, not a retry. Runtime verifies
signer, payload hash, connector and expiry on completion.

**After this work.** At acceptance Home fixes one absolute `deadlineAt` in epoch
milliseconds: at most 60 seconds from acceptance for the entire link/approve
effect, at most two seconds for check, and earlier if launch, stored request or
challenge expiry requires it. Discovery, account choice, network choice,
signing and progress never restart the clock. Newly learned earlier expiry
can only shorten it. Home enforces the elapsed bound with a monotonic clock;
windows render the same deadline. Stop is immediate local control. A provider
promise may outlive this deadline: Home fences continuation after every await,
keeps the provider busy until that promise settles, and drops late signatures
and ownership proofs before verification. No later challenge, handoff, sign or
send may start for that retired effect. Already-committed Runtime work remains
authoritative; a reply arriving late cannot erase its receipt.

**After this work.** Once a transaction call was dispatched, stop/timeout leaves
`dispatch:unknown` and a Result unknown view. It never re-enables Send for that
consumed ID. A late transaction hash is retained only long enough to attempt
the existing Runtime completion under its original bindings and TTL; if Runtime
refuses it, success remains unknown and the person checks the outside wallet.
This does not extend an injected connector's completion TTL. WalletConnect's
existing different receipt rule is owned by
[Wallet Provider](WALLET_PROVIDER.md#first-shippable-slice). Late completion
refreshes authoritative state only; it does not reopen or resolve a retired UI
wait. Home reload cannot recover an extension promise and cannot prove that
an outside transaction stopped.

**After this work.** Home subscribes to selected provider `accountsChanged` and
EVM `chainChanged` / UniSat `networkChanged` for the active frame lifetime.
It sends unsolicited `home:wallet-connector-state` messages with schema
`elastos.home.wallet-connector-state/v2`, exactly `type`, `schema`, `connectorId`,
`generation`, `snapshot`. Validate event shapes and coalesce updates. A network
event triggers a serialized silent reread; UniSat's raw network string is not
a chain identity. During an outstanding provider call, mark affected snapshot
fields unknown and schedule at most one reread after settlement; do not overlap
calls. Events are hints, not authority or proof of lock, removal or signing.
Before another effect Home reads current state again. Event changes never
mint links or auto-send a request.

**After this work.** Discovery holds at most 32 provider entries for the page
lifetime. Frame registration holds its token, generation, last validated
snapshot and at most 64 used request IDs for five minutes. At capacity return `wallet_busy` for new effects until entries expire, keeping
unexpired replay protection. Reserve capacity for the active effect's stop;
repeating that stop has no further effect.
One busy-provider record retains only the original binding, dispatch state and
pending continuation until settlement or page unload; a stopped never-settling
call remains busy. Challenge/payload/signature bytes live only during their
needed step and are cleared at completion, failure or retirement. A pending
transaction continuation may retain only its original completion binding until
settlement or expiry. Home persists none of this in browser storage and logs
no extension material. Frame close, sign-out and shell replacement remove
subscriptions, tokens and UI snapshots and fence continuations; Runtime still
owns durable accounts/requests/receipts. Page unload releases all page memory.

**After this work.** A registered caller asking an unknown kind/version gets
the corresponding fixed outcome. A newer window waits at most two seconds for v2 readiness, then performs a
harmless v2 check with that generation. An already-open v1 Home has no v2
readiness. If it receives an unknown check/stop kind or v2 envelope, its current
handler returns the fixed v1 denial. The client discards that reply text and
uses `unsupported_version` reload guidance. Missing readiness or a missing
handler gives the same guidance after two seconds. It never falls back to a
v1 link/approve effect. The Clipboard purpose contract remains independent.

### Wallet window navigation (N1)

**Today.** Wallet opens the three connectors without a selected request ID.
Inbox can return to WalletConnect with an empty query. WalletConnect can open
only its exact internet entry in Inbox. Connector-to-Wallet/source-app routes
are absent. Wallet accepts `wallet_request` but lacks the activity query.

**After this work.** Extend only the rows below on `home:open-target`. All
messages have exact keys `type`, `target`, `homeToken`, `query`, except the
source-app row which also has `requestId`. Here `requestId` is the canonical
Wallet request ID, not an effect-message correlation ID. IDs in all these rows
match `[A-Za-z0-9:._-]{1,256}`, with no decoding, trimming or coercion. They are
selectors, never authority. Existing no-query Wallet connect messages remain
accepted only as the exact legacy empty-selection form. Runtime mints fresh
target-scoped authority; the source frame's token stays private to Home.

| Status | Source window | Target | Exact query / additional key | Home and target validation |
| --- | --- | --- | --- | --- |
| After this work | Inbox | Wallet | `{wallet_request:id}` | Read the principal's Runtime request, then select that ID. Existing Review in Wallet path. |
| After this work | Wallet | `wallet-metamask`, `wallet-unisat`, `wallet-walletconnect` | `{}` to connect; `{wallet_request:id}` to review | For a selection, stored `connector_id` must equal target. Preserve ID through Runtime launch, attachment and frame query or checked existing-window delivery. |
| After this work | Inbox | `wallet-walletconnect` | `{}` | Return after the exact internet decision; opens readiness, never resumes a dropped intent. |
| After this work | Any of the three connectors | Wallet | `{wallet_request:id}` | Stored request must belong to this principal and source connector. Wallet shows that record or a fixed unavailable result, never silently selects another. |
| After this work | Any of the three connectors | Wallet | `{tab:"activity"}` | Open the existing activity drawer even when requests remain pending. This row changes presentation only. |
| After this work | `wallet-metamask` or `wallet-unisat` | `wallet-walletconnect` | `{}` | Start QR connection only if configured/launchable. Transfer no request or signing authority to the other connector. |
| After this work | `wallet-walletconnect` | Inbox | `{notification_id:"walletconnect-internet:permission"}` | Exact existing internet entry only; no other notification ID. Permission behavior belongs to N5. |
| After this work | Any of the three connectors | Runtime-recorded source app | `{}` plus top-level `requestId:id` | Home reads the canonical principal-owned request, checks its connector matches the sender and derives `target` from stored `capsule_id`. The supplied target is only an equality assertion. Launch the currently admitted app with empty query; transfer neither request payload nor automatic retry. |

**After this work.** Each row checks the registered source WindowProxy,
`Origin: null`, live source launch token and Runtime capability before launch.
Missing records, wrong principal/connector/target, extra keys, arbitrary URLs,
noncanonical IDs and unlaunchable targets fail closed with fixed recovery
wording. A completed/expired record may select its result or source app while
Runtime still retains it; it grants no new signing action. A missing source
app returns an unavailable result and leaves Open Wallet available. Neither a
label nor a caller-supplied URL can identify the source app.

**After this work.** Connector attachment validation must admit only the
existing `home_origin` and optional validated `wallet_request` query, plus the
existing token fragment. Reused windows acknowledge the exact selected ID with
their current document nonce; failed delivery is visible. No sibling receives
a source token. The GUI shell carries only validated presentation commands.
N3 owns the request view and rejection behavior:
[external account requests](WALLET_PROVIDER.md#n3-outside-wallet-requests).

#### N1/N2 enforcement, proof and review

**After this work.** Home's extension lane owns N2 envelope checks, provider
serialization and deadline/event handling in `home-wallet-connector-host.js`.
The Runtime/Inbox/Wallet/navigation lane owns N1 in `home-shell-host.js` and
Wallet, plus Runtime preflight/handoff/completion validation. The shared-view
and window lanes consume these contracts. Tests import real modules; the
scripted extension replays pinned recordings rather than invented lock/errors.

| Status | Required named tests | Run location / proof obligation |
| --- | --- | --- |
| After this work | `n2_closed_actions_and_frame_binding`, `n2_unknown_kind_and_old_home_reload` | Home lane, Node module tests plus headless opaque frames; forged source/token/generation, replay, extra fields and old-page probe cause zero provider effects. |
| After this work | `n2_recorded_provider_facts`, `n2_account_network_events` | Home lane, real host module with recording replay; changed UUID, permitted versus global account, empty accounts, 4001/4100/-32002/4902, queued signatures, UniSat chain enum and no lock inference. |
| After this work | `n2_preflight_before_handoff` | Home and Runtime lanes, real modules and server tests; wrong/empty accounts, network refusal, stale request and timeout leave handoff count zero and pending state intact. A concurrent handoff wins at most once. |
| After this work | `n2_one_deadline_stop_late_reply`, `n2_serializes_across_frames` | Home lane, controlled clocks and deferred provider replies; one 60-second budget across stages, stop at every await, late proof ignored, late transaction never resent, reopened frame remains busy. |
| After this work | `n1_navigation_rows_and_near_misses`, `n1_request_id_survives_launch_and_reuse`, `n1_source_app_from_runtime_record` | Navigation lane, real Home/Wallet modules plus headless frames; exercise every row, reject adjacent invalid rows, open actual activity drawer with a pending request, substitute source app/ID, and test missing/unlaunchable records. |
| After this work | `wallet_windows_state_producers_and_controls` | Shared-view and window lanes, built Home; import the design state list, reach every accepted state through its producer and press every control. Include no extension Disconnect and the actual selected/permitted account. |

**After this work.** These are delivery test names, not existing PASS claims.
Each lane records a fail-before/pass-after result for its new behavior; retain
existing authority tests that already pass. Integration runs them through the
behavior suite and the server/provider targets, then the installed journeys
specified in [Wallet Provider](WALLET_PROVIDER.md#wallet-connection-integration-proof).

**After this work.** Out of scope: generic RPC, direct capsule networking,
extension disconnect/revoke, automatic sends, a cross-browser lock, guessed
wallet lock state, additional connectors/chains, general Inbox presentation,
and new guest authority. Keep unproven states pending design/security disposition;
only Anders can remove a promised state from scope.

**After this work.** Human security review questions:

- Does the v2 frame/generation binding and legacy probe preserve the existing
  Home-plus-connector authority boundary at every entry?
- Does the fixed preflight read expose only the request facts this connector
  already has authority to read, with atomic handoff still deciding consumption?
- Is the busy lifetime and late-transaction completion policy sufficient to
  prevent duplicate sends after stop, reload and another frame's attempt?
- Is the positive host signal used for `extensions_unavailable` trustworthy for
  every supported wrapper, without treating provider absence as evidence?
- Do the N1 rows derive source-app identity and fresh target authority solely
  from Runtime records, including reused windows and expired requests?

## Passkeys And Sign-Out

Runtime owns principals, passkey records, session grants, revocation, and audit.
Home owns the browser sign-in prompt because WebAuthn is bound to the top-level
Home origin.

Only approved first-party targets may ask Home for fresh passkey authority.
Home binds that proof to the requesting capsule, operation, and request before
returning a new target-scoped token to the same source and origin.

Both shells can sign out. Browser `home-cli` sign-out is a launch-token-bound
terminal host intent; `home-gui` uses the same host message contract. Neither
shell owns or clears authentication state itself.

## First-run recovery and Profile sequence

For a new principal, Home presents Recovery Kit first and Profile second.
Runtime-owned `recovery_readiness` and `profile_readiness` facts decide the
state. System owns Recovery Kit creation and export; People owns the signed
Profile. Home only coordinates the visible sequence.

The first Profile must fail closed until Runtime reports that the principal root
is protected and a Recovery Kit has been handed to the person. The setup UI has
no skip authority. Closing or pressing Escape may leave a session reminder, but
it cannot mint readiness or bypass the People gate. Existing Profiles are not
retroactively treated as new first-run accounts.

The readiness projection and the first-Profile mutation gate must derive from
one recovery rule or be protected by an equivalence regression test. UI state,
browser storage, a successful route, or a downloaded filename is not recovery
authority.

## Recovery And Cleanup

Changing shells retires the previous root frame before the next shell becomes
active. CSS hiding is not an accepted lifecycle model for a live previous
shell. Home's browser-local active-shell hint may suppress a flash during boot,
but Runtime state remains authoritative.

If the selected shell fails to launch, Home shows the host-owned recovery
surface. Recovery can retry, return to `home-gui` through the Runtime shell
route, or sign out. It does not mount a hidden desktop as a fallback.

A saved shell that is no longer launchable (for example the Terminal view when
host developer mode is off) is not a launch failure: Runtime drops it from the
shell candidates and resets the saved choice, and Home switches to `home-gui`
through the same Runtime shell route, so every later load opens the Desktop.

## Verification

The minimum machine proof is:

```bash
node scripts/home-shell-bridge-smoke.mjs
node scripts/home-browser-context-smoke.mjs
scripts/home-browser-context-opaque-frame-smoke.sh
node scripts/home-clipboard-headless-smoke.mjs
node scripts/home-clipboard-source-gate.mjs
node scripts/home-shell-system-switch-smoke.mjs
node scripts/home-shell-switchback-recovery-smoke.mjs
node scripts/home-shell-unavailable-shell-fallback-smoke.mjs
node scripts/home-cli-browser-smoke.mjs
node scripts/wallet-connector-transaction-smoke.mjs
node scripts/check-product-data.mjs
node scripts/home-shell-objective-audit.mjs
(cd elastos && cargo test -p elastos-server test_home_launch -- --nocapture)
```

The contract audit `first_party_capsules_have_complete_projection_contract`
keeps shell-facing catalog facts aligned. Product acceptance additionally uses
`scripts/home-shell-objective-audit.mjs --require-complete` with hash-bound
operator evidence.

For a behavior-changing shell review, create a screen-capture-free artifact
path and validate it before the objective audit:

```bash
node scripts/home-shell-manual-ux-report.mjs --template
node scripts/home-shell-manual-ux-report.mjs --notes-template --out /tmp/home-shell-manual-notes.md
node scripts/home-shell-manual-ux-report.mjs --artifact-entry /tmp/home-shell-manual-notes.md
node scripts/home-shell-manual-ux-report.mjs --report-from-notes /tmp/home-shell-manual-notes.md --out /tmp/home-shell-manual-ux.json
node scripts/home-shell-manual-ux-report.mjs --input /tmp/home-shell-manual-ux.json
node scripts/home-shell-objective-audit.mjs --manual-ux /tmp/home-shell-manual-ux.json --require-complete
```

The notes-to-report command converts the reviewed notes, requires
`source.commit` to match the candidate, and records the absence of desktop
first-paint before Home CLI. Set `redacted=true` only after reviewing the notes
for secrets.
