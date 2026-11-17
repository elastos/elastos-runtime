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

**After this work.** The recovery surface and version-change advice follow
[payment-safe recovery](#n2-payment-safe-recovery). Outstanding payment work
takes precedence over a reload suggestion, including a generic host error.
Wallet-window Clipboard unknown-purpose recovery uses this same policy.

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

**Today.** The v1 edge accepts link and approve from registered MetaMask/Brave
and UniSat frames. Home selects the unique `io.metamask` provider, then the
unique `com.brave.wallet` alternative; UniSat uses `window.unisat`. Discovery
has a 32-entry bound and rejects conflicts. Home forwards bounded error text,
checks account/network after consuming approval, and can finish an answer after
the window's separate 60-second timer. WalletConnect runs its SDK in its own
opaque capsule. The following v2 rules are build requirements.

#### N2 readiness and authority renewal

**After this work.** All three connector documents install their listeners
first. After document load they send `home:wallet-connector-hello` to top-level
Home. Schema is `elastos.home.wallet-connector-hello/v2`; exact keys are `type`,
`schema`, `connectorId`, `connectorToken`, `parentOrigin`, `documentNonce`.
`documentNonce` is one crypto-random UUID per document, shared with that
window's N1 selection protocol. Home validates the registered WindowProxy,
`Origin: null`, exact target/token, parent origin and unexpired launch record.
It answers `home:wallet-connector-ready`, schema
`elastos.home.wallet-connector-ready/v2`, with exactly `type`, `schema`,
`connectorId`, `documentNonce`, `generation`. Generation is crypto-random,
16–128 ASCII characters from `[A-Za-z0-9_-]`.

**After this work.** The same hello nonce in the same frame-load epoch returns
the same generation. A new nonce retires the previous registration and fences
its effects; its outstanding provider call stays busy. Home also retires on
each frame-element load after the initial Runtime-routed document load;
about:blank does not establish a registration. The document sends
hello after its load task, and retries at 0, 500, 1,000 and 1,500 ms. A load
fence requires a fresh hello in the new load epoch; an old document's retired
nonce cannot revive its registration. Retain at most 64 retired nonce
tombstones per launched frame until frame removal or launch expiry; at capacity
require closing/reopening that frame rather than forgetting a live tombstone. Home answers only to the current source,
never by a registration-time push into `about:blank`.

**After this work.** At two seconds without ready, or on a v1-schema reply, the
window shows fixed `unsupported_version` recovery text under
[payment-safe recovery](#n2-payment-safe-recovery) and hides its
new N1 controls. It keeps listening: a valid late ready for its current nonce
removes that guidance and enables the rows. No effect or new N1 row runs before
ready, and no v1 fallback effect runs. WalletConnect receives this handshake
for navigation but remains excluded from the injected-provider effect set.

**After this work.** Renewal under the existing frame-authority renewal
protocol keeps document nonce, generation, used IDs and in-flight effect. Home uses the context's current token on each Runtime call;
a live-frame closure cannot keep using the old token. The transaction-only
continuation after frame retirement follows the retained-binding exception in
[N2 waiting](#n2-waiting-settlement-and-memory). Renewal must preserve principal,
session, proof, grant and actor; a change is retirement, not renewal. An expired
current launch retires registration and fences effects/events. Renewal after
expiry starts a new registration and never resumes an old effect.

#### N2 exact messages and results

**After this work.** `home:wallet-connector-effect` uses schema
`elastos.home.wallet-connector-effect/v2`. Exact keys: `type`, `schema`,
`requestId`, `connectorId`, `connectorToken`, `parentOrigin`, `generation`,
`action`. Effect IDs are crypto-random 16–128 ASCII characters from
`[A-Za-z0-9_-]`. Canonical account/request selectors use
`[A-Za-z0-9:._-]{1,256}` without trimming, decoding or coercion. IDs select
records and carry no authority. Home accepts only these exact action variants:

| Status | Action | Meaning |
| --- | --- | --- |
| After this work | `{kind:"check"}` or `{kind:"check",accountId:id}` | Silent read for a new link, or membership of the Runtime-resolved linked account. No prompt, challenge, handoff or link. |
| After this work | `{kind:"link"}` or `{kind:"link",accountId:id}` | Ordinary Connect wallet; the optional selector restores the same canonical account. Runtime admission precedes the first prompting call. |
| After this work | `{kind:"approve",approvalRequestId:id}` | Resolve the canonical pending request, preflight, consume once, then perform its one typed payload effect. |
| After this work | `{kind:"stop",effectRequestId:id}` | Stop this generation's matching local wait. It does not withdraw a wallet prompt or reject a Home request. |

**After this work.** Windows own person-visible Connect/Send/Stop controls.
Home cannot prove a click inside an opaque frame; capability checks and the
outside wallet's own confirmation remain the effect guards. A frame supplies
no method, parameters, message, signature, transaction or deadline. Restoring
access uses Connect wallet, which requests accounts; Check access stays silent.
A connector gives only the instruction text permitted by
[payment-safe recovery](#n2-payment-safe-recovery). Home/browser controls own reload;
there is no connector reload message.

**After this work.** Results use type `home:wallet-connector-effect-result`,
schema `elastos.home.wallet-connector-effect-result/v2`, and exactly these
11 keys: `type`, `schema`, `connectorId`, `generation`, `requestId`, `stage`,
`deadlineAt`, `snapshot`, `outcome`, `waitEnd`, `dispatch`. `outcome:null` means
progress; a non-null outcome is final. There is no `finished` stage. The final
`stage` is the last stage reached, so it also supplies the ended phase without
a redundant `endedStage` field. Home posts a stage before its associated call.

| Status | Stage | Associated work |
| --- | --- | --- |
| After this work | `checking` | Runtime admission/read, discovery and silent reads. |
| After this work | `choosing_account` | Every `eth_requestAccounts` or UniSat `requestAccounts`, including when an empty list requires access. This does not assert that a chooser is visible; the wallet may ask to unlock. |
| After this work | `choosing_network` | The existing Runtime-configured EVM switch/add sequence. |
| After this work | `waiting_signature` | The ownership-challenge or request payload signature call. |
| After this work | `waiting_transaction` | The transaction send call. |
| After this work | `verifying` | Runtime verifies proof or records completion. |

**After this work.** `dispatch` starts `not_sent`. Account reads, account
prompts and network prompts never change it. Approval becomes `handed_off`
when Runtime handoff returns. It becomes `sent` only at the ownership/payload
signature or transaction send call boundary. That means the call was made,
not that a signature, broadcast or chain confirmation succeeded. Only a
transaction whose send call was made and whose wait ended before Home
received its hash uses `unknown`. A known hash uses sent even if Runtime
recording fails. A later hash updates receipt state through the advisory,
without resolving the ended effect a second time. `waitEnd` is non-null only with `outcome:"stopped"`: `user` or
`deadline`. Final effect results retain the last absolute `deadlineAt`.

**After this work.** Check always ends at `stage:"checking"`,
`dispatch:"not_sent"`, `waitEnd:null`, with its original two-second deadline.
A check whose provider read passes its two-second deadline ends `failed` at
`checking`, with `snapshot.busy:true` and `availability:"unknown"`; the pending
read keeps its provider slot. Keep safely discovered providerId/alternatives,
but clear firstAccount, requiredAccountAvailable, network and networkIssue to
null and access to unknown. This proves neither absence nor a cause. A late read
does not replace that final result or install its expired account/network facts;
it releases busy and sends the settlement advisory below. A new check can then
read fresh facts.
A check accepted while its provider is already busy returns `outcome:"done"`,
`snapshot.busy:true` from this registration's bounded cache, with no provider
call. Both cases spend a request ID. Stop has all 11 keys: its own correlation ID, `stage:"checking"`,
`deadlineAt:null`, the current bounded snapshot, `outcome:"done"`,
`waitEnd:null`, `dispatch:"not_sent"`. The target effect separately ends
`stopped` with its last stage/deadline/dispatch. A missing or already-ended stop
target returns `request_unavailable` in that same stop shape.

**After this work.** Unregistered sources and invalid correlation IDs receive
no reply. A registered caller with a valid ID but malformed envelope gets a
fixed `invalid_request` result at `checking`, deadline null, empty snapshot,
waitEnd null and dispatch not_sent. Clients ignore failure-placeholder facts.
A valid busy refusal carries cached facts with the actual provider-busy flag;
capacity exhaustion alone may return host_busy with busy false. Every non-admitted link/approve refusal uses checking, deadline null, waitEnd
null and dispatch not_sent. Unknown schema/kind gets unsupported_version/kind;
extra keys get invalid_request. A v2 Home
answers an identifiable v1 effect caller in its exact v1 error shape (`type`,
`schema`, `requestId`, `connectorId`, `error`) with constant text
`Check your wallet and Wallet's activity before continuing.` and zero effects. New clients treat any such v1
reply as unsupported_version, without rendering its text.

#### N2 provider facts and closed outcomes

**After this work.** Snapshot keys are exactly `providerId`, `alternatives`,
`availability`, `firstAccount`, `requiredAccountAvailable`, `network`,
`networkIssue`, `access`, `busy`, `paymentPending`. Empty facts are null provider/account/network,
empty alternatives, unknown availability/access, null membership/networkIssue,
and the known busy and paymentPending Booleans. paymentPending is a
conservative page-reload safety bit, not proof that a transaction was sent.
It is true while Home holds any transaction-receipt slot or unsettled
transaction send call on this page, including another provider or retired
frame; reservation sets it before handoff. Ending delivery authority may
release the receipt slot while the send promise remains pending: its bounded
provider-busy record retains a transaction-call Boolean until settlement,
so paymentPending stays true even for a fresh frame in that interval. It is also true for a recipient when another live WalletConnect frame
could hold private payment work that Home cannot observe. A WalletConnect
recipient checks its own local handed-off state as well as this bit; Home's
generic recovery treats every such opaque frame as unknown. No new
WalletConnect reporting message is added. False is permitted only when Home
knows neither risk is present. It carries no request ID, account, hash,
extension identity or other frame's facts and does not serialize providers.
Failure-placeholder snapshots use false and are ignored; missing, stale or
untrusted payment safety is treated as unknown by the view.
A fresh registration whose selected provider is
already busy gets these empty facts with busy true, not the older frame's
account data. A call on another provider leaves its busy fact false.
Caches remain confined to their verified principal/session/connector and
canonical selector. They are observations, not signing authority.

**After this work.** `providerId` is `io.metamask`, `com.brave.wallet`, `unisat`
or null. The MetaMask connector may report only its selected MetaMask/Brave
provider and at most the other eligible EVM identifier in `alternatives`.
UniSat has no alternative in this set. A MetaMask check learns nothing about
UniSat or another connector's extensions. MetaMask remains preferred when both
EVM providers exist; a Brave-linked account then may be unavailable to this
selected provider. This is a known limit, not a wallet-selection API. Stable
identifiers name providers; EIP-6963 UUIDs and object identity are page-local
conflict checks, not reload-stable identity or cryptographic authentication.

**After this work.** `availability` is `found`, `absent`, `unknown` or
`unavailable`. Found means an allowed provider object is present; it does not
prove that its extension answers. A stale object can still announce itself.
A timed-out check reports unknown as specified above. This head has no trusted
wrapper fact for unavailable. In 2.0.2
`extensions_unavailable` stays in the closed outcome list but has no producer;
no lane infers it from user-agent strings, missing providers or Runtime host OS.
Until a wrapper supplies a reviewed fact, use cause-neutral absence and
[N1's restricted alternative](#n1-walletconnect-alternative).
Configured Brave behavior is still unrecorded.
Silent-method compatibility claims cover the recorded MetaMask/UniSat builds;
Brave needs its own recording before acceptance.

**After this work.** Home bounds its private site-account array to 32 canonical
addresses of at most 128 ASCII bytes each. Only `firstAccount` can carry an address across this edge, and only in a
new-link check/link without an account selector. It is null in linked-account
checks, restoration and approval. For a new link it is the first permitted
account, lower-case `0x` plus 40 lower-case
hex digits for EVM, or a validated Bitcoin address (lower-case bech32; base58
case preserved). `requiredAccountAvailable` is null with no selector; otherwise
it is membership of the Runtime-resolved required address. The full array never
crosses the edge. Account-to-confirm uses firstAccount from progress for a new
link, or the canonical required account for restoration. Capture that account once for the attempt; later facts never retarget an
active proof/request. EVM signing uses the bound requested address when it is
still permitted, even if the array order changes. Cards get stored
request/account details through their existing scoped Runtime reads.

| Status | Network read | `network` | `networkIssue` |
| --- | --- | --- | --- |
| After this work | Valid EVM chain ID | `eip155:<positive safe-integer decimal>` | null |
| After this work | UniSat `getChain().enum` = `BITCOIN_MAINNET` | `bip122:000000000019d6689c085ae165831e93` | null |
| After this work | `BITCOIN_TESTNET` | null | `bitcoin_testnet` |
| After this work | `FRACTAL_BITCOIN_MAINNET` | null | `fractal` |
| After this work | Any other/malformed UniSat enum | null | `unrecognized` |

**After this work.** `getNetwork()` and network-event strings cannot identify
Bitcoin mainnet. UniSat's three issue values stay distinct even if a design
later groups their screens. EVM ordering-only account changes do not imply
unavailability; membership decides. `access` is unknown, available, empty or
lost. For MetaMask/Brave, previously confirmed required-account membership
followed by an empty list yields lost/access_removed before the generic
account_not_authorized outcome. Otherwise a missing required account yields
account_not_authorized. UniSat empty accounts after linking always yield
empty/account_not_authorized, rendered as account not available, with no cause
claim. Lost resets only when a fresh read or prompted account response confirms
required membership; changing selectors resets the observation baseline.

| Status | Closed outcome | Meaning |
| --- | --- | --- |
| After this work | `done` | Check/control completed, or Runtime accepted proof/completion. |
| After this work | `declined` | Numeric wallet 4001 in the reported stage, including a recorded native notification close. It identifies neither a button nor the person's intent. |
| After this work | `request_not_authorized` | Numeric 4100; no account/method cause inferred. |
| After this work | `account_not_authorized`, `access_removed` | Account availability and precedence above; neither proves lock or revocation cause. |
| After this work | `account_mismatch` | The proof signer changed from the bound signer. |
| After this work | `unknown_network` | Unresolved 4902 after allowed switch/add, unsupported UniSat enum or invalid required network. |
| After this work | `host_busy` | Local serialization/admission capacity; it proves no wallet prompt. |
| After this work | `wallet_busy` | Actual -32002; the recorded connect case reports a request already open in the wallet. |
| After this work | `no_wallet` | No usable allowed provider found here; installation/private/disable causes stay unknown. |
| After this work | `extensions_unavailable` | Reserved; not producible in 2.0.2 without a reviewed wrapper fact. |
| After this work | `stopped` | Person stopped, or authoritative wait expiry passed; a prompt can remain open. |
| After this work | `unsupported_request`, `request_expired`, `request_unavailable` | Stored intent unsupported, expiry passed, or request/stop target unavailable. |
| After this work | `invalid_request`, `denied`, `replay`, `retired` | Shape, authority, used-ID or registration-lifetime refusal. |
| After this work | `unsupported_kind`, `unsupported_version` | Unknown action/schema; no effect. |
| After this work | `failed` | All remaining errors, with fixed local wording. |

**After this work.** Numeric codes, methods, error data and extension text stay
inside Home and off screen. Failures cross only as the closed outcome and phase; snapshots contain the
typed facts above. Provider objects, signatures, transaction hashes and
payloads stay private.
[N4](WALLET_PROVIDER.md#n4-wallet-name-and-mark) owns display identity.

#### N2 Runtime admission, preflight and errors

**After this work.** Every injected effect route requires Home's same-origin
launch authority plus the carried connector token for the same principal,
session, proof and grant, exact selected resource/actor, and Home authorizer.
Check/stop/events use the page registration and expiry checks, not a claim that
they make a Runtime call. Resolving an account selector uses the fixed scoped
read below. WalletConnect may use only the N1 read, not injected effects.

| Status | Fixed Runtime route | Exact body / success |
| --- | --- | --- |
| After this work | `POST /api/apps/home/wallet-connector/link/admit` | Base body `schema,connector_id,connector_token` plus `effect_request_id`. Result `schema,action:"link_admitted",connector_id,admission_id,expires_at`. |
| After this work | `POST /api/apps/home/wallet-connector/accounts/:account_id/preflight` | Base body. Result `schema,action:"account_preflight",connector_id,account`; account has exactly `account_id,address,chain_namespace`. Active principal-owned link and matching connector required. |
| After this work | `POST /api/apps/home/wallet-connector/approvals/:request_id/preflight` | Base body. Result `schema,action:"approval_preflight",connector_id,request_id,request,evm_chains`; request has exactly `request_id,status,intent,account_id,address,chain_namespace,payload_hash,expires_at`. Pending, unexpired, correct connector/session only. |

**After this work.** Base schema is
`elastos.home.wallet-connector.effect.request/v1`; success schema is
`elastos.home.wallet-connector.effect.result/v1`. These reads stay in Home and
return no signing payload to a frame. Network configuration is Runtime-owned.
Admission precedes every link account prompt, requires an active proof binding,
and binds the authority tuple and effect ID. An idempotent retry returns the
same admission/expiry. One unconsumed admission per launch lineage is retained
for at most 300 seconds; a fresh effect supersedes the older unused admission.
Its challenge and verify bodies carry `admission_id`; challenge expiry cannot
exceed admission expiry. Verification consumes proof/admission once and upserts
the canonical account, so a late/replayed response cannot add it twice.
[N4](WALLET_PROVIDER.md#n4-wallet-name-and-mark) names identity fields on verify
and any completion that links an account.

**After this work.** Approval preflight happens before any account/network
prompt or handoff. If its site-account list is empty, Home requests account
access, then rechecks required membership. It runs the existing approved EVM
switch/add sequence before handoff and rechecks account/network after prompts.
Wrong account/network, refusal, unsupported intent and expiry leave the request
pending while its TTL allows. Runtime atomically rechecks the immutable request
and consumes once. Home compares the handoff to preflight before its one payload
call. A race after consumption does not permit a second handoff/send.

**After this work.** For a wallet-metamask transaction only, the existing
POST /api/apps/home/wallet-connector/approvals/:request_id/handoff success
envelope has exactly schema, action, connector_id, request_id, handoff,
evm_chains and external_result_deadline_at. The last value is the positive
safe-integer epoch-second bound from the atomically approved stored record
defined in [N3](WALLET_PROVIDER.md#n3-metamask-transaction-results). Home retains
it privately; it is not the frame's wait deadline and never crosses N2.
Signature handoffs retain the six-key envelope without that field. Existing
typed handoff payload keys and schemas stay unchanged. A missing/malformed
bound after a transaction handoff prevents a send and offers Wallet/activity
recovery; it never triggers a second handoff.

**After this work.** Every `/api/apps/home/wallet-connector/*` failure, including
JSON rejection and the N1 read, has exactly
`{schema:"elastos.home.wallet-connector.effect.error/v1",code}`. No text/data or
additional fields. HTTP/code pairs are fixed below. Home maps by recognized
code, not English text or status alone; a missing/unknown/malformed body maps
to failed. Error codes are not rendered to the person.

| Status | HTTP | Runtime code | Home outcome |
| --- | --- | --- | --- |
| After this work | 400 | `invalid_request` | invalid_request |
| After this work | 403 | `denied` | denied |
| After this work | 404 | `request_unavailable` | request_unavailable |
| After this work | 410 | `request_expired` | request_expired |
| After this work | 422 | `unsupported_request` | unsupported_request |
| After this work | 422 | `unknown_network` | unknown_network |
| After this work | 409 | `conflict` | request_unavailable |
| After this work | 409 | `unsupported_version` | unsupported_version |
| After this work | 500 | `failed` | failed |

#### N2 waiting, settlement and memory

**After this work.** There is no 60-second link or approval timeout. Link has
one absolute deadline: the earlier of Home acceptance plus 300 seconds and the
Runtime admission/challenge expiry. Approval uses the stored request's own
expiry. Silent check has two seconds. Stages, account choice and unlock never
restart these clocks. Home posts checking immediately (deadline null until
approval preflight supplies it), bounds each Runtime admission/read to two
seconds, then reports the authoritative deadline in epoch milliseconds. A
newly learned earlier proof expiry can shorten, never extend, the link deadline.

**After this work.** A wallet answer received while Home still waits and the
request/admission remains valid counts, including the recorded 77/112-second
completions. Only stop or expiry ends that wait; expired/revoked launch authority
also ends registration, with retired outcome. Signature and link answers after
the wait ends are dropped. Transaction hashes follow the receipt-only rule
below, including after Stop, wait expiry or frame retirement. Launch expiry is separate from
`deadlineAt`: timely same-authority renewal keeps the wait deadline and does not
freeze it at the old token's expiry. If current authority expires first, Home
retires the registration; a later renewal cannot revive that effect.

**After this work.** Home sends stopped/waitEnd deadline for link/approve at
their deadline; check uses its failed result above. With
no first progress after two seconds, the window shows a communication warning
and keeps Stop available; it neither cancels automatically nor retries. After
known deadlineAt plus two seconds without a final result it displays the local
expiry fallback, preserving request identity and uncertainty. Late authoritative
receipts still refresh Runtime state. Stop or expiry fences every continuation
before another challenge/handoff/sign/send or proof verification. The
transaction-only receipt continuation is the stated exception: it records an
already returned hash and grants no further wallet effect. Already accepted
Runtime work can finish and its receipt remains authoritative.

**After this work.** One provider call at a time per selected provider
(`io.metamask`, `com.brave.wallet`, `unisat`) is allowed across all frames in
this page, including reads; calls to different providers do not block each
other. Another tab still meets Runtime's one-shot gate. An unanswered call
holds only its provider's slot until settlement or page unload. Link/approve
refused for that occupied slot return host_busy. Checks run only on open,
focus return and explicit Check access, with no interval polling. A window
skips every new check while one is in flight or its snapshot says busy; repeated
focus/check actions are discarded, not queued or given IDs. Release of busy
permits the next explicit/open/focus check, without an automatic retry.
Every accepted check, cached or not, spends one replay ID. Clients never reuse
an ID in a document. Home keeps at most 64 IDs per frame generation: inactive IDs for five minutes, active IDs pinned until the effect
and its outstanding call settle plus five minutes. Reserve one slot for the
active effect's stop; refuse new work instead of evicting live/pinned IDs.
Runtime proof/admission consumption and handoff provide the durable replay
fence independently of this bounded page cache.

**After this work.** Home sends provider-busy transitions only to registrations
watching that provider, using each registration's own cache and authority.
Busy is exactly occupancy of that provider's slot; another provider's call
cannot set it or cause a serialization refusal. Payment-safety transitions go
immediately to all three live connector registrations with each recipient's
own cache and computed bit; no other provider/account/network facts cross to
another connector. WalletConnect gets empty provider facts and busy false.
Frame load/removal also recomputes this risk. Immediately after ready, Home
posts one initial state with empty provider facts and the current busy/risk
bits, without a provider call. A window treats safety as unknown until that
current-generation state arrives. Type
is `home:wallet-connector-state`, schema
`elastos.home.wallet-connector-state/v2`; exact keys are `type`, `schema`,
`connectorId`, `documentNonce`, `generation`, `snapshot`, `settled`. Normally
settled is null. If a provider call outlives its stopped/expired effect or
failed check, or transaction receipt work outlives the ended wait, send exactly
one advisory to its still-live original registration when that work settles.
This includes Stop during verifying after the hash has already arrived:
`settled:{effectRequestId,result:"answered"|"declined"|"failed",receipt}`.
These three inner keys are exact. Answered means a successful provider return,
declined means 4001, failed means all other settlement. The visible 4001
wording is "The wallet did not approve this request."; it makes no claim that
the person selected Decline rather than closing a native notification.
receipt is exactly null, "recorded" or "recording_failed". It is non-null only
for a returned transaction hash: recorded means Runtime acknowledged its
receipt, recording_failed means the bounded submission sequence below ended
without acknowledgement while Home keeps the hash. Busy release is sent
immediately with settled null if receipt
recording is still running; the one advisory follows that recording result.
It carries no text, signature or hash and does not resolve the ended wait
again. Signature/link answers may produce late-ignored wording; a transaction
advisory with non-null receipt instead says the wallet returned a result and
offers Open Wallet. recording_failed adds fixed result-recording failure
guidance, never Result unknown or another Send for the consumed ID.
A replacement/reloaded generation receives only busy release and fresh facts,
not another generation's settled effect ID. With no live original generation,
that advisory is dropped.

**After this work.** Account/network events are validated hints. Home coalesces
ordinary fact changes for 100 ms, preserving order of busy/paymentPending transitions and the
one settlement advisory. EVM reordering emits a changed firstAccount in new-link contexts only. With
a linked/request selector, unchanged membership produces no account-loss state
and no ordering-only message; the list/order remains private. Network events schedule one serialized reread;
UniSat event strings do not replace getChain identity. During a provider call,
mark affected facts unknown and retain at most one reread. Events never link
an account or send a request.

**After this work.** While the continuation's delivery authority below remains
valid, a hash Home actually receives from a transaction send call is recorded
once through its bounded transaction-only submission sequence, whatever ended
the wait: Stop, request/wait expiry, frame close,
or retirement by load/reload or a new readiness nonce. Retain the last current
carried token and immutable consumed-request/payload-hash/signer/authority
binding independently of the frame generation. This continuation makes no new
provider call or handoff and sends no reply to a closed or retired frame.
Signature and link answers do not use it.

**After this work.** The continuation uses the same Home page,
principal/session/proof/grant and valid Home/carried authority. Runtime's
stored result deadline in [N3](WALLET_PROVIDER.md#n3-metamask-transaction-results)
limits acceptance independently of token expiry; a renewed token never extends
that deadline. It retains one received hash privately until Runtime acknowledges the receipt or that
authority/page ends; a frame-only retirement cannot clear it. Runtime's
receipt-only persistence and expiry handling are owned by
[N3](WALLET_PROVIDER.md#n3-outside-wallet-requests), not by a window timer.
Runtime stores an identical hash idempotently after this work; a different
hash for the same consumed ID is conflict, never another send. This is an
implementation obligation, not today's completion behavior. Receipt HTTP
failure keeps that bounded slot while its authority is valid; it does not
discard the known hash or retry the wallet. Reserve one of at most 64 transaction-receipt slots per
selected provider in this page before consuming a transaction request; at
capacity return host_busy with the actual provider busy flag and
paymentPending true, leave the request pending and use payment-safe recovery.
A receipt slot is released after acknowledgement, a failure before handoff,
or a settled provider error with no hash and no remaining send call, or at
authority/page end; frame retirement alone cannot release it. This bound does not block another provider or
account/signature operations. Receipt submission has a two-second HTTP timeout;
it is separate from the ended wallet wait and cannot authorize another send. A still-waiting effect reports failed at verifying on
the final receipt failure; an ended wait uses the closed receipt advisory
above. Sign-out, shell replacement, carried-authority expiry, page unload and
onRetire(reason=authority_changed) end the private continuation and its delivery
rights. authority_changed means the old principal/session/proof/grant/actor
binding was replaced; it neither transfers the hash nor adopts the new token.
Frame removal, frame reload/new readiness and same-authority renewal retain the
continuation as specified above. These events do not change Runtime's stored
waiting state or result deadline. Another session cannot inherit delivery.
Top-level Home reload destroys the page and any private pending/received hash;
a hash not recorded before that destruction cannot be recovered by this rule. WalletConnect retains its existing distinct
receipt rule in [Wallet Provider](WALLET_PROVIDER.md#first-shippable-slice).

**After this work.** A received hash triggers attempt 1 immediately. Only a
transport failure, two-second HTTP timeout or exact Runtime failed/HTTP 500
starts a monotonic retry timer: attempt 2 one second after the first failure,
attempt 3 five seconds after the second failure. There are at most three HTTP
submissions total per consumed request/hash, including timed-out attempts;
focus, reopening and repeated events add none. Each attempt uses the same
immutable binding/hash and currently valid same-authority token. A new attempt
checks authority and the stored result deadline first; denial, expiry, conflict
or any other closed error ends the sequence without another retry. At most one
client HTTP wait runs at a time; timed-out Runtime work may overlap a retry,
so identical completion must be atomic. A late acknowledgement prevents further
attempts.
An ambiguous timed-out submission may finish at Runtime; idempotent completion
makes a later identical submission harmless.

**After this work.** Receipt progress stays verifying while the sequence runs
and the original wait is live. Its final acknowledgement or exhaustion is the
single receipt result/advisory; Stop/expiry may end that wait earlier without
ending receipt-only work. If the sequence ends without acknowledgement, retain
the known hash in its bounded slot until acknowledgement or delivery authority/
page end; no fourth automatic attempt is made. Fixed guidance is "Your wallet
returned a transaction result, but Home could not save it. Check {wallet_name}
and Wallet's activity before making another payment." A retained known hash
uses recording_failed, including when Runtime's deadline later passes, rather
than claiming Home did not receive a result. No new send or connector switch
is offered. The joined transaction test covers loss of acknowledgement after
a successful save and every retry/authority/deadline boundary.

**After this work.** Discovery retains at most 32 page-local entries. Per-frame
facts, nonce/generation, replay IDs and one effect are cleared on retirement;
only the bounded nonce tombstones, provider-busy record and transaction
exception above can outlive it. No browser storage or logs retain extension material. A never-settled
call stays busy until page unload. Closing a wallet tab or side panel alone is
not proven cancellation; a native notification close may settle the promise.
Only actual settlement releases its provider slot.

#### N2 payment-safe recovery

**After this work.** Payment guidance takes precedence over every busy,
capacity, failed-check, unsupported-version, navigation-failure, generic host
and update/reload suggestion. A window treats payment as unresolved after its
transaction reaches dispatch handed_off, sent or unknown, or while a current
trusted snapshot has paymentPending true. Missing/stale/untrusted safety facts
are conservative: they do not permit reload advice. Home applies the same
guard to its own recovery surface across all outstanding page payment work.

**After this work.** For an unresolved payment, say "Check {wallet_name} and
Wallet's activity before making another payment." Use the fixed local name for
the selected provider (MetaMask, Brave Wallet or UniSat); a generic host with no
selected provider says "your connected wallet". Offer Open Wallet/activity
through the authorized N1 row when ready, otherwise explain how to open Wallet
from Home. This branch gives neither reload advice nor another connector,
including when host_busy came from receipt capacity with busy false. It never
offers Send for the consumed request. A known unrecorded hash uses the more
specific recording_failed sentence above.

**After this work.** Only a check, message or link context with trusted current
paymentPending false and no handed-off transaction may use the non-payment
busy instruction: "Answer or close the request in your wallet, or reload Home
with the browser's Reload control." After that message/link wait has ended,
replace "Answer" with "Reject" so a discarded signature is not requested.
A check can explain that no answer arrived; presence is not liveness. With
unknown safety or an unsupported old Home, show only the wallet/activity
guidance until safety is known. Reload remains instruction text, owned by the
browser, with no connector-triggered reload message. The narrow WalletConnect
alternative has the separate N1 predicate below.

### Wallet window navigation (N1)

**Today.** Wallet launches connectors without a selected ID; Inbox can return
to WalletConnect. WalletConnect can open its exact internet entry. New
connector-to-Wallet/source-app rows and activity selection are build work.

**After this work.** New requests use `home:open-target` with exact keys `type`,
`target`, `query`, `homeToken`, `requestId`, `documentNonce`. Here requestId is a
crypto-random navigation correlation ID, not a Wallet request selector. The
source-app row also has `walletRequestId`. Canonical selectors use the N2
256-character rule; navigation IDs/nonces use crypto UUIDs. Home binds source,
opaque origin, live token and current document; connector callers also require
v2 readiness. Existing exact legacy forms remain accepted only on today's rows.

| Status | Source | Target | Exact query / extra selector |
| --- | --- | --- | --- |
| After this work | Inbox | Wallet | `{wallet_request:id}` |
| After this work | Wallet | Any of the three connectors | `{}` to connect; `{wallet_request:id}` with stored connector_id equal to target |
| After this work | Inbox | WalletConnect | `{}` after internet decision; readiness only, not a retired intent |
| After this work | Any connector | Wallet | `{wallet_request:id}` belonging to this principal/source connector |
| After this work | Any connector | Wallet | `{tab:"activity"}`; open actual drawer even with pending requests |
| After this work | MetaMask | WalletConnect | `{}`; only N1's new-link alternative predicate below, configured target only, no request/authority transfer |
| After this work | WalletConnect | Inbox | `{notification_id:"walletconnect-internet:permission"}` |
| After this work | Any connector | Runtime-recorded source app | `{}` plus `walletRequestId:id`; supplied target is only an equality assertion |

#### N1 WalletConnect alternative

**After this work.** Offer WalletConnect only from the MetaMask connector for
a new link: no account selector, no selected wallet request, no prior handoff,
trusted current paymentPending false, live v2 readiness and a configured target.
Home checks the source's registered selection and payment state, not merely the
empty destination query, before accepting this row. UniSat has no such control
or row: its Bitcoin account cannot use this EVM-only connector. An account-bound
request/restoration and every post-handoff state keep their original connector.
Neither absence nor a failed/busy check relaxes these conditions. This is an
alternative way to create a new link, not a way to retry an existing payment.
A validly registered request that fails the source/selection/payment predicate
gets N1 reason denied; an unconfigured target gets target_unavailable.
n1_navigation_rows_and_near_misses covers every failed predicate, including
UniSat, a restored account, a selected request and post-handoff/receipt states.

**After this work.** Home resolves every selected request with one fixed read:
`POST /api/apps/home/wallet-connector/approvals/:request_id/navigation`.
Exact body is `{schema:"elastos.home.wallet-connector.navigation.request/v1",
source_id,source_token}`. The explicit source allow-list is wallet, inbox and
the three connectors. Runtime validates same-origin Home authority and the
carried source authority for the same principal/session/proof/grant. Connector
sources must match the record's connector_id; Wallet/Inbox retain only their
existing principal-scoped review rights. The response stays in Home and has
exactly `schema:"elastos.home.wallet-connector.navigation.result/v1"`,
`request_id`, `status`, `connector_id`, `capsule_id`. Connector ID may be null
for a managed record. Status is pending, approved, completed, rejected or expired;
dismissed WalletConnect transactions use rejected as today. Retained answered
and expired records are readable for navigation; missing/pruned/foreign records
all use HTTP 404/request_unavailable in the N2 error body. Navigation can
read retained same-principal resolved history from an earlier session, but
earlier-session pending selections are unavailable under
[session visibility](WALLET_PROVIDER.md#request-visibility-across-runtime-sessions). It cannot reuse
an earlier session's effect authority. This read returns no payload, signature or new
signing authority and accepts WalletConnect as well as both injected connectors.

**After this work.** The asking app comes from stored requested_by_actor,
projected as capsule_id. Source-app recovery derives the currently admitted
catalog target from it; it never launches home, any Runtime-recognized shell,
or the sender. It transfers an empty query, not a website URL or retry command.
The window owns one navigation per visible press; Home cannot prove that press.
Unlaunchable/missing targets leave Open Wallet recovery available.
[N3](WALLET_PROVIDER.md#n3-requester-and-site-provenance) owns the asking app;
[N7](WALLET_PROVIDER.md#n7-requesting-site-display) owns site display. Site text
does not change these navigation rows or their Runtime-derived destinations.

#### N1 existing-window delivery and refusals

**After this work.** The navigation lane owns `home-shell-host.js`, all
`capsules/home-gui/browser/**` including `shell-windows.js` and
`shell-wallet-rail.js`, Wallet and Inbox. It extends the existing Inbox/Wallet
selection protocol, rather than inventing a connector-only delivery path.
Each connector implements these exact target-substituted v1 messages:

| Status | Direction | Exact keys / values |
| --- | --- | --- |
| After this work | Window to parent GUI | `home:app-ready`: type,homeToken,documentNonce; same nonce as hello |
| After this work | GUI to window | `elastos.<target>.window-ready.request/v1`: type,homeToken,requestId |
| After this work | Window to GUI | `elastos.<target>.window-ready.result/v1`: type,homeToken,requestId,documentNonce |
| After this work | GUI to window | `elastos:<target>-chrome-command`: type,cmd,homeToken,requestId,documentNonce,sequence,expiresAt,query; cmd is review-request |
| After this work | Window to GUI | `elastos.<target>.window.result/v1`: type,homeToken,requestId,documentNonce,ok |
| After this work | Window to GUI on unload | `home:app-unloading`: type,homeToken,documentNonce |

**After this work.** Target is the exact capsule ID. Query is exactly
`{wallet_request:id}` for connectors; Wallet also accepts `{tab:"activity"}`
through its existing review-request command. Inbox keeps select-notification
and notification_id. Validate exact source, opaque origin, token, nonce,
strictly increasing safe-integer sequence, current frame/route and expiry.
The absolute navigation budget is 15 seconds from Home acceptance, including
the two-second Runtime read. GUI passes that same expiresAt (never a fresh
15 seconds) through delivery. Cold launch and reuse both preserve the ID;
attachment admits only home_origin, optional wallet_request and the token
fragment. Failure/expiry blocks late delivery and automatic retry. Token/route renewal
ends an unacknowledged navigation with delivery_failed; a late acknowledgement
is ignored and the person may retry with current authority. An already accepted
queued selection stays queued and uses the renewed token for its Runtime read.
Reload/new nonce fails old delivery, while N2 renewal itself preserves the
active wallet effect and generation.

**After this work.** A selection received during an effect is queued once,
acknowledged ok within the budget and visibly described as waiting for the
current action. It never changes that effect's account, payload or ID. After
the effect ends, re-read and display the queued record (or its unavailable
result); Send is always a separate action. A busy provider can keep Send disabled
after selection. The existing ok acknowledgement means selection accepted,
including queued selection, not proof of display or approval.

**After this work.** An empty-query row completes when GUI accepts its
launch/focus command; it does not require a selection acknowledgement from an
ordinary app. A row with selection waits for the acknowledgement above. Both
use the same total budget and accepted means admission, not visible completion.
For the Runtime navigation read, invalid_request, denied and unsupported_version
map to the same N1 reason. request_unavailable, request_expired and conflict
map to request_unavailable. Every other code, malformed/unknown error body,
transport failure or two-second read timeout maps to delivery_failed. These
mappings are covered by n1_navigation_read_all_connectors and
n1_refusal_result_to_source; neither error path retries automatically.

**After this work.** Home answers the requesting source frame with type
`home:open-target-result`, schema `elastos.home.open-target-result/v2`, exact
keys `type,schema,requestId,documentNonce,ok,reason`. Successful reason is
`accepted`; refusal reasons are `invalid_request`, `denied`,
`request_unavailable`, `target_unavailable`, `unsupported_version`,
`delivery_failed`, `timeout`. N1 has no busy reason: active-effect selections
are queued as above; other delivery refusal maps to delivery_failed. Home sends timeout at 15 seconds. The source
helper checks Home source/origin and its pending ID/nonce, then renders fixed
local recovery wording for that reason. It falls back to the same timeout
wording at 17 seconds if the reply is missing. Invalid IDs/unregistered sources
get no reply. GUI also retains its existing delivery-failure feedback. Fixed source-helper
copy is: invalid_request/denied, `Home could not open this destination.`;
request_unavailable, `This request is unavailable. Open Wallet to check it.`;
target_unavailable, `This app is unavailable. Open Wallet to check the request.`;
unsupported_version uses N2's payment-safe recovery (reload instruction only
in a proven non-payment check/message/link context); delivery_failed/timeout,
`Could not open this destination. Try again.` only when no payment guidance
takes precedence. Old Home cannot authorize new
rows; v2 connector controls stay hidden without ready.

#### N2 shell-host hook interface

**Today.** home-shell-host imports the effect handler and moves
context.walletEffectState during renewal. There is no exported v2 lifecycle
bridge. The navigation lane owns every edit to this file; the extension lane
owns home-wallet-connector-host.js and consumes the bridge below.

**After this work.** home-shell-host exports the following three functions.
At boot it passes exactly {readHomeWalletConnectorAuthority,
postHomeWalletConnectorMessage} to the extension module's
createHomeWalletConnectorHost(bridge), then calls
installHomeWalletConnectorHooks with the returned object once, before any
frame listener can deliver a wallet message. The factory does not install hooks. Injection avoids an
extension-module import of the UI shell host and lets its real-module tests
supply a test bridge.

| Status | Export | Promise |
| --- | --- | --- |
| After this work | installHomeWalletConnectorHooks(hooks) | Exactly onMessage, onFrameLoad, onRetire, onRenew, all functions; a second installation fails. Callbacks are synchronous. onMessage returns Boolean claimed; lifecycle callbacks return void. |
| After this work | readHomeWalletConnectorAuthority(frameHandle, loadEpoch) | Returns null for a removed/retired/expired frame or a different load epoch. Otherwise returns exactly connectorId, connectorToken, parentOrigin, expiresAt, authorityKey. Every live-frame Runtime call reads this afresh; a transaction continuation after frame retirement follows N2's retained binding instead. authorityKey is an opaque page-local identity retained only by same-authority renewal; it is not frame-provided proof or wire data. |
| After this work | postHomeWalletConnectorMessage(frameHandle, loadEpoch, message) | Returns Boolean delivered. Sends only N2 ready/result/state to the bound current WindowProxy using the opaque target origin, after rechecking epoch, source, current authority and retirement. The extension validates current nonce/generation and the closed message before calling it. Failed delivery has no fallback recipient. |

**After this work.** This bridge covers only wallet-metamask, wallet-unisat and
wallet-walletconnect; the reader returns null for every other target.
expiresAt is epoch milliseconds. authorityKey is an opaque object compared by
reference, kept inside Home. frameHandle is one opaque Home-owned object per
launched connector frame, stable across token renewal, separate from its
document loadEpoch.
loadEpoch is a non-negative safe integer, starting at zero for blank and
incrementing at each Runtime document load; exhaustion requires close/reopen.
The navigation lane creates/binds it only from the Runtime-authorized launch
and GUI frame record. The callback arguments and order are exact:

| Status | Callback | Navigation-owned trigger / extension-owned response |
| --- | --- | --- |
| After this work | onMessage(event, frameHandle, loadEpoch, data) | Home resolves WindowProxy, opaque origin, live exact token and target before delivery. Hello/effect read connectorToken, N1 continues to read homeToken. Route both wallet hello and effect, for all three connectors, before generic message fallthrough. True consumes every recognized hello/effect, including a refusal; false is only for an unrelated type and resumes existing dispatch. The extension owns exact N2 shape/nonce/generation validation and ready/result/state production. |
| After this work | onFrameLoad(frameHandle, loadEpoch, phase) | Home increments loadEpoch at frame-element load and calls before a wallet hello can register. Earlier messages cannot establish N2 readiness. phase is blank, initial or reload. Blank cannot register; initial is the first Runtime-routed load; reload is every later load and retires the old generation before a new hello. The extension owns generation/replay/fact state, not the iframe listener. |
| After this work | onRenew(frameHandle, loadEpoch) | After verified same-authority renewal, Home updates the token mapping and reader in place, then calls once. Handle, epoch and authorityKey stay unchanged. The extension retains generation, IDs and effects, updates the last-current token in any transaction continuation and reads the fresh token at the next Runtime call. An authority change uses onRetire instead. |
| After this work | onRetire(frameHandle, loadEpoch, reason) | Home calls once before removing the context. Reason is frame_removed, launch_expired, authority_changed, sign_out, shell_replaced or page_unload. Actual expiry has a timer and is also checked before dispatch/read/post. The extension fences effects/registrations synchronously. frame_removed keeps the permitted receipt continuation; every authority-ending reason, including authority_changed, ends delivery/continuation but leaves Runtime's stored waiting record unchanged. Provider-busy occupancy remains until its call settles or the page unloads. |

**After this work.** During onRetire only, the posting function permits one
terminal result with outcome retired and an empty failure-placeholder snapshot
to the original still-loaded document, even when its authority just expired.
That placeholder uses null provider/account/network/membership/networkIssue,
empty alternatives, unknown availability/access, busy false and paymentPending false; clients ignore
it as a fact source. This exception permits no ready, progress or state. Removed/reloaded documents
receive nothing. After the callback it refuses every post for that context.
A new hello nonce in the same load epoch is retired inside the extension host
before a replacement generation is issued; its old continuations cannot post.
The navigation lane owns wiring, ordering and expiry; the extension lane owns
its state machine. n2_shell_host_hooks_contract imports the real modules and
tests each callback, failed post and current-token read, including preserving
a transaction receipt across frame-only retirement.

#### Connector request feedback in view

**Today.** WalletConnect places wait/Cancel/status above its request list;
showStatus updates text without bringing it into view. A scrolled request can
complete while the person sees no result.

**After this work.** In all three connector windows, after Review/Send,
Stop/Cancel where offered, and every resulting success/decline/failure/unavailable
state, the current wait with its available way out and then the outcome are
in view without the person scrolling. This holds after list refresh/reflow and
from a request at the bottom of a long scrolled list. The exit remains usable
throughout the wait; status is associated with that request, not another card.
The design chooses the layout and focus treatment.

**After this work.** Test the actual app-frame viewport inside Home's smallest
supported 320 by 220 outer window (including chrome deductions), and a narrow
phone outer window of 360 by 640 CSS pixels, both themes and both pinned
Chromium/WebKit engines. Both sizes are in scope, including 320 by 220 even
though the design pictures do not cover it. Assert
visible bounding boxes and operable controls after the action and after each
asynchronous transition, not merely text present somewhere in the DOM.
walletconnect_request_feedback_in_view is owned by the WalletConnect-window
lane; extension_request_feedback_in_view is owned by shared view and runs
both MetaMask/UniSat consumers. Installed evidence uses the exact built assets.
This rule adds no control or layout design.

#### N1/N2 tests, ownership and review defaults

**After this work.** Home's extension lane owns `home-wallet-connector-host.js`;
Runtime/navigation owns home-shell-host and all Rust; its exact hook exports
are defined above. It owns the complete Home-plus-Runtime test row, including
the JS integration harness and Rust route/provider targets. Home extension
implements the imported host module; the Runtime/navigation owner joins and
reports both sides before those tests pass.
The shared-view/window lanes own clients. One fixture file,
`scripts/fixtures/wallet-connector-v2-messages.json`, contains valid and invalid
instances of every v2 hello/ready/effect/result/state/navigation-result message,
plus their exact stage/dispatch and N1 query examples. The real Home module
tests and every connector window test import that same file. It includes the
N4 wire examples linked from [N4](WALLET_PROVIDER.md#n4-wallet-name-and-mark)
and N7 valid/invalid private summary examples linked from
[N7](WALLET_PROVIDER.md#n7-requesting-site-display).
The first commit of the scripted-extension enabling lane creates this fixture
file, before the four build lanes start. That lane also owns the recorded
provider replay used by n2_stale_provider_check_and_reload_guidance; the shared
view does not own a second packet file. Home extension, Runtime/navigation,
MetaMask/UniSat windows, WalletConnect window and shared-view tests all import
this same file (Rust uses include_str plus serde_json). The integrator reviews
later fixture changes. This first file deliberately encodes draft N1/N2
messages before the human review; it is not approval to implement them.
[The lane gates](WALLET_PROVIDER.md#lane-start-gates-and-shared-file-order)
define permitted pre-review work and replacement of changed draft examples. Test authors retain existing
guards and use real modules, not extracted source.

| Status | Owner | Required named tests |
| --- | --- | --- |
| After this work | Home extension | `n2_closed_actions_and_frame_binding`, `n2_unknown_kind_and_old_home_reload`, `n2_recorded_provider_facts`, `n2_account_network_events`, `n2_one_deadline_stop_late_reply`, `n2_serializes_across_frames`, `n2_v2_message_fixtures_shared`, `n2_v1_on_new_home`, `n2_check_never_prompts`, `n2_ready_handshake_and_authority_renewal`, `n2_stage_dispatch_table`, `n2_busy_release_and_late_settlement`, `n2_capacity_and_stop_reserve`, `n2_walletconnect_frame_refused`, `n2_stale_provider_check_and_reload_guidance` |
| After this work | Runtime/navigation (single accountable owner; Home extension contributes its module) | `n2_preflight_before_handoff`, `n2_runtime_error_codes`, `n2_empty_accounts_prompt_on_send`, `n2_link_admission_before_prompt`, `n2_narrow_check_and_unisat_network_facts`, `n2_transaction_completion_after_frame_close`, `n2_shell_host_hooks_contract` |
| After this work | Runtime/navigation — N7 | Owns all Rust, Inbox and Wallet projection/consumer work and N7 producer/privacy/compatibility tests in [N7](WALLET_PROVIDER.md#n7-requesting-site-display); connector windows only render the field |
| After this work | WalletConnect window / shared view | `walletconnect_request_feedback_in_view` (WalletConnect-window owner), `extension_request_feedback_in_view` (shared-view owner, MetaMask/UniSat consumers) |
| After this work | Navigation and GUI | `n1_navigation_rows_and_near_misses`, `n1_request_id_survives_launch_and_reuse`, `n1_source_app_from_runtime_record`, `n1_old_home_rows_unavailable`, `n1_selection_during_active_effect`, `n1_refusal_result_to_source`, `n1_source_app_excluded_targets`, `n1_navigation_read_all_connectors` |
| After this work | Shared-view enabling lane (single accountable owner; all three window lanes contribute real-module cases) | `wallet_windows_state_producers_and_controls`; one joined three-window matrix using the common packets and actual producers |

**After this work.** n2_stale_provider_check_and_reload_guidance uses the
round-two retained/re-announced disabled MetaMask provider and its unanswered
RPC as its dead-provider replay. The scripted extension stalls the silent read
with a controlled pending promise, not an invented reply or lock diagnosis.
It proves the two-second failed/unknown/busy result, an independent UniSat
call, focus deduplication without spent IDs, late read settlement without stale
facts, and fresh discovery after top-level Home reload in a proven non-payment
context. It also proves both guidance branches: checks/messages/linking with
paymentPending false have browser-owned reload recovery; handed-off/sent/unknown
transactions, retained slots (including busy false at capacity), retired-frame
payment work (including an unsettled send after authority end released its
receipt slot) and unknown safety have wallet/activity guidance, zero reload
advice and zero alternative-connector controls. Cover unsupported-version,
navigation failure, update and generic host recovery, not just the busy card.
The shared packets include paymentPending transitions and ignored placeholders.
Home extension is the single accountable owner of n2_v2_message_fixtures_shared;
every real Home/window test imports it and contributes to that one matrix.
n2_serializes_across_frames covers both same-provider serialization and
different-provider independence; n2_stage_dispatch_table covers final phases
and check/stop shapes; n2_busy_release_and_late_settlement covers the one
advisory and its receipt variants. Each consolidated name owns all cases of
its former pair.

**After this work.** These names are lane obligations, not results. JS tests run
in the behavior suite; server/provider tests run all targets under the shared
lease and release CI. Pending real-recording cases are listed in
[Wallet Provider](WALLET_PROVIDER.md#wallet-connection-integration-proof).
Out of scope: generic RPC, cross-connector discovery, full account disclosure,
connector reload authority, extension disconnect, new guest authority and
additional signing methods. Irzhy reviews the existing dual authority boundary,
the narrowed check and source-app row before code unless Anders waives. A wrapper
signal and wider check disclosure remain human review questions; defaults are
no unavailable producer and first-account/membership only.

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
