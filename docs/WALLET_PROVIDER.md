# Wallet Provider

Status: unmarked sections describe **today**. N3, N4 and N5 distinguish
**today** from **after this work**; future requirements are build contracts,
not installed-product acceptance.

`wallet-provider` is the blockchain-quadrant authority boundary for wallet
proofs, account links, approvals, typed signatures, and transaction requests.
It is not the Runtime root of identity and it is not an app SDK.

The contract is:

`signed launch-token v4 -> verified RuntimeWalletAuthority -> private RuntimeWalletAdapter -> WalletProviderRequestV2 (Wallet Bus 2.3) -> wallet-provider`

Capsules never receive private keys, browser wallet objects, raw wallet RPC,
node RPC, seed phrases, or provider SDK handles. A wallet address is a proof
binding on a Runtime principal, not the principal itself.

The generic provider plane exposes only read-only
`elastos://wallet/meta/status`. Generic HTTP, component/Carrier, attached
component, capability-request, and Inspect callers cannot select a principal,
forward a local bearer token, dispatch `wallet_contract`, or request any Wallet
account, proof, approval, signing, secret, Recovery, or transaction operation.

## Authority Model

Runtime authority comes first:

1. Runtime principal
2. Verified proof binding
3. Short-lived session grant
4. Scoped capability
5. Provider-mediated effect
6. Signed audit event

Wallets, Essentials, EVM accounts, BTC accounts, EID, and UniversalX are proof
or signing adapters behind that model. They must not mint Runtime principals,
sessions, or privileged capabilities directly.

PC2's wallet bridge is useful reference material for method classification:
wallet reads, wallet signing, and network RPC are separate authority classes.
Runtime should reuse that classification as provider tests and connector
behavior, not by injecting a broad EIP-1193 wallet object into ordinary app
capsules. Browser wallets belong in dedicated connector capsules such as
`wallet-metamask` and `wallet-unisat`; built-in wallet authority belongs in
`wallet-provider`. External wallet links carry an explicit `connector_id`, and
external approval completion fails closed if a different connector tries to
finish the request. Opaque connector frames initiate the fixed link or approval
intent, while the trusted Home host owns only the top-level injected-provider
effect; System does not initiate wallet-link ceremonies.

## User-Facing Wallet Ontology

The product surface should present one Wallet, not separate wallet products
named after connector tools such as MetaMask, WalletConnect, Bitcoin signing,
or the built-in key store. The user model is:

- **Account**: a balance/address surface for one network or account group.
- **Approval method**: the way an action is authorized, such as passkey,
  MetaMask, WalletConnect, Essentials, Ledger, or a Bitcoin wallet signature.
- **Connected wallet/device**: a specific external tool that can serve as an
  approval method.

Implementation nouns remain stricter: provider code may use `signer`,
`connector_id`, proof binding, account ID, and chain namespace. UI copy should
prefer Wallet, Account, Approval, and Connected wallet unless the user is in a
specialized connector flow where the exact external tool matters. Connector
capsules are on-demand approval surfaces; they should not compete with the
single Wallet mental model.

The visible Home launcher surface is `Wallet`. It summarizes accounts, native
balances, pending requests, defaults, and approval methods. Connector capsules
such as MetaMask, UniSat, and WalletConnect remain launchable only as approval methods
from Wallet flows, not as separate top-level wallet products. Built-in
Bitcoin accounts live beside EVM accounts in Wallet; external Bitcoin approval
tools remain connector methods. The connector frames remain opaque and never
receive browser-extension provider objects. For injected MetaMask/Brave and
UniSat, a closed connector intent asks the trusted top-level Home host to perform
the exact Runtime challenge or typed approval effect. WalletConnect retains its
configured connector-owned adapter path.

## Storage

Wallet state belongs in runtime-managed provider storage, not browser local
storage and not app capsule storage:

`localhost://ElastOS/SystemServices/Wallet/...`

The current implementation stores linked-account metadata, default-account
preferences, encrypted managed EVM wallet envelopes, pending SIWE proof
challenges, and typed wallet approval requests in `wallet-state.json`. Account
records and defaults are keyed by `principal_id`; proof challenges are
short-lived, single-use, and bind the exact challenge resource.
The typed `RequestApproval` operation records a pending approval for an allowed
intent and returns no signature. Runtime resolves and supplies the exact
principal-owned account, chain namespace, intent, resource, reason, payload, and
expiry before invoking the private adapter.

Built-in wallet keys are provider-owned and encrypted at rest under
`localhost://ElastOS/SystemServices/Wallet/wallet-key.hex`. They are
passkey-controlled, not passkey-derived: a long-lived Wallet/System/Inbox launch
token may list and review requests, but every built-in signature, transaction
send, account deletion, and Wallet recovery-key export/import must include a
fresh passkey-bound Home token before the provider uses or changes key material.
App capsules never receive the private key, wallet object, or raw wallet RPC.
External wallets still use the same approval request and completion receipt
shape, but the final signature is completed by the connector capsule that owns
the linked account.

Full Recovery Kits and individual Wallet recovery keys are intentionally
different. `elastos.recovery-kit/v1` restores the encrypted user root and every
recoverable built-in Wallet key included in the exported bundle. External
wallets such as MetaMask, WalletConnect, Ledger, Essentials, and UniSat restore
only their links/metadata because their private keys stay in those wallets.
`elastos.wallet.recovery-key/v1` remains an advanced per-account escape hatch
for one built-in wallet key. An old managed account whose key cannot decrypt on
the current Runtime must remain fail-closed until a full bundle or that account's
Wallet recovery key is imported or a replacement account is created.

Future DID anchoring may publish recovery or credential metadata, but local
Runtime state remains the operational source for current sessions. DID-backed
recovery proofs belong behind `did-provider` and Recovery Kit import authority,
not in approval-method connector capsules. Current import consumes a DID proof
only as a provider-verified protector check for an existing recovered root;
DID-only recovery still needs a DID-envelope unwrap/rewrap path.

## Operations

The public provider surface is intentionally limited to one operation:

| Operation | Capability resource | Action | Purpose |
|-----------|---------------------|--------|---------|
| `status` | `elastos://wallet/meta/status` | `read` | Report bounded provider identity, version, and adapter status without principal data |

All principal-sensitive work uses the private Runtime-local Wallet Bus 2.3
envelope. Runtime derives `RuntimeWalletAuthority` only from a successfully
validated signed launch token, constructs `WalletProviderRequestV2`, and
dispatches a typed `WalletProviderOperationV2` through
`RuntimeWalletAdapter`. The typed variants cover account reads and writes,
proof challenges and verification, approval lifecycle operations, validated
chain-outcome projection, and managed Recovery import/export. They are not
generic provider methods or capsule capability resources.

Generic `wallet_contract`, legacy proof/account/approval/signing/secret/Recovery
names, signing URI derivation, and Wallet transaction prepare/broadcast all fail
before provider invocation. Transaction prepare and broadcast remain typed
`chain-provider` effects; wallet-provider owns proof bindings, approval state,
managed signing, and connector completion receipts.

Wallet owns accounts, approval methods, built-in send, and recovery-key
actions. `POST /api/apps/wallet/wallet/managed` creates or returns the
principal's built-in managed wallet accounts for the supported default
networks: ESC, Base, and Bitcoin mainnet. The same provider-owned key is reused
across EVM namespaces so ESC and Base show one coherent built-in wallet address;
Bitcoin uses a separate provider-owned P2WPKH key scope instead of reusing the
EVM key.
`POST /api/apps/wallet/wallet/default` selects the principal's default linked
wallet for a chain and intent. The setting lives in `wallet-provider`; Wallet
only renders the choice and cannot take over MetaMask, WalletConnect, or the
built-in wallet authority.
Inbox is a review surface: it can show and reject pending wallet requests, but
built-in signing routes back to Wallet so the user performs a fresh passkey
ceremony at the moment of use. `POST
/api/apps/wallet/wallet/approvals/:request_id/approve` approves managed wallet
requests only when a fresh passkey-bound Home token is supplied; the provider
then signs inside the wallet boundary and stores a receipt. External injected
wallets are handled by dedicated opaque connector capsules plus the trusted Home
host. MetaMask/Brave and UniSat frames can read their Runtime account and
approval summaries, but their only effect request is the closed
`home:wallet-connector-effect` contract. Runtime's Home connector endpoints
validate exact same-origin Home authority and a carried connector launch token
for the same principal, session, proof, and grant before issuing a challenge or
typed handoff. Home alone calls the top-level injected provider and returns only
status to the connector frame. The generic direct connector completion path
remains for configured WalletConnect, and only explicitly allowlisted
connectors can use it. Wallet and Inbox can reject pending requests.
App capsules still cannot call wallet RPC or receive signatures without the
provider approval path.

For built-in EVM transaction requests, wallet-provider only signs
`elastos.chain.unsigned_transaction_intent/v1` payloads produced by
chain-provider with `transaction_type=eip155_legacy`, nonce, gas price, gas
limit, chain ID, from, to, value, and data already bound. Incomplete or
cross-chain transaction intents fail closed before an approval request is
created. External wallet transaction signing remains connector-owned; a normal
MetaMask SIWE link is not treated as transaction-signing support until the
connector has a real transaction handoff.

For built-in Bitcoin proof requests, wallet-provider only signs
`elastos.wallet.bitcoin_bip322_request/v1` payloads that bind the managed
P2WPKH address, the Bitcoin mainnet BIP-122 namespace, and an exact Runtime
Bitcoin challenge resource. Arbitrary messages and non-Runtime challenges fail
before approval.

External Bitcoin proof requests use the same approval contract. For UniSat,
Runtime returns the exact typed Bitcoin proof handoff only to the trusted Home
bridge; Home asks the top-level provider to sign that message and completes the
approval only after wallet-provider verifies the signature against the linked
address, selected proof type, and stored Runtime challenge. Neither Wallet nor
the opaque connector frame handles a free-form message or returned signature.

Wallet price data is also treated as an external effect. The temporary
CoinGecko HTTP source is disabled until Wallet raises an Inbox request and an
admin approves the local price-source policy. Actual HTTP fetch attempts then
emit `wallet.price_source.fetch.*` audit events for requested, completed, or
failed/blocked use. The target remains a typed oracle/price provider with
signed receipts instead of a raw HTTP dependency.

There is no `sign(data)` operation. Signing intents must bind principal,
proof binding, capsule, provider, chain/network, resource, nonce, expiry, and
reason. The account is either the principal's explicit default for the named
chain and intent or an explicit account that belongs to that same chain. Valid
intents include auth challenge, capability grant, credential, publish envelope,
transaction intent, Bitcoin BIP-322 proof, and revocation.

## First Shippable Slice

The default wallet path is now:

`passkey unlock -> open Wallet -> create built-in managed accounts -> view native balances -> select default -> app requests typed signature for chain + intent -> Wallet/Inbox review -> fresh passkey approval in Wallet -> wallet-provider signs inside its boundary -> signed audit/receipt`

The optional injected-wallet path is:

`passkey unlock -> open opaque approval-method connector capsule -> send one closed link intent to trusted Home -> Home discovers exact MetaMask or Brave fallback -> Runtime validates matching Home + connector launch-token v4 authority -> Runtime issues SIWE challenge -> Home signs only that challenge -> wallet-provider verifies and links account + connector_id to the existing principal -> audit -> revoke -> prove replay/expiry/wrong-chain/wrong-origin/wrong-connector fail closed`

The built-in Bitcoin proof path is now:

`passkey unlock -> create built-in managed Bitcoin wallet -> Runtime issues BIP-322 challenge -> app requests typed bitcoin_bip322_proof -> Wallet/Inbox review -> fresh passkey approval in Wallet -> wallet-provider signs inside its boundary -> signed audit/receipt`

The optional external Bitcoin proof path uses the same connector boundary:

`passkey unlock -> open opaque UniSat connector -> send one closed link intent to trusted Home -> Runtime validates matching Home + connector launch-token v4 authority -> Runtime issues the address-selected Bitcoin proof challenge -> Home asks top-level UniSat to sign that exact challenge using the selected proof mode -> verify through wallet-provider -> link BTC proof binding to the existing principal -> audit -> revoke`

For approval-gated Bitcoin proof signing after a BTC address is linked:

`app requests typed bitcoin_bip322_proof -> Wallet/Inbox review -> opaque UniSat connector requests exact approval id -> Runtime gives trusted Home the typed handoff -> top-level UniSat signs the exact Runtime proof message using the selected proof mode -> wallet-provider verifies and records a signed receipt`

The provider issues and verifies the SIWE proof challenge, and the browser EVM
wallet-link route uses that provider only after an active passkey-backed Runtime
session exists. Runtime links the wallet proof binding to that existing principal
and audits/revokes the link; the wallet proof must not mint a Home session by
itself. SIWE messages preserve the wallet-reported address display form for
wallet UX compatibility while Runtime verification normalizes addresses for
cryptographic comparison and proof IDs. Wallet approvals now have review,
approve/reject, managed signing,
dedicated MetaMask and UniSat connector handoff completion, connector-bound receipt
storage, and signed runtime audit scaffolding. An approval that expires before
managed signing or external handoff completion fails closed instead of becoming
a stale signing authority.

SDK availability checks share a verified-result cache. Async HTTP handlers run
verification in the blocking pool. Synchronous setup and CLI callers hash inline. Async package inventory and
local Exit callers yield while the blocking pool verifies the SDK. The cache checks the current
config on each admission. A changed pinned digest, SDK size, modification time,
or file identity invalidates the entry; Unix identity includes device, inode,
and change time. Missing or invalid files fail closed. Runtime restart clears
the cache, and it retains at most 16 SDK paths. Matching and mismatched hashes
share the same file-stamp and pin invalidation rules. Metadata before and after
hashing comes from the same open file handle. Existing admitted relay frames
keep their original admission; new admissions check the current files.

WalletConnect is a dedicated connector capsule (`wallet-walletconnect`). The
reviewed Reown SDK and its bundled QR renderer run only in that capsule's opaque
sandboxed frame. `wallet-provider` owns proof verification, linked accounts,
approval state and receipts. Runtime accepts the connector's own live launch
capability, bound to its principal, session and launch instance, for storage,
relay admission, linking and signing handoffs. Each route checks the selected
connector resource and proof binding. Config reads, linking, approval, completion
and storage deletion accept an older storage revision with these launch checks.
A connector can load the current revision, retain a returned result or retry
cleanup. Relay use and storage writes require
the current revision. Home owns window orchestration.

The relay-only adapter returns an empty optional Reown Verify website
attestation. That service uses direct HTTP and iframes outside Runtime's relay
route. Runtime verifies the linking signature and each approval binding; a
phone wallet may show the Home origin as unverified.

Mode A connects a phone wallet to sign Runtime challenges and approved requests.
Mode B, where external dApps use ElastOS as a WalletConnect wallet, requires its
own security decision. The phone holds signing keys and confirms each request.
Isolation protects Home. A compromised SDK still holds its pairing session and
could ask the phone to sign a different request; the phone's confirmation is the
last guard. Signup and sign-in remain candidates for the separate first-run
authority decision.

Runtime supplies the exact principal, requesting actor, account, chain, payload
hash and expiry. It checks pending state before handing off once, and checks the
approved request and hash before completion. A closed connector window leaves an
approved, unfinished transaction visible with "Check your phone wallet". Opening
it again supplies recovery instructions and keeps the send control disabled.
A returned transaction hash is passed to Runtime once even if the account,
network or expiry changed during the phone prompt. An approved WalletConnect
transaction can complete once within 24 hours after expiry, in the same Runtime
session. Wallet keeps an approved WalletConnect transaction in its request list.
Its owner can use Dismiss in Wallet to close it and release its approval slot,
in the same Runtime session or a later session. System and Inbox list pending
requests only. Runtime accepts dismissal through their owner-authorized actions
if a pending card remains on screen after WalletConnect approves the send.
The connector and requesting app keep their original authority. The requesting
app keeps its rejection after dismissal. Completion keeps its original session
binding. Dismiss does not cancel a phone transaction.
Runtime records one hash returned within the same grace period after dismissal,
with the normal completion bindings. The request stays dismissed; Activity shows
"Sent from wallet after request was dismissed" with the hash and a sent mark.
Runtime logs `wallet.approval.sent_after_dismissal` for this receipt, and the
connector reports "Request dismissed. Transaction sent from wallet."
An unfinished prompt expires after the grace period; other connectors keep their normal TTL.
Runtime checks the returned
transaction hash's format only. The phone wallet confirms the transaction;
the hash alone does not prove that it matches the approved payload. A completion error keeps the
hash visible for checking before another send. Unused signatures and ownership
proofs stop when their account, network or expiry changes. Typed-data requests
stay pending because this connector's reviewed bundle does not support that method.

The capsule installs `walletconnect-storage.mjs` before importing the pinned SDK.
Browser Storage holds UI preferences in memory and resets on reload. Protocol
and keychain names raise `SecurityError` there. Runtime's private key/value store
holds pairings, sessions and cryptographic keys, selected by the verified
principal. The SDK uses the constant context `wallet-walletconnect`; Runtime's
principal boundary separates each person's files. The connector supplies no
session migration. Disconnect clears session storage and the memory shim while
linked accounts stay in Wallet. Revocation clears session files; linked
account removal clears the account owner's file after the last active WalletConnect
account is removed. Other linked accounts keep their pairing. Principal removal
clears that principal's file.
A cleanup failure after account or principal removal leaves that change saved
and records an operator-retry warning. Successful cleanup advances a Runtime
storage revision that fences late writes and relay use from an old SDK
instance after cleanup. Reopening the connector starts a fresh instance.

Inbox owns internet consent through one request and the owner's passkey. Allow
returns focus to the connector; the same Inbox entry offers Turn Off. Runtime
admits only the opaque connector's single-use relay ticket, caps waiting sockets,
rechecks the launch and owner on each heartbeat and outbound frame, authenticates
relay TLS, and limits frames and sockets. It reaches only
`relay.walletconnect.org` and `relay.walletconnect.com` on TLS port 443 through
a local Exit backend and its separate adapter and relay sockets. When Browser's
local Exit helper starts successfully, the first matching existing backend takes
precedence; the default Browser wildcard therefore carries the relay. WalletConnect's
backend handles requests those backends do not match. When the Browser helper stays
stopped or fails to start, WalletConnect's relay-only backend precedes the generated
Browser backend for these two TLS hosts. Operator backends keep their order and
first match. Exit configuration refresh uses the same merge and checks the Browser
relay helper at that moment. Retained Browser backends keep their matching for
other traffic, including on older linux-amd64 Homes with a wildcard Browser config.
Runtime validates the merged configuration with
exit-provider's parser and keeps the existing Exit configuration if the addition
is refused. Turn Off cancels handshakes and open sockets. Hosted Carrier Exit
selection remains a separate integration.

The native-Storage comparison and deterministic sandbox test cover Chromium and
WebKit. The opt-in real-relay test, selected with
`ELASTOS_WALLETCONNECT_PROJECT_FILE`, separately checks pairing, page reload and
a fresh source-gateway process restart. Installed desktop acceptance and a real
phone wallet require their own evidence.

The connector is installed with Home and stays hidden and unroutable until
`elastos.walletconnect.connector/v1` configuration and the matching hashed local
SDK asset exist. `scripts/vendor-walletconnect-adapter.sh` uses `npm ci` with the
complete dependency lock in `scripts/walletconnect/package-lock.json`. It builds
the `connectWalletConnectEvm` adapter inside the capsule's `vendor` directory;
release packaging includes those bytes in the verified capsule archive.

The release workflow reads the operator's `REOWN_PROJECT_ID` secret. Independent
operators can supply `ELASTOS_WALLETCONNECT_PROJECT_FILE` during release preparation or source-home
setup. Staging checks the reviewed adapter hash and includes `vendor/connector.json`
before the capsule is hashed. An existing operator configuration in
`ElastOS/SystemServices/WalletConnect/config.json` takes precedence. Source uses
fixture IDs in tests and carries each operator's project ID only in that
operator's release or installed configuration. A person using Home presses
Connect and scans the QR code. Essentials and ELA signing build on this boundary.
Essentials, ELA, EID, BTC BIP-322, and UniversalX should reuse the same
proof-binding shape.
UniSat is the first dedicated browser Bitcoin connector because its injected API
documents `requestAccounts` and `signMessage`. Managed Bitcoin accounts remain
Bitcoin-mainnet native P2WPKH and managed signing remains
`managed_btc_p2wpkh`. Separately, wallet-provider source tests cover external
BIP-322 simple verification for native P2WPKH and Taproot P2TR, plus legacy
Bitcoin signed-message verification for P2PKH and nested SegWit P2SH-P2WPKH.
Those verifier tests are not real UniSat compatibility evidence. Product
acceptance still requires pinned real-wallet evidence for each claimed path,
and the weaker proof-strength policy for legacy signed-message verification
remains open.

Do not add a BTC signing button to the MetaMask connector unless MetaMask exposes
and documents a BIP-322-capable dapp API for Bitcoin accounts. MetaMask Bitcoin
account support by itself is not enough; Runtime needs a signed proof that
`wallet-provider` can verify against the exact Runtime challenge. Until that
exists, MetaMask remains the EVM connector, Wallet owns built-in Bitcoin
accounts, and UniSat owns external BIP-322 proof-link handoff.

ERC-1271 smart-account SIWE proofs are now supported through a two-provider
sequence: `chain-provider` verifies `isValidSignature(bytes32,bytes)`, then
`wallet-provider` consumes the matching Runtime challenge only if the typed
chain proof binds the same contract address, chain ID, message hash, and
signature hash.

Bitcoin ownership proofs use the same Runtime-first shape. Browser-facing
`/api/auth/btc/challenge` and `/api/auth/btc/verify` routes remain
connector-token scoped for direct configured connector use; System/Home tokens
cannot create or verify BTC wallet links there. Injected UniSat instead uses the
dedicated Home connector endpoints, which require both exact same-origin Home
authority and a carried UniSat token bound to the same principal, session,
proof, and grant. Internally,
`bitcoin_challenge` issues a short-lived, single-use challenge for a Bitcoin
address, and `verify_bip322_proof` consumes it only when the signed message
matches the stored challenge exactly. The external verifier has source-tested
support for BIP-322 simple native P2WPKH and P2TR proofs under
`bip322_simple`, and for Bitcoin signed-message P2PKH and P2SH-P2WPKH proofs
under `bitcoin_signed_message`. The built-in managed Bitcoin account is
different: it remains native P2WPKH and uses `managed_btc_p2wpkh` when signing
the Runtime-bound proof after approval. Unsupported networks and scripts,
malformed witnesses, replayed or expired challenges, wrong-message signatures,
and non-Runtime managed proof messages fail closed.

Source-tested verification is not a product compatibility or capability-strength
claim. Real UniSat evidence for P2WPKH, P2TR, P2PKH, and P2SH-P2WPKH remains
open, as does an explicit weaker-proof policy for `bitcoin_signed_message`.
P2WSH, multisig, hardware-wallet-specific behavior, and any additional script
types still need pinned vectors, wallet evidence, connector UX, and policy
before they can be claimed as supported.

## Wallet connection contracts

**After this work.** Runtime decides authority and navigation facts;
wallet-provider owns accounts, proof challenges, request state and receipts;
Inbox owns the internet permission decision; Wallet owns account and request
review; each connector window asks for its allowed effect. These contracts
cover N3 to N5. [N1 and N2](HOME_SHELL_HOST_CONTRACT.md#injected-wallet-connector-effects-n2)
own window navigation and the injected-provider edge, including their exact
schemas, checks and outcomes. The existing
[Clipboard edge](HOME_SHELL_HOST_CONTRACT.md#first-party-clipboard-edge) owns
Copy link. These are the six additions authorized for this work; display state
and request selection confer no additional authority.

### N3 outside-wallet requests

**Today.** `gateway_inbox.rs::append_wallet_approval_notifications` selects
`wallet-review-request:<id>` only for `browser_account_access`. Other requests,
including outside-wallet accounts, get `wallet-approve-request:<id>`. Inbox
then offers Approve, Review in Wallet and Reject. Runtime's
`approve_pending_managed_wallet_request` refuses a proof type that is not
managed. Wallet's request view opens MetaMask or UniSat without the selected ID;
it has no matching WalletConnect action. This is a routing gap, not permission
to approve outside-wallet requests with a Home passkey.

| Status | Runtime classification | Inbox behavior | Wallet behavior |
| --- | --- | --- | --- |
| After this work | `browser_account_access` | Keep `wallet-review-request:<id>`. | Keep its existing account-access review and decision. |
| After this work | Managed proof type under the existing Runtime managed-account predicate | Keep the existing managed request action and fresh-passkey rule. | Keep managed approval/signing and Reject. |
| After this work | Every other account proof type, including an external record with missing/unknown connector metadata | Emit `wallet-review-request:<id>` with `action_ref.app:"wallet"`. | Show the same request. Offer its known supported connector only when the stored binding allows it; otherwise explain that it cannot be sent and keep Reject while pending. |

**After this work.** The notification keeps the existing
`wallet-approval-request:<id>` identity, title, asking app and reason, with the
current list/detail/rail presentation and counts. Inbox shows Review in Wallet
as its sole action for an external request. Inbox keeps its current title, asking-app/reason body and list/detail/rail
metadata. Wallet supplies the full account, network and deadline detail. No
new review checkpoint or second approval record is created. General
presentation, unread counts and action vocabulary remain owned by the wider
Inbox work.

**After this work.** Runtime's refusal of direct managed approval for external
proofs stays on both Wallet and Inbox routes, even if a stale card or a caller
still submits it. Changing the producer removes the failing control; server
validation enforces the authority boundary. Review in Wallet uses N1's exact
request selector. Wallet reads the canonical principal-owned record again,
shows its purpose, source, reason, account, network and time, and opens the
stored `connector_id` with that same ID. MetaMask's compatible provider may
actually be Brave; its name follows N4. An unsupported request retains its
summary and Reject path and has no Send action. Opening a connector does not
consume the request; explicit Send follows the N2 preflight or WalletConnect's
existing bound handoff checks.

**Today.** Handoff changes pending to approved before the outside wallet
answers. Completion creates the verified result. A wallet-side decline alone
does not record a Home rejection. Consumed message requests leave the pending
feed; WalletConnect approved transactions remain in Wallet with Dismiss under
the receipt rules in [First Shippable Slice](#first-shippable-slice).

**After this work.** Preserve that lifecycle. Wallet rejects a pending request
through its existing Runtime action. The outside wallet owns decline of its
prompt. Dismiss closes the eligible handed-off WalletConnect transaction in
Home and leaves its outside result uncertain. Reject/Dismiss uses the exact
selected ID, clears the answered selection before refresh, and retains its
success acknowledgement. Activity is a separate next action through N1.
Completion means Runtime accepted the receipt; a transaction hash alone proves
neither chain confirmation nor payload execution. Reopened or refreshed views
read Runtime state and offer no second send for a consumed ID.

**After this work.** Enforcement and required tests for the Runtime/Inbox/Wallet/
navigation lane:

| Status | Required named test | Where it runs / what it proves |
| --- | --- | --- |
| After this work | `n3_external_inbox_review_action` | Server notification-producer test and real Inbox module test: all external proof/connector cases select Review in Wallet; managed and account-access cases retain their rules. No external Approve control. |
| After this work | `n3_direct_external_approve_refused` | Server route tests for Wallet and Inbox with valid fresh passkey authority: outside-account approval still fails before signing/handoff. Retain the existing refusal tests. |
| After this work | `n3_same_request_to_each_connector` | Real Wallet/Home/window modules and headless journey: each supported stored connector receives the selected ID; missing/unknown connector has Reject and no Send. Reopen, expiry and a second pending request cannot change selection silently. |
| After this work | `n3_reject_dismiss_acknowledgement` | Real Wallet module plus provider tests: reject/dismiss once, clear selection before refresh, retain acknowledgement, then open Activity. Outside decline leaves the existing Home lifecycle unchanged. |

**After this work.** Out of scope: the general Inbox presenter/count policy,
a stored reviewed state, automatic rejection on outside decline, new signing
methods, and a new source-app Bitcoin transaction API. In particular UniSat's
current host handoff supports Bitcoin proof signing, not a Bitcoin transaction
send. The all-connector transaction requirement remains an acceptance gap;
the smallest safe alternative is Anders's explicit scope decision or a
separately reviewed typed transaction contract before implementation.

**After this work.** Human security review question: does Runtime classify every
outside-account proof as review-only while both direct-approval entry paths
still refuse it, including old records and stale Inbox cards?

### N4 wallet name and mark

**Today.** `LinkedAccount` stores `connector_id` and optional user `label`, not
the outside wallet's display identity. WalletConnect keeps a cleaned peer name
in live client state; Wallet uses local account-name fallbacks. A reopened
window cannot rely on that live name. EIP-6963 names/icons and WalletConnect peer
metadata are untrusted claims.

**After this work.** Add only these optional display fields to linked-account
storage and its existing principal-scoped account summaries. They are separate
from the person's account `label`, proof identity and `connector_id`.

| Status | Field | Stored value and source |
| --- | --- | --- |
| After this work | `wallet_display_name` | Cleaned name, at most 80 Unicode scalar values and 256 UTF-8 bytes. Home maps its selected extension's stable ID to the fixed name MetaMask, Brave Wallet or UniSat. WalletConnect supplies its peer's untrusted name at verified linking. |
| After this work | `wallet_mark` | Optional exact key from `wallet`, `metamask`, `unisat`. The generic `wallet` key is the fallback. Runtime maps known extension IDs; an exact cleaned WalletConnect name `MetaMask` may select the bundled MetaMask mark as a display claim only. Other peer names use the generic mark. |

**After this work.** Runtime and wallet-provider enforce the same bounds and
cleaning before saving and when reading old/external records. First accept
only a string of at most 1,024 UTF-8 bytes; absent, wrong-type or oversized input
becomes absent display metadata while the valid ownership proof keeps its
normal result. Remove all characters whose Unicode General_Category is `Cc` or `Cf`,
including bidirectional controls and zero-width format characters. Collapse
remaining Unicode whitespace runs to one ASCII space, trim, then truncate at a
scalar boundary to both stored limits.
An empty result is absent. Render it as text, never HTML, a URL, a selector or
an asset path. Keep the account/address and verified Home source label separate
from this name so the name cannot imply Runtime authority.

**After this work.** The bundled map is `wallet` to `wallet/browser/icons/icon-64.png`,
`metamask` to `wallet/browser/icons/metamask.png`, and `unisat` to
`wallet/browser/icons/unisat.png`. Capsules package the required local assets;
a key never becomes a remote fetch or cross-frame authority. Brave uses the
generic mark until a new bundled mark is separately admitted. WalletConnect's
own heading retains its existing connector mark; `wallet_mark` identifies the
outside wallet, not the connection transport. Unknown keys render the generic
mark. Adjacent text supplies the accessible name; the decorative image has
empty alt text. Remote icons, SVG/data URLs and peer URLs are discarded.

**After this work.** Bind metadata to the exact account and connector whose
ownership proof was verified. Carry it through the existing typed linking
path, including link completion through an approval where applicable; a failed
proof or another principal/connector cannot overwrite it. There is no standalone
metadata-write capability. A later verified relink may replace these display
fields without changing a user label or creating a second account. Account
lists, Wallet's connection section and reopened connector windows read the
stored sanitized fields. Live unverified selection remains separate from a
previously linked account. Removal/disconnect follows existing account/session
ownership rules; display metadata grants no signing or internet authority.

**After this work.** An older external record without these fields shows
Your wallet with the generic Wallet mark and its known address/network. Keep
any user account label as that account's label. Do not guess a peer brand from
an address or assume `wallet-metamask` proves that MetaMask rather than Brave
was selected in the past. New linking stores the actual selected identity.

**After this work.** Update from 2.0.1 reads the old wallet store with both new
fields absent by default. The update preserves account IDs, defaults, proof
bindings, ownership, request states and key material. New fields stay optional;
no display-only change may require a one-way store migration or new signing
schema. Undo to 2.0.1 must load accounts linked before and after update and
keep their existing supported operations working. The old provider may ignore
and drop these optional display fields when it rewrites the store; a later
update then uses the safe fallback. Preserving display branding through that
old write is outside this contract; preserving account authority and data is
a release gate. An old Home tab across update follows N2's reload negotiation.
These compatibility requirements need exact-version installed proof; source
Serde tolerance alone is insufficient.

**After this work.** Enforcement and required tests for the Runtime/Wallet lane:

| Status | Required named test | Where it runs / what it proves |
| --- | --- | --- |
| After this work | `n4_metadata_bounds_and_text_rendering` | Provider and server unit targets plus real Wallet/window modules: wrong types, 1,025-byte input, multibyte limits, controls, bidi text, HTML-like names and unknown mark keys all use bounded inert text/local assets. |
| After this work | `n4_metadata_bound_to_verified_link` | Provider/server targets: failed, wrong-principal and wrong-connector links cannot change fields; successful link/relink covers each connector and keeps user labels. |
| After this work | `n4_old_record_and_reopened_window` | Provider decode and real Wallet/connector modules: absent fields show the fallback; newly stored actual Brave/MetaMask/UniSat/peer identity survives reopening. |
| After this work | `n4_update_201_undo_preserves_accounts` | Installed update/Undo job: old linked account, update, add link, close/reopen, Undo, perform an old-supported account operation that saves, update again. Compare accounts/defaults/proofs/requests and confirm safe metadata fallback after the old write. |

**After this work.** Out of scope: remote branding, authenticated wallet-brand
claims, a Brave mark addition, user-label changes, key migration, new guest
linking policy, and retention guarantees for display fields in an old writer.

**After this work.** Human security review questions:

- Do bounded, cleaned peer names and the local mark map remain inert in every
  account, connector and recovery view, without looking like a trusted Home label?
- Does the installed update/Undo evidence prove account authority survives an
  old provider write even when it drops the new optional display fields?

### N5 WalletConnect internet entry in Inbox

**Today.** Runtime keeps one owner-visible entry with ID
`walletconnect-internet:permission`. Requested consent lasts 30 minutes.
Allowed consent offers Turn Off. The notification producer omits `action_ref`
after refusal, completed revocation or request expiry; Inbox already has Allow
recovery code, but that code needs an action-bearing entry to be reached.
Round 19 drops a connector's pending effect on refusal/revocation/expiry/Cancel
and refreshes permission when Home returns the window.

**After this work.** Keep that exact entry and its existing request/decision
kinds. The Runtime producer retains an actionable reference for every saved
state below, including after restart; absent consent becomes the single Asked
entry only through the existing request path. The current consent record and
ID decide the action, not an old notification payload. Inbox uses the existing
owner/passkey confirmation and grant/revoke routes. Selecting Allow in an off
state obtains or creates a fresh requested record through the existing route,
reads its current ID, then obtains the exact fresh proof and answers that ID.
A stale action cannot approve a replacement record. No new generic permission
or decision API is introduced.

| Status | Runtime state / entry kind | Action retained in Inbox | Connector result |
| --- | --- | --- | --- |
| After this work | Requested, unexpired / `walletconnect_internet_request` | Allow and Don't Allow for the current request | Waiting for your answer in Inbox; Show Request and local Cancel. Only a still-active matching intent may continue once after Allow. |
| After this work | Granted / `walletconnect_internet_decision` | Turn Off | Connect wallet, plus Manage in Inbox; permission alone does not start a connection. |
| After this work | Refused / `walletconnect_internet_decision` | Allow | Off; Open Inbox, then return for an explicit new action. |
| After this work | Revoked, cleanup complete / `walletconnect_internet_decision` | Allow | Off; saved connection has been cleared. Linked Wallet accounts remain. |
| After this work | Requested but past 30-minute expiry / `walletconnect_internet_decision` | Allow, obtaining a fresh question/ID before proof | Access request expired; Open Inbox, then explicit Connect/Send as applicable. |
| After this work | Revoked with `cleanup_pending` or still-closing owned sockets / `walletconnect_internet_decision` | Turn Off again; Allow unavailable until cleanup completes | Off; finish clearing the connection in Inbox. A failed cleanup leaves this recovery action available. |

**After this work.** Producer action IDs use the existing
`walletconnect-internet-allow:<current-id>` or
`walletconnect-internet-turn-off:<current-id>` families. An off/expired Allow
reference opens the existing recovery path, not a direct stale grant. An
answered/off entry is informational and excluded from pending counts under the
current rule. Keep the exact-entry link valid in both list/detail navigation;
no duplicate permission entry, switch in the connector, or new Inbox layout.
Permission grant remains owner-authorized and passkey-bound. A guest can ask
the owner, and has no Allow control or owner grant. First-run setup consent
remains governed by the separate first-run authority decision.

**After this work.** Follow Browser's current Inbox pattern: automatically open
the request on a still-active attempt, Show Request while asked, Open Inbox
while off, and a retained decision with Allow/Turn Off recovery. Keep these
WalletConnect differences explicit: Cancel drops only the unsent local intent
and leaves the question in Inbox; Turn Off also clears connection state and
stops relay work; cleanup can need another Turn Off; Manage in Inbox lives
beside Connect rather than Browser settings. The permission lasts independently
of wallet-message/QR deadlines. Titles, decision dates, general notification
focus and counts keep the existing presentation policy; broad alignment belongs
to the wider Inbox work. The consent explains internet use, the relay service's
visibility of this computer's internet address, wallet-owned keys and separate
wallet approval. It calls the other application a wallet app, not a new
product called phone wallet.

**After this work.** Refusal, Turn Off, expiry or local Cancel retires the
pending intent. A later Allow returns readiness and guidance, never runs that
retired intent. Only the same unexpired question and still-active local intent
may resume once. A delayed older permission read cannot replace a newer result
or resurrect that intent. Reopening/reloading a connector requires explicit
Connect/Send and rechecks the canonical Wallet request before handoff. Runtime
revocation continues to fence late relay admissions/writes and cleanup remains
a precondition of a new connection.

**After this work.** Enforcement and required tests:

| Status | Required named test | Where it runs / lane |
| --- | --- | --- |
| After this work | `n5_permission_entry_all_states` | Runtime/Inbox/Wallet lane: server producer plus real Inbox module; all six rows, exact entry/action IDs, stale ID, restart, owner versus guest and decision counts. |
| After this work | `n5_allow_after_refusal_off_expiry` | Runtime/Inbox/Wallet lane: real Inbox and gateway journey; each off state creates/uses a fresh proof for the current question and returns the same window to readiness. |
| After this work | `n5_cleanup_blocks_allow_until_complete` | Runtime and WalletConnect lanes: failed Turn Off, retry and socket completion retain recovery and prevent a new session until cleanup finishes. |
| After this work | `n5_retired_intent_never_resumes` | WalletConnect window lane, real controller/client modules and headless Inbox return: refusal, revoke, expiry, Cancel, reopen/reload and a delayed old read never resend. Same active intent resumes exactly once. |

**After this work.** Out of scope: Browser's permission implementation,
general Inbox design/count/focus changes, hosted Exit selection, more relay
hosts, a second permission control and guest authority changes.

**After this work.** Human security review question: can each retained Allow
path obtain only the owner's current passkey-bound decision while stale IDs,
cleanup and a retired connector intent remain fenced?

### Wallet connection integration proof

**After this work.** Required test names above are obligations for the build
lanes, not assertions that these tests exist or pass today. Each changed
behavior needs a failing test on the pre-change real module and a passing test
after the lane change. Preserve existing tests for already-enforced authority.
Run JS module tests in the behavior suite; run the source gate and all test
targets of touched server/provider packages. The release integrator runs the
full Linux check and installed CI jobs for the combined candidate.

| Status | Required integration test | Evidence / owner |
| --- | --- | --- |
| After this work | `wallet_connection_same_id_installed_journeys` | Integration lane: one ID through Inbox, Wallet, each connector and the outside wallet to a shown result for each supported message/transaction path. Start also from saved unfinished connection, pending Inbox question, handed-off request, busy provider, reopened frame and reloaded Home. Prove no duplicate send. |
| After this work | `wallet_connection_real_wallets_and_webkit` | Integration lane: installed Home with scripted wallet over the real relay, real MetaMask and UniSat at least once, WebKit and native desktop. Record exact extension/engine versions, artifact hashes, declined/wrong-account/late replies and a real test-network transaction. Replay alone is not real-extension acceptance. |
| After this work | `wallet_connection_expiry_reconnect_and_controls` | Integration and window lanes: saved connection past its actual seven-day expiry, wallet-side removal, network/account changes, every accepted design state reached by its real producer, every control pressed. Include focus, polite announcements and a human screen-reader pass. |

**After this work.** The integration owner records source/tree, installed
artifact parity, commands, results and human checks in the owning issue's one
acceptance record. A different-family adversarial review covers all six narrow
additions. Irzhy's N1/N2 contract review is required before product code;
Anders decides whether to wait or waive. His network/session review precedes
product acceptance, and Anders owns the final trial.
The contracts confer no waiver. Whether guests may link extension wallets and
what Home should say about a wallet's unverified-origin warning remain human
policy decisions. No build lane resolves them by adding authority.

**After this work.** Human security review questions:

- May a guest link an extension wallet under the existing principal/grant model,
  or must that journey remain gated until Anders approves a policy?
- What exact Home guidance, if any, is safe when the outside wallet calls the
  local Home origin unverified, given that Verify attestation remains absent?
- Can the current UniSat proof-only effect meet the all-connector transaction
  requirement, or does Anders require a separate reviewed transaction contract?

## Red Lines

- No address-only login.
- No wallet-address-derived encryption keys.
- No arbitrary signing.
- No app-visible wallet RPC or node RPC.
- No private keys outside wallet-provider authority.
- No Essentials or UniversalX requirement for default Home unlock.
- No blockchain UI before fail-closed tests and capability schema exist.
