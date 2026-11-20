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
receive browser-extension provider objects. For injected compatible Ethereum wallets and
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
host. compatible Ethereum wallets and UniSat frames can read their Runtime account and
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

`passkey unlock -> open opaque approval-method connector capsule -> send one closed link intent to trusted Home -> Home selects an announced EIP-6963 Ethereum wallet under the discovery rule below -> Runtime validates matching Home + connector launch-token v4 authority -> Runtime issues SIWE challenge -> Home signs only that challenge -> wallet-provider verifies and links account + connector_id to the existing principal -> audit -> revoke -> prove replay/expiry/wrong-chain/wrong-origin/wrong-connector fail closed`

Home owns EIP-6963 discovery for the MetaMask option. On each Connect or Send,
Home requests fresh announcements, removes conflicting objects, UUIDs and rdns
values, and bounds the list to 32 distinct entries. Connect uses `io.metamask`
when present, then the only wallet, then the person's choice from a name-sorted
list. The list carries Home-issued one-use handles bound to that frame and its
launch lifetime. The window sends the selected handle with the link action.

For Send, the window includes the linked address with the approval request ID.
Before taking the Runtime handoff, Home asks at most eight discovered wallets
for `eth_accounts`, in parallel with a one-second timeout. Home uses a wallet
that reports the linked address first, preferring MetaMask among matches. If none
reports it, the request stays pending and the window offers Check again and
Close window. Home retains the signer check after the handoff. Each selected
wallet is checked again before dispatch. UniSat uses its own provider contract.

The window retains wallet identity only for its current action. A successful
link or approval returns the selected wallet's name, rdns and optional data-image
icon. The account card shows that name and icon after success in this window;
a saved link starts as Your wallet with its address and network and an empty
mark slot. Announced identity stays inside window content. Home's header, tab
title and hidden page title remain MetaMask. Each window has a hidden page
title and its content starts with the status line. Home owns wallet objects;
Runtime owns account links and one-use approval authority.

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
approved, unfinished transaction visible with "This transaction may already have
been sent. Check your wallet before sending again." Opening
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
"Dismissed, but your wallet reported it as sent" with the hash and a sent mark.
Runtime logs `wallet.approval.sent_after_dismissal` for this receipt, and the
connector reports "Request dismissed. Your wallet reported this transaction as sent."
An unfinished WalletConnect prompt expires after the grace period. Other
connectors keep their signing TTL; [N3](#n3-outside-wallet-requests) defines
MetaMask's receipt-only exception after this work.
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

**After this work.** Runtime decides authority and stored request provenance;
wallet-provider owns accounts/proofs/receipts; Inbox owns internet consent;
Wallet owns account/request review; a connector asks for an allowed effect.
[N1 and N2](HOME_SHELL_HOST_CONTRACT.md#injected-wallet-connector-effects-n2)
own the exact frame, navigation and Runtime edge messages. The existing
[Clipboard edge](HOME_SHELL_HOST_CONTRACT.md#first-party-clipboard-edge) owns
Copy link. The source-app recovery row is included in N1's issue scope and human
review. WalletConnect client error classification stays inside its existing
capsule authority; a design label N6 adds no new effect or permission.

#### WalletConnect stopped pairing and replacement QR

**Today.** The client aborts its local attempt, retires the adapter and clears
Runtime session storage on Cancel/fresh Connect. The pinned adapter aborts its
pairing attempt and requests relay transport closure. A local cancellation alone is
not evidence that every earlier proposal/late callback can no longer be adopted.

**After this work.** Before Get new QR code or fresh Connect issues a replacement
URI, the WalletConnect-window lane ends the stopped pairing/proposal using the
pinned SDK's cancellation/retirement path and completes Runtime's existing
storage-revision cleanup barrier. The old URI/topic/proposal is no longer
eligible for adoption by that client; an old approval, display_uri, storage
write or late result cannot restore it, link an account or replace the new
attempt. Stop and repeated new-QR presses join the same cleanup operation.
Only its successful completion permits one fresh attempt/URI. A failed or
timed-out cleanup shows "Home could not end the earlier connection. Try again."
and offers cleanup retry, without issuing another QR. This rule covers pairing/
proposal replacement, not cancellation of a handed-off transaction.

**After this work.** `walletconnect_stopped_pairing_ends_before_new_qr` has one
accountable owner, the WalletConnect-window lane. Its real client/adapter test
stops before/after proposal, delays cleanup, repeats Stop/new-QR presses and
delivers an old proposal approval; it proves no replacement URI before the
barrier, one fresh URI after it, and no adoption/link from the retired attempt.
Run it in the behaviour suite and both pinned browser engines. Keep existing
cancellation guards; where a branch already works, retain it as a regression
rather than inventing a failing provider response.

### N3 outside-wallet requests

**Today.** The Inbox producer chooses wallet-review-request only for Browser
account access; other external requests get wallet-approve-request. Runtime
refuses their direct managed approval. N1 describes the connector launch gap.
The Wallet toolbar badge in `capsules/home-gui/browser/shell-wallet-rail.js`
counts only the approve prefix today.

| Status | Runtime classification | Inbox action | Wallet decision |
| --- | --- | --- | --- |
| After this work | Browser account access | Existing `wallet-review-request:<id>` | Existing account-access review |
| After this work | Managed proof under the existing predicate | Existing managed action | Fresh passkey, managed signing or Reject |
| After this work | Every external proof, including missing/unknown connector metadata | `wallet-review-request:<id>` | Open the known stored connector with the same ID, or show unavailable; keep Reject while pending |

**After this work.** Inbox keeps the existing notification identity
`wallet-approval-request:<id>` and current list/detail/rail presentation. It
shows Review in Wallet for an external request, without managed Approve or a
second review checkpoint. The generic entry Open control, if retained, opens
that same Wallet review rather than the source app or a signing operation.
General Inbox presenter/unread policy remains outside this work.

**After this work.** The navigation lane owns all
`capsules/home-gui/browser/**`. In shell-wallet-rail.js the Wallet toolbar badge
counts every wallet_approval_request entry whose action begins
wallet-approve-request: or wallet-review-request:. This also adds Browser
account-access requests to that badge. Each request ID counts once; moving a
request from approve to review does not drop it. Test
`n3_wallet_badge_counts_review_requests` covers both prefixes, duplicates,
account access and unrelated entries through the real module.

**After this work.** Runtime retains its direct-approval refusal for external
proofs on both Wallet and Inbox routes, including stale cards with a fresh
passkey. Pre-review N3 changes are confined to classification, gateway
dispatch/presentation and tests of that existing refusal. They do not edit
approve_and_sign_managed, its managed-proof predicate, signing call, request
consumption or shared expiry/pruning behavior in approval.rs. If an apparent
refusal fix needs any such provider change, that part waits for the human
N1/N2 gate; preserve managed approve-and-sign regressions unchanged. Wallet reads the canonical record, shows the existing reason/account/
network/deadline facts, and opens its stored connector with N1's selector.
Unsupported requests retain their summary and Reject, without Send. Opening a
connector consumes nothing; explicit Send performs preflight and one handoff.

#### N3 requester and site provenance

**Today.** Stored WalletApprovalRequest.requested_by_actor is the Runtime-
verified asking actor, projected as capsule_id in SystemWalletApprovalSummary.
The summary also carries request_id, intent, resource, reason, account, chain,
expiry and status. Browser signing payloads privately contain origin/page_url,
but ordinary signature and transaction card summaries have no site field.
The existing browser_account_access review is the exception: its validated
review object contains origin/page_url. A reason or resource string is not
independent proof of a website identity.

**After this work.** Cards name the requesting app from capsule_id and its
Runtime catalog label, falling back to the bounded literal actor ID.
[N7](#n7-requesting-site-display) owns the recorded Browser site projection,
including account access, absent metadata and its display-only trust label.
Cards do not derive requester identity from reason, resource or a message to
sign. Recovery opens the recorded asking app with an empty query, not a website;
N7 changes no N1 destination. Home's ownership proof and an app's signing
request remain distinct purposes; a fixture cannot turn one into the other.

**Today.** Handoff changes pending to approved before the outside answer.
Outside decline does not itself store Home rejection. Consumed message requests
leave the pending feed; approved WalletConnect transactions remain in Wallet
with Dismiss under [the existing receipt rules](#first-shippable-slice).

**After this work.** Preserve that lifecycle. Wallet Reject ends a pending
Home request. Dismiss closes an eligible handed-off WalletConnect transaction
locally, not in the wallet. After Reject/Dismiss, clear selection before refresh
and retain the acknowledgement; Activity remains a separate action. A consumed
ID is never resent. Result unknown is reserved for an unresolved send disposition; a known
wallet refusal keeps its outcome, including when saving it fails. A known but unrecorded hash uses
[Home's receipt-status rule](HOME_SHELL_HOST_CONTRACT.md#n2-waiting-settlement-and-memory).
A returned hash alone establishes neither chain confirmation nor that the
transaction matches the payload.

#### N3 MetaMask transaction results

**Today.** Handoff consumes a pending request before the wallet answers.
An outside decline stores no settlement. MetaMask approval expires at its
original request expiry (maximum 30 minutes); WalletConnect alone has its
existing grace/Dismiss rule. The active limit is 100 per principal. The
provider's replay helper does not yet make hash completion idempotent.

**After this work — proposal for the human review of N1/N2.** Runtime/navigation
owns result retention and the proposed settlement operation. At each new
wallet-metamask transaction handoff, atomically store approved_at,
external_result_deadline_at = approved_at + 43,200 seconds (12 hours), and
external_result_authority_binding before returning success. The deadline is an
optional Runtime-owned u64 epoch second, calculated with checked arithmetic;
invalid/overflowing approved_at refuses handoff before consumption. The last field
is computed with the existing wallet_authority_binding function from the
verified connector handoff invocation, not from the requesting app's distinct
authority_binding and not from caller parameters. It binds principal, session,
proof, grant, connector actor and launch ID; same-authority renewal preserves
it. The caller sets neither field. Twelve hours is the proposed default for
Irzhy to confirm; it never renews with a page, frame, token or later result.

**After this work — NB2.** The stored deadline may appear on Wallet's scoped
summary for display; it never enters the existing handoff envelope or nested
typed payload. Home's old and new handoff wire shapes stay unchanged under
their existing schemas. Runtime enforces the deadline; Home needs no new
deadline read. [N2](HOME_SHELL_HOST_CONTRACT.md#n2-runtime-admission-preflight-and-errors)
owns the exact unchanged envelope and old-page compatibility test.

#### NB1 proposed wallet-call settlement

**After this work — default proposal, not approved authority.** Home reports
only the actual settled result of the one eth_sendTransaction call made for
that consumed compatible Ethereum wallets request. A valid returned hash uses the existing
completion route. A call without a usable hash uses the proposed Home-only
call-settlement route and Runtime-private RecordExternalCallOutcome operation,
with exactly request_id, payload_hash, signer and outcome as operation data.
The gateway derives the verified authority; the body is not proof. No new
public capsule capability or generic Bus path may invoke this operation.
Home and the Runtime mediator must enforce the dual-authorizer check before
provider mutation, even if a direct caller has a connector launch capability.

| Status | Closed outcome | Home's only producer | Runtime state / view |
| --- | --- | --- | --- |
| Proposed default | not_approved | That send promise rejects with numeric 4001, including native prompt close; the button/person's intention is unknowable | Rejected, external_call_outcome not_approved, resolved_at now; terminal not sent, outside active quota/list |
| Proposed default | not_authorized | That send promise rejects with numeric 4100 | Rejected, external_call_outcome not_authorized, resolved_at now; terminal not sent, outside active quota/list |
| Proposed default | unresolved | That made call settles with another error or an invalid/missing hash; absence is not proof of no send | Approved, external_call_outcome unresolved; active result-unavailable record until hash/deadline, not a claim that the wallet still waits |
| Proposed default | Valid hash through existing completion | That call returns a well-formed hash, or a later authorized positive receipt corrects earlier evidence | Completed with the original receipt bindings; canonical positive-hash evidence wins |
| Proposed default | No settlement report and no hash | No recorded answer: call still pending, old Home lacks the reporter, delivery authority ended, or saving failed | Approved, no external_call_outcome; active no-recorded-answer view until stored bound |

**After this work — default proposal.** No caller supplies a reason, error
message, numeric code, timestamp, cancellation claim, transaction, signature,
account change or new payload. Root Home derives only the closed outcome
above; free text and extra keys are invalid. Stop, local timeout, request
expiry, frame close, account/network events and failed Runtime HTTP submission
are not wallet settlements. No report may be invented before a send call,
from a UI button or merely because no hash is present. An ambiguous error
uses unresolved, never not sent. The not-sent label means the wallet call
reported non-approval; it is not cryptographic proof that no transfer exists.

**After this work — default proposal.** Runtime requires same-origin Home
authority plus the same valid carried connector authority as the handoff,
with active principal/session/proof/grant and exact wallet-metamask actor.
The provider checks the stored external_result_authority_binding, request ID,
transaction intent, approved handoff, payload hash, canonical signer and
now < external_result_deadline_at. It accepts at most one no-hash outcome:
identical retries return the stored acknowledgement; a different no-hash code
conflicts. It never changes the signed payload, requesting actor, original
authority or deadline. Existing hash-completion request/response schemas stay
unchanged. New-code handoffs use the stored connector binding for both paths.
An older surviving Approved record may derive the deadline from approved_at
before pruning, but without a stored connector-result binding it gets hash-only
legacy completion checks and no new no-hash authority; do not bootstrap that
binding from a presented settlement. Such records and old pages use the
honest fallback view below when no outcome is recorded.

**After this work — default proposal.** not_approved/not_authorized leave the
waiting list and active quota immediately. Store them as Rejected with the
closed external_call_outcome so they are distinct from a person's pending
Reject; they never later become result unknown. Clearing the finished card/
acknowledgement clears selection as for other finished requests; it grants no
Dismiss, deletes no receipt binding and does not revive Send. Normal Activity
retains the answer. An unresolved answer is labelled result unavailable; the
no-outcome view says Home has not recorded an answer, not that the wallet
definitely has not answered. Only unresolved/unrecorded disposition can become
result unknown at the bound. Home's known local refusal remains visible even
when its report fails; Wallet truthfully says no outcome was recorded.

**After this work — positive receipt precedence.** A same-bound valid hash
received before the stored deadline is recorded even after a not-sent report,
finished-view clearing or an unresolved report. Atomically change the canonical
view to Completed, retain the earlier closed outcome as audit history, and
replace the not-sent label/count with the positive result. There is still only
one hash receipt and no second handoff/provider call. Identical hashes return
the same acknowledgement; different hashes conflict. A no-hash report after
a stored hash conflicts and cannot downgrade, hide or delete it. At/after the
deadline, a new first hash/report is expired; retained identical acknowledgements
may still be read under valid authority. This is a defensive ordering case,
not a claim that a standards-compliant promise normally settles twice.

**After this work — bounded retention.** Keep a settled no-hash record's
minimal immutable receipt binding and closed outcome through the original
result deadline, even if its finished view is cleared or normal 100-item
resolved-history display rolls over. It is outside the active quota. Reserve
space for the maximum permitted receipt update before handoff; the existing
64 MiB wallet-store bound still applies. Refuse new admission before consumption
rather than evict a live binding or a received result. A late positive hash is
recording, not new admission: do not reject it merely because the active count
has since reached 100. Existing completed/chain-outcome accounting may then
put the count above the admission threshold; new admissions remain refused
until normal resolution reduces it. No unbounded new history or expiry reset
is allowed. Storage/lifecycle bounds remain independent of active quota.

**After this work — authority limit and risk.** This proposal changes Runtime
recording authority and quota/visibility, so it waits for Irzhy, not just a
contract diff PASS. It creates no transaction, signing, linking, cancellation,
internet or navigation authority; all money movement still needs its original
one-time handoff and the wallet's own approval. A caller able to withhold a
hash can already leave Runtime without positive evidence by silence. This
report cannot erase positive evidence already stored, and later positive
evidence wins. It does add a trusted-Home assertion about a call's outcome;
there is no chain proof of absence. The review must judge that trust and
misleading-wallet risk explicitly. Another frame/session or the requesting
app gains no report authority from knowing an ID or self-consistent fields.

**After this work — timing and quota.** An unanswered/no-recorded-answer record
remains Approved through the fixed 12-hour result bound, including after its
request expiry, and counts toward the principal's 100 active requests.
A known unresolved answer stays active with result-unavailable wording.
At the bound it becomes Expired/result unknown, resolved_at is that stored
bound, and it leaves active quota. Pending/Approved/Completed/Rejected/Expired
remain the status enum; result unknown is a derived view, not a new status.
Under the default, 100 sequential recorded 4001/4100 refusals do not consume
100 active slots; each terminal report releases its slot. Other existing
store/lifecycle limits still apply. Sign-out, authority_changed and page loss
end page delivery, not the stored record; a later session may inspect it
read-only but receives no completion/report right. Approved no-answer and
unresolved records have no Send/Retry/Reject/Dismiss; Dismiss stays WalletConnect-only.
Wallet offers inspection of account, network, asking app, result deadline and
Activity, plus guidance to check the selected wallet itself. Selecting a retained
record shows that read-only result state, rather than an unavailable pending
card or an invitation to resend.

#### NB1 fallback if the human review refuses no-hash reports

**After this work — alternative, mutually exclusive with the default.** Add
no call-settlement route/private operation and send no no-hash report. Keep
hash-only result collection with the same proposed 12-hour stored bound.
Home preserves its observed refusal/prompt-close result locally; the Runtime
record has no such knowledge and remains Approved/active until hash or bound.
Its view is unrecorded result, not "the wallet is still waiting" and not a
claim that the person declined. Proposed Wallet wording for Sasha: "Home has
not recorded a transaction result. It keeps this request open until {time}.
Check your wallet before starting a payment." The connector may add: "The
wallet did not approve this request. Home cannot save that answer." This is
an explicit recording gap, not an unanswered-wallet claim. The expiry view
says result not recorded/check wallet; a locally known refusal keeps its
outcome instead of being relabelled unknown.

**After this work — fallback cost.** There is no Dismiss for that Approved
MetaMask record and no same-ID resend. Each unreported decline/closed prompt
occupies one principal active slot until the bound. About 100 such requests
within twelve hours fill the 100-active threshold and the next admission is
refused until slots expire or a valid result resolves them. Hiding a card
does not release a slot. This also describes old Home pages or failed delivery
under the default when Runtime receives no settlement. The reviewer must
accept this UX/quota cost if choosing the fallback; it is not silently fixed.

**Today.** The connector approvals feed filters out terminal records. It does
not yet provide the selected-result refresh below.

**After this work — gated canonical result refresh.** Extend the existing
GET /api/apps/:wallet_connector/wallet/approvals route with one optional
wallet_request query selector, using N1's canonical request-ID validation.
Keep its current response shape; approval_requests adds at most that one
selected retained terminal/result record to the normal bounded feed, deduplicated
by ID. Without the selector, retain the ordinary bounded feed. The Runtime
checks the verified principal and stored connector before looking up a retained
binding; an unavailable, other-principal or other-connector selector returns
HTTP 404 with the closed N2 effect.error/v1 body and code request_unavailable. This read grants no report/completion
right and bypasses neither session rules nor request authority. Other apps and
connectors receive no added result data. Retained bindings outside the normal
history are selected-only, not an unbounded new history feed.

**After this work.** Runtime/navigation owns this scoped read and its tests;
all connector consumers render it. After a settlement advisory or conflicting
submission, the window refreshes with its selected request ID and renders
canonical positive-hash evidence ahead of an earlier no-send result. Terminal
records are history, not waiting rows. This is a connector read for a selected
result, not a new Home deadline read or a changed handoff. The binding/precedence
test covers cross-principal/connector refusal, history rollover, cardinality
and the real consumer refresh.

#### Wallet result list and count

**After this work — gated with result retention.** Runtime/navigation owns
wallet-activity.js pendingRequests, wallet-requests.js rendering and wallet.js
renderApprovalsBadge. One canonical waiting projection drives both the drawn
full waiting list and its count: principal/session-visible Pending requests,
plus Approved external transactions awaiting an unrecorded/unresolved result
under their connector's rule, including MetaMask and WalletConnect. Count
each ID once. A selected-request detail may filter the view but keeps the
full-list count labelled as total; it does not invent another waiting total.
Recorded terminal not-sent, Completed and Expired records leave that waiting
count/list together. Ordinary Activity/history is separate. Legacy fallback
Approved records remain in both until their bound. GUI notification badge
rules in N3 remain pending-notification rules, not this Wallet waiting count.

**After this work.** n2_transaction_completion_after_frame_close remains
Runtime/navigation's joined Home/provider test: Stop, request expiry, frame
close/load/new nonce, authority_changed and same-authority renewal; the exact
43,200-second boundary/equality, active quota/history, old records/Undo, read-only
versus expired views, concurrent identical/conflicting hashes, lost acknowledgement,
three bounded attempts, exhaustion and delivery end. All signing refusals remain
unchanged. Add
n2_no_hash_settlement_binding_and_precedence (same owner): all three outcomes,
4001 native-close neutrality, no report for Stop/timer/no call, direct capsule/
Wallet/Inbox/Bus refusal, wrong principal/session/proof/grant/launch/signer/hash,
duplicate/conflicting reports, no downgrade after hash, late hash after cleared
not-sent, full active quota, retained binding/byte bounds, failed saving and
frame/authority end. Test 100 sequential refusals under default and fallback.
n3_wallet_waiting_count_matches_list (Runtime/navigation) proves Pending,
Approved MetaMask/WalletConnect, no-answer, unresolved, terminal/cleared results,
selected detail and expiry. All these producer/transport/result tests are
gated; use real modules, and mark late contradictory evidence as an adversarial
protocol fixture rather than an invented extension recording.

**After this work.** New fields and the optional private operation require
mixed-version/installed update/Undo proof. Old Home's successful transaction
handoff/hash completion must work unchanged against new Runtime. Old Home
does not gain a no-hash reporter retroactively. Undo to 2.0.1 may drop new
outcome/binding fields or prune by old expiry/history rules; it cannot promise
the new retention or answer display. Re-update never revives terminal/pruned
authority. WalletConnect's existing grace/Dismiss rules are unchanged; this
no-hash proposal applies only to wallet-metamask transaction calls.

**After this work.** [Issue scope](https://github.com/elastos/elastos-runtime/issues/575)
is a message on each connector and a transaction on WalletConnect and MetaMask
only. UniSat signs messages only today; a Bitcoin transaction through UniSat
would be new authority and is not in this scope. No transaction decision remains
open for this contract.

| Status | Runtime/Inbox/Wallet/navigation lane tests | Run location |
| --- | --- | --- |
| After this work | `n3_external_inbox_review_action`, `n3_direct_external_approve_refused` | Runtime/navigation owns: server producer and both routes; real Inbox controls, old cards and managed/account-access regressions |
| After this work | `n3_same_request_to_each_connector`, `n3_reject_dismiss_acknowledgement` | Runtime/navigation owns; provider/Inbox/Wallet acknowledgement cases may run pre-review, connector-module and N1 journey cases wait; the full name passes only after all subcases |
| After this work | `n3_wallet_badge_counts_review_requests`, `n3_requester_provenance_without_site_invention` | Runtime/navigation owns: real GUI badge and cards; actor provenance, account-access exception, absent site and fixture rejection |

**After this work.** Out of scope: general Inbox presenter/count redesign,
stored reviewed state, automatic Home rejection on wallet decline, website
navigation and UniSat transaction authority. Irzhy confirms the external-proof
refusal and requester/source-app boundaries before product acceptance.

### N4 wallet name and mark

**Today.** LinkedAccount stores connector_id and a user label, without stored
wallet display identity. WalletConnect keeps a peer name in client memory;
metadata and announced names/icons are untrusted. The following wire fields
and shared cleaner are build work.

#### N4 wire fields and one derivation owner

**After this work.** Injected EVM and Bitcoin Home link/verify bodies gain
exactly one optional identity field, `provider_id`. The same field is permitted
on Home approval complete only when that completion links an account. All other
existing body fields remain exact; N2 separately adds admission_id to link
challenge/verify. Home derives provider_id from its selected provider object,
not a frame string, and sends no display name, mark or extension metadata.
Runtime checks it against the connector:

| Status | Connector | Allowed provider_id | Derived name / mark |
| --- | --- | --- | --- |
| After this work | wallet-metamask | io.metamask | MetaMask / metamask |
| After this work | wallet-metamask | com.brave.wallet | Brave Wallet / wallet |
| After this work | wallet-unisat | unisat | UniSat / unisat |
| After this work | Any legacy link without provider_id | absent | absent name / wallet |

**After this work.** WalletConnect adds only optional `wallet_peer_name` to
`POST /api/auth/evm/verify`, and to its existing
`POST /api/apps/wallet-walletconnect/wallet/approvals/:request_id/complete` only
when completion links an account. It is a raw peer-name string, at most 1,024
UTF-8 bytes after well-formed transport conversion. Runtime accepts it only for
the WalletConnect actor; it accepts provider_id only for the injected actors.
The fields are mutually exclusive. Wrong actor/identity returns denied; wrong
wire type/oversize returns invalid_request, using N2's closed error projection
on the Home routes. Normal clients omit non-string/oversized peer metadata,
so malformed peer metadata does not replace a valid proof with a bad JSON body.

**After this work.** Before JSON encoding, the WalletConnect adapter calls
String.toWellFormed() (or the equivalent standard UTF-8 encoder/decoder
replacement) so lone surrogates become U+FFFD. This is transport repair, not a
second name cleaner. Runtime checks wire type/byte bounds and connector match;
it neither cleans names nor selects a name/mark. It carries validated optional
provider_id or wallet_peer_name through LinkVerifiedAccount and any linking
CompleteConnectorHandoff in WalletProviderOperationV2. Bus protocol stays 2.3;
the fields default to absent and serialize only when present. No field changes
proof hashes, signing intents or authority. An older strict Bus consumer may
reject new params: report unsupported_version before any store mutation,
rather than retrying with weakened fields. The Runtime/provider component set
must be compatible; store compatibility alone proves no mixed-Bus compatibility.

**After this work.** Exactly one implementation,
`elastos-wallet-contract::wallet_display_identity`, derives the fixed extension
identity or cleans the peer name and selects the bundled mark. Wallet-provider
calls it after verified linking and when projecting old stored display fields.
All stored/projected metadata uses its returned values; Home and Runtime
gateway have no parallel cleaner or name/mark mapper. Pre-link brand labels
are fixed localized copy for the provider enum, not untrusted metadata or a
second storage derivation. The function lives in the shared
contract crate; the Runtime lane owns that crate, provider storage and tests.
Frontend code validates returned bounds and renders text; it does not reclean.

#### N4 cleaning table and vectors

**After this work.** Character data is pinned to Unicode 15.0.0
[UnicodeData.txt](https://www.unicode.org/Public/15.0.0/ucd/UnicodeData.txt)
(SHA-256 `806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73`)
and [PropList.txt](https://www.unicode.org/Public/15.0.0/ucd/PropList.txt)
(SHA-256 `e05c0a2811d113dae4abd832884199a3ea8d187ee1b872d8240a788a96540bfd`).
The shared implementation owns the generated L*/Nd and M* range tables from
that same UnicodeData, including First/Last ranges. It uses neither host-
dependent Unicode classification nor a new general-category crate. The exact
removal/whitespace policy is below; ranges are inclusive.

| Status | Code points | Treatment, in order |
| --- | --- | --- |
| After this work | 0009–000D, 0020, 0085, 00A0, 1680, 2000–200A, 2028–2029, 202F, 205F, 3000 | Map White_Space to ASCII space before control removal; collapse runs and trim |
| After this work | 0000–001F, 007F–009F | Remove remaining Cc |
| After this work | 00AD, 0600–0605, 061C, 06DD, 070F, 0890–0891, 08E2, 180E | Remove Cf |
| After this work | 200B–200F, 202A–202E, 2060–2064, 2066–206F, FEFF, FFF9–FFFB | Remove Cf |
| After this work | 110BD, 110CD, 13430–1343F, 1BCA0–1BCA3, 1D173–1D17A, E0001, E0020–E007F | Remove remaining Cf |
| After this work | 034F, 115F–1160, 17B4–17B5, 2800, 3164, FFA0 | Remove additional blank-looking/filler characters |
| After this work | 180B–180D, 180F, FE00–FE0F, E0100–E01EF, FFFD | Remove variation selectors and transport replacement characters |
| After this work | UnicodeData M* | Keep at most two consecutive marks after a non-space base; drop leading marks and extra marks |
| After this work | Remaining text | Trim, truncate to 40 Unicode scalar values (at most 160 UTF-8 bytes), then trim again |
| After this work | No UnicodeData L* or Nd left | Name is absent |
| After this work | Reserved labels other than Wallet / Your wallet | Name is absent on whole token-sequence match anywhere, ASCII case-insensitive; token boundaries are ends or non-L*/Nd characters |
| After this work | Wallet / Your wallet | Name is absent only on whole cleaned-name match, ASCII case-insensitive |

**After this work.** Reserved sequences are Home, ElastOS, ElastOS Home,
Runtime, System, Inbox, People, Library, Documents and Assistant, matched as
whole token sequences anywhere. Wallet and Your wallet match only the whole
cleaned name, so Trust Wallet, Coinbase Wallet and OKX Wallet keep their names
with the generic mark. Check after truncation. Preserve other letter case; perform no
normalization or confusable folding. Look-alike letters in another script are
a stated limit, not authenticated branding. The generic WalletConnect mark and
separate transport/source label remain required even when a peer calls itself
MetaMask. All peer code-point filtering occurs in the one shared function. Fixed
validated extension labels bypass peer reserved-name rejection; they are derived
from the checked provider ID rather than peer metadata. Keep generated
Unicode table provenance and its required license with that implementation.

| Status | Input (escapes are literal test notation) | Cleaned name / peer mark |
| --- | --- | --- |
| After this work | `  Alice\tKey App  ` | `Alice Key App` / wallet |
| After this work | `Meta\u202EMask\u200B` | `MetaMask` / wallet |
| After this work | `\u3164\u2800\uFE0F` or emoji-only | absent / wallet |
| After this work | `\u0301A` | `A` / wallet |
| After this work | `a` followed by five U+0301 | `a` followed by two U+0301 / wallet |
| After this work | `\uD800Alice` in JS | transport `\uFFFDAlice`; cleaner returns `Alice` / wallet |
| After this work | `H` + Cyrillic U+043E + `me` | retained as untrusted text / wallet; not covered by ASCII reserved-name matching |
| After this work | `Home`, `SYSTEM support`, `Alice Home Wallet` | absent / wallet |
| After this work | `Wallet`, ` wallet `, `Your wallet`, `YOUR WALLET` | absent / wallet |
| After this work | `Trust Wallet`, `Coinbase Wallet`, `OKX Wallet` | retained exactly / wallet |
| After this work | `A` repeated 41 times | 40 `A` scalars / wallet |
| After this work | `钱包` | retained / wallet |
| After this work | absent, non-string at the client, or client string over 1,024 bytes | omitted metadata, absent / wallet |

**After this work.** Store optional provider_id, wallet_display_name and wallet_mark, separate
from the person's label. provider_id is the same single validated identity
field carried on the wire and Bus; it is absent for WalletConnect. The shared
function uses it to derive injected names on read, rather than inferring a
provider from a stored name. Without it, an old injected record uses the
generic fallback. For WalletConnect, the stored cleaned display name is fed
through that same peer cleaner on read and the mark is always wallet. Mark keys are wallet, metamask and unisat;
provider identity selects an extension mark, but every WalletConnect peer gets
wallet, regardless of its name. Brand marks for WalletConnect peers remain a
human question, default generic. The bundled map remains Wallet's icon-64.png,
metamask.png and unisat.png; remote URLs, SVG/data icons and caller marks are
excluded. Metadata changes only on a successful matching link/relink, never a
failed proof or another principal/connector. A relink keeps the canonical ID,
user label and defaults; it does not create a duplicate account.

**After this work.** Render the returned name in its own text element with
`dir="auto"` and `unicode-bidi:isolate`, separate from trusted Home/app labels.
Use one clipped line, overflow hidden, text-overflow ellipsis and bounded line
height so marks cannot cover neighboring controls. Accessibility uses that same
cleaned name; the decorative mark has empty alt text. Do not interpolate raw
peer text into HTML, selectors, URLs or an instruction that looks Home-owned.

#### N4 compatibility and tests

**After this work.** All three optional stored display/identity fields use serde default and
omit-when-absent behavior. Old records show Your wallet, the generic mark and known
address/network, retaining any user account label. Do not infer past MetaMask
versus Brave selection from connector_id alone. Invalid stored display values
use the same shared cleaning/fallback path without changing account authority.

**After this work.** Update from 2.0.1 preserves accounts, defaults, proofs,
requests and keys under their normal expiry/revocation rules. Undo reads old
and newly linked accounts; the old writer may drop display fields on save.
Re-update then shows the fallback. There is no one-way migration. Exact-version
installed proof and mixed-Bus tests remain required; source Serde tolerance is
not installed acceptance.

| Status | Runtime/Wallet lane tests | Location / proof |
| --- | --- | --- |
| After this work | `n4_metadata_bounds_and_text_rendering`, `n4_metadata_bound_to_verified_link`, `n4_old_record_and_reopened_window` | Runtime/navigation owns: shared cleaner, provider/server targets and real view modules; ownership, isolation, marks, bounds and fallback |
| After this work | `n4_wire_fields_host_runtime` | Runtime/navigation owns; imports shared packet fixture from N2; identity field/actor match, well-formed transport, successful recorded-pattern link; no second mapper |
| After this work | `n4_cleaning_vectors_shared` | Runtime/navigation owns: every vector and exact Unicode tables above; all call sites use the shared implementation |
| After this work | `n4_bus_mixed_version_optional_metadata` | Runtime/navigation owns: fields absent accepted by old shape; strict old consumer rejects new params before mutation; compatible new pair preserves them |
| After this work | `n4_update_201_undo_preserves_accounts` | Runtime/navigation owns the test; integration runs installed update, add link, Undo, old operation/save, re-update and fallback |

**After this work.** Out of scope: authenticated peer branding, remote icons,
confusable detection, user-label/key migration, a new Brave mark and guaranteed
branding retention through an old writer. Sasha and Irzhy review spoof-resistant
presentation; brand marks for WalletConnect peers default to generic until a
human decision.

### Request visibility across Runtime sessions

**Today.** ListApprovals filters pending records by principal, while connector
handoff checks session_id. Inbox uses that same list. A new sign-in can
therefore show an earlier session's Review control that fails at handoff.

**After this work.** A pending request is offered only in its own Runtime
session. ListApprovals uses the verified caller's session as well as principal;
pending records with another or absent session_id are omitted even when
include_resolved is true. Wallet, Inbox, connector feeds, pending/unread counts
and the Wallet badge use this filtered projection. A new session gets no
Review, Approve, Reject or Send for that record. This avoids offering an action
that cannot work, without expiring a request that might still belong to a
live session on another client.

**After this work.** Keep the original stored record, session binding, status,
hash and normal expiry/history pruning. Do not rebind, clone or automatically
resubmit it. Its own still-authorized session keeps its existing rights.
Resolved history remains history; the existing owner Dismiss rule for an
already-approved WalletConnect transaction stays unchanged and grants no Send.
A stale selection or direct review/preflight/handoff from another session is
request_unavailable, not a server-failure journey. The N1/N2 adapters to be built use
the specified HTTP 404/request_unavailable body. Wallet/Inbox and windows
show: "This request is unavailable. Return to the app and ask for a new request."
The app must create a fresh ID under the current session; Home never carries
the old request across sessions.

**After this work.** n4_pending_requests_current_session_only is owned by
Runtime/navigation: provider dispatch/all targets, gateway, Inbox, Wallet,
badge and all connector selectors. The provider/list/count/card cases can be
built before the human review; connector-selector and stale N1/N2 adapter cases
wait for that gate. The whole test is complete only after both groups pass.
It fails today on the principal-only list;
it must prove same-principal/two-session and absent-session cases, count
filtering, stale selection without a wallet call, unchanged stored records,
owning-session access and the retained Dismiss exception. Update/Undo does not
migrate sessions: 2.0.1 may again show its old unusable card after Undo, but still
refuses cross-session handoff; re-update applies the filter again.

### N5 WalletConnect internet entry in Inbox

**Today.** The single entry ID is walletconnect-internet:permission. After
refusal/off/expiry its decision entry may have no action_ref. Inbox nevertheless
shows working Allow, calls allowInternet(null), posts exactly
`{action:"request"}` to `/api/apps/wallet-walletconnect/internet`, obtains the
current question, requests the owner's passkey proof, and answers that ID.
The grant is already bound under the consent lock to current Consent.id,
requested status, 30-minute expiry and passkey proof. Question creation is
idempotent under that same lock. A guest request creates no question; the guest
is told to ask the owner. These are source facts, not missing producers.

**After this work.** Keep that behavior and the existing producer. Add no field
to the strict Consent record, no expected_entry_id/expected_consent_id request
field and no additional fence. The existing grant fence is the current consent
ID/status/expiry/passkey check, not the constant notification entry ID. There
is no demonstrated sequence in which that gate grants a stale question. A
recovery may use a question another owner window just created; the passkey still
authorizes that current question. Cancelling the passkey leaves the fresh
question unanswered for its normal lifetime.

| Status | Kind / current state | Inbox controls and behavior |
| --- | --- | --- |
| After this work | walletconnect_internet_request; current requested and unexpired | Allow and Don't Allow using the current action ID; re-read before proof |
| After this work | walletconnect_internet_decision; granted | Turn Off using the current turn-off action |
| After this work | decision; refused | Allow recovery via `{action:"request"}`, then the current question/proof |
| After this work | decision; revoked with cleanup complete | Same Allow recovery; accounts remain in Wallet |
| After this work | decision; question expired | Same Allow recovery, obtaining a new active question before proof |
| After this work | decision; cleanup_pending or owned sockets closing | Turn Off again; Allow waits for existing cleanup to finish |

**After this work.** Inbox chooses by entry kind and current state, not merely
the action prefix. A decision entry never shows Don't Allow. Retain the current
producer's absent action_ref after completed Turn Off; do not fabricate allow
references for off records. A stale request card does not silently become a
recovery action. Runtime still checks ID/status/expiry/proof independently.

**After this work.** An existing grant/step-up stale-ID/status/expiry refusal has one fixed answer:
HTTP 409 with exactly the N2 error body and code conflict. The existing request,
step-up and answer checks keep their semantics; only their conflict projection
is standardized. Inbox displays exactly: `Refresh Inbox and review the current request before trying again.` It refreshes, creates no automatic retry
and neither grants nor fabricates a question on that error. This is response
classification, not a new consent fence or producer change.

**After this work.** Follow Browser's current request/decision pattern while
keeping WalletConnect's listed differences: Cancel drops the unsent local
intent but leaves the question; Turn Off clears connection state and relay
work; cleanup may need another Turn Off; Manage in Inbox is beside Connect,
not Browser settings. Titles/dates, general focus/count policy and Browser's
implementation stay unchanged. Permission wording identifies the internet
question, relay address visibility, wallet-held keys and separate wallet
approval. Allow returns to WalletConnect through N1; it resumes only the same
still-active intent once. Refusal, revocation, expiry and Cancel drop that
intent; a later Allow gives readiness for a new explicit action. Delayed reads
cannot overwrite the newer permission state or resurrect a dropped intent.

**After this work.** A guest is told to ask the owner; no Ask owner button,
owner notification or question-creation path is added. A guest can explicitly
check again after the owner acts under the existing rules. Whether a guest may
ask the owner from this window remains Anders's question; default is instruction
only. Guest extension linking also keeps the existing Runtime proof rule until
Anders decides its policy; no new guest-specific block or authority is inferred.

| Status | Required named tests | Lane / location |
| --- | --- | --- |
| After this work | `n5_permission_entry_all_states`, `n5_allow_after_refusal_off_expiry` | Runtime/navigation owns: Inbox real producer, current-ID/passkey routes and six-state UI; retain absent-action assertions and existing working recovery tests |
| After this work | `n5_inbox_action_by_kind_and_409`, `n5_guest_request_creates_no_question` | Runtime/navigation owns: Inbox/gateway; decision versus request, exact conflict answer, stale proof/ID/expiry, idempotent concurrent request creation and guest instruction |
| After this work | `n5_cleanup_blocks_allow_until_complete` | Runtime/navigation owns the joined test; WalletConnect lane supplies its controller; existing cleanup predicates, failed cleanup and retry |
| After this work | `n5_retired_intent_never_resumes` | WalletConnect-window lane owns: real controller/client, Home return and delayed read; same active intent resumes once, dropped intents stay dropped |

**After this work.** Out of scope: new consent fields/fences, producer changes,
Browser policy changes, hosted Exit selection, more relay hosts, a second switch
and guest-to-owner request creation. Owner: Runtime/Inbox/Wallet/navigation lane,
with the WalletConnect lane retaining the local intent sequence guard.

### N7 requesting site display

**Today.** Runtime's Browser signature producer stores optional origin and
page_url in the private payload; Browser transactions carry them in their
Runtime transaction intent. SystemWalletApprovalSummary omits a general site
field. Browser account access already has a validated review.origin, but its
siblings do not display the same site projection. Signing/transaction origins
are recorded Browser input, not proof that a website was independently
authenticated. N7 adds display context, not that proof.

**After this work.** The one optional output field is `requesting_origin`,
a string omitted when absent. Runtime/navigation owns it on each permitted
SystemWalletApprovalSummary and the principal's private Inbox
wallet_approval_request entry. It is available to that principal's Wallet and
Inbox, and only to the connector matching the record's connector_id; managed
requests have no connector recipient. Derive the audience from verified
Runtime authority, never a caller-provided audience or principal. Apply the
existing request visibility rules, including
[the session filter](#request-visibility-across-runtime-sessions), before projection.

**After this work.** No requesting_origin or new site label is copied into
generic Home/shell summaries, badges, System/Chat/other-app notifications,
another principal's response or another connector's feed. Shared DTOs default
the field to absent for those audiences. Home remains a broker, not a site
consumer: N1's navigation read and N2's envelopes keep their exact fields.
Browser's existing private request/status bindings remain unchanged.

**After this work.** One Runtime function,
`wallet_request_display_origin(record)` in gateway_wallet_approvals.rs,
produces the form for every permitted consumer. It reads only the immutable
recorded payload.origin and recorded page_url. It accepts only the
Runtime-produced Browser shapes below, with the verified stored
requested_by_actor equal to browser and the producer's principal/session,
account and chain bindings matching the stored request. Transaction effect
bindings remain checked against Runtime's existing effect record. Metadata
from another app is ineligible even if it copies these keys or schemas.

| Status | Eligible request | Recorded source |
| --- | --- | --- |
| After this work | browser_personal_sign / browser_typed_data_sign | payload schema elastos.browser.wallet-signature-request/v1; matching method and existing request bindings |
| After this work | Browser transaction_intent | payload schema elastos.chain.unsigned_transaction_intent/v1, source browser_wallet and its Runtime effect binding |
| After this work | browser_account_access | payload schema elastos.browser.account-access-request/v1, permission eth_accounts and its existing record bindings |

**After this work.** The eligible producer is the local Browser wallet bridge.
Origin/page_url supplied by a remote Engine peer, including the currently
inactive gateway_browser_remote admit/forward_remote_wallet_consumer_request
path, is ineligible even with an authenticated peer, browser actor, matching
schema or page/generation binding. Those bindings authenticate the peer, not
the site's origin. A future remote producer must keep its reported origin out
of display-eligible local request shapes until separate provenance review;
a peer-supplied "local" marker supplies no proof. Imported or otherwise unknown
producer provenance gives no site. This adds no persisted N7 provenance field
or new remote-wallet feature. n7_site_absent_or_forged_origin covers the remote
mediation path as well as copied local keys; it cannot create a site label.

**After this work.** Missing, null or non-string recorded origin gives no field,
even if page_url alone could suggest a site. Neither a reason/resource, a
signature message, wallet peer name, client field/query nor a fixture label is
a source. The helper respects the existing 32 KiB approval-payload bound before
parsing page_url. Invalid display metadata is omitted; it does not reject or
rewrite the approval, payload, payload hash, authority or original private data.
Rejected metadata is not logged as raw origin/page_url.

**After this work.** Source origin and output are each 1–512 ASCII bytes.
Source must contain only an absolute HTTP(S) scheme and authority: no
credentials (including an empty userinfo marker), backslash, whitespace/control,
path (even a trailing slash), query or fragment. Runtime's existing url parser
checks the host and consistency with the recorded page_url's origin, then
origin().ascii_serialization() supplies lowercase scheme/DNS host, bracketed
IPv6 and a port only when non-default (80 for HTTP, 443 for HTTPS). There is no
DNS lookup. The private page_url may contain a path/query/fragment; none is
projected. A mismatching or over-bound value gives no field, never truncation.

**After this work.** Non-ASCII source origins are omitted. ASCII IDN A-labels
such as xn--bcher-kva.example remain literal ASCII in the output and on every
screen; neither the server nor a consumer decodes them to look-alike Unicode
letters. No consumer has a second formatter, Unicode-host display or friendly
site-name substitute. This prevents Unicode look-alikes being rendered as a
different plain-ASCII site; it does not authenticate the site or detect every
ASCII look-alike.

| Status | Recorded origin / condition | requesting_origin |
| --- | --- | --- |
| After this work | https://Shop.Example:443 with matching page URL | https://shop.example |
| After this work | http://localhost:8099 | http://localhost:8099 |
| After this work | https://[2001:db8::1]:443 | https://[2001:db8::1] |
| After this work | https://xn--bcher-kva.example | Same literal ASCII text |
| After this work | https://bücher.example | absent |
| After this work | https://user:pass@shop.example or https://@shop.example | absent |
| After this work | https://shop.example/ or /pay, ?q or #fragment on the origin | absent |
| After this work | More than 512 bytes, non-string, mismatch with page_url, or missing recorded origin | absent |
| After this work | Non-Browser app with forged origin/requesting_origin | absent |

**After this work.** Inbox, Wallet and the owning connector render that exact
value as text in its own element, with dir=auto and unicode-bidi:isolate,
separate from the trusted app name and untrusted request details. The default
label is "Site reported by Browser". The full origin must be available before
a decision; it is not replaced with a friendly or shortened host. It is never
HTML/Markdown, an anchor, linkified text, a navigation target or a wallet/RPC
parameter. Home, Runtime and connectors make no routing, permission, account,
network, approval, signing or completion decision from this projection.
Existing approval and account-access origin bindings stay as they are.

**After this work.** Account-access cards use this same field for site identity,
not a separately formatted review.origin or page_url. Existing review data
remains for the existing account-access protocol, not as a display fallback.
When the field is absent, show the requesting app only and omit the site row;
never guess a site from other text. The site identity appears once per card;
the existing generated account-access reason can use an intent-based sentence
rather than repeat its embedded origin. Other request content is labelled as
content from the app, not as site identity.

**After this work.** No requesting_origin field is persisted or added to Bus
operations, and no payload/schema/hash is migrated. On update from 2.0.1, an
older record projects a site only when its existing eligible origin and page
bindings pass the same helper; a record without them remains app-only. Requests
created between update and Undo keep their ordinary JSON payload origin and
page_url. 2.0.1 reads those same fields and preserves payload Value on save,
but does not provide N7's display field. Re-update recomputes it if the record
survives normal expiry/pruning. Undo never restores request authority or carries
a request to another session. Installed round-trip proof remains required.

| Status | Named test | Accountable owner / proof |
| --- | --- | --- |
| After this work | `n7_browser_site_projection_all_surfaces` | Runtime/navigation owns the joined Rust/Inbox/Wallet test; browser signatures and transactions appear in all three permitted places for each matching connector, managed requests in Inbox/Wallet only; every other audience has no new field/label |
| After this work | `n7_site_absent_or_forged_origin` | Runtime/navigation; positive recorded-Browser control plus non-Browser, missing/invalid recorded origin, forged client/payload/query/reason values, wrong principal/connector and generic Home/System/Chat responses |
| After this work | `n7_origin_form_and_ascii_vectors` | Runtime/navigation; every vector above, bounds, backslash/control cases, default/non-default ports, unchanged approval/hash and no raw credential logging |
| After this work | `n7_account_access_uses_same_projection` | Runtime/navigation; same site in the sibling question, one site label, unchanged grant/step-up bindings, no display fallback to page_url |
| After this work | `n7_old_records_update_undo` | Runtime/navigation owns fixtures; integration runs installed 2.0.1 update, create requests, Undo/save/re-update, missing-origin fallback and byte-preserved private data/bindings |
| After this work | `n7_connector_site_rendering` | Shared-view enabling lane is the single accountable owner of one joined three-connector test; WalletConnect-window contributes its real renderer. Shared packet/summary fixtures, plain isolated text, literal A-labels and zero URL navigation |

**After this work.** N7 adds no Browser method, chain or connector pairing.
Producer journeys use supported Browser flows; all three connector renderers
can be checked with the authorized summary shape without claiming a new
Browser-to-UniSat signing/transaction flow.

**After this work.** These new named tests must fail against today's omitted
projection/consumer behavior before implementation and pass after it. JS runs
in the behaviour suite; all affected Rust targets run in their lane's leased
checks and release CI. Out of scope: website navigation, authenticated website
branding, live-page attestation, new approval authority and new persistent
request data. Human security question: may a recorded Browser origin be called
a verified site without independent Browser-engine provenance? Irzhy with
Anders answers; default is "Site reported by Browser", display only, with no
verified-site claim.

### Wallet connection integration proof

**After this work.** Names above and below are obligations. New behavior gets
real-module fail-before/pass-after tests; existing guards remain passing tests.
The owning tables include shared-packet conformance, frame lifetime, stage,
error, delivery and metadata cases. Home and every window import the same v2
fixture file; source-independent copies of those examples are not allowed. The release
integrator runs the combined Linux and installed jobs; source checks alone are
not product acceptance.

| Status | Required test | Owner / proof |
| --- | --- | --- |
| After this work | `wallet_connection_same_id_installed_journeys` | Integration: one ID through Inbox/Wallet/connector/result; messages on all three, transactions on WalletConnect/MetaMask only; leftover pending/handed-off/busy/reopened states and no duplicate send |
| After this work | `wallet_connection_real_wallets_and_webkit` | Integration owns: installed real relay peer, actual MetaMask/UniSat, WebKit and native desktop, exact versions/artifact hashes and human trial |
| After this work | `wallet_connection_expiry_reconnect_and_controls` | Integration owns: actual producers, expiry/reconnect, every accepted control, focus and human screen-reader checks |
| After this work | `wallet_connection_old_home_tab_across_update` | Integration owns the installed update case: new v2 window in old Home makes zero provider calls and uses N2's payment-safe unsupported-version guidance; a pre-existing v1 window may reach the wallet, but its old link has no admission_id and Runtime refuses it without linking. Browser-owned reload/reopen guidance is permitted only when payment safety is established; pre-existing v1 documents gain no v2 behavior retroactively. |
| After this work | `n2_guest_without_proof_creates_no_prompt` | Runtime/navigation owns JS plus Runtime admission coverage; absent proof is rejected before prompting under today's principal policy |

**After this work.** These cases require primary recordings before their replay
fixtures are written; a lane cannot manufacture a provider reply from this
specification. New raw observations take precedence over an older report:

| Status | Recording-gated test | Evidence gate / affected tests |
| --- | --- | --- |
| After this work | `n2_real_transaction_hash_and_late_receipt_recording` | Scripted-extension lane owns fixture validation/import; Home and Runtime/navigation own its consuming tests. Raw follow-up recordings now contain MetaMask sends returning hashes, including after more than 100 seconds, with independent local-chain receipts. Validate/import those observations before transaction branches of n2_one_deadline_stop_late_reply, n2_transaction_completion_after_frame_close and real transaction acceptance. The local test chain adds no supported product network or installed proof. |
| After this work | `n2_real_unisat_link_after_unlock_recording` | Scripted-extension lane owns fixture validation/import; Home and Runtime/navigation own its consuming tests. Raw follow-up recording now shows a single locked requestAccounts completing after unlock and account approval. Validate/import it before the empty-account prompt branch of n2_empty_accounts_prompt_on_send/link admission acceptance; combine with recorded proof signing and real Runtime verification to prove linking, which requestAccounts alone does not prove. |
| After this work | `n2_real_brave_discovery_and_silent_check_recording` | Scripted-extension lane owns the missing fixture; Home and Wallet consumers wait. Still awaits configured Brave announcements, identity and non-prompting reads; Brave replay/alternatives and n4_old_record_and_reopened_window compatibility wait for it. |

**After this work.** Structural tests may use the contract's enum/wire examples;
those are not invented provider observations. Existing recorded signature
patterns still cover the message/deadline branches. Record new reply hashes,
versions and observation provenance in the fixture before writing the blocked
replay cases. Unit-test proof signatures may use isolated fixture keys and do
not claim real-wallet compatibility.

### Lane start gates and shared-file order

**After this work.** Main's contract diff check permits only the pre-review
column below. The scripted-extension fixture and shared-view enabling commits
come first; the four build lanes then take those dependencies. Irzhy's recorded
N1/N2 review, or Anders's explicit waiver, opens the gated column. N1 reviews
who may move Home's window; N2 reviews which page may drive an extension and
with what authority, including nullable paymentPending, result settlement,
close/return focus and the received-hash deadline. NB1 is a proposal: choose
the default or fallback explicitly before any of its gated implementation.
Main records the reviewed contract tree and fixture commit in #575. A contract
diff PASS is not this human approval.

| Status | Lane / files it owns | May build and test before N1/N2 human review | Waits for that review or waiver |
| --- | --- | --- | --- |
| After this work | Scripted-extension enabling | First commit creates scripts/fixtures/wallet-connector-v2-messages.json with valid/invalid draft packets, N1 rows, N4 wire and N7 summaries; recorded provider replays and primary-recording validation/import, including stalled MetaMask and transaction/unlock observations. Validate JSON/schema examples without enabling Home effects. | Real-module N1/N2 integration and any claim that draft conformance proves approved authority. Still-unrecorded Brave cases also wait for their recording. |
| After this work | Shared-view enabling | Pure renderers/state reducers on supplied fixtures; isolated wallet/site text, fixed local copy, geometry and operable exits. Own the single joined wallet_windows_state_producers_and_controls and n7_connector_site_rendering matrices across all three real window views; run render-only cases now. | Live Home messages, hello/ready, N1 delivery and controls that invoke N2. Actual-producer branches of the joined state/control matrix wait; a render-only pass is partial evidence. |
| After this work | Runtime/Inbox/Wallet/navigation; all Rust, capsules/inbox/browser/inbox.js, capsules/wallet/browser/** and capsules/home-gui/browser/** | N3 classification, existing direct-approval refusals, Reject/Dismiss acknowledgements and GUI badge; N4 shared cleaner, optional metadata/storage and existing-route cases; provider/list/card/count parts of session visibility; N5 current consent routes/kind/409 rules; N7 local projection/privacy/compatibility and Inbox/Wallet rendering. Run n3_direct_external_approve_refused, only provider/Inbox/Wallet subcases of n3_reject_dismiss_acknowledgement, n3_wallet_badge_counts_review_requests, n3_requester_provenance_without_site_invention, pure N4 cleaner/storage tests, N5 existing-route tests and N7 tests on current scoped routes. | Every N1 selector/read/allow-list/GUI selection, source-app row and close-return/focus extension; connector subcases of n3_reject_dismiss_acknowledgement; N3 Review in Wallet/open-stored-connector delivery and n3_same_request_to_each_connector; click/navigation cases of n3_external_inbox_review_action; N4 connector-selector/stale-adapter subcases of n4_pending_requests_current_session_only; n4_wire_fields_host_runtime and injected-link adapter cases; all new N2 routes/admission, shell-host hooks, payment safety routing, hash/no-hash settlement authority/binding/retention, waiting list/count, selected terminal-result read and result provider/storage/view changes. Full joined n2_* Home-plus-Runtime rows and all n1_* tests wait. |
| After this work | Home-extension build; capsules/home/browser/home-wallet-connector-host.js | Review recorded replay data and draft fixture structure; prepare the test inputs. No new N2 product implementation. | All new N2 host effects, state/generation/readiness/continuation/paymentPending/retry code and real-host tests, including its single accountable n2_v2_message_fixtures_shared matrix. Runtime/navigation supplies home-shell-host hooks after the gate; extension imports them. |
| After this work | MetaMask/UniSat-window build; their browser files | Consume the enabling pure views and draft snapshots for N4/N7 rendering and extension_request_feedback_in_view; contribute real view cases to the shared owner. Fixed copy and view-only tests use fixtures without invoking Home. | Sending hello, enabling N1 rows, current-authority effect clients, N2 state/effect routing and live controls; end-to-end test branches that reach Home/Runtime adapters. |
| After this work | WalletConnect-window build; capsules/wallet-walletconnect/browser/** and scripts/walletconnect/adapter.mjs | Existing-authority SDK error/local wait/intent handling, E5 stopped-pairing cleanup and walletconnect_stopped_pairing_ends_before_new_qr, N4 peer-name rendering on its existing link route, N5 local intent/cleanup cases, N7 rendering contribution and walletconnect_request_feedback_in_view. Test these through current scoped APIs or pure view fixtures. | WalletConnect hello/ready as well as all its new N1 rows (including Inbox return/activity/source-app) and packet/state routing. Home-return/navigation subcases of n5_retired_intent_never_resumes wait. It remains outside injected-provider N2 effects. |
| After this work | Integration/release | Assemble existing-route and render-only evidence with exact artifacts; retain partial results and named outstanding gates. Run ungated compatibility cases only after their implementations exist. | Full one-ID Inbox→Wallet→connector journeys, installed old-Home cases, received-hash/update/Undo proof and product acceptance wait for gated implementations, review and all dependencies. Anders's final trial remains required. |

**After this work.** Split mixed tests into clearly named subcases inside the
existing test name; do not create a second owner or a second test with the same
promise. In particular n4_pending_requests_current_session_only has ungated
provider/list/count/card cases and gated connector-selector/adapter cases.
Report each group separately; the full named test is not PASS until both run.
The same rule applies to mixed N3, N4 wire, N5 return and shared-window matrices.
Pre-review candidates keep incomplete new navigation/effects unexposed; pure
tests do not authorize an installed partial journey.

| Status | Shared file | First editor / permitted first change | Later editor / permitted later change |
| --- | --- | --- | --- |
| After this work | capsules/wallet-provider/src/approval.rs, storage.rs and models.rs | Runtime/navigation, pre-review: N4 metadata and session/list visibility only; N3 refusal tests leave approve_and_sign_managed and its signing/expiry helpers unchanged. Keep current completion semantics | Same lane, after review: atomic external_result_deadline_at/result-authority binding, chosen NB1 operation, receipt precedence/idempotency, retained binding, active-quota/pruning and state transitions. Preserve earlier filters/metadata and their tests. |
| After this work | capsules/inbox/browser/inbox.js | Runtime/navigation, pre-review: N3 classification presentation/refusal/acknowledgement, N5 kind/consent controls and N7 text | Same lane, after review: N1 Review in Wallet selector/result delivery and any selector-dependent Open control. Preserve consent and display changes. |
| After this work | capsules/wallet/browser/wallet-requests.js and wallet-activity.js | Runtime/navigation, pre-review: N4/N7 text, filtered list/count, existing Reject/Dismiss acknowledgement | Same lane, after review: selected-request connector launch through N1, then gated MetaMask result/settlement view and canonical waiting count/list. Wallet index heading/focus receiver also waits. Preserve earlier rendering and WalletConnect-only Dismiss predicate. |
| After this work | capsules/wallet-walletconnect/browser/wallet-walletconnect.js | WalletConnect-window, pre-review: local waits/cleanup, existing consent intent, metadata/site/feedback views | Same lane, after review: hello/ready and N1 navigation/state delivery only, preserving those views and cleanup guards. Other lanes contribute tests/exports rather than editing this file. |
| After this work | capsules/home/browser/home-shell-host.js and capsules/home-gui/browser/** | Runtime/navigation alone; pre-review GUI badge only, no new N1/N2 shell-host edits | Same lane after review owns N1 close/return/focus and the specified N2 hook exports, frame load/removal/expiry/renewal and state routing; Home-extension consumes the hooks and does not edit the file. |
| After this work | scripts/fixtures/wallet-connector-v2-messages.json | Scripted-extension enabling first commit: provisional protocol/examples before human review | Integrator coordinates accepted changes after review; every Home, Rust, shared-view and window consumer imports the same accepted bytes. No lane keeps a private copy or an older draft packet shape. |

**After this work — fixture correction.** Replace round 5's seven-key
transaction handoff example with the existing six-key envelope; the seventh
deadline key is an invalid example. Preserve the real v2.0.1 Home source
provenance for n2_old_home_transaction_handoff_compatible. New draft examples
also cover nullable safety, the proposed settlement route and three outcomes,
refused advisory/receipt semantics, selected-result read selectors, and the
internal Accounts close-return delivery. No new handoff schema or deadline read is introduced. Scripted-
extension owns the provisional file; integrator coordinates changes after
review. If the reviewer chooses the fallback, remove valid no-hash producer/
operation examples and assert their absence; do not ship both policies as a
runtime/user setting. All imported packet consumers must be rerun.

**After this work.** The first shared file intentionally encodes N1/N2 messages
before the human review. It is a draft contract test input, not a security
decision. If the review changes a shape, predicate or bound, first update these
owning documents, then the one fixture, then every dependent consumer/test in
that order; repeat the affected conformance/behavior checks and discard earlier
draft PASS claims. Until first implementation is accepted, replace the draft
rather than adding a compatibility path for it. The shared-view enabling commit
supplies pure exports that later lanes import; the integrator coordinates any
later shared export change. Each file keeps its named editor through both
phases; the phase boundary is not permission for concurrent edits.

### For the human review of N1 and N2

**After this work — proposals for review.** Main records the accepted contract
tree, fixture commit, choices/waivers, checks/skips and next owner in #575.
Irzhy's approval and Anders's scope decisions open only the gated work they
cover. The default and fallback are alternatives for that review, not a runtime
switch. Contract diff approval alone grants neither. Sasha owns final visible
copy under the selected behavior.

| Decision | Reviewer / proposed default until decided |
| --- | --- |
| Which page may drive which wallet, with what authority? | Irzhy; retain trusted Home plus matching carried proof-bound connector authority, exact closed effects, frame binding and one consumed handoff; no gated code before approval |
| Which N1 moves are permitted, including source-app return? | Irzhy/Anders; only the documented rows; Runtime derives source app, excluding Home/shell/sender; selectors grant no authority |
| Close-own-window and fixed Wallet return/focus? | Irzhy/Anders, Sasha on focus UX; retain existing self-close scope; gate the fixed Accounts return and non-action heading focus, preserving existing edits and provider-call occupancy |
| Stored result-collection duration? | Irzhy; proposed 43,200 seconds from approved_at, immutable and independent of live token/session expiry; not a signing/send extension |
| May Home report a settled no-hash result? | Irzhy; proposed NB1 default: 4001/4100 terminal not-sent, ambiguous settlement unresolved; Home-only dual-authorized Runtime mediation and stored connector-result binding. If refused, choose the explicit hash-only fallback and its 100-active quota cost |
| May a no-send assertion outweigh positive hash evidence? | Irzhy; no. A same-bound late valid hash wins, no-hash cannot downgrade it, no second send; retain receipt bindings through the fixed bound under the store byte limit, admit new work only with reserved result space |
| What about quota after late correction and old pages? | Irzhy; recorded no-send releases active quota, old/unreported declines follow fallback; late hash recording is not refused as new admission, and existing completed-result accounting may block later admissions |
| How are outcomes/counts worded and counted? | Sasha with Irzhy; answered outcomes persist, no person-decline inference, no recorded answer differs from unresolved answer; one waiting list drives its labelled count and terminal not-sent leaves both |
| How is unknown WalletConnect activity treated? | Anders/Irzhy; nullable safety: true only for known work, null for unobservable cross-window activity. Presence is not a payment; neutral uncertainty/Close/check recovery, no reload/alternative while unknown. No invented trusted status producer |
| May a window read its selected retained result? | Irzhy; the gated scoped approvals selector returns at most one extra result for its verified principal/stored connector, preserves session rules and grants no mutation authority |
| Can the handoff wire shape change for old Home? | Compatibility constraint for the review to verify: preserve current six keys, nested shapes and schemas; no new old-page negotiation/read; old Home completes a transaction against new Runtime |
| May check disclose more accounts? | Irzhy/Anders; firstAccount for new link and required membership only |
| Which wrapper fact produces extensions_unavailable? | Sasha supplies, Irzhy reviews, Anders accepts; no producer in this release until a trusted fact is agreed |
| May a guest link or create an owner question? | Anders; existing proof rules and instruction to ask owner, no new guest request path |
| Is a recorded origin a verified site, including remote Engine input? | Irzhy/Anders; local recorded Browser projection only, labelled reported by Browser; remote/unknown provenance absent, no authenticated-site claim |
| Peer brand marks, name confusables or wallet unverified-origin warnings? | Sasha/Irzhy with Anders's decision; generic peer mark, the single bounded cleaner/isolated text, no extra authenticity claim or Home assurance |

**After this work.** Ungated display defaults apply only to the pre-review
column. Gated proposals become implementation instructions only after Main
records the human choice. They grant no generic wallet methods, new website
navigation, guest authority or connector reload capability.

### Design wording and focus constraints

**After this work.** Sasha/design owns the exact busy/Close window sentences;
the contract owns behavior and focus mechanism. Replace the design sentence
"You declined this transaction in MetaMask": 4001 also means native prompt
close, so [N2's outcome rule](HOME_SHELL_HOST_CONTRACT.md#n2-waiting-settlement-and-memory)
requires wallet-attributed non-approval without a claim about the person's
choice. Apply it consistently in connector and Wallet views. Show unknown
cross-window work as unknown, not an asserted payment. The focus journey must
include the preserved active-Wallet-edit and failed-return cases specified by
N1. This document does not edit or approve the design pictures.


## Red Lines

- No address-only login.
- No wallet-address-derived encryption keys.
- No arbitrary signing.
- No app-visible wallet RPC or node RPC.
- No private keys outside wallet-provider authority.
- No Essentials or UniversalX requirement for default Home unlock.
- No blockchain UI before fail-closed tests and capability schema exist.
