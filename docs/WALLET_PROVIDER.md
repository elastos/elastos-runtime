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

**After this work.** Runtime decides authority and stored request provenance;
wallet-provider owns accounts/proofs/receipts; Inbox owns internet consent;
Wallet owns account/request review; a connector asks for an allowed effect.
[N1 and N2](HOME_SHELL_HOST_CONTRACT.md#injected-wallet-connector-effects-n2)
own the exact frame, navigation and Runtime edge messages. The existing
[Clipboard edge](HOME_SHELL_HOST_CONTRACT.md#first-party-clipboard-edge) owns
Copy link. The source-app recovery row is included in N1's issue scope and human
review. WalletConnect client error classification stays inside its existing
capsule authority; a design label N6 adds no new effect or permission.

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
passkey. Wallet reads the canonical record, shows the existing reason/account/
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
Runtime catalog label, falling back to the bounded literal actor ID. For
ordinary Browser signatures/transactions they may say Browser passed the
request and that site details are unavailable. They cannot show example.org,
This Home, a fixture site or a guessed URL as the verified requester. Existing
validated account-access review.origin may be rendered as isolated plain text
for that intent only. No site field is added in this release, and cards do not
parse one out of reason, resource or a message to sign.

**After this work.** A future general site display needs Runtime validation
against the active Browser page and origin, bound to the requesting actor,
principal/session, request ID and payload hash, then one reviewed typed
projection shared by Inbox, Wallet and connectors. That is separate work.
Recovery here opens the asking app with an empty query, not the website. Copy
must say return to the requesting page in Browser where appropriate; Open
example.org is unsupported. Home's ownership proof and an app's signing request
remain distinct purposes; a fixture cannot turn one into the other.

**Today.** Handoff changes pending to approved before the outside answer.
Outside decline does not itself store Home rejection. Consumed message requests
leave the pending feed; approved WalletConnect transactions remain in Wallet
with Dismiss under [the existing receipt rules](#first-shippable-slice).

**After this work.** Preserve that lifecycle. Wallet Reject ends a pending
Home request. Dismiss closes an eligible handed-off WalletConnect transaction
locally, not in the wallet. After Reject/Dismiss, clear selection before refresh
and retain the acknowledgement; Activity remains a separate action. A consumed
ID is never resent. Result unknown must stay explicit when Home lacks a receipt;
a returned hash alone establishes neither chain confirmation nor that the
transaction matches the payload.

**After this work.** [Issue scope](https://github.com/elastos/elastos-runtime/issues/575)
is a message on each connector and a transaction on WalletConnect and MetaMask
only. UniSat signs messages only today; a Bitcoin transaction through UniSat
would be new authority and is not in this scope. No transaction decision remains
open for this contract.

| Status | Runtime/Inbox/Wallet/navigation lane tests | Run location |
| --- | --- | --- |
| After this work | `n3_external_inbox_review_action`, `n3_direct_external_approve_refused` | Server producer and both routes; real Inbox controls, old cards and managed/account-access regressions |
| After this work | `n3_same_request_to_each_connector`, `n3_reject_dismiss_acknowledgement` | Real Wallet/Home/window modules, provider and headless journey |
| After this work | `n3_wallet_badge_counts_review_requests`, `n3_requester_provenance_without_site_invention` | Real GUI badge and cards; actor provenance, account-access exception, absent site and fixture rejection |

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
| After this work | Reserved labels as whole token sequences, ASCII case-insensitive | Name is absent; token boundaries are ends or non-L*/Nd characters |

**After this work.** Reserved sequences are Home, ElastOS, ElastOS Home,
Runtime, System, Wallet, Your wallet, Inbox, People, Library, Documents and
Assistant. Check after truncation. Preserve other letter case; perform no
normalization or confusable folding. Look-alike letters in another script are
a stated limit, not authenticated branding. The generic WalletConnect mark and
separate transport/source label remain required even when a peer calls itself
MetaMask. All peer code-point filtering occurs in the one shared function. Fixed
validated extension labels bypass peer reserved-name rejection; otherwise
Brave Wallet would be rejected as an untrusted use of Wallet. Keep generated
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
| After this work | `n4_metadata_bounds_and_text_rendering`, `n4_metadata_bound_to_verified_link`, `n4_old_record_and_reopened_window` | Shared cleaner, provider/server targets and real view modules; ownership, isolation, marks, bounds and fallback |
| After this work | `n4_wire_fields_host_runtime` | Shared packet fixture from N2; identity field/actor match, well-formed transport, successful recorded-pattern link; no second mapper |
| After this work | `n4_cleaning_vectors_shared` | Every vector and exact Unicode tables above; all call sites use the shared implementation |
| After this work | `n4_bus_mixed_version_optional_metadata` | Fields absent accepted by old shape; strict old consumer rejects new params before mutation; compatible new pair preserves them |
| After this work | `n4_update_201_undo_preserves_accounts` | Installed update, add link, Undo, old operation/save, re-update and fallback |

**After this work.** Out of scope: authenticated peer branding, remote icons,
confusable detection, user-label/key migration, a new Brave mark and guaranteed
branding retention through an old writer. Sasha and Irzhy review spoof-resistant
presentation; brand marks for WalletConnect peers default to generic until a
human decision.

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
is standardized. Inbox displays exactly: `This request has changed. Refresh
Inbox and review the current request.` It refreshes, creates no automatic retry
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
| After this work | `n5_permission_entry_all_states`, `n5_allow_after_refusal_off_expiry` | Runtime/Inbox real producer, current-ID/passkey routes and six-state UI; retain absent-action assertions and existing working recovery tests |
| After this work | `n5_inbox_action_by_kind_and_409`, `n5_guest_request_creates_no_question` | Inbox/gateway; decision versus request, exact conflict answer, stale proof/ID/expiry, idempotent concurrent request creation and guest instruction |
| After this work | `n5_cleanup_blocks_allow_until_complete` | Runtime and WalletConnect; existing cleanup predicates, failed cleanup and retry |
| After this work | `n5_retired_intent_never_resumes` | WalletConnect real controller/client, Home return and delayed read; same active intent resumes once, dropped intents stay dropped |

**After this work.** Out of scope: new consent fields/fences, producer changes,
Browser policy changes, hosted Exit selection, more relay hosts, a second switch
and guest-to-owner request creation. Owner: Runtime/Inbox/Wallet/navigation lane,
with the WalletConnect lane retaining the local intent sequence guard.

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
| After this work | `wallet_connection_real_wallets_and_webkit` | Installed real relay peer, actual MetaMask/UniSat, WebKit and native desktop, exact versions/artifact hashes and human trial |
| After this work | `wallet_connection_expiry_reconnect_and_controls` | Actual producers, expiry/reconnect, every accepted control, focus and human screen-reader checks |
| After this work | `wallet_connection_old_home_tab_across_update` | New v2 window in an old Home tab: zero provider calls, unsupported-version guidance and hidden new N1 controls until reload; pre-existing v1 documents do not gain v2 behavior retroactively |
| After this work | `n2_guest_without_proof_creates_no_prompt` | Home/Runtime admission rejects absent proof before prompting, under today's principal policy |

**After this work.** These cases require primary recordings before their replay
fixtures are written; a lane cannot manufacture a provider reply from this
specification. New raw observations take precedence over an older report:

| Status | Recording-gated test | Evidence gate / affected tests |
| --- | --- | --- |
| After this work | `n2_real_transaction_hash_and_late_receipt_recording` | Raw follow-up recordings now contain MetaMask sends returning hashes, including after more than 100 seconds, with independent local-chain receipts. Validate/import those observations before transaction branches of n2_one_deadline_stop_late_reply, n2_transaction_completion_after_frame_close and real transaction acceptance. The local test chain adds no supported product network or installed proof. |
| After this work | `n2_real_unisat_link_after_unlock_recording` | Raw follow-up recording now shows a single locked requestAccounts completing after unlock and account approval. Validate/import it before the empty-account prompt branch of n2_empty_accounts_prompt_on_send/link admission acceptance; combine with recorded proof signing and real Runtime verification to prove linking, which requestAccounts alone does not prove. |
| After this work | `n2_real_brave_discovery_and_silent_check_recording` | Still awaits configured Brave announcements, identity and non-prompting reads; Brave replay/alternatives and n4_old_record_and_reopened_window compatibility wait for it. |

**After this work.** Structural tests may use the contract's enum/wire examples;
those are not invented provider observations. Existing recorded signature
patterns still cover the message/deadline branches. Record new reply hashes,
versions and observation provenance in the fixture before writing the blocked
replay cases. Unit-test proof signatures may use isolated fixture keys and do
not claim real-wallet compatibility.

**After this work.** Main records candidate, checks/skips, reviews, installed
proof, remaining gate and next owner in the owning issue. Irzhy's contract and
network/session reviews and Anders's final trial remain acceptance gates; a
waiver belongs to Anders. Defaults for remaining human questions are:

| Status | Question | Who answers / default |
| --- | --- | --- |
| After this work | May the check disclose more than firstAccount and required membership? | Irzhy with Anders; narrowed projection only |
| After this work | Which trusted wrapper fact may produce extensions_unavailable? | Sasha supplies it, Irzhy reviews trust, Anders accepts scope; no producer in 2.0.2 until then |
| After this work | May a guest link an extension wallet or request owner consent from a window? | Anders; existing proof rules, instruction to ask owner, no new request path |
| After this work | Should Home explain a wallet's unverified-origin warning? | Irzhy advises, Anders decides; Home adds no warning or assurance |
| After this work | May self-named WalletConnect peers receive brand marks? | Sasha and Irzhy, with Anders's decision; generic mark |
| After this work | Is look-alike-name handling beyond the explicit table needed? | Sasha/Irzhy; isolated, clipped untrusted text, reserved labels blocked, no confusable-authentication claim |

**After this work.** Those defaults settle lane implementation. They grant no
new wallet methods, internet scope, page reload authority or website navigation.

## Red Lines

- No address-only login.
- No wallet-address-derived encryption keys.
- No arbitrary signing.
- No app-visible wallet RPC or node RPC.
- No private keys outside wallet-provider authority.
- No Essentials or UniversalX requirement for default Home unlock.
- No blockchain UI before fail-closed tests and capability schema exist.
