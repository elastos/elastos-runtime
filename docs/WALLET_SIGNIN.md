# Wallet sign-in Runtime contract

Runtime attaches wallet sign-in methods to an existing passkey account. System owns
that account's method list. Wallet owns payment connections. Home owns signed-out
sign-in. Account IDs, roots, Profiles and passkey added-from labels stay unchanged.

## Rules

An Admin adds and enables his own wallet methods. Each account can disable or
remove its own methods, including after demotion to Guest. Adding a wallet leaves Sign in off.
Turning Sign in on requires a fresh signature from that wallet and fresh passkey
approval for the exact action. Turning it off or removing it requires fresh
passkey approval. Payment links acquire sign-in authority only through this
explicit operation. Wallet sessions can use Home; passkeys approve sensitive actions.
Ordinary passkey removal keeps every account's final active passkey, including
accounts with wallet sign-in enabled. A separate passkey-approved Remove account
intent revokes that account's passkeys and clears its wallet access. Before
removing an Admin account, another account must retain an active Admin passkey.
Removal and switch off end the wallet's sessions and pending sign-in attempts. Concurrent changes are
serialized. Recovery Kit recovery keeps the passkey recovery flow and clears the
recovered account's wallets.

Supported signers are passkey, WalletConnect, MetaMask-compatible ordinary EVM keys
and UniSat Bitcoin mainnet proofs. Unsupported Bitcoin networks are refused before
a ceremony starts. WalletConnect supports Elastos Smart Chain (20) and Base
(8453). Contract-wallet signatures require a separate contract and are refused.
Wallet account creation, wallet-target recovery and wallet approval are disabled
at both begin and completion routes.

## Transport and errors

JSON POST bodies have a 96 KiB limit. Fields shown are required unless marked
optional. Signed-in requests carry the existing Home/System launch token in the
`x-elastos-home-token` header. Runtime checks the live session, account and method again
at completion. Public requests use the configured passkey origin policy (HTTPS
outside loopback). A ceremony lasts at most 180 seconds. IDs are opaque.
A caller generates a random 32-byte hex `browser_secret` per ceremony, keeps it
in tab memory, and sends it on begin and complete. Runtime stores its digest.
Secrets and signatures stay out of URLs, logs and durable browser storage.

Errors use HTTP 413 for an oversized body, 415 for an unsupported content type,
400/422 for malformed JSON or schema, 403 for invalid wallet
addresses, browser secrets or refused authority/proof, 409 for
changed state or conflicting ownership, 429 for capacity and 503 for unavailable
transport. JSON is `{"error":"wallet_signin_refused"}` for unknown wallet, wrong
browser, expired/replayed proof and disabled method. Signed-out responses disclose
no account names or ownership. A refused completion grants no session. A lost
completion response may be retried with identical input while the ceremony is
live; it returns the same result. After expiry, start again. Cancel is idempotent.

## List and manage methods

`GET /api/auth/wallet-methods` returns the caller's account only:

```json
{"account_id":"principal:…","methods":[{"method_id":"wallet:…","connector":"metamask","address":"0x…","chain_id":20,"network":"","sign_in_enabled":false,"created_at":1800000000,"last_used_at":null}]}
```

Passkeys remain available from the existing passkey list API, with existing
metadata. A wallet method has one account owner; connector names describe the
signer and convey no account authority. EVM ownership is chain and address;
Bitcoin ownership is network and address.

`POST /api/auth/wallet-methods/begin`:

```json
{"action":"add","connector":"metamask","address":"0x…","chain_id":20,"network":"","browser_secret":"<64 hex characters>"}
```

For the first WalletConnect Add, use this authenticated management route with
`action: "add"`, `connector: "walletconnect"`, an empty address, chain_id 20,
network `""`, browser_secret and `allow_temporary_internet: true`. Show the short
connection disclosure first. Begin returns the temporary pairing transport.
After pairing, call `/api/auth/wallet/signin/select` with the same ceremony_id,
browser_secret, selected address and chain_id to obtain the exact Add message.
Selection replaces the initial chain_id with the wallet's chosen supported chain.
Keep the management launch header on these calls. Then sign and approve Add as
below. Anonymous sign-in pairing requires an already enabled compatible method;
authenticated Add creates the first method without that prerequisite.

For `enable`, `disable` and `remove`, send the owned `method_id` returned by Add
instead of connector, address, chain_id and network. A payment wallet first uses
Add, which leaves Sign in off, then Enable with that method ID. Enable requires
an existing method; wallet identity fields alone cannot create or enable one.
Begin returns:

```json
{"ceremony_id":"wallet:…","message":"Home-built message, empty for disable/remove","expires_at":1800000180,"approval":{"operation":"auth.wallet.method","request":{"ceremony_id":"wallet:…","account_id":"principal:…","action":"add","method_id":"wallet:…","connector":"metamask","address":"0x…","chain_id":20,"network":"","authorizes_short_public_walletconnect":false},"notice":"Confirm this wallet sign-in method change with your passkey."}}
```

Show the account, Home origin, full wallet address, network, exact message and
effect before requesting the signature or passkey. Enable also shows Runtime's
`approval.notice` before passkey approval. Home echoes the full Runtime-bound
approval request unchanged when it asks for passkey approval.
For add/enable sign the exact `message` using personal_sign
(EVM) or UniSat signMessage (Bitcoin). Then use existing
`POST /api/auth/passkey-step-up/begin` with its existing schema, app_token and the
returned approval operation/request. Complete WebAuthn through
`/api/auth/passkey-step-up/complete` to obtain `step_up_token`.

`POST /api/auth/wallet-methods/complete`:

```json
{"ceremony_id":"wallet:…","browser_secret":"<same secret>","signature":"0x…","signature_type":"personal_sign","public_key":"","step_up_token":"…"}
```

`signature`, `signature_type` and `public_key` are optional for disable/remove.
Bitcoin uses `bip322_simple` or `bitcoin_signed_message`; public_key is supplied
where that proof mode needs it. The response is
`{"status":"complete","method_id":"wallet:…","sign_in_enabled":false}`.
The response for remove has `status: "removed"`. A repeated method change needs
new approval. Begin never changes wallet authority.

## Signed-out sign-in

`POST /api/auth/wallet/signin/begin` accepts connector, address, chain_id, network
and browser_secret as above. It returns ceremony_id, exact message and expires_at.
The address may be empty only when WalletConnect pairing starts; call
`POST /api/auth/wallet/signin/select` with ceremony_id, browser_secret, address
and chain_id after pairing to obtain the message. Selection is bound once.

`POST /api/auth/wallet/signin/complete` accepts ceremony_id, browser_secret,
signature, signature_type and public_key. Runtime verifies the Home-built proof,
current switch and ownership, then issues the existing Home authentication result
(session_id, principal_id, proof_binding_id, expires_at, app_token) and session
cookie. Home opens the same account directly. Runtime binds the proof to the
sign-in purpose, Home origin and ceremony; the browser secret binds completion
to the requester. A wallet signature proves control of the wallet, not that the
signer is at this browser. The review shows the Home origin, full address,
network and exact message, with this line: "Continue only if you started this
sign-in in this browser." The review uses these details without a separate
comparison code.

`POST /api/auth/wallet/cancel` accepts ceremony_id and browser_secret and returns
`{"status":"cancelled"}`. It clears the ceremony's temporary transport authority.

WalletConnect begin also returns `attempt_token`, `instance_id` and
`storage_revision`. Reuse Runtime's temporary connector transport: config,
storage and relay-admission under `/api/apps/wallet-walletconnect/`, with
`x-elastos-wallet-attempt`, `x-elastos-wallet-instance` and storage `If-Match`.
Storage writes and new relay admissions require the current revision. A redeemed
relay keeps its live ceremony and instance binding across SDK storage writes;
retirement and expiry end its authority.
The permission reaches only WalletConnect setup and relay endpoints, ends at the
ceremony deadline, and grants neither payment nor capsule launch authority.
The SDK receives its minimum supported 300-second signature request expiry. Runtime and the
Home flow enforce the shorter ceremony deadline and retire the transport frame.
MetaMask and UniSat use the selected extension to sign; they receive no Runtime
network authority. Wallet rejection, missing extension and account change return
to the signer choice; a fresh attempt uses a fresh browser secret.

## Disabled routes and approval prompts

`POST /api/auth/wallet/register/begin`, `/register/complete`, `/recover/begin`,
`/recover/complete`, `/approve/begin` and `/approve/complete` (all below
`/api/auth/wallet`) return HTTP 403 `{"error":"passkey_required"}`.
Existing passkey creation and recovery routes keep their contracts. Existing
passkey step-up remains the sole approval issuer. A wallet session asks for a
passkey from the same account; it cannot approve by signing with a wallet.

## Update and Undo

Wallet records use a separate additive file under the Runtime auth root. The old
binary reads its unchanged auth state and preserves the wallet file. On forward
update Runtime checks every wallet against current passkey account state. Account
removal or replacement recovery invalidates the old wallet generation. New wallet
sessions use an additive session store which the old binary ignores. Undo keeps
passkey access and forward update retains eligible wallet records.

## Screen states

Add: select signer → pair/select address → review → wallet signature → passkey
approval → added, Sign in off. Enable: review → fresh wallet signature → passkey
approval → on. Disable/remove: review effect → passkey approval → complete.
Sign-in: signer choice → pair/select → review → sign → Home. Every pending state
has Cancel and an expiry path. An uncertain response is retried with the same
ceremony; a refused or expired ceremony starts from signer choice.

## Account actions from a wallet session

The existing passkey step-up begin accepts optional `approving_passkey_id`. For a
wallet session it selects an active passkey from the same account; omission selects
the first available account passkey. The pending proof and signed approval retain
the original wallet session/grant separately from this approving passkey. Runtime
checks both at effect commit. Passkey sessions retain their existing selection.
The existing step-up request/result schema names remain unchanged.

The removal and role routes keep their names. Ordinary passkey removal and role
changes from a wallet session require `x-elastos-step-up-token` with a fresh
same-account passkey approval. Their exact approval request is
`{"proof_binding_id":"<target>"}`, where `<target>` is a passkey proof binding ID:

| Route | Approval operation |
|---|---|
| `/api/auth/passkeys/<target>/revoke` | `auth.passkey.remove` |
| `/api/auth/passkeys/<target>/promote-admin` | `auth.account.promote` |
| `/api/auth/passkeys/<target>/demote-guest` | `auth.account.demote` |

These role routes use the target in the path and the approval in the header;
they take no role-change JSON body. An Admin changes another account's role.
Promotion makes every passkey of the target account Admin. Demotion makes every
passkey of that account Guest, requires another account with an active Admin
passkey, and refuses the caller's own account. Passkey sessions keep their
direct ordinary removal and role requests. Explicit Remove account requires
the distinct approved request below from either session type.

Existing add-passkey and full Recovery Kit export contracts retain their step-up
token fields. Wallet sessions use their account's passkey for those approvals.
Kit recovery continues through the passkey recovery path.

WalletConnect add may begin with an empty address and chain_id 0, then call the
same `/api/auth/wallet/signin/select` route with the management ceremony and its
browser secret. Runtime retains the account and action across selection. Removal
and switch off grant zero temporary relay authority. Wallet responses include
`home_token` and `system_token`; `app_token` is an alias for `home_token`.

Method changes and response retries require a live original session. Revocation
wins over a cached success. Session renewal keeps the ceremony's session/grant
identity and its original deadline. A browser with an uncertain disabled-method
response can sign in with its passkey and read the current list.

The additive record stores current passkey witnesses and a checkpoint in the
legacy signed audit history. Passkey rotation preserves wallets when continuity
is proven. After Undo, a missing or pruned audit continuation requires adding the
wallet again with a fresh signature and passkey approval. This conservative
refusal also covers recovery performed by the older binary. A malformed wallet
file refuses wallet access while passkey access remains available.

## Short WalletConnect sign-in permission

The Sign in ON review displays `approval.notice` before passkey approval. Its
`approval.request.authorizes_short_public_walletconnect` field is true for an
ordinary EVM wallet on Elastos Smart Chain (20) or Base (8453), whether it was
added through MetaMask or WalletConnect. This permission lets visitors start
bounded sign-in relay connections. The relay service can see the Home
computer's internet address. Runtime binds this effect to the fresh approval.
Payment connections keep their separate Inbox permission.

A WalletConnect add/enable/sign-in begin sends `allow_temporary_internet: true`
only after the person continues past a plain notice that the wallet is reached
over the internet. The field defaults to false and records consent; authentication
comes from the signed wallet proof and Runtime's current account state.
Signed-out pairing also requires at least one enabled compatible EVM method on
this Home, on chain 20 or 8453, through either MetaMask or WalletConnect.
`has_relay_method` checks this Home-wide condition; it does not require a prior
WalletConnect method or the selected address. Runtime checks the condition
during relay admission and use. Switching off the final compatible method also
ends pairing attempts that have yet to select an address.

For wallet sessions, `/api/apps/system/access/guest-registration` requires a
fresh passkey token in `x-elastos-step-up-token`, operation
`auth.account.guest-registration`, request `{"enabled":true}` or false as sent.
Host terminal and host audit controls require a passkey session. Update approvals
use the existing fresh passkey step-up flow from either sign-in session. Profile
and Library account access accept the Runtime-verified wallet account binding.

System can call management routes from its opaque capsule origin with its verified
System launch header. Home owns WebAuthn and receives the System launch plus the
returned approval intent through the existing approval bridge. Public signed-out
sign-in keeps the same-origin Home boundary; other capsules receive a refusal.

`GET /api/auth/passkey/status` adds `wallet_signin_available` and
`walletconnect_signin_available`. Home uses them to show the wallet choice and its
compatible relay option. These booleans reveal availability; account names,
addresses and method IDs remain in the authenticated account list.

## Explicit account removal

Ordinary passkey removal preserves every account's final active passkey under
concurrent requests, even when wallet sign-in remains enabled or another Admin
exists. It also preserves the Home's final active Admin passkey. The warning for
an account's final passkey is "Keep a passkey on this account, or choose Remove
account." If the target is the Home's final Admin passkey, Runtime instead returns
"Add another admin passkey before removing this one." Both refusals use HTTP 409.

A screen that offers Remove account shows the affected account and explains
that all its passkeys, wallet sign-in methods and sessions will end. The caller
can remove his own account; an Admin can remove another account.
It sends JSON with `Content-Type: application/json` to
`POST /api/auth/passkeys/<target>/revoke`:
`{"remove_account":true,"account_id":"<exact account>"}`, with a fresh passkey token
in `x-elastos-step-up-token`. The operation is `auth.account.remove` and its exact
request is `{"proof_binding_id":"<target>","account_id":"<exact account>","remove_account":true}`.
This approval is required for both passkey and wallet sessions. Runtime requires
another account with an active Admin passkey before removing an Admin account,
even when the target account has several passkeys. An omitted body or `{}` means
ordinary passkey removal. `remove_account: true` requires the explicit matching
`account_id`; Runtime checks the account and exact approval when it commits removal.

## Permission decisions from a wallet session

A wallet session can use access that Runtime has already granted. Positive Inbox
permission decisions also need a fresh same-account passkey. For Community presence,
contact acceptance, room admission, capability and service grants, Wallet price HTTP,
and hosted/model egress approval, use operation `inbox.approve` with
`{"action_id":"<complete Inbox action ID>"}`. Send its token in the existing
Inbox action JSON `step_up_token` field. Browser internet, WalletConnect payment
internet, wallet payments and Inspector retain their existing exact approval intents.
Read, dismiss, decline and deny controls keep their existing authority.

System presence modes `always` and `while_open` use operation
`community.presence.grant`, request `{"mode":"<selected mode>"}`, and the
`x-elastos-step-up-token` header. Selecting `hidden` ends access directly. The legacy
Chat room approval route uses `inbox.approve` with action ID
`room-approve-request:<request ID>` in that header. Home can run the passkey bridge
for the Chat launch token.

`POST /api/auth/sessions/<target>/revoke` from a wallet session requires operation
`auth.session.revoke`, request `{"session_id":"<target>"}`, and the approval header
when the target is another session. Signing out the current session stays direct.
Runtime rechecks current account authority while it commits the revocation.

Screens implement explicit Remove account controls and route sensitive permission
decisions through Home's passkey approval bridge before the combined product is
accepted. Runtime applies the exact approved intent when it commits each effect.

Inbox summary includes `wallet_session`, derived from the live launch context.
Inbox uses it to ask Home for `inbox.approve` with the exact `action_id` before
a positive permission decision. Runtime checks the live session and consumes
the approval when it saves the decision. Passkey sessions keep their existing
action-specific approval flow.
