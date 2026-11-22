# Wallet sign-in Runtime contract

Runtime attaches wallet sign-in methods to an existing passkey account. System owns
that account's method list. Wallet owns payment connections. Home owns signed-out
sign-in. Account IDs, roots, Profiles and passkey added-from labels stay unchanged.

## Rules

An Admin manages his own wallet methods. Adding a wallet leaves Sign in off.
Turning Sign in on requires a fresh signature from that wallet and fresh passkey
approval for the exact action. Turning it off or removing it requires fresh
passkey approval. Payment links acquire sign-in authority only through this
explicit operation. Wallet sessions can use Home; passkeys approve sensitive actions.
Every account retains a passkey. Removing the final account passkey clears its
wallet access; the Home's final Admin passkey remains protected. Removal and switch
off end the wallet's sessions and pending sign-in attempts. Concurrent changes are
serialized. Recovery Kit recovery keeps the passkey recovery flow and clears the
recovered account's wallets.

Supported signers are passkey, WalletConnect, MetaMask-compatible ordinary EVM keys
and UniSat Bitcoin proofs. WalletConnect supports Elastos Smart Chain (20) and Base
(8453). Contract-wallet signatures require a separate contract and are refused.
Wallet account creation, wallet-target recovery and wallet approval are disabled
at both begin and completion routes.

## Transport and errors

JSON POST bodies have a 96 KiB limit. Fields shown are required unless marked
optional. Signed-in requests carry the existing Home/System launch token in the
Authorization header. Runtime checks the live session, account and method again
at completion. Public requests use the configured passkey origin policy (HTTPS
outside loopback). A ceremony lasts at most 180 seconds. IDs are opaque.
A caller generates a random 32-byte hex `browser_secret` per ceremony, keeps it
in tab memory, and sends it on begin and complete. Runtime stores its digest.
Secrets and signatures stay out of URLs, logs and durable browser storage.

Errors use HTTP 400 for invalid input, 403 for refused authority/proof, 409 for
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

For `enable`, `disable` and `remove`, send `method_id` instead of connector,
address, chain_id and network. Begin returns:

```json
{"ceremony_id":"wallet:…","message":"Home-built message, empty for disable/remove","expires_at":1800000180,"approval":{"operation":"auth.wallet.method","request":{"ceremony_id":"wallet:…","account_id":"principal:…","action":"add","method_id":"wallet:…"}}}
```

Show the account, full wallet address, network and effect before requesting the
signature or passkey. For add/enable sign the exact `message` using personal_sign
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
cookie. Home opens the same account directly. A proof for payment linking,
adding a method, another Home or another browser cannot sign in.

`POST /api/auth/wallet/cancel` accepts ceremony_id and browser_secret and returns
`{"status":"cancelled"}`. It clears the ceremony's temporary transport authority.

WalletConnect begin also returns `attempt_token`, `instance_id` and
`storage_revision`. Reuse Runtime's temporary connector transport: config,
storage and relay-admission under `/api/apps/wallet-walletconnect/`, with
`x-elastos-wallet-attempt`, `x-elastos-wallet-instance` and storage `If-Match`.
The permission reaches only WalletConnect setup and relay endpoints, ends at the
ceremony deadline, and grants neither payment nor capsule launch authority.
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
