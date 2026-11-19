# Protected content

The target [storage and access contract](STORAGE_AND_ACCESS.md) extends the
object model to private storage, controlled sharing, groups, devices, and
agents. The [implementation guide](OBJECT_PROTECTION_IMPLEMENTATION.md) defines
how to replace or supplement dKMS/dDRM mechanisms while preserving Runtime
authority and existing object formats. These are staged design instructions;
the provider sequence below retains its own source and installed acceptance gates.

Protected content is Runtime-mediated. Library and Marketplace own the creator
and buyer experience, `elacity-player` owns video presentation,
`elacity-reader` owns everything else a bought file can be — a picture, a
document, text, a 3D model, a book or a comic — and `creator` uploads a file
through the Library transport and protects-and-lists it in one flow. Runtime
owns authority, durable operations, provider selection, Wallet and Chain
coordination, lifecycle, audit, and settlement.

Library offers protection on any file the Runtime accepts. The source mime
decides the kind: `video/*` and `audio/*` are media and take the rendition
path; everything else is an object and takes the chunked-payload path. The
kind then decides the viewer, so the creator never picks one.

The intended content-distribution contract gives free and protected content
the same package identity and availability path. Protected content adds rights,
key release, and decryption. See
[Content capsule distribution](CONTENT_CAPSULE_DISTRIBUTION.md) for the planned
catalog and Get contract.

The canonical source path is described below. Source tests and simulation
proofs do not establish installed playback or independent-host availability;
current acceptance evidence belongs in the owning GitHub issue. There is no
parallel provisional protected-content authority.

## Canonical path

The source path has one operation sequence:

1. Library or Creator submits a typed source object and the permitted product
   terms.
2. Runtime creates the durable operation identity and selects the private
   `media-provider`.
3. For media, `media-provider` prepares the clear DASH renditions (one video,
   one audio, or both) in Runtime-authorized private staging. It owns probe
   and transcode process behavior. For an object, no rendition step runs: the
   file is sealed as it is. The mint workflow adds no size or duration cap to
   either path (see "Limits").
4. The private protect provider encrypts the prepared media, provisions the
   immutable 2-of-3 custody envelope, and returns bounded identities and
   receipts.
5. Runtime publishes the encrypted package into private offline IPFS. The
   creator serves it over Carrier. Pool members with accepted copy obligations
   pull and verify the exact package, keep host-wide storage charges, and
   announce active copies through Carrier. These copies do not enter public
   IPFS. Separately, Runtime validates and pins the public metadata folder and
   cover before requesting mint approval; public announcement continues in a
   bounded background task.
6. Runtime binds creator mint and listing effects to the verified Wallet
   account and operator Chain configuration. It projects a listing only after
   the exact effect and finalized evidence agree. For new mints, the Chain
   provider checks that the content key ID belongs to the finalized asset.
   Runtime saves the resulting rights policy once, then publishes the listing
   with that seal. A retry reuses the saved policy and keeps the original mint
   ID, content key, and custody shares. The public metadata can be published
   before mint approval. It says that the buyer needs a sealed policy once
   the asset is final, while the final policy travels in the portable listing.

   Open uses the finalized policy in the Wallet approval and in the custody
   release request. A Home that finds the asset through its public metadata
   resolves the seal against the finalized key-to-asset binding. Existing
   listings keep their recorded format and approval path.

   The creator tail raises
   exactly one wallet effect — the mint transaction itself. That is a
   statement about minting, not about the asset's whole life: an ERC-1155
   operator approval is still how secondary trading is authorized, and an
   owner reselling some of the access tokens or royalty shares they hold will
   raise one. What the contract grants by itself is the movement of freshly
   minted copies, so asking a creator to approve an operator while they are
   still listing is asking for authority nothing is about to use. The account
   backing the mint is the Wallet transaction default for the mint's chain
   namespace, and it may be either a Runtime-managed account or a
   connector-linked external one: what is required is that the account can
   sign, not how it signs. An external account completes the effect through
   its connector and the operation resumes from the recorded approval; a
   managed account completes it in place.

   A mint keeps the account it started with. The publish request that opens a
   mint is identified by the principal, the object, its storage and the
   attempt — not by the wallet — so a retry of the same object reaches the
   account the attempt recorded, and the effect identity stays durable across
   retries.

   What Runtime does when the wallet's transaction default has moved on since
   then depends on how far the mint has got, because only one of the three
   stages can still be stopped for free. With terms recorded and nothing
   raised, Runtime refuses before raising the effect and names both accounts
   and the two ways out: set the recorded account back as the default, or
   discard the recorded terms and protect the object again on the current one.
   Once an effect is raised the approval is out and may already be signed or
   broadcast, so the mint finishes on the account that raised it — refusing
   there would strand a transaction in flight rather than prevent one. A
   settled mint is likewise never refused: its chain effect is done, and
   refusing would leave the listing permanently unpublishable.

   While a publish is outstanding, the answer also carries how far it has got,
   as stages read from the mint journal rather than guessed at by the caller:
   the custody escrow, the ciphertext reaching verified content availability,
   and the chain listing. The journal enforces that order itself — creator
   terms cannot be recorded against a mint whose custody is unprovisioned or
   whose availability evidence is absent — so the stages cannot report a phase
   the server has not reached. They ride the same answer an app is already
   polling, not a channel of their own.

   An attempt that stopped before sending anything on chain never blocks a
   new mint of the same file. A new mint sets it aside: its journal records --
   intent, media preparation and every mint record bound to it -- are moved,
   never deleted, into
   `protected-content/runtime-mint-set-aside-<YYYYMMDD>/<request id>/` beside
   a note naming the stage it reached and its terms. A Wallet approval it left
   out is declined first, and the attempt is set aside only once the Wallet
   confirms the approval closed with nothing signed. If the Wallet cannot be
   asked, the approval is not on record, or the decline cannot be confirmed,
   the new mint is refused with `approval_open` and nothing moves; Resume is
   the way on. An approval that went to an external connector is never
   declined, because the connector can sign and send without the Wallet
   knowing: that attempt is refused with `approval_in_connector` and finished
   by Resume.

   Archiving is crash-safe. It records the move it is about to make, then
   advances the attempt, then moves the files. A move that a crash interrupts
   is finished later only if the attempt had already advanced; otherwise it
   never happened, the attempt is still current, and its files stay where
   they are.

   An attempt whose transaction was sent or mined -- and a settled mint, listed
   or not -- is never set aside: a new mint at other terms is refused, the
   refusal names the terms that differ, and Resume finishes the attempt. So no
   token is ever left on chain without its record. A settled mint whose
   listing file cannot be read is kept too (`listing_unreadable`). Creator asks
   for a new mint explicitly; any other caller gets one as soon as its terms
   differ from the attempt's, and the same terms continue that attempt.

   Three refusals stay fail-closed rather than archiving on their own: the
   file is not the one the attempt prepared, the attempt started under another
   account, deployment or custody selection, or a protect request it sent has
   an unknown outcome. Each carries an `attempt_conflict` code, and Creator
   answers it with Start over when the attempt sent nothing on chain.

   Each attempt has its own identity. The publish request is identified by
   the principal, the object, its storage and the attempt number. Attempt 0
   is every object's first and keeps the original derivation, so every
   intent, preparation and record already on disk keeps loading; later
   attempts hash the attempt number in. The current attempt is held in the
   journal (`attempt-<first request id>`), advanced when an attempt is set
   aside, and absent until then. The media-provider operation id and the
   protect session follow the request id, and a mint id hashes the attempt's
   own random content access id, so a new attempt never meets the identity of
   an archived one.

   Creator lists the unfinished attempts in its folder when it opens. One that
   is recoverable -- the key was escrowed to the pool, a Wallet approval is
   still out, or a transaction was sent or mined -- is offered with Resume,
   which re-runs it from its recorded terms with nothing typed (raising a
   lapsed approval again for the same transaction, or finishing a listing
   that never published). One that sent nothing on chain is also offered
   Start over, which sets it aside and fills the form with its recorded terms
   for review. One that stopped before its terms
   were recorded asks for them again: the journal records terms only once the
   content is available, so there is nothing earlier to fill in. One that
   nothing irreversible came of -- terms recorded and nothing raised, or an
   approval that expired or was declined before anything was signed -- is set
   aside without asking.

   A publish that finds the mint already settled raises no effect and sends no
   transaction; it only re-publishes the listing from the existing record. The
   answer says so, and names when it settled, the transaction that settled it,
   and the account it minted on — so a caller can tell a replay from a fresh
   mint instead of reporting work that happened earlier as work it just did,
   and a creator who has since switched wallets can see which account holds
   the listing.
7. Marketplace reads listing objects built by Runtime from the chain and the
   asset's metadata folder. A buy request names the item, the seller and the
   terms the buyer agreed to; Runtime re-reads those terms and answers
   `terms_changed` rather than proceeding when they differ. Runtime derives
   the buyer, account, effect, and Chain authority.
8. A Home that holds the item verifies the exact signed availability receipt.
   A non-holder resolves a verified signed pool descriptor matching the item's
   custody epoch and verifies the manifest against the bound content identity.
   On a non-holder, Import, adoption and Open use this manifest-only check;
   they do not download the whole protected file. The original-composition
   holder path still verifies the full published files and fresh receipt.
   Pool servers stage content and check each served part against its signed
   size/hash or media Merkle proof before passing it to the decrypt provider.
9. Library or Marketplace asks Home to launch `elacity-player` for media or
   `elacity-reader` for other files. Runtime binds opaque launch authority to
   the principal, mint, executable actor and session. It prepares the selected
   pool servers and their recipient attestations before requesting the Wallet
   signature over the exact rights request.
10. Each custody node independently checks finalized chain rights and the signed
    operation, epoch, recipient and time window. A threshold of approved nodes
    returns contributions encrypted to each authorized pool-server recipient.
11. Each pool server's private decrypt provider reconstructs and uses the CEK
    inside its process. Verified output is encrypted to the buyer's delivery
    key and returned through bounded session reads. Runtime enforces ordered
    reads and binds retries, resumed starts and replacement sessions to the
    same principal, mint and content binding. Close settles viewer, decrypt,
    pool-session and staging ownership.

The account's chain rights authorize access regardless of where they were
acquired. An available published asset should open from any Home with those
rights, without a publisher contact, pairing, an extra publisher approval, or a
required manual import. A verified pool route and available protected content
are still required. A shared listing import is optional and creates local
records; it never grants access by itself.

Runtime journals identities, state, receipts and settlement. Providers keep
clear media, staging, CEKs, shares and private process handles inside their
owned boundaries. Carrier transports Runtime-selected content and custody
operations; no capsule receives the transport route or key material.

An independent Home can mint into a pool it uses. Its local protect provider
encrypts the asset, and the pool's custody providers store the shares. The
`custody-pool` service exposes descriptor discovery and playback sessions.
It has no operation for encrypting another Home's asset. The descriptor's
`max_seals_per_sealer` field is reserved for that workflow and does not
enforce a host-wide limit today. The separate rights-policy seal is applied
after Runtime verifies the finalized chain binding for the same asset.

### Importing a shared listing on another Home

Import first verifies the original published package, metadata, chain binding
and protected-content manifest. A non-holder then records the listing through
the existing `Asset` adoption path using its verified pool-bound local identity.
An older composition mint includes its creator's node owner-state roots, so
that original mint ID can differ from the receiving Home's local ID. This
compatibility is confined to import: pool-minted packages and verified receipt
holders still require the original mint ID to match exactly.

Runtime keeps the original `listing_uri` and `package_sha256` as local source
provenance. `Asset.source_listing` exists only in memory and is excluded from
serialization. An owner-only extension under
`protected-content/runtime-listing-sources/` stores that provenance separately,
bound to the schema, local mint ID, local package digest and asset CID. The
legacy listing JSON retains its closed `Asset { asset_uri }` shape even when
provenance exists. Older Runtime versions ignore the separate directory and
can still read the base listing and its owned-copy records.

With valid provenance, Share returns the immutable original source URI; its
package hash stays separate from the local package digest and ID. Offered
terms stay unchanged. Local publisher-account attribution is normalized from
the chain-verified creator account, rather than borrowed from an outer metadata
publisher. An Asset without source provenance keeps its held-only listing
behavior. A verified imported Asset with provenance can appear in the catalog
before purchase, as an imported offer did before; visibility grants no reading
rights.

Runtime writes the base listing first, then atomically writes the bounded
extension. An extension-write failure can fail Add without corrupting the base
listing or existing purchase records. Missing, malformed or stale extensions
are ignored when loading the base record, so optional provenance cannot block
owned access. A verified Add retry can repair that provenance after repeating
the original proof checks.

Repeating Add with the same source is idempotent. Runtime can add provenance to
an existing Asset only when the local package and asset match; a conflicting
source or package is refused. Upgrading a granted listing preserves its access
and purchase bindings, and existing paid acquisition records remain unchanged.
Retention includes both the asset and original listing CIDs; it does not claim
that the complete protected file has been downloaded. This describes source
behavior; installed Add and subsequent playback need their own acceptance
checks.

The listing-summary contract distinguishes receipt evidence from a verified
manifest fetch. `last_verified_receipt` carries the real signed receipt digest
and observed replica count. `last_verified_fetch` carries an empty
`receipt_digest` and zero `observed_replicas`; `required_replicas` remains the
configured policy target, not proof that those copies were observed. The
Marketplace label for fetch evidence is “Manifest checked”, never a fabricated
replica ratio. Either evidence kind requires a positive check time and fresh
checks before Buy and Open; a displayed row is not a rights or availability
grant.

An adopted or granted listing may have `published_at: null`. The contract
preserves that unknown date rather than creating a publication timestamp, and
the row remains displayable. Non-null dates must still be valid positive
timestamps. These display rules do not change finalized chain-rights checks,
pool resolution or per-part verification. Contract and source checks remain
separate from installed Marketplace acceptance.

### Buying from an offer

Buying and reading are two workflows over two datasets. Buying from a live
offer (`buy_offer`) never runs the read-side checks above: the access token
exists on chain whether or not the file is retrievable, and the read-side
checks answer "can this be opened?", never "can this be bought?". Buying an
imported listing package (`buy`, the legacy path step 8 also names) still
runs them — its terms are frozen into the package it imports rather than
read fresh from a live offer.

An item's key is `(chain_namespace, ledger, token_id)`; a KID is only an
alias for it, trusted after `ipReference(kid)` returns that same tuple. An
offer's key is `(operative, ACCESS_TOKEN, seller)`. A shared link names the
asset only — `elastos://<metadata-folder-cid>` — and never a seller, so a
link never favours one seller over another. The asset is the token's own
metadata folder, and its shared `metadata.json` is the read dataset; the
Runtime's own `manifest.json` in the same folder is never required to buy.

The Runtime builds the listing object from the chain and that folder; the
index (today the Elacity GraphQL endpoint) contributes an identifier and
display text only, nothing the purchase relies on. The chain provider starts
the first two independent sources together for item, offer, KID binding, and
verified-listing reads. It tries further sources in order when needed and
pins disagreeing finalized heights to the lowest observed finalized block.
Mint receipt verification reads all configured sources, up to two at a time,
so a conflicting receipt still participates in the decision. At most 32
sellers are read per item, and a listing states `offers_truncated` when there
were more. A `buy_offer`
request names the item, the asset URI, the seller and the terms the buyer
agreed to. A purchase rests on the chain's terms only: Runtime verifies the
item from the chain alone — `(ledger, token_id)` to a non-zero operative,
and `tokenURI` to the asset folder the request names. Before any Wallet
request it also reads the folder's shared `metadata.json`, and the chain's
binding of the KID that document names, only to tell whether this Home's
custody pool holds the item's keys, or else whether this Home can reach the
item's pool. When either cannot be read, the buy is
refused as unavailable and the same Buy tries again (see below). Nothing
the buy learns from them is recorded. When the fresh read disagrees, the answer is `terms_changed`
with the current terms (`null` once the offer is sold out or gone), and no
Wallet request is raised. A press naming a different seller or different
terms than a recorded attempt already in flight does not drive that
attempt: it answers `attempt_in_progress`, naming the recorded seller and
terms, and raises no Wallet request either. Once that attempt's buy is
confirmed, any press finishes it. A buyer holds at most one open purchase
per item across both purchase paths at once — a `buy_offer` attempt
refuses while a listing-package purchase for the same item is unresolved,
and a listing-package `buy` refuses symmetrically; each answers
`already_owned` when the other purchase is complete.

Readability — whether the folder's own document carries a complete ElastOS
protection entry — is advisory only. Every listing states it as `verified`
(a `cenc:elastos-pq-hybrid-threshold-v1` entry with all four identities),
`unverified` (any other ElastOS-scheme entry), `foreign` (no ElastOS-scheme
entry) or `unknown` (Runtime could not read the document or confirm its KID
binding now; the item's `kid` is then `null`). None of them blocks a
purchase: a foreign item's access token is still valid on chain and still
honoured by ela.city. Marketplace presents unknown access as View; it offers
Buy only after the relevant listing and access checks have completed. When a
purchase cannot reach the market
or the chain, Marketplace says so and the same Buy tries again; it keeps
"The purchase did not finish." for a purchase that failed. After a market purchase completes, opening it reuses the same
shared `metadata.json` the listing was built from — an adoption step builds
the ordinary listing and purchase records the open path already consumes,
so nothing in the open path itself changes. The purchase answers
`adopted`, `foreign` or `pending`. A pending adoption runs again when this
Home answers the completed purchase again or is asked for the owned copy;
nothing reruns it on its own. Marketplace offers Download copy for such an
item: it asks for the owned copy by its item (`download_owned_copy` with
`{item}`), which reruns adoption and never pays. See
[the market buy design](audits/2026-09-24-protected-content-market-buy-design.md)
for the full architecture, wire shapes and the rulings made while it was
implemented.

Access is decided by the chain, not by how it was acquired. An account the
chain grants an item without any purchase on this Home — a channel admin,
for example — downloads and opens it the same way. With no market purchase
for the item, `download_owned_copy` with `{item}` re-derives the item from
the chain and its asset folder with the listing object's binding check (all
three legs must hold, and every identifier in the request must agree with
them). It then reads the grant for the proven KID at the `finalized` block.
A grant is adopted from the shared `metadata.json` into a listing and an
owned copy whose acquisition is `granted`. Bought copies stay `bought` or
`market`, and minted ones stay `minted`. The listing binds to one this Home
already holds for the mint. Otherwise it states zero terms (seller = the
item's operative, price `0x0`, the native pay token, no processor) under
origin `granted`. It appears among that principal's held assets without
creating a sale offer or a share grant. A real listing
replaces a granted one: a market purchase of the item by another person on
the same Home, or the creator's imported package. The granted copy is bound
to the item, its content and its KID, never to a listing's terms, so it
keeps opening. The owned copy records the finalized grant instead of a
transaction. Its open re-reads that grant at `finalized` before asking the
Wallet, and custody reads it again before any release. Every download
builds the copy on the grant at `finalized`. A grant only the head has
refuses with `code` `access_confirming` ("Your access is still being
confirmed on Base. Try again in a few minutes." in Marketplace). A chain
that answers "no" at both refuses with `code` `no_access` ("This account
has no access to this item."). A chain, folder or KID binding that cannot
be read leaves the download unavailable and writes nothing.

An item's keys are held by the custody pool that minted it. A Home can
build, buy into or open a copy of an item when it can reach that pool: its
own pool, a pool it serves, or a pool an admin added in Custody under "Pools
this Home uses". Runtime first compares the node set the item's key envelope
names with the nodes this Home's composition selects, and the envelope's
threshold with the epoch's own. When they differ, Runtime looks for a kept
pool descriptor whose epoch names that node set and has a node that can
serve. When no pool resolves, the granted download, import, a
listing-package `buy` and opening answer `custody_elsewhere` and write
nothing.

Before server preparation and Wallet approval, a fresh resolve can use a known
pool's verified routes to ask its `describe` operation for a newer descriptor.
If a cached descriptor already matches the envelope, Runtime refreshes that
pool. If no cached descriptor matches, Runtime can ask already known pool
authorities and check their answers against the envelope. The whole lookup has
a 20-second budget per resolve call. An update must be signed by the queried
pool authority, match the exact envelope, advance the verified sequence, and
keep the previously verified v3 bundles, member routes and trust mode.
Unreachable or invalid answers leave any matching verified cache available,
subject to node high-water checks. An
unresponsive first peer may exhaust the entire budget. Pending polls may
resolve again; this is not a 20-second budget for the whole Open journey.
Active viewer reads and the cached listing projection do not perform this
network refresh.

A signed v3 descriptor can carry more than one epoch. The owner signer keeps
the exact prior epoch bundles and member routes when signing for a different
installed composition of the same pool. Existing assets still require an
authorized quorum from their original epoch. Runtime selects that epoch from
the asset's key envelope and uses the current descriptor sequence. When a new
local mint starts, Runtime retains its selected composition beside its mint
journal. Resume can load that composition and verifies it against the signed
identities and node bindings stored in the intent. A completed mint can replay
its stored result after the original term expires. Runtime still checks the
same completed mint, source, Wallet and committee. Starting new provisioning
requires a committee in its signed term.

The Custody admin can stage a rollover candidate through the prepare route.
Runtime stores the signed proposal, descriptor, and exact composition in an
owner-only record. An exact retry returns the same proposal. The installed
composition and published descriptor keep serving. The consent route records
a successor member's signed decision against that exact proposal. A Custody
admin can submit the signed record, and Runtime checks the member's signature.
A recorded decline prevents a later approval of the same proposal. These
routes stage evidence for a future switch. Active pool selection is unchanged.
An independent Home currently picks the first term-valid epoch in the
descriptor for a new mint. Once that epoch's term ends, it can select the
next eligible epoch in the same descriptor. A resumed mint still uses its
recorded epoch.
For the current local development deployment, the activation plan is to
upgrade the participating Homes and custody providers together. Before a
successor is published, new provisioning must require the owner's committed
epoch choice. An unsupported version must be refused at startup or at the
provisioning boundary. An upgraded process must recover the same selection
after restart. Descriptor refresh lets readers discover the serving epoch for
an item. Transfer or retirement of its original quorum needs a separate
protocol.

The custody share store can validate and reload an isolated remote-sealing
record. It retains the owner-signed pool descriptor, the minter's signed
request and the sealer's signed authorization with the share. Each release
checks the original content access ID. Existing share record formats keep
their encoding. The remote record has a new format, so the providers that
read a store must support that format before the first remote share is
persisted there. The custody provider's private command accepts a bounded
request and a pool identity that Runtime resolves for the loaded root.
The provider checks that identity and its stored descriptor sequence before
writing. It returns the stored share's record and provisioning identities.
The test runs the command in the custody process, then exercises release
against the stored share. Runtime accepts the remote-seal share through its
pool provisioning operation. It binds the authenticated sender to the
descriptor's sealer and to the Runtime issuer in the signed authorization.
It resolves the receiving root, applies host storage limits, and serializes
the write with Stop. The sender asks the local custody provider to sign for
the verified envelope and sends a share to each node in its signed committee.
It checks each reply against the expected node, record, and provisioning
identity. A retry keeps verified results and sends to unresolved nodes.
The isolated Runtime completion verifier binds the sealer's signature to the original
request and descriptor, then checks the fetched envelope, key commitment,
and typed object or DASH identity. The archived signature can be checked
after descriptor expiry. The publication verifier checks the settled item's
finalized chain binding through the chain provider. It checks the fetched
manifest's object and publisher before reading package files. It checks
the package paths and signed file CIDs against the content manifest, then
requests a fresh availability receipt for the independently selected
publisher and receipt signer. Live remote mint dispatch still needs integration.
Before a remote open, the mint journal can retain the exact signed request,
pool descriptor, and selected node. After restart, dispatch rechecks the
local minter's identity and the request's validity before reusing that same
selection. Runtime can ask the custody provider over its private command
channel to sign the protect provider's session statement. The statement binds
the session ID, upload key and exact descriptor digest. The custody provider
checks the selected root, pool, stored descriptor sequence and signed mint
request before signing. Runtime verifies the signature and the exact statement.
The protect provider opens the object session on Runtime's private plane and
returns the encrypted object header for Runtime to stage. It keeps the upload
key in the provider. Repeating the same authorized Open returns the same
header and session. The provider checks the pool limit, the host's eight
remote upload slots and the shared limit for all protection sessions.
The private transfer command retains its most recent response. After an
uncertain reply, Runtime repeats the same command and saves any returned
encrypted frame before it advances the sequence or reports the chunk as
saved. Resume first settles the outstanding command so it can report the
last chunk actually saved. A partial storage write makes the session
unusable.
At finalization Runtime reads the staged file and sends its ciphertext hash
and size to the protect provider. The provider checks both against the
completed upload before it creates encrypted shares. Runtime checks the
returned envelope against the same file, signed request and custody
committee, then writes the object manifest. Exact finalization retries
return the saved envelope within the session window.
The journal retains the verified attestation and the last cumulative
acknowledgement. Resume rechecks the attestation's expiry, and an
acknowledgement from another session or a backwards position is refused.
The upload client reconciles the durable position with the sealer before
sending another part. Once the complete upload is acknowledged, it retries
finalize for the same session. Runtime stores the signed completion in a
bounded owner-only file linked to the unchanged mint intent. After restart
it can read that evidence even if the upload session has expired. Publication
still requires fresh availability and finalized chain binding.
The Carrier adapter uses the selected pool peer and rejects replies for a
different session or upload piece. The custody-pool service accepts object
upload requests from an admitted Carrier peer. It binds each session and
reply to that endpoint, bounds the number of uploads and checks available
host storage before staging a new object.
The isolated object sealer discards partial chunks on resume and
acknowledges a complete chunk only after staging succeeds. A failed
staging write prevents resume and finalization for that session.
The protect provider's isolated receiver uses the same bounded upload fields
as the Runtime client. It checks the offered descriptor against the locally
selected descriptor and binds parts to the authenticated peer and signed mint
request. The receiver holds uploads within the signed limit for each pool.
An exact retry after a lost open reply returns the same session to its
authenticated owner. Resume reports the last staged chunk. The
receiver reads the staged ciphertext back before producing the custody
envelope and returns that same envelope when finalization is retried.
A loopback Carrier test runs Runtime's upload coordinator and file adapter
against an isolated receiver. It checks that a changed source file is
rejected, a missing part acknowledgement is recovered through Resume, and a
lost completion reply can be retrieved after reopening the mint journal.
The journal can replay the saved result after the upload expires. The test
uses a fixture publication and passes the staged envelope to private custody
roots for all three recipients. The sealer signs the original mint and
envelope binding. Runtime signs the
exact node record, with an effect ID derived from the mint request, envelope
and recipient. Fresh authorizations keep the original record, effect ID and
content access ID on retry. Before calling Content, Runtime checks every
committee receipt and the staged ciphertext. It also rechecks the admitted
root and confirmed publisher. The same directory
add supplies the package root and each file CID through Content. The publisher
reads those files back and verifies the receipt before returning evidence for
the completion statement. The Runtime builds the statement from that evidence
and the signed mint request. The custody provider checks its own stored share
against the exact request, descriptor, envelope, content access ID and key
commitment before returning the node signature through its private command.
Runtime verifies the signature and exact statement, then commits the signed
reply to an owner-only record before returning it. A retry by the same authenticated
Carrier endpoint can recover the identical reply within the original session
window. The finalize wire reply uses the same signed completion format as a
fresh reply. A different endpoint or an expired session receives no completion.
The receiving service handles Open, part, Resume, and finalize for objects.
Library mint selection and remote DASH sealing still need integration.
The upload selector uses eligible nodes from the request's exact epoch and
excludes this Home's routes and node keys by default. The sealer checks its
host trust and the descriptor already kept for the selected root. The signed
minter must match the Home authenticated by Carrier. That root
must have its own confirmed publisher before the sealer accepts a file.
For a prepared object file, the minter checks the full digest and length
against the saved mint intent. It reads one bounded chunk at a time and
checks the chunk again before encrypting it for the selected upload session.
The file adapter takes an already authorized descriptor and creates no
plaintext copy on disk. The installed Library workflow still needs wiring.

`buy_offer` checks whether this Home can resolve custody before any Wallet
request, for a new attempt and for an earlier attempt whose first Wallet
request was never raised. Its check fails closed. It is `custody_elsewhere` when no pool this
Home knows keeps the item. It is `unavailable` (nothing paid; try again)
when the document, the KID's binding or this Home's custody state cannot be
read now. It passes for an item of a pool this Home can reach, or one whose
document names no ElastOS protection this Home could adopt. An attempt whose
Wallet request is already out is never refused: the person may already be
paying.

A completed market purchase that cannot resolve custody reports that adoption
is unresolved; it must not ask the person to pay again. `custody_route` is a
verified fact: `pool` means Runtime has a matching pool descriptor, while
`unresolved` means it cannot establish that route now. Neither a public listing
nor a contact relationship substitutes for descriptor verification. Failure to
resolve or fetch content does not revoke the account's chain rights.

Explore asks the chain whether the current account has access, including when
this Home holds no copy. Visible cards read bounded listing/access results.
Card reads can ask for the access result first. When Runtime can identify the
account and establish its access, it returns an account-bound card response
without fetching sale offers. When listing metadata holders are unavailable,
Runtime can still resolve the item's verified chain identity and return a
positive account access result. Cards with no positive access result, full
listing details, and Buy still use verified offers. Open checks access again
before it reads any protected content.
Held access shows Open; an available offer without access shows Buy; an account
that needs setup shows Add Wallet. Unknown results show View and retryable
failures offer Try again. A manual retry shows Checking immediately and
takes the next free card-access slot ahead of queued background cards.
Automatic retries show Checking while a read is running. Add listing lets
already running card checks finish and defers new ones in that Marketplace
tab until Add settles. A refresh invalidates cached results and retries.
Runtime returns an opaque account-bound `access_subject`, so an answer from a
previous account cannot become the current account's access result.

## Listing metadata

A mint's token URI resolves to a DIRECTORY, never to a file inside it. The
Operative appends its own suffixes to whatever base URI it holds — `uri(id)`
is `base + "/{id}.json"` and `metadataURI()` is `base + "/contract.json"` — so
a base that already named `metadata.json` produced `…/metadata.json/0000…0001.json`,
which resolves to nothing. The mint completed and the asset was unlistable.

The directory carries the documents a marketplace reads:

| file | read by |
| --- | --- |
| `metadata.json` | the indexer: `name`, `description`, `image`, `media.uri`, `media.contentType`, `properties.publisher`, `kid` |
| `content.json` | referenced by `media.object` |
| `contract.json` | referenced by `properties.contract`; pricing and supply |
| `0000…0001.json` | the Access Token type |
| `0000…0002.json` | the Royalty Share type |
| `manifest.json` | this Runtime's own portable-listing document |

Two facts are load-bearing. `metadata.json` sits at the directory root, because
that is where the token URI resolves. And `kid` equals the on-chain
`contentId` — `0x` followed by the bytes16 content access id — at every level
the indexer reads; the content market rejects metadata whose `kid` disagrees,
so the portable-listing verifier asserts it rather than leaving it to fail on
chain.

The runtime's own document is `manifest.json`. It could not keep the name
`metadata.json`: that name belongs to the document the token URI resolves to.
Listings published before the rename have it at `metadata.json` with no
siblings, and still verify — the verifier tries `manifest.json` first and
accepts the older layout only when the document there really is the runtime's.

`asset.protections[0]` describes this Runtime's own custody, not the Lit-shaped
slot the wiki schema describes: a reader that recognises
`cenc:elastos-pq-hybrid-threshold-v1` knows which release protocol to speak, and
one that does not is not misled into trying the wrong one. That string is not
written here — the descriptor carries
`ELASTOS_PQ_PROTECTION_SCHEME_V1`, the same constant the `pssh` box in the init
segment states as its `protection_scheme`. The folder and the box name one
protocol from one definition, because while they were two constants they drifted
apart, and a reader that found the folder first would have spoken a protocol the
box does not implement.

The descriptor carries identity only — the threshold, the node count and the
rights policy that governs release — and never sealed shares, the key envelope
or the commitment, which stay in the runtime's own document and in the custody
nodes. It deliberately carries no second name for the scheme beside the
protection type: the threshold is here as numbers, so a string also spelling out
"2 of 3" could contradict the data next to it, and the suites — how the samples
are encrypted, and which key encapsulation the released key arrives under — are
already stated once in the `pssh` payload as `content_encryption` and
`key_encapsulation`.

Royalties are carried in ERC-1155 `ROYALTY_SHARE` units, the chain's own
denomination: 1000 exist per asset and one unit is 0.1% of the sale. A creator
surface shows every share, so the rows come to 1000 units — but the protocol
owner's 50 are minted by the contracts from `CentralStorage.protocolShares()`
and are not the creator's to set, so what a publish request carries is the rest:
the creator's 950, split across the payees they name. A split that does not
total 950 is refused rather than adjusted, because a listing showing an adjusted
split would describe a payout that will not happen. A publish that names no
split gets the chain default, the creator's whole share to the creator.

## Media renditions and the CENC header

### The v2 media package

Every new media mint is a v2 package: DASH with CENC (`cenc` scheme, AES-128-CTR)
under `protected-content/v2/`. It holds a fixed-size identity head
(`identity.bin`), a deterministic `stream.mpd`, and per rendition an `init.mp4`
and 2-second `seg-N.m4s` segments (numbered from 1). `media-provider` probes
the source and produces up to two renditions: H.264 video (`avc1.640028`, at
most 1080p at 30 fps) and AAC-LC audio (`mp4a.40.2`), either alone or both,
video first. A source with only sound becomes an audio-only package. Cover art
is skipped rather than taken for a video track. The MPD is for external
players; the Elastos player does not read it, and its integrity comes from the
content manifest like every other file.

The identity head is about 400 bytes whatever the duration. It carries the
suite (`cenc-dash-aes128ctr/v2`), the default KID (the content access id), the
digest of the whole ciphertext stream, and for each rendition its codec, init
digest, segment count and an RFC 6962 Merkle root over the segments. A leaf
commits to the segment's kind, index, SHA-256 and length. The content manifest
already lists every file's SHA-256 and size, so the leaves need no extra file.
Open and buy check the manifest against those roots once. A read then returns
the segment's audit path with the decrypted part, and the player verifies it,
so every read is proven.

A v1 item (one fMP4 rendition under `protected-content/v1/`) stays readable
and plays through the unchanged v1 path. New mints never write v1. The viewer
answer is `elastos.library.runtime-custody-viewer/v2` for a v2 item; its
read operations are unchanged.

### Audio policy

The audio rendition is AAC-LC. The source's audio is copied when the browser
can play it as is: AAC-LC, mono, stereo or 5.1, at 44.1 or 48 kHz. Any other
source, or any doubt about it, is re-encoded: 256k for stereo, 192k for mono
and 384k for up to 5.1 channels. More than six channels are downmixed to 5.1,
and a rate other than 44.1 or 48 kHz becomes 48 kHz.

Runtime has no source for a poster yet, so an audio-only item always lands on
the controls-only frame; that is the honest state, not a failure.

### Protection systems

Protected media carries a CENC Protection System Specific Header. One custody
`pssh` box declares the Elacity post-quantum hybrid-threshold protection
scheme. Its payload is public scheme description and never key material: the
versioned schema name, the protection scheme, the sample-encryption profile,
the key-encapsulation suite, the content access id a consumer presents when it
asks for a key, and the custody pool, epoch and committee authorization
identities that say which quorum can answer. Those custody identities are
bound at publish to the mint's own, so a box lifted from one title cannot
stand for another.

Each protection system is one adapter that both encodes and decodes its own
box, listed in one registry:

| System | Role | Encodes | Decodes |
|---|---|---|---|
| W3C Common (1077efec-c0b2-4d02-ace3-3c1e52e2fb4b) | KID list, no data | yes | KID check |
| `cenc:elastos-pq-hybrid-threshold-v1` (b01c5dff-46fb-497e-8525-6fb946873253) | custody, pool-based | yes, the only active encoder | yes, data scheme `-v1` |
| `cenc:elastos-pq-hybrid-threshold-v0` (b6e254ef-0dc5-47fe-94e7-0e72ed1dc7b0) | custody, earlier format | no | yes, data scheme `-v0` or `-v1` |

The v1 system is organised around the custody pool rather than direct nodes:
its data names the pool, epoch and committee authorization, never shares or
per-node data. Producers encode only through the writer binding, which names
that system, so every new mint writes b01c5dff, v1 fMP4 included (the 16
system-id bytes are the only difference from its earlier output). The v0 id
is decode-only, and an item minted under it still reads. Readers decode only
through the registry: the layout validators, the PSSH-set rule, the MPD builder
and the decrypt-open session constructors.

A DASH init carries a W3C Common box, then any extra boxes the producer was
given, then the custody box last. An unregistered system id is foreign: its box
is kept verbatim and listed in the MPD without a `value`. An init carries at
most one custody box, and all renditions of one item share one custody system.
Nothing supplies extra boxes yet; the wire field, validators and MPD listing are
in place. The media-format profile (V1 or V2 layout) is a separate axis from the
protection system.

Adding a system is one adapter, which encodes and decodes its own box, plus one
registry line; the shared conformance suite then runs over it.

Sample encryption is AES-128-CTR, which has no per-sample authentication
tag. This is inherent to the CENC standard, which defines no authenticated
scheme. Tamper-evidence on the media path therefore comes from outside the
cipher, and before any keystream is applied. For a v1 item it is the staged
segment's SHA-256 and byte-length check. For a v2 item it is the same check
against the manifest plus the Merkle proof of the segment against the identity
head. Any future consumer that fetches segments over a network rather than
reading Runtime-staged bytes has to carry that check itself or it has no
integrity protection at all. The object path does not have this shape: its
chunks are AES-256-GCM and the integrity is in the cipher. [Protected-content
crypto review](PROTECTED_CONTENT_CRYPTO_REVIEW.md) records both, with the tests
that pin them.

At decrypt open, before any key work, the decrypt provider checks the custody
box against the release: its content access id is the release policy's, and its
pool, epoch and committee authorization are the ones the release's key envelope
names. A DASH v2 item always carries the box.

### Limits

The mint workflow adds no size or duration cap, for media or for objects. The
source, the package and the number of segments are bounded only by the
encoding (`u32` counts, 1 PiB of encrypted content), and the producers stream
rather than hold the package. The media-provider's old limit fields are still
accepted so installed configuration loads, but they are not enforced, and its
timeout is now a stall timeout.

One cap stays, by design: a protected segment is at most 2 MiB minus 32 KiB.
Segments are 2 seconds with a bounded bitrate, so ordinary media is well
inside it. It exists because a decrypt answer echoes the encrypted segment and
the clear part as JSON number arrays, up to four characters per byte, and that
answer must fit the 16 MiB provider frame. A mint refuses a larger segment,
and the manifest check refuses a listing that declares one, so an oversized
foreign listing fails at buy instead of at play.

Protocol and storage limits are not part of the mint workflow and are unchanged:
the Library/Runtime object upload size (100 MiB, chunked uploads included), the
local content-manifest bound (1 MiB) and the principal-root and whole-file
source reads. They can still bound the largest source or package until they are
lifted, which is tracked in #444. Publish and open also hold roughly a
package's bytes in memory several times over; that is tracked there too.

### Creator copy

A video whose encoder wrote more slices per frame than the protection can
describe (one subsample entry must fit a 255-byte `saiz` entry) is refused with
"This video has too many slices per frame; re-encode it with fewer slices."
Creator shows it as it is.

### Known follow-ups

- Publish and open memory (#444).
- Show an "already minted" outcome when a duplicate mint reverts.
- A connector approval declined externally.

## Viewer admission

A viewer operation is admitted on the verified executable actor behind the
launch token, never on anything the caller sends. The gateway refuses a
viewer operation unless the launch token's selected resource and executable
actor are the same and that actor is one of the two admitted viewers. It then
strips every routing and binding field from the request body and substitutes
the verified values. The session binding is derived over that verified actor,
so a binding minted for one viewer can never match the other, and a viewer
launched for one kind of content cannot open the other kind.

## Private providers

`ProviderRegistry` owns reserved Runtime-only native provider targets:

- `protect`
- `media`
- `custody`
- `protected-content-decrypt`

Capsule URI lookup, public provider proxying, interface projection, and route
lists exclude these native targets. Runtime registers a target only after the
provider returns the exact successful identity, a valid release version (it may
differ from the Runtime's after a Runtime-only update), configured state,
schema or protocol version, and ordered operation set. Rejected startup settles and reaps the child
before it returns an error.

Protect, media, and decrypt run as local native provider processes. Custody can
use Carrier to reach a Runtime-selected remote endpoint. Runtime keeps signed
operation authority, provider selection, policy, and response verification.

The Runtime-owned `custody-pool` service exposes the authenticated server
prepare/open/read/close contract over Runtime-selected routes. The separate
`public-ipfs` target is local and Runtime-only; it cannot be invoked by a capsule
or a Carrier peer. Neither service grants direct access to the native decrypt
provider.

The custody node state root keeps the historical directory name
`protected-content/custody-provider/inactive`. Provisioned hosts already hold
state there, so the path is frozen; the name carries no meaning about whether
the custody plane is active.

## Identity and rights

The CENC KID and `EncryptedContentIdentityV1` are separate:

- The KID is the exact bytes16 value used by the deployed rights read.
- The encrypted-content identity binds the complete protected object and media
  contract.

Verified deployed read behavior is:

- `AuthorityGateway.hasAccessByContentId(address,bytes16) -> bool` owns access
  reads.
- `CentralStorage.ipReference(bytes16)` is the proven KID read resolution.
- Unknown KIDs revert with `UnboundContentId(bytes16)`; a bound KID without
  access returns `false`.

The configured Base 8453 contract uses these operations. Deployed verification
evidence belongs in its GitHub issue:

- `CentralStorage.bindIP(bytes16,address,uint256)` accepts acknowledged
  contracts only and is called by `AssetFactory.registerNewAsset`.
- Native `AuthorityGateway.buyAccess` uses selector `0xf7580ad9`.
- ERC20 `AuthorityGateway.buyAccess` uses selector `0x0ede2294`; Wallet first
  approves the operative `paymentProcessor()`.
- EventHub is the mint event emitter.
- A deployed bound KID has recorded allowed, denied, and unbound results.

The exact funded buy receipt and event remain installed proof. Deployed access
is one boolean per holder and KID, so signed Runtime policy owns the View and
Download action distinction.

The operator supplies one owner-only
`protected-content/chain-provider.json` with one versioned
`protected_content_network`. A Home with protected content enabled and no such
file installs the proven Base deployment at Chain provider startup: the rights
gateway, mint ledger, event emitter, USDC and ETH pay tokens, and four public
evidence RPC sources. An existing file is never replaced. Runtime supplies its
operation issuer identity separately. Each custody node uses its own node-host Chain provider, reads 2-5
explicit private RPC sources, and requires two exact agreeing finalized
results. Generic Chain configuration remains separate and is not a
protected-content fallback.

## Custody and decryption

An operator can set `protected_content_remote_object_sealing = true` for new
Library object mints and `protected_content_remote_dash_sealing = true` for
new Library DASH mints. Both settings default to off. The selected custody
pool must admit the Home's Runtime issuer and advertise an eligible sealer.
Runtime sends the authorized preparation in encrypted parts. Once it saves the
signed request, Resume keeps the same pool, sealer and content access ID even
if the setting changes. The portable listing carries the sealer's signed
publication proof. Public mint metadata retains the creator's profile.

The sealer sends verified ciphertext to Content for publication. Content hashes
the staged files, builds the package manifest, and streams the directory into
the private IPFS store. It gets the root and file CIDs from that import and
validates the complete file table before pinning. The sealer checks the stored
package and its availability receipt before signing completion. Remote-seal
listings use portable-listing v3, with a 1 MiB listing limit for the signed proof.

Remote sealing shares the host storage limit with custody shares and kept
copies. An accepted upload reserves its spool space before sending bytes to
Protect. Content's private import receives a separate charge before dispatch.
The spool charge is released after its files are removed. Both charges stay
in place if a lost import reply leaves the backend's use of the spool uncertain.
An exact import retry reuses the import charge, which remains in the host total
after the spool is removed.

The source policy is exactly 2-of-3 across distinct operators and failure
domains. Each custody node stores one share and checks the exact signed Runtime
operation, Wallet subject, KID, full encrypted-content identity, action,
custody epoch, policy, finalized rights evidence, recipient authorization, and
time window.

Custody membership and content storage are separate roles. A pool member with
an accepted copy obligation pulls the bound package after share acceptance,
verifies it, and charges its bytes under host-wide ownership. Repair checks
active obligations. Stop serializes each copy's removal against other owners
and announcement, so stopping one pool cannot remove another owner's copy or
resurrect a stopped announcement. Active member copies announce on Carrier,
not the public IPFS DHT. A key-only custody deployment is not counted as a
content replica.

A separate public Kubo store holds only the mint's validated metadata folder
and cover. Metadata sharing is enabled by default when protected content is
enabled, but the store runs only with the admin's standing consent in Inbox.
Import and pin must finish before mint approval; bounded background announcement
must not hold that approval open. Ciphertext never enters this public store.
See [Public Metadata Store](CONTENT_AVAILABILITY.md#public-metadata-store).

### Key release waits for finality

A custody node releases its share only on rights evidence read at the chain's
`finalized` block. `latest` and `safe` are never accepted. The rule is part of
the signed policy (`RightsObservationFinalityV1::Finalized`, see
[the contract](PROTECTED_CONTENT_CONTRACTS_V1.md)), and the chain provider
hard-codes it for every rights read that can lead to a release. There are two
reasons:

- A released key cannot be recalled. The evidence that justifies a release
  must be state that can no longer be undone. On Base, `finalized` means the
  Ethereum block that carries the L2 batch is finalized by Ethereum consensus.
  `safe` means only that the batch is posted to Ethereum: an Ethereum reorg
  before finality, combined with the sequencer posting different L2 history,
  could still remove the mint or purchase that granted access.
- The corroboration across RPC sources depends on it. Sources are pinned to
  the lowest finalized block among them and must agree on its hash. That is
  sound only because the finalized head never moves backwards. The `safe`
  head can be reset after an Ethereum reorg.

This has a visible cost. Access is readable at the chain head in the block
that grants it, and the upfront ownership check reads the head, so a new mint
or purchase shows as owned within seconds. Custody cannot release until the
`finalized` block reaches that block. On Base, that is Ethereum finality (two
epochs, about 13–15 minutes) plus batch posting: roughly 15–20 minutes after
the transaction confirms.

The open waits through that window instead of failing. For a copy confirmed
less than an hour ago, before any Wallet request or custody call, it asks the
chain provider the question custody will ask, at the `finalized` block. If
access is not there yet but is at the head, the open answers the `finalizing`
stage: resumable, nobody needs to act, with an estimated `ready_at`. The
Reader and the Player keep asking every 15 seconds for up to 40 minutes and
show the estimate. In every other case, including a chain read that fails,
the open proceeds unchanged and custody gives its own answer. The wait never
releases anything early; it only avoids a release attempt that would be
refused.

The market waits the same way. The listing read decides on the `finalized`
block, so a new item is not for sale until that block reaches it. When the
listing read finds no item, Runtime reads the chain head once, only to choose
its answer. An item the head binds answers `pending_finality` with an
estimated `ready_at`: the head block's time plus the current lag of the
`finalized` block behind the head. Marketplace then shows the item's Buy and
Open disabled with "Confirming on Base · ready in about N min". It reads the
listing again at `ready_at` (or at the index's own estimate, when that is
earlier), then every minute while the item is on screen and its tab is in
sight, a bounded number of reads at a time, and enables the controls when the
listing loads. An Explore card whose index
date is less than 30 minutes old starts in that state, and Marketplace reads
its listing when the card shows. The head read is never evidence: buy, open
and release read the `finalized` block as before.

A release attempted inside the window anyway, for example one resumed from an
earlier Wallet approval, still fails closed: every custody node logs
`rights observed block_tag=finalized … outcome=unbound` and rejects with
`unknown_protected_content_object`.

The rule stays. Reading `safe` instead was considered and rejected: it would
trade a guarantee that cannot be recalled for about 15 minutes of waiting.

`CustodyEnvelopeV1` is private Runtime provisioning material. Runtime can
carry the envelope but cannot open the node-sealed shares. Public metadata
contains bounded identities, threshold and epoch facts, the CEK commitment,
and signatures.

The decrypt provider generates each operation-scoped recipient key and keeps
the secret behind an opaque handle. The authenticated Profile authorizes the
exact public key. Reconstruction uses the authenticated release operation,
verified signed epoch, released contributions and terminal receipt, recipient
possession, and public CEK commitment. Runtime stores no playback custody
envelope or sealed-share bytes. Close expires the launch authority and settles
Runtime, decrypt, viewer, and staging ownership.

The current confidentiality suite is
`elastos-xwing-draft06-hkdf-sha256-aes256gcm/v1` for new protected content.
External cryptographic review remains open before public dKMS or production
confidentiality claims. [Protected-content crypto review](PROTECTED_CONTENT_CRYPTO_REVIEW.md)
is the reviewer-facing package: every primitive with its crate version and
parameters, what each construction binds, a threat model naming the test that
pins each claim, and committed golden vectors replayed against the shipped
code.

## Forming the custody pool from Home

The Custody app lets an admin on the publishing Home form the custody pool.
The app calls the same Runtime functions as the `protected-content-config` and
`node peer add` commands. Each step maps to one command:

| Step | The admin does | Runtime command |
| --- | --- | --- |
| Prepare | Copies the Runtime issuer for the node operators and creates the pool signing key | `show-runtime-issuer`, `create-policy-authority-key` |
| Add nodes | Fills one slot for each node: **Find nodes** asks a contact that offers custody, or the owner pastes a node address and Runtime fetches the node card from the node. A pasted or dropped node card is the fallback. **Include this Home** sets up this Home's own node, and **Remove** on that slot deletes it again with a passkey (`custody.local_node.remove`) until a pool is installed. The signed pool numbers the shares by node key, so slots read "Node 1", "Node 2" until the pool is installed | `provision-custody-node` (this Home only) |
| Review | Reads the pool checks and selects the term | the descriptor checks of `generate-custody-composition` |
| Sign | Signs with a passkey. Runtime installs, verifies and registers the nodes | `generate-custody-composition`, `verify-custody-composition`, then `node peer add` for each remote node |
| Active | Reads the members, term, threshold and fingerprint, and can verify again | `verify-custody-composition` |

The node operators set up their nodes outside the app. Each operator sends the
pool owner a **node address**. The owner pastes it into a node slot, and
Runtime fetches the node's **node card** from the node over Carrier. When the
fetch is not possible, the operator sends the card itself, and the owner
pastes or drops it into the slot. A card is one line of text: the prefix
`elastos-node-card:v1:`, then unpadded base64url of a JSON object with the
schema `elastos.protected-content.custody-node-card/v1`. The object has these
fields:

- `schema`: the schema name above.
- `node`: standard base64 of the node descriptor's exact bytes.
- `ticket`: the Carrier connect ticket that reaches the node.
- `provides`: the sorted roles the node hosts, from `chain`, `custody` and
  `ipfs`.
- `ipfs_peer_id`: the node's kubo peer id. A card has it exactly when
  `provides` includes `ipfs`.

`protected-content-config export-node-card` writes a card from a descriptor,
a ticket, the roles and the kubo peer id, and prints its fingerprint. The
`deploy/custody-host` harness (`up.sh up`) writes one card for each node to
`shared/<did>.node-card`. The card carries no signature, so the app shows its
fingerprint for the owner to confirm with the operator.

### Fetching a node card from its node

The node address is the node's Carrier connect ticket. The ticket holds one
endpoint, whose id is the node's Ed25519 key, so the node's DID comes from the
address. The app reads slot text that starts with `elastos-node-card:` as a
card. It sends all other text to `POST /api/apps/custody/node-cards/fetch` as
`{"address": "<ticket>"}`. This route is for Home admins only, like the other
Custody routes.

1. Runtime decodes the ticket. A ticket that does not decode, or that does
   not hold exactly one endpoint, gets `bad_address`.
2. Runtime sends the signed operator request `custody.node_card.read` to that
   endpoint. It does not save the node as a peer.
3. The node answers with the schema
   `elastos.protected-content.custody-node-card-read/v1`, `node` (standard
   base64 of its exact descriptor bytes), `provides`, and `ipfs_peer_id` when
   the node hosts `ipfs`. The answer holds no secret.
4. Runtime makes the card from the answer and the ticket, then does the same
   checks as for a pasted card. It also makes sure that the descriptor's peer
   DID is the DID it dialed. If not, the fetch gets `ticket_mismatch`.

The answer is `{"card": "<card text>", "view": {...}}`. The slot then holds the
card text, and the pool check and the install use it as they use a pasted
card. A refusal is `{"code": "<code>", "detail": "<reason or null>"}`:

| Code | Meaning |
| --- | --- |
| `bad_address` | The text is not a node address. |
| `unreachable` | Runtime could not reach the node, the wait ended, or the answer did not verify. |
| `not_owner` | The node signed a refusal. The detail gives the node's reason. Causes include a requester that is not the node's trusted Home, clock skew and a replayed request. |
| `no_card` | The node has no node-local descriptor. |
| a card code | The card failed a check, as a pasted card can. |

**The single-requester rule.** A custody node trusts one Runtime issuer: the
`trusted-runtime-issuer` file in its custody state root. A Home's Runtime
issuer is the Ed25519 key of its DID. So the node answers
`custody.node_card.read` only when the requester is
`did:key(trusted issuer)`. This is true when that DID is not in the node's
peer store and not in an allow list. No peer gets this action from an allow
list: `node peer add --allow custody.node_card.read` is refused, and a grant in
an older configuration has no effect. The action changes nothing on the node.
To all other requesters the node gives the same refusals as before this
action existed. It does not tell them whether a DID is its trusted Home.

**The node-local descriptor.** For a Carrier route (`--transport-peer-did`),
`provision-custody-node` keeps the node's descriptor at
`protected-content/custody-node.descriptor.json`, owner-only, and the node
answers from that file. A local route is never dialed, so it keeps no file. Provisioning again with the same
identity, issuer and labels is idempotent. Different labels are refused. The
`deploy/custody-host` entrypoint runs `provision-custody-node` again on each
restart that has the three provisioning variables, so a node set up before
this file existed gets it on its next restart. The restart's descriptor copy
goes to a scratch directory that the entrypoint removes, because `--output` is
create-only. `up.sh up` logs each node's address as a label line followed by
the ticket alone on its own line, and tells the owner to paste the addresses
into Custody › Pools. It still exports
each node card as the fallback.

The Custody app keeps its files in the Home's `protected-content/` directory:
`policy-authority.key` (the pool signing key, kept on this Home only),
`custody-local-node.descriptor.json` (this Home's own node) and
`custody-pool-members.json` (the member names and cards beside the installed
pool).

### Finding nodes among contacts

A pool owner can also fill a node slot from its People contacts. A Home
offers custody to its contacts, the owner asks one of them, and that Home's
admin approves the request in Inbox with a passkey. The approval brings the
node card back, and the card fills the slot without pasting. When the pool is
installed, the owner tells each member node that it is in the signed pool.
Both Homes exchange signed custody messages over the contacts-only message
plane that [PEOPLE_CONVERSATIONS.md](PEOPLE_CONVERSATIONS.md#slice-7---custody-messages-between-contacts)
describes. A Home's identity in these messages is the verified signer, never a
field of the message.

#### The node Home

The admin turns on **Offer custody to my contacts** in Custody › Hosting and
gives a Run by and a Location. **Offering custody reveals this Home's
custody-node status (Run by, Location and roles) to all accepted contacts.**
Any accepted contact can ask, and the offer goes out while it is on, while
protected content is on, and while this Home holds no custody state. A Home
has one custody role: a Home that serves a pool, includes itself in a pool or
owns an installed pool holds a custody state, so it cannot turn the offer on
and answers other owners `already_serving`. Before a pool is installed, the
admin removes this Home from its own pool with **Remove** on its slot. Runtime
then stops this Home's custody provider and deletes the node's keys and
`custody-local-node.descriptor.json`, and the Home can offer custody again.
Runtime first moves the keys aside in one step, and from then on the node
counts as removed. A Remove that stops part way finishes when this Home starts
again, or on the next Remove, Include or offer change. When Include makes
the custody root itself, it marks the setup with
`custody-local-node.including` until the node file is written.
Until a pool is installed, Remove deletes keys that an interrupted Include
left without their node file, and so does the next start when the marker is
there. Keys that `provision-custody-node` made in the terminal have no marker,
and a start never deletes them. A pool takes this Home only while its node
file names the keys its custody root holds; otherwise the slot refuses
`local_node_no_keys`, Custody shows no node, and Include sets the node up
again. A root that cannot be read right now refuses `local_node_unreadable`
and changes nothing. Once a pool is installed, Include refuses
`pool_installed`.

To send and receive custody messages, the admin's Profile needs the custody
signing scope. **Enable custody messages** grants it with a passkey
(`custody.messages.enable`). Without it, the Home offers nothing, and its
contacts see it as `needs_update`.

A request arrives in the admin's Inbox as a card with the owner's name, the
term, and the Run by and Location the offer gave. Only a Profile that is an
admin on this Home receives requests; any other Profile refuses them as
`not_admin`. **Approve** needs a passkey (`custody.node_request.approve`)
over exactly the request that this Home recorded. Approve sets up this Home's
custody node for that owner and answers with its node card. **Decline** needs
no passkey and is final.

- **One owner per Home.** A Home serves one pool owner, named only by its
  custody root's trusted issuer. Approving declines the waiting requests of
  other owners with `already_serving`, and a later request from another owner
  gets the same answer.
- **Decline after Approve began.** A request whose approval did not finish
  stays in Inbox and is finished by approving again. It can be declined only
  while this Home's node does not already trust that owner.
- **Consent is to a term and a signing key.** Approve keeps the term and the
  owner's pool signing key fingerprint that the request named. A later
  request from the same owner with the same term and the same key gets the
  card again without asking. A request with another term or another key
  waits in Inbox as a new request, and approving it answers with the node
  that already runs; nothing is set up again.
- **Bounds.** A Home keeps at most 16 requests, at most 2 waiting ones from
  one owner, and decided or expired requests for 7 days.

#### The pool owner

In a node slot, **Find nodes** asks every accepted contact, except the
admin's own Profile, whether it offers custody. It asks at most 4 contacts at
a time, gives each 5 seconds, and stops after 20 seconds. Each contact reads
as `offering` (with its Run by, Location and roles), `not_offering`,
`unreachable` or `needs_update`. `needs_update` comes from the contact's own
Profile, without a call: that Home has not enabled custody messages. A node
that approved holds a custody state and stops offering, so the finder shows it
as **Approved** with the node slot it fills. Without contacts, the finder
points to People.

**Ask** sends a signed request for the selected term. It names the owner's
pool signing key fingerprint, and it grants nothing, so it needs no passkey.
The send is refused with a stable code: `bad_term`, `pool_installed`,
`no_signing_key`, `not_contact`, `needs_update`, `messages_not_enabled`,
`already_requested` (a request to that Home still waits, or that Home's
latest approval is for this term already) or
`too_many_requests` (16 requests are kept). A request lives for 24 hours. The
owner sends it again after a restart until the node takes it. A node that
refuses the request outright, such as `not_admin`, settles it as declined
with that code. A node that approved another term can be asked again: the
slot shows **Ask again for <term>**, and the node's admin approves the new
term in Inbox.

The owner takes a decision only when it names one of its requests by its
exact bytes, comes from the Home the request went to, arrives no later than
one hour after the request expired, and, for an approval, carries that Home's
own node card. This Home's own node is never accepted. The same decision
again changes nothing, and a different one is `already_decided`. The slot
shows **Waiting for <name>**, **Approved by <name>** (the card fills the
slot), **Declined** with the node's reason, **Not sent** when this Home could
not deliver it, or **Expired**.

**Sign and install** refuses `term_changed` when a slot holds a card from an
approved request and the install term differs from the term that node
approved. The owner asks again for the new term. A pasted card is not
matched to any request.

#### Pool active

After the install, Runtime records which members it tells. This Home's own
node is `this_home`. A member whose Home is not an accepted contact is
`not_contact`. Every other member waits for a signed **pool-active** notice.
The notice carries the exact installed composition, its fingerprint, every
member's share with its Run by and Location, the pool's start and end, the
threshold, and the share of the member it goes to. The owner rebuilds the
notice from the installed pool on each delivery pass until the member's Home
acknowledges it or refuses it. A member whose notice cannot be built settles
once: `missing_labels` for a pool installed from the terminal, which kept no
labels, and `pool_unavailable` when the installed pool is gone, unreadable or
another one.

The node keeps a notice only when all of these hold, in order:

1. The receiving Profile is an admin on this Home (`not_admin`).
2. The signer is the owner that this node serves (`not_served_owner`).
3. The pool is signed by the pool signing key that the admin approved for
   that owner (`wrong_issuer`).
4. The pool runs no longer than the term that the admin approved, with a
   minute and the clock skew to spare (`term_mismatch`).
5. This Home's node is in the pool (`not_member`), at the share that the
   notice names (`wrong_share`).
6. The pool starts later than the pool the node already keeps
   (`stale_notice`). The same pool again changes nothing.

The members' Run by and Location in a notice are the owner's display text.
The composition holds them only as hashed ids, and the node does not check
them against those ids.

The node keeps the pool's facts, not the composition. Custody › Hosting then
shows "Share <n> of <N> · <k> needed", the end date and the members. Until a
notice arrives it shows "Waiting for the owner to confirm the pool." The
admin's Inbox shows **Custody pool active** once for each pool.

On the owner's Active pool view, each member reads **Told**, **Not told yet**,
**Could not tell (<code>)**, **This Home** or **Not a contact**. **Notify
members again** retries every member that waits or was refused, except a
composition too large to send. It also matches `not_contact` members against
the current contacts again.

#### Files and limits

Discovery keeps these owner-only files in `protected-content/`:

- On a node Home: `custody-offer.json` (the offer), `custody-node-requests.json`
  (requests received and the signed decisions), `custody-served-consent.json`
  (the term and pool signing key the admin approved) and
  `custody-served-pool.json` (the pool facts from the last notice).
- On an owner Home: `custody-node-requests-out.json` (requests sent and their
  decisions) and `custody-pool-notices.json` (which members were told).

The current limits are:

- **Contacts only.** A Home offers custody to its accepted People contacts. A
  Community-wide offer list comes later on the same messages.
- **Pools of up to 9 members can be told.** A notice carries the whole signed
  composition, and its limit is 40 KiB. A 3-member composition is 14,583
  bytes and a 9-member one 40,117 bytes. The composition holds labels only as
  fixed-size ids, so these sizes hold with the longest Run by and Location
  (64 bytes each), and such a 9-member notice still fits a signed message.
  Larger pools get `too_large` until L1 gives the notice a smaller signed
  proof.
- **Protected content on.** A node with protected content off offers
  nothing, refuses requests `not_offering`, and Inbox refuses to approve
  (`protected_content_off`). Declining stays possible.
- **2-of-3 Runtime pools.** Discovery takes the slot count from the
  threshold, but the Runtime loader installs 2-of-3 pools until L1.
- **No changes to a live pool.** Adding a node to an installed pool comes
  later.
- **Stop keeps only recorded pins.** When a Home stops serving a pool, a pin
  that the pool's copy made stays only if a Library publication or a runtime
  listing on this Home also names its CID. A pin made outside those records,
  such as a direct `content.publish` or a third party with an operator-added
  grant, is not protected and goes with the pool's copy.

## Capsule boundary

Capsules receive typed object identities, product terms, progress, immutable
listing projections, opaque launch authority, and bounded media output. Runtime
derives the principal, Wallet account, Chain authority, provider selection,
availability decision, rights evidence, and effect identity.

Visible protected-content UI is live product surface backed only by the
Runtime-owned path. Source behavior alone is still not installed or live
product evidence: each installed claim needs its own receipt.

## Installed source contract

For an Add listing investigation, follow `action_id` in the `action_trace`
logs: the page sends the same `x-elastos-action-id` on the listing lookup and
its legacy import fallback. Every response returned by those handlers has its
own server-generated `x-elastos-request-id`, including authentication, JSON,
start-validation and final audit refusals. A returned error finishes the trace;
it is not reported as caller cancellation. These labels are diagnostic only
and grant no authority. Canonical CID/start labels are recorded only after the
existing validation accepts them. Stage child spans retain their own labels
during concurrent work. Request and stage events record start, finish or
cancellation with bounded outcome codes and elapsed time; compare stage
outcomes and HTTP status to locate the refusal.

The trace starts at the handler boundary. Front-door middleware refusals,
CORS preflight and extractor failures that prevent handler entry, such as a
provider-proxy body-size limit, do not receive this handler action trace.
A JSON rejection explicitly passed into the listing handler does receive it.
An absent action trace alone therefore does not prove that no request reached
the gateway.

Provider bridge traces distinguish `phase = queued` from `phase = executing`.
`queue_wait_ms` measures waiting for the shared provider I/O lock;
`execution_ms` measures time after that wait, including the dispatch fence,
request write/flush and response read. It is not CPU time. A bridge completion
with `ok = true` means transport completed, not that the provider accepted the
operation: inspect the stage outcome and response status as well. These traces
exclude full request bodies, tokens, Wallet signatures and URL query strings.
Their presence alone does not identify or repair an Add listing failure.

For a slow Add listing, compare the elapsed time of `chain_verification`
with the bridge queue and execution times for its mint-receipt and listing
reads. A successful import and a later card access check have separate
request IDs and outcomes. If the card shows Try again, trace that card's
listing request separately. Compare its item and offer stages with the
overall deadline. A listing read that returns after the deadline cannot
establish the account's access. To verify recovery, check that a fresh access
read returns the expected account state and that the card shows the matching
action. Use an account with verified access to check Open.

Full `scripts/setup-source-home.sh` installs the stable Runtime under the
platform data root at `bin/elastos`. It writes the owner-only
`receipts/source-home-installation.json` receipt after components, native
providers, capsule trees, and source-home capsule metadata are final.

Run `scripts/protected-content-installed-static-audit.py` with explicit source
root, installed data root, installed Runtime, platform, profile, and role. Its
bounded redacted receipt separates:

- source and static artifact failures;
- operator configuration prerequisites; and
- active installed proof prerequisites.

`ready_for_active_proof` means the static artifacts and supplied operator
configuration passed admission. Runtime startup, signed custody validation,
live Chain evidence, replication and repair, and mint-buy-play remain active
proof.

Operator provisioning of that configuration is one explicit command surface,
`elastos protected-content-config`. It creates the policy authority key,
provisions each custody host's state root and exports its node
descriptor, prints the Runtime operation issuer custody hosts must trust,
assembles and signs the owner-only 2-of-3 custody composition from three node
descriptors, and installs the private multi-source Chain configuration. A
generated composition or Chain configuration is proven against the Runtime
loader before success is reported, and an installed composition can be
re-verified in place. The installer never creates this operator state.

The macOS and Linux source-home restart helpers validate the installation
receipt and current clean source before any stop or migration. They select only
the stable installed Runtime, own one exact PID file, stop only the proven
prior Runtime, preserve one bounded principal-root rollback, and write one
owner-only restart receipt.

Principal-root migration writes encrypted rollback objects bound to the
principal, root, object URI and recovery data key. Runtime can restore the
original plaintext during migration recovery. It keeps the rollback payload
through release recovery and Home acceptance. Every Home start, local or public
and whether the installed Home controller, the installer or the owner started
it, then removes verified payload files and keeps the migration receipts.

Home start, `elastos update` and Recovery status read the label at the start
of each file in the protected folders, a few kilobytes for an encrypted file.
A file without a label is read whole only when it is at most 16 MiB, to tell an
unencrypted file from a damaged one, and one pass reads at most 80 MiB of such
files. A file left over once that is spent is named as not checked in this
pass and treated as damaged until a later pass checks it. They check three
things: no unencrypted file was found, each encrypted file is labelled for this
Home's current key and for the place where it is stored, and no interrupted
encryption step is waiting. Large files and large totals do not stop Home.
File contents are checked when a file is opened: Home runs the full AES-GCM
check over the whole file and uses none of it unless the check passes. A file
that looks encrypted but does not carry a correct label is damaged. This
includes a file of your own that only looks like an encrypted file; it stays
unencrypted until you upload it again in Library. A damaged file is named in
the start log and in Recovery status, shows as Blocked in Library, and is never
encrypted again. Home never changes or deletes it by itself; a Library save
over it, Empty Trash, or a new or reset background image in System →
Appearance (for a damaged background image) still can.

Cleanup holds the installation writer lock and verifies the signed installed
release, exact Home process and generation, host ownership, health response,
private attach, served Home hash and configured protected roots. An active
release transaction or migration journal keeps its recovery copies until it
finishes. A source-home deployment keeps its encrypted copies until the
installed release acceptance gate passes. Its owner also reconciles the restart
receipt and payload-free proof directory before the next source-home restart.

Cleanup also checks older Runtime migration and upgrade directories under
`backups/`. It imports a legacy plaintext backup only when its committed
receipt, object inventory, file names, hashes and ownership agree; a backup
that fails any of these checks stays in place and is reported on each Home
start. The owner of such a backup, or of an older manual backup outside
`backups/`, supplies the original owner-only plan and exact backup directory:

```sh
"$ELASTOS_INSTALLED_RUNTIME" principal-root-cleanup \
  --data-dir "$ELASTOS_DATA_DIR" \
  --binary "$ELASTOS_INSTALLED_RUNTIME" \
  --plan "$ELASTOS_MIGRATION_PLAN" \
  --backup-dir "$ELASTOS_MIGRATION_BACKUP"
```

Keep the original plan bytes, including formatting, because the receipt binds
their hash. A missing plan or receipt, changed payload, link, or uncertain
directory stays with its owner for reconciliation. These cleanup gaps are
reported while Home remains available. Cleanup durably removes the verified
files from the active filesystem; earlier snapshots and external copies have
their own retention policy. The recovery key remains available for active
protected objects, so this cleanup does not claim physical or cryptographic
erasure.

`elastos run <provider> [--with <provider>]... --carrier-addr <addr>` hosts
one or more native providers standalone, outside the full Home/gateway
supervisor tree, and writes an owner-only readiness receipt at
`<data_dir>/run/provider-host.ready.json` once every requested provider is
registered and Carrier is bound. A custody node in the storage role is
exactly this composition: `elastos run custody-provider --with ipfs-provider
--with chain-provider --carrier-addr <addr>`. Starting these providers alone
is not evidence of a member copy: storage responsibility requires an accepted
pool copy obligation and verified retained content. The chain
plane is not optional on a committee member: a node settles every release
by evaluating the rights request through its own
`protected_content_rights_evidence` call, so the host refuses to start the
chain plane without a `protected-content/chain-provider.json` naming the
protected-content network, and its evidence RPC URLs must be reachable from
the node itself (not only from the client).

`deploy/custody-host/` builds a simulation-only container image of that
composition plus a same-host, container-per-node compose harness for three
custody nodes. Its own README states the simulation boundary explicitly:
process isolation and real Carrier transport between the containers are
faithfully simulated, but distinct hardware, distinct operators, and
distinct failure domains are not, and the image must never hold a real
recipient's key material. The operator flow over that harness is: each
node's container provisions its custody state and exports a
DID-named public descriptor to a shared handoff directory on first boot, and
reads the client's protected-content chain configuration back from that same
directory on every boot (`up.sh sync-chain-config` derives it, rewriting
host-loopback evidence RPC URLs to the container-reachable host gateway); the
operator runs `elastos node peer add` against each node's exported connect
ticket from the client Runtime; the operator then runs the offline
composition ceremony described above over the three descriptors to
assemble and sign the owner-only 2-of-3 composition; a node restart (the
platform restart helper, or the container's own restart) proves the node
returns with the same DID and no required environment; and the installed
proof driver script (see [scripts/README.md](../scripts/README.md)) drives
the resulting composition end to end.

## Remaining work

Protected content is an opt-in configuration. A fresh Home leaves out the
protected-content providers, Creator, Custody, Elacity Player and Elacity
Reader; each stays published for `elastos setup --with <name>`. Home shows
their surfaces only after `elastos config set protected_content true`.
[#388](https://github.com/elastos/elastos-runtime/issues/388) owns the ordered
installed proof and acceptance. The source interfaces described here do not
replace that gate.

## Provisional retirement (completed)

The provisional `drm-provider`, `rights-provider`, `key-provider`, and
`decrypt-provider` capsules, the `elastos://drm`, `elastos://rights`,
`elastos://key`, and `elastos://decrypt` schemes, the
`elastos_common::protected_content` DTO surface, the content plane's `sealed`
object kind, the Library share provider chain, and the provisional
retirement-guard smoke were removed in one slice. No fallback, dual route, or
compatibility decoder exists.

The retired names are not reservable: they were removed from the provider
registry's reserved sub-provider allowlist, so a later provider cannot
re-register those routes. `scripts/check-product-data.mjs` fails if any of them
reappears in `components.json`, an install profile, or a release publish list.

Picture, document, text, 3D, book and comic viewers ship in
`elacity-reader`. Global listing discovery is described in
[Later: Marketplace discovery](audits/2026-09-24-protected-content-market-buy-design.md#later-marketplace-discovery).
Public custody governance remains separate later work.
