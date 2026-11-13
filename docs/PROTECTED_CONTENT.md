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

The canonical path is the installed product path. Source tests cover
same-Runtime and two-Runtime journeys, and the installed proof driver recorded
`finalize` `overall_ok: true` on the simulation-only harness. There is no other
protected-content authority.

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
5. Runtime publishes the encrypted object through the normal
   `elastos://content` path with a one-copy requirement: the creator's Home
   holds the ciphertext and serves it to any peer. Pool members hold no copy
   in this release; redundancy comes back with the pool redesign. The
   repair task keeps the same requirement.
6. Runtime binds creator mint and listing effects to the verified Wallet
   account and operator Chain configuration. It projects a listing only after
   the exact effect and finalized evidence agree. The creator tail raises
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
8. Before open, and before a buy of an imported listing package (`buy`),
   a Home whose custody pool holds the item verifies one fresh signed
   availability receipt for the exact mint, content identity, CID,
   publisher, provider, policy, replica count, and freshness window. A Home
   that does not hold the item resolves the item's pool (its own, served or
   known pools) and proves availability without a receipt: at adoption it
   fetches and verifies the manifest and every file, and at open it checks
   the manifest against the bound identity; the pool server that stages the
   item verifies the files it serves. Its listing records `kind`
   `verified_fetch` (older records read as `receipt`), its purchases record
   `verified-fetch`, and its draft binds the item's epoch committee with an
   owner-state root derived from the pool, the epoch and each node. An
   imported package on such a Home is unresolved.
9. Library or Marketplace asks Home to launch the viewer the content calls for
   — `elacity-player` for media, `elacity-reader` for everything else — with an
   opaque, short-lived launch authority. Runtime binds the open to the
   principal, object, verified executable actor, launch, decrypt session, and
   token.
10. Three independent custody nodes evaluate rights locally. Any two approved
    nodes return recipient-encrypted contributions.
11. The private protected-content decrypt provider reconstructs and uses the
    CEK inside its process. It serves bounded ordered media reads, or bounded
    fixed-size chunk reads for a non-media file, to the exact viewer session
    and settles open, read, and close ownership.

Source tests cover this sequence across two Runtimes with separate principals,
Wallets, device identities and state. The creator exports an immutable listing
package; the buyer imports and verifies it before purchase and playback. Custody
release authenticates the buyer Runtime issuer declared by the signed operation
and bound by the buyer Profile. The creator Runtime retains provisioning
authority. The funded installed localhost-to-seed journey remains open.
Shared listing links work independently of global listing discovery.

Runtime journals identities, state, receipts, and settlement. Providers keep
clear media, ciphertext staging, CEKs, shares, process details, and private
routes inside their owned boundaries. Carrier transports only
Runtime-selected remote custody traffic. Storage, provider, Carrier, and Chain
topology stays private.

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
display text only, nothing the purchase relies on. Offers are read with the
existing multi-source corroboration, every source pinned to the lowest
finalized block among them; at most 32 sellers are read per item, and a
listing states `offers_truncated` when there were more. A `buy_offer`
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
honoured by ela.city, and Marketplace keeps Buy enabled for an `unknown`
item without saying where it opens. When a purchase cannot reach the market
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
origin `granted`, and nothing ever buys, shares or lists it. A real listing
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

`buy_offer` checks the same thing before any Wallet request, for a new
attempt and for an earlier attempt whose first Wallet request was never
raised. Its check fails closed. It is `custody_elsewhere` when no pool this
Home knows keeps the item. It is `unavailable` (nothing paid; try again)
when the document, the KID's binding or this Home's custody state cannot be
read now. It passes for an item of a pool this Home can reach, or one whose
document names no ElastOS protection this Home could adopt. An attempt whose
Wallet request is already out is never refused: the person may already be
paying.

A market purchase that completed anyway answers adoption
`custody_elsewhere`, not `pending`. The listing object states
`custody_route` only when Runtime proved it: `pool` when this Home can reach
the item's pool, and `unresolved` when it cannot. The listing reads only the
descriptors this Home keeps and makes no Carrier call. For `unresolved`,
Marketplace says "This item's pool cannot be reached from this Home yet. Add
the pool in Custody." and offers no Buy, Open or Download. A completed
purchase of such an item says "Bought, but …", and a buy refused before
payment says "Nothing was paid. …", on both buy paths. After an admin adds
the pool in Custody, the same item buys and opens through that pool.

Explore asks the chain whether this person has access to an item this Home
holds no copy of. It reads each item's listing object lazily, only for the
cards on screen, with at most two market reads at once across the page.
Access minted, bought anywhere or held by subscription shows Open, which
builds the copy through `download_owned_copy` and opens it. No access shows
Buy, and so does a Home with no wallet account to ask about, because the
sheet leads to setting one up. Until the answer arrives, and while a read
that failed waits for its next try, the card shows a disabled "Checking…".
Retries back off and stop after three, and the card then settles on an
enabled "View" that opens the sheet. A settled unknown shows the same
"View", and the card never shows Buy for it. Cards read only while in the
viewport, or while rendered where the browser cannot tell. The listing
object names the account only as an opaque `access_subject`: HMAC-SHA256,
keyed with a secret derived from this Home's own device key, over the
person, chain and wallet account. Nothing outside the Home can recompute it
from an address. The page keeps the latest subject for each chain. An
answer counts only while its subject is still that chain's, and settled
answers are read again after five minutes. Coming back to the tab re-reads
one card, so an account switched in Wallet is noticed.
A download in progress shows "Downloading…" with a status line wherever the
item is shown, even after the sheet is closed and reopened, and ends on
"Saved to your Library" or the refusal's own copy.

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

`ProviderRegistry` owns four reserved Runtime-only targets:

- `protect`
- `media`
- `custody`
- `protected-content-decrypt`

Capsule URI lookup, public provider proxying, interface projection, and route
lists exclude all four targets. Runtime registers a target only after the
provider returns the exact successful identity, a valid release version (it may
differ from the Runtime's after a Runtime-only update), configured state,
schema or protocol version, and ordered operation set. Rejected startup settles and reaps the child
before it returns an error.

Protect, media, and decrypt run as local native provider processes. Custody can
use Carrier to reach a Runtime-selected remote endpoint. Runtime keeps signed
operation authority, provider selection, policy, and response verification.

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

The source policy is exactly 2-of-3 across distinct operators and failure
domains. Each custody node stores one share and checks the exact signed Runtime
operation, Wallet subject, KID, full encrypted-content identity, action,
custody epoch, policy, finalized rights evidence, recipient authorization, and
time window.

Custody membership and ciphertext replication are separate roles. In this
release only the key-share role is used: Kubo runs offline as each Home's local
store, peers accept no pushed replicas, and the creator's Home serves the one
required copy. A minted asset's public metadata folder and cover go to a
separate public IPFS store before the mint approval, on a Home that offers
metadata sharing (off by default) and with the Home admin's consent in Inbox; the ciphertext never enters it (see
[Public Metadata Store](CONTENT_AVAILABILITY.md#public-metadata-store)). The rest of this section describes the storage role the pool
redesign brings back. A custody node's job is the key share: the
ciphertext is an *input* to a release, handed to the node at the moment one
is evaluated, not something it is obliged to hold. A deployment that wants
custody without storage runs the node with the availability and IPFS planes
absent (`--role custody` for the container image), and it is then never
counted toward the replica requirement. This matters for availability
reasoning: a custody node that is not a replica cannot be a single point of
failure for content the way a conscripted replica can, and the exact
three-replica requirement in the canonical path is satisfied by nodes that
actually host that plane.

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
sight, at most two reads at a time, and enables the controls when the
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

## Capsule boundary

Capsules receive typed object identities, product terms, progress, immutable
listing projections, opaque launch authority, and bounded media output. Runtime
derives the principal, Wallet account, Chain authority, provider selection,
availability decision, rights evidence, and effect identity.

Visible protected-content UI is live product surface backed only by the
Runtime-owned path. Source behavior alone is still not installed or live
product evidence: each installed claim needs its own receipt.

## Installed source contract

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
--with chain-provider --carrier-addr <addr>`. In this release it holds no
content replica: the creator's Home serves the protected copy. The chain
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

Protected content is off by default in 0.8.0. A fresh Home leaves out the
protected-content providers, Creator, Custody, Elacity Player and Elacity
Reader; each stays published for `elastos setup --with <name>`. Home shows
their surfaces only after `elastos config set protected_content true`.
[#388](https://github.com/elastos/elastos-runtime/issues/388) owns the rebuild
after 0.8.0, its ordered proof and its acceptance.

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
