# Security

## Reporting

If you find a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/elastos/elastos-runtime/security/advisories/new). Do not open a public issue.

Do not describe an unfixed issue in a public issue, pull request, commit message, or branch name.

## Current isolation and target boundary

First-party apps run as web projections in the browser's opaque sandboxed
frames. Runtime checks each app's signed launch token and actor before it performs an effect.
Home can currently obtain every app's capability, so a compromised Home can
reach those apps' authority. The target limits Home to delegation and gives each
app a separate, revocable capability. The WASM Component authoring path runs in
Wasmtime with memory and fuel limits and Runtime Bus hostcalls. Components run
inside the Runtime process: separate linear memories, but the same operating
system process as Runtime keys. Installed Homes admit only release-path
capsules matched by signed CID receipts and capsules signed by the release
publisher, so third-party executable capsules need key-free, confined
worker processes before they are admitted
([World Computer plan](https://github.com/elastos/elastos-runtime/issues/285)).

Providers run as native operating-system processes with the Runtime user's
rights. Only the model provider is partly confined. The trusted shell helper
also runs as a native host process. The web Terminal is disabled by default;
host developer mode and closed guest registration are required to enable it.
An enabled Terminal runs commands with the host user's rights.

Stored data has a separate boundary. [Stored keys and recovery](#stored-keys-and-recovery)
explains host access while Home is locked and what the Recovery Kit contains.

Home runs a second, public IPFS node only on a Home that offers metadata
sharing, which is off by default, and only after the Home admin agrees in
Inbox with a passkey. That node holds only the metadata folders and covers of the assets
this Home mints, which the Runtime validates before import. It is a
Runtime-only target with no HTTP gateway, and capsules cannot reach it. The
IPFS network records this Home's network address with what it shares. Stop
sharing ends the Home's sharing and survives a restart; copies that other
nodes keep stay public. Protected ciphertext stays in the private store, which
runs offline
([Public Metadata Store](docs/CONTENT_AVAILABILITY.md#public-metadata-store)).

The [isolation plan](https://github.com/elastos/elastos-runtime/issues/173)
records the remaining gates. Source checks describe this source tree. Accepted
installed proof binds the exact Runtime, components and app assets to the
journeys tested on that device.

## Browser internet consent

A new or updated Home starts with Browser internet access off. The Home owner
allows this computer's internet connection for Browser from the current Inbox
request with a passkey. Runtime binds that approval to its request ID and expiry.
Browser Settings offers Manage in Inbox. Inbox confirms Turn Off and requires
a passkey. Runtime
stores the consent decision separately from the capability token; the decision,
Inbox and Browser responses contain no token bytes.

Runtime admits internet access only through VM Browser engines. This includes
remote VM engines. Hosted, native and test-only Playwright engines are refused
on the Runtime Browser path. The Browser frame uses the VM Open route; legacy
Net HTTP, connect, resolve and stream routes return 410. Runtime owns Exit and
Net resources. App capability requests and existing app tokens cannot access
them. Direct owner shell network writes require an explicit capability token.
Each Browser launch receives its own Runtime
instance binding. Runtime checks the current grant at provider dispatch and at
each Exit relay open. Stop writes the revoked decision before it invalidates the
grant generation, cancels Runtime-owned byte copies and acknowledges completion.
A provider fetch or Chain call accepted before Stop can still finish. A remote
engine can take longer to close, while Runtime has already stopped its copies.
An accepted Carrier invocation can keep Stop pending until its reply arrives.
Inbox keeps Turn Off available to retry until Runtime confirms cleanup.

The approval display still has the [trusted-display gap (#178)](https://github.com/elastos/elastos-runtime/issues/178).
Home renders the request and starts the passkey ceremony; WebAuthn does not prove
that the person saw that exact text on an independent trusted display. The target
is a trusted display that binds what the person sees to the approved effect.

## Stored keys and recovery

Disk storage checked on 19 November 2026. Paths below are relative to the Home
data folder; `<person>` is that person's folder name. The table describes
application encryption; file names and filesystem metadata stay readable.

Runtime creates a person's data key during Profile setup or, if the key is missing,
during Recovery Kit export. The person's recovery phrase protects that key.
Runtime keeps an internal recovery record, including the
phrase, encrypted in `ElastOS/System/Auth/auth-state.json`; the unencrypted
archive key is in `recovery-archive.key` beside it. Before that protection exists,
Assistant, direct messages, and People refuse saves. Documents, Library, and
Home settings can instead write plain data.

After protection exists, Home encrypts a write only when the write goes through
principal-root protection. Document titles and names in
`ElastOS/Documents/<document>/document.json`, the Library publication index,
Community history, notifications, model run records, and Wallet account and
approval records stay plain. For existing plain files in scanned protected
folders, Home encrypts in place only when the file is 16 MiB or less and the
batch is at most 64 files and 64 MiB. Larger files stay plain until you move
them out and upload them again in Library, which encrypts uploads of up to 100
MiB.

An interrupted upload over 512 KiB can leave a readable copy in Home's
`Runtime/ObjectUploadSessions/<id>/payload.bin`. Library cannot resume that
upload, and uploading the file again leaves the old copy. Home deletes it only
when a later chunked upload starts more than 24 hours after the interrupted one
last received data. To remove it sooner, stop Home and delete that `<id>` folder.

Library can encrypt a surviving plain file of 16 MiB or less when it reads
it. Migration and
Recovery Kit export scan Library folders under each person (Desktop,
Documents, Pictures, Videos, Downloads, Public, `.Trash`, and Library under
AppData) and also Assistant, Home, Profile, Home Agent, transaction effects,
GBA, and declared capsule storage roots. Chat and People folders are not in
that declared inventory; only their service writers use principal-root
protection for new saves, and a plain file copied into those folders stays
plain without blocking Kit export. A plain file over the size or batch
limits in any scanned root blocks Recovery Kit export until you fix it.

System's **Download Recovery Kit** saves one recovery file for the signed-in
person, with optional password protection. If you leave the password empty, Home
writes plain JSON that includes Wallet private keys, the recovery phrase, and
the Profile signing seed when a Profile is present. Use a strong password and
keep the file offline. Its coverage is listed below. Keys are stored next to
the data they protect, in the same Home data folder; the person's data key is
in the Auth archive above. `wallet-key.hex` beside the Wallet service stays
readable on disk.

| Data and storage path | Encrypted on disk? | Key location | Recovery Kit restores |
|---|---|---|---|
| Home recovery authority: `ElastOS/System/Auth/auth-state.json` | Recovery material only; other auth state is plain | `recovery-archive.key` in the same Auth folder | Home recovery authority and data key (not passkeys or sessions) |
| Assistant conversations and drafts: `Users/<person>/.AppData/ElastOS/Assistant/workspace-v2.json` and legacy `workspace.json` | Yes; answers also appear in model run records | Person's data key | Data key; files separate |
| Direct messages: `Users/<person>/.AppData/ElastOS/Chat/direct-messages.json` | Yes for a Chat service write. A copied plain file at this path stays plain, and Home still starts. | Person's data key | Data key; files separate |
| Community history: `collaboration/default-conversation/history-v1.json` and plain message envelopes in `state-v1.json` | No | None | Omitted |
| Contacts and Profile: `Users/<person>/.AppData/ElastOS/People`, `Users/<person>/.AppData/ElastOS/Profile` | Yes for Home-written bodies; a copied plain file stays plain until re-written | Person's data key; Profile signing key inside the protected file | Profile identity and contacts present at export |
| Documents: `Users/<person>/Documents`; titles and file names in `ElastOS/Documents/<document>/document.json`; published bytes in `ipfs-repo` | Bodies Home writes after protection exists use principal-root protection; existing files stay plain if over 16 MiB or if the batch is over 64 files or 64 MiB until re-written; only plain files inside scanned roots for these reasons block Kit export; metadata and published bytes are plain | Person's data key for bodies | Data key; files separate |
| Library files and records under `Users/<person>`; publication index under `ElastOS/SystemServices/Library`; published bytes in `ipfs-repo` | Private files and records Library writes after protection exists use principal-root protection; an earlier plain file stays plain if it is over 16 MiB, if its batch is over 64 files or 64 MiB, or if it is outside the migration folders; only plain files inside scanned roots block Kit export; files outside those roots remain unchecked and may stay plain; published bytes and shared index are plain | Person's data key for private files/records | Data key; files separate |
| Notifications: `Local/Shared/System/Notifications` | No | None | Omitted |
| Built-in Wallet: `ElastOS/SystemServices/Wallet/wallet-state.json` | Signing keys only; account and approval records are plain | Derived from nearby `wallet-key.hex` and the person's principal ID | Active built-in Wallet account keys at export; export a key before removing an account |
| Browser profile: `Users/<person>/BrowserProfiles/default/profile.ext4` | No | None | Omitted |
| Model run records: `providers/model-provider/journal` | No; retains answers, events, and a hash of the input under its retention policy | None | Omitted |
| Model provider credentials: `providers/model-provider/secrets` | No; files restricted to the host account | None | Omitted |
| Home settings: `Users/<person>/.AppData/ElastOS/Home` | Settings Home writes after protection exists use principal-root protection, including `preferences.json`; same in-place limits as Documents; the Browser profile disk stays plain | Person's data key | Data key; files separate |

Community history, notifications, document metadata, and the Wallet file are
shared Home files, outside each person's private folder.

The Runtime account, software running as that host account, root, and the
hosting operator can read stored data, Wallet keys, and recovery material at any
time, including while Home is locked.
Passkeys control sign-in. An unlocked self-hosted Home trusts its owner and
their host software. Protection against
hosted operators and root belongs to [hosted protection (#209)](https://github.com/elastos/elastos-runtime/issues/209);
protection against other software or OS users while a self-hosted Home is locked
belongs to [locked Home protection (#210)](https://github.com/elastos/elastos-runtime/issues/210).
The Recovery Kit restores the same Profile signing seed and the same built-in
Wallet private keys that were in the export. A new passkey controls sign-in
only; it does not replace those keys. If your device or a Recovery Kit copy was
stolen, move funds to new wallet keys and create a new Profile before you treat
the old identity as closed.

A complete data-folder copy contains the keys needed to read the protected data.
Protect that backup and your Recovery Kit as secrets. Use hosted accounts only for public
demos; keep wallets, private data, and recovery material on your own device until
hosted protection passes its acceptance gate. Independent review and installed
proof remain security gates.

The Recovery Kit is not a whole-Home backup. Keep separate backups as listed in
the table before the disk is lost. [Backup and recovery (#567)](https://github.com/elastos/elastos-runtime/issues/567),
[file backup (#603)](https://github.com/elastos/elastos-runtime/issues/603),
and [replicas on your own devices (#498)](https://github.com/elastos/elastos-runtime/issues/498)
own that work. The [target storage model](docs/STORAGE_AND_ACCESS.md) explains
working copies, revisions, heads, keys, and replicas.

## Open Findings

The following security-relevant findings remain open in the current runtime and are documented here for transparency.

### Capability state and key rotation are not restart safe

**Severity:** Medium
**Files:** `elastos/crates/elastos-runtime/src/capability/manager.rs`, `elastos/crates/elastos-server/src/security_cmd.rs`
**Status:** Open

Capability signing-key creation and `elastos emergency rotate` log persistence
errors but continue with in-memory state. The emergency command can therefore
report success even when the new key was not written. Rotation also advances a
fresh in-process capability store rather than a durable epoch record. Until the
key and revocation state are committed atomically, operators must verify the
persisted key and restart result instead of treating command completion as a
durable rotation receipt.

### Runtime owns Carrier admission

**Severity:** Medium
**Files:** `elastos/crates/elastos-server/src/carrier.rs`, `elastos/crates/elastos-server/src/carrier_service.rs`
**Status:** Open (host-plane envelope)

Runtime identifies each Carrier peer by its endpoint key. A key alone gives no
authority. A Home serves a peer's `content/fetch` only for a CID that an active
publication on it lists, and a Library publication only to a peer whose
authenticated device belongs to an accepted contact of the person who
published it, as receiving Homes take files only from contacts. A protected
listing's sealed payload is served to any peer; opening it needs the key
release a purchase grants. A pin is only local storage: files received in
Chat, models and withdrawn publications stay pinned, and pinned alone is never
served to peers. Unpublish withdraws the record, which stops new transfers of
that file at once, unless another file still shared on this Home (yours or
another person's) has the same contents. After an ordinary Library Unpublish,
the readable copy stays pinned in Home's IPFS repository (`ipfs-repo`). Home
has no cleanup that removes it, and no user control or documented command yet
to remove an individual retained copy.
A Home answers a peer's read in one message and checks again just before
sending it, so a read under way when the publication is withdrawn is refused
on the same terms. Bytes already sent can't be recalled.
Over HTTP, an ordinary Home's raw CID routes (`/content/<cid>`, `/ipfs/<cid>`,
`/s/<cid>`) answer only its own Home and app sessions; a seed keeps its public
CID gateway.
Only a node that serves publisher content (a seed) answers the raw
`content_fetch` byte operation or serves without these checks. In this
release a seed accepts no new replicas from other Homes; replicas it already holds
stay. A Home accepts a new replica from a peer only if the owner gave that peer
the `content.replica` permission; replicas it already holds stay. The owner
trusts such a peer like an own device: it can ask the Home to pin content,
import complete content and read storage status. An import pins only the CID
it was asked for and never removes an existing pin. No peer can publish,
remove or repair content on a Home or a seed. Peers cannot use the
availability provider. A Home signs an availability announcement only from its
own pin state. Peers cannot push or read gossip messages directly. Only topics
that a Home joins keep messages, to a maximum of 100 topics. A granted peer's
`ensure` (once the pin succeeds) announces the CID and joins its topic, so a
granted peer shares that limit with the Home's own topics. A granted peer's
`import_exact`, `admission` and `status`, and any peer's `fetch`, join no
topic. No peer can push a whole object with `import_object`.

Host-process provider capsules use a raw operation and path envelope without a
capsule capability token. Runtime owns admission for this trusted provider
class. Manifests and audit output must show this boundary. The envelope does
not grant capsule authority.

### I/O bridge line reads are not bounded while reading

**Files:** `elastos/crates/elastos-runtime/src/handler/io_bridge.rs`
**Status:** Open

The I/O bridge rejects complete lines above 1 MiB, but its line readers
allocate before that check. Size checks after reading do not bound memory use
or an incomplete frame's lifetime. Add bounds while reading, with oversized
and slow-frame tests.

### Whole-object Carrier fetch replies are held in memory

**Files:** `elastos/crates/elastos-server/src/carrier.rs`
**Status:** Open ([#341](https://github.com/elastos/elastos-runtime/issues/341))

A whole-object content fetch reply arrives as one line. It is refused while
reading once it passes one 200 MiB file as base64 (about 268 MiB), the largest
file Runtime downloads whole. Only two such fetches run at once, and one per
peer.

### Contact requests by DID

**Severity:** Low
**Files:** `elastos/crates/elastos-server/src/collaboration_discovery_runtime.rs`, `elastos/crates/elastos-server/src/collaboration_contact_store.rs`
**Status:** Open ([#86](https://github.com/elastos/elastos-runtime/issues/86))

Anyone who has a Profile's DID can send it one contact request through the
seed's Community node, whether or not that Profile is visible in Discovery.
The node learns which Profile asked which and holds the requester's signed
Profile; it learns nothing more about the recipient until the recipient
answers in Inbox. Only the device that signed a request, answer or mailbox
read may submit it, and the recipient's Home checks every request and answer
itself. Profiles and devices are free to create, so the per-sender and
per-device limits bound one identity only: many new identities can fill one
person's 16 request slots on the node until those requests expire after
24 hours, and that person's other requests wait meanwhile. Leave Community
stops all requests.

## Resolved Findings

These findings are resolved in source but remain listed as security history because they shaped the runtime contract.

### I/O bridge parse-size check

**Severity:** Low (reduced from Medium)
**Files:** `elastos/crates/elastos-runtime/src/handler/io_bridge.rs`
**Status:** Fixed (2026-03-28)

The I/O bridge rejects complete request lines above 1 MiB before parsing. The
old `carrier_bridge.rs` has been removed. This resolved parse-size check does
not close the read-time framing gap above.

### Carrier and operator peer reads

**Files:** `elastos/crates/elastos-server/src/carrier.rs`, `elastos/crates/elastos-server/src/operator_control.rs`
**Status:** Fixed

Lines from peers are read with a size cap and a deadline, and longer lines are
refused before they are buffered. Incoming Carrier requests allow one provider
request or one gossip message plus envelope, within 10 seconds. Operator
requests, read before their signature is checked, allow 64 KiB within 10
seconds. Replies are capped by what the request can return: a full gossip
topic for a pull, one importable object for a provider call, update metadata
for an operator answer. Provider replies share a 256 MiB in-flight budget.
Whole-object content fetch replies allow one 200 MiB file as base64; the open
item above tracks streaming them. Relays close after five minutes without bytes
in either direction, and stream acknowledgements have deadlines.

## Architecture

Runtime validates signed capability tokens against the caller, action,
resource, epoch, revocation and token constraints. It checks principal and
session authority separately. Carrier authenticates transport endpoints;
Runtime verifies product identity and signed message authority before exposing
typed app projections. These checks complement the current browser boundary
and do not establish provider process confinement or a separate Home authority.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full trust model.
