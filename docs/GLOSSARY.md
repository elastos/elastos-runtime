# Glossary

> Supplemental vocabulary note.
>
> This file is for term lookup, not for the primary repo narrative or current
> behavior contract. Use [ARCHITECTURE.md](ARCHITECTURE.md) for the system summary,
> [COMMAND_MATRIX.md](COMMAND_MATRIX.md) for command expectations, and [GitHub issues](https://github.com/elastos/elastos-runtime/issues) for status and proof.

Key terms used in the ElastOS codebase and documentation.

**Naming convention:** "ElastOS" (two capitals) is this runtime. "Elastos" is the broader ecosystem and foundation. `elastos` (lowercase) is the binary, crate names, and URI scheme.

## Current isolation and target boundary

[Security](../SECURITY.md#current-isolation-and-target-boundary) owns the current
app, provider, Home, and host boundaries and their limitations. Its
[storage table](../SECURITY.md#stored-keys-and-recovery) describes disk encryption,
key custody, and recovery coverage.

## ElastOS Four Quadrants

The planning frame for balancing the system: **PC2/Home**, **Runtime**,
**Carrier**, and **Blockchain**. The quadrants are responsibility boundaries, not
separate products. See [ARCHITECTURE.md](ARCHITECTURE.md#elastos-four-quadrants)
for the canonical definition.

## Runtime

The trusted base (`elastos` binary). It checks signatures,
capabilities, routing, lifecycle, and audit. Providers run outside the trusted
core as native processes. Release app, shell and viewer capsule manifests select
`execution: web-projection` and the `elastos.runtime-projection/v1` ABI. Runtime
serves their `browser/index.html` entrypoints. Native host and engine adapters
also sit outside the trusted core; their role defines their authority.
Also called the ElastOS kernel. In this repository, ElastOS alone means the
whole system, not only the Runtime. A PC² Host is the computer the Runtime runs
on: today an app on macOS or Linux, later possibly a dedicated appliance image.

## Principal

The runtime authority subject. A principal may represent a human account,
agent, device, capsule, or provider. Sessions and capability tokens are issued
to principals. Wallet addresses, passkeys, and DIDs are proof bindings or linked
identities for a principal, not replacements for the principal itself.
A person using Home, that person's local principal, their signed Profile, and a
delivery Device DID remain separate identities and authority subjects.

## Home

The Runtime environment where a person opens apps and uses an account. Runtime
owns its sign-in methods, sessions and authority decisions.

## Account

A local person record in one Home, identified by `person:local:<id>`. An account
owns its sign-in methods and role. A Wallet account is a separate app record for
a blockchain address.

## Sign-in method

A passkey or an added wallet that Runtime accepts to sign in to an account.
Adding a wallet takes one wallet signature and a passkey approval. It grants
sign-in access independently of Wallet payment connections.

## Wallet

The app that manages payment accounts and wallet connections. Connect a wallet
here to use it for payments. Accounts manages wallet sign-in separately; adding
a sign-in method leaves Wallet payment records unchanged.

## WalletConnect

The connection protocol for a compatible wallet app. Choose WalletConnect to
pair with a QR code or connection link. After pairing, the wallet shows its own name.

## Passkey

The default human proof for Home. A passkey proves control of a local account to
the runtime and unlocks short-lived sessions. It is not a wallet, not a DID, and
normally does not expose raw key material for encryption.

## Recovery Kit

The recovery file saved by System's **Download Recovery Kit**. Keep it private,
with its optional password. The [storage table](../SECURITY.md#stored-keys-and-recovery)
defines its contents and the data that needs separate backups.

## Profile DID

The stable person/contact identity used by signed People, discovery, accepted
contacts, and direct-conversation identity. A Profile DID belongs to a
principal-owned signed Profile document and can remain stable across device
replacement or revocation; see the
[recovery coverage](../SECURITY.md#stored-keys-and-recovery). Recovery restores
the same Profile signing seed from the Kit; a new passkey does not replace it.
It is not the passkey and not the local principal identifier. It represents the
person in collaboration, but the signed Profile document is not the human actor
or the delivery device.

## WebAuthn PRF

A WebAuthn extension that can derive credential-bound secret output during a
passkey ceremony. In ElastOS this may become a passkey-root protector for
wrapping a principal data key on the client side. Raw PRF output is key material:
it must not be sent to runtime auth routes, logged, or stored as ordinary
session data.

## Device DID (`did:key`)

The self-certifying device/node identity derived from local key material. The
runtime currently uses `did:key` for Carrier/node signing, routing, delivery
attribution, and local provider identity. It is useful without a blockchain,
but it is device/transport identity, not person/contact identity, and it does
not prove a global name claim.

## Account DID (`did:elastos` / EID)

A future or linked global account identity anchored by Elastos DID/EID
infrastructure. Use it for portable profiles, credentials, publisher identity,
service endpoints, recovery, DAO actions, and globally unique name claims. It
is not required for a local passkey account.

## Handle / Name

A human-readable label such as `alice`. Local handles are display names scoped
to one runtime or space and can collide elsewhere. A globally scarce name needs
a registry with consensus, ownership, transfer, recovery, and expiry rules, such
as an EID/DID-chain namespace or a namespace smart contract. Runtime authority
must bind to principal IDs, DIDs, signatures, and CIDs, not to an unverified
handle string.

## Digital Capsule

The portable signed package model in ElastOS. A Digital Capsule is capability-governed and explicitly described. It may be an app capsule, provider capsule, shell capsule, agent capsule, or sealed data/content capsule. User objects such as documents remain first-class objects; they become data capsules only when packaged with capsule metadata and provenance. Also written DigitCapsule. See [CAPSULE_MODEL.md](CAPSULE_MODEL.md) for the full model.

## Capsule

Shorthand for a Digital Capsule, usually an executable package. First-party apps
use web projections; first-party providers use native operating-system processes.
WASM Components have a separate tested authoring path. Browser VM engines have
host-specific adapters and need target proof. A package role or declared type
alone establishes neither isolation nor granted authority.

## Capsule Runtime (AppCapsule Runtime)

The per-capsule execution contract. This is the common runtime surface that makes one capsule portable across substrates such as WASM and microVM. It is not the trusted node core and not Carrier. In the current repo, this concept spans `elastos-guest`, `elastos-compute`, `elastos-crosvm`, and the guest bridge protocols rather than one single crate. Also called the RTOS-Runtime. Despite that name it gives no real-time guarantee: each capsule sees one flat address space, and hard real-time control stays in the device provider or controller (PRINCIPLES.md §19). Licence and right checks belong to Runtime admission and effects, never to code inside the capsule.

## Capsule Artifact

The immutable packaged form of a capsule: manifest, code or rootfs payload, and signature/provenance material.

## Content Capsule

A non-executable Digital Capsule with `role=content` and `type=data`. Games,
GGUF models, sealed media, and other portable data use this role when packaged
with a manifest and provenance. The CID of the complete immutable
manifest-and-payload closure is its package identity. A viewer binding or
compatible provider interface describes how Runtime may use it; neither grants
authority. See
[Content capsule distribution](CONTENT_CAPSULE_DISTRIBUTION.md).

## Capsule Instance

One running copy of a capsule, bound to a session, capability set, and execution substrate.

## Capsule State

Mutable state associated with a capsule instance or user, kept separate from the immutable capsule artifact.

## Shell

A capsule that presents Runtime facts and emits typed user or agent intents. A
shell may be graphical, CLI, or TUI, but its manifest role is not an authority
grant. Runtime policy decides which shell identities may become active and
authorizes every launch, approval, provider, and shell-switch effect.

## ESP

ElastOS Shell Protocol. ESP is the shell-facing contract for Runtime facts and
typed intents. Home and alternate shells use it without gaining authority.
Some branch history calls the Runtime and capability baseline first integrated
on the ESP line the "ESP substrate." That is lineage shorthand, not a second
protocol, expansion, authority layer, or capsule ABI.

## Provider

A capsule or Runtime-owned service that implements a typed contract. Examples
include `localhost-provider` for rooted local storage, `did-provider` for
identity, `model-provider` for typed model offers and durable runs,
`chain-provider` for typed chain reads and proofs, `wallet-provider` for Wallet
proof and approval authority, `rights-provider` for protected-content rights
evidence, `decrypt-provider` for scoped decrypt/render sessions,
`availability-provider` for configured replication, and `ipfs-provider` for
low-level local IPFS through Kubo. Runtime selects providers. Application
capsules use typed Runtime resources instead of choosing providers or network
routes. P2P networking is provided by Carrier below Runtime routing.

## Observation

A provider report about a named subject at a stated time. An observation used
for authority or safety must carry enough source, freshness, integrity, and
replay evidence for the consuming policy. Receiving a webhook or transport
message does not establish that the reported state is true.

## Actuation

An effect intended to change digital, economic, rights, or physical state.
Runtime authorizes and routes it through a typed provider operation. A physical
controller retains the final local safety decision. Ownership evidence is not
an actuation capability.

## Effect settlement

Runtime's durable knowledge of whether an external effect occurred. Transport
acceptance, provider acceptance, execution, and observed outcome are separate
claims. If Runtime cannot prove the outcome after dispatch, settlement remains
unknown and retry follows the operation's reconciliation contract.

## Content Availability Provider

The intended higher-level provider contract for publishing, fetching, checking,
repairing, and unpublishing SmartWeb objects. It sits above low-level
`ipfs-provider` and hides whether bytes are pinned locally, replicated through
Elacity/supernodes, served by volunteer nodes, or later backed by paid storage
markets. Normal app capsules should use `elastos://content/*`, not raw
`elastos://ipfs/*`.

## Protected Content Coordination

The intended Runtime-owned sequence for sealed content. Runtime will bind the
exact object, Profile, Wallet-approved action, session, rights evidence, custody
epoch, and decrypt session. It will then coordinate rights, custody, and decrypt
providers.
Apps receive scoped output or an opaque handle. They do not receive raw CEKs,
custody shares, provider routes, endpoint DIDs, network locations, credentials,
Wallet RPC, Chain RPC, Kubo/IPFS APIs, or Elacity authority.

## dKMS

Distributed key-management system for protected content. The ElastOS direction is
PQ-hybrid threshold release for new content: AES-256 CEKs, `t-of-n` shares,
hybrid X25519 + ML-KEM share wrapping, Runtime-selected custody providers, and
scoped decrypt sessions.
FROST may help sign classical v0 receipts or cohort decisions, but it is not the
long-term dKMS security root. Runtime selects the local adapter or Carrier route
for a dKMS operation. The caller does not select a dKMS peer, host, backend, or
transport.

## CEK

Content encryption key. A CEK may exist only inside reviewed key-release and
decrypt custody. Runtime, Carrier, ordinary Apps, and ordinary receipts may
carry sealed key material or bounded results, but never the live CEK.

## Carrier

The authenticated off-box communication and content transport of an ElastOS
node. Carrier can carry peer discovery, messaging, streams, replication, and
content transfer when Runtime routing selects it. It is not the capsule API,
the authority system, or the whole Runtime. Transport-peer authentication does
not by itself prove application-message authorship. See
[CARRIER.md](CARRIER.md) for the full framing. Some vision texts use "Carrier"
for the whole kernel; in this repository Carrier is the transport only.

## `elastos://`

The native namespace exposed by the runtime. It is broader than Carrier alone:

- some `elastos://` operations are Carrier-backed, such as peer and content flows
- some are provided by first-party providers, such as DID or AI routes
- all are routed and capability-checked by the runtime

So `elastos://` is the contract surface; Carrier is one major substrate behind it.

## Exit

The typed egress contract for reaching public network destinations under
Runtime policy. Carrier is endpoint-authenticated transport between ElastOS
nodes. Runtime may reach a remote Exit over Carrier, but Exit and Carrier remain
separate capabilities and responsibilities.

## HTTP

HTTP is an implementation and compatibility protocol in this repo, not the definition of Carrier.

Main roles:

- runtime control API between capsules/shell and the node
- browser/gateway access path for humans and installers
- tunnel/edge exposure for web interoperability

Trust still comes from capabilities, hashes, and signatures, not from HTTP itself.

## Guest Network

An explicit compatibility mode where a capsule gets conventional guest
networking instead of using its typed Runtime resources and substrate adapter.
This is useful for provider capsules or legacy workloads that truly need raw
TCP or guest-facing services, but it is not the preferred default for ordinary
Apps.

## iroh

The current transport implementation for Carrier's network plane. A Rust library providing QUIC, DHT-based peer discovery, gossip messaging, and mDNS local discovery. Used by the built-in Carrier node (`carrier.rs`).

## Boson / Carrier Native

The Elastos Foundation's native Carrier protocol. Boson is a future transport
target for interoperability. If it matures, it can sit under the Carrier
abstraction alongside iroh.

## TAP Device

A virtual network interface used only when a microVM capsule is explicitly
placed into guest-network compatibility mode. It provides an isolated
point-to-point link between the VM and the host. Ordinary Apps use their typed
Runtime resources through the selected substrate adapter and should not require
TAP or `sudo` at launch. TAP remains a Runtime-owned compatibility path for
workloads that genuinely need a guest NIC.

## Capability Token

A cryptographically signed permission (Ed25519). Grants a specific capsule the right to perform a specific action on a specific resource. Tokens have constraints: epoch, expiry, max uses, delegatability.

## Capability View

A derived per-capsule projection of active Runtime grants, provider bindings,
and WebSpace mounts. It helps shells, Capsules, and System inspection discover
which resources are currently available under stable names. The view grants no
authority by itself: every resource operation still requires the applicable
Runtime-verified capability. It is not a second token store or namespace
access-control system.

## CID (Content ID)

A content fingerprint that names fixed bytes or a fixed graph of content, such
as a saved revision or published package. A CID names content rather than its
location; a changing working copy needs a new revision before it can have a CID.
Availability receipts separately state which provider accepted or verified a
responsibility to keep those bytes reachable. A CID grants no permission and
makes no person, device, account, or global name claim.

## Working copy, revision, head, key, replica

In the [target storage model](STORAGE_AND_ACCESS.md#two-kinds-of-data), a working
copy is a file or database for frequent writes. A revision is a fixed save named
by its CID. A head is the signed pointer that selects the current revision,
also called a signed mutable head. A key encrypts private data and lets an
authorised reader open it. A replica is a revision kept elsewhere under the owner's
storage policy.

## Service Offer

A signed or Runtime-projected description of an available running provider
capability and its grant policy, using `elastos.service.offer/v1` where that
contract applies. It is not a content package, publisher signature, license,
availability receipt, or install grant. A model provider may offer inference
for an admitted GGUF content capsule; the GGUF itself is not a service offer.

## IPLD

InterPlanetary Linked Data: the content-addressed object graph/data model used
to represent hash-linked structures. In ElastOS it is the right model for
published object manifests, signed heads, provenance records, sealed-content
descriptors, and availability receipts. IPLD is not Carrier, not IPFS storage,
and not an access-control or rights system.

## WebSpace

In the World Computer-aligned model, a WebSpace is a mounted resolver surface for
named data and provider-backed resources. It is not just a folder on disk.
`localhost://...` is the operator's own local computer space. Domain/DNS-backed
spaces such as `joe.ela.city://...` or `dns://team-space/...` are other
principals' SmartWeb spaces, mounted only through explicit capability keys.
The resolver owns `localhost://WebSpaces/<mount>/...` first and returns typed
handles instead of letting an app walk raw storage. A mount can project native
ElastOS resources such as `elastos://content/*`, named remote spaces, or
resolver-private provider targets such as `cloud://drive/...`; those targets
remain provider authority, while Library/Home show the mounted WebSpace view.
Mutable WebSpace mounts/forks can also materialize local provider-owned objects
with explicit access-policy metadata; that local materialization is provider
state, not a raw app-visible filesystem alias.
