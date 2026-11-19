# Code and product tree

This map names stable responsibility areas in this source tree. Exact install
membership comes from [`components.json`](../../components.json), current truth
from [GitHub issues](https://github.com/elastos/elastos-runtime/issues), and supported contracts from the linked
documentation. This file must not be used as release evidence.

The [layered C4 model](c4.md) owns the system diagrams. This file owns the path
index so the two do not drift into competing topology descriptions.

## Repository roots

| Path | Responsibility |
| --- | --- |
| `PRINCIPLES.md` | Stable decision constraints |
| `AGENTS.md` | Agent and operator process |
| `components.json` | Install profiles and component artifacts |
| `elastos/` | Trusted Runtime workspace, Bus contract, and host tools |
| `capsules/` | First-party Apps, shells, viewers, content, and providers |
| `docs/` | Architecture and interface contracts |
| `scripts/` | Build, verification, staging, and operator workflows |

## Trusted Runtime workspace

| Path | Responsibility |
| --- | --- |
| `elastos/crates/elastos-runtime` | Capability, session, capsule, invoke, and provider authority |
| `elastos/crates/elastos-server` | Binary, CLI, gateway, Home routes, Carrier, collaboration, and supervision |
| `elastos/crates/elastos-auth` | Proof-bound authorization contracts |
| `elastos/crates/elastos-identity` | Passkey and local identity support |
| `elastos/crates/elastos-common` | Shared contract types |
| `elastos/crates/elastos-namespace` | Content-addressed namespace support |
| `elastos/crates/elastos-storage` | Storage abstraction |
| `elastos/crates/elastos-compute` | Execution-substrate abstraction |
| `elastos/crates/elastos-crosvm` | Linux KVM microVM adapter |
| `elastos/crates/elastos-vz` | macOS Virtualization.framework adapter |
| `elastos/crates/elastos-guest` | Capsule-side Runtime and Bus SDK |
| `elastos/wit/elastos-bus-v1.wit` | Component Bus ABI |

## Home and product surfaces

| Surface | Primary path |
| --- | --- |
| Home host | `capsules/home` |
| Desktop shell | `capsules/home-gui` |
| Terminal shell | `capsules/home-cli` |
| System | `capsules/system` |
| People and Profile UI | `capsules/people` |
| Inbox approvals | `capsules/inbox` |
| Product Chat | `capsules/chat-room` |
| Library and objects | `capsules/library`, `capsules/object-provider` |
| Protected-content publishing | `capsules/creator` |
| Protected video viewer | `capsules/elacity-player` |
| Protected document, book and 3D viewer | `capsules/elacity-reader` |
| Browser App | `capsules/browser` |
| Wallet UI and approval methods | `capsules/wallet`, `capsules/wallet-*` |

These paths contain product behavior or projections. They do not become
authority because Home renders them. Runtime admits each identity and verifies
each effect.

## Runtime routing and providers

| Surface | Primary path |
| --- | --- |
| Provider registry | `elastos/crates/elastos-runtime/src/provider/registry.rs` |
| Runtime invoke | `elastos/crates/elastos-runtime/src/invoke/` |
| Supervisor | `elastos/crates/elastos-server/src/supervisor.rs` |
| Capsule Bus | `elastos/wit/elastos-bus-v1.wit`, `elastos/crates/elastos-guest/src/bus.rs` |
| Carrier | `elastos/crates/elastos-server/src/carrier.rs` |
| Provider packages | `capsules/*-provider` and provider entries in `components.json` |

Provider packages include typed boundaries for AI, chain, wallet, objects,
Browser Net/Exit/Engine, content availability, IPFS, and tunnels; the
Runtime-only protect, media, custody, and decrypt providers are listed under
`components.json` profiles. `components.json` is authoritative for the selected
install set; directory presence alone is not a support claim.

## Protected content and pool storage

Paths below are under `elastos/crates/elastos-server/src/` unless stated.

| Responsibility | Source |
| --- | --- |
| Runtime mint, adoption and viewer lifecycle | `protected_content_runtime.rs` |
| Remote object and DASH sources, upload and sealer authority | `remote_seal_source.rs`, `protected_content_runtime/remote_dash_source.rs`, `custody_pool_seal.rs`, `custody_pool_seal/service.rs` |
| Encrypted package manifest, private storage routing, pin and receipt | `content.rs` |
| Remote seal spool and import reservations under the host's shared storage limit | `custody_pool_seal/storage.rs`, `protected_content_runtime.rs` |
| Pool prepare, Wallet rights, release and buyer reads | `protected_content_pool_open.rs` |
| Verified signed descriptor lookup, rollover preparation and consent | `custody_pool_descriptor.rs`, `custody_pool_resolver.rs`, `api/gateway_custody.rs` |
| Server staging, proof checks and session delivery | `custody_pool_service.rs` |
| Accepted copy obligations, ownership and Stop | `custody_consent.rs` |
| Private content transport and active-copy announcements | `carrier.rs` |
| Validated metadata/cover publication and consent | `public_metadata_publisher.rs`, `public_metadata_consent.rs` |
| Canonical authority and pool-session contracts | `elastos/crates/elastos-protected-content-contracts/` |
| Pool-session state machine and transport types | `elastos/crates/elastos-protected-content-runtime/src/pool_session.rs` |
| Key custody and decrypt primitives | `elastos/crates/elastos-protected-content-custody/` |

Public metadata and cover pins are separate from protected ciphertext copies.
With remote sealing enabled for the asset type, the creator Runtime saves and
signs the mint request and sends encrypted upload pieces over Carrier to a
verified sealer in the selected pool. The sealer Runtime coordinates share
storage and asks Content to stream the staged encrypted package into private
Kubo. Content owns the manifest, storage accounting, pin and availability
receipt. The creator Runtime verifies the signed result and uses the Wallet
and Chain flow. The portable listing carries the sealer proof, and public
metadata names the creator.
Account rights come from finalized chain checks, not Contacts or a manual import.
See [Protected content](../PROTECTED_CONTENT.md) for the workflow and
[Content availability](../CONTENT_AVAILABILITY.md) for the two IPFS stores.

## Collaboration and Profile

| Concern | Primary path |
| --- | --- |
| Profile authority and loading | `elastos/crates/elastos-server/src/collaboration_profile_*.rs` |
| Discovery and presence | `elastos/crates/elastos-server/src/collaboration_discovery*.rs`, `collaboration_presence.rs` |
| Contacts and direct messages | `elastos/crates/elastos-server/src/collaboration_contact_store.rs`, `collaboration_direct_messages/` |
| Delivery and transport | `elastos/crates/elastos-server/src/collaboration_delivery.rs`, `collaboration_transport.rs` |
| Product projections | `capsules/people`, `capsules/inbox`, `capsules/chat-room` |

The signed Profile DID is person/contact identity. The local principal,
passkey, device DID, and Profile DID remain separate authority claims. See
[People and conversations](../PEOPLE_CONVERSATIONS.md).

## Browser path

```text
Browser App
  -> Runtime
  -> Net provider
  -> Exit provider
  -> Browser Engine Adapter
  -> selected engine
```

Primary paths are `capsules/browser`, `capsules/net-provider`,
`capsules/exit-provider`, `capsules/browser-engine-adapter`, and the host
adapters under `elastos/tools/` and `elastos/crates/elastos-vz` or
`elastos/crates/elastos-crosvm`.

[Browser capsule](../BROWSER_CAPSULE.md), [Browser VM target](../BROWSER_VM_TARGET.md),
define the contract; GitHub issues hold the current proof level.

## Private network path

The target private-network contract composes existing Runtime, Carrier, Net,
and Exit boundaries. A signed `PrivateNetwork` object records membership and
service policy. Runtime resolves named services and uses Carrier only for an
off-box route. An optional TUN or LAN Gateway adapter stays behind Runtime
policy and does not become the capsule ABI.

Primary implementation areas are the Runtime capability and provider registry,
`elastos-server/src/carrier.rs`, `capsules/net-provider`, and
`capsules/exit-provider`. Source presence is not proof that the complete
private-network product is implemented. See the
[private network contract](../PRIVATE_NETWORK.md) and GitHub issues.

## Model path

The component catalog includes `model-provider` behind Runtime authorization.
Exact profile membership and dependency closure come from `components.json`. The
retired terminal `chat` and `agent` source capsules are not the product
architecture. Product Chat is `chat-room`.

A general Agent Host with durable task sessions and governed tools is target
architecture, not a shipped claim. See
[human and agent architecture](../AGENT_ARCHITECTURE.md) and the
[model provider contract](../MODEL_PROVIDER.md).
