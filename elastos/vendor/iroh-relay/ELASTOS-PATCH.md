# ElastOS patch

Source: the crates.io `iroh-relay` 1.4.1 package, SHA-256
`7e5589e7c1475700686603a970275687f760df853bc6525c7eb1347aa31d7230`.
The package's licences and source files are preserved. Registry marker files
`.cargo-ok` and `.cargo_vcs_info.json` are omitted.

The standalone lock file uses `url` 2.5.9 and `form_urlencoded` 1.2.3 to address
RUSTSEC-2026-0592. The vendor provenance records this dependency update.

The library emits only an `rlib`. Runtime and capsule workspaces share a build
directory with different profiles; Cargo's combined `lib` and `cdylib` outputs
use a fixed rlib filename that can replace another profile's dependency identity.
Rust consumers use the hashed rlib; the relay server binary target is unchanged.

`QuicClient::new` in `src/quic.rs` sets
`transport.datagram_receive_buffer_size(None)`. QUIC address discovery uses
observed-address reports, so its client offers no application datagrams.
Runtime's relay policy controls production use.

Noq 1.4.0 already counts queue overhead when it bounds datagrams, including
empty ones (`noq-proto/src/connection/datagrams.rs`, `DatagramState::received`
and `DatagramBuffer::memory_used`). This patch enforces the narrower Carrier
contract of refusing unused application datagrams on address-discovery
connections. It does not claim that noq 1.4.0 has the earlier accounting gap.

Drop this patch and the workspace patch entry when the upstream client offers
no datagrams and `relay_address_discovery_offers_no_quic_datagrams` passes
against that release. `carrier_relay_paths_and_address_discovery_still_work`
checks observed addresses, relay traffic, forced relay-only payloads and direct
path promotion with Carrier's transport config.

The QAD server also owns bounded pending handshakes (256), established sessions
(4096), and separate per-IP caps (8 for each phase). Handshakes expire after five
seconds and sessions after sixty seconds. Admission guards release counts on
failure and cancellation; the owned task set is drained at shutdown. Application
streams and datagrams are disabled, and incoming packet buffers are bounded.
The discovery tests exercise real held handshakes, capacity, expiry and shutdown.
Retire these changes when upstream enforces the same limits and these tests pass
against the replacement source.

If QAD startup fails after HTTP starts, startup awaits HTTP teardown before
returning the error. Normal shutdown also waits for the HTTP task to finish.
The failed-start control proves an immediate rebind of the released listeners.

An optional authenticated-endpoint budget charges encoded relay frames before
forwarding. All sockets for one endpoint share its bucket, including debt from
cancelled frames; idle state is retired only after a full refill, with a fixed
state-capacity limit. Connection I/O retains its separate pre-authentication
limit. Throttled frames remain cancellable while the actor serves other queues.
The real relay wire test measures fresh-socket and replacement bursts.

HTTP upgrade handshakes are tracked, deadline-bound and cancelled by their
service owner. Shutdown waits for them before closing registered clients;
dropping the HTTP server also cancels their service token. A held authenticated
handshake control proves that its admission is released during shutdown.

The HTTP transport uses the configurable `ConnectionLimits` policy, whose total
and pending capacities reserve places for at least 64 source allocations.
The guard survives HTTP upgrade and remains with the relay actor. IPv4 uses one
address; IPv6 uses a /48. Runtime terminates TLS itself and accounts the socket's
actual source address. QAD validates source ownership with stateless Retry before
reserving bounded pending slots and uses the same /48 grouping.
Retire these changes when upstream bounds both transports with equivalent guards.

The standalone workspace keeps its independent lock graph. Repository Cargo
configuration owns intermediate build storage; final executables remain in each
workspace's target directory. The product lock-graph guard checks that Runtime
still resolves these path forks rather than an additional registry copy.

The final actor flush uses the existing write deadline, including during owned
shutdown. A peer that leaves a real output buffer full cannot hold shutdown open.

The test-only self_signed_tls_pem helper supplies disposable certificate material for Runtime failed-start fixtures.

Runtime source quotas group IPv6 by /48, retain admission pacing across sockets,
and reserve capacity for 64 source allocations. Home and source byte budgets
retain debt across connections; the global forwarding budget reserves current
credit only. Relay control replies stay readable during application waits.
Native TLS loads its approved identity at process startup.

After a deliberate vendor edit, format the crate on Linux, review the diff and
run `python3 scripts/check-carrier-vendor.py --record-provenance`. The source
gate checks this provenance without rewriting it. The advisory job projects the
two product lock graphs to their upstream registry identities in temporary
audit input; the shipped lock files keep the patched sources.
