# ElastOS gossip patch

Source: the crates.io `iroh-gossip` 0.102.0 package, SHA-256
`f78267c0d936a3f51b8aa24419a7a267e42d1800ac99315f48045f2540c57922`.
Licences and packaged sources are preserved.

The library emits only an `rlib`. Runtime and capsule workspaces share a build
directory with different profiles; Cargo's combined `rlib` and `cdylib` outputs
use a fixed rlib filename that can replace another profile's dependency identity.
Rust consumers use the hashed rlib; this fork's dynamic library is unused.

`Builder::received_addr_filter` filters incoming gossip route information before
it enters the gossip address lookup. Runtime supplies its one relay-pin policy,
including after each actor rebuild. This preserves direct route discovery while
excluding unapproved relays. Retire this patch when upstream exposes an equivalent
received-address filter and the regression test passes against that source.

One existing optional-writer condition uses `is_none_or` for the pinned toolchain's Clippy check; its meaning is unchanged. The packaged simulator target also has a configuration-input unit test.

The standalone workspace keeps intermediates in its own target directory. Its
independent lock graph cannot replace Home dependencies in the shared cache.

The added [workspace] table gives the packaged crate an independent test workspace.
