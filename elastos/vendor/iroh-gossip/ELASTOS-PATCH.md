# ElastOS gossip patch

Source: the crates.io `iroh-gossip` 0.102.0 package, SHA-256
`f78267c0d936a3f51b8aa24419a7a267e42d1800ac99315f48045f2540c57922`.
Licences and packaged sources are preserved.

`Builder::received_addr_filter` filters incoming gossip route information before
it enters the gossip address lookup. Runtime supplies its one relay-pin policy,
including after each actor rebuild. This preserves direct route discovery while
excluding unapproved relays. Retire this patch when upstream exposes an equivalent
received-address filter and the regression test passes against that source.
