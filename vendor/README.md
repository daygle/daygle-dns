# Vendored crates

Patched copies of two [hickory-dns](https://github.com/hickory-dns/hickory-dns)
crates, wired in through `[patch.crates-io]` in the workspace `Cargo.toml`.
Each started as the unmodified crates.io release (`hickory-resolver` 0.26.3,
`hickory-net` 0.26.3, MIT OR Apache-2.0); the commit that added this directory
holds them exactly as published, so `git diff` against it shows every change.

The changes are in hickory's recursor and DNSSEC validator, which Daygle DNS
cannot reach from its own code. Each is covered by a test against a fake DNS
hierarchy in `crates/daygle-dns-recursive/src/recursor/hierarchy_tests.rs`.
All are worth offering upstream.

## Changes

1. **The validator's zone cut probes do not follow CNAMEs**
   (`hickory-net` `xfer/dns_handle.rs`, `dnssec/mod.rs`; `hickory-resolver`
   `recursor/handle.rs`). To prove an unsigned answer insecure, the validator
   asks for the NS records at each name above it to find the zone cut, and
   the recursor followed a CNAME at one of those names to its target: a name
   with a CNAME cannot hold NS records (RFC 1034 section 3.6.2, RFC 2181
   section 10.1), so it is not a cut, and the target is no help in finding
   one. `DnsHandle::lookup_zone_cut` (a plain lookup by default) is what the
   validator now asks with; the recursor's handle answers it without
   following the alias. `h-adashx4ae.ut.taobao.com` spent 4.3s resolving
   `shop.taobao.com`, the target of `ut.taobao.com`, this way.

2. **A zone's glueless name servers are looked up when only one has glue**
   (`hickory-resolver` `recursor/handle.rs`). Glueless name servers (named
   in another zone, so the parent sends no address) were looked up only when
   none had glue. With glue for just one, that one server was the whole
   pool, and a single query it did not answer failed. Now, below two name
   servers with addresses, up to two glueless ones are looked up as well.
   `ntp.org` (glue only for `ns1.everett.org` in `.org`) failed the DS query
   for `pool.ntp.org` that way, turning `0.datadog.pool.ntp.org` bogus.

3. **QNAME minimisation follows RFC 9156's limits, and referrals to names it
   passed over** (`hickory-resolver` `recursor/handle.rs`). The walk added
   one label per probe all the way down, and in relaxed mode kept doing so
   after a server wrongly answered NXDOMAIN for an empty non-terminal. Now:
   - the first four probes add one label each, then labels are added so a
     walk sends at most ten probes (section 2.3);
   - after an NXDOMAIN in relaxed mode the next probe is the full name
     (section 3), instead of one probe per name down to it;
   - a referral to a zone cut between the current zone and the name probed
     (one of the names passed over) is followed. It arrives as a
     `ForwardNS` error, since only NS records owned by the name asked count
     as an answer; its glue is kept only inside the current zone.
   Strict mode still stops at an NXDOMAIN (RFC 8020).

4. **No deprecation warnings on newer toolchains** (`hickory-resolver`
   `name_server.rs`, `recursor/handle.rs`). Newer Rust renamed
   `fetch_update` to `try_update`; the two calls keep the old name, which
   still builds on the minimum supported Rust (1.95), under
   `#[allow(deprecated)]`. Drop this once upstream switches.

## Upgrading hickory

Bump the version in the workspace `Cargo.toml`, replace each directory here
with the new release's sources (from `~/.cargo/registry/src/`), and re-apply
the changes listed above (or drop the ones upstream has adopted). The tests
named above check that each still holds.
