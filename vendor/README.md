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

4. **A zone cut probe that cannot be read lets the parent's DS answer
   decide** (`hickory-net` `dnssec/mod.rs`, `find_ds_records`). The probe
   asks the servers of the zone below a possible cut for their NS records,
   and any error other than NXDOMAIN or NODATA ended the search as bogus.
   A zone whose servers send nothing this resolver can read (both of
   `ptsecurity.com`'s answer FORMERR to every query carrying EDNS) was
   therefore never proved insecure, and every answer from it, positive or
   negative, was bogus. Now the DS at that name is asked for, as it would be
   after a successful probe: a signed proof of no DS at a delegation makes
   the answer insecure, a DS keeps it secure, and anything else moves the
   search one label up. The DS answer is validated exactly as before, so
   nothing becomes provable that a forged probe reply could not already
   reach. Covered by the tests in
   `crates/daygle-dns-recursive/src/recursor/validator_tests.rs`, against a
   signed fake root.

5. **A glueless name server's addresses are cached** (`hickory-resolver`
   `recursor/handle.rs`, `append_ips_from_lookup`). The A and AAAA lookups
   for a zone's glueless name servers went straight to the name server
   pool and their answers were not kept, though the delegation code reads
   the cache for exactly those addresses. A provider's name servers serve
   many zones, so each zone along a CNAME chain looked them up again:
   `email-static.useinsider.com` crosses two Huawei Cloud CDN zones served
   by `ns3`/`ns33.cdnhwc10.cn` and looked both up twice. The answers, only
   the records asked for and their signatures, now go into the response
   cache (and a "no records" answer too). Covered by
   `a_shared_glueless_name_server_is_looked_up_once`.

6. **A negative-cache floor on NS questions applies to a plain NODATA only** (`hickory-resolver`
   `cache.rs`). Daygle gives NS questions a five-minute floor on "no records"
   answers (`ttl_config` in `crates/daygle-dns-recursive/src/recursor.rs`),
   since zones such as Huawei Cloud's CDN ones keep them for 10 s and the walk
   and the validator ask them over and over. The cache applied a floor to
   every no-records error alike, which would also have kept an NXDOMAIN (some
   servers wrongly send one for an empty non-terminal) and a referral (only
   valid in the zone that sent it) for five minutes and stalled the next walk
   through them. For NS questions those now keep their own TTL; other
   questions keep any configured floor as before. Covered by
   `an_ns_nodata_with_a_short_soa_minimum_is_not_asked_again` and the
   `recursive_lame_servers` tests.

7. **No deprecation warnings on newer toolchains** (`hickory-resolver`
   `name_server.rs`, `recursor/handle.rs`). Newer Rust renamed
   `fetch_update` to `try_update`; the two calls keep the old name, which
   still builds on the minimum supported Rust (1.95), under
   `#[allow(deprecated)]`. Drop this once upstream switches.

## Upgrading hickory

Bump the version in the workspace `Cargo.toml`, replace each directory here
with the new release's sources (from `~/.cargo/registry/src/`), and re-apply
the changes listed above (or drop the ones upstream has adopted). The tests
named above check that each still holds.
