# Vendored crates

Patched copies of two [hickory-dns](https://github.com/hickory-dns/hickory-dns)
crates, wired in through `[patch.crates-io]` in the workspace `Cargo.toml`.
Each started as the unmodified crates.io release (`hickory-resolver` 0.26.3,
`hickory-net` 0.26.3, MIT OR Apache-2.0); the commit that added this directory
holds them exactly as published, so `git diff` against it shows every change.

## Changes

None yet.

## Upgrading hickory

Bump the version in the workspace `Cargo.toml`, replace each directory here
with the new release's sources (from `~/.cargo/registry/src/`), and re-apply
the changes listed above (or drop the ones upstream has adopted).
