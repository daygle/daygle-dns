#!/bin/sh
# Refresh the CNAME-cloaking tracker catalogue the Disguised Third-Party
# Trackers privacy category uses, from AdGuard's cname-trackers (MIT).
set -eu
cd "$(dirname "$0")/.."
base=https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master
curl -fsSL "$base/script/src/cloaked-trackers.json" -o crates/daygle-dns-policy/data/cname-trackers.json
curl -fsSL "$base/LICENSE" -o crates/daygle-dns-policy/data/cname-trackers.LICENSE
echo "Updated; run cargo test -p daygle-dns-policy cname_trackers before committing."
