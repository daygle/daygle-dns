# Rehearsing an update rollback

This runbook is for a disposable VM. Do not run it against a production host.
It covers the two apply branches, models and install, and names the states and
log lines that mean the rollback actually happened.

The repository also has two disposable harnesses that run in the normal test
suite. They exercise the production apply script with stubbed `systemctl` and
`curl`, so they prove control flow but not a real service unit:

```bash
cargo test -p daygle-dns-api --test models_update_apply
cargo test -p daygle-dns-api --test install_update_apply
```

A host rehearsal is still the only check of the real systemd unit, the real
health endpoint, and privilege separation through `runuser`.

## Where the update files live

| Path | What it is |
| --- | --- |
| `/var/lib/daygle-dns/updates` | Service-writable hand-off directory watched by `daygle-dns-update.path` |
| `/var/lib/daygle-dns/updates/staging/apply.json` | Staged manifest (`kind`, `version`, `sha256`) |
| `/var/lib/daygle-dns/updates/staging/apply.bin` | Staged installer payload or models tar.gz |
| `/tmp/daygle-dns-update/state.json` | Current phase the console polls |
| `/tmp/daygle-dns-update/update.log` | Service-side download and build log |
| `/tmp/daygle-dns-update/apply.log` | Root apply log, including probe and rollback lines |
| `/etc/daygle-dns/models` | Installed AI model files and `bundle-version` |
| `/usr/local/bin/daygle-dns` | Installed binary on the default prefix |

The exact paths follow the installer arguments. Check them with:

```bash
systemctl cat daygle-dns-update.service
systemctl cat daygle-dns.service | grep -E 'ExecStart|WorkingDirectory'
```

## Prepare the VM

1. Install the current release and let it come up healthy.
2. Enable the AI scanner and leave it in train mode long enough to record
   threat verdicts. The model probe needs at least one confident threat
   verdict; with none, `/api/ai/model-health` returns `available: false` and
   the models update installs without a comparison.
3. Confirm the baseline probe works from the host:

```bash
curl -fsS http://127.0.0.1:5380/api/health
curl -fsS http://127.0.0.1:5380/api/ai/model-health
```

The second response must include `"available":true` and a non-empty `sample`.
Save it:

```bash
curl -fsS http://127.0.0.1:5380/api/ai/model-health > /tmp/model-health-before.json
```

4. Record the files a rollback must preserve:

```bash
sha256sum /etc/daygle-dns/models/* > /tmp/models-before.sha256
cat /etc/daygle-dns/models/bundle-version 2>/dev/null || true
sha256sum /usr/local/bin/daygle-dns
daygle-dns --version
```

5. Take a VM snapshot. The update helper intentionally keeps no persistent
   copy of the previous model files or binary after a run; the snapshot is the
   recovery path if the host is left half-updated.

## Models rollback rehearsal

Use a test release whose `daygle-dns-models.tar.gz` contains a model that
performs worse on the held-out names, with a matching published
`.sha256` file. A release with a bundle that regresses the probe is the only
way to reach this branch; the apply step refuses an unpublished or mismatched
bundle before it touches the models directory.

1. Start the update from the console's AI page, or call
   `POST /api/ai/update-models` with an admin session. A `202` only means the
   run started.
2. Follow the phase as it changes:

```bash
watch -n1 cat /tmp/daygle-dns-update/state.json
```

Expected sequence on a regression:

```text
applying    -> restarting -> rolling_back -> error
```

On a healthy bundle the sequence ends at `done`.

3. Read the exact lines in the apply log:

```bash
grep -E 'model probe|restor|rolling back' /tmp/daygle-dns-update/apply.log
```

A regression logs:

```text
model probe regressed: 0 held-out threat(s) lost before, 3 after
restored model ... does not match its backup      # only if verification failed
```

The final state message should read:

```text
The new AI models read N held-out threat name(s) as non-threats, up from M; the previous model files were restored.
```

If the restore failed, the message ends with `some previous model files could
not be restored; restore them from backup` instead. In that case the host is
not recovered.

4. Verify the rollback, not just the message:

```bash
sha256sum -c /tmp/models-before.sha256
cat /etc/daygle-dns/models/bundle-version 2>/dev/null || true
systemctl is-active daygle-dns
curl -fsS http://127.0.0.1:5380/api/ai/model-health
```

- Every model hash matches the baseline.
- `bundle-version` is unchanged, or absent if it was absent before. A
  rolled-back bundle must not record its version.
- The service is `active`.
- The probe returns the baseline `lost` count, not the regressed one.

5. Check the request was consumed:

```bash
test ! -e /var/lib/daygle-dns/updates/request.processing && echo consumed
```

## Install rollback rehearsal

The install branch runs the canonical installer, which restarts the service
itself. To force the rollback path without a broken production release, use a
disposable test build whose installed binary exits at startup. Build it from a
throwaway branch and publish it as the release the updater will select, or
temporarily point the apply helper's canonical repository constants at your
test fork on this VM only. Never leave those constants changed.

1. Start a full update from the console's Update page. The service-side helper
   reports `preparing`, `downloading`, `cloning`, `building`, `installing`,
   then the apply step reports `applying` and `restarting`.
2. The expected failure sequence is:

```text
applying -> restarting -> rolling_back -> error
```

If the installer itself exits nonzero, the sequence can go from `applying`
straight to `error`; the message then starts `the full installer failed`.

3. Read the apply log:

```bash
grep -E 'health check failed|rolling back|previous binary|restored' /tmp/daygle-dns-update/apply.log
```

A health failure after a successful install logs:

```text
health check failed after installing vX.Y.Z - rolling back
rolling back /usr/local/bin/daygle-dns to the previous binary
```

The final state message should contain:

```text
was installed but did not come up, so the previous version was restored and is running again
```

4. Verify the binary and service:

```bash
sha256sum /usr/local/bin/daygle-dns
daygle-dns --version
systemctl is-active daygle-dns
curl -fsS http://127.0.0.1:5380/api/health
```

The hash must match the baseline binary hash and the version must be the
previous release.

5. Check that the service restart in the log is the rollback restart, not the
   installer's own restart. Both are expected to appear; the apply log line
   `rolling back` is the one that matters.

## When the host does not recover

- If the state is `error` and `apply.log` says some previous files could not be
  restored, restore the VM snapshot or reinstall the previous release; the
  helper has no persistent backup after it exits.
- If the service is down and the binary hash matches the baseline, check
  `journalctl -u daygle-dns -n 100 --no-pager` and the config file before
  retrying.
- If `state.json` is stuck in a running phase after the process is gone, the
  API treats a dead helper as `error` after its start grace period. Check the
  pid in the state file and `apply.log` before starting another update.

## What CI covers

The two harnesses are ordinary integration tests. The dedicated `Shell
scripts` CI job runs both of them, ShellCheck, and `sh -n` over every shipped
script:

| Test | What it proves |
| --- | --- |
| `models_update_apply` | Bundle checksum, extraction, backup, install, pinned probe POST, regression detection, restored bytes, two restarts, error state |
| `install_update_apply` | Canonical installer marker, binary replacement, failed health check, restored binary, rollback restart, recovery message |

Run them with:

```bash
cargo test -p daygle-dns-api --test models_update_apply
cargo test -p daygle-dns-api --test install_update_apply
```

They do not prove a real systemd unit, a live health endpoint, network
downloads, or `runuser` privilege separation. Those remain the host rehearsal
above.
