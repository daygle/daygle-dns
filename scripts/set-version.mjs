// Injects the release tag's version into the workspace before building.
//
// The authoritative version lives in Cargo.toml ([workspace.package]
// `version = "..."`) and is repeated in Cargo.lock for every workspace member.
// Cargo embeds it at compile time (CARGO_PKG_VERSION), so the binary's
// `--version`, the API's /status and /health endpoints and the dashboard all
// report it. When a release tag (e.g. v1.2.7) is pushed this script rewrites
// those two files so the artifacts report the tagged version instead of
// whatever was last committed.
//
// The GUI version in web/package.json + package-lock.json is then propagated
// by web/scripts/sync-version.mjs, which is invoked automatically below.
//
// Usage:
//   node scripts/set-version.mjs v1.2.7   # explicit tag or version
//   node scripts/set-version.mjs          # falls back to $GITHUB_REF_NAME
//
// The version is the tag with a single leading "v" removed and must be valid
// semver (e.g. 1.2.7 or 1.2.7-rc.1).

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(scriptDir);

const cargoToml = join(repoRoot, 'Cargo.toml');
const cargoLock = join(repoRoot, 'Cargo.lock');
const syncVersion = join(repoRoot, 'web', 'scripts', 'sync-version.mjs');

const raw = (process.argv[2] || process.env.GITHUB_REF_NAME || '').trim();
const version = raw.replace(/^v/, '');

if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(
    `Invalid version: "${raw}". Pass a tag like v1.2.7 or set GITHUB_REF_NAME.`,
  );
  process.exit(1);
}

/** Replace the first `version = "..."` under [workspace.package] in Cargo.toml. */
function setWorkspaceVersion(text) {
  const section = text.match(/^\[workspace\.package\]$/m);
  if (!section) {
    throw new Error(`[workspace.package] not found in ${cargoToml}`);
  }
  const head = text.slice(0, section.index);
  const body = text.slice(section.index);
  const re = /^(version\s*=\s*")[^"]*(")/m;
  if (!re.test(body)) {
    throw new Error(
      `version = "..." not found under [workspace.package] in ${cargoToml}`,
    );
  }
  return head + body.replace(re, `$1${version}$2`);
}

/**
 * Rewrite the version of every workspace member entry in Cargo.lock. Anchoring
 * on the top-level `name = "..."`/`version = "..."` pair avoids the indented
 * dependency lists, which never contain a `name = ` line of their own. The
 * `\r?\n` handles both LF and CRLF checkouts.
 */
function setLockVersions(text) {
  let count = 0;
  const next = text.replace(
    /(\r?\nname = "daygle-dns(?:-[a-z0-9]+)?"\r?\nversion = ")[^"]*(")/g,
    (_match, prefix, suffix) => {
      count += 1;
      return prefix + version + suffix;
    },
  );
  if (count === 0) {
    throw new Error(`no daygle-dns workspace packages found in ${cargoLock}`);
  }
  return { text: next, count };
}

writeFileSync(cargoToml, setWorkspaceVersion(readFileSync(cargoToml, 'utf8')));

const lock = setLockVersions(readFileSync(cargoLock, 'utf8'));
writeFileSync(cargoLock, lock.text);

console.log(
  `Set workspace version to ${version} (Cargo.toml + ${lock.count} Cargo.lock entries).`,
);

// Propagate the workspace version into web/package.json + package-lock.json so
// callers only need to run this one command.
execFileSync(process.execPath, [syncVersion], { stdio: 'inherit' });
