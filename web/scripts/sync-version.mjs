// Keeps the GUI version in sync with the Rust workspace version.
//
// The authoritative version lives in Cargo.toml ([workspace.package]
// `version = "..."`). This script propagates it into web/package.json and
// web/package-lock.json (the root package entry), so the embedded GUI always
// reports the same release version as the server.
//
// Usage:
//   node scripts/sync-version.mjs          # update the files in place
//   node scripts/sync-version.mjs --check  # exit 1 if they are out of sync
//
// It runs automatically before every `npm run build` (see package.json) and
// is checked in the release workflow, so a release cannot ship with a GUI
// whose version drifted from the workspace.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const checkOnly = process.argv.includes('--check');
const scriptDir = dirname(fileURLToPath(import.meta.url));
const webDir = dirname(scriptDir);
const repoRoot = dirname(webDir);

const cargoToml = join(repoRoot, 'Cargo.toml');
const packageJson = join(webDir, 'package.json');
const packageLockJson = join(webDir, 'package-lock.json');

/** Read the workspace version from Cargo.toml's [workspace.package] section. */
function workspaceVersion() {
  const text = readFileSync(cargoToml, 'utf8');
  const section = text.match(/^\[workspace\.package\]$/m);
  if (!section) {
    throw new Error(`[workspace.package] not found in ${cargoToml}`);
  }
  const rest = text.slice(section.index);
  const m = rest.match(/^version\s*=\s*"([^"]+)"/m);
  if (!m) {
    throw new Error(`version = "..." not found under [workspace.package] in ${cargoToml}`);
  }
  return m[1];
}

/**
 * Rewrite the root package's version fields. The pattern anchors on the
 * "daygle-dns-gui" name field and then matches the first "version" field in
 * the same JSON object ([^{}] cannot cross a closing brace), so it works for
 * both layouts - package.json has "private"/"type" between name and version,
 * while the lockfile entries have them adjacent. Dependency versions are
 * never touched. Returns the number of fields updated.
 */
function syncFile(path, version) {
  const text = readFileSync(path, 'utf8');
  const re = /("name"\s*:\s*"daygle-dns-gui"\s*,[^{}]*?"version"\s*:\s*")[^"]*(")/g;
  let updates = 0;
  const next = text.replace(re, (match, prefix, suffix) => {
    const current = match.slice(prefix.length, match.length - suffix.length);
    if (current === version) {
      return match;
    }
    updates += 1;
    return prefix + version + suffix;
  });
  if (updates > 0 && !checkOnly) {
    writeFileSync(path, next);
  }
  return updates;
}

const version = workspaceVersion();
const updated = syncFile(packageJson, version) + syncFile(packageLockJson, version);

if (updated === 0) {
  console.log(`GUI version ${version} is in sync with the workspace.`);
} else if (checkOnly) {
  console.error(
    `GUI version is out of sync: workspace is ${version}. ` +
      'Run `node scripts/sync-version.mjs` (or `npm run build`) in web/ and commit the result.',
  );
  process.exit(1);
} else {
  console.log(`Updated GUI version to ${version} (${updated} field${updated === 1 ? '' : 's'}).`);
}
