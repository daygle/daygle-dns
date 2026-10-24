// Normalises the generated console bundle to LF line endings.
//
// CI rebuilds web/dist and fails when the result differs from the committed
// bundle. Vite copies web/index.html verbatim, so a Windows checkout with
// core.autocrlf=true produces CRLF (and, for an already-CRLF blob, CRCRLF)
// while the Linux runner produces LF from the same sources. Stripping the CRs
// after every build makes the output identical on both, so the committed
// bundle only ever looks stale when it genuinely is.
//
// Runs automatically after `vite build` (see package.json).

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Extensions Vite may emit as text; anything else is left untouched. */
const TEXT_EXTENSIONS = new Set(['.html', '.css', '.js', '.mjs', '.json', '.svg', '.txt']);

const distDir = join(dirname(dirname(fileURLToPath(import.meta.url))), 'dist');

let rewritten = 0;

function normalise(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      normalise(path);
      continue;
    }
    if (!TEXT_EXTENSIONS.has(extname(entry.name))) {
      continue;
    }
    const text = readFileSync(path, 'utf8');
    if (!text.includes('\r')) {
      continue;
    }
    writeFileSync(path, text.replace(/\r/g, ''));
    rewritten += 1;
  }
}

normalise(distDir);
console.log(`Normalised ${rewritten} generated file${rewritten === 1 ? '' : 's'} to LF.`);
