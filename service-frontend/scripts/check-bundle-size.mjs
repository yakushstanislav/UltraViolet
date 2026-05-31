#!/usr/bin/env node
/**
 * Fails CI when the main entry chunk exceeds a gzip budget after `npm run build`.
 * Route-level code splitting keeps index small; maps/forms load on demand.
 */
import { gzipSync } from 'node:zlib';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const assetsDir = path.resolve(__dirname, '../dist/assets');

/** Gzip size ceiling for the main entry chunk (bytes). */
const INDEX_GZIP_MAX = 120_000;

const indexFiles = readdirSync(assetsDir).filter(
  (name) => name.startsWith('index-') && name.endsWith('.js') && !name.endsWith('.gz')
);

if (indexFiles.length !== 1) {
  console.error(
    `check-bundle-size: expected one index-*.js in dist/assets, found ${indexFiles.length}`
  );
  process.exit(1);
}

const indexPath = path.join(assetsDir, indexFiles[0]);
const raw = readFileSync(indexPath);
const gzipped = gzipSync(raw);

console.log(
  `index chunk: ${indexFiles[0]} raw=${raw.length} gzip=${gzipped.length} (max ${INDEX_GZIP_MAX})`
);

if (gzipped.length > INDEX_GZIP_MAX) {
  console.error(
    `check-bundle-size: index gzip ${gzipped.length} exceeds budget ${INDEX_GZIP_MAX}`
  );
  process.exit(1);
}
