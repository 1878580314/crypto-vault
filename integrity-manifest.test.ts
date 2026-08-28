import assert from 'node:assert/strict';
import { matchesManifestEntry, parseManifest } from './src/integrity.ts';

const digest256 = 'a'.repeat(64);
const otherDigest256 = 'b'.repeat(64);

const json = parseManifest(JSON.stringify({
  format: 'CRYPTA-INTEGRITY',
  version: 2,
  files: [{
    path: 'payload.bin',
    hashes: { 'SHA-256': digest256, 'SHA3-256': otherDigest256 },
  }],
}));
const jsonEntry = json.files[0]!;
assert.equal(matchesManifestEntry(jsonEntry, { 'SHA-256': digest256, 'SHA3-256': digest256 }), false);
assert.equal(matchesManifestEntry(jsonEntry, { 'SHA-256': digest256, 'SHA3-256': otherDigest256 }), true);

const unlabeled = parseManifest(`${digest256} *payload.bin\n`);
const unlabeledEntry = unlabeled.files[0]!;
assert.equal(unlabeledEntry.expectations?.[0]?.mode, 'any');
assert.equal(matchesManifestEntry(unlabeledEntry, { 'SHA3-256': digest256 }), true);
assert.equal(matchesManifestEntry(unlabeledEntry, { BLAKE3: otherDigest256 }), false);

const labeled = parseManifest(`# SHA-256\n${digest256} *payload.bin\n`);
const labeledEntry = labeled.files[0]!;
assert.equal(labeledEntry.expectations?.[0]?.mode, 'all');
assert.equal(matchesManifestEntry(labeledEntry, { BLAKE3: digest256 }), false);
assert.equal(matchesManifestEntry(labeledEntry, { 'SHA-256': digest256 }), true);

const labelReset = parseManifest(`# SHA-256\n${digest256} *first.bin\n# unrelated section\n${otherDigest256} *second.bin\n`);
assert.equal(labelReset.files[1]!.expectations?.[0]?.mode, 'any');
assert.equal(matchesManifestEntry(labelReset.files[1]!, { BLAKE3: otherDigest256 }), true);

assert.throws(
  () => parseManifest(`# SHA-256\n${digest256} *payload.bin\n# SHA-256\n${otherDigest256} *payload.bin\n`),
  /冲突/,
);

const bsd = parseManifest(`SHA256(payload.bin) = ${digest256}\n`);
assert.equal(matchesManifestEntry(bsd.files[0]!, { 'SHA-256': digest256 }), true);

console.log('integrity manifest tests passed');
