import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyArtifact } from '../src/pages/Provenance/verifyArtifact.js';

test('verifies archive bytes against the reference algorithm and detects a one-byte change', async () => {
  const original = new Uint8Array([0, 255, 32]);
  const component = { officialHashAlgorithm: 'SHA-512', officialHash: createHash('sha512').update(original).digest('hex') };
  const result = await verifyArtifact(new File([original], 'package.tgz'), component);
  assert.equal(result.status, 'CHECKSUM_MATCH');
  assert.equal(result.sha256, createHash('sha256').update(original).digest('hex'));
  original[0] = 1;
  assert.equal((await verifyArtifact(new File([original], 'package.tgz'), component)).status, 'CHECKSUM_MISMATCH');
});
