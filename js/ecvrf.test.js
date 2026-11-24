import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  BETA_LENGTH,
  PROOF_LENGTH,
  PUBLIC_KEY_LENGTH,
  derivePublicKey,
  isPublicKey,
  proofToHash,
  prove,
  verify,
} from './ecvrf.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vf = JSON.parse(fs.readFileSync(path.join(__dirname, '../vectors/vectors.json'), 'utf8'));

const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');

test('suite metadata', () => {
  assert.equal(vf.suite, 'ECVRF-EDWARDS25519-SHA512-TAI');
  assert.equal(PUBLIC_KEY_LENGTH, 32);
  assert.equal(PROOF_LENGTH, 80);
  assert.equal(BETA_LENGTH, 64);
});

test('positive vectors: derivePublicKey, prove, verify, proofToHash', async () => {
  for (const vec of vf.vectors) {
    const sk = fromHex(vec.sk);
    const alpha = fromHex(vec.alpha);
    const pk = await derivePublicKey(sk);
    assert.equal(toHex(pk), vec.pk, `${vec.label}: pk`);
    assert.equal(isPublicKey(pk), true, `${vec.label}: isPublicKey`);

    const pi = await prove(sk, alpha);
    assert.equal(toHex(pi), vec.pi, `${vec.label}: pi`);

    const beta = await proofToHash(pi);
    assert.equal(toHex(beta), vec.beta, `${vec.label}: proofToHash`);

    const res = await verify(pk, pi, alpha);
    assert.equal(res.valid, true, `${vec.label}: verify`);
    assert.equal(toHex(res.beta), vec.beta, `${vec.label}: verify beta`);
  }
});

test('negative vectors', async () => {
  for (const vec of vf.negative_vectors) {
    const res = await verify(fromHex(vec.pk), fromHex(vec.pi), fromHex(vec.alpha));
    assert.equal(res.valid, vec.expected_verify, vec.description);
    if (!vec.expected_verify) assert.equal(res.beta, null);
  }
});
