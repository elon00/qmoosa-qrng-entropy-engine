import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { SignedEntropyBeaconVerifier, GENESIS_HASH, encodeBeaconMessage } from '../src/beacon-verifier.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const secondKey = generateKeyPairSync('ed25519');
const makeRecord = (sequence = 0, previousHash = GENESIS_HASH, timestampMs = 1000, key = privateKey) => {
  const unsigned = { sequence, timestampMs, entropyHex: randomBytes(32).toString('hex'), previousHash };
  return { ...unsigned, signatureBase64: sign(null, encodeBeaconMessage(unsigned), key).toString('base64') };
};
const newVerifier = () => new SignedEntropyBeaconVerifier(publicKey, { allowGenesis: true });

test('genuine Ed25519 signature and hash-linked next beacon accepted', () => {
  const verifier = newVerifier();
  const first = verifier.verifyAndAppend(makeRecord());
  assert.match(first.beaconHash, /^[0-9a-f]{64}$/);
  const second = verifier.verifyAndAppend(makeRecord(1, first.beaconHash, 1001));
  assert.equal(verifier.checkpoint.nextSequence, 2);
  assert.equal(verifier.checkpoint.previousHash, second.beaconHash);
});
test('default construction refuses untrusted genesis/reset', () => {
  assert.throws(() => new SignedEntropyBeaconVerifier(publicKey), /TRUSTED_CHECKPOINT_REQUIRED/);
});
test('trusted checkpoint resumes continuity without accepting old sequence', () => {
  const v = newVerifier(); const old = makeRecord(); const first = v.verifyAndAppend(old);
  const resumed = new SignedEntropyBeaconVerifier(publicKey, { checkpoint: v.checkpoint });
  assert.throws(() => resumed.verifyAndAppend(old), /REPLAY_OR_SEQUENCE_GAP/);
  resumed.verifyAndAppend(makeRecord(1, first.beaconHash, 1001));
});
test('replay and sequence gaps rejected without state change', () => {
  const v = newVerifier(); const r = makeRecord(); v.verifyAndAppend(r);
  const checkpoint = v.checkpoint;
  assert.throws(() => v.verifyAndAppend(r), /REPLAY_OR_SEQUENCE_GAP/);
  assert.throws(() => v.verifyAndAppend(makeRecord(3, checkpoint.previousHash)), /REPLAY_OR_SEQUENCE_GAP/);
  assert.deepEqual(v.checkpoint, checkpoint);
});
test('wrong trusted public key rejects authentic but untrusted signature', () => {
  assert.throws(() => newVerifier().verifyAndAppend(makeRecord(0, GENESIS_HASH, 1000, secondKey.privateKey)), /INVALID_BEACON_SIGNATURE/);
});
test('signed payload tampering is rejected', () => {
  const v = newVerifier(); const r = makeRecord(); r.entropyHex = randomBytes(32).toString('hex');
  assert.throws(() => v.verifyAndAppend(r), /INVALID_BEACON_SIGNATURE/);
  assert.equal(v.checkpoint.nextSequence, 0);
});
test('wrong previous hash rejected even when validly signed', () => {
  assert.throws(() => newVerifier().verifyAndAppend(makeRecord(0, 'a'.repeat(64))), /BROKEN_HASH_CHAIN/);
});
test('timestamp rollback rejected without advancing state', () => {
  const v = newVerifier(); const first = v.verifyAndAppend(makeRecord(0, GENESIS_HASH, 2000));
  assert.throws(() => v.verifyAndAppend(makeRecord(1, first.beaconHash, 1999)), /TIMESTAMP_ROLLBACK/);
  assert.equal(v.checkpoint.nextSequence, 1);
});
test('reject malformed hex, signature, and extra schema fields', () => {
  const v = newVerifier();
  assert.throws(() => v.verifyAndAppend({ ...makeRecord(), entropyHex: 'ab' }), /INVALID_ENTROPY/);
  assert.throws(() => v.verifyAndAppend({ ...makeRecord(), signatureBase64: 'AA==' }), /INVALID_SIGNATURE_ENCODING/);
  assert.throws(() => v.verifyAndAppend({ ...makeRecord(), certifiedQuantum: true }), /INVALID_RECORD_SCHEMA/);
});
test('reject non-Ed25519 trust anchors and ambiguous checkpoint options', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => new SignedEntropyBeaconVerifier(rsa.publicKey, { allowGenesis: true }), /ED25519_KEY_REQUIRED/);
  assert.throws(() => new SignedEntropyBeaconVerifier(publicKey, { allowGenesis: true, checkpoint: newVerifier().checkpoint }), /AMBIGUOUS_CHECKPOINT/);
});
test('reject malformed trusted checkpoint and integer overflow', () => {
  assert.throws(() => new SignedEntropyBeaconVerifier(publicKey, { checkpoint: { nextSequence: -1, lastTimestampMs: 0, previousHash: GENESIS_HASH } }), /INVALID_SEQUENCE/);
  assert.throws(() => newVerifier().verifyAndAppend({ ...makeRecord(), sequence: Number.MAX_SAFE_INTEGER + 1 }), /INVALID_SEQUENCE/);
});
test('checkpoint snapshot cannot mutate verifier state', () => {
  const v = newVerifier(); const snap = v.checkpoint; snap.nextSequence = 500;
  assert.equal(v.checkpoint.nextSequence, 0);
});
