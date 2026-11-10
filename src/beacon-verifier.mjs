import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

export const GENESIS_HASH = '0'.repeat(64);
const RECORD_FIELDS = ['sequence', 'timestampMs', 'entropyHex', 'previousHash', 'signatureBase64'];

function assertSafeCounter(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('INVALID_' + field.toUpperCase());
}
function assertHash(value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError('INVALID_' + field.toUpperCase());
  }
}
function canonicalMessage(record) {
  assertSafeCounter(record.sequence, 'sequence');
  assertSafeCounter(record.timestampMs, 'timestamp');
  assertHash(record.entropyHex, 'entropy');
  assertHash(record.previousHash, 'previous_hash');
  return Buffer.from([
    'QMOOSA-SIGNED-ENTROPY-BEACON-V1',
    String(record.sequence), String(record.timestampMs),
    record.entropyHex, record.previousHash
  ].join('\n'), 'utf8');
}
function signatureBytes(encoded) {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new TypeError('INVALID_SIGNATURE_ENCODING');
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== encoded) {
    throw new TypeError('INVALID_SIGNATURE_ENCODING');
  }
  return bytes;
}
function validateCheckpoint(checkpoint) {
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint) ||
      Object.keys(checkpoint).sort().join(',') !== 'lastTimestampMs,nextSequence,previousHash') {
    throw new TypeError('INVALID_CHECKPOINT');
  }
  assertSafeCounter(checkpoint.nextSequence, 'sequence');
  assertSafeCounter(checkpoint.lastTimestampMs, 'timestamp');
  assertHash(checkpoint.previousHash, 'previous_hash');
  return Object.freeze({ ...checkpoint });
}

/**
 * Verifies signatures and in-process chain continuity. It cannot establish that
 * the signed bytes originate from a quantum device, or persist checkpoints.
 * Caller MUST store checkpoints durably and authenticate them across restarts.
 */
export class SignedEntropyBeaconVerifier {
  #key;
  #checkpoint;
  constructor(trustedEd25519PublicKey, options = {}) {
    this.#key = trustedEd25519PublicKey?.type === 'public'
      ? trustedEd25519PublicKey : createPublicKey(trustedEd25519PublicKey);
    if (this.#key.asymmetricKeyType !== 'ed25519') throw new TypeError('ED25519_KEY_REQUIRED');
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('INVALID_OPTIONS');
    if (options.allowGenesis === true && options.checkpoint !== undefined) {
      throw new TypeError('AMBIGUOUS_CHECKPOINT');
    }
    if (options.allowGenesis === true) {
      this.#checkpoint = Object.freeze({ nextSequence: 0, lastTimestampMs: 0, previousHash: GENESIS_HASH });
    } else if (options.checkpoint !== undefined) {
      this.#checkpoint = validateCheckpoint(options.checkpoint);
    } else {
      throw new Error('TRUSTED_CHECKPOINT_REQUIRED');
    }
  }
  get checkpoint() { return { ...this.#checkpoint }; }
  verifyAndAppend(record) {
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
        Object.keys(record).sort().join(',') !== [...RECORD_FIELDS].sort().join(',')) {
      throw new TypeError('INVALID_RECORD_SCHEMA');
    }
    const message = canonicalMessage(record);
    const signature = signatureBytes(record.signatureBase64);
    if (record.sequence !== this.#checkpoint.nextSequence) throw new Error('REPLAY_OR_SEQUENCE_GAP');
    if (record.timestampMs < this.#checkpoint.lastTimestampMs) throw new Error('TIMESTAMP_ROLLBACK');
    if (record.previousHash !== this.#checkpoint.previousHash) throw new Error('BROKEN_HASH_CHAIN');
    if (!verifySignature(null, message, this.#key, signature)) throw new Error('INVALID_BEACON_SIGNATURE');
    if (record.sequence === Number.MAX_SAFE_INTEGER) throw new Error('SEQUENCE_EXHAUSTED');
    const digest = createHash('sha256')
      .update('QMOOSA-SIGNED-ENTROPY-BEACON-HASH-V1\0')
      .update(message).update(signature).digest('hex');
    this.#checkpoint = Object.freeze({
      nextSequence: record.sequence + 1,
      lastTimestampMs: record.timestampMs,
      previousHash: digest
    });
    return { sequence: record.sequence, beaconHash: digest };
  }
}

/** Exported only to enable independent producers to sign the exact wire format. */
export function encodeBeaconMessage(record) { return canonicalMessage(record); }
