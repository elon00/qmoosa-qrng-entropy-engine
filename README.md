# QMOOSA QRNG Entropy Engine — Batch 018 (partial implementation)

This repository belongs to the [QMOOSA-1000 canonical manifest](https://github.com/elon00/qmoosa-1000/blob/main/catalog/canonical.json).

## Implemented offline component

`src/beacon-verifier.mjs` verifies **real Ed25519 signatures** on 32-byte entropy-beacon payloads, enforces a canonical message format, a monotonic sequence/timestamp, and a SHA-256 hash-linked chain. Invalid records fail without advancing the checkpoint. The caller must supply an authenticated, durably persisted checkpoint or explicitly allow a one-time genesis.

Run without dependencies, network calls, secrets, or chain resources:

```bash
node --version # >=20
npm run check
npm test
```

The regression suite generates ephemeral test keys in memory and tests valid signatures, tampering, replay, gaps, wrong signers, malformed input, broken links and checkpoint recovery. This is **not** a QRNG implementation, a quantum-entropy attestation, a production entropy beacon, a post-quantum signature scheme, or FIPS-certified cryptography. Signing authenticates a source; it does not prove that source used quantum hardware.

See [SECURITY.md](SECURITY.md) for the unresolved hardware provenance, authenticated transport, durable checkpoint, key rotation, security review and production gates. The rest of the Batch 018 family is scaffold-only.

**Portfolio gates: IMPLEMENTED (whole repository) = NOT VERIFIED; SECURITY_APPROVED = NO; DEPLOYMENT_READY = NO.** CI success must be confirmed at the exact PR head before reporting it.
