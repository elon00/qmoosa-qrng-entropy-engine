# Security and reality gate — Batch 018 entropy engine

This package verifies a **signed, hash-linked entropy beacon** with real Node.js Ed25519 signature verification. It does **not** produce quantum entropy, connect to QRNG hardware, attest a physical quantum process, or prove statistical entropy quality. A signature authenticates the claimed publisher only; it does not prove the publisher used a QRNG. Ed25519 here is **not** post-quantum cryptography and no FIPS validation or security certification is claimed.

## Threat boundaries

- The caller must provision and authenticate a trusted Ed25519 public key out-of-band.
- Verification fails closed unless the caller supplies a trusted checkpoint or explicitly opts into genesis. An attacker who can replace both the checkpoint and public key can defeat this boundary.
- The checkpoint is in-memory. The caller must persist it atomically and durably across crashes and restore it securely; without that, a restart can re-accept previously signed beacons.
- Timestamps are monotonic signed integers, not a trusted clock or proof of freshness.
- The verifier validates signature, format, sequence, and chain continuity only. It does not provide randomness extraction, entropy estimation, quantum-source attestation, distributed consensus, or external provider integration.

## Acceptance gates remaining

1. Select a real QRNG provider and independently verify its provenance, attestations, and threat model.
2. Implement authenticated transport, durable atomic checkpoints, restart/concurrent-writer tests, and key rotation with trust-anchor governance.
3. Independently review source authenticity, cryptographic protocols, and the complete production deployment architecture.
4. Run CI at the exact branch HEAD and verify all checks; no CI success is assumed from local tests.

**IMPLEMENTED (entire Batch 018): NO. SECURITY_APPROVED: NO. DEPLOYMENT_READY: NO.** No public-chain deployment, paid resource, or secret is required for these offline tests.
