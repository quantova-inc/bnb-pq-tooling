# Quantova post quantum tooling for BNB Chain

Open source contributions from Quantova Inc toward the BNB Chain post quantum roadmap.

## Contents

- `BAPs/BAP-xxxx.md` is the Post Quantum Evidence Anchor Standard, an application standard for anchoring a post quantum commitment to an off chain record on BNB Smart Chain.
- `src/QstampAnchor.sol` is the reference contract. It has no owner, no upgrade path and no privileged function.
- `test/QstampAnchor.t.sol` covers the contract with unit and fuzz tests.
- `test/Parity.t.sol` proves the on chain commitment equals the value produced by the client adapter.
- `adapter/bsc-anchor.ts` builds the commitment and reads the anchor from the Qstamp SDK.

## Test

```
forge test
```

## Design notes

A record never reaches the chain. A salted SHA3-256 fingerprint is bound to the signer and the record kind, and only that 32 byte commitment is written on chain. keccak256 and SHA3-256 both retain about 128 bits of security against a quantum search.

## License

CC0 1.0 for the standard and the reference implementation.

## Phase 0 registry and envelopes

The `registry/` folder adds the Post Quantum Algorithm Registry and Versioned Envelopes BEP draft and its reference implementation. It gives every post quantum key, signature and commitment a self describing format so that verification dispatches on a declared identifier instead of on field width.
