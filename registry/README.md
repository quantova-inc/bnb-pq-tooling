# Post quantum algorithm registry and versioned envelopes

Reference implementation of the Post Quantum Algorithm Registry and Versioned Envelopes BEP draft, the Phase 0 crypto agility foundation of the BNB Chain post quantum roadmap.

## Files

- `envelope.ts` is the registry, encoder and decoder. The decoder dispatches on the declared identifier and never on body length.
- `envelope.test.ts` round trips a real key, signature and seed for every scheme and checks that a wrong version, an unknown identifier, a mismatched object kind and an out of band length are all rejected.
- `vectors.json` is a language neutral set of valid and reject vectors so a Go or Rust client can be checked against the same specification.
- `verify.ts` implements the two signature verification checks over versioned objects, `verifyMlDsaSignature` for FIPS 204 and `verifySlhDsaSignature` for FIPS 205. Each refuses an object of the wrong kind, a key and signature of different schemes, and a scheme outside its family.
- `verify.test.ts` checks that genuine ML-DSA and SLH-DSA signatures verify, that a tampered message fails, and that mismatched and misplaced objects are refused.

## Test

```
npm install
npm test
npm run vectors
```
