# Post quantum algorithm registry and versioned envelopes

Reference implementation of the Post Quantum Algorithm Registry and Versioned Envelopes BEP draft, the Phase 0 crypto agility foundation of the BNB Chain post quantum roadmap.

## Files

- `envelope.ts` is the registry, encoder and decoder. The decoder dispatches on the declared identifier and never on body length.
- `envelope.test.ts` round trips a real key, signature and seed for every scheme and checks that a wrong version, an unknown identifier, a mismatched object kind and an out of band length are all rejected.
- `vectors.json` is a language neutral set of valid and reject vectors so a Go or Rust client can be checked against the same specification.

## Test

```
npm install
npm test
npm run vectors
```
