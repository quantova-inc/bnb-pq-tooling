# Post quantum verification C ABI for CIP-0206

This crate binds the from scratch `qtv-crypto` core at https://github.com/Quantova/Q-Crypto and exposes three verification functions across a stable C ABI, so a host such as the Cardano Haskell node can call them the same way it calls its other native crypto. The core is written to FIPS 204 and FIPS 205 with no third party cryptographic dependency and has been independently assessed by NioLabs with no critical and no high severity finding.

## Symbols

```
int32_t qc_verify_ml_dsa_65(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);
int32_t qc_verify_ml_dsa_87(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);
int32_t qc_verify_slh_dsa (const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);
```

Each takes a pointer and length for the public key, the message and the signature, and returns one for a valid signature and zero otherwise. The message is verified in the pure form with an empty context.

## Build and check

```
cargo build --release
cc -I c-api c-api/smoke.c target/release/libqcardano_pqc_ffi.a -o smoke && ./smoke
```

`cargo build --release` produces `libqcardano_pqc_ffi.a` and `libqcardano_pqc_ffi.dylib`, and the header is in `c-api/qcardano_pqc.h`.
