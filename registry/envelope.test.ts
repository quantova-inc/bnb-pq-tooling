import { describe, expect, it } from 'vitest';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256, keccak_256 } from '@noble/hashes/sha3.js';
import { decode, encode, EnvelopeError, KIND, REGISTRY } from './envelope.ts';

const seed32 = Uint8Array.from({ length: 32 }, (_, i) => i);
const msg = new TextEncoder().encode('bnb post quantum envelope');

describe('versioned envelope round trips', () => {
  const mldsa: Array<[number, any]> = [
    [0x0001, ml_dsa44],
    [0x0002, ml_dsa65],
    [0x0003, ml_dsa87],
  ];

  it.each(mldsa)('ML-DSA id %s public key, signature and seed', (algId, scheme) => {
    const k = scheme.keygen(seed32);
    const pk = encode(algId, KIND.publicKey, k.publicKey);
    expect(decode(pk).body).toEqual(k.publicKey);
    const seed = encode(algId, KIND.seed, seed32);
    expect(decode(seed).body).toEqual(seed32);
    const sig = scheme.sign(msg, k.secretKey, { extraEntropy: false });
    const env = encode(algId, KIND.signature, sig);
    const d = decode(env);
    expect(d.body).toEqual(sig);
    expect(scheme.verify(d.body, msg, k.publicKey)).toBe(true);
  });

  it('SLH-DSA-SHA2-128s public key', () => {
    const k = slh_dsa_sha2_128s.keygen(new Uint8Array(48).fill(1));
    const env = encode(0x0004, KIND.publicKey, k.publicKey);
    expect(decode(env).body).toEqual(k.publicKey);
  });

  it('ML-KEM-768 encapsulation key and ciphertext', () => {
    const k = ml_kem768.keygen(new Uint8Array(64).fill(2));
    const ek = encode(0x0101, KIND.publicKey, k.publicKey);
    expect(decode(ek).name).toBe('ML-KEM-768');
    const { cipherText } = ml_kem768.encapsulate(k.publicKey, new Uint8Array(32).fill(3));
    const ct = encode(0x0101, KIND.ciphertext, cipherText);
    expect(decode(ct).body).toEqual(cipherText);
  });

  it('commitment digests for SHA3-256 and KECCAK-256', () => {
    const a = encode(0x0201, KIND.commitment, sha3_256(msg));
    const b = encode(0x0202, KIND.commitment, keccak_256(msg));
    expect(decode(a).body.length).toBe(32);
    expect(decode(b).body.length).toBe(32);
  });
});

describe('decoder fails closed', () => {
  const k = ml_dsa44.keygen(seed32);
  const valid = encode(0x0001, KIND.publicKey, k.publicKey);

  it('rejects an unsupported version', () => {
    const bad = Uint8Array.from(valid);
    bad[0] = 0x02;
    expect(() => decode(bad)).toThrow(EnvelopeError);
  });

  it('rejects an unknown identifier', () => {
    const bad = Uint8Array.from(valid);
    bad[1] = 0x7f;
    bad[2] = 0xfe;
    expect(() => decode(bad)).toThrow(EnvelopeError);
  });

  it('rejects identifier 0x0000', () => {
    const bad = Uint8Array.from(valid);
    bad[1] = 0x00;
    bad[2] = 0x00;
    expect(() => decode(bad)).toThrow(EnvelopeError);
  });

  it('rejects a kind that is not valid for the class', () => {
    expect(() => encode(0x0201, KIND.signature, new Uint8Array(32))).toThrow(EnvelopeError);
    const bad = Uint8Array.from(valid);
    bad[3] = KIND.ciphertext;
    expect(() => decode(bad)).toThrow(EnvelopeError);
  });

  it('rejects a body one byte short or one byte long', () => {
    expect(() => encode(0x0001, KIND.publicKey, k.publicKey.subarray(0, 1311))).toThrow(EnvelopeError);
    const over = new Uint8Array(1313);
    over.set(k.publicKey);
    expect(() => encode(0x0001, KIND.publicKey, over)).toThrow(EnvelopeError);
  });

  it('rejects an envelope shorter than the header', () => {
    expect(() => decode(new Uint8Array(3))).toThrow(EnvelopeError);
  });

  it('never dispatches on length alone', () => {
    const slh = slh_dsa_sha2_128s.keygen(new Uint8Array(48).fill(1)).publicKey;
    const asMlKemNothing = REGISTRY.get(0x0004)!.lengths.publicKey;
    expect(asMlKemNothing).toBe(32);
    const env = encode(0x0004, KIND.publicKey, slh);
    expect(decode(env).name).toBe('SLH-DSA-SHA2-128s');
  });

  it('accepts the FN-DSA-512 signature length band and rejects outside it', () => {
    expect(() => encode(0x0005, KIND.signature, new Uint8Array(617))).not.toThrow();
    expect(() => encode(0x0005, KIND.signature, new Uint8Array(666))).not.toThrow();
    expect(() => encode(0x0005, KIND.signature, new Uint8Array(616))).toThrow(EnvelopeError);
    expect(() => encode(0x0005, KIND.signature, new Uint8Array(667))).toThrow(EnvelopeError);
  });
});
