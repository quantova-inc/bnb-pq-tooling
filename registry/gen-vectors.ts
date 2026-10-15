import { writeFileSync } from 'node:fs';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256, keccak_256 } from '@noble/hashes/sha3.js';
import { encode, KIND } from './envelope.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
const msg = new TextEncoder().encode('bnb post quantum envelope');

const valid: Array<{ scheme: string; kind: string; envelope: string }> = [];
const push = (scheme: string, kind: string, algId: number, k: number, body: Uint8Array) =>
  valid.push({ scheme, kind, envelope: hex(encode(algId, k as 1, body)) });

for (const [id, name, s] of [
  [0x0001, 'ML-DSA-44', ml_dsa44],
  [0x0002, 'ML-DSA-65', ml_dsa65],
  [0x0003, 'ML-DSA-87', ml_dsa87],
] as const) {
  const k = s.keygen(seed);
  push(name, 'publicKey', id, KIND.publicKey, k.publicKey);
  push(name, 'seed', id, KIND.seed, seed);
  push(name, 'signature', id, KIND.signature, s.sign(msg, k.secretKey, { extraEntropy: false }));
}

const slh = slh_dsa_sha2_128s.keygen(new Uint8Array(48).fill(1));
push('SLH-DSA-SHA2-128s', 'publicKey', 0x0004, KIND.publicKey, slh.publicKey);

const kem = ml_kem768.keygen(new Uint8Array(64).fill(2));
push('ML-KEM-768', 'publicKey', 0x0101, KIND.publicKey, kem.publicKey);
push('ML-KEM-768', 'ciphertext', 0x0101, KIND.ciphertext, ml_kem768.encapsulate(kem.publicKey, new Uint8Array(32).fill(3)).cipherText);

push('SHA3-256', 'commitment', 0x0201, KIND.commitment, sha3_256(msg));
push('KECCAK-256', 'commitment', 0x0202, KIND.commitment, keccak_256(msg));

const reject = [
  { reason: 'unsupported version', envelope: '02' + '0001' + '01' + '00'.repeat(1312) },
  { reason: 'unknown identifier', envelope: '01' + '7ffe' + '01' + '00'.repeat(32) },
  { reason: 'reserved identifier 0x0000', envelope: '01' + '0000' + '01' + '00'.repeat(32) },
  { reason: 'kind not valid for class', envelope: '01' + '0201' + '02' + '00'.repeat(32) },
  { reason: 'body one byte short', envelope: '01' + '0001' + '01' + '00'.repeat(1311) },
  { reason: 'body one byte long', envelope: '01' + '0001' + '01' + '00'.repeat(1313) },
  { reason: 'header truncated', envelope: '010001' },
];

writeFileSync('vectors.json', JSON.stringify({ version: 1, valid, reject }, null, 2) + '\n');
console.log('valid', valid.length, 'reject', reject.length);
