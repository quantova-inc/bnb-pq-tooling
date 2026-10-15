import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

export const ANCHOR_ABI = [
  'event Anchored(address indexed signer, bytes32 indexed kind, bytes32 commitment, uint64 batchSize, uint256 timestamp)',
  'function anchor(bytes32 commitment, bytes32 kind, uint64 batchSize) external',
  'function anchored(bytes32 commitment) external view returns (uint256 timestamp)',
] as const;

const WORD = 32;

function hex(bytes: Uint8Array): string {
  return '0x' + Buffer.from(bytes).toString('hex');
}

function toWord(input: Uint8Array | string): Uint8Array {
  const bytes = typeof input === 'string' ? Buffer.from(input.replace(/^0x/, ''), 'hex') : input;
  if (bytes.length > WORD) {
    throw new Error('value exceeds 32 bytes');
  }
  const word = new Uint8Array(WORD);
  word.set(bytes, WORD - bytes.length);
  return word;
}

function addressWord(address: string): Uint8Array {
  const bytes = Buffer.from(address.replace(/^0x/, ''), 'hex');
  if (bytes.length !== 20) {
    throw new Error('address must be 20 bytes');
  }
  return toWord(bytes);
}

export function fingerprint(salt: Uint8Array, record: Uint8Array): Uint8Array {
  if (salt.length !== 16) {
    throw new Error('salt must be 16 bytes');
  }
  const input = new Uint8Array(salt.length + record.length);
  input.set(salt);
  input.set(record, salt.length);
  return sha3_256(input);
}

export function commitment(
  fingerprintBytes: Uint8Array,
  signer: string,
  kind: Uint8Array | string,
): string {
  if (fingerprintBytes.length !== WORD) {
    throw new Error('fingerprint must be 32 bytes');
  }
  const encoded = new Uint8Array(3 * WORD);
  encoded.set(toWord(fingerprintBytes), 0);
  encoded.set(addressWord(signer), WORD);
  encoded.set(toWord(kind), 2 * WORD);
  return hex(keccak_256(encoded));
}

export function kindTag(label: string): string {
  const bytes = new TextEncoder().encode(label);
  if (bytes.length > WORD) {
    throw new Error('kind label exceeds 32 bytes');
  }
  return hex(toWord(bytes));
}
