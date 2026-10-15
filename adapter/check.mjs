import { commitment, fingerprint, kindTag } from './bsc-anchor.ts';
const salt = Uint8Array.from(Buffer.from('000102030405060708090a0b0c0d0e0f','hex'));
const record = new TextEncoder().encode('agent decision 42');
const fp = fingerprint(salt, record);
const signer = '0x00000000000000000000000000000000000000aa';
const c = commitment(fp, signer, kindTag('qstamp'));
console.log('fingerprint', Buffer.from(fp).toString('hex'));
console.log('kind', kindTag('qstamp'));
console.log('commitment', c);
