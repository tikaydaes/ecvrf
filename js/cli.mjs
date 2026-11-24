#!/usr/bin/env node
import { derivePublicKey, prove, verify } from './ecvrf.js';

const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');

const [, , cmd, ...args] = process.argv;
if (cmd === 'prove') {
  console.log(toHex(await prove(fromHex(args[0]), fromHex(args[1]))));
} else if (cmd === 'verify') {
  const res = await verify(fromHex(args[0]), fromHex(args[1]), fromHex(args[2]));
  if (!res.valid) process.exit(1);
  console.log(toHex(res.beta));
} else if (cmd === 'derive-pk') {
  console.log(toHex(await derivePublicKey(fromHex(args[0]))));
} else {
  console.error('usage: cli.mjs prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>');
  process.exit(2);
}
