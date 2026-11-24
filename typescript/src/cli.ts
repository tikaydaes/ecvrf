import { derivePublicKey, prove, verify } from './ecvrf.js';

declare const process: {
  argv: string[];
  exit(code?: number): never;
};

const fromHex = (h: string): Uint8Array => {
  if (h.length % 2 !== 0) throw new Error('odd hex length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

async function main(): Promise<void> {
  const [, , cmd, ...args] = process.argv;
  if (cmd === 'prove') {
    console.log(toHex(await prove(fromHex(args[0]), fromHex(args[1]))));
  } else if (cmd === 'verify') {
    const res = await verify(fromHex(args[0]), fromHex(args[1]), fromHex(args[2]));
    if (!res.valid || !res.beta) process.exit(1);
    console.log(toHex(res.beta));
  } else if (cmd === 'derive-pk') {
    console.log(toHex(await derivePublicKey(fromHex(args[0]))));
  } else {
    console.error('usage: cli.js prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>');
    process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
