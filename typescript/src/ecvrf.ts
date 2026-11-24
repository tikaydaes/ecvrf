/**
 * RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03) in zero-dependency
 * TypeScript (BigInt + Web Crypto SHA-512). Works in browsers and Node >= 20.
 *
 * Note: BigInt arithmetic is not constant-time. Verification and proofToHash
 * operate on public inputs only; use a constant-time implementation (Go, Rust,
 * Zig) for production secret-key proving.
 */

export const SUITE_BYTE = 0x03;
export const SECRET_KEY_LENGTH = 32;
export const PUBLIC_KEY_LENGTH = 32;
export const PROOF_LENGTH = 80;
export const BETA_LENGTH = 64;
const CHALLENGE_LENGTH = 16;

export interface VerifyResult {
  valid: boolean;
  beta: Uint8Array | null;
}

type ExtPoint = readonly [bigint, bigint, bigint, bigint];

// Edwards25519 parameters
const P = (1n << 255n) - 19n;
const Q = (1n << 252n) + 27742317777372353535851937790883648493n;

const mod = (a: bigint, m: bigint = P): bigint => {
  const r = a % m;
  return r < 0n ? r + m : r;
};

function pow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

const inv = (a: bigint): bigint => pow(a, P - 2n, P);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) >> 2n, P);

function xRecover(y: bigint): bigint | null {
  const yy = (y * y) % P;
  const xx = mod((yy - 1n) * inv(mod(D * yy + 1n)));
  let x = pow(xx, (P + 3n) >> 3n, P);
  if (mod(x * x - xx) !== 0n) x = (x * SQRT_M1) % P;
  if (mod(x * x - xx) !== 0n) return null;
  if ((x & 1n) !== 0n) x = P - x;
  return x;
}

const BY = mod(4n * inv(5n));
const BX = xRecover(BY)!;
const B: ExtPoint = [BX, BY, 1n, (BX * BY) % P];
const ID: ExtPoint = [0n, 1n, 1n, 0n];

function add(p1: ExtPoint, p2: ExtPoint): ExtPoint {
  const [x1, y1, z1, t1] = p1;
  const [x2, y2, z2, t2] = p2;
  const a = mod((y1 - x1) * (y2 - x2));
  const b = mod((y1 + x1) * (y2 + x2));
  const c = mod(((2n * t1 * t2) % P) * D);
  const d = mod(2n * z1 * z2);
  const e = mod(b - a);
  const f = mod(d - c);
  const g = mod(d + c);
  const h = mod(b + a);
  return [(e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P];
}

function mulRaw(pt: ExtPoint, k: bigint): ExtPoint {
  let acc = ID;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) acc = add(acc, addend);
    addend = add(addend, addend);
    k >>= 1n;
  }
  return acc;
}

function mul(pt: ExtPoint, k: bigint): ExtPoint {
  return mulRaw(pt, mod(k, Q));
}

function isIdentity([x, y, z]: ExtPoint): boolean {
  return mod(x) === 0n && mod(y - z) === 0n;
}

function fromLE(bytes: Uint8Array): bigint {
  let r = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    r = (r << 8n) | BigInt(bytes[i]);
  }
  return r;
}

function toLE(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

async function sha512(bytes: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-512', copy));
}

function encodePoint([x, y, z]: ExtPoint): Uint8Array {
  const zi = inv(z);
  const ax = (x * zi) % P;
  const ay = (y * zi) % P;
  const out = toLE(ay, 32);
  out[31] |= Number(ax & 1n) << 7;
  return out;
}

function decodePoint(b: Uint8Array): ExtPoint | null {
  if (!(b instanceof Uint8Array) || b.length !== 32) return null;
  const sign = (b[31] >> 7) & 1;
  const yBytes = new Uint8Array(b);
  yBytes[31] &= 0x7f;
  const y = fromLE(yBytes);
  if (y >= P) return null;
  let x = xRecover(y);
  if (x === null) return null;
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return [x, y, 1n, (x * y) % P];
}

function validateKey(pk: Uint8Array): ExtPoint | null {
  const y = decodePoint(pk);
  if (!y) return null;
  if (isIdentity(mulRaw(y, 8n))) return null;
  return y;
}

/** Reports whether b is a valid non-small-order 32-byte Ed25519 public key. */
export function isPublicKey(b: Uint8Array): boolean {
  return validateKey(b) !== null;
}

async function expandSecretKey(sk: Uint8Array): Promise<{ x: bigint; prefix: Uint8Array }> {
  if (!(sk instanceof Uint8Array) || sk.length !== SECRET_KEY_LENGTH) {
    throw new Error(`ecvrf: secret key must be ${SECRET_KEY_LENGTH} bytes`);
  }
  const h = await sha512(sk);
  const xb = new Uint8Array(h.subarray(0, 32));
  xb[0] &= 248;
  xb[31] &= 127;
  xb[31] |= 64;
  return { x: fromLE(xb), prefix: h.subarray(32) };
}

async function encodeToCurve(pk: Uint8Array, alpha: Uint8Array): Promise<ExtPoint | null> {
  const prefix = concat(new Uint8Array([SUITE_BYTE, 0x01]), pk, alpha);
  for (let ctr = 0; ctr < 256; ctr++) {
    const hash = await sha512(concat(prefix, new Uint8Array([ctr, 0x00])));
    const pt = decodePoint(hash.subarray(0, 32));
    if (pt) return mulRaw(pt, 8n);
  }
  return null;
}

async function challenge(...points: ExtPoint[]): Promise<{ c: bigint; cBytes: Uint8Array }> {
  const hash = await sha512(
    concat(new Uint8Array([SUITE_BYTE, 0x02]), ...points.map(encodePoint), new Uint8Array([0x00])),
  );
  const cBytes = hash.subarray(0, CHALLENGE_LENGTH);
  return { c: fromLE(cBytes), cBytes };
}

async function gammaToHash(gamma: ExtPoint): Promise<Uint8Array> {
  return sha512(
    concat(new Uint8Array([SUITE_BYTE, 0x03]), encodePoint(mulRaw(gamma, 8n)), new Uint8Array([0x00])),
  );
}

function decodeProof(pi: Uint8Array): { gamma: ExtPoint; c: bigint; s: bigint } | null {
  if (!(pi instanceof Uint8Array) || pi.length !== PROOF_LENGTH) return null;
  const gamma = decodePoint(pi.subarray(0, 32));
  if (!gamma) return null;
  const c = fromLE(pi.subarray(32, 48));
  const s = fromLE(pi.subarray(48, 80));
  if (s >= Q) return null;
  return { gamma, c, s };
}

/** Derives the 32-byte Ed25519 public key from a 32-byte seed sk. */
export async function derivePublicKey(sk: Uint8Array): Promise<Uint8Array> {
  const { x } = await expandSecretKey(sk);
  return encodePoint(mulRaw(B, x));
}

/** RFC 9381 Section 5.1: generates an 80-byte proof Gamma(32) || c(16) || s(32). */
export async function prove(sk: Uint8Array, alpha: Uint8Array): Promise<Uint8Array> {
  if (!(alpha instanceof Uint8Array)) throw new Error('ecvrf: alpha must be Uint8Array');
  const { x, prefix } = await expandSecretKey(sk);
  const y = mulRaw(B, x);
  const pk = encodePoint(y);
  const h = await encodeToCurve(pk, alpha);
  if (!h) throw new Error('ecvrf: encode_to_curve failed');
  const gamma = mulRaw(h, x);
  const kHash = await sha512(concat(prefix, encodePoint(h)));
  const k = mod(fromLE(kHash), Q);
  const u = mul(B, k);
  const v = mul(h, k);
  const { c, cBytes } = await challenge(y, h, gamma, u, v);
  const s = mod(k + c * x, Q);
  return concat(encodePoint(gamma), cBytes, toLE(s, 32));
}

/** RFC 9381 Section 5.2: 64-byte VRF output beta without verifying the proof. */
export async function proofToHash(pi: Uint8Array): Promise<Uint8Array> {
  const d = decodeProof(pi);
  if (!d) throw new Error('ecvrf: not a proof');
  return gammaToHash(d.gamma);
}

/** RFC 9381 Section 5.3: verifies pi for pk and alpha; never throws. */
export async function verify(pk: Uint8Array, pi: Uint8Array, alpha: Uint8Array): Promise<VerifyResult> {
  const invalid: VerifyResult = { valid: false, beta: null };
  if (!(alpha instanceof Uint8Array)) return invalid;
  const y = validateKey(pk);
  const d = decodeProof(pi);
  if (!y || !d) return invalid;
  const h = await encodeToCurve(pk, alpha);
  if (!h) return invalid;
  const negC = mod(Q - d.c, Q);
  const u = add(mul(B, d.s), mul(y, negC));
  const v = add(mul(h, d.s), mul(d.gamma, negC));
  const { c: cPrime } = await challenge(y, h, d.gamma, u, v);
  if (cPrime !== d.c) return invalid;
  return { valid: true, beta: await gammaToHash(d.gamma) };
}
