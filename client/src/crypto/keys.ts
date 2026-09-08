/**
 * ============================================================================
 *  VEIL — CRYPTOGRAPHIC CORE (@noble implementation)
 * ============================================================================
 *  Identity is a keypair, nothing else. No phone number, no email, no
 *  server-side directory, no account recovery. Losing the master seed is
 *  losing the identity — that is the product, not a bug.
 *
 *  Primitives (all pure TypeScript / @noble):
 *    Ed25519  @noble/curves/ed25519  — invitations, inbox authorization tokens
 *    X25519   @noble/curves/ed25519  — ECDH for the ratchet (x25519 export)
 *    BLAKE2b  @noble/hashes/blake2   — domain-separated KDF, fingerprints,
 *                                      blinded inbox IDs
 *    XChaCha20-Poly1305 @noble/ciphers/chacha — payload AEAD (24-byte nonce)
 *    Argon2id @noble/hashes/argon2   — PIN -> vault key stretching
 *
 *  NOTE ON SUBPATH IMPORTS:
 *  @noble/hashes v2 exports map specifies './blake2.js' (containing blake2b)
 *  and './argon2.js' (containing argon2id), while @noble/curves and
 *  @noble/ciphers export './ed25519.js' and './chacha.js'.
 * ============================================================================
 */

// @noble v2 exports map requires explicit '.js' subpaths (e.g. './ed25519.js', './blake2.js', './argon2.js', './chacha.js')
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { argon2id } from '@noble/hashes/argon2.js';

/**
 * Kept for interface compatibility with App.tsx and callers.
 * Pure TypeScript @noble libraries are synchronous and require no WASM readiness.
 */
export async function initCrypto(): Promise<void> {
  return Promise.resolve();
}

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

export const CRYPTO = {
  SEED_BYTES: 32,
  SUBKEY_BYTES: 32,
  AEAD_KEY_BYTES: 32,
  /** XChaCha20-Poly1305 nonce. */
  NONCE_BYTES: 24,
  TAG_BYTES: 16,
  FINGERPRINT_BYTES: 20,
  VAULT_KEY_BYTES: 32,
  VAULT_SALT_BYTES: 16,
  RENDEZVOUS_BYTES: 16,
} as const;

/**
 * Domain-separation labels. Every KDF invocation in Veil passes through
 * `deriveSubSeed`, and every call site must own a distinct label here. Reusing
 * a label across purposes is the single most likely way to break this design.
 */
const LBL = {
  identity: 'ed25519.identity',
  exchange: 'x25519.exchange',
  fingerprint: 'veil.fingerprint.v1',
  vaultSalt: 'veil.vault.salt.v1',
  inbox: 'veil.inbox.blind.v1',
  chainStep: 'veil.ratchet.chain.v1',
  msgKey: 'veil.ratchet.msgkey.v1',
  watermark: 'veil.watermark.v1',
  inviteSig: 'veil.invite.sig.v1',
} as const;

/** Hierarchical mask path. Every persona is a pure function of (seed, index). */
export const maskPath = (index: number): string => `m/veil/mask/${index}`;

/** Reserved persona indices. Index 1 is the Ghost/decoy persona. */
export const MASK_INDEX = { PERSONAL: 0, GHOST: 1 } as const;

/* -------------------------------------------------------------------------- */
/* Byte utilities (Pure TypeScript — no Buffer / atob / btoa)                  */
/* -------------------------------------------------------------------------- */

/** CSPRNG using standard crypto.getRandomValues (polyfilled in index.js). */
export const randomBytes = (n: number): Uint8Array => {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
};

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_LOOKUP = new Uint8Array(256);
for (let i = 0; i < B64_CHARS.length; i++) {
  B64_LOOKUP[B64_CHARS.charCodeAt(i)] = i;
}
// Robustness: also accept standard '+' and '/'
B64_LOOKUP['+'.charCodeAt(0)] = 62;
B64_LOOKUP['/'.charCodeAt(0)] = 63;

/** Hand-rolled Base64URL encoding without padding over Uint8Array. */
export function toB64(bytes: Uint8Array): string {
  let out = '';
  const len = bytes.length;
  let i = 0;
  for (; i + 2 < len; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64_CHARS[b0 >> 2];
    out += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    out += B64_CHARS[((b1 & 15) << 2) | (b2 >> 6)];
    out += B64_CHARS[b2 & 63];
  }
  if (i < len) {
    const b0 = bytes[i];
    out += B64_CHARS[b0 >> 2];
    if (i + 1 < len) {
      const b1 = bytes[i + 1];
      out += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
      out += B64_CHARS[(b1 & 15) << 2];
    } else {
      out += B64_CHARS[(b0 & 3) << 4];
    }
  }
  return out;
}

/** Hand-rolled Base64URL decoding without padding over Uint8Array. */
export function fromB64(s: string): Uint8Array {
  let str = s;
  while (str.endsWith('=')) {
    str = str.slice(0, -1);
  }
  const len = str.length;
  if (len === 0) return new Uint8Array(0);

  const mod = len % 4;
  if (mod === 1) {
    throw new Error('[veil/crypto] invalid base64 string length');
  }

  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);

  let inIdx = 0;
  let outIdx = 0;

  while (inIdx < len) {
    const c0 = str.charCodeAt(inIdx++);
    const c1 = inIdx < len ? str.charCodeAt(inIdx++) : 65; // 'A' -> 0
    const c2 = inIdx < len ? str.charCodeAt(inIdx++) : 65;
    const c3 = inIdx < len ? str.charCodeAt(inIdx++) : 65;

    const v0 = B64_LOOKUP[c0];
    const v1 = B64_LOOKUP[c1];
    const v2 = B64_LOOKUP[c2];
    const v3 = B64_LOOKUP[c3];

    const triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

    if (outIdx < outLen) out[outIdx++] = (triple >> 16) & 255;
    if (outIdx < outLen) out[outIdx++] = (triple >> 8) & 255;
    if (outIdx < outLen) out[outIdx++] = triple & 255;
  }

  return out;
}

const HEX_CHARS = '0123456789abcdef';

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_CHARS[b >> 4] + HEX_CHARS[b & 15];
  }
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('[veil/crypto] hex string must have even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const val = parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(val)) {
      throw new Error('[veil/crypto] invalid hex character');
    }
    out[i / 2] = val;
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const utf8 = (s: string): Uint8Array => encoder.encode(s);
const fromUtf8 = (b: Uint8Array): string => decoder.decode(b);

/** Constant-time equality. Never use `===` on secrets or MACs. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Best-effort zeroization. In a managed runtime this is advisory only — the GC
 * may have already copied the buffer. It still meaningfully shortens the window
 * in which a heap dump yields plaintext keys.
 */
export function wipe(...buffers: (Uint8Array | undefined | null)[]): void {
  for (const b of buffers) {
    if (b && b.length) b.fill(0);
  }
}

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

/* -------------------------------------------------------------------------- */
/* KDF                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Keyed BLAKE2b as a KDF: subkey = BLAKE2b(msg = label, key = parentSeed).
 * Full-length unique label gives unlimited, self-documenting domain separation.
 */
export function deriveSubSeed(
  parentSeed: Uint8Array,
  label: string,
  outLen: number = CRYPTO.SUBKEY_BYTES,
): Uint8Array {
  if (parentSeed.length < 16) throw new Error('[veil/crypto] parent seed too short.');
  return blake2b(utf8(label), { dkLen: outLen, key: parentSeed });
}

/** 256-bit master seed. This is the entire backup surface of an identity. */
export const generateMasterSeed = (): Uint8Array => randomBytes(CRYPTO.SEED_BYTES);

/* -------------------------------------------------------------------------- */
/* Personas ("masks")                                                         */
/* -------------------------------------------------------------------------- */

export interface MaskIdentity {
  index: number;
  path: string;
  /** Ed25519 — signs invites and inbox authorization tokens. */
  signPk: Uint8Array;
  signSk: Uint8Array;
  /** X25519 — ECDH input to the ratchet. */
  dhPk: Uint8Array;
  dhSk: Uint8Array;
  /** Human-verifiable safety number, Crockford base32, space-grouped. */
  fingerprint: string;
}

/**
 * Deterministically derives a persona from the master seed. Two devices holding
 * the same seed derive byte-identical masks with no synchronization, which is
 * how multi-device works without a server-side directory.
 */
export function deriveMask(masterSeed: Uint8Array, index: number): MaskIdentity {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error('[veil/crypto] mask index must be a non-negative integer.');
  }
  const path = maskPath(index);

  const branch = deriveSubSeed(masterSeed, path);
  const edSeed = deriveSubSeed(branch, LBL.identity);
  const xSeed = deriveSubSeed(branch, LBL.exchange);

  const sign = ed25519.keygen(edSeed);
  const dh = x25519.keygen(xSeed);

  const signSk = new Uint8Array(sign.secretKey);
  const dhSk = new Uint8Array(dh.secretKey);

  wipe(branch, edSeed, xSeed);

  return {
    index,
    path,
    signPk: sign.publicKey,
    signSk,
    dhPk: dh.publicKey,
    dhSk,
    fingerprint: computeFingerprint(sign.publicKey, dh.publicKey),
  };
}

/** Frees a mask's secret material. Call on lock, background, or persona switch. */
export function destroyMask(mask: MaskIdentity): void {
  wipe(mask.signSk, mask.dhSk);
}

/* -------------------------------------------------------------------------- */
/* Fingerprints                                                               */
/* -------------------------------------------------------------------------- */

/** Crockford base32 — no I/L/O/U, so it survives being read aloud over a call. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function crockford(bytes: Uint8Array): string {
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(acc << (5 - bits)) & 31];
  return out;
}

/**
 * Binds BOTH public keys into one 160-bit fingerprint. Fingerprinting only the
 * Ed25519 key would let an attacker swap the X25519 key while the safety number
 * a user reads out loud stays unchanged.
 */
export function computeFingerprint(signPk: Uint8Array, dhPk: Uint8Array): string {
  const digest = blake2b(concat(signPk, dhPk), {
    dkLen: CRYPTO.FINGERPRINT_BYTES,
    key: utf8(LBL.fingerprint).slice(0, 32),
  });
  return (crockford(digest).match(/.{1,4}/g) ?? []).join(' ');
}

/* -------------------------------------------------------------------------- */
/* AEAD — XChaCha20-Poly1305                                                  */
/* -------------------------------------------------------------------------- */

export interface SealedPayload {
  /** 24 random bytes. */
  nonce: Uint8Array;
  /** ciphertext || 16-byte Poly1305 tag. */
  ciphertext: Uint8Array;
}

/**
 * Encrypts with a fresh random 24-byte nonce.
 * Wire format: nonce(24) || ciphertext || tag(16).
 */
export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): SealedPayload {
  if (key.length !== CRYPTO.AEAD_KEY_BYTES) {
    throw new Error('[veil/crypto] AEAD key must be 32 bytes.');
  }
  const nonce = randomBytes(CRYPTO.NONCE_BYTES);
  const cipher = xchacha20poly1305(key, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);
  return { nonce, ciphertext };
}

/** Returns null on any authentication failure. Never throws on bad input. */
export function aeadDecrypt(
  key: Uint8Array,
  sealed: SealedPayload,
  aad?: Uint8Array,
): Uint8Array | null {
  if (key.length !== CRYPTO.AEAD_KEY_BYTES) return null;
  if (sealed.nonce.length !== CRYPTO.NONCE_BYTES) return null;
  if (sealed.ciphertext.length < CRYPTO.TAG_BYTES) return null;
  try {
    const cipher = xchacha20poly1305(key, sealed.nonce, aad);
    return cipher.decrypt(sealed.ciphertext);
  } catch {
    // Forged tag, wrong key, or truncated frame returns null
    return null;
  }
}

export const encryptString = (key: Uint8Array, text: string, aad?: Uint8Array): SealedPayload =>
  aeadEncrypt(key, utf8(text), aad);

export function decryptString(
  key: Uint8Array,
  sealed: SealedPayload,
  aad?: Uint8Array,
): string | null {
  const pt = aeadDecrypt(key, sealed, aad);
  if (!pt) return null;
  const text = fromUtf8(pt);
  wipe(pt);
  return text;
}

/** Compact wire form: b64u(nonce) ++ '.' ++ b64u(ct||tag). */
export const packSealed = (s: SealedPayload): string => `${toB64(s.nonce)}.${toB64(s.ciphertext)}`;

export function unpackSealed(packed: string): SealedPayload | null {
  const dot = packed.indexOf('.');
  if (dot <= 0) return null;
  try {
    return {
      nonce: fromB64(packed.slice(0, dot)),
      ciphertext: fromB64(packed.slice(dot + 1)),
    };
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Ratchet helpers                                                            */
/* -------------------------------------------------------------------------- */

/**
 * One symmetric-chain step. Returns the next chain key and the one-shot message
 * key. The caller must persist only the *next* chain key and immediately wipe
 * the message key after use — that is what gives forward secrecy.
 */
export function advanceChain(chainKey: Uint8Array): {
  nextChainKey: Uint8Array;
  messageKey: Uint8Array;
} {
  return {
    nextChainKey: deriveSubSeed(chainKey, LBL.chainStep),
    messageKey: deriveSubSeed(chainKey, LBL.msgKey, CRYPTO.AEAD_KEY_BYTES),
  };
}

/**
 * DH ratchet step: X25519 ECDH, mixed into the current root key. The raw
 * scalarmult output is never used as a key directly — it is always run through
 * the KDF together with the previous root.
 */
export function dhRatchet(
  rootKey: Uint8Array,
  ourDhSk: Uint8Array,
  theirDhPk: Uint8Array,
): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const shared = x25519.getSharedSecret(ourDhSk, theirDhPk);
  const mixed = blake2b(concat(rootKey, shared), {
    dkLen: 64,
    key: utf8(LBL.exchange).slice(0, 32),
  });
  wipe(shared);
  const next = { rootKey: mixed.slice(0, 32), chainKey: mixed.slice(32, 64) };
  wipe(mixed);
  return next;
}

/* -------------------------------------------------------------------------- */
/* Blinded inbox addressing                                                   */
/* -------------------------------------------------------------------------- */

export const epochHour = (nowMs: number = Date.now()): number => Math.floor(nowMs / 3_600_000);

/**
 * blinded_inbox_id = BLAKE2b(msg = "label|epochHour", key = receivingRatchetPk)
 *
 * The relay only ever sees this rotating opaque string.
 */
export function blindedInboxId(
  receivingRatchetPk: Uint8Array,
  hour: number = epochHour(),
): string {
  return toB64(
    blake2b(utf8(`${LBL.inbox}|${hour}`), {
      dkLen: 32,
      key: receivingRatchetPk,
    }),
  );
}

/**
 * The set of addresses to subscribe to. We include the neighbouring hours to
 * absorb clock skew and messages sent right at a boundary.
 */
export const inboxWindow = (receivingRatchetPk: Uint8Array, now = Date.now()): string[] => {
  const h = epochHour(now);
  return [h - 1, h, h + 1].map((e) => blindedInboxId(receivingRatchetPk, e));
};

/**
 * Inbox authorization token. Proves to the relay that the subscriber controls
 * the mask that owns this inbox, without naming an account. Bound to a
 * server-issued nonce so it cannot be replayed onto another connection.
 */
export function signInboxAuth(
  mask: MaskIdentity,
  inboxId: string,
  serverNonce: Uint8Array,
): { signPk: string; signature: string } {
  const msg = concat(utf8(`veil.inbox.auth.v1|${inboxId}|`), serverNonce);
  return {
    signPk: toB64(mask.signPk),
    signature: toB64(ed25519.sign(msg, mask.signSk)),
  };
}

/* -------------------------------------------------------------------------- */
/* Invitations — veil://invite?...                                            */
/* -------------------------------------------------------------------------- */

export interface VeilInvite {
  v: 1;
  /** Ed25519 identity public key. */
  ik: Uint8Array;
  /** X25519 exchange public key (initial ratchet root contribution). */
  xk: Uint8Array;
  /** One-time rendezvous token — the first-contact mailbox seed. */
  rz: Uint8Array;
  /** Absolute expiry, unix seconds. Short-lived by default. */
  exp: number;
  /** Optional free-text nickname. Never a real name by default. */
  nick?: string;
}

export interface ParsedInvite extends VeilInvite {
  fingerprint: string;
  /** First-contact inbox derived from the rendezvous token. */
  rendezvousInbox: string;
}

/**
 * Canonical signing preimage. Sorted, fixed-order, explicitly delimited.
 */
function inviteCanonical(i: VeilInvite): Uint8Array {
  const canonical = [
    `v=${i.v}`,
    `ik=${toB64(i.ik)}`,
    `xk=${toB64(i.xk)}`,
    `rz=${toB64(i.rz)}`,
    `exp=${i.exp}`,
    `nick=${i.nick ?? ''}`,
  ].join('&');
  return concat(utf8(`${LBL.inviteSig}|`), utf8(canonical));
}

/** Builds a signed, expiring, single-use invitation URI. */
export function createInvite(
  mask: MaskIdentity,
  opts: { ttlSeconds?: number; nick?: string } = {},
): { uri: string; rendezvous: Uint8Array; expiresAt: number } {
  const ttl = opts.ttlSeconds ?? 3600; // one hour
  const invite: VeilInvite = {
    v: 1,
    ik: mask.signPk,
    xk: mask.dhPk,
    rz: randomBytes(CRYPTO.RENDEZVOUS_BYTES),
    exp: Math.floor(Date.now() / 1000) + ttl,
    nick: opts.nick,
  };

  const sig = ed25519.sign(inviteCanonical(invite), mask.signSk);

  const q = new URLSearchParams({
    v: String(invite.v),
    ik: toB64(invite.ik),
    xk: toB64(invite.xk),
    rz: toB64(invite.rz),
    exp: String(invite.exp),
    sig: toB64(sig),
  });
  if (invite.nick) q.set('nick', invite.nick);

  return {
    uri: `veil://invite?${q.toString()}`,
    rendezvous: invite.rz,
    expiresAt: invite.exp * 1000,
  };
}

/**
 * Parses and fully verifies an invitation. Returns null for anything
 * malformed, unsigned, mis-signed, or expired.
 */
export function parseInvite(uri: string): ParsedInvite | null {
  try {
    if (!uri.startsWith('veil://invite?')) return null;
    const q = new URLSearchParams(uri.slice('veil://invite?'.length));

    const version = Number(q.get('v'));
    const sigRaw = q.get('sig');
    if (version !== 1 || !sigRaw) return null;

    const invite: VeilInvite = {
      v: 1,
      ik: fromB64(q.get('ik') ?? ''),
      xk: fromB64(q.get('xk') ?? ''),
      rz: fromB64(q.get('rz') ?? ''),
      exp: Number(q.get('exp')),
      nick: q.get('nick') ?? undefined,
    };

    if (invite.ik.length !== 32 || invite.xk.length !== 32) return null;
    if (invite.rz.length !== CRYPTO.RENDEZVOUS_BYTES) return null;
    if (!Number.isFinite(invite.exp)) return null;

    const ok = ed25519.verify(fromB64(sigRaw), inviteCanonical(invite), invite.ik);
    if (!ok) return null;
    if (invite.exp * 1000 < Date.now()) return null;

    return {
      ...invite,
      fingerprint: computeFingerprint(invite.ik, invite.xk),
      rendezvousInbox: blindedInboxId(
        blake2b(invite.rz, {
          dkLen: 32,
          key: utf8(LBL.inbox).slice(0, 32),
        }),
      ),
    };
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Vault key stretching (consumed by src/storage/db.ts)                       */
/* -------------------------------------------------------------------------- */

/**
 * Argon2id cost parameters for deriveVaultKey.
 * NOTE: The measured performance cost under Hermes is unverified until profiled on-device.
 */
export const VAULT_KDF_ITERATIONS = 3;
export const VAULT_KDF_MEMORY_KIB = 64 * 1024; // 64 MiB
export const VAULT_KDF_PARALLELISM = 1;
export const VAULT_KDF_DKLEN = 32;

/**
 * PIN -> 256-bit SQLCipher raw key via Argon2id.
 *
 * `partitionLabel` differs per partition ('primary' | 'decoy') so the same PIN
 * cannot possibly derive both keys.
 */
export function deriveVaultKey(
  pin: string,
  deviceSalt: Uint8Array,
  partitionLabel: string,
): Uint8Array {
  if (deviceSalt.length !== CRYPTO.VAULT_SALT_BYTES) {
    throw new Error('[veil/crypto] device salt must be 16 bytes.');
  }
  const salt = blake2b(utf8(`${LBL.vaultSalt}|${partitionLabel}`), {
    dkLen: CRYPTO.VAULT_SALT_BYTES,
    key: deviceSalt,
  });
  return argon2id(pin, salt, {
    t: VAULT_KDF_ITERATIONS,
    m: VAULT_KDF_MEMORY_KIB,
    p: VAULT_KDF_PARALLELISM,
    dkLen: VAULT_KDF_DKLEN,
    maxmem: VAULT_KDF_MEMORY_KIB * 1024,
  });
}

/* -------------------------------------------------------------------------- */
/* Forensic watermark tag                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Derives the per-minute watermark payload. Deterministic given the same
 * inputs, so a recovered screenshot can be replayed against the audit set to
 * identify which device/session/minute produced the capture.
 */
export function watermarkTag(input: {
  deviceFingerprint: string;
  sessionId: string;
  recipientFingerprint: string;
  minuteUtc: number;
}): Uint8Array {
  const msg = utf8(
    [
      LBL.watermark,
      input.deviceFingerprint,
      input.sessionId,
      input.recipientFingerprint,
      String(input.minuteUtc),
    ].join('|'),
  );
  return blake2b(msg, { dkLen: 32 });
}

export default {
  initCrypto,
  generateMasterSeed,
  deriveMask,
  destroyMask,
  deriveSubSeed,
  computeFingerprint,
  aeadEncrypt,
  aeadDecrypt,
  encryptString,
  decryptString,
  packSealed,
  unpackSealed,
  advanceChain,
  dhRatchet,
  blindedInboxId,
  inboxWindow,
  signInboxAuth,
  createInvite,
  parseInvite,
  deriveVaultKey,
  watermarkTag,
  randomBytes,
  wipe,
  timingSafeEqual,
  toB64,
  fromB64,
  toHex,
  fromHex,
  VAULT_KDF_ITERATIONS,
  VAULT_KDF_MEMORY_KIB,
  VAULT_KDF_PARALLELISM,
  VAULT_KDF_DKLEN,
};
