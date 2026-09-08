/**
 * ============================================================================
 *  VEIL — CRYPTOGRAPHIC CORE
 * ============================================================================
 *  Identity is a keypair, nothing else. No phone number, no email, no
 *  server-side directory, no account recovery. Losing the master seed is
 *  losing the identity — that is the product, not a bug.
 *
 *  Primitives (all libsodium):
 *    Ed25519  crypto_sign          — invitations, inbox authorization tokens
 *    X25519   crypto_kx / scalarmult — ECDH for the ratchet
 *    BLAKE2b  crypto_generichash   — domain-separated KDF, fingerprints,
 *                                    blinded inbox IDs
 *    XChaCha20-Poly1305            — payload AEAD (24-byte random nonce)
 *    Argon2id crypto_pwhash        — PIN -> vault key stretching
 *
 *  NOTE ON THE CIPHER: a 24-byte nonce is XChaCha20-Poly1305, not the IETF
 *  ChaCha20-Poly1305 construction (which takes 12 bytes). We deliberately use
 *  XChaCha so that nonces can be sampled at random forever without birthday
 *  risk — with 12 bytes, random nonces become unsafe around 2^32 messages
 *  per key, which a long-lived ratchet chain can plausibly approach.
 *
 *  RUNTIME: `libsodium-wrappers` runs as WASM/asm.js and needs a working
 *  `crypto.getRandomValues`. On React Native install `react-native-get-random-values`
 *  as the first import of your entrypoint, or swap this module's `sodium`
 *  binding for `react-native-libsodium` (API-compatible for everything used
 *  here) to get native performance and to keep key material out of the JS heap.
 * ============================================================================
 */

import _sodium from 'libsodium-wrappers';

type Sodium = typeof _sodium;
let sodium: Sodium;

/** Must be awaited exactly once, before any other export is touched. */
export async function initCrypto(): Promise<void> {
  if (sodium) return;
  await _sodium.ready;
  sodium = _sodium;
}

function requireReady(): Sodium {
  if (!sodium) {
    throw new Error('[veil/crypto] initCrypto() must be awaited before use.');
  }
  return sodium;
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
/* Byte utilities                                                             */
/* -------------------------------------------------------------------------- */

export const randomBytes = (n: number): Uint8Array => requireReady().randombytes_buf(n);

export const toB64 = (b: Uint8Array): string =>
  requireReady().to_base64(b, _sodium.base64_variants.URLSAFE_NO_PADDING);

export const fromB64 = (s: string): Uint8Array =>
  requireReady().from_base64(s, _sodium.base64_variants.URLSAFE_NO_PADDING);

export const toHex = (b: Uint8Array): string => requireReady().to_hex(b);
export const fromHex = (s: string): Uint8Array => requireReady().from_hex(s);
const utf8 = (s: string): Uint8Array => requireReady().from_string(s);
const fromUtf8 = (b: Uint8Array): string => requireReady().to_string(b);

/** Constant-time equality. Never use `===` on secrets or MACs. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const s = requireReady();
  if (a.length !== b.length) return false;
  try {
    return s.memcmp(a, b);
  } catch {
    return false;
  }
}

/**
 * Best-effort zeroization. In a managed runtime this is advisory only — the GC
 * may have already copied the buffer. It still meaningfully shortens the window
 * in which a heap dump yields plaintext keys.
 */
export function wipe(...buffers: (Uint8Array | undefined | null)[]): void {
  for (const b of buffers) {
    if (b && b.length) requireReady().memzero(b);
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
 *
 * Chosen over `crypto_kdf_derive_from_key` because that API restricts the
 * context to 8 bytes and the subkey selector to a u64, which cannot express
 * readable hierarchical paths like `m/veil/mask/3/x25519.exchange`. Keyed
 * BLAKE2b with a full-length unique label is an accepted KDF construction and
 * gives us unlimited, self-documenting domain separation.
 */
export function deriveSubSeed(
  parentSeed: Uint8Array,
  label: string,
  outLen: number = CRYPTO.SUBKEY_BYTES,
): Uint8Array {
  const s = requireReady();
  if (parentSeed.length < 16) throw new Error('[veil/crypto] parent seed too short.');
  return s.crypto_generichash(outLen, utf8(label), parentSeed);
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
  const s = requireReady();
  if (!Number.isInteger(index) || index < 0) {
    throw new Error('[veil/crypto] mask index must be a non-negative integer.');
  }
  const path = maskPath(index);

  const branch = deriveSubSeed(masterSeed, path);
  const edSeed = deriveSubSeed(branch, LBL.identity);
  const xSeed = deriveSubSeed(branch, LBL.exchange);

  const sign = s.crypto_sign_seed_keypair(edSeed);
  const dh = s.crypto_kx_seed_keypair(xSeed);

  wipe(branch, edSeed, xSeed);

  return {
    index,
    path,
    signPk: sign.publicKey,
    signSk: sign.privateKey,
    dhPk: dh.publicKey,
    dhSk: dh.privateKey,
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
  const s = requireReady();
  const digest = s.crypto_generichash(
    CRYPTO.FINGERPRINT_BYTES,
    concat(signPk, dhPk),
    utf8(LBL.fingerprint).slice(0, 32),
  );
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
 *
 * `aad` is authenticated but not encrypted. Veil always binds the retention
 * mode, the message counter and the sender fingerprint into the AAD, so a
 * relay cannot downgrade a View-Once message to Persistent by flipping a
 * cleartext header byte — the tag would fail.
 */
export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): SealedPayload {
  const s = requireReady();
  if (key.length !== CRYPTO.AEAD_KEY_BYTES) {
    throw new Error('[veil/crypto] AEAD key must be 32 bytes.');
  }
  const nonce = randomBytes(CRYPTO.NONCE_BYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad ?? null,
    null, // nsec — unused by this construction
    nonce,
    key,
  );
  return { nonce, ciphertext };
}

/** Returns null on any authentication failure. Never throws on bad input. */
export function aeadDecrypt(
  key: Uint8Array,
  sealed: SealedPayload,
  aad?: Uint8Array,
): Uint8Array | null {
  const s = requireReady();
  if (key.length !== CRYPTO.AEAD_KEY_BYTES) return null;
  if (sealed.nonce.length !== CRYPTO.NONCE_BYTES) return null;
  if (sealed.ciphertext.length < CRYPTO.TAG_BYTES) return null;
  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      sealed.ciphertext,
      aad ?? null,
      sealed.nonce,
      key,
    );
  } catch {
    // Forged tag, wrong key, or truncated frame — all indistinguishable here,
    // which is exactly what we want to surface to the caller.
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
  const s = requireReady();
  const shared = s.crypto_scalarmult(ourDhSk, theirDhPk);
  const mixed = s.crypto_generichash(64, concat(rootKey, shared), utf8(LBL.exchange).slice(0, 32));
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
 * The relay only ever sees this rotating opaque string. Because the key is the
 * *current receiving ratchet* public key and the message includes the hour, the
 * address changes both when the ratchet steps and every hour — so a relay
 * cannot link two subscriptions across epochs, and a compromised relay log from
 * yesterday reveals nothing about today's routing.
 */
export function blindedInboxId(
  receivingRatchetPk: Uint8Array,
  hour: number = epochHour(),
): string {
  const s = requireReady();
  return toB64(s.crypto_generichash(32, utf8(`${LBL.inbox}|${hour}`), receivingRatchetPk));
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
  const s = requireReady();
  const msg = concat(utf8(`veil.inbox.auth.v1|${inboxId}|`), serverNonce);
  return {
    signPk: toB64(mask.signPk),
    signature: toB64(s.crypto_sign_detached(msg, mask.signSk)),
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
 * Canonical signing preimage. Sorted, fixed-order, explicitly delimited — a
 * signature over a URL string with arbitrary parameter order is a classic
 * malleability bug.
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
  const s = requireReady();
  const ttl = opts.ttlSeconds ?? 3600; // one hour; QR codes leak when they linger
  const invite: VeilInvite = {
    v: 1,
    ik: mask.signPk,
    xk: mask.dhPk,
    rz: randomBytes(CRYPTO.RENDEZVOUS_BYTES),
    exp: Math.floor(Date.now() / 1000) + ttl,
    nick: opts.nick,
  };

  const sig = s.crypto_sign_detached(inviteCanonical(invite), mask.signSk);

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
 * malformed, unsigned, mis-signed, or expired — the caller must not attempt
 * partial recovery, because a half-valid invite is an attacker-controlled one.
 */
export function parseInvite(uri: string): ParsedInvite | null {
  const s = requireReady();
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

    const ok = s.crypto_sign_verify_detached(fromB64(sigRaw), inviteCanonical(invite), invite.ik);
    if (!ok) return null;
    if (invite.exp * 1000 < Date.now()) return null;

    return {
      ...invite,
      fingerprint: computeFingerprint(invite.ik, invite.xk),
      rendezvousInbox: blindedInboxId(
        s.crypto_generichash(32, invite.rz, utf8(LBL.inbox).slice(0, 32)),
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
 * PIN -> 256-bit SQLCipher raw key via Argon2id.
 *
 * MODERATE limits (~256 MiB, ~0.7s) are intentional: a 6-digit PIN has ~20
 * bits of entropy, so the *only* thing standing between an imaged device and
 * the plaintext vault is the cost of this function. Do not lower it to make
 * unlock feel snappier; raise the PIN length instead.
 *
 * `partitionLabel` differs per partition ('primary' | 'decoy') so the same PIN
 * cannot possibly derive both keys.
 */
export function deriveVaultKey(
  pin: string,
  deviceSalt: Uint8Array,
  partitionLabel: string,
): Uint8Array {
  const s = requireReady();
  if (deviceSalt.length !== CRYPTO.VAULT_SALT_BYTES) {
    throw new Error('[veil/crypto] device salt must be 16 bytes.');
  }
  const salt = s.crypto_generichash(
    CRYPTO.VAULT_SALT_BYTES,
    utf8(`${LBL.vaultSalt}|${partitionLabel}`),
    deviceSalt,
  );
  return s.crypto_pwhash(
    CRYPTO.VAULT_KEY_BYTES,
    pin,
    salt,
    s.crypto_pwhash_OPSLIMIT_MODERATE,
    s.crypto_pwhash_MEMLIMIT_MODERATE,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
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
  const s = requireReady();
  const msg = utf8(
    [
      LBL.watermark,
      input.deviceFingerprint,
      input.sessionId,
      input.recipientFingerprint,
      String(input.minuteUtc),
    ].join('|'),
  );
  return s.crypto_generichash(32, msg, null);
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
};
