/**
 * ============================================================================
 *  VEIL — BLIND WEBSOCKET RELAY
 * ============================================================================
 *  The relay is a dumb, forgetful mailbox. Its complete knowledge of the world:
 *
 *    - a set of opaque, hourly-rotating inbox IDs that someone subscribed to
 *    - opaque ciphertext blobs, held in RAM, dropped the instant they are ACKed
 *
 *  It has NO accounts, NO passwords, NO contact graph, NO message history, NO
 *  access log, and NO disk writes. Redis is used exclusively as a pub/sub bus
 *  for cross-node fan-out — never SET, never a Stream, never a key with a TTL.
 *  Restarting the process is a complete and irreversible data wipe.
 *
 *  SUBSCRIBER AUTHORIZATION WITHOUT IDENTITY
 *  Since there is no directory, the relay cannot know who "owns" an inbox. It
 *  uses first-claim registration, held in RAM only: the first Ed25519 key to
 *  claim a blinded inbox ID within an epoch owns it for that epoch, and every
 *  subsequent claim must prove possession of that same key over a fresh
 *  server nonce. This stops a passive eavesdropper who learned an inbox ID
 *  from stealing its mail, without the relay ever learning a persistent
 *  identity — the claiming key is itself an ephemeral per-inbox subkey and the
 *  registration evaporates when the epoch rolls or the process restarts.
 *
 *  KNOWN LIMITS, stated plainly: an active adversary who controls the relay
 *  from before a user's very first subscription of an epoch can pre-claim that
 *  inbox. Defeating that requires the client to pin the relay's key and detect
 *  claim rejection — implemented client-side, out of scope for this file. And
 *  a global passive observer can still correlate connection timing; the fixed
 *  envelope size and NOOP cover traffic below raise the cost but do not
 *  eliminate it.
 * ============================================================================
 */

import { createServer, type IncomingMessage } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { WebSocketServer, WebSocket, type RawData } from 'ws';
// Replace: import { Redis } from 'ioredis';
import RedisMock from 'ioredis-mock';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const _sodium = require('libsodium-wrappers');

/* -------------------------------------------------------------------------- */
/* Config                                                                     */
/* -------------------------------------------------------------------------- */

const CONFIG = {
  port: Number(process.env.VEIL_PORT ?? 8443),
  redisUrl: process.env.VEIL_REDIS_URL ?? 'redis://127.0.0.1:6379',

  /** Fixed padded envelope size. Uniformity denies size-correlation attacks. */
  envelopeBytes: 4096,
  maxFrameBytes: 8192,

  /** Volatile buffering. Nothing survives these bounds. */
  bufferTtlMs: 24 * 3_600_000,
  maxQueueDepth: 256,
  maxQueuedInboxes: 200_000,

  /** Per-connection limits. */
  maxSubsPerConn: 64,
  ratePerSec: 20,
  rateBurst: 60,
  idleTimeoutMs: 90_000,
  heartbeatMs: 25_000,

  /** Inbox claim lifetime — two epoch hours, matching the client's window. */
  claimTtlMs: 2 * 3_600_000,
} as const;

/**
 * We emit NO access log, NO IP, NO inbox ID, and NO timestamp-correlatable
 * per-message line. Only aggregate counters and fatal faults. A verbose relay
 * log is a metadata database with extra steps.
 */
const log = {
  boot: (m: string) => process.stdout.write(`[veil-relay] ${m}\n`),
  fault: (m: string) => process.stderr.write(`[veil-relay][fault] ${m}\n`),
};

/* -------------------------------------------------------------------------- */
/* Protocol                                                                   */
/* -------------------------------------------------------------------------- */

type ClientFrame =
  | { t: 'HELLO'; v: 1 }
  | { t: 'SUB'; inbox: string; pk: string; sig: string }
  | { t: 'UNSUB'; inbox: string }
  | { t: 'SEND'; inbox: string; env: string }
  | { t: 'ACK'; inbox: string; ids: string[] }
  | { t: 'NOOP' }
  | { t: 'PING' };

type ServerFrame =
  | { t: 'HELLO'; v: 1; nonce: string; envelopeBytes: number }
  | { t: 'SUBBED'; inbox: string }
  | { t: 'DENIED'; inbox: string }
  | { t: 'DELIVER'; inbox: string; id: string; env: string }
  | { t: 'ACCEPTED'; inbox: string; id: string }
  | { t: 'DROPPED'; inbox: string; reason: 'full' }
  | { t: 'PONG' }
  | { t: 'ERR'; code: string };

interface Envelope {
  id: string;
  inbox: string;
  env: string; // base64 ciphertext, fixed padded length
  expiresAt: number;
}

/* -------------------------------------------------------------------------- */
/* Volatile state                                                            */
/* -------------------------------------------------------------------------- */

/** inbox -> pending envelopes. RAM only. Never serialized anywhere. */
const queues = new Map<string, Envelope[]>();

/** inbox -> local live subscribers. */
const subscribers = new Map<string, Set<Conn>>();

/** inbox -> first-claim owner key + expiry. RAM only, epoch-scoped. */
const claims = new Map<string, { pk: Uint8Array; expiresAt: number }>();

interface Conn {
  ws: WebSocket;
  /** Per-connection challenge; every SUB signature is bound to it. */
  nonce: Buffer;
  subs: Set<string>;
  /** Token bucket. */
  tokens: number;
  lastRefill: number;
  alive: boolean;
  lastSeen: number;
}

const conns = new Set<Conn>();

/* -------------------------------------------------------------------------- */
/* Crypto                                                                     */
/* -------------------------------------------------------------------------- */

let sodium: typeof _sodium;

const b64 = {
  dec(s: string): Uint8Array {
    return new Uint8Array(Buffer.from(s, 'base64url'));
  },
};

const utf8 = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));

/** Same preimage the client builds in `signInboxAuth`. */
function authPreimage(inbox: string, nonce: Buffer): Uint8Array {
  const prefix = utf8(`veil.inbox.auth.v1|${inbox}|`);
  const out = new Uint8Array(prefix.length + nonce.length);
  out.set(prefix, 0);
  out.set(nonce, prefix.length);
  return out;
}

/* -------------------------------------------------------------------------- */
/* Redis pub/sub bus (fan-out only)                                          */
/* -------------------------------------------------------------------------- */

const CH_DELIVER = 'veil:relay:deliver';
const CH_ANNOUNCE = 'veil:relay:announce';

const pub = new RedisMock(CONFIG.redisUrl, { lazyConnect: true, enableOfflineQueue: false });
const sub = new RedisMock(CONFIG.redisUrl, { lazyConnect: true, enableOfflineQueue: false });

/**
 * Cross-node routing, without any shared storage:
 *
 *  - On SEND, the ingress node buffers locally AND publishes on CH_DELIVER.
 *    Whichever node holds a live subscriber pushes it and returns the ACK,
 *    which is broadcast so the ingress node can drop its copy.
 *  - On SUB, the node publishes on CH_ANNOUNCE. Any node holding buffered mail
 *    for that inbox re-publishes it. That is how an offline client's mail
 *    reaches it after reconnecting to a different node — with zero persistence.
 */
async function initBus(): Promise<void> {
  await Promise.all([pub.connect(), sub.connect()]);
  await sub.subscribe(CH_DELIVER, CH_ANNOUNCE);

  sub.on('message', (channel: string, raw: string) => {
    try {
      const msg = JSON.parse(raw);
      if (channel === CH_DELIVER) {
        // Only act if WE hold a subscriber; otherwise ignore entirely.
        if (subscribers.has(msg.inbox)) fanOut(msg as Envelope, false);
      } else if (channel === CH_ANNOUNCE) {
        flushLocalBuffer(msg.inbox);
      }
    } catch {
      /* malformed bus traffic is discarded silently */
    }
  });
}

/* -------------------------------------------------------------------------- */
/* Queue mechanics                                                            */
/* -------------------------------------------------------------------------- */

function send(conn: Conn, frame: ServerFrame): void {
  if (conn.ws.readyState !== WebSocket.OPEN) return;
  try {
    conn.ws.send(JSON.stringify(frame));
  } catch {
    /* the socket is dying; the close handler will clean up */
  }
}

/** Pushes to local subscribers; buffers only if none and `allowBuffer`. */
function fanOut(env: Envelope, allowBuffer: boolean): void {
  const set = subscribers.get(env.inbox);
  if (set && set.size > 0) {
    for (const conn of set) {
      send(conn, { t: 'DELIVER', inbox: env.inbox, id: env.id, env: env.env });
    }
    // Held pending ACK so a socket that dies mid-flight does not lose mail.
    buffer(env);
    return;
  }
  if (allowBuffer) buffer(env);
}

function buffer(env: Envelope): void {
  let q = queues.get(env.inbox);
  if (!q) {
    if (queues.size >= CONFIG.maxQueuedInboxes) return; // shed, never spill to disk
    q = [];
    queues.set(env.inbox, q);
  }
  if (q.some((e) => e.id === env.id)) return; // idempotent across bus echoes
  if (q.length >= CONFIG.maxQueueDepth) q.shift(); // oldest out; bounded RAM
  q.push(env);
}

function flushLocalBuffer(inbox: string): void {
  const q = queues.get(inbox);
  if (!q || q.length === 0) return;
  const now = Date.now();
  const live = q.filter((e) => e.expiresAt > now);
  queues.set(inbox, live);

  const set = subscribers.get(inbox);
  if (set && set.size > 0) {
    for (const conn of set) {
      for (const e of live) send(conn, { t: 'DELIVER', inbox, id: e.id, env: e.env });
    }
  } else {
    // A subscriber exists on another node — hand the mail to the bus.
    for (const e of live) {
      pub.publish(CH_DELIVER, JSON.stringify(e)).catch(() => {});
    }
  }
}

/** ACK is the delete. There is no soft-delete, tombstone, or archive. */
function dropAcked(inbox: string, ids: string[]): void {
  const q = queues.get(inbox);
  if (!q) return;
  const doomed = new Set(ids);
  const remaining = q.filter((e) => !doomed.has(e.id));
  if (remaining.length === 0) queues.delete(inbox);
  else queues.set(inbox, remaining);
}

/* -------------------------------------------------------------------------- */
/* Rate limiting                                                              */
/* -------------------------------------------------------------------------- */

function allow(conn: Conn): boolean {
  const now = Date.now();
  const elapsed = (now - conn.lastRefill) / 1000;
  conn.lastRefill = now;
  conn.tokens = Math.min(CONFIG.rateBurst, conn.tokens + elapsed * CONFIG.ratePerSec);
  if (conn.tokens < 1) return false;
  conn.tokens -= 1;
  return true;
}

/* -------------------------------------------------------------------------- */
/* Frame handling                                                             */
/* -------------------------------------------------------------------------- */

function handleSub(conn: Conn, f: Extract<ClientFrame, { t: 'SUB' }>): void {
  if (conn.subs.size >= CONFIG.maxSubsPerConn) {
    send(conn, { t: 'DENIED', inbox: f.inbox });
    return;
  }

  let pk: Uint8Array;
  let sig: Uint8Array;
  try {
    pk = b64.dec(f.pk);
    sig = b64.dec(f.sig);
  } catch {
    send(conn, { t: 'DENIED', inbox: f.inbox });
    return;
  }
  if (pk.length !== 32 || sig.length !== 64) {
    send(conn, { t: 'DENIED', inbox: f.inbox });
    return;
  }

  // 1. Signature must be over THIS connection's nonce — kills replay.
  if (!sodium.crypto_sign_verify_detached(sig, authPreimage(f.inbox, conn.nonce), pk)) {
    send(conn, { t: 'DENIED', inbox: f.inbox });
    return;
  }

  // 2. First-claim ownership, constant-time compared.
  const now = Date.now();
  const existing = claims.get(f.inbox);
  if (existing && existing.expiresAt > now) {
    const a = Buffer.from(existing.pk);
    const b = Buffer.from(pk);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      send(conn, { t: 'DENIED', inbox: f.inbox });
      return;
    }
  }
  claims.set(f.inbox, { pk, expiresAt: now + CONFIG.claimTtlMs });

  conn.subs.add(f.inbox);
  let set = subscribers.get(f.inbox);
  if (!set) {
    set = new Set();
    subscribers.set(f.inbox, set);
  }
  set.add(conn);

  send(conn, { t: 'SUBBED', inbox: f.inbox });

  // Drain anything already here, then ask peer nodes to drain too.
  flushLocalBuffer(f.inbox);
  pub.publish(CH_ANNOUNCE, JSON.stringify({ inbox: f.inbox })).catch(() => {});
}

function handleSend(conn: Conn, f: Extract<ClientFrame, { t: 'SEND' }>): void {
  // Enforce the fixed envelope size. Rejecting non-uniform payloads is what
  // makes padding actually protective — otherwise clients degrade it silently.
  const size = Buffer.byteLength(f.env, 'base64');
  if (size !== CONFIG.envelopeBytes) {
    send(conn, { t: 'ERR', code: 'ENVELOPE_SIZE' });
    return;
  }
  if (typeof f.inbox !== 'string' || f.inbox.length < 16 || f.inbox.length > 128) {
    send(conn, { t: 'ERR', code: 'INBOX_FORM' });
    return;
  }

  const envelope: Envelope = {
    // Server-assigned: a client-chosen ID is a covert channel and a collision risk.
    id: randomBytes(12).toString('base64url'),
    inbox: f.inbox,
    env: f.env,
    expiresAt: Date.now() + CONFIG.bufferTtlMs,
  };

  fanOut(envelope, true);
  pub.publish(CH_DELIVER, JSON.stringify(envelope)).catch(() => {});
  send(conn, { t: 'ACCEPTED', inbox: f.inbox, id: envelope.id });
}

function handleFrame(conn: Conn, raw: RawData): void {
  conn.lastSeen = Date.now();

  if (Buffer.byteLength(raw as Buffer) > CONFIG.maxFrameBytes) {
    conn.ws.close(1009, 'frame');
    return;
  }
  if (!allow(conn)) {
    send(conn, { t: 'ERR', code: 'RATE' });
    return;
  }

  let f: ClientFrame;
  try {
    f = JSON.parse((raw as Buffer).toString('utf8'));
  } catch {
    send(conn, { t: 'ERR', code: 'PARSE' });
    return;
  }

  switch (f.t) {
    case 'HELLO':
      send(conn, {
        t: 'HELLO',
        v: 1,
        nonce: conn.nonce.toString('base64url'),
        envelopeBytes: CONFIG.envelopeBytes,
      });
      break;
    case 'SUB':
      handleSub(conn, f);
      break;
    case 'UNSUB':
      conn.subs.delete(f.inbox);
      subscribers.get(f.inbox)?.delete(conn);
      if (subscribers.get(f.inbox)?.size === 0) subscribers.delete(f.inbox);
      break;
    case 'SEND':
      handleSend(conn, f);
      break;
    case 'ACK':
      if (conn.subs.has(f.inbox) && Array.isArray(f.ids)) dropAcked(f.inbox, f.ids.slice(0, 256));
      break;
    case 'NOOP':
      // Client cover traffic. Accepted and discarded — its only purpose is to
      // make real sends indistinguishable from idling to a network observer.
      break;
    case 'PING':
      send(conn, { t: 'PONG' });
      break;
    default:
      send(conn, { t: 'ERR', code: 'UNKNOWN' });
  }
}

/* -------------------------------------------------------------------------- */
/* Server                                                                     */
/* -------------------------------------------------------------------------- */

async function main(): Promise<void> {
  await _sodium.ready;
  sodium = _sodium;
  await initBus();

  // No request logging middleware, deliberately. `/healthz` returns a bare 200
  // with no version string or counters — a fingerprintable banner is metadata.
  const http = createServer((req, res) => {
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const wss = new WebSocketServer({
    server: http,
    maxPayload: CONFIG.maxFrameBytes,
    // Compression OFF: a shared compression context across messages leaks
    // plaintext similarity through ciphertext length (CRIME/BREACH-style).
    perMessageDeflate: false,
    clientTracking: false,
  });

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    // The socket is the only handle we keep. `req` — and therefore the source
    // IP, User-Agent and headers — is intentionally never read or stored.
    void req;

    ws.binaryType = 'nodebuffer';
    (req.socket as any)?.setNoDelay?.(true);

    const conn: Conn = {
      ws,
      nonce: randomBytes(32),
      subs: new Set(),
      tokens: CONFIG.rateBurst,
      lastRefill: Date.now(),
      alive: true,
      lastSeen: Date.now(),
    };
    conns.add(conn);

    send(conn, {
      t: 'HELLO',
      v: 1,
      nonce: conn.nonce.toString('base64url'),
      envelopeBytes: CONFIG.envelopeBytes,
    });

    ws.on('message', (raw) => handleFrame(conn, raw));
    ws.on('pong', () => {
      conn.alive = true;
      conn.lastSeen = Date.now();
    });
    ws.on('error', () => ws.terminate());
    ws.on('close', () => {
      for (const inbox of conn.subs) {
        const set = subscribers.get(inbox);
        set?.delete(conn);
        if (set && set.size === 0) subscribers.delete(inbox);
      }
      conn.subs.clear();
      conn.nonce.fill(0);
      conns.delete(conn);
    });
  });

  /* ---- Heartbeat + idle reaping --------------------------------------- */

  const heartbeat = setInterval(() => {
    const now = Date.now();
    for (const conn of conns) {
      if (!conn.alive || now - conn.lastSeen > CONFIG.idleTimeoutMs) {
        conn.ws.terminate();
        continue;
      }
      conn.alive = false;
      try {
        conn.ws.ping();
      } catch {
        conn.ws.terminate();
      }
    }
  }, CONFIG.heartbeatMs);

  /* ---- Expiry sweep ---------------------------------------------------- */

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [inbox, q] of queues) {
      const live = q.filter((e) => e.expiresAt > now);
      if (live.length === 0) queues.delete(inbox);
      else if (live.length !== q.length) queues.set(inbox, live);
    }
    for (const [inbox, claim] of claims) {
      if (claim.expiresAt <= now) {
        claim.pk.fill(0);
        claims.delete(inbox);
      }
    }
  }, 60_000);

  /* ---- Shutdown: zeroize everything before exiting -------------------- */

  const shutdown = async (signal: string) => {
    log.boot(`shutdown (${signal})`);
    clearInterval(heartbeat);
    clearInterval(sweep);

    for (const conn of conns) {
      try {
        conn.ws.close(1001, 'restart');
      } catch {
        /* already gone */
      }
    }

    // Overwrite buffered ciphertext before releasing it to the GC, so a core
    // dump taken after SIGTERM does not yield deliverable envelopes.
    for (const q of queues.values()) {
      for (const e of q) e.env = '';
    }
    queues.clear();
    subscribers.clear();
    for (const c of claims.values()) c.pk.fill(0);
    claims.clear();

    await Promise.allSettled([pub.quit(), sub.quit()]);
    wss.close();
    http.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('unhandledRejection', (e) => log.fault(String(e)));

  http.listen(CONFIG.port, () => log.boot(`blind relay listening :${CONFIG.port}`));
}

main().catch((e) => {
  log.fault(String(e));
  process.exit(1);
});
