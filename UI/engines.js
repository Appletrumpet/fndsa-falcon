// Die drei Implementierungen hinter einer gemeinsamen Schnittstelle
// (UI/README.md). Alle Aufrufe sind asynchron, weil Python in einem Worker
// läuft; Rust und C rechnen direkt im Hauptthread.
//
//   load()                         → lädt beim ersten Gebrauch
//   keygen(logn, seed48)           → { key, pk, skLen, ms }
//   sign(key, msg, random40)       → { sig, ms }
//   verify(pk, sig, msg, runs)     → { accepted, failedAt, norm, bound, micros }
//                                    wirft bei ungültigem Public Key oder
//                                    Signaturformat (wie die Rust-Hülle)
//   free(key)
//
// Laufzeiten werden in der jeweiligen Implementierung gemessen, ohne den
// Weg über Nachrichten an den Worker.

import initRust, { verify as rustVerify, version as rustVersion, Signer } from './pkg/rust/fndsa_wasm.js';
import createFalconC from './pkg/c/falcon_c.js';

const once = (fn) => {
  let p = null;
  return () => (p ??= fn());
};

// ---------------------------------------------------------------- Rust

const rust = {
  id: 'rust',
  name: 'Rust',
  runtime: 'WASM',
  timingRuns: 100,
  version: '',
  load: once(async () => {
    await initRust();
    rust.version = rustVersion();
  }),
  async keygen(logn, seed) {
    const t0 = performance.now();
    const s = new Signer(logn, seed);
    const ms = performance.now() - t0;
    return { key: s, pk: s.publicKey, skLen: s.secretKeyLength, ms };
  },
  async sign(key, msg, random) {
    const t0 = performance.now();
    const sig = key.sign(msg, random);
    return { sig, ms: performance.now() - t0 };
  },
  async verify(pk, sig, msg, runs = 1) {
    let r = rustVerify(pk, sig, msg); // wirft bei ungültiger Eingabe
    const t0 = performance.now();
    for (let i = 0; i < runs; i++) {
      r.free();
      r = rustVerify(pk, sig, msg);
    }
    const micros = ((performance.now() - t0) / runs) * 1000;
    const out = { accepted: r.accepted, failedAt: r.failedAt ?? null, norm: r.norm ?? null, bound: r.bound, micros };
    r.free();
    return out;
  },
  free(key) {
    key?.free();
  },
};

// ---------------------------------------------------------------- C

const MAX_PK = 1793;
const MAX_SIG = 1 + 40 + 1414;
let M = null; // Emscripten-Modul

/** Kopiert Bytes in den WASM-Speicher; Zeiger mit M._free freigeben. */
function put(bytes) {
  const p = M._malloc(Math.max(1, bytes.length));
  M.HEAPU8.set(bytes, p);
  return p;
}

const readU32 = (p) => new DataView(M.HEAPU8.buffer).getUint32(p, true);

const c = {
  id: 'c',
  name: 'C',
  runtime: 'WASM',
  timingRuns: 100,
  version: 'Emscripten 3.1.74',
  load: once(async () => {
    M = await createFalconC();
  }),
  async keygen(logn, seed) {
    const seedP = put(seed);
    const pkP = M._malloc(MAX_PK);
    const lenP = M._malloc(4);
    try {
      const t0 = performance.now();
      const key = M._fw_keygen(logn, seedP, seed.length, pkP, lenP);
      const ms = performance.now() - t0;
      if (!key) throw new Error('Keygen fehlgeschlagen');
      const pk = M.HEAPU8.slice(pkP, pkP + readU32(lenP));
      return { key, pk, skLen: M._fw_sk_length(key), ms };
    } finally {
      M.HEAPU8.fill(0, seedP, seedP + seed.length);
      M._free(seedP);
      M._free(pkP);
      M._free(lenP);
    }
  },
  async sign(key, msg, random) {
    const msgP = put(msg);
    const rndP = put(random);
    const sigP = M._malloc(MAX_SIG);
    const lenP = M._malloc(4);
    try {
      const t0 = performance.now();
      const rc = M._fw_sign(key, msgP, msg.length, rndP, random.length, sigP, lenP);
      const ms = performance.now() - t0;
      if (rc !== 0) throw new Error(`Sign fehlgeschlagen (${rc})`);
      return { sig: M.HEAPU8.slice(sigP, sigP + readU32(lenP)), ms };
    } finally {
      M.HEAPU8.fill(0, rndP, rndP + random.length);
      for (const p of [msgP, rndP, sigP, lenP]) M._free(p);
    }
  },
  async verify(pk, sig, msg, runs = 1) {
    const pkP = put(pk);
    const sigP = put(sig);
    const msgP = put(msg);
    const outP = M._malloc(4 * 8);
    try {
      const call = () => M._fw_verify(pkP, pk.length, sigP, sig.length, msgP, msg.length, outP);
      const rc = call();
      if (rc === -1) throw new Error('Public Key ungültig');
      if (rc === -2) throw new Error('Signatur zu kurz oder Header ungültig');
      const t0 = performance.now();
      for (let i = 0; i < runs; i++) call();
      const micros = ((performance.now() - t0) / runs) * 1000;
      const o = new Float64Array(M.HEAPU8.buffer, outP, 4);
      return {
        accepted: o[0] === 1,
        failedAt: o[1] < 0 ? null : o[1],
        norm: o[2] < 0 ? null : o[2],
        bound: o[3],
        micros,
      };
    } finally {
      for (const p of [pkP, sigP, msgP, outP]) M._free(p);
    }
  },
  free(key) {
    if (key) M._fw_free(key);
  },
};

// ---------------------------------------------------------------- Python

let worker = null;
let nextId = 1;
const pending = new Map();

function call(op, ...args) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });
}

/** Letzte Zeile einer Python-Ausnahme, ohne Traceback. */
const pyError = (msg) => msg.trim().split('\n').pop().replace(/^\w+Error: /, '');

const python = {
  id: 'python',
  name: 'Python',
  runtime: 'Pyodide',
  timingRuns: 5,
  version: '',
  load: once(async () => {
    worker = new Worker('python-worker.js');
    worker.onmessage = (e) => {
      const { id, ok, value, error } = e.data;
      const p = pending.get(id);
      pending.delete(id);
      ok ? p.resolve(value) : p.reject(new Error(pyError(error)));
    };
    worker.onerror = (e) => {
      for (const p of pending.values()) p.reject(new Error(e.message || 'Python-Worker abgestürzt'));
      pending.clear();
    };
    python.version = `Pyodide ${await call('version')}`;
  }),
  async keygen(logn, seed) {
    const t0 = performance.now();
    const [key, pk, skLen] = await call('keygen', logn, seed);
    // Keygen dauert Sekunden; der Weg über den Worker fällt nicht ins Gewicht
    return { key, pk, skLen, ms: performance.now() - t0 };
  },
  async sign(key, msg, random) {
    const t0 = performance.now();
    const sig = await call('sign', key, msg, random);
    return { sig, ms: performance.now() - t0 };
  },
  async verify(pk, sig, msg, runs = 1) {
    const r = await call('verify_timed', pk, sig, msg, runs);
    if (r.error) throw new Error(r.error);
    return { accepted: r.accepted, failedAt: r.failedAt, norm: r.norm, bound: r.bound, micros: r.micros };
  },
  free(key) {
    if (key) call('free', key).catch(() => {});
  },
};

export const ENGINES = { rust, c, python };
export const ORDER = ['rust', 'c', 'python'];
