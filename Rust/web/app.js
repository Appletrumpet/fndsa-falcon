// Web-Oberfläche für fndsa (UI-PLAN.md §6): Zustand, Animation, Tastatur.
// Rust rechnet Verify in einem Aufruf; die fünf Schritte werden danach
// verzögert abgespielt (UI-PLAN.md U8). Die angezeigte Laufzeit ist
// gemessen, nicht die Dauer der Animation.

import init, { verify, version, Signer } from './pkg/fndsa_wasm.js';

const STEP_DELAY = 400; // ms je Schritt, nur Darstellung
const TIMING_RUNS = 100; // ein Aufruf liegt unter der Auflösung des Browsers
const STEPS = 5;
const REASONS = {
  0: 'anderer Grad als der Schlüssel',
  2: 's₂ ist ungültig kodiert',
  4: 'Norm über der Schranke',
};

const $ = (id) => document.getElementById(id);

const state = {
  set: '512',
  kat: null,
  pk: null,
  sig: null,
  original: null,
  msg: null,
  flip: null,
  custom: false,
  run: 0, // Zähler, damit eine neue Prüfung die laufende Animation abbricht
};
let signer = null;
let lastSigned = null;

// ---------------------------------------------------------------- Hilfen

const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function parseHex(text, what) {
  const t = text.replace(/0x/gi, '').replace(/[\s,:]/g, '');
  if (t.length % 2 !== 0 || /[^0-9a-f]/i.test(t)) {
    throw new Error(`${what}: kein gültiges Hex`);
  }
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(2 * i, 2), 16);
  return out;
}

const group = (n) => Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));

function describePk(b) {
  if (b.length === 0) return '0 B';
  const logn = b[0] & 0x0f;
  const ok = b[0] >> 4 === 0 && logn >= 1 && logn <= 10;
  return ok ? `n = ${1 << logn} · ${b.length} B` : `${b.length} B · Header ungültig`;
}

function describeSig(b) {
  if (b.length === 0) return '0 B';
  const logn = b[0] & 0x0f;
  if (b[0] >> 4 !== 3 || logn < 1 || logn > 10) return `${b.length} B · Header ungültig`;
  const padded = { 9: 666, 10: 1280 }[logn] === b.length;
  return `n = ${1 << logn} · ${b.length} B · ${padded ? 'gepolstert' : 'ungepolstert'}`;
}

/** Nachricht als Text, wenn sie gültiges UTF-8 ohne Steuerzeichen ist. */
function messageText(b) {
  try {
    const s = new TextDecoder('utf-8', { fatal: true }).decode(b);
    return /[\u0000-\u0008\u000b-\u001f\u007f]/.test(s) ? null : s;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- Anzeige

function renderInputs() {
  $('pk-hex').textContent = hexOf(state.pk);
  $('pk-meta').textContent = describePk(state.pk);
  $('sig-meta').textContent = describeSig(state.sig);

  const sigEl = $('sig-hex');
  sigEl.replaceChildren();
  if (state.flip) {
    // Ausschnitt um das gekippte Byte, damit es sichtbar bleibt
    const { byte } = state.flip;
    const from = Math.max(0, byte - 20);
    const to = Math.min(state.sig.length, byte + 40);
    sigEl.append(from > 0 ? '…' : '', hexOf(state.sig.subarray(from, byte)));
    const mark = document.createElement('mark');
    mark.textContent = hexOf(state.sig.subarray(byte, byte + 1));
    sigEl.append(mark, hexOf(state.sig.subarray(byte + 1, to)), to < state.sig.length ? '…' : '');
    const region = byte <= 40 ? 'Salt' : 's₂';
    $('sig-note').textContent = `Byte ${byte} (${region}), Bit ${state.flip.bit} gekippt`;
  } else {
    sigEl.textContent = hexOf(state.sig);
    $('sig-note').textContent = '';
  }

  const text = messageText(state.msg);
  const msgEl = $('msg-view');
  msgEl.classList.toggle('text', text !== null);
  msgEl.textContent = text ?? hexOf(state.msg);
  $('msg-meta').textContent = `${state.msg.length} B${text === null ? ' · Hex' : ''}`;

  const logn = state.pk.length ? state.pk[0] & 0x0f : 0;
  $('badge').textContent = logn >= 1 && logn <= 10 ? `Falcon-${1 << logn} · WASM` : 'WASM';
}

function setStatus(el, kind, word, sub) {
  const box = $(el);
  box.classList.remove('run', 'ok', 'bad');
  if (kind) box.classList.add(kind);
  $(`${el}-word`).textContent = word;
  $(`${el}-sub`).textContent = sub ?? '';
}

function setSteps(kinds, countText) {
  const items = $('steps').children;
  for (let i = 0; i < STEPS; i++) {
    items[i].className = kinds[i] || '';
  }
  $('progress-count').textContent = countText;
}

function showNorm(report) {
  const box = $('norm');
  if (report?.norm == null) {
    box.hidden = true;
    return;
  }
  const over = report.norm > report.bound;
  $('norm-text').textContent =
    `‖(s₁, s₂)‖² = ${group(report.norm)}  ${over ? '>' : '≤'}  ⌊β²⌋ = ${group(report.bound)}`;
  const fill = $('gauge-fill');
  // Schranke bei 80 % der Breite
  fill.style.width = `${Math.min(100, (report.norm / report.bound) * 80)}%`;
  fill.classList.toggle('over', over);
  box.hidden = false;
}

function resetView() {
  state.run++;
  setStatus('status', '', 'bereit', '');
  setSteps([], '0 / 5 abgeschlossen');
  showNorm(null);
}

// ---------------------------------------------------------------- Prüfen

function readReport(r) {
  const o = { accepted: r.accepted, failedAt: r.failedAt, norm: r.norm, bound: r.bound };
  r.free();
  return o;
}

function measureMicros() {
  const t0 = performance.now();
  for (let i = 0; i < TIMING_RUNS; i++) verify(state.pk, state.sig, state.msg).free();
  return ((performance.now() - t0) / TIMING_RUNS) * 1000;
}

async function runVerify() {
  const token = ++state.run;
  showNorm(null);
  let report = null;
  let error = null;
  let micros = 0;
  try {
    report = readReport(verify(state.pk, state.sig, state.msg));
    micros = measureMicros();
  } catch (e) {
    error = e?.message ?? String(e);
  }

  // Abspielen: Schritte bis zum Fehler grün, Fehlerschritt rot, Rest leer
  const failed = error !== null ? 0 : report.failedAt ?? -1;
  const kinds = [];
  for (let k = 0; k < STEPS; k++) {
    kinds[k] = 'run';
    setSteps(kinds, `${k} / 5 abgeschlossen`);
    setStatus('status', 'run', 'prüft …', `Schritt ${k + 1} von 5`);
    await sleep(STEP_DELAY);
    if (token !== state.run) return;
    if (k === failed) {
      kinds[k] = 'bad';
      break;
    }
    kinds[k] = 'ok';
  }

  if (error !== null) {
    setSteps(kinds, 'abgebrochen bei Schritt 1');
    setStatus('status', 'bad', 'Eingabe ungültig', error);
  } else if (report.accepted) {
    setSteps(kinds, '5 / 5 abgeschlossen');
    setStatus('status', 'ok', 'gültig', `${group(micros)} µs je Prüfung`);
    showNorm(report);
  } else {
    setSteps(kinds, `abgebrochen bei Schritt ${failed + 1}`);
    setStatus('status', 'bad', 'abgelehnt', REASONS[failed] ?? '');
    showNorm(report);
  }
}

function flipBit() {
  if (!state.original || state.original.length < 42) return;
  const r = crypto.getRandomValues(new Uint32Array(2));
  // Salt oder s₂ (ab Byte 1; Byte 0 ist der Header)
  const byte = 1 + (r[0] % (state.original.length - 1));
  const bit = r[1] % 8;
  state.sig = state.original.slice();
  state.sig[byte] ^= 1 << bit;
  state.flip = { byte, bit };
  renderInputs();
  runVerify();
}

function restoreOriginal() {
  if (!state.original) return;
  state.sig = state.original.slice();
  state.flip = null;
  renderInputs();
  resetView();
}

function loadData(pk, sig, msg, custom) {
  state.pk = pk;
  state.sig = sig.slice();
  state.original = sig.slice();
  state.msg = msg;
  state.flip = null;
  state.custom = custom;
  renderInputs();
  resetView();
}

function loadCase(i) {
  const c = state.kat[state.set][i];
  $('kat-select').value = String(i);
  loadData(parseHex(c.pk, 'pk'), parseHex(c.sig, 'sig'), parseHex(c.msg, 'msg'), false);
}

function fillSelect() {
  const sel = $('kat-select');
  sel.replaceChildren();
  state.kat[state.set].forEach((c, i) => {
    sel.append(new Option(`KAT-Fall ${c.count} (Falcon-${state.set})`, String(i)));
  });
  sel.append(new Option('Eigene Daten', 'custom'));
}

function setSet(set) {
  state.set = set;
  $('set-512').setAttribute('aria-pressed', String(set === '512'));
  $('set-1024').setAttribute('aria-pressed', String(set === '1024'));
  $('btn-keygen').textContent = `Schlüssel erzeugen (Falcon-${set})`;
  fillSelect();
  loadCase(0);
  // offener Chat: Schlüssel für den neuen Parametersatz erzeugen
  if (!$('view-chat').hidden && chat.set !== set) chatKeys();
}

// ---------------------------------------------------------------- Eigene Daten

async function readFileInto(input, target, asHex) {
  const f = input.files?.[0];
  if (!f) return;
  const bytes = new Uint8Array(await f.arrayBuffer());
  $(target).value = asHex ? hexOf(bytes) : new TextDecoder().decode(bytes);
}

function openOwnDialog() {
  $('own-pk').value = hexOf(state.pk);
  $('own-sig').value = hexOf(state.sig);
  const text = messageText(state.msg);
  document.querySelector(`input[name=msg-mode][value=${text === null ? 'hex' : 'text'}]`).checked = true;
  $('own-msg').value = text ?? hexOf(state.msg);
  $('own-error').textContent = '';
  $('own-dialog').showModal();
}

function applyOwn(e) {
  if (e.submitter?.value === 'cancel') return;
  try {
    const pk = parseHex($('own-pk').value, 'Public Key');
    const sig = parseHex($('own-sig').value, 'Signatur');
    const hexMode = document.querySelector('input[name=msg-mode]:checked').value === 'hex';
    const msg = hexMode
      ? parseHex($('own-msg').value, 'Nachricht')
      : new TextEncoder().encode($('own-msg').value);
    loadData(pk, sig, msg, true);
    $('kat-select').value = 'custom';
    // Dialog schliesst sich (method=dialog), danach prüfen
    setTimeout(runVerify, 0);
  } catch (err) {
    e.preventDefault();
    $('own-error').textContent = err.message;
  }
}

// ---------------------------------------------------------------- Signieren

async function keygen() {
  setStatus('sign-status', 'run', 'erzeugt …', `Falcon-${state.set}`);
  await nextFrame();
  try {
    const seed = crypto.getRandomValues(new Uint8Array(48));
    const t0 = performance.now();
    const s = new Signer(state.set === '512' ? 9 : 10, seed);
    const ms = performance.now() - t0;
    seed.fill(0);
    signer?.free();
    signer = s;
    const pk = signer.publicKey;
    $('key-pk-hex').textContent = hexOf(pk);
    $('key-meta').textContent = `Falcon-${1 << signer.logn} · pk ${pk.length} B · sk ${signer.secretKeyLength} B`;
    $('btn-sign').disabled = false;
    $('sign-sig-hex').textContent = '';
    $('sign-sig-meta').textContent = '';
    $('btn-to-verify').disabled = true;
    lastSigned = null;
    setStatus('sign-status', '', 'Schlüssel bereit', `Keygen ${ms.toFixed(0)} ms`);
  } catch (e) {
    setStatus('sign-status', 'bad', 'Fehler', e?.message ?? String(e));
  }
}

function updateSignMsgMeta() {
  $('sign-msg-meta').textContent = `${new TextEncoder().encode($('sign-msg').value).length} B`;
}

async function sign() {
  if (!signer) return;
  setStatus('sign-status', 'run', 'signiert …', '');
  await nextFrame();
  try {
    const msg = new TextEncoder().encode($('sign-msg').value);
    const random = crypto.getRandomValues(new Uint8Array(40));
    const t0 = performance.now();
    const sig = signer.sign(msg, random);
    const ms = performance.now() - t0;
    random.fill(0);
    lastSigned = { pk: signer.publicKey, sig, msg };
    $('sign-sig-hex').textContent = hexOf(sig);
    $('sign-sig-meta').textContent = describeSig(sig);
    $('btn-to-verify').disabled = false;
    setStatus('sign-status', 'ok', 'signiert', `${sig.length} B in ${ms.toFixed(1)} ms`);
  } catch (e) {
    setStatus('sign-status', 'bad', 'Fehler', e?.message ?? String(e));
  }
}

function toVerify() {
  if (!lastSigned) return;
  showView('verify');
  loadData(lastSigned.pk, lastSigned.sig, lastSigned.msg, true);
  $('kat-select').value = 'custom';
  runVerify();
}

// ---------------------------------------------------------------- Chat

// Zwei Personen im selben Fenster (Alice wird simuliert). Jede Nachricht
// wird mit dem Signer des Absenders signiert und mit dessen Public Key
// geprüft, wie es der Empfänger täte.
const chat = {
  people: null, // { me: Signer, alice: Signer }
  set: null,
  sender: 'me',
  messages: [], // { from, text, original, msg, sig, report, micros }
  selected: -1,
};

const DEMO = [
  ['alice', 'Hast du die Folien?'],
  ['me', 'Ja, schicke ich gleich'],
  ['alice', 'Danke, bis morgen'],
];

const NAMES = { me: 'Du', alice: 'Alice' };
const STEP_COUNT = 5;

function verifyMessage(m) {
  const pk = chat.people[m.from].publicKey;
  const t0 = performance.now();
  const runs = 20;
  let r = null;
  for (let i = 0; i < runs; i++) {
    r?.free();
    r = verify(pk, m.sig, m.msg);
  }
  m.micros = ((performance.now() - t0) / runs) * 1000;
  m.report = readReport(r);
}

function addMessage(from, text) {
  const msg = new TextEncoder().encode(text);
  const random = crypto.getRandomValues(new Uint8Array(40));
  const sig = chat.people[from].sign(msg, random);
  random.fill(0);
  const m = { from, text, original: null, msg, sig, report: null, micros: 0 };
  verifyMessage(m);
  chat.messages.push(m);
  return chat.messages.length - 1;
}

async function chatKeys() {
  $('chat-meta').textContent = 'Schlüssel werden erzeugt …';
  await nextFrame();
  const logn = state.set === '512' ? 9 : 10;
  const make = () => {
    const seed = crypto.getRandomValues(new Uint8Array(48));
    const s = new Signer(logn, seed);
    seed.fill(0);
    return s;
  };
  chat.people?.me.free();
  chat.people?.alice.free();
  chat.people = { me: make(), alice: make() };
  chat.set = state.set;
  chat.messages = [];
  chat.selected = -1;
  for (const [from, text] of DEMO) addMessage(from, text);
  chat.selected = chat.messages.length - 1;
  const fp = (s) => hexOf(s.publicKey.subarray(1, 4));
  $('chat-meta').textContent =
    `Falcon-${state.set} · Du ${fp(chat.people.me)}… · Alice ${fp(chat.people.alice)}…`;
  renderChat();
}

function renderChat() {
  const list = $('chat-list');
  list.replaceChildren();
  chat.messages.forEach((m, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = `bubble ${m.from === 'me' ? 'me' : 'them'}`;
    if (i === chat.selected) b.classList.add('selected');
    if (!m.report.accepted) b.classList.add('rejected');
    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = NAMES[m.from];
    const badge = document.createElement('span');
    const ok = m.report.accepted;
    badge.className = `badge-line ${ok ? 'ok' : 'bad'}`;
    badge.textContent = ok
      ? '✓ signiert · gültig'
      : `✕ ungültig${m.original !== null ? ' · verfälscht' : ''}`;
    b.append(who, m.text, badge);
    b.addEventListener('click', () => {
      chat.selected = i;
      renderChat();
    });
    list.append(b);
  });
  list.scrollTop = list.scrollHeight;
  renderInspector();
}

function renderInspector() {
  const m = chat.messages[chat.selected];
  const steps = $('insp-steps').children;
  $('insp-tamper').disabled = !m;
  $('insp-restore').disabled = !m || m.original === null;
  if (!m) {
    setStatus('insp', '', '–', 'Nachricht anklicken');
    for (const li of steps) li.className = '';
    $('insp-norm').textContent = 'Norm';
    $('insp-raw').textContent = '';
    return;
  }
  const r = m.report;
  const failed = r.failedAt ?? -1;
  for (let k = 0; k < STEP_COUNT; k++) {
    steps[k].className = failed === -1 || k < failed ? 'ok' : k === failed ? 'bad' : '';
  }
  $('insp-norm').textContent =
    r.norm == null
      ? 'Norm'
      : `Norm ${group(r.norm)} ${r.norm > r.bound ? '>' : '≤'} ${group(r.bound)}`;
  const from = NAMES[m.from];
  if (r.accepted) {
    setStatus('insp', 'ok', 'gültig', `von ${from} · ${group(m.micros)} µs geprüft`);
  } else {
    setStatus('insp', 'bad', 'abgelehnt', `angeblich von ${from} · ${REASONS[failed] ?? ''}`);
  }
  $('insp-raw').textContent =
    `Salt ${hexOf(m.sig.subarray(1, 7))}… · Signatur ${m.sig.length} B · Nachricht ${m.msg.length} B`;
}

/** Ein Zeichen der Nachricht ändern, die Signatur bleibt dieselbe. */
function tamper() {
  const m = chat.messages[chat.selected];
  if (!m) return;
  if (m.original === null) m.original = m.text;
  const t = m.text;
  const i = [...t].findIndex((ch) => /[a-zäöüA-ZÄÖÜ0-9]/.test(ch));
  const chars = [...t];
  if (i >= 0) {
    const ch = chars[i];
    chars[i] = /[0-9]/.test(ch)
      ? String((Number(ch) + 1) % 10)
      : ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase();
  } else {
    chars.push('!');
  }
  m.text = chars.join('');
  m.msg = new TextEncoder().encode(m.text);
  verifyMessage(m);
  renderChat();
}

function restoreMessage() {
  const m = chat.messages[chat.selected];
  if (!m || m.original === null) return;
  m.text = m.original;
  m.original = null;
  m.msg = new TextEncoder().encode(m.text);
  verifyMessage(m);
  renderChat();
}

function setSender(who) {
  chat.sender = who;
  $('as-me').setAttribute('aria-pressed', String(who === 'me'));
  $('as-alice').setAttribute('aria-pressed', String(who === 'alice'));
  $('chat-text').placeholder = who === 'me' ? 'Nachricht an Alice' : 'Antwort von Alice';
  $('chat-text').focus();
}

function sendChat(e) {
  e.preventDefault();
  const text = $('chat-text').value.trim();
  if (!text || !chat.people) return;
  chat.selected = addMessage(chat.sender, text);
  $('chat-text').value = '';
  renderChat();
}

// ---------------------------------------------------------------- Ansichten, Tastatur

function showView(name) {
  for (const v of ['verify', 'sign', 'chat']) {
    $(`view-${v}`).hidden = v !== name;
    $(`tab-${v}`).setAttribute('aria-selected', String(v === name));
  }
  // Schlüssel erst beim ersten Öffnen (oder nach Wechsel 512/1024) erzeugen
  if (name === 'chat' && chat.set !== state.set) chatKeys();
}

function onKey(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const tag = e.target?.tagName;
  if (tag === 'TEXTAREA' || tag === 'INPUT' || tag === 'SELECT') return;
  if ($('own-dialog').open) return;
  if (e.key === '1') return setSet('512');
  if (e.key === '2') return setSet('1024');
  if ($('view-verify').hidden) return;
  if (e.key === 'Enter' && tag !== 'BUTTON') {
    e.preventDefault();
    runVerify();
  } else if (e.key === 'b' || e.key === 'B') {
    flipBit();
  } else if (e.key === 'r' || e.key === 'R') {
    restoreOriginal();
  }
}

function wire() {
  $('btn-verify').addEventListener('click', runVerify);
  $('btn-flip').addEventListener('click', flipBit);
  $('btn-reset').addEventListener('click', restoreOriginal);
  $('btn-own').addEventListener('click', openOwnDialog);
  $('set-512').addEventListener('click', () => setSet('512'));
  $('set-1024').addEventListener('click', () => setSet('1024'));
  $('kat-select').addEventListener('change', (e) => {
    if (e.target.value === 'custom') openOwnDialog();
    else loadCase(Number(e.target.value));
  });
  $('own-form').addEventListener('submit', applyOwn);
  $('own-pk-file').addEventListener('change', (e) => readFileInto(e.target, 'own-pk', true));
  $('own-sig-file').addEventListener('change', (e) => readFileInto(e.target, 'own-sig', true));
  $('own-msg-file').addEventListener('change', (e) => {
    document.querySelector('input[name=msg-mode][value=hex]').checked = true;
    readFileInto(e.target, 'own-msg', true);
  });
  $('tab-verify').addEventListener('click', () => showView('verify'));
  $('tab-sign').addEventListener('click', () => showView('sign'));
  $('tab-chat').addEventListener('click', () => showView('chat'));
  $('chat-form').addEventListener('submit', sendChat);
  $('as-me').addEventListener('click', () => setSender('me'));
  $('as-alice').addEventListener('click', () => setSender('alice'));
  $('insp-tamper').addEventListener('click', tamper);
  $('insp-restore').addEventListener('click', restoreMessage);
  $('chat-newkeys').addEventListener('click', chatKeys);
  $('chat-clear').addEventListener('click', () => {
    chat.messages = [];
    chat.selected = -1;
    renderChat();
  });
  $('btn-keygen').addEventListener('click', keygen);
  $('btn-sign').addEventListener('click', sign);
  $('btn-to-verify').addEventListener('click', toVerify);
  $('sign-msg').addEventListener('input', updateSignMsgMeta);
  document.addEventListener('keydown', onKey);
}

async function main() {
  try {
    await init();
    $('version').textContent = `${version()} · nur zur Vorführung`;
    const res = await fetch('kat.json');
    if (!res.ok) throw new Error(`kat.json: HTTP ${res.status}`);
    state.kat = await res.json();
  } catch (e) {
    setStatus('status', 'bad', 'nicht geladen', e?.message ?? String(e));
    $('version').textContent = 'WASM nicht geladen – web/build.sh ausführen';
    return;
  }
  wire();
  updateSignMsgMeta();
  setSet('512');
}

main();
