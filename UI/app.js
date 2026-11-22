// Web-Oberfläche (UI/README.md): Prüfen, Signieren, Chat und Vergleich mit
// den drei Implementierungen Rust, C und Python (engines.js).
//
// Verify rechnet in einem Aufruf; die fünf Schritte werden danach verzögert
// abgespielt (Rust/UI-PLAN.md U8). Angezeigte Laufzeiten sind gemessen,
// nicht die Dauer der Animation.

import { ENGINES, ORDER } from './engines.js';

const STEP_DELAY = 400; // ms je Schritt, nur Darstellung
const STEPS = 5;
const REASONS = {
  0: 'anderer Grad als der Schlüssel',
  2: 's₂ ist ungültig kodiert',
  4: 'Norm über der Schranke',
};
const VIEWS = { sign: 'Signieren', verify: 'Prüfen', chat: 'Chat', compare: 'Vergleich' };

const $ = (id) => document.getElementById(id);

const state = {
  set: '512',
  view: 'verify',
  kat: null,
  pk: null,
  sig: null,
  original: null,
  msg: null,
  flip: null,
  run: 0, // Zähler, damit eine neue Prüfung die laufende Animation abbricht
};
let engine = ENGINES.rust;
let keypair = null; // { engine, key, pk, skLen } der Ansicht Signieren
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

const group = (n) => Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));
const errText = (e) => e?.message ?? String(e);
const logn = () => (state.set === '512' ? 9 : 10);
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

/** Laufzeit lesbar: µs, ms oder s. */
function fmtMs(ms) {
  if (ms < 1) return `${group(ms * 1000)} µs`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  if (ms < 10000) return `${group(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function describePk(b) {
  if (b.length === 0) return '0 B';
  const ln = b[0] & 0x0f;
  const ok = b[0] >> 4 === 0 && ln >= 1 && ln <= 10;
  return ok ? `n = ${1 << ln} · ${b.length} B` : `${b.length} B · Header ungültig`;
}

function describeSig(b) {
  if (b.length === 0) return '0 B';
  const ln = b[0] & 0x0f;
  if (b[0] >> 4 !== 3 || ln < 1 || ln > 10) return `${b.length} B · Header ungültig`;
  const padded = { 9: 666, 10: 1280 }[ln] === b.length;
  return `n = ${1 << ln} · ${b.length} B · ${padded ? 'gepolstert' : 'ungepolstert'}`;
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

function setStatus(el, kind, word, sub) {
  const box = $(el);
  box.classList.remove('run', 'ok', 'bad');
  if (kind) box.classList.add(kind);
  $(`${el}-word`).textContent = word;
  $(`${el}-sub`).textContent = sub ?? '';
}

// ---------------------------------------------------------------- Menüs

const MENUS = { 'menu-btn': 'menu', 'impl-btn': 'impl-menu' };

function closeMenus(focusButton) {
  for (const [btn, menu] of Object.entries(MENUS)) {
    if (!$(menu).hidden && focusButton) $(btn).focus();
    $(menu).hidden = true;
    $(btn).setAttribute('aria-expanded', 'false');
  }
}

function toggleMenu(btn) {
  const menu = $(MENUS[btn]);
  const open = menu.hidden;
  closeMenus(false);
  if (!open) return;
  menu.hidden = false;
  $(btn).setAttribute('aria-expanded', 'true');
  const current = menu.querySelector('[aria-current="page"], [aria-checked="true"]') ?? menu.querySelector('button');
  current.focus();
}

/** Pfeiltasten im offenen Menü. */
function menuKeys(e) {
  const menu = e.currentTarget;
  const items = [...menu.querySelectorAll('button')];
  const i = items.indexOf(document.activeElement);
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const d = e.key === 'ArrowDown' ? 1 : -1;
    items[(i + d + items.length) % items.length].focus();
  } else if (e.key === 'Escape') {
    closeMenus(true);
  } else if (e.key === 'Tab') {
    closeMenus(false);
  }
}

// ---------------------------------------------------------------- Implementierung

function renderEngine() {
  $('impl-name').textContent = engine.name;
  $('impl-rt').textContent = engine.runtime;
  for (const b of document.querySelectorAll('[data-impl]')) {
    if (b.getAttribute('role') === 'menuitemradio') {
      b.setAttribute('aria-checked', String(b.dataset.impl === engine.id));
    }
  }
  $('version').textContent = `${engine.name}: ${engine.version || engine.runtime} · nur zur Vorführung`;
}

async function setEngine(id) {
  closeMenus(true);
  const next = ENGINES[id];
  if (next === engine) return;
  $('impl-name').textContent = `${next.name} lädt …`;
  try {
    await next.load();
  } catch (e) {
    $('impl-name').textContent = engine.name;
    setStatus('status', 'bad', `${next.name} nicht geladen`, errText(e));
    return;
  }
  engine = next;
  try {
    localStorage.setItem('fndsa-impl', id);
  } catch {}
  renderEngine();
  dropKeypair();
  resetView();
  dropChat();
  if (state.view === 'chat') chatKeys();
}

// ---------------------------------------------------------------- Prüfen

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
  setStatus('status', '', 'bereit', engine.name);
  setSteps([], '0 / 5 abgeschlossen');
  showNorm(null);
}

async function runVerify() {
  const token = ++state.run;
  const eng = engine;
  showNorm(null);
  setStatus('status', 'run', 'prüft …', eng.name);
  let report = null;
  let error = null;
  try {
    report = await eng.verify(state.pk, state.sig, state.msg, eng.timingRuns);
  } catch (e) {
    error = errText(e);
  }
  if (token !== state.run) return;

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
    setStatus('status', 'ok', 'gültig', `${fmtMs(report.micros / 1000)} mit ${eng.name}`);
    showNorm(report);
  } else {
    setSteps(kinds, `abgebrochen bei Schritt ${failed + 1}`);
    setStatus('status', 'bad', 'abgelehnt', `${REASONS[failed] ?? ''} · ${eng.name}`);
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

function loadData(pk, sig, msg) {
  state.pk = pk;
  state.sig = sig.slice();
  state.original = sig.slice();
  state.msg = msg;
  state.flip = null;
  renderInputs();
  resetView();
}

function loadCase(i) {
  const c = state.kat[state.set][i];
  $('kat-select').value = String(i);
  loadData(parseHex(c.pk, 'pk'), parseHex(c.sig, 'sig'), parseHex(c.msg, 'msg'));
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
  if (state.view === 'chat' && chat.set !== set) chatKeys();
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
    loadData(pk, sig, msg);
    $('kat-select').value = 'custom';
    // Dialog schliesst sich (method=dialog), danach prüfen
    setTimeout(runVerify, 0);
  } catch (err) {
    e.preventDefault();
    $('own-error').textContent = err.message;
  }
}

// ---------------------------------------------------------------- Signieren

function dropKeypair() {
  keypair?.engine.free(keypair.key);
  keypair = null;
  lastSigned = null;
  $('key-pk-hex').textContent = '';
  $('key-meta').textContent = 'noch keines';
  $('btn-sign').disabled = true;
  $('sign-sig-hex').textContent = '';
  $('sign-sig-meta').textContent = '';
  $('btn-to-verify').disabled = true;
  setStatus('sign-status', '', 'bereit', `erst Schlüssel erzeugen · ${engine.name}`);
}

async function keygen() {
  const eng = engine;
  $('btn-keygen').disabled = true;
  setStatus('sign-status', 'run', 'erzeugt …', `Falcon-${state.set} mit ${eng.name}`);
  await nextFrame();
  try {
    const seed = random(48);
    const kp = await eng.keygen(logn(), seed);
    seed.fill(0);
    if (eng !== engine) {
      eng.free(kp.key); // inzwischen umgeschaltet
      return;
    }
    dropKeypair();
    keypair = { engine: eng, ...kp };
    $('key-pk-hex').textContent = hexOf(kp.pk);
    const sk = kp.skLen ? ` · sk ${kp.skLen} B` : '';
    $('key-meta').textContent = `Falcon-${1 << (kp.pk[0] & 15)} · pk ${kp.pk.length} B${sk}`;
    $('btn-sign').disabled = false;
    setStatus('sign-status', '', 'Schlüssel bereit', `Keygen ${fmtMs(kp.ms)} mit ${eng.name}`);
  } catch (e) {
    setStatus('sign-status', 'bad', 'Fehler', errText(e));
  } finally {
    $('btn-keygen').disabled = false;
  }
}

function updateSignMsgMeta() {
  $('sign-msg-meta').textContent = `${new TextEncoder().encode($('sign-msg').value).length} B`;
}

async function sign() {
  if (!keypair) return;
  const kp = keypair;
  $('btn-sign').disabled = true;
  setStatus('sign-status', 'run', 'signiert …', kp.engine.name);
  await nextFrame();
  try {
    const msg = new TextEncoder().encode($('sign-msg').value);
    const rnd = random(40);
    const { sig, ms } = await kp.engine.sign(kp.key, msg, rnd);
    rnd.fill(0);
    if (kp !== keypair) return;
    lastSigned = { pk: kp.pk, sig, msg };
    $('sign-sig-hex').textContent = hexOf(sig);
    $('sign-sig-meta').textContent = describeSig(sig);
    $('btn-to-verify').disabled = false;
    setStatus('sign-status', 'ok', 'signiert', `${sig.length} B in ${fmtMs(ms)} mit ${kp.engine.name}`);
  } catch (e) {
    setStatus('sign-status', 'bad', 'Fehler', errText(e));
  } finally {
    $('btn-sign').disabled = !keypair;
  }
}

function toVerify() {
  if (!lastSigned) return;
  showView('verify');
  loadData(lastSigned.pk, lastSigned.sig, lastSigned.msg);
  $('kat-select').value = 'custom';
  runVerify();
}

// ---------------------------------------------------------------- Chat

// Zwei Personen im selben Fenster (Alice wird simuliert). Jede Nachricht
// wird mit dem Schlüssel des Absenders signiert und mit dessen Public Key
// geprüft, wie es der Empfänger täte; gerechnet wird mit der gewählten
// Implementierung.
const chat = {
  engine: null,
  people: null, // { me: { key, pk }, alice: { key, pk } }
  set: null,
  gen: 0, // Zähler, damit neue Schlüssel eine laufende Erzeugung abbrechen
  sender: 'me',
  messages: [], // { from, text, original, msg, sig, report }
  selected: -1,
};

const DEMO = [
  ['alice', 'Hast du die Folien?'],
  ['me', 'Ja, schicke ich gleich'],
  ['alice', 'Danke, bis morgen'],
];
const NAMES = { me: 'Du', alice: 'Alice' };

function dropChat() {
  chat.gen++;
  if (chat.people) {
    chat.engine.free(chat.people.me.key);
    chat.engine.free(chat.people.alice.key);
  }
  chat.people = null;
  chat.set = null;
  chat.messages = [];
  chat.selected = -1;
}

async function verifyMessage(m) {
  const runs = Math.max(1, Math.round(chat.engine.timingRuns / 5));
  m.report = await chat.engine.verify(chat.people[m.from].pk, m.sig, m.msg, runs);
}

async function addMessage(from, text) {
  const msg = new TextEncoder().encode(text);
  const rnd = random(40);
  const { sig } = await chat.engine.sign(chat.people[from].key, msg, rnd);
  rnd.fill(0);
  const m = { from, text, original: null, msg, sig, report: null };
  await verifyMessage(m);
  chat.messages.push(m);
  return chat.messages.length - 1;
}

async function chatKeys() {
  dropChat();
  const gen = chat.gen;
  const eng = engine;
  $('chat-meta').textContent = `Schlüssel werden erzeugt (${eng.name}) …`;
  renderChat();
  await nextFrame();
  try {
    const make = async () => {
      const seed = random(48);
      const kp = await eng.keygen(logn(), seed);
      seed.fill(0);
      return kp;
    };
    const me = await make();
    const alice = await make();
    if (gen !== chat.gen) {
      eng.free(me.key);
      eng.free(alice.key);
      return;
    }
    chat.engine = eng;
    chat.people = { me, alice };
    chat.set = state.set;
    for (const [from, text] of DEMO) {
      await addMessage(from, text);
      if (gen !== chat.gen) return;
    }
    chat.selected = chat.messages.length - 1;
    const fp = (p) => hexOf(p.pk.subarray(1, 4));
    $('chat-meta').textContent =
      `Falcon-${state.set} · ${eng.name} · Du ${fp(me)}… · Alice ${fp(alice)}…`;
    renderChat();
  } catch (e) {
    if (gen === chat.gen) $('chat-meta').textContent = `Fehler: ${errText(e)}`;
  }
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
    setStatus('insp', '', '–', chat.people ? 'Nachricht anklicken' : '');
    for (const li of steps) li.className = '';
    $('insp-norm').textContent = 'Norm';
    $('insp-raw').textContent = '';
    return;
  }
  const r = m.report;
  const failed = r.failedAt ?? -1;
  for (let k = 0; k < STEPS; k++) {
    steps[k].className = failed === -1 || k < failed ? 'ok' : k === failed ? 'bad' : '';
  }
  $('insp-norm').textContent =
    r.norm == null
      ? 'Norm'
      : `Norm ${group(r.norm)} ${r.norm > r.bound ? '>' : '≤'} ${group(r.bound)}`;
  const from = NAMES[m.from];
  if (r.accepted) {
    setStatus('insp', 'ok', 'gültig', `von ${from} · ${fmtMs(r.micros / 1000)} mit ${chat.engine.name}`);
  } else {
    setStatus('insp', 'bad', 'abgelehnt', `angeblich von ${from} · ${REASONS[failed] ?? ''}`);
  }
  $('insp-raw').textContent =
    `Salt ${hexOf(m.sig.subarray(1, 7))}… · Signatur ${m.sig.length} B · Nachricht ${m.msg.length} B`;
}

/** Ein Zeichen der Nachricht ändern, die Signatur bleibt dieselbe. */
async function tamper() {
  const m = chat.messages[chat.selected];
  if (!m) return;
  if (m.original === null) m.original = m.text;
  const chars = [...m.text];
  const i = chars.findIndex((ch) => /[a-zäöüA-ZÄÖÜ0-9]/.test(ch));
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
  await verifyMessage(m);
  renderChat();
}

async function restoreMessage() {
  const m = chat.messages[chat.selected];
  if (!m || m.original === null) return;
  m.text = m.original;
  m.original = null;
  m.msg = new TextEncoder().encode(m.text);
  await verifyMessage(m);
  renderChat();
}

function setSender(who) {
  chat.sender = who;
  $('as-me').setAttribute('aria-pressed', String(who === 'me'));
  $('as-alice').setAttribute('aria-pressed', String(who === 'alice'));
  $('chat-text').placeholder = who === 'me' ? 'Nachricht an Alice' : 'Antwort von Alice';
  $('chat-text').focus();
}

async function sendChat(e) {
  e.preventDefault();
  const text = $('chat-text').value.trim();
  if (!text || !chat.people) return;
  $('chat-text').value = '';
  const gen = chat.gen;
  const i = await addMessage(chat.sender, text);
  if (gen !== chat.gen) return;
  chat.selected = i;
  renderChat();
}

// ---------------------------------------------------------------- Vergleich

// Gleiche Nachricht und gleicher Seed für alle drei; danach prüft jede
// Implementierung die Signaturen der anderen.
let comparing = false;

function cmpCol(id) {
  const col = document.querySelector(`.cmp[data-impl="${id}"]`);
  return {
    set(k, v) {
      col.querySelector(`[data-k="${k}"]`).textContent = v;
    },
    state(kind, text) {
      col.classList.remove('run', 'ok', 'bad');
      if (kind) col.classList.add(kind);
      col.querySelector('[data-k="state"]').textContent = text;
    },
  };
}

async function runCompare() {
  if (comparing) return;
  comparing = true;
  $('cmp-run').disabled = true;
  const msg = new TextEncoder().encode($('cmp-msg').value);
  const seed = random(48);
  const results = {};
  $('cmp-cross').textContent = 'Jede Signatur wird von allen drei Implementierungen geprüft.';
  $('cmp-seed').textContent = 'Alle drei erzeugen ihr Schlüsselpaar aus denselben 48 Bytes.';
  for (const id of ORDER) {
    const col = cmpCol(id);
    for (const k of ['keygen', 'sign', 'verify', 'size', 'fp']) col.set(k, '–');
    col.state('', 'wartet');
  }

  for (const id of ORDER) {
    const eng = ENGINES[id];
    const col = cmpCol(id);
    try {
      col.state('run', 'lädt …');
      await eng.load();
      col.state('run', 'Keygen …');
      await nextFrame();
      const kp = await eng.keygen(logn(), seed.slice());
      col.set('keygen', fmtMs(kp.ms));
      col.set('fp', `${hexOf(kp.pk.subarray(1, 5))}…`);
      col.state('run', 'Sign …');
      await nextFrame();
      const signRuns = id === 'python' ? 3 : 10;
      let total = 0;
      let sig = null;
      for (let i = 0; i < signRuns; i++) {
        const r = await eng.sign(kp.key, msg, random(40));
        total += r.ms;
        sig = r.sig;
      }
      eng.free(kp.key);
      col.set('sign', fmtMs(total / signRuns));
      col.set('size', `${sig.length} B`);
      col.state('run', 'Verify …');
      await nextFrame();
      const v = await eng.verify(kp.pk, sig, msg, eng.timingRuns);
      col.set('verify', fmtMs(v.micros / 1000));
      results[id] = { pk: kp.pk, sig };
      col.state(v.accepted ? 'ok' : 'bad', v.accepted ? '✓ gültig' : '✕ abgelehnt');
    } catch (e) {
      col.state('bad', `Fehler: ${errText(e)}`);
    }
  }
  seed.fill(0);

  // Gegenseitig prüfen: signiert von Zeile, geprüft von Spalte
  const done = Object.keys(results);
  let ok = 0;
  const failures = [];
  for (const s of done) {
    for (const v of done) {
      try {
        const r = await ENGINES[v].verify(results[s].pk, results[s].sig, msg, 1);
        if (r.accepted) ok++;
        else failures.push(`${ENGINES[s].name} → ${ENGINES[v].name}`);
      } catch (e) {
        failures.push(`${ENGINES[s].name} → ${ENGINES[v].name}: ${errText(e)}`);
      }
    }
  }
  const total = done.length * done.length;
  const cross = $('cmp-cross');
  cross.replaceChildren();
  const head = document.createElement('span');
  head.className = failures.length ? 'bad' : 'ok';
  head.textContent = `${failures.length ? '✕' : '✓'} ${ok} von ${total} Prüfungen gültig`;
  const sub = document.createElement('small');
  sub.textContent = failures.length
    ? `abgelehnt: ${failures.join(', ')}`
    : `${done.map((id) => ENGINES[id].name).join(', ')} prüfen die Signaturen der anderen.`;
  cross.append(head, sub);

  // Gleicher Seed: welche Implementierungen kommen auf denselben Schlüssel?
  const seedBox = $('cmp-seed');
  seedBox.replaceChildren();
  const same = (a, b) => results[a] && results[b] && hexOf(results[a].pk) === hexOf(results[b].pk);
  const line = document.createElement('span');
  const note = document.createElement('small');
  if (same('c', 'python') && same('rust', 'c')) {
    line.className = 'ok';
    line.textContent = '✓ alle drei erzeugen denselben Public Key';
  } else if (same('c', 'python')) {
    line.className = 'ok';
    line.textContent = '✓ C und Python: bitgleicher Public Key';
    note.textContent =
      'Rust erzeugt Schlüssel wie die Referenzimplementierung (NIST-KAT-kompatibel) und kommt deshalb aus demselben Seed zu einem anderen Schlüssel.';
  } else {
    line.className = done.length >= 2 ? 'bad' : '';
    line.textContent = done.length >= 2 ? '✕ unterschiedliche Public Keys' : 'zu wenige Ergebnisse';
  }
  seedBox.append(line, note);

  $('cmp-run').disabled = false;
  comparing = false;
}

function updateCmpMsgMeta() {
  $('cmp-msg-meta').textContent = `${new TextEncoder().encode($('cmp-msg').value).length} B`;
}

// ---------------------------------------------------------------- Ansichten, Tastatur

function showView(name) {
  if (!(name in VIEWS)) name = 'verify';
  state.view = name;
  for (const v of Object.keys(VIEWS)) $(`view-${v}`).hidden = v !== name;
  for (const b of document.querySelectorAll('#menu [data-view]')) {
    if (b.dataset.view === name) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  }
  $('crumb').textContent = `/ ${VIEWS[name]}`;
  document.title = `Falcon · ${VIEWS[name]}`;
  $('keys-hint').hidden = name !== 'verify';
  if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
  // Schlüssel erst beim ersten Öffnen (oder nach Wechsel 512/1024) erzeugen
  if (name === 'chat' && (chat.set !== state.set || chat.engine !== engine)) chatKeys();
}

function onKey(e) {
  if (e.key === 'Escape') return closeMenus(true);
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const tag = e.target?.tagName;
  if (tag === 'TEXTAREA' || tag === 'INPUT' || tag === 'SELECT') return;
  if ($('own-dialog').open) return;
  if (!$('menu').hidden || !$('impl-menu').hidden) return;
  if (e.key === '1') return setSet('512');
  if (e.key === '2') return setSet('1024');
  if (state.view !== 'verify') return;
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
  $('menu-btn').addEventListener('click', () => toggleMenu('menu-btn'));
  $('impl-btn').addEventListener('click', () => toggleMenu('impl-btn'));
  $('menu').addEventListener('keydown', menuKeys);
  $('impl-menu').addEventListener('keydown', menuKeys);
  for (const b of document.querySelectorAll('#menu [data-view]')) {
    b.addEventListener('click', () => {
      closeMenus(true);
      showView(b.dataset.view);
    });
  }
  for (const b of document.querySelectorAll('#impl-menu [data-impl]')) {
    b.addEventListener('click', () => setEngine(b.dataset.impl));
  }
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.nav, .impl')) closeMenus(false);
  });
  window.addEventListener('hashchange', () => showView(location.hash.slice(1)));

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

  $('cmp-run').addEventListener('click', runCompare);
  $('cmp-msg').addEventListener('input', updateCmpMsgMeta);
  document.addEventListener('keydown', onKey);
}

async function main() {
  try {
    await ENGINES.rust.load();
    const res = await fetch('kat.json');
    if (!res.ok) throw new Error(`kat.json: HTTP ${res.status}`);
    state.kat = await res.json();
  } catch (e) {
    setStatus('status', 'bad', 'nicht geladen', errText(e));
    $('version').textContent = 'WASM nicht geladen – UI/build.sh ausführen';
    return;
  }
  // zuletzt gewählte Implementierung; Python lädt erst bei Bedarf
  let saved = null;
  try {
    saved = localStorage.getItem('fndsa-impl');
  } catch {}
  if (saved === 'c' || saved === 'python') {
    try {
      await ENGINES[saved].load();
      engine = ENGINES[saved];
    } catch {}
  }
  ENGINES.c.load().catch(() => {});
  wire();
  renderEngine();
  updateSignMsgMeta();
  updateCmpMsgMeta();
  setSet('512');
  dropKeypair();
  showView(location.hash.slice(1));
}

main();
