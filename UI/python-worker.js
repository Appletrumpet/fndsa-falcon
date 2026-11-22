// Python-Implementierung im Browser (UI/README.md): Pyodide in einem Web
// Worker, damit lange Rechnungen (Keygen dauert Sekunden) die Seite nicht
// blockieren. Nachrichten: { id, op, args } → { id, ok, value | error }.
// op ist eine Funktion aus py/webapi.py.

const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/v0.26.4/full/';
importScripts(`${PYODIDE}pyodide.js`);

async function boot() {
  const py = await loadPyodide({ indexURL: PYODIDE });
  const files = await (await fetch('py/files.json')).json();
  py.FS.mkdirTree('/home/pyodide/falcon');
  for (const f of [...files, 'webapi.py']) {
    const res = await fetch(`py/${f}`);
    if (!res.ok) throw new Error(`py/${f}: HTTP ${res.status}`);
    py.FS.writeFile(`/home/pyodide/${f}`, await res.text());
  }
  py.runPython("import sys; sys.path.insert(0, '/home/pyodide')");
  return { api: py.pyimport('webapi'), version: py.version };
}

const ready = boot();

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    const { api, version } = await ready;
    if (op === 'version') {
      self.postMessage({ id, ok: true, value: version });
      return;
    }
    const r = api[op](...args);
    const value = r?.toJs ? r.toJs({ dict_converter: Object.fromEntries }) : r;
    r?.destroy?.();
    self.postMessage({ id, ok: true, value });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
  }
};
