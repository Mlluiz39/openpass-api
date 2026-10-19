// OpenPass browser extension — options page.
//
// The API key is stored in chrome.storage.local (never synced) and is only
// ever sent to the server URL configured here.

const DEFAULTS = {
  serverUrl: "https://openpass.mlluizdevtech.com.br",
  apiKey: "",
  autoFillOnLoad: true,
  askToSave: true,
};

const els = {
  serverUrl: document.getElementById("serverUrl"),
  apiKey: document.getElementById("apiKey"),
  autoFillOnLoad: document.getElementById("autoFillOnLoad"),
  askToSave: document.getElementById("askToSave"),
  result: document.getElementById("result"),
  save: document.getElementById("save"),
  test: document.getElementById("test"),
};

function send(type, extra) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...(extra || {}) }, (res) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      resolve(res || { ok: false, error: "sem resposta" });
    });
  });
}

function setResult(text, kind) {
  els.result.textContent = text;
  els.result.className = kind || "";
}

function readForm() {
  return {
    serverUrl: els.serverUrl.value.trim().replace(/\/+$/, ""),
    apiKey: els.apiKey.value.trim(),
    autoFillOnLoad: els.autoFillOnLoad.checked,
    askToSave: els.askToSave.checked,
  };
}

async function load() {
  const cfg = { ...DEFAULTS, ...(await chrome.storage.local.get(DEFAULTS)) };
  els.serverUrl.value = cfg.serverUrl;
  els.apiKey.value = cfg.apiKey;
  els.autoFillOnLoad.checked = !!cfg.autoFillOnLoad;
  els.askToSave.checked = !!cfg.askToSave;
}

els.save.addEventListener("click", async () => {
  const cfg = readForm();
  if (!cfg.serverUrl) {
    setResult("Informe a URL do servidor.", "err");
    return;
  }
  await send("saveConfig", { config: cfg });
  setResult("Configurações salvas.", "ok");
});

els.test.addEventListener("click", async () => {
  setResult("Testando…", "");
  // Testing an unsaved form is the common case, so save first.
  await send("saveConfig", { config: readForm() });
  const res = await send("testConnection");
  if (!res.ok) {
    setResult(res.error, "err");
    return;
  }
  setResult(`Conectado. ${res.data.vaults} cofre(s) visível(is) para esta chave.`, "ok");
});

load();
