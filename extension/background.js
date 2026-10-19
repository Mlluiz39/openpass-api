// OpenPass browser extension — background service worker (Manifest V3).
//
// All network access to the vault happens here rather than in the content
// script: the API key stays out of pages, and a compromised page can only ask
// for the entries that match its own origin.

const DEFAULTS = {
  serverUrl: "https://openpass.mlluizdevtech.com.br",
  apiKey: "",
  autoFillOnLoad: true,
  askToSave: true,
};

async function getConfig() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...stored };
}

function normalizeServer(url) {
  const trimmed = String(url || "").trim().replace(/\/+$/, "");
  return trimmed;
}

async function api(path, { method = "GET", body, query } = {}) {
  const cfg = await getConfig();
  const base = normalizeServer(cfg.serverUrl);
  if (!base) throw new Error("Servidor não configurado. Abra as opções da extensão.");
  if (!cfg.apiKey) throw new Error("Chave de API não configurada. Abra as opções da extensão.");

  const url = new URL(base + path);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    }
  }

  let res;
  try {
    res = await fetch(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${cfg.apiKey}`,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    throw new Error("Não consegui falar com o OpenPass. Confira a URL do servidor.");
  }

  if (res.status === 401 || res.status === 403) {
    throw new Error("Chave de API inválida ou sem permissão (precisa de entries:read e entries:write).");
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).error || "";
    } catch {
      /* a non-JSON error body is fine, the status alone is enough */
    }
    throw new Error(detail || `O servidor respondeu ${res.status}.`);
  }
  if (res.status === 204) return null;
  return res.json();
}

// ----------------------------------------------------------------- storage

// A submitted form is remembered until the page settles, so the save banner
// can appear on the page the browser actually lands on.
const PENDING_KEY = "pendingSave";

async function setPending(pending) {
  await chrome.storage.session.set({ [PENDING_KEY]: pending });
}

async function takePending(origin) {
  const { [PENDING_KEY]: pending } = await chrome.storage.session.get(PENDING_KEY);
  if (!pending) return null;
  await chrome.storage.session.remove(PENDING_KEY);
  // Only offer the banner on the same site the credentials were typed into.
  if (pending.origin && origin && pending.origin !== origin) return null;
  return pending;
}

// -------------------------------------------------------------- operations

async function getMatches(rawUrl, reveal = false) {
  const res = await api("/api/v1/entries/match", {
    query: { url: rawUrl, reveal: reveal ? "1" : "" },
  });
  return (res && res.data) || [];
}

// entryNameFor derives a human name for a new entry: the bare host, which is
// how Chrome's own export names things.
function entryNameFor(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return u.hostname.replace(/^www\./, "");
  } catch {
    return rawUrl;
  }
}

async function saveLogin({ url, username, password, vaultId }) {
  const payload = {
    path: entryNameFor(url),
    type: "login",
    value: password,
    metadata: { url, username },
    tags: ["extension"],
  };
  if (vaultId) payload.vault_id = vaultId;

  const res = await api("/api/v1/entries", { method: "POST", body: payload });
  return res.entry || res.data || res;
}

async function updatePassword(entryId, password) {
  // The API's PUT replaces the entry, so the existing metadata is preserved by
  // reading it first — a password change must never drop the username.
  const current = await api(`/api/v1/entries/${entryId}`);
  const entry = current.entry || current.data || current;
  return api(`/api/v1/entries/${entryId}`, {
    method: "PUT",
    body: {
      vault_id: entry.vault_id,
      path: entry.path,
      type: entry.type,
      value: password,
      metadata: entry.metadata || {},
      tags: entry.tags || [],
    },
  });
}

// ---------------------------------------------------------------- 2FA codes

// getCode fetches the current one-time password for an entry. The code is
// short-lived by design (30s), so it is never cached here.
async function getCode(entryId) {
  return api(`/api/v1/entries/${entryId}/code`);
}

// generatePassword asks the server for a fresh random password, so the
// generator shares one implementation with the web panel.
async function generatePassword(options) {
  return api("/api/v1/password/generate", { method: "POST", body: options || {} });
}

async function testConnection() {
  const res = await api("/api/v1/vaults");
  const vaults = (res && res.data) || [];
  return { ok: true, vaults: vaults.length };
}

// --------------------------------------------------------------- messaging

const handlers = {
  getConfig,
  saveConfig: async ({ config }) => {
    await chrome.storage.local.set(config);
    return getConfig();
  },
  getMatches: async ({ url, reveal }) => getMatches(url, reveal),
  saveLogin,
  updatePassword: async ({ entryId, password }) => updatePassword(entryId, password),
  getCode: async ({ entryId }) => getCode(entryId),
  generatePassword: async ({ options }) => generatePassword(options),
  testConnection,
  takePending: async ({ origin }) => takePending(origin),
  setPending,
  fillTab: async ({ tabId, entryId, username, password }) => {
    await chrome.tabs.sendMessage(tabId, {
      type: "fillCredentials",
      entryId,
      username,
      password,
    });
    return { ok: true };
  },
  notify: async ({ message }) => {
    await chrome.notifications?.create?.({
      type: "basic",
      iconUrl: "icons/icon-128.png",
      title: "OpenPass",
      message,
    });
    return { ok: true };
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false;

  Promise.resolve(handler(msg, sender))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
  return true; // keep the channel open for the async response
});

// A visitor lands on the page a form submitted to; hand the content script the
// pending credentials so it can offer to save them.
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== "complete" || !tab.url) return;
  const cfg = await getConfig();
  if (!cfg.askToSave) return;

  let origin;
  try {
    origin = new URL(tab.url).origin;
  } catch {
    return;
  }

  const { [PENDING_KEY]: pending } = await chrome.storage.session.get(PENDING_KEY);
  if (!pending || pending.origin !== origin) return;

  try {
    await chrome.tabs.sendMessage(tabId, { type: "showSaveBanner", pending });
  } catch {
    // No content script on this page (chrome://, PDF viewer, ...): leave the
    // pending save for the next page that can host the banner.
  }
});
