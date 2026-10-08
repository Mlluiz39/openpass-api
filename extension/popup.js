// OpenPass browser extension — popup.
//
// Shows the logins for the active tab; clicking one asks the background worker
// for the secret and hands it to the content script to fill.

const statusEl = document.getElementById("status");
const listEl = document.getElementById("list");
const codeEl = document.getElementById("codePanel");

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

function render(children) {
  listEl.replaceChildren(...children);
}

function message(text, className) {
  const div = document.createElement("div");
  div.className = className;
  div.textContent = text;
  return div;
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function useMatch(tabId, entryId, username, password) {
  await send("fillTab", { tabId, entryId, username, password });
  window.close();
}

// --- 2FA panel: shows a live code and copies it on click.
function hideCodePanel() {
  codeEl.style.display = "none";
  codeEl.replaceChildren();
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

async function showCode(entry) {
  const res = await send("getCode", { entryId: entry.id });
  if (!res.ok) {
    hideCodePanel();
    return;
  }
  const { code, seconds_remaining } = res.data;

  codeEl.style.display = "block";
  const label = document.createElement("div");
  label.className = "user";
  label.textContent = `Código 2FA — ${entry.path}`;

  const value = document.createElement("button");
  value.className = "code";
  value.textContent = code;
  value.title = "Clique para copiar";
  value.addEventListener("click", async () => {
    const ok = await copyToClipboard(value.textContent);
    label.textContent = ok ? "Código copiado!" : "Não consegui copiar";
    setTimeout(() => {
      label.textContent = `Código 2FA — ${entry.path}`;
    }, 1500);
  });

  const timer = document.createElement("div");
  timer.className = "user";
  let remaining = seconds_remaining;
  timer.textContent = `${remaining}s restantes`;

  const tick = setInterval(async () => {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(tick);
      const fresh = await send("getCode", { entryId: entry.id });
      if (fresh.ok) {
        // Refresh in place: silently replacing a value that may already be in
        // the user's clipboard would be surprising.
        value.textContent = fresh.data.code;
        remaining = fresh.data.seconds_remaining;
        timer.textContent = `${remaining}s restantes`;
      }
      return;
    }
    timer.textContent = `${remaining}s restantes`;
  }, 1000);

  codeEl.replaceChildren(label, value, timer);
  await copyToClipboard(code);
}

async function load() {
  statusEl.textContent = "…";
  const tab = await activeTab();
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    statusEl.textContent = "n/d";
    render([message("Esta página não aceita preenchimento (apenas http/https).", "empty")]);
    return;
  }

  const res = await send("getMatches", { url: tab.url });
  if (!res.ok) {
    statusEl.textContent = "erro";
    render([
      message(res.error, "error"),
      message("Confira a URL do servidor e a chave de API em Configurar.", "empty"),
    ]);
    return;
  }

  const matches = res.data || [];
  statusEl.textContent = `${matches.length} login${matches.length === 1 ? "" : "s"}`;

  if (!matches.length) {
    render([message("Nenhum login salvo para este site.", "empty")]);
    return;
  }

  render(
    matches.map((m) => {
      const wrap = document.createElement("div");
      wrap.className = "row";

      const btn = document.createElement("button");
      btn.className = "item";

      const name = document.createElement("span");
      name.className = "name";
      name.textContent = m.entry.path;

      const user = document.createElement("span");
      user.className = "user";
      user.textContent = m.entry.metadata?.username || "sem usuário";

      btn.append(name, user);
      btn.addEventListener("click", async () => {
        btn.querySelector(".user").textContent = "buscando…";
        // The panel never reveals the secret; the background worker sends it
        // straight to the page's content script.
        const reveal = await send("getMatches", { url: tab.url, reveal: true });
        if (!reveal.ok) {
          btn.querySelector(".user").textContent = reveal.error;
          return;
        }
        const match = (reveal.data || []).find((x) => x.entry.id === m.entry.id);
        if (!match) {
          btn.querySelector(".user").textContent = "não encontrado";
          return;
        }
        // Hand the values over without ever putting them in this UI.
        await send("fillTab", {
          tabId: tab.id,
          entryId: m.entry.id,
          username: match.entry.metadata?.username || "",
          password: match.value,
        });
        window.close();
      });
      wrap.appendChild(btn);

      // The 2FA button appears only for entries that carry a secret.
      if (m.entry.has_totp) {
        const totp = document.createElement("button");
        totp.className = "totp";
        totp.textContent = "🔐";
        totp.title = "Ver código 2FA";
        totp.addEventListener("click", async (e) => {
          e.stopPropagation();
          totp.disabled = true;
          await showCode(m.entry);
          totp.disabled = false;
        });
        wrap.appendChild(totp);
      }

      return wrap;
    })
  );
}

document.getElementById("openOptions").addEventListener("click", () => chrome.runtime.openOptionsPage());
document.getElementById("reload").addEventListener("click", load);
load();
