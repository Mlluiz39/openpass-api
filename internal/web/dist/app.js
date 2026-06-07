const app = document.querySelector("#app");

const state = {
  view: "dashboard",
  theme: localStorage.getItem("openpass_theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  keys: [],
  vaults: [],
  entries: [],
  logs: [],
  backups: [],
  revealed: {},
  message: "",
  mobileMenuOpen: false,
  editingVaultId: null,
  backupHistoryOpen: false,
};

const permissions = [
  "vaults:read",
  "vaults:write",
  "entries:read",
  "entries:write",
  "backup:create",
  "backup:restore",
  "audit:read",
];

applyTheme();

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  document.documentElement.style.colorScheme = state.theme;
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  localStorage.setItem("openpass_theme", state.theme);
  applyTheme();
  renderShell();
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "include",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error((data && data.error) || res.statusText);
  }
  return data;
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function splitList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function permObject(form) {
  const out = {};
  form.querySelectorAll("[data-perm]").forEach((input) => {
    out[input.value] = input.checked;
  });
  return out;
}

async function boot() {
  try {
    await api("/api/admin/me");
    await loadAll();
    renderShell();
  } catch {
    renderLogin();
  }
}

function renderLogin(error = "") {
  app.innerHTML = `
    <main class="login">
      <button class="theme-float" id="loginThemeBtn" type="button">${state.theme === "dark" ? "Light" : "Dark"}</button>
      <section class="login-panel">
        <div class="login-mark"><span class="mark-box">OP</span> OpenPass</div>
        <h1>Secret manager local para agentes e rotinas.</h1>
        <p>Um painel compacto para copiar chaves, guardar credenciais e auditar acessos sem subir uma stack pesada.</p>
        <form class="login-form" id="loginForm">
          <label>Senha admin<input type="password" name="password" autocomplete="current-password" required /></label>
          <button class="btn green" type="submit">Entrar</button>
          ${error ? `<div class="error">${escapeHTML(error)}</div>` : ""}
        </form>
      </section>
      <section class="login-stage">
        <div class="stage-board">
          <div class="stage-row">
            <div class="stage-cell"><strong>API keys</strong><div>Crie, revele, copie e revogue tokens.</div></div>
            <div class="stage-cell"><strong>Secrets</strong><div>Valores criptografados no SQLite.</div></div>
            <div class="stage-cell"><strong>Logs</strong><div>Auditoria por IP, rota e status.</div></div>
          </div>
          <div class="stage-cell"><strong>Deploy</strong><div>Um binario Go servindo API e painel CRM.</div></div>
        </div>
      </section>
    </main>
  `;
  document.querySelector("#loginThemeBtn").addEventListener("click", () => {
    state.theme = state.theme === "dark" ? "light" : "dark";
    localStorage.setItem("openpass_theme", state.theme);
    applyTheme();
    renderLogin(error);
  });
  document.querySelector("#loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = new FormData(event.currentTarget).get("password");
    try {
      await api("/api/admin/login", { method: "POST", body: JSON.stringify({ password }) });
      await loadAll();
      renderShell();
    } catch (err) {
      renderLogin(err.message);
    }
  });
}

async function loadAll() {
  const [keys, vaults, entries, logs, backups] = await Promise.all([
    api("/api/admin/keys").catch(() => ({ data: [] })),
    api("/api/admin/vaults").catch(() => ({ data: [] })),
    api("/api/admin/entries").catch(() => ({ data: [] })),
    api("/api/admin/audit-logs?limit=80").catch(() => ({ data: [] })),
    api("/api/admin/backups").catch(() => ({ data: [] })),
  ]);
  state.keys = keys.data || [];
  state.vaults = vaults.data || [];
  state.entries = entries.data || [];
  state.logs = logs.data || [];
  state.backups = backups.data || [];
}

function renderShell() {
  app.innerHTML = `
    <div class="app-shell ${state.mobileMenuOpen ? "menu-open" : ""}">
      <div class="mobile-bar">
        <button class="hamburger ${state.mobileMenuOpen ? "active" : ""}" id="menuBtn" type="button" aria-label="${state.mobileMenuOpen ? "Fechar menu" : "Abrir menu"}" aria-expanded="${state.mobileMenuOpen ? "true" : "false"}" aria-controls="sideMenu"><span></span><span></span><span></span></button>
        <div class="mobile-brand"><span class="mark-box">OP</span> OpenPass</div>
      </div>
      <button class="menu-backdrop" id="menuBackdrop" type="button" aria-label="Fechar menu"></button>
      <aside class="sidebar" id="sideMenu">
        <div class="brand"><span class="mark-box">OP</span> OpenPass</div>
        <nav class="nav">
          ${navButton("dashboard", "Dashboard", "01")}
          ${navButton("keys", "API Keys", "02")}
          ${navButton("vaults", "Cofres", "03")}
          ${navButton("entries", "Secrets", "04")}
          ${navButton("backup", "Backup", "05")}
          ${navButton("logs", "Logs", "06")}
        </nav>
        <div class="sidebar-tools">
          <button class="theme-button" id="themeBtn" type="button"><span>Tema</span><b>${state.theme === "dark" ? "Dark" : "Light"}</b></button>
          <button class="logout-button" id="logoutBtn" type="button"><span>Sair</span><b>--</b></button>
        </div>
      </aside>
      <main class="main">
        <div id="view"></div>
      </main>
    </div>
  `;
  document.querySelector("#menuBtn").addEventListener("click", () => {
    state.mobileMenuOpen = !state.mobileMenuOpen;
    renderShell();
  });
  document.querySelector("#menuBackdrop").addEventListener("click", () => {
    state.mobileMenuOpen = false;
    renderShell();
  });
  document.querySelectorAll("[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.view = btn.dataset.view;
      state.mobileMenuOpen = false;
      renderShell();
    });
  });
  document.querySelector("#themeBtn").addEventListener("click", toggleTheme);
  document.querySelector("#logoutBtn").addEventListener("click", async () => {
    await api("/api/admin/logout", { method: "POST", body: "{}" });
    renderLogin();
  });
  renderView();
}

function navButton(view, label, code) {
  return `<button class="${state.view === view ? "active" : ""}" data-view="${view}"><span>${label}</span><b>${code}</b></button>`;
}

function renderView() {
  if (state.view === "keys") return renderKeys();
  if (state.view === "vaults") return renderVaults();
  if (state.view === "entries") return renderEntries();
  if (state.view === "backup") return renderBackup();
  if (state.view === "logs") return renderLogs();
  return renderDashboard();
}

function header(title, eyebrow) {
  return `
    <div class="topbar">
      <div><div class="eyebrow">${eyebrow}</div><h2>${title}</h2></div>
      <button class="btn ghost" id="refreshBtn">Atualizar</button>
    </div>
  `;
}

function attachRefresh() {
  document.querySelector("#refreshBtn")?.addEventListener("click", async () => {
    await loadAll();
    renderShell();
  });
}

function renderDashboard() {
  const activeKeys = state.keys.filter((key) => key.is_active).length;
  const denied = state.logs.filter((log) => log.result === "denied").length;
  document.querySelector("#view").innerHTML = `
    ${header("Painel operacional", "Visao geral")}
    <section class="grid metrics">
      ${metric("Keys ativas", activeKeys)}
      ${metric("Cofres", state.vaults.length)}
      ${metric("Secrets", state.entries.length)}
      ${metric("Backups", state.backups.length)}
    </section>
    <section class="panel" style="margin-top:14px">
      <div class="panel-head"><div class="panel-title">Ultimos acessos</div></div>
      ${logsTable(state.logs.slice(0, 8))}
    </section>
  `;
  attachRefresh();
}

function metric(label, value) {
  return `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`;
}

function renderKeys() {
  document.querySelector("#view").innerHTML = `
    ${header("API Keys", "Agentes e automacoes")}
    ${state.message ? `<p class="notice">${state.message}</p>` : ""}
    <section class="panel">
      <div class="panel-head"><div class="panel-title">Nova key</div></div>
      <form class="form-grid" id="keyForm">
        <label>Nome<input name="name" required placeholder="Claude Code local" /></label>
        <label>Ambiente<select name="env"><option value="live">live</option><option value="test">test</option></select></label>
        <label>Rate RPM<input name="rate_limit_rpm" type="number" min="1" value="60" /></label>
        <label>Allowed IPs<input name="allowed_ips" placeholder="203.0.113.0/24, 10.0.0.5" /></label>
        <label class="span-2">Vault scope<input name="vault_scope" placeholder="IDs separados por virgula" /></label>
        <label class="span-2">Descricao<input name="description" placeholder="Uso desta key" /></label>
        <div class="span-4">
          <div class="checks">${permissions.map((perm) => `<label class="check"><input data-perm type="checkbox" value="${perm}" ${perm.endsWith(":read") ? "checked" : ""}/> ${perm}</label>`).join("")}</div>
        </div>
        <button class="btn green" type="submit">Criar key</button>
      </form>
      ${keysTable()}
    </section>
  `;
  state.message = "";
  attachRefresh();
  document.querySelector("#keyForm").addEventListener("submit", createKey);
  document.querySelectorAll("[data-reveal-key]").forEach((btn) => btn.addEventListener("click", revealKey));
  document.querySelectorAll("[data-revoke-key]").forEach((btn) => btn.addEventListener("click", revokeKey));
  document.querySelectorAll("[data-delete-key]").forEach((btn) => btn.addEventListener("click", deleteKey));
  document.querySelectorAll("[data-copy]").forEach((btn) => btn.addEventListener("click", copyRevealed));
}

function keysTable() {
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Nome</th><th>Prefixo</th><th>Status</th><th>Permissoes</th><th>Uso</th><th>Acoes</th></tr></thead>
      <tbody>
        ${state.keys.map((key) => `
          <tr>
            <td><strong>${escapeHTML(key.name)}</strong><br><span class="mono">${escapeHTML(key.id)}</span></td>
            <td class="mono">${escapeHTML(key.key_prefix)}...${escapeHTML(key.key_suffix)}</td>
            <td>${key.is_active ? `<span class="badge green">ativa</span>` : `<span class="badge red">revogada</span>`}</td>
            <td>${Object.entries(key.permissions || {}).filter(([, v]) => v).map(([k]) => `<span class="badge">${escapeHTML(k)}</span>`).join(" ")}</td>
            <td>${escapeHTML(key.last_used_at || "sem uso")}</td>
            <td>
              <div class="actions">
                <button class="btn blue" data-reveal-key="${key.id}">Revelar</button>
                <button class="btn ghost" data-revoke-key="${key.id}">Revogar</button>
                <button class="btn red" data-delete-key="${key.id}">Excluir</button>
              </div>
              ${state.revealed[key.id] ? `<div class="secret-box mono">${escapeHTML(state.revealed[key.id])}<br><button class="btn ghost" data-copy="${key.id}">Copiar</button></div>` : ""}
            </td>
          </tr>
        `).join("") || `<tr><td colspan="6">Nenhuma key criada.</td></tr>`}
      </tbody>
    </table></div>
  `;
}

async function createKey(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const created = await api("/api/admin/keys", {
    method: "POST",
    body: JSON.stringify({
      name: data.get("name"),
      env: data.get("env"),
      description: data.get("description"),
      rate_limit_rpm: Number(data.get("rate_limit_rpm") || 60),
      allowed_ips: splitList(data.get("allowed_ips")),
      vault_scope: splitList(data.get("vault_scope")),
      permissions: permObject(form),
    }),
  });
  state.revealed[created.id] = created.token;
  state.message = "Key criada. O token completo tambem esta salvo criptografado e pode ser revelado depois.";
  await loadAll();
  renderShell();
}

async function revealKey(event) {
  const id = event.currentTarget.dataset.revealKey;
  const data = await api(`/api/admin/keys/${id}/reveal`);
  state.revealed[id] = data.token;
  renderShell();
}

async function revokeKey(event) {
  await api(`/api/admin/keys/${event.currentTarget.dataset.revokeKey}/revoke`, { method: "PATCH", body: "{}" });
  await loadAll();
  renderShell();
}

async function deleteKey(event) {
  await api(`/api/admin/keys/${event.currentTarget.dataset.deleteKey}`, { method: "DELETE", body: "" });
  await loadAll();
  renderShell();
}

function renderVaults() {
  const editing = state.vaults.find((vault) => vault.id === state.editingVaultId);
  document.querySelector("#view").innerHTML = `
    ${header("Cofres", "Organizacao")}
    <section class="panel">
      <div class="panel-head"><div class="panel-title">${editing ? "Editar cofre" : "Novo cofre"}</div></div>
      <form class="form-grid" id="vaultForm">
        <label>Nome<input name="name" required placeholder="Producao" value="${escapeHTML(editing?.name || "")}" /></label>
        <label class="span-2">Descricao<input name="description" placeholder="Ambiente, cliente ou projeto" value="${escapeHTML(editing?.description || "")}" /></label>
        <button class="btn green" type="submit">${editing ? "Salvar alteracoes" : "Criar cofre"}</button>
        ${editing ? `<button class="btn ghost" type="button" id="cancelVaultEdit">Cancelar</button>` : ""}
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>Nome</th><th>ID</th><th>Descricao</th><th>Atualizado</th><th>Acoes</th></tr></thead>
        <tbody>${state.vaults.map((vault) => `
          <tr>
            <td><strong>${escapeHTML(vault.name)}</strong></td>
            <td class="mono">${escapeHTML(vault.id)}</td>
            <td>${escapeHTML(vault.description || "")}</td>
            <td>${escapeHTML(vault.updated_at)}</td>
            <td>
              <div class="actions">
                <button class="btn ghost" data-edit-vault="${vault.id}">Editar</button>
                <button class="btn red" data-delete-vault="${vault.id}">Excluir</button>
              </div>
            </td>
          </tr>
        `).join("") || `<tr><td colspan="5">Nenhum cofre.</td></tr>`}</tbody>
      </table></div>
    </section>
  `;
  attachRefresh();
  document.querySelector("#vaultForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    if (state.editingVaultId) {
      await api(`/api/admin/vaults/${state.editingVaultId}`, { method: "PUT", body: JSON.stringify({ name: data.get("name"), description: data.get("description") }) });
      state.editingVaultId = null;
    } else {
      await api("/api/admin/vaults", { method: "POST", body: JSON.stringify({ name: data.get("name"), description: data.get("description") }) });
    }
    await loadAll();
    renderShell();
  });
  document.querySelector("#cancelVaultEdit")?.addEventListener("click", () => {
    state.editingVaultId = null;
    renderShell();
  });
  document.querySelectorAll("[data-edit-vault]").forEach((btn) => btn.addEventListener("click", (event) => {
    state.editingVaultId = event.currentTarget.dataset.editVault;
    renderShell();
  }));
  document.querySelectorAll("[data-delete-vault]").forEach((btn) => btn.addEventListener("click", deleteVault));
}

async function deleteVault(event) {
  const id = event.currentTarget.dataset.deleteVault;
  const vault = state.vaults.find((item) => item.id === id);
  const related = state.entries.filter((entry) => entry.vault_id === id).length;
  const ok = confirm(`Excluir o cofre "${vault?.name || id}"? ${related ? `Isso tambem remove ${related} secret(s).` : ""}`);
  if (!ok) return;
  await api(`/api/admin/vaults/${id}`, { method: "DELETE", body: "" });
  if (state.editingVaultId === id) state.editingVaultId = null;
  await loadAll();
  renderShell();
}

function renderEntries() {
  document.querySelector("#view").innerHTML = `
    ${header("Secrets", "Credenciais copiaveis")}
    <section class="panel">
      <div class="panel-head"><div class="panel-title">Novo secret</div></div>
      <form class="form-grid" id="entryForm">
        <label>Cofre<select name="vault_id" required>${state.vaults.map((vault) => `<option value="${vault.id}">${escapeHTML(vault.name)}</option>`).join("")}</select></label>
        <label>Path<input name="path" required placeholder="database/password" /></label>
        <label>Tipo<input name="type" required value="password" /></label>
        <label>Tags<input name="tags" placeholder="database, prod" /></label>
        <label class="span-4">Valor<textarea name="value" required placeholder="secret"></textarea></label>
        <button class="btn green" type="submit">Salvar secret</button>
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>Path</th><th>Cofre</th><th>Tipo</th><th>Tags</th><th>Acoes</th></tr></thead>
        <tbody>${state.entries.map(entryRow).join("") || `<tr><td colspan="5">Nenhum secret.</td></tr>`}</tbody>
      </table></div>
    </section>
  `;
  attachRefresh();
  document.querySelector("#entryForm").addEventListener("submit", createEntry);
  document.querySelectorAll("[data-reveal-entry]").forEach((btn) => btn.addEventListener("click", revealEntry));
  document.querySelectorAll("[data-delete-entry]").forEach((btn) => btn.addEventListener("click", deleteEntry));
  document.querySelectorAll("[data-copy]").forEach((btn) => btn.addEventListener("click", copyRevealed));
}

function entryRow(entry) {
  const vault = state.vaults.find((item) => item.id === entry.vault_id);
  return `
    <tr>
      <td><strong>${escapeHTML(entry.path)}</strong><br><span class="mono">${escapeHTML(entry.id)}</span></td>
      <td>${escapeHTML(vault ? vault.name : entry.vault_id)}</td>
      <td><span class="badge amber">${escapeHTML(entry.type)}</span></td>
      <td>${(entry.tags || []).map((tag) => `<span class="badge">${escapeHTML(tag)}</span>`).join(" ")}</td>
      <td>
        <div class="actions">
          <button class="btn blue" data-reveal-entry="${entry.id}">Revelar</button>
          <button class="btn red" data-delete-entry="${entry.id}">Excluir</button>
        </div>
        ${state.revealed[entry.id] ? `<div class="secret-box mono">${escapeHTML(state.revealed[entry.id])}<br><button class="btn ghost" data-copy="${entry.id}">Copiar</button></div>` : ""}
      </td>
    </tr>
  `;
}

async function createEntry(event) {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  await api("/api/admin/entries", {
    method: "POST",
    body: JSON.stringify({
      vault_id: data.get("vault_id"),
      path: data.get("path"),
      type: data.get("type"),
      value: data.get("value"),
      tags: splitList(data.get("tags")),
    }),
  });
  await loadAll();
  renderShell();
}

async function revealEntry(event) {
  const id = event.currentTarget.dataset.revealEntry;
  const data = await api(`/api/admin/entries/${id}/reveal`);
  state.revealed[id] = data.value;
  renderShell();
}

async function deleteEntry(event) {
  await api(`/api/admin/entries/${event.currentTarget.dataset.deleteEntry}`, { method: "DELETE", body: "" });
  await loadAll();
  renderShell();
}

function renderBackup() {
  document.querySelector("#view").innerHTML = `
    ${header("Backup criptografado", "Exportar e restaurar")}
    ${state.message ? `<p class="notice">${state.message}</p>` : ""}
    <section class="grid backup-grid">
      <div class="panel">
        <div class="panel-head"><div class="panel-title">Gerar backup</div></div>
        <form class="form-grid compact-form" id="backupExportForm">
          <label class="span-2">Senha opcional<input type="password" name="password" autocomplete="new-password" placeholder="vazio usa a chave do app" /></label>
          <div class="span-4 backup-note">Use uma senha se quiser restaurar em outra maquina sem depender do arquivo <span class="mono">data/openpass.secret</span>.</div>
          <button class="btn green" type="submit">Baixar .opbackup</button>
        </form>
      </div>
      <div class="panel">
        <div class="panel-head"><div class="panel-title">Restaurar backup</div></div>
        <form class="form-grid compact-form" id="backupRestoreForm">
          <label class="span-2">Arquivo .opbackup<input type="file" name="file" accept=".opbackup,application/json" required /></label>
          <label class="span-2">Senha<input type="password" name="password" autocomplete="new-password" placeholder="mesma senha usada no export" /></label>
          <div class="span-4 backup-note danger">Restaurar substitui keys, cofres, secrets e logs atuais. As sessoes admin permanecem.</div>
          <button class="btn red" type="submit">Restaurar agora</button>
        </form>
      </div>
    </section>
    <section class="panel" style="margin-top:14px">
      <div class="panel-head">
        <div class="panel-title">Historico local <span class="badge">${state.backups.length}</span></div>
        <div class="actions">
          <button class="btn ghost" id="toggleBackupHistory">${state.backupHistoryOpen ? "Ocultar" : "Mostrar"}</button>
          <button class="btn red" id="clearBackupHistory">Limpar historico</button>
        </div>
      </div>
      ${state.backupHistoryOpen ? `
        <div class="table-wrap"><table>
          <thead><tr><th>Arquivo</th><th>Status</th><th>Formato</th><th>Tamanho</th><th>Quando</th></tr></thead>
          <tbody>${state.backups.map((item) => `
            <tr>
              <td class="mono">${escapeHTML(item.filename)}</td>
              <td><span class="badge ${item.status === "restored" ? "amber" : "green"}">${escapeHTML(item.status)}</span></td>
              <td>${escapeHTML(item.format)}</td>
              <td>${escapeHTML(item.size_bytes || 0)} bytes</td>
              <td>${escapeHTML(item.created_at || "")}</td>
            </tr>
          `).join("") || `<tr><td colspan="5">Nenhum backup registrado.</td></tr>`}</tbody>
        </table></div>
      ` : `<div class="panel-empty">Historico recolhido para manter a tela limpa.</div>`}
    </section>
  `;
  state.message = "";
  attachRefresh();
  document.querySelector("#backupExportForm").addEventListener("submit", exportBackup);
  document.querySelector("#backupRestoreForm").addEventListener("submit", restoreBackup);
  document.querySelector("#toggleBackupHistory").addEventListener("click", () => {
    state.backupHistoryOpen = !state.backupHistoryOpen;
    renderShell();
  });
  document.querySelector("#clearBackupHistory").addEventListener("click", clearBackupHistory);
}

async function exportBackup(event) {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const res = await fetch("/api/admin/backup/export", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: data.get("password") }),
  });
  if (!res.ok) {
    throw new Error("backup_export_failed");
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match ? match[1] : "openpass-backup.opbackup";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
  state.message = "Backup criptografado gerado e baixado.";
  await loadAll();
  renderShell();
}

async function restoreBackup(event) {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const file = data.get("file");
  if (!file) return;
  const backup = await file.text();
  await api("/api/admin/backup/restore", {
    method: "POST",
    body: JSON.stringify({ password: data.get("password"), backup }),
  });
  state.message = "Backup restaurado com sucesso.";
  await loadAll();
  renderShell();
}

async function clearBackupHistory() {
  if (!state.backups.length) return;
  if (!confirm("Limpar o historico local de backups? Isso nao apaga arquivos .opbackup que voce ja baixou.")) return;
  await api("/api/admin/backups", { method: "DELETE", body: "" });
  state.message = "Historico de backup limpo.";
  await loadAll();
  renderShell();
}

function renderLogs() {
  document.querySelector("#view").innerHTML = `
    ${header("Audit logs", "Rastreamento")}
    <section class="panel">
      <div class="panel-head">
        <div class="panel-title">Eventos recentes</div>
        <select id="resultFilter">
          <option value="">Todos</option>
          <option value="success">success</option>
          <option value="denied">denied</option>
          <option value="error">error</option>
        </select>
      </div>
      ${logsTable(state.logs)}
    </section>
  `;
  attachRefresh();
  document.querySelector("#resultFilter").addEventListener("change", async (event) => {
    const value = event.currentTarget.value;
    const data = await api(`/api/admin/audit-logs?limit=100${value ? `&result=${value}` : ""}`);
    state.logs = data.data || [];
    renderShell();
  });
}

function logsTable(logs) {
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Resultado</th><th>Rota</th><th>Key</th><th>IP</th><th>Status</th><th>Duracao</th><th>Quando</th></tr></thead>
      <tbody>${logs.map((log) => `
        <tr>
          <td><span class="badge ${log.result === "success" ? "green" : log.result === "denied" ? "red" : "amber"}">${escapeHTML(log.result)}</span></td>
          <td><span class="mono">${escapeHTML(log.method)} ${escapeHTML(log.endpoint)}</span></td>
          <td class="mono">${escapeHTML(log.key_prefix || log.api_key_id || "")}</td>
          <td>${escapeHTML(log.ip_address || "")}</td>
          <td>${escapeHTML(log.status_code)}</td>
          <td>${escapeHTML(log.duration_ms)}ms</td>
          <td>${escapeHTML(log.created_at || "")}</td>
        </tr>
      `).join("") || `<tr><td colspan="7">Sem logs.</td></tr>`}</tbody>
    </table></div>
  `;
}

async function copyRevealed(event) {
  const value = state.revealed[event.currentTarget.dataset.copy];
  if (!value) return;
  await navigator.clipboard.writeText(value);
  event.currentTarget.textContent = "Copiado";
}

boot();
