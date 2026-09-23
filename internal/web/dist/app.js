const app = document.querySelector("#app");

const state = {
  theme: localStorage.getItem("openpass_theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  entries: [],
  vaults: [],
  activeCategory: "all",
  searchQuery: "",
  revealed: {},
  copiedKey: null,
  expanded: {},
  modal: null, // { mode: 'create' | 'edit', item?: Entry, selectedType?: string }
  backupModalOpen: false,
  securityModalOpen: false,
  recoveryKey: null,
  recoveryView: false,
  toast: null,
};

const CATEGORIES = [
  { id: "all", label: "Todos", icon: "✨" },
  { id: "apikey", label: "API Keys", icon: "🔑" },
  { id: "bank", label: "Bancos", icon: "🏦" },
  { id: "email", label: "E-mails", icon: "📧" },
  { id: "login", label: "Logins", icon: "🌐" },
  { id: "note", label: "Notas", icon: "📝" },
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
  render();
}

function showToast(message, type = "success") {
  state.toast = { message, type };
  renderToast();
  setTimeout(() => {
    state.toast = null;
    renderToast();
  }, 2500);
}

function renderToast() {
  const existing = document.querySelector("#toastContainer");
  if (!state.toast) {
    if (existing) existing.remove();
    return;
  }
  if (!existing) {
    const el = document.createElement("div");
    el.id = "toastContainer";
    document.body.appendChild(el);
  }
  document.querySelector("#toastContainer").innerHTML = `
    <div class="toast ${state.toast.type}">
      <span>✓</span>
      <span>${escapeHTML(state.toast.message)}</span>
    </div>
  `;
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
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    throw new Error((data && data.error) || res.statusText || "Erro na requisição");
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

async function copyText(text, keyId = null, successMsg = "Copiado para a área de transferência!") {
  if (!text) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    if (keyId) {
      state.copiedKey = keyId;
      render();
      setTimeout(() => {
        if (state.copiedKey === keyId) {
          state.copiedKey = null;
          render();
        }
      }, 1800);
    }
    showToast(successMsg);
  } catch (err) {
    alert("Não foi possível copiar: " + err.message);
  }
}

function generateStrongPassword(length = 20) {
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*+-=";
  const arr = new Uint8Array(length);
  window.crypto.getRandomValues(arr);
  let res = "";
  for (let i = 0; i < length; i++) {
    res += charset[arr[i] % charset.length];
  }
  return res;
}

async function boot() {
  try {
    await api("/api/admin/me");
    await loadData();
    render();
  } catch {
    renderLogin();
  }
}

async function loadData() {
  try {
    const res = await api("/api/admin/entries");
    state.entries = res.data || [];
  } catch {
    state.entries = [];
  }
  try {
    const res = await api("/api/admin/vaults");
    state.vaults = res.data || [];
  } catch {
    state.vaults = [];
  }
}

function renderLogin(error = "") {
  if (state.recoveryView) {
    app.innerHTML = `
      <main class="login-wrap">
        <section class="login-card">
          <div class="login-brand-icon">🔑</div>
          <div>
            <h1 class="login-title">Recuperar Acesso</h1>
            <p class="login-subtitle">Digite sua Chave de Emergência para criar uma nova senha</p>
          </div>
          ${error ? `<div class="login-error">${escapeHTML(error)}</div>` : ""}
          <form class="login-form" id="recoveryForm">
            <div class="form-group">
              <label class="form-label">Chave de Recuperação de Emergência</label>
              <input class="form-input mono" name="recovery_key" placeholder="OP-REC-XXXX-XXXX-XXXX-XXXX" required autofocus />
            </div>
            <div class="form-group">
              <label class="form-label">Nova Senha Mestra</label>
              <div class="password-input-wrap">
                <input class="form-input" id="recoveryPassInput" type="password" name="new_password" placeholder="Mínimo 6 caracteres" required />
                <div class="password-tools">
                  <button type="button" class="pass-tool-btn" id="btnToggleRecPass" title="Ver / Ocultar">👁️</button>
                  <button type="button" class="pass-tool-btn" id="btnGenRecPass" title="Gerar senha forte">🎲 Gerar</button>
                </div>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Confirmar Nova Senha</label>
              <input class="form-input" type="password" name="confirm_password" placeholder="Repita a nova senha" required />
            </div>
            <button class="btn btn-primary" type="submit" style="padding:12px;font-size:16px;">Redefinir Senha e Entrar</button>
            <div style="text-align:center;margin-top:6px;">
              <button type="button" class="link-btn" id="btnBackToLogin">← Voltar para o Login</button>
            </div>
          </form>
        </section>
      </main>
    `;

    document.querySelector("#btnBackToLogin").addEventListener("click", () => {
      state.recoveryView = false;
      renderLogin();
    });

    document.querySelector("#btnToggleRecPass")?.addEventListener("click", () => {
      const el = document.querySelector("#recoveryPassInput");
      if (el) el.type = el.type === "password" ? "text" : "password";
    });

    document.querySelector("#btnGenRecPass")?.addEventListener("click", () => {
      const el = document.querySelector("#recoveryPassInput");
      if (el) {
        el.value = generateStrongPassword(20);
        el.type = "text";
        showToast("Senha forte gerada!");
      }
    });

    document.querySelector("#recoveryForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const data = new FormData(e.currentTarget);
      const recoveryKey = data.get("recovery_key");
      const newPass = data.get("new_password");
      const confirmPass = data.get("confirm_password");

      if (newPass !== confirmPass) {
        renderLogin("As senhas digitadas não coincidem.");
        return;
      }

      try {
        const res = await api("/api/admin/recover-password", {
          method: "POST",
          body: JSON.stringify({
            recovery_key: recoveryKey,
            new_password: newPass,
          }),
        });
        state.recoveryView = false;
        state.recoveryKey = res.new_recovery_key;
        showToast("Senha redefinida com sucesso!");
        await loadData();
        render();
        if (res.new_recovery_key) {
          alert(`Sua senha foi redefinida com sucesso!\n\nUMA NOVA CHAVE DE RECUPERAÇÃO FOI GERADA:\n${res.new_recovery_key}\n\nGuarde esta nova chave em um local seguro.`);
        }
      } catch (err) {
        renderLogin(err.message === "chave_de_recuperacao_invalida" ? "Chave de recuperação incorreta ou inválida." : err.message);
      }
    });
    return;
  }

  app.innerHTML = `
    <main class="login-wrap">
      <section class="login-card">
        <div class="login-brand-icon">🔒</div>
        <div>
          <h1 class="login-title">OpenPass</h1>
          <p class="login-subtitle">Seu cofre pessoal de senhas e credenciais</p>
        </div>
        ${error ? `<div class="login-error">${escapeHTML(error)}</div>` : ""}
        <form class="login-form" id="loginForm">
          <div class="form-group">
            <label class="form-label">Senha mestra do cofre</label>
            <input class="form-input" type="password" name="password" autocomplete="current-password" placeholder="Digite sua senha de acesso" required autofocus />
            <div style="display:flex;justify-content:flex-end;margin-top:4px;">
              <button type="button" class="link-btn" id="linkForgotPassword">Esqueci minha senha</button>
            </div>
          </div>
          <button class="btn btn-primary" type="submit" style="padding:12px;font-size:16px;">Entrar no Cofre</button>
        </form>
      </section>
    </main>
  `;

  document.querySelector("#linkForgotPassword").addEventListener("click", () => {
    state.recoveryView = true;
    renderLogin();
  });

  document.querySelector("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = new FormData(e.currentTarget).get("password");
    try {
      await api("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      await loadData();
      render();
    } catch (err) {
      renderLogin(err.message === "unauthorized" ? "Senha incorreta." : err.message);
    }
  });
}

function render() {
  const filtered = filterEntries();

  app.innerHTML = `
    <header class="header">
      <div class="header-inner">
        <div class="brand" id="brandLogo">
          <div class="brand-icon">OP</div>
          <span class="brand-title">OpenPass</span>
          <span class="brand-badge">Cofre Pessoal</span>
        </div>
        <div class="header-actions">
          <button class="btn btn-primary btn-new-desktop" id="btnNewItem">
            <span>+</span> Novo Registro
          </button>
          <button class="btn btn-ghost" id="btnSecurity" title="Alterar senha e chave de recuperação">
            <span>⚙️</span> <span class="hide-mobile">Segurança</span>
          </button>
          <button class="btn btn-ghost" id="btnBackup" title="Backup e restauração">
            <span>💾</span> <span class="hide-mobile">Backup</span>
          </button>
          <button class="btn btn-ghost btn-icon" id="btnTheme" title="Alternar tema">
            ${state.theme === "dark" ? "☀️" : "🌙"}
          </button>
          <button class="btn btn-ghost btn-icon" id="btnLogout" title="Sair do cofre">
            🚪
          </button>
        </div>
      </div>
    </header>

    <div class="search-container">
      <div class="search-bar">
        <span class="search-icon">🔍</span>
        <input 
          class="search-input" 
          id="searchInput" 
          type="search" 
          placeholder="Buscar senhas, bancos, e-mails, chaves API..." 
          value="${escapeHTML(state.searchQuery)}"
        />
        ${state.searchQuery ? `<button class="search-clear" id="searchClear">✕</button>` : ""}
      </div>
    </div>

    <div class="categories-wrap">
      ${CATEGORIES.map((cat) => {
        const count = getCategoryCount(cat.id);
        const isActive = state.activeCategory === cat.id;
        return `
          <button class="category-pill ${isActive ? "active" : ""}" data-category="${cat.id}">
            <span>${cat.icon}</span>
            <span>${cat.label}</span>
            <span class="pill-badge">${count}</span>
          </button>
        `;
      }).join("")}
    </div>

    <main class="main-content">
      ${filtered.length === 0 ? renderEmptyState() : `
        <div class="items-grid">
          ${filtered.map(renderCard).join("")}
        </div>
      `}
    </main>

    <button class="mobile-fab" id="fabNewItem" aria-label="Novo item">
      +
    </button>

    ${state.modal ? renderItemModal() : ""}
    ${state.backupModalOpen ? renderBackupModal() : ""}
    ${state.securityModalOpen ? renderSecurityModal() : ""}
  `;

  attachEvents();
}

function getCategoryCount(catId) {
  if (catId === "all") return state.entries.length;
  return state.entries.filter((e) => e.type === catId).length;
}

function filterEntries() {
  let list = [...state.entries];
  if (state.activeCategory !== "all") {
    list = list.filter((e) => e.type === state.activeCategory);
  }
  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase().trim();
    list = list.filter((e) => {
      const title = (e.path || "").toLowerCase();
      const meta = Object.values(e.metadata || {}).join(" ").toLowerCase();
      const tags = (e.tags || []).join(" ").toLowerCase();
      return title.includes(q) || meta.includes(q) || tags.includes(q);
    });
  }
  return list;
}

function renderEmptyState() {
  const isSearching = !!state.searchQuery.trim();
  return `
    <div class="empty-state">
      <div class="empty-icon">${isSearching ? "🔍" : "🔐"}</div>
      <h3 class="empty-title">${isSearching ? "Nenhum resultado encontrado" : "Seu cofre está vazio"}</h3>
      <p class="empty-desc">
        ${isSearching 
          ? "Tente buscar por outro termo ou limpe a busca." 
          : "Comece guardando suas senhas de banco, e-mails, logins de sites ou chaves de API com segurança máxima."}
      </p>
      ${!isSearching ? `
        <button class="btn btn-primary" id="emptyBtnNew">
          <span>+</span> Adicionar Primeiro Registro
        </button>
      ` : ""}
    </div>
  `;
}

function renderCard(item) {
  const meta = item.metadata || {};
  const isExpanded = !!state.expanded[item.id];
  const isRevealed = Object.prototype.hasOwnProperty.call(state.revealed, item.id);
  const revealedVal = state.revealed[item.id];
  const typeBadge = getTypeBadge(item.type);

  let primaryCopyLabel = "Copiar Senha";
  let secondaryDetail = "";
  let secondaryCopyText = "";
  let secondaryCopyLabel = "";

  if (item.type === "bank") {
    secondaryDetail = meta.agency && meta.account ? `Ag: ${meta.agency} • Cc: ${meta.account}` : (meta.account || "");
    if (meta.pix) {
      secondaryCopyText = meta.pix;
      secondaryCopyLabel = "Copiar Pix";
    }
  } else if (item.type === "email") {
    secondaryDetail = meta.email || "";
    if (meta.email) {
      secondaryCopyText = meta.email;
      secondaryCopyLabel = "Copiar E-mail";
    }
  } else if (item.type === "login") {
    secondaryDetail = meta.username || meta.email || "";
    if (meta.username || meta.email) {
      secondaryCopyText = meta.username || meta.email;
      secondaryCopyLabel = "Copiar Usuário";
    }
  } else if (item.type === "apikey") {
    primaryCopyLabel = "Copiar Key";
    secondaryDetail = meta.platform ? `Plataforma: ${meta.platform}` : "";
    if (meta.secret) {
      secondaryCopyText = meta.secret;
      secondaryCopyLabel = "Copiar Secret";
    }
  } else if (item.type === "note") {
    primaryCopyLabel = "Copiar Nota";
    secondaryDetail = "Nota confidencial";
  }

  const isCopiedPrimary = state.copiedKey === `pri_${item.id}`;
  const isCopiedSecondary = state.copiedKey === `sec_${item.id}`;

  return `
    <article class="vault-card">
      <div class="card-header">
        <div class="card-identity">
          <div class="card-type-icon type-${item.type}">
            ${typeBadge.icon}
          </div>
          <div class="card-name-group">
            <h4 class="card-title">${escapeHTML(item.path)}</h4>
            <div class="card-subtitle">
              ${meta.url ? `<a href="${escapeHTML(meta.url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(secondaryDetail || meta.url)} ↗</a>` : escapeHTML(secondaryDetail || typeBadge.label)}
            </div>
          </div>
        </div>
        <span class="card-badge type-${item.type}">${typeBadge.label}</span>
      </div>

      <div class="card-fields">
        ${item.type === "bank" && meta.pix ? `
          <div class="card-field-row">
            <span class="card-field-label">Chave Pix</span>
            <span class="card-field-value mono">${escapeHTML(meta.pix)}</span>
          </div>
        ` : ""}

        ${item.type === "bank" && meta.secondary ? `
          <div class="card-field-row">
            <span class="card-field-label">Senha Transação</span>
            <span class="card-field-value mono">••••••</span>
          </div>
        ` : ""}

        <div class="card-secret-row">
          <span class="card-field-label">${item.type === "apikey" ? "API Key" : item.type === "note" ? "Nota" : "Senha"}</span>
          <span class="card-secret-val ${isRevealed ? "" : "mono"}">
            ${isRevealed ? escapeHTML(revealedVal) : "••••••••••••"}
          </span>
          <button class="icon-btn" data-reveal="${item.id}" title="${isRevealed ? "Ocultar" : "Revelar"}">
            ${isRevealed ? "🙈" : "👁️"}
          </button>
        </div>
      </div>

      ${isExpanded ? `
        <div class="card-details-expanded">
          ${meta.recovery ? `
            <div class="card-field-row">
              <span class="card-field-label">Recuperação</span>
              <span class="card-field-value">${escapeHTML(meta.recovery)}</span>
            </div>
          ` : ""}
          ${meta.url ? `
            <div class="card-field-row">
              <span class="card-field-label">Link</span>
              <span class="card-field-value"><a href="${escapeHTML(meta.url)}" target="_blank" rel="noopener">${escapeHTML(meta.url)} ↗</a></span>
            </div>
          ` : ""}
          ${meta.notes ? `
            <div class="notes-box">${escapeHTML(meta.notes)}</div>
          ` : ""}
          ${item.updated_at ? `
            <div class="card-field-row" style="color:var(--text-dim);font-size:11px;">
              <span>Atualizado</span>
              <span>${new Date(item.updated_at).toLocaleDateString("pt-BR")}</span>
            </div>
          ` : ""}
        </div>
      ` : ""}

      <div class="card-actions">
        <button class="card-copy-btn ${isCopiedPrimary ? "copied" : ""}" data-copy-secret="${item.id}">
          ${isCopiedPrimary ? "✓ Copiado!" : `📋 ${primaryCopyLabel}`}
        </button>

        ${secondaryCopyText ? `
          <button class="card-copy-btn ${isCopiedSecondary ? "copied" : ""}" data-copy-secondary="${item.id}" data-val="${escapeHTML(secondaryCopyText)}">
            ${isCopiedSecondary ? "✓ Copiado!" : `📋 ${secondaryCopyLabel}`}
          </button>
        ` : ""}

        <button class="icon-btn" data-toggle-expand="${item.id}" title="${isExpanded ? "Recolher" : "Mais detalhes"}">
          ${isExpanded ? "▲" : "▼"}
        </button>
        <button class="icon-btn" data-edit="${item.id}" title="Editar registro">
          ✏️
        </button>
        <button class="icon-btn delete" data-delete="${item.id}" title="Excluir">
          🗑️
        </button>
      </div>
    </article>
  `;
}

function getTypeBadge(type) {
  switch (type) {
    case "apikey": return { label: "API Key", icon: "🔑" };
    case "bank": return { label: "Banco", icon: "🏦" };
    case "email": return { label: "E-mail", icon: "📧" };
    case "login": return { label: "Login", icon: "🌐" };
    case "note": return { label: "Nota", icon: "📝" };
    default: return { label: "Item", icon: "🔐" };
  }
}

function renderItemModal() {
  const { mode, item, selectedType } = state.modal;
  const currentType = selectedType || (item ? item.type : "login");
  const isEdit = mode === "edit";
  const meta = (item && item.metadata) || {};

  return `
    <div class="modal-overlay" id="modalBackdrop">
      <div class="modal-content" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h3 class="modal-title">${isEdit ? "Editar Registro" : "Novo Registro"}</h3>
          <button class="icon-btn" id="modalClose">✕</button>
        </div>

        <form id="itemForm" class="modal-body">
          ${!isEdit ? `
            <div class="form-group">
              <label class="form-label">Tipo de credencial</label>
              <div class="type-selector">
                ${CATEGORIES.filter((c) => c.id !== "all").map((cat) => `
                  <button type="button" class="type-btn ${currentType === cat.id ? "active" : ""}" data-modal-type="${cat.id}">
                    <span class="type-btn-icon">${cat.icon}</span>
                    <span>${cat.label}</span>
                  </button>
                `).join("")}
              </div>
            </div>
          ` : ""}

          <input type="hidden" name="type" value="${currentType}" />

          <div class="form-group">
            <label class="form-label">
              ${currentType === "bank" ? "Nome do Banco / Instituição" :
                currentType === "email" ? "Provedor / Nome da Conta" :
                currentType === "apikey" ? "Nome do Serviço / Plataforma" :
                currentType === "note" ? "Título da Nota" : "Nome do Site / Serviço"}
            </label>
            <input class="form-input" name="path" required placeholder="${
              currentType === "bank" ? "Ex: Nubank, Itaú, Inter" :
              currentType === "email" ? "Ex: Gmail Pessoal, Outlook Empresa" :
              currentType === "apikey" ? "Ex: OpenAI GPT, Stripe Prod, AWS" :
              currentType === "note" ? "Ex: Chaves de Recuperação, Frase Secreta" : "Ex: Netflix, Amazon, Mercado Livre"
            }" value="${escapeHTML(item ? item.path : "")}" />
          </div>

          ${currentType === "login" ? `
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Usuário ou Login</label>
                <input class="form-input" name="meta_username" placeholder="seu.usuario" value="${escapeHTML(meta.username || "")}" />
              </div>
              <div class="form-group">
                <label class="form-label">E-mail associado</label>
                <input class="form-input" name="meta_email" type="email" placeholder="seu@email.com" value="${escapeHTML(meta.email || "")}" />
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Endereço do Site (URL)</label>
              <input class="form-input" name="meta_url" placeholder="https://exemplo.com/login" value="${escapeHTML(meta.url || "")}" />
            </div>
          ` : ""}

          ${currentType === "bank" ? `
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Agência</label>
                <input class="form-input" name="meta_agency" placeholder="0001" value="${escapeHTML(meta.agency || "")}" />
              </div>
              <div class="form-group">
                <label class="form-label">Conta com Dígito</label>
                <input class="form-input" name="meta_account" placeholder="123456-7" value="${escapeHTML(meta.account || "")}" />
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Chave Pix</label>
                <input class="form-input" name="meta_pix" placeholder="CPF, e-mail ou aleatória" value="${escapeHTML(meta.pix || "")}" />
              </div>
              <div class="form-group">
                <label class="form-label">Senha de Transação / Cartão</label>
                <input class="form-input" type="password" name="meta_secondary" placeholder="Opcional" value="${escapeHTML(meta.secondary || "")}" />
              </div>
            </div>
          ` : ""}

          ${currentType === "email" ? `
            <div class="form-group">
              <label class="form-label">Endereço de E-mail</label>
              <input class="form-input" name="meta_email" type="email" required placeholder="contato@gmail.com" value="${escapeHTML(meta.email || "")}" />
            </div>
            <div class="form-group">
              <label class="form-label">E-mail ou Tel. de Recuperação</label>
              <input class="form-input" name="meta_recovery" placeholder="backup@email.com ou (11) 9..." value="${escapeHTML(meta.recovery || "")}" />
            </div>
          ` : ""}

          ${currentType === "apikey" ? `
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Plataforma</label>
                <input class="form-input" name="meta_platform" placeholder="OpenAI, Anthropic, GitHub..." value="${escapeHTML(meta.platform || "")}" />
              </div>
              <div class="form-group">
                <label class="form-label">Link Docs / Dashboard</label>
                <input class="form-input" name="meta_url" placeholder="https://platform.openai.com" value="${escapeHTML(meta.url || "")}" />
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Secret / Chave Secundária (opcional)</label>
              <input class="form-input" name="meta_secret" placeholder="API Secret" value="${escapeHTML(meta.secret || "")}" />
            </div>
          ` : ""}

          <div class="form-group">
            <label class="form-label">
              ${currentType === "apikey" ? "API Key / Token" :
                currentType === "note" ? "Conteúdo Secreto da Nota" : "Senha Principal"}
              ${isEdit ? '<span style="font-weight:normal;font-size:12px;color:var(--text-dim)">(vazio para manter)</span>' : ""}
            </label>
            ${currentType === "note" ? `
              <textarea class="form-textarea" name="value" placeholder="Digite sua nota confidencial..." ${isEdit ? "" : "required"}>${isEdit && state.revealed[item.id] ? escapeHTML(state.revealed[item.id]) : ""}</textarea>
            ` : `
              <div class="password-input-wrap">
                <input class="form-input" id="modalPasswordInput" type="password" name="value" placeholder="${isEdit ? "••••••••••••" : "Digite ou gere uma senha forte"}" ${isEdit ? "" : "required"} />
                <div class="password-tools">
                  <button type="button" class="pass-tool-btn" id="btnTogglePassVisibility" title="Ver / Ocultar">👁️</button>
                  <button type="button" class="pass-tool-btn" id="btnGeneratePass" title="Gerar senha forte">🎲 Gerar</button>
                </div>
              </div>
            `}
          </div>

          <div class="form-group">
            <label class="form-label">Anotações extras (opcional)</label>
            <textarea class="form-textarea" name="meta_notes" placeholder="Informações adicionais, dicas de segurança...">${escapeHTML(meta.notes || "")}</textarea>
          </div>
        </form>

        <div class="modal-footer">
          <button type="button" class="btn btn-ghost" id="modalCancel">Cancelar</button>
          <button type="submit" form="itemForm" class="btn btn-primary">
            ${isEdit ? "Salvar Alterações" : "Salvar no Cofre"}
          </button>
        </div>
      </div>
    </div>
  `;
}

function renderSecurityModal() {
  return `
    <div class="modal-overlay" id="securityModalBackdrop">
      <div class="modal-content" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h3 class="modal-title">Segurança do Cofre</h3>
          <button class="icon-btn" id="securityModalClose">✕</button>
        </div>

        <div class="modal-body">
          <section style="display:flex;flex-direction:column;gap:12px;">
            <h4 style="font-size:15px;font-weight:700;">🔒 Alterar Senha de Acesso</h4>
            <form id="changePasswordForm" style="display:flex;flex-direction:column;gap:12px;">
              <div class="form-group">
                <label class="form-label">Senha Atual</label>
                <input class="form-input" type="password" name="current_password" required placeholder="Digite sua senha atual" />
              </div>
              <div class="form-group">
                <label class="form-label">Nova Senha Mestra</label>
                <div class="password-input-wrap">
                  <input class="form-input" id="newPassInput" type="password" name="new_password" required placeholder="Mínimo 6 caracteres" />
                  <div class="password-tools">
                    <button type="button" class="pass-tool-btn" id="btnToggleNewPass" title="Ver / Ocultar">👁️</button>
                    <button type="button" class="pass-tool-btn" id="btnGenNewPass" title="Gerar senha forte">🎲 Gerar</button>
                  </div>
                </div>
              </div>
              <div class="form-group">
                <label class="form-label">Confirmar Nova Senha</label>
                <input class="form-input" type="password" name="confirm_password" required placeholder="Repita a nova senha" />
              </div>
              <button class="btn btn-primary" type="submit">Salvar Nova Senha</button>
            </form>
          </section>

          <hr style="border:none;border-top:1px solid var(--border-subtle);margin:8px 0;" />

          <section style="display:flex;flex-direction:column;gap:12px;">
            <h4 style="font-size:15px;font-weight:700;">🔑 Chave de Recuperação de Emergência</h4>
            <p style="font-size:13px;color:var(--text-muted);line-height:1.4;">
              Guarde esta chave em um local seguro. Se você esquecer a senha mestra, ela é a <strong>única forma</strong> de redefinir o acesso e recuperar suas senhas.
            </p>
            <div class="recovery-key-card">
              <span class="recovery-key-text" id="displayRecoveryKey">${escapeHTML(state.recoveryKey || "Carregando chave...")}</span>
              <button class="btn btn-ghost btn-icon" id="btnCopyRecoveryKey" title="Copiar Chave de Recuperação">📋</button>
            </div>
            <div>
              <button type="button" class="btn btn-ghost" id="btnRegenerateKey" style="font-size:12px;">
                🔄 Gerar Nova Chave de Emergência
              </button>
            </div>
          </section>
        </div>

        <div class="modal-footer">
          <button type="button" class="btn btn-ghost" id="securityModalCancel">Fechar</button>
        </div>
      </div>
    </div>
  `;
}

function renderBackupModal() {
  return `
    <div class="modal-overlay" id="backupModalBackdrop">
      <div class="modal-content" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h3 class="modal-title">Backup Seguro do Cofre</h3>
          <button class="icon-btn" id="backupModalClose">✕</button>
        </div>

        <div class="modal-body">
          <section style="display:flex;flex-direction:column;gap:12px;">
            <h4 style="font-size:15px;font-weight:700;">📥 Baixar Cópia Criptografada</h4>
            <p style="font-size:13px;color:var(--text-muted);">
              Baixe um arquivo seguro (<strong>.opbackup</strong>) diretamente no seu celular ou computador para ter uma cópia 100% sob seu controle.
            </p>
            <form id="exportForm" style="display:flex;flex-direction:column;gap:10px;">
              <div class="form-group">
                <label class="form-label">Senha opcional para proteger o arquivo</label>
                <input class="form-input" type="password" name="password" placeholder="Opcional (vazio usa chave mestra)" />
              </div>
              <button class="btn btn-primary" type="submit">
                Baixar Arquivo de Backup
              </button>
            </form>
          </section>

          <hr style="border:none;border-top:1px solid var(--border-subtle);margin:8px 0;" />

          <section style="display:flex;flex-direction:column;gap:12px;">
            <h4 style="font-size:15px;font-weight:700;">📤 Restaurar Backup</h4>
            <p style="font-size:13px;color:var(--text-muted);">
              Selecione um arquivo <strong>.opbackup</strong> para restaurar suas credenciais.
            </p>
            <form id="restoreForm" style="display:flex;flex-direction:column;gap:10px;">
              <div class="form-group">
                <label class="form-label">Arquivo de backup</label>
                <input class="form-input" type="file" name="file" accept=".opbackup,application/json" required />
              </div>
              <div class="form-group">
                <label class="form-label">Senha do backup (se houver)</label>
                <input class="form-input" type="password" name="password" placeholder="Senha usada no download" />
              </div>
              <button class="btn btn-ghost" type="submit" style="color:var(--danger);border-color:var(--danger);">
                Restaurar Dados Agora
              </button>
            </form>
          </section>
        </div>

        <div class="modal-footer">
          <button type="button" class="btn btn-ghost" id="backupModalCancel">Fechar</button>
        </div>
      </div>
    </div>
  `;
}

function attachEvents() {
  document.querySelector("#btnTheme")?.addEventListener("click", toggleTheme);
  
  document.querySelector("#btnLogout")?.addEventListener("click", async () => {
    await api("/api/admin/logout", { method: "POST", body: "{}" });
    renderLogin();
  });

  const openNewItemModal = () => {
    state.modal = { mode: "create", selectedType: state.activeCategory === "all" ? "login" : state.activeCategory };
    render();
  };

  document.querySelector("#btnNewItem")?.addEventListener("click", openNewItemModal);
  document.querySelector("#fabNewItem")?.addEventListener("click", openNewItemModal);
  document.querySelector("#emptyBtnNew")?.addEventListener("click", openNewItemModal);

  document.querySelector("#btnBackup")?.addEventListener("click", () => {
    state.backupModalOpen = true;
    render();
  });

  document.querySelector("#btnSecurity")?.addEventListener("click", async () => {
    state.securityModalOpen = true;
    render();
    try {
      const res = await api("/api/admin/recovery-key");
      state.recoveryKey = res.recovery_key;
      const displayEl = document.querySelector("#displayRecoveryKey");
      if (displayEl) displayEl.textContent = state.recoveryKey;
    } catch (err) {
      console.error(err);
    }
  });

  // Search input live filtering
  const searchInput = document.querySelector("#searchInput");
  if (searchInput) {
    searchInput.focus();
    searchInput.setSelectionRange(searchInput.value.length, searchInput.value.length);
    searchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value;
      render();
    });
  }

  document.querySelector("#searchClear")?.addEventListener("click", () => {
    state.searchQuery = "";
    render();
  });

  // Category pills
  document.querySelectorAll("[data-category]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      state.activeCategory = e.currentTarget.dataset.category;
      render();
    });
  });

  // Quick Copy Secret (Password / Token)
  document.querySelectorAll("[data-copy-secret]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const id = e.currentTarget.dataset.copySecret;
      let val = state.revealed[id];
      if (!val) {
        try {
          const res = await api(`/api/admin/entries/${id}/reveal`);
          val = res.value;
          state.revealed[id] = val;
        } catch (err) {
          alert("Erro ao revelar: " + err.message);
          return;
        }
      }
      copyText(val, `pri_${id}`, "Senha/Token copiado!");
    });
  });

  // Quick Copy Secondary (User, Pix, Secret)
  document.querySelectorAll("[data-copy-secondary]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const id = e.currentTarget.dataset.copySecondary;
      const val = e.currentTarget.dataset.val;
      copyText(val, `sec_${id}`);
    });
  });

  // Reveal / Hide
  document.querySelectorAll("[data-reveal]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const id = e.currentTarget.dataset.reveal;
      if (Object.prototype.hasOwnProperty.call(state.revealed, id)) {
        delete state.revealed[id];
        render();
        return;
      }
      try {
        const res = await api(`/api/admin/entries/${id}/reveal`);
        state.revealed[id] = res.value;
        render();
      } catch (err) {
        alert("Erro ao revelar: " + err.message);
      }
    });
  });

  // Expand / Collapse details
  document.querySelectorAll("[data-toggle-expand]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const id = e.currentTarget.dataset.toggleExpand;
      state.expanded[id] = !state.expanded[id];
      render();
    });
  });

  // Edit item
  document.querySelectorAll("[data-edit]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const id = e.currentTarget.dataset.edit;
      const item = state.entries.find((entry) => entry.id === id);
      if (!item) return;
      if (item.type === "note" && !state.revealed[id]) {
        try {
          const res = await api(`/api/admin/entries/${id}/reveal`);
          state.revealed[id] = res.value;
        } catch {}
      }
      state.modal = { mode: "edit", item, selectedType: item.type };
      render();
    });
  });

  // Delete item
  document.querySelectorAll("[data-delete]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const id = e.currentTarget.dataset.delete;
      const item = state.entries.find((entry) => entry.id === id);
      if (!confirm(`Excluir permanentemente "${item?.path || "este item"}"?`)) return;
      try {
        await api(`/api/admin/entries/${id}`, { method: "DELETE" });
        showToast("Registro excluído com sucesso.");
        await loadData();
        render();
      } catch (err) {
        alert("Erro ao excluir: " + err.message);
      }
    });
  });

  // Item Modal events
  if (state.modal) {
    const closeModal = () => {
      state.modal = null;
      render();
    };
    document.querySelector("#modalClose")?.addEventListener("click", closeModal);
    document.querySelector("#modalCancel")?.addEventListener("click", closeModal);
    document.querySelector("#modalBackdrop")?.addEventListener("click", closeModal);

    document.querySelectorAll("[data-modal-type]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        state.modal.selectedType = e.currentTarget.dataset.modalType;
        render();
      });
    });

    document.querySelector("#btnGeneratePass")?.addEventListener("click", () => {
      const passInput = document.querySelector("#modalPasswordInput");
      if (passInput) {
        const strongPass = generateStrongPassword(20);
        passInput.value = strongPass;
        passInput.type = "text";
        showToast("Senha forte de 20 caracteres gerada!");
      }
    });

    document.querySelector("#btnTogglePassVisibility")?.addEventListener("click", () => {
      const passInput = document.querySelector("#modalPasswordInput");
      if (passInput) {
        passInput.type = passInput.type === "password" ? "text" : "password";
      }
    });

    document.querySelector("#itemForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const data = new FormData(form);

      const path = data.get("path");
      const type = data.get("type");
      const value = data.get("value") || "";

      const metadata = {};
      for (const [key, val] of data.entries()) {
        if (key.startsWith("meta_") && String(val).trim()) {
          metadata[key.replace("meta_", "")] = String(val).trim();
        }
      }

      try {
        if (state.modal.mode === "create") {
          await api("/api/admin/entries", {
            method: "POST",
            body: JSON.stringify({
              path,
              type,
              value,
              metadata,
            }),
          });
          showToast("Salvo no cofre com sucesso!");
        } else {
          await api(`/api/admin/entries/${state.modal.item.id}`, {
            method: "PUT",
            body: JSON.stringify({
              path,
              type,
              value,
              metadata,
            }),
          });
          showToast("Registro atualizado com sucesso!");
        }
        state.modal = null;
        await loadData();
        render();
      } catch (err) {
        alert("Erro ao salvar: " + err.message);
      }
    });
  }

  // Security Modal events
  if (state.securityModalOpen) {
    const closeSecurity = () => {
      state.securityModalOpen = false;
      render();
    };
    document.querySelector("#securityModalClose")?.addEventListener("click", closeSecurity);
    document.querySelector("#securityModalCancel")?.addEventListener("click", closeSecurity);
    document.querySelector("#securityModalBackdrop")?.addEventListener("click", closeSecurity);

    document.querySelector("#btnToggleNewPass")?.addEventListener("click", () => {
      const el = document.querySelector("#newPassInput");
      if (el) el.type = el.type === "password" ? "text" : "password";
    });

    document.querySelector("#btnGenNewPass")?.addEventListener("click", () => {
      const el = document.querySelector("#newPassInput");
      if (el) {
        el.value = generateStrongPassword(20);
        el.type = "text";
        showToast("Senha forte gerada!");
      }
    });

    document.querySelector("#btnCopyRecoveryKey")?.addEventListener("click", () => {
      if (state.recoveryKey) {
        copyText(state.recoveryKey, null, "Chave de Emergência copiada!");
      }
    });

    document.querySelector("#btnRegenerateKey")?.addEventListener("click", async () => {
      const pass = prompt("Para gerar uma nova chave de emergência, digite sua senha mestra atual:");
      if (!pass) return;
      try {
        const res = await api("/api/admin/regenerate-recovery-key", {
          method: "POST",
          body: JSON.stringify({ password: pass }),
        });
        state.recoveryKey = res.recovery_key;
        const displayEl = document.querySelector("#displayRecoveryKey");
        if (displayEl) displayEl.textContent = state.recoveryKey;
        showToast("Nova chave gerada com sucesso!");
      } catch (err) {
        alert("Não foi possível gerar nova chave: " + err.message);
      }
    });

    document.querySelector("#changePasswordForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const data = new FormData(form);
      const currentPass = data.get("current_password");
      const newPass = data.get("new_password");
      const confirmPass = data.get("confirm_password");

      if (newPass !== confirmPass) {
        alert("A nova senha e a confirmação não coincidem.");
        return;
      }

      try {
        await api("/api/admin/change-password", {
          method: "POST",
          body: JSON.stringify({
            current_password: currentPass,
            new_password: newPass,
          }),
        });
        showToast("Senha alterada com sucesso!");
        closeSecurity();
      } catch (err) {
        alert("Erro ao alterar senha: " + (err.message === "senha_atual_incorreta" ? "Senha atual incorreta." : err.message));
      }
    });
  }

  // Backup Modal events
  if (state.backupModalOpen) {
    const closeBackup = () => {
      state.backupModalOpen = false;
      render();
    };
    document.querySelector("#backupModalClose")?.addEventListener("click", closeBackup);
    document.querySelector("#backupModalCancel")?.addEventListener("click", closeBackup);
    document.querySelector("#backupModalBackdrop")?.addEventListener("click", closeBackup);

    document.querySelector("#exportForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const password = new FormData(e.currentTarget).get("password");
      try {
        const res = await fetch("/api/admin/backup/export", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        });
        if (!res.ok) throw new Error("Falha ao gerar arquivo de backup.");
        const blob = await res.blob();
        const disposition = res.headers.get("Content-Disposition") || "";
        const match = disposition.match(/filename="([^"]+)"/);
        const filename = match ? match[1] : `openpass-backup-${new Date().toISOString().slice(0, 10)}.opbackup`;
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        showToast("Backup baixado com sucesso!");
        closeBackup();
      } catch (err) {
        alert("Erro: " + err.message);
      }
    });

    document.querySelector("#restoreForm")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const data = new FormData(form);
      const file = data.get("file");
      if (!file) return;
      if (!confirm("Restaurar um backup substituirá todos os registros atuais. Deseja continuar?")) return;
      try {
        const backupText = await file.text();
        await api("/api/admin/backup/restore", {
          method: "POST",
          body: JSON.stringify({
            password: data.get("password"),
            backup: backupText,
          }),
        });
        showToast("Backup restaurado com sucesso!");
        closeBackup();
        await loadData();
        render();
      } catch (err) {
        alert("Erro na restauração: " + err.message);
      }
    });
  }
}

boot();
