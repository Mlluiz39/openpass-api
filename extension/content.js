// OpenPass browser extension — content script.
//
// Runs in every frame. It never holds the API key: it asks the background
// worker for the logins that match this page and only receives the secret when
// the user actually picks an entry.

(() => {
  if (window.__openpassInjected) return;
  window.__openpassInjected = true;

  // Only the top document draws the inline menu and the save banner; child
  // frames still fill forms, but a banner in every iframe would be a mess.
  const IS_TOP = window.top === window;

  let config = { autoFillOnLoad: true, askToSave: true };
  let menu = null;
  let banner = null;
  let lastFocusedPassword = null;
  let lastFocusedUsername = null;
  let cachedMatches = null;

  // ------------------------------------------------------------- utilities

  function send(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (res) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
            return;
          }
          resolve(res || { ok: false, error: "sem resposta" });
        });
      } catch {
        resolve({ ok: false, error: "extensão indisponível" });
      }
    });
  }

  const PASSWORD_SELECTOR = 'input[type="password"]';

  function isVisible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = getComputedStyle(el);
    return style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0";
  }

  function passwordFields() {
    return Array.from(document.querySelectorAll(PASSWORD_SELECTOR)).filter(isVisible);
  }

  function isEmpty(el) {
    return !el || !el.value;
  }

  // usernameFieldFor looks for the text input that belongs with a password
  // field: the closest preceding visible text/email input in the same form.
  function usernameFieldFor(passwordEl) {
    const scope = passwordEl.form || document;
    const candidates = Array.from(
      scope.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])')
    ).filter((el) => isVisible(el) && !el.disabled && !el.readOnly);

    const inputs = Array.from(scope.querySelectorAll("input")).filter(isVisible);
    const pwIndex = inputs.indexOf(passwordEl);

    // Prefer a candidate that appears before the password field.
    const before = candidates.filter((el) => inputs.indexOf(el) < pwIndex);
    if (before.length) return before[before.length - 1];
    return candidates[0] || null;
  }

  // setValue writes like a user would, so React/Vue apps notice the change.
  function setValue(el, value) {
    if (!el) return;
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement : HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(proto.prototype, "value")?.set;
    setter ? setter.call(el, value) : (el.value = value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillCredentials(username, password, passwordEl) {
    const target = passwordEl && isVisible(passwordEl) && passwordEl.isConnected
      ? passwordEl
      : passwordFields()[0];
    if (!target) return false;

    if (username !== undefined && username !== null) {
      const userEl = usernameFieldFor(target);
      if (userEl) setValue(userEl, username);
    }
    if (password !== undefined && password !== null) {
      setValue(target, password);
    }

    // Apps that validate on blur need to see the field leave focus, and the
    // user almost always wants to press the submit button next.
    target.dispatchEvent(new Event("blur", { bubbles: true }));
    const submit = target.form?.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
    return !!submit;
  }

  // ------------------------------------------------------------ inline menu

  function closeMenu() {
    if (menu) {
      menu.remove();
      menu = null;
    }
  }

  function ensureMenuStyles() {
    if (document.getElementById("openpass-styles")) return;
    const style = document.createElement("style");
    style.id = "openpass-styles";
    style.textContent = `
      .openpass-menu {
        position: fixed; z-index: 2147483647; min-width: 260px; max-width: 340px;
        background: #15161c; color: #e8e9ef; border: 1px solid #2c2e39;
        border-radius: 10px; box-shadow: 0 12px 32px rgba(0,0,0,.45);
        font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
        overflow: hidden;
      }
      .openpass-menu header {
        display:flex; align-items:center; gap:8px; padding:9px 11px;
        border-bottom:1px solid #2c2e39; font-weight:600; font-size:12px;
        letter-spacing:.02em; text-transform:uppercase; color:#9aa0b4;
      }
      .openpass-menu button.openpass-item {
        display:flex; flex-direction:column; gap:2px; width:100%; text-align:left;
        padding:10px 11px; background:transparent; border:0; color:inherit;
        font:inherit; cursor:pointer; border-bottom:1px solid #23252e;
      }
      .openpass-menu button.openpass-item:last-child { border-bottom:0; }
      .openpass-menu button.openpass-item:hover { background:#21232c; }
      .openpass-item .openpass-name { font-weight:600; }
      .openpass-item .openpass-user { color:#9aa0b4; font-size:12px; }
      .openpass-empty { padding:12px 11px; color:#9aa0b4; }
      .openpass-banner {
        position: fixed; z-index: 2147483647; right: 16px; bottom: 16px;
        width: 340px; background:#15161c; color:#e8e9ef; border:1px solid #2c2e39;
        border-radius: 12px; box-shadow: 0 16px 40px rgba(0,0,0,.5);
        font: 13px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; padding: 14px;
      }
      .openpass-banner h4 { margin:0 0 8px; font-size:14px; }
      .openpass-banner .openpass-row { margin:6px 0; color:#9aa0b4; font-size:12px; word-break:break-all; }
      .openpass-banner .openpass-actions { display:flex; gap:8px; margin-top:12px; }
      .openpass-banner button {
        flex:1; padding:8px 10px; border-radius:8px; cursor:pointer;
        border:1px solid #2c2e39; background:#21232c; color:#e8e9ef; font:inherit; font-weight:600;
      }
      .openpass-banner button.openpass-primary { background:#4f7cff; border-color:#4f7cff; color:#fff; }
      .openpass-banner button:disabled { opacity:.6; cursor:default; }
    `;
    document.documentElement.appendChild(style);
  }

  function positionMenu(anchor) {
    if (!menu) return;
    const rect = anchor.getBoundingClientRect();
    const top = Math.min(rect.bottom + 6, window.innerHeight - menu.offsetHeight - 8);
    const left = Math.min(rect.left, window.innerWidth - menu.offsetWidth - 8);
    menu.style.top = `${Math.max(8, top)}px`;
    menu.style.left = `${Math.max(8, left)}px`;
  }

  async function openMenu(anchor) {
    const matches = await loadMatches();
    closeMenu();
    ensureMenuStyles();

    menu = document.createElement("div");
    menu.className = "openpass-menu";

    const header = document.createElement("header");
    header.textContent = "OpenPass";
    menu.appendChild(header);

    if (!matches || !matches.length) {
      const empty = document.createElement("div");
      empty.className = "openpass-empty";
      empty.textContent = "Nenhum login salvo para este site.";
      menu.appendChild(empty);
      document.documentElement.appendChild(menu);
      positionMenu(anchor);
      return;
    }

    matches.forEach((match) => {
      const btn = document.createElement("button");
      btn.className = "openpass-item";
      btn.type = "button";

      const name = document.createElement("span");
      name.className = "openpass-name";
      name.textContent = match.entry.path;
      btn.appendChild(name);

      const user = document.createElement("span");
      user.className = "openpass-user";
      user.textContent = match.entry.metadata?.username || "sem usuário";
      btn.appendChild(user);

      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        btn.disabled = true;
        await useMatch(match.entry.id, anchor);
        closeMenu();
      });

      menu.appendChild(btn);
    });

    document.documentElement.appendChild(menu);
    positionMenu(anchor);
  }

  async function loadMatches(force = false) {
    if (cachedMatches && !force) return cachedMatches;
    const res = await send({ type: "getMatches", url: location.href });
    cachedMatches = res.ok ? res.data : [];
    return cachedMatches;
  }

  // useMatch fetches the secret for one entry and fills the form.
  async function useMatch(entryId, anchor) {
    const res = await send({ type: "getMatches", url: location.href, reveal: true });
    if (!res.ok) return false;
    const match = (res.data || []).find((m) => m.entry.id === entryId);
    if (!match) return false;

    const passwordEl = lastFocusedPassword && lastFocusedPassword.isConnected
      ? lastFocusedPassword
      : passwordFields()[0];
    fillCredentials(match.entry.metadata?.username, match.value, passwordEl);
    return true;
  }

  // --------------------------------------------------------- save/update banner

  function closeBanner() {
    if (banner) {
      banner.remove();
      banner = null;
    }
  }

  function showBanner({ title, lines, primaryLabel, onPrimary, secondaryLabel, onSecondary }) {
    ensureMenuStyles();
    closeBanner();

    banner = document.createElement("div");
    banner.className = "openpass-banner";

    const h = document.createElement("h4");
    h.textContent = title;
    banner.appendChild(h);

    (lines || []).forEach((line) => {
      const row = document.createElement("div");
      row.className = "openpass-row";
      row.textContent = line;
      banner.appendChild(row);
    });

    const actions = document.createElement("div");
    actions.className = "openpass-actions";

    const primary = document.createElement("button");
    primary.className = "openpass-primary";
    primary.textContent = primaryLabel;
    primary.addEventListener("click", async () => {
      primary.disabled = true;
      primary.textContent = "Salvando…";
      const err = await onPrimary();
      if (err) {
        primary.disabled = false;
        primary.textContent = primaryLabel;
        const row = document.createElement("div");
        row.className = "openpass-row";
        row.textContent = err;
        banner.appendChild(row);
        return;
      }
      closeBanner();
    });
    actions.appendChild(primary);

    const secondary = document.createElement("button");
    secondary.textContent = secondaryLabel || "Agora não";
    secondary.addEventListener("click", () => {
      onSecondary?.();
      closeBanner();
    });
    actions.appendChild(secondary);

    banner.appendChild(actions);
    document.documentElement.appendChild(banner);
  }

  // ------------------------------------------------------------ form capture

  function currentOrigin() {
    return location.origin;
  }

  document.addEventListener(
    "submit",
    (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;

      const pw = Array.from(form.querySelectorAll(PASSWORD_SELECTOR)).find((el) => el.value);
      if (!pw) return;

      const userEl = usernameFieldFor(pw);
      send({
        type: "setPending",
        pending: {
          origin: currentOrigin(),
          url: location.href,
          username: userEl?.value || "",
          password: pw.value,
        },
      });
    },
    true
  );

  // Detects the credentials of a form whose submit button was clicked without
  // a real submit event (common in SPAs that call fetch directly).
  document.addEventListener(
    "click",
    (event) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const button = target.closest('button[type="submit"], input[type="submit"], button:not([type])');
      if (!button) return;
      const form = button.form || button.closest("form");
      if (!form) return;

      const pw = Array.from(form.querySelectorAll(PASSWORD_SELECTOR)).find((el) => el.value);
      if (!pw) return;
      const userEl = usernameFieldFor(pw);
      send({
        type: "setPending",
        pending: {
          origin: currentOrigin(),
          url: location.href,
          username: userEl?.value || "",
          password: pw.value,
        },
      });
    },
    true
  );

  async function offerSave(pending) {
    if (!config.askToSave) return;

    const res = await send({ type: "getMatches", url: location.href, reveal: true });
    const matches = res.ok ? res.data || [] : [];
    const sameUser = matches.find(
      (m) => (m.entry.metadata?.username || "") === (pending.username || "")
    );

    if (sameUser && sameUser.value === pending.password) return; // already stored

    if (sameUser) {
      showBanner({
        title: "Atualizar senha no OpenPass?",
        lines: [sameUser.entry.path, pending.username || "sem usuário"],
        primaryLabel: "Atualizar",
        onPrimary: async () => {
          const r = await send({
            type: "updatePassword",
            entryId: sameUser.entry.id,
            password: pending.password,
          });
          return r.ok ? null : r.error;
        },
      });
      return;
    }

    if (matches.length) return; // another login exists for this site: leave it alone

    showBanner({
      title: "Salvar login no OpenPass?",
      lines: [pending.username || "sem usuário", new URL(pending.url).hostname],
      primaryLabel: "Salvar",
      onPrimary: async () => {
        const r = await send({
          type: "saveLogin",
          url: pending.url,
          username: pending.username,
          password: pending.password,
        });
        return r.ok ? null : r.error;
      },
    });
  }

  // -------------------------------------------------------------- lifecycle

  document.addEventListener(
    "focusin",
    (event) => {
      const el = event.target;
      if (!(el instanceof HTMLInputElement)) return;
      if (el.type === "password") {
        lastFocusedPassword = el;
      } else if (["text", "email", "tel"].includes(el.type) || !el.type) {
        lastFocusedUsername = el;
      }
    },
    true
  );

  // The inline menu opens on focus, like Bitwarden's, but only when the field
  // is empty — otherwise it covers a value the user is editing.
  document.addEventListener(
    "focusin",
    async (event) => {
      if (!IS_TOP) return;
      const el = event.target;
      if (!(el instanceof HTMLInputElement)) return;
      const isPassword = el.type === "password";
      const isUser = ["text", "email", "tel"].includes(el.type) || !el.type;
      if (!isPassword && !isUser) return;
      if (!isEmpty(el)) return;

      // Wait a beat: filling triggers focus events we must not react to.
      const started = Date.now();
      await new Promise((r) => setTimeout(r, 120));
      if (document.activeElement !== el || Date.now() - started > 1000) return;

      if (isPassword) lastFocusedPassword = el;
      await openMenu(el);
    },
    true
  );

  document.addEventListener(
    "mousedown",
    (event) => {
      if (!menu) return;
      if (event.target === menu || menu.contains(event.target)) return;
      closeMenu();
    },
    true
  );

  window.addEventListener("scroll", () => positionMenu(document.activeElement || document.body), true);
  window.addEventListener("resize", () => positionMenu(document.activeElement || document.body));

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === "fillCredentials") {
      const ok = fillCredentials(msg.username, msg.password, lastFocusedPassword);
      sendResponse({ ok });
      return true;
    }
    if (msg?.type === "showSaveBanner") {
      offerSave(msg.pending).then(() => sendResponse({ ok: true }));
      return true;
    }
    if (msg?.type === "getConfig") {
      sendResponse(config);
      return true;
    }
    return false;
  });

  // --------------------------------------------------------------- autofill

  async function autoFillOnce() {
    if (!config.autoFillOnLoad || !passwordFields().length) return;

    const res = await send({ type: "getMatches", url: location.href, reveal: true });
    if (!res.ok) return;
    const matches = res.data || [];
    if (!matches.length) return;

    // Autofill only when exactly one login matches: with several candidates,
    // guessing would be worse than letting the user pick.
    const target = passwordFields()[0];
    if (!isEmpty(target)) return;
    if (matches.length !== 1) return;

    fillCredentials(matches[0].entry.metadata?.username, matches[0].value, target);
  }

  (async () => {
    const cfg = await send({ type: "getConfig" });
    if (cfg.ok && cfg.data) config = { ...config, ...cfg.data };
    setTimeout(autoFillOnce, 600);
  })();
})();
