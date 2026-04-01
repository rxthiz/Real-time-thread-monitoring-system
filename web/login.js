const el = {
  form: document.getElementById("loginForm"),
  roleInput: document.getElementById("roleInput"),
  usernameInput: document.getElementById("usernameInput"),
  passwordInput: document.getElementById("passwordInput"),
  loginBtn: document.getElementById("loginBtn"),
  loginError: document.getElementById("loginError"),
};

const ROLE_USERNAMES = {
  user: "user",
  admin: "admin",
};

function setError(message) {
  if (!message) {
    el.loginError.hidden = true;
    el.loginError.textContent = "";
    return;
  }
  el.loginError.hidden = false;
  el.loginError.textContent = String(message);
}

function updateRoleDefaults() {
  const role = String(el.roleInput.value || "user").toLowerCase();
  const defaultUsername = ROLE_USERNAMES[role];
  if (!el.usernameInput.value && defaultUsername) {
    el.usernameInput.value = defaultUsername;
  }
}

async function ensureLoggedOutView() {
  try {
    const res = await fetch("/api/auth/me", { cache: "no-store" });
    if (res.ok) {
      window.location.replace("/");
    }
  } catch (_err) {
    // Ignore startup auth checks if backend is unavailable.
  }
}

async function onSubmit(event) {
  event.preventDefault();
  setError("");
  el.loginBtn.disabled = true;

  const role = String(el.roleInput.value || "").trim().toLowerCase();
  const username = String(el.usernameInput.value || "").trim();
  const password = String(el.passwordInput.value || "");

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role, username, password }),
    });
    if (!res.ok) {
      let reason = `Login failed (${res.status})`;
      try {
        const body = await res.json();
        if (body?.detail) reason = String(body.detail);
      } catch (_err) {
        // Ignore parse failures.
      }
      throw new Error(reason);
    }
    window.location.replace("/");
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unable to login";
    setError(msg);
  } finally {
    el.loginBtn.disabled = false;
  }
}

function init() {
  updateRoleDefaults();
  el.roleInput.addEventListener("change", updateRoleDefaults);
  el.form.addEventListener("submit", (event) => {
    onSubmit(event).catch(() => setError("Unable to login"));
  });
  ensureLoggedOutView().catch(() => {});
}

init();
