const SESSION_KEY = "villamor-supabase-session";

export class SupabaseClient {
  constructor(url, publishableKey) {
    this.url = url.replace(/\/$/, "");
    this.publishableKey = publishableKey;
    this.session = this.readSession();
  }

  readSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY);
      localStorage.removeItem(SESSION_KEY);
      if (raw) sessionStorage.setItem(SESSION_KEY, raw);
      return JSON.parse(raw) || null;
    } catch {
      return null;
    }
  }

  saveSession(session) {
    this.session = session;
    localStorage.removeItem(SESSION_KEY);
    if (session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    else sessionStorage.removeItem(SESSION_KEY);
  }

  async signIn(email, password) {
    const session = await this.authRequest("/token?grant_type=password", {
      method: "POST",
      body: { email, password },
    });
    this.saveSession(session);
    return session;
  }

  async signUp(email, password, displayName) {
    const result = await this.authRequest("/signup", {
      method: "POST",
      body: {
        email,
        password,
        data: { display_name: displayName },
      },
    });
    if (result.access_token) this.saveSession(result);
    return result;
  }

  async requestPasswordReset(email, redirectTo) {
    const query = redirectTo ? `?redirect_to=${encodeURIComponent(redirectTo)}` : "";
    return this.authRequest(`/recover${query}`, {
      method: "POST",
      body: { email },
    });
  }

  consumePasswordRecovery() {
    const parameters = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    if (parameters.get("type") !== "recovery") return false;

    const accessToken = parameters.get("access_token");
    const refreshToken = parameters.get("refresh_token");
    if (!accessToken || !refreshToken) return false;

    this.saveSession({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: parameters.get("token_type") || "bearer",
      expires_in: Number(parameters.get("expires_in") || 3600),
      expires_at: Math.round(Date.now() / 1000) + Number(parameters.get("expires_in") || 3600),
      user: decodeJwtPayload(accessToken)?.sub
        ? { id: decodeJwtPayload(accessToken).sub }
        : null,
    });
    history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
    return true;
  }

  consumeAuthRedirectError() {
    const parameters = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const description = parameters.get("error_description");
    if (!description) return "";
    history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
    return description;
  }

  async updatePassword(password) {
    const user = await this.authUserRequest("/user", {
      method: "PUT",
      body: JSON.stringify({ password }),
    });
    if (this.session) this.saveSession({ ...this.session, user });
    return user;
  }

  async signOut() {
    if (this.session?.access_token) {
      await fetch(`${this.url}/auth/v1/logout`, {
        method: "POST",
        headers: this.headers(true),
      }).catch(() => null);
    }
    this.saveSession(null);
  }

  async refreshSession() {
    if (!this.session?.refresh_token) return null;
    try {
      const session = await this.authRequest("/token?grant_type=refresh_token", {
        method: "POST",
        body: { refresh_token: this.session.refresh_token },
      });
      this.saveSession(session);
      return session;
    } catch (error) {
      this.saveSession(null);
      error.code = "AUTH_REQUIRED";
      throw error;
    }
  }

  async authRequest(path, { method, body }) {
    const response = await fetch(`${this.url}/auth/v1${path}`, {
      method,
      headers: {
        apikey: this.publishableKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.msg || payload.message || payload.error_description || "Falha na autenticação.");
    }
    return payload;
  }

  async authUserRequest(path, options = {}, retry = true) {
    const response = await fetch(`${this.url}/auth/v1${path}`, {
      ...options,
      headers: this.headers(true, {
        "Content-Type": "application/json",
        ...options.headers,
      }),
    });

    if (response.status === 401 && retry && this.session?.refresh_token) {
      await this.refreshSession();
      return this.authUserRequest(path, options, false);
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(
        payload.msg || payload.message || payload.error_description || `Erro de autenticação ${response.status}.`,
      );
      error.code = payload.code || (response.status === 401 ? "AUTH_REQUIRED" : "AUTH_ERROR");
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  getAssuranceLevel() {
    return decodeJwtPayload(this.session?.access_token)?.aal || "aal1";
  }

  async getUser() {
    return this.authUserRequest("/user", { method: "GET" });
  }

  async listFactors() {
    const user = await this.getUser();
    return Array.isArray(user?.factors) ? user.factors : [];
  }

  async enrollTotp(friendlyName = "POS-VENDA VIP") {
    const factor = await this.authUserRequest("/factors", {
      method: "POST",
      body: JSON.stringify({
        factor_type: "totp",
        friendly_name: friendlyName,
      }),
    });

    if (factor?.totp?.qr_code && !factor.totp.qr_code.startsWith("data:")) {
      factor.totp.qr_code = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(factor.totp.qr_code)}`;
    }
    return factor;
  }

  async unenrollFactor(factorId) {
    return this.authUserRequest(`/factors/${encodeURIComponent(factorId)}`, {
      method: "DELETE",
    });
  }

  async challengeMfa(factorId) {
    return this.authUserRequest(`/factors/${encodeURIComponent(factorId)}/challenge`, {
      method: "POST",
      body: "{}",
    });
  }

  async verifyMfa(factorId, challengeId, code) {
    const result = await this.authUserRequest(`/factors/${encodeURIComponent(factorId)}/verify`, {
      method: "POST",
      body: JSON.stringify({
        challenge_id: challengeId,
        code,
      }),
    });
    const session = {
      ...this.session,
      ...result,
      user: result.user || this.session?.user,
      expires_at: Math.round(Date.now() / 1000) + Number(result.expires_in || 3600),
    };
    this.saveSession(session);
    return session;
  }

  headers(authenticated = true, extra = {}) {
    return {
      apikey: this.publishableKey,
      ...(authenticated && this.session?.access_token
        ? { Authorization: `Bearer ${this.session.access_token}` }
        : {}),
      ...extra,
    };
  }

  async request(path, options = {}, retry = true) {
    const response = await fetch(`${this.url}/rest/v1/${path}`, {
      ...options,
      headers: this.headers(true, options.headers),
    });

    if (response.status === 401 && retry && this.session?.refresh_token) {
      await this.refreshSession();
      return this.request(path, options, false);
    }

    const text = await response.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = text || null;
    }
    if (!response.ok) {
      const error = new Error(
        payload?.message || payload?.details || (typeof payload === "string" && payload) || `Erro Supabase ${response.status}.`,
      );
      error.code = payload?.code || (response.status === 401 ? "AUTH_REQUIRED" : "SUPABASE_ERROR");
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  async selectAll(table, query = "select=*") {
    const rows = [];
    const pageSize = 1000;
    const orderedQuery = query.includes("order=")
      ? query
      : `${query}&order=${encodeURIComponent(defaultOrder(table))}`;
    for (let offset = 0; ; offset += pageSize) {
      const page = await this.request(`${table}?${orderedQuery}`, {
        headers: { Range: `${offset}-${offset + pageSize - 1}` },
      });
      rows.push(...page);
      if (page.length < pageSize) return rows;
    }
  }

  async rpc(name, args = {}) {
    return this.request(`rpc/${encodeURIComponent(name)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify(args),
    });
  }

  async upsert(table, rows, onConflict) {
    const chunkSize = 200;
    for (let index = 0; index < rows.length; index += chunkSize) {
      await this.request(`${table}?on_conflict=${encodeURIComponent(onConflict)}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Prefer: "resolution=merge-duplicates,return=minimal",
        },
        body: JSON.stringify(rows.slice(index, index + chunkSize)),
      });
    }
  }

  async insert(table, row) {
    return this.request(table, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify(row),
    });
  }

  async delete(table, filter) {
    return this.request(`${table}?${filter}`, {
      method: "DELETE",
      headers: { Prefer: "return=minimal" },
    });
  }
}

function defaultOrder(table) {
  return {
    profiles: "id.asc",
    contracts: "contract_id.asc",
    terminations: "contract_id.asc",
    source_terminations: "contract_id.asc",
    source_reversions: "contract_id.asc",
    source_exceptions: "contract_id.asc",
    import_runs: "created_at.desc,id.desc",
    audit_logs: "created_at.desc,id.desc",
    app_settings: "key.asc",
  }[table] || "id.asc";
}

function decodeJwtPayload(token) {
  if (!token) return null;
  try {
    const payload = token.split(".")[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, "=");
    return JSON.parse(decodeURIComponent(
      atob(padded)
        .split("")
        .map((character) => `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`)
        .join(""),
    ));
  } catch {
    return null;
  }
}
