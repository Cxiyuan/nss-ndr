const base = "";

let token = localStorage.getItem("ndr_token") || "";

export function setToken(t: string) {
  token = t;
  localStorage.setItem("ndr_token", t);
}

export function clearToken() {
  token = "";
  localStorage.removeItem("ndr_token");
}

export function isAuthed() {
  return !!token;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = body
    ? { "Content-Type": "application/json" }
    : {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const resp = await fetch(base + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (resp.status === 401) {
    clearToken();
    if (window.location.pathname !== "/login") {
      window.location.assign("/login");
    }
    throw new Error("登录已过期，请重新登录");
  }
  if (!resp.ok) {
    let msg = resp.statusText;
    try {
      const e = await resp.json();
      msg = e.error || msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return resp.json() as Promise<T>;
}

export interface Section {
  key: string;
  value: string;
  describe?: string;
  updated_at?: string;
}

export interface Rule {
  id?: string;
  name: string;
  name_cn?: string;
  rule: string;
  threshold?: string;
  type?: string;
  enabled?: boolean;
  category?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SigmaRule {
  id?: string;
  title: string;
  content: string;
  category?: string;
  product?: string;
  service?: string;
  level?: string;
  status?: string;
  schedule?: string;
  last_run_at?: string;
  builtin?: boolean;
  type?: string; // simple | correlation
  backend?: string;
  correlation?: {
    clue_product?: string;
    confirm_product?: string;
    group_by: string;
    timespan?: string;
    required: string;
    fallback: string;
    confidence: string;
  };
}

export interface ConfigField {
  key: string;
  label: string;
  type: string;
  group: string;
  order: number;
  help?: string;
  unit?: string;
  min?: number;
  max?: number;
  step?: number;
  options?: string[];
  default?: any;
  value?: any;
}

export interface ConfigGroup {
  key: string;
  label: string;
  order: number;
}

export interface ConfigSchema {
  groups: ConfigGroup[];
  fields: ConfigField[];
}

export interface ETOpenCat {
  key: string;
  name_cn: string;
  desc_cn: string;
  file: string;
  total: number;
  enabled_count: number;
  enabled: boolean;
}

export interface ETOpenGroup {
  key: string;
  name: string;
  desc: string;
  categories: ETOpenCat[];
}

export interface ETOpenRulePage {
  total: number;
  rules: Rule[];
}

export const api = {
  login: (username: string, password: string) =>
    req<any>("POST", "/api/login", { username, password }),
  logout: () => req<any>("POST", "/api/logout"),
  changePassword: (old_password: string, new_password: string) =>
    req<any>("POST", "/api/password", { old_password, new_password }),
  health: () => req<any>("GET", "/api/health"),
  configSchema: () => req<ConfigSchema>("GET", "/api/config/schema"),
  saveFormConfig: (fields: Record<string, any>, comment: string) =>
    req<any>("PUT", "/api/config", { fields, comment }),
  listSections: () => req<Section[]>("GET", "/api/configs"),
  getSection: (key: string) => req<Section>("GET", `/api/configs/${key}`),
  saveSection: (key: string, value: string, comment: string) =>
    req<any>("PUT", `/api/configs/${key}`, { value, comment }),
  apply: (comment: string) => req<any>("POST", "/api/apply", { comment }),
  status: () => req<any>("GET", "/api/status"),
  history: () => req<any[]>("GET", "/api/history"),
  audit: () => req<any[]>("GET", "/api/audit"),
  listRules: () => req<Rule[]>("GET", "/api/rules"),
  createRule: (r: Rule) => req<Rule>("POST", "/api/rules", r),
  updateRule: (id: string, r: Rule) => req<Rule>("PUT", `/api/rules/${id}`, r),
  deleteRule: (id: string) => req<any>("DELETE", `/api/rules/${id}`),
  setRuleEnabled: (id: string, enabled: boolean) =>
    req<any>("POST", `/api/rules/${id}/${enabled ? "enable" : "disable"}`),
  applyRules: () => req<any>("POST", "/api/rules/apply"),
  etopenTree: () => req<ETOpenGroup[]>("GET", "/api/etopen/tree"),
  etopenRules: (category: string, q: string, offset: number, limit: number) =>
    req<ETOpenRulePage>(
      "GET",
      `/api/etopen/rules?category=${encodeURIComponent(category)}&q=${encodeURIComponent(q)}&offset=${offset}&limit=${limit}`
    ),
  etopenCategory: (category: string, enabled: boolean) =>
    req<any>("POST", `/api/etopen/category/${encodeURIComponent(category)}/${enabled ? "enable" : "disable"}`),
  etopenRule: (id: string, enabled: boolean) =>
    req<any>("POST", `/api/etopen/rule/${encodeURIComponent(id)}/${enabled ? "enable" : "disable"}`),
  listSigma: () => req<SigmaRule[]>("GET", "/api/sigma"),
  createSigma: (r: SigmaRule) => req<SigmaRule>("POST", "/api/sigma", r),
  updateSigma: (id: string, r: SigmaRule) => req<SigmaRule>("PUT", `/api/sigma/${id}`, r),
  deleteSigma: (id: string) => req<any>("DELETE", `/api/sigma/${id}`),
  setSigmaStatus: (id: string, status: string) =>
    req<any>("POST", `/api/sigma/${id}/${status === "enabled" ? "enable" : "disable"}`),
  runSigma: (id: string) => req<any>("POST", `/api/sigma/${id}/run`),
  previewSigma: (id: string) => req<any>("GET", `/api/sigma/${id}/preview`),
  evidenceSigma: (id: string, window?: string) =>
    req<any>("GET", `/api/sigma/${id}/evidence${window ? `?window=${encodeURIComponent(window)}` : ""}`),
};
