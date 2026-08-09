const base = "";

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const resp = await fetch(base + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
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
  rule: string;
  threshold?: string;
  type?: string;
  enabled?: boolean;
  category?: string;
  created_at?: string;
  updated_at?: string;
}

export const api = {
  health: () => req<any>("GET", "/api/health"),
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
};
