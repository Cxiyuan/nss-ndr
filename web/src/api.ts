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

// ---- 运维监控（仅本探针自身运维指标）----

export interface TrafficSample {
  ts: string;
  eps: number;
  bps: number;
}

export interface DatasetCount {
  dataset: string;
  count: number;
}

export interface XdrPushStats {
  success: number;
  failed: number;
  dlq: number;
  last_success?: string;
  last_failed?: string;
}

export interface WorkloadStats {
  total_events_today: number;
  events_by_dataset: DatasetCount[];
  alerts_today: number;
  strelka_files_today: number;
  xdr_push: XdrPushStats;
  generated_at: string;
  es_error?: string;
}

export interface ComponentHealth {
  name: string;
  state: string;
}

export interface ESHealth {
  status: string;
  nodes: number;
  error?: string;
}

export interface DiskUsage {
  mount: string;
  usage_pct: number;
  free_gb: number;
}

export interface CleanerStatus {
  last_run?: string;
  removed_files: number;
  removed_bytes: number;
  pressure_triggered: boolean;
  fs_usage_pct: number;
  error?: string;
}

export interface HealthStats {
  components: ComponentHealth[];
  es: ESHealth;
  disk: DiskUsage[];
  cleaner: CleanerStatus;
  generated_at: string;
}

export interface AlertBucket {
  hour: string;
  count: number;
}

export interface AlertsTodayStats {
  buckets: AlertBucket[];
  total: number;
  generated_at: string;
  es_error?: string;
}

// ---- 分析任务状态（M14: 4 步流水线 + 跨任务记忆）----

export interface AnalysisListItem {
  task_id: string;
  instruction: string;
  stage: string;
  verdict: string;
  confidence: number;
  llm_used: boolean;
  escalated: boolean;
  elapsed_ms: number;
  updated_at: string;
}

export interface AnalysisState {
  task_id: string;
  instruction: string;
  target: any;
  stage: string;
  metrics: any;
  heuristic_verdict: any;
  llm_verdict: any;
  xdr_verdict: any;
  final_verdict: any;
  llm_used: boolean;
  escalated: boolean;
  elapsed_ms: number;
  created_at: string;
  updated_at: string;
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

  // 运维监控（仅本系统自身运维指标）
  monitoringTraffic: () => req<{ samples: TrafficSample[] }>("GET", "/api/monitoring/traffic"),
  monitoringWorkload: () => req<WorkloadStats>("GET", "/api/monitoring/workload"),
  monitoringHealth: () => req<HealthStats>("GET", "/api/monitoring/health"),
  monitoringAlertsToday: () => req<AlertsTodayStats>("GET", "/api/monitoring/alerts-today"),

  // 分析任务状态（M14）
  listAnalysis: (limit?: number) => req<AnalysisListItem[]>("GET", `/api/analysis${limit ? `?limit=${limit}` : ""}`),
  getAnalysisState: (taskId: string) => req<AnalysisState>("GET", `/api/analysis/${taskId}`),
};
