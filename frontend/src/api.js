const TOKEN_KEY = "promptshield.token";

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export function setToken(value) {
  if (value) localStorage.setItem(TOKEN_KEY, value);
  else localStorage.removeItem(TOKEN_KEY);
}

function extractDetail(data, status) {
  const detail = data && data.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((item) => item?.msg || item?.detail || "").filter(Boolean);
    if (parts.length) return parts.join("; ");
  }
  if (detail && typeof detail === "object") return JSON.stringify(detail);
  return `Request failed with status ${status}.`;
}

async function request(path, { method = "GET", body, formData, auth = true } = {}) {
  const headers = {};
  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  let payload;
  if (formData) {
    payload = formData;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(`/api${path}`, { method, headers, body: payload });
  } catch (err) {
    throw new ApiError("Cannot reach the PromptShield API. Check your connection.", 0, null);
  }

  const raw = await response.text();
  let data = null;
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = { detail: raw.slice(0, 300) };
    }
  }

  if (!response.ok) {
    if (response.status === 401 && auth) {
      setToken("");
      window.dispatchEvent(new Event("promptshield:unauthorized"));
    }
    throw new ApiError(extractDetail(data, response.status), response.status, data);
  }
  return data;
}

const qs = (params = {}) => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") search.set(key, value);
  });
  const str = search.toString();
  return str ? `?${str}` : "";
};

export const api = {
  // auth
  login: (email, password) => request("/auth/login", { method: "POST", body: { email, password }, auth: false }),
  register: (payload) => request("/auth/register", { method: "POST", body: payload, auth: false }),
  me: () => request("/auth/me"),
  demoAccounts: () => request("/auth/demo-accounts", { auth: false }),

  // scanning
  scanText: (payload) => request("/scan/text", { method: "POST", body: payload }),
  scanFile: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/scan/pdf", { method: "POST", formData: form });
  },
  scanEmail: (payload) => request("/scan/email", { method: "POST", body: payload }),
  scanUrl: (payload) => request("/scan/url", { method: "POST", body: payload }),
  analyzeMultiple: (payload) => request("/analyze/multiple-documents", { method: "POST", body: payload }),
  listScans: (params) => request(`/scans${qs(params)}`),
  getScan: (id) => request(`/scans/${id}`),
  aiProcess: (id) => request(`/scans/${id}/ai-process`, { method: "POST" }),
  simulateAiCall: (id) => request(`/scans/${id}/simulate-ai-call`, { method: "POST" }),

  // dashboard / threats / history
  statistics: () => request("/dashboard/statistics"),
  analytics: (days = 14) => request(`/analytics${qs({ days })}`),
  threats: (params) => request(`/threats${qs(params)}`),
  threat: (id) => request(`/threats/${id}`),
  updateThreat: (id, payload) => request(`/threats/${id}`, { method: "PATCH", body: payload }),
  history: (params) => request(`/history${qs(params)}`),
  audit: (limit = 100) => request(`/audit${qs({ limit })}`),

  // firewall
  validateAction: (payload) => request("/firewall/validate-action", { method: "POST", body: payload }),
  actions: (limit = 50) => request(`/firewall/actions${qs({ limit })}`),
  approvals: (params) => request(`/firewall/approvals${qs(params)}`),
  decideApproval: (id, decision, note) =>
    request(`/firewall/approvals/${id}/decision`, { method: "POST", body: { decision, note } }),
  policy: () => request("/firewall/policy"),
  updatePolicy: (payload) => request("/firewall/policy", { method: "PUT", body: payload }),

  // testing lab + system
  runEvaluation: (payload) => request("/testing/run", { method: "POST", body: payload }),
  testingRuns: (limit = 20) => request(`/testing/runs${qs({ limit })}`),
  testingRun: (id) => request(`/testing/runs/${id}`),
  dataset: () => request("/testing/dataset"),
  samples: () => request("/samples"),
  systemInfo: () => request("/system/info"),
  health: () => request("/health", { auth: false }),
};

export const RISK_BADGE = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
};

export const DECISION_LABEL = {
  allow: "Allowed as untrusted",
  flag: "Flagged for review",
  quarantine: "Quarantined",
  block: "Blocked",
  require_approval: "Human approval required",
  // Firewall decisions use this wording.
  require_human_approval: "Human approval required",
};

export function decisionClass(decision) {
  if (decision === "block" || decision === "quarantine") return "badge-critical";
  if (decision === "require_approval" || decision === "require_human_approval") return "badge-high";
  if (decision === "flag") return "badge-medium";
  return "badge-low";
}

export function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function pretty(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
