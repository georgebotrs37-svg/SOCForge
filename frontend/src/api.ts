const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
const TOKEN_KEY = "socforge.session_token";
const LEGACY_TOKEN_KEY = "socforge.access_token";

export type User = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: boolean;
};

export type Shift = {
  id: string;
  scenario_id: string;
  template: "phishing_macro" | "brute_force" | "ransomware_precursor";
  seed: number;
  status: "active" | "completed" | "abandoned";
  started_at: string;
  ended_at: string | null;
  duration_minutes: number;
  log_count: number;
  alert_count: number;
};

export type Alert = {
  id: string;
  chain_id: string | null;
  title: string;
  description: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  source: string;
  occurred_at: string;
  details: Record<string, unknown>;
};

export type LogEvent = {
  id: string;
  index_name: string;
  source_type: string;
  occurred_at: string;
  host: string | null;
  username: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  event_data: Record<string, unknown>;
};

export type QueryResponse = {
  history_id: string;
  result_count: number;
  returned_count: number;
  truncated: boolean;
  results: Record<string, unknown>[];
};

function getToken(): string | null {
  const sessionToken = window.sessionStorage.getItem(TOKEN_KEY);
  if (sessionToken) return sessionToken;

  const legacyToken = window.localStorage.getItem(LEGACY_TOKEN_KEY);
  if (legacyToken) {
    window.sessionStorage.setItem(TOKEN_KEY, legacyToken);
    window.localStorage.removeItem(LEGACY_TOKEN_KEY);
  }
  return legacyToken;
}

export function getStoredToken(): string | null {
  return getToken();
}

export function saveToken(token: string): void {
  window.sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  window.localStorage.removeItem(TOKEN_KEY);
  window.sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  authenticated = true,
): Promise<T> {
  const token = authenticated ? getToken() : null;
  const response = await fetch(`${API_BASE_URL}/api/v1${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") {
        message = body.detail;
      } else if (Array.isArray(body.detail)) {
        message = body.detail
          .map((item) =>
            typeof item === "object" && item !== null && "msg" in item
              ? String(item.msg)
              : "Invalid request",
          )
          .join(", ");
      }
    } catch {
      // Keep the HTTP status message when the server does not return JSON.
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export async function login(email: string, password: string): Promise<string> {
  const result = await request<{ access_token: string }>(
    "/auth/login",
    {
      method: "POST",
      body: JSON.stringify({ email, password }),
    },
    false,
  );
  saveToken(result.access_token);
  return result.access_token;
}

export async function register(
  email: string,
  displayName: string,
  password: string,
): Promise<void> {
  await request<User>(
    "/auth/register",
    {
      method: "POST",
      body: JSON.stringify({
        email,
        display_name: displayName,
        password,
      }),
    },
    false,
  );
}

export function getCurrentUser(): Promise<User> {
  return request<User>("/auth/me");
}

export function listShifts(): Promise<Shift[]> {
  return request<Shift[]>("/shifts");
}

export type ShiftOptions = {
  duration_minutes: number;
  noise_events_per_minute: number;
};

export type SOCSettings = {
  default_shift_duration_minutes: number;
  default_noise_events_per_minute: number;
  critical_alert_sla_seconds: number;
  max_query_rows: number;
  log_sources: string[];
  attack_templates: Shift["template"][];
};

export function createShift(
  template: Shift["template"],
  options: ShiftOptions,
): Promise<Shift> {
  return request<Shift>("/shifts", {
    method: "POST",
    body: JSON.stringify({ template, ...options }),
  });
}

export function getSOCSettings(): Promise<SOCSettings> {
  return request<SOCSettings>("/settings/soc");
}

export async function checkApiHealth(): Promise<boolean> {
  const response = await fetch(`${API_BASE_URL}/health`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Health check failed (${response.status})`);
  }
  const body = (await response.json()) as { status?: unknown };
  return body.status === "ok";
}

export function listAlerts(shiftId: string): Promise<Alert[]> {
  return request<Alert[]>(`/shifts/${encodeURIComponent(shiftId)}/alerts?limit=200`);
}

export function listLogs(shiftId: string): Promise<LogEvent[]> {
  return request<LogEvent[]>(`/shifts/${encodeURIComponent(shiftId)}/logs?limit=200`);
}

export function runQuery(shiftId: string, query: string): Promise<QueryResponse> {
  return request<QueryResponse>(`/shifts/${encodeURIComponent(shiftId)}/query`, {
    method: "POST",
    body: JSON.stringify({ query, result_limit: 100 }),
  });
}
