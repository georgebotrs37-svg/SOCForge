import { useEffect, useState, type FormEvent } from "react";
import {
  checkApiHealth,
  clearToken,
  createShift,
  getCurrentUser,
  getSOCSettings,
  getStoredToken,
  listAlerts,
  listLogs,
  listShifts,
  login,
  register,
  runQuery,
  type Alert,
  type LogEvent,
  type QueryResponse,
  type SOCSettings,
  type Shift,
  type User,
} from "./api";
import SettingsPage from "./SettingsPage";
import {
  hasStoredPreferences,
  loadPreferences,
  savePreferences,
  type SOCPreferences,
} from "./preferences";

const templates: { id: Shift["template"]; label: string }[] = [
  { id: "phishing_macro", label: "Phishing with macro" },
  { id: "brute_force", label: "Brute-force login" },
  { id: "ransomware_precursor", label: "Ransomware precursor" },
];

function formatDate(value: string): string {
  return new Date(value).toLocaleString();
}

function summarizeLog(log: LogEvent): string {
  const important = Object.entries(log.event_data)
    .filter(([, value]) => ["string", "number", "boolean"].includes(typeof value))
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${String(value)}`);
  return important.join(" · ") || "No additional event details";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "An unexpected error occurred";
}

export default function App() {
  const [token, setToken] = useState(getStoredToken);
  const [user, setUser] = useState<User | null>(null);
  const [socSettings, setSocSettings] = useState<SOCSettings | null>(null);
  const [preferences, setPreferences] = useState<SOCPreferences>(loadPreferences);
  const [preferencesCustomized, setPreferencesCustomized] = useState(hasStoredPreferences);
  const [activePage, setActivePage] = useState<"dashboard" | "settings">("dashboard");
  const [shifts, setShifts] = useState<Shift[]>([]);
  const [selectedShift, setSelectedShift] = useState<Shift | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [query, setQuery] = useState("index=windows | head 20");
  const [queryResult, setQueryResult] = useState<QueryResponse | null>(null);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const template = preferences.defaultTemplate;
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(Boolean(token));
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    if (preferencesCustomized) savePreferences(preferences);
  }, [preferences, preferencesCustomized]);

  function updatePreferences(nextPreferences: SOCPreferences) {
    setPreferences(nextPreferences);
    setPreferencesCustomized(true);
  }

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    Promise.all([getCurrentUser(), listShifts(), getSOCSettings()])
      .then(([currentUser, currentShifts, currentSettings]) => {
        if (cancelled) return;
        setUser(currentUser);
        setShifts(currentShifts);
        setSocSettings(currentSettings);
        if (!hasStoredPreferences()) {
          setPreferences((current) => ({
            ...current,
            defaultDurationMinutes: currentSettings.default_shift_duration_minutes,
            defaultNoisePerMinute: currentSettings.default_noise_events_per_minute,
          }));
        }
        setSelectedShift(
          currentShifts.find((shift) => shift.status === "active") ?? currentShifts[0] ?? null,
        );
        setError("");
      })
      .catch((loadError: unknown) => {
        if (cancelled) return;
        clearToken();
        setToken(null);
        setUser(null);
        setError(errorMessage(loadError));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    if (!token || !selectedShift) {
      setAlerts([]);
      setLogs([]);
      setQueryResult(null);
      return;
    }

    let cancelled = false;
    setBusy(true);
    Promise.all([listAlerts(selectedShift.id), listLogs(selectedShift.id)])
      .then(([shiftAlerts, shiftLogs]) => {
        if (cancelled) return;
        setAlerts(shiftAlerts);
        setLogs(shiftLogs);
        setError("");
      })
      .catch((loadError: unknown) => {
        if (!cancelled) setError(errorMessage(loadError));
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedShift, token]);

  useEffect(() => {
    if (!token || !selectedShift || !preferences.autoRefresh) return;
    const interval = window.setInterval(() => {
      Promise.all([listAlerts(selectedShift.id), listLogs(selectedShift.id)])
        .then(([shiftAlerts, shiftLogs]) => {
          setAlerts(shiftAlerts);
          setLogs(shiftLogs);
          setError("");
        })
        .catch((refreshError: unknown) => setError(errorMessage(refreshError)));
    }, preferences.refreshSeconds * 1000);
    return () => window.clearInterval(interval);
  }, [preferences.autoRefresh, preferences.refreshSeconds, selectedShift, token]);

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (authMode === "register") {
        await register(email, displayName, password);
        setAuthMode("login");
        setNotice("Account created. Sign in with your new credentials.");
      } else {
        const accessToken = await login(email, password);
        setToken(accessToken);
        setPassword("");
      }
    } catch (authError) {
      setError(errorMessage(authError));
    } finally {
      setBusy(false);
    }
  }

  async function startShift() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const created = await createShift(template, {
        duration_minutes: preferences.defaultDurationMinutes,
        noise_events_per_minute: preferences.defaultNoisePerMinute,
      });
      setShifts((current) => [created, ...current]);
      setSelectedShift(created);
      setNotice("Training shift started.");
    } catch (startError) {
      setError(errorMessage(startError));
    } finally {
      setBusy(false);
    }
  }

  async function submitQuery(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedShift) return;
    setBusy(true);
    setError("");
    try {
      setQueryResult(await runQuery(selectedShift.id, query));
    } catch (queryError) {
      setError(errorMessage(queryError));
      setQueryResult(null);
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    clearToken();
    setToken(null);
    setUser(null);
    setSocSettings(null);
    setShifts([]);
    setSelectedShift(null);
    setError("");
    setNotice("");
  }

  if (loading) {
    return (
      <main className="grid min-h-screen place-items-center bg-slate-950 text-slate-200">
        <p role="status">Connecting to SOCForge…</p>
      </main>
    );
  }

  if (!token || !user) {
    return (
      <main className="grid min-h-screen place-items-center bg-slate-950 px-4 py-10 text-slate-100">
        <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-emerald-400">
            SOC Analyst Training
          </p>
          <h1 className="mt-3 text-4xl font-bold text-white">SOCForge</h1>
          <p className="mt-3 text-sm text-slate-400">
            Sign in to start and investigate a training shift.
          </p>
          <form className="mt-7 space-y-4" onSubmit={submitAuth}>
            {authMode === "register" && (
              <label className="block text-sm text-slate-300">
                Display name
                <input
                  autoComplete="name"
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-400"
                  maxLength={120}
                  onChange={(event) => setDisplayName(event.target.value)}
                  required
                  value={displayName}
                />
              </label>
            )}
            <label className="block text-sm text-slate-300">
              Email
              <input
                autoComplete="email"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-400"
                onChange={(event) => setEmail(event.target.value)}
                required
                type="email"
                value={email}
              />
            </label>
            <label className="block text-sm text-slate-300">
              Password
              <input
                autoComplete={authMode === "login" ? "current-password" : "new-password"}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-400"
                minLength={authMode === "register" ? 12 : 1}
                onChange={(event) => setPassword(event.target.value)}
                required
                type="password"
                value={password}
              />
              {authMode === "register" && (
                <span className="mt-1 block text-xs text-slate-500">At least 12 characters</span>
              )}
            </label>
            {error && <p className="text-sm text-rose-300" role="alert">{error}</p>}
            {notice && <p className="text-sm text-emerald-300" role="status">{notice}</p>}
            <button
              className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-60"
              disabled={busy}
              type="submit"
            >
              {busy ? "Please wait…" : authMode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>
          <button
            className="mt-4 w-full text-sm text-slate-400 hover:text-white"
            onClick={() => {
              setAuthMode(authMode === "login" ? "register" : "login");
              setError("");
              setNotice("");
            }}
            type="button"
          >
            {authMode === "login" ? "New to SOCForge? Create an account" : "Already registered? Sign in"}
          </button>
          <p className="mt-6 text-xs leading-5 text-slate-500">
            Educational use only. SOCForge scores are practice feedback, not a certification.
          </p>
        </section>
      </main>
    );
  }

  const criticalAlerts = alerts.filter(
    (alert) => alert.severity === "critical" || alert.severity === "high",
  ).length;

  return (
    <main className="soc-app-shell min-h-screen text-slate-100">
      <aside className="soc-sidebar">
        <a aria-label="SOCForge home" className="soc-brand" href="/">
          <span className="soc-brand-mark">S</span>
          <span>
            <strong>SOCForge</strong>
            <small>THREAT OPERATIONS</small>
          </span>
        </a>
        <p className="soc-nav-label">WORKSPACE</p>
        <nav aria-label="Main navigation" className="soc-nav">
          <button
            aria-current={activePage === "dashboard" ? "page" : undefined}
            className={activePage === "dashboard" ? "soc-nav-item active" : "soc-nav-item"}
            onClick={() => setActivePage("dashboard")}
            type="button"
          >
            <span className="soc-nav-icon">⌂</span> Operations
            <span className="soc-nav-dot" />
          </button>
          <button
            aria-current={activePage === "settings" ? "page" : undefined}
            className={activePage === "settings" ? "soc-nav-item active" : "soc-nav-item"}
            onClick={() => setActivePage("settings")}
            type="button"
          >
            <span className="soc-nav-icon">⚙</span> SOC settings
          </button>
        </nav>
        <p className="soc-nav-label soc-nav-label-spaced">THREAT ENVIRONMENT</p>
        <div className="soc-side-status">
          <span className="soc-live-dot" />
          <span>
            <strong>Training range</strong>
            <small>Isolated · Safe mode</small>
          </span>
        </div>
        <div className="soc-sidebar-bottom">
          <div className="soc-user-chip">
            <span className="soc-avatar">{user.display_name.slice(0, 1).toUpperCase()}</span>
            <span className="soc-user-text">
              <strong>{user.display_name}</strong>
              <small>{user.role}</small>
            </span>
          </div>
          <p>EDUCATIONAL ENVIRONMENT<br />No production systems connected</p>
        </div>
      </aside>

      <div className="soc-workspace">
        <div className="soc-utility-bar">
          <span><span className="soc-live-dot" /> TRAINING ENVIRONMENT</span>
          <span>CONTROLLED SIMULATION <i /> SOCFORGE PLATFORM</span>
        </div>
        <div className="soc-content mx-auto max-w-[1600px] space-y-6">
        <header className="soc-topbar rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-2xl shadow-slate-950/40">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="soc-eyebrow">SECURITY OPERATIONS CENTER <span>/</span> {activePage === "dashboard" ? "OVERVIEW" : "CONFIGURATION"}</p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white md:text-4xl">
                {activePage === "dashboard" ? "Operations overview" : "SOC configuration"}
              </h1>
              <p className="mt-2 text-sm text-slate-400">
                Live training telemetry · Signed in as {user.display_name}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {shifts.length > 0 && (
                <label className="text-sm text-slate-300">
                  Shift
                  <select
                    className="ml-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                    onChange={(event) => {
                      const shift = shifts.find((item) => item.id === event.target.value);
                      setSelectedShift(shift ?? null);
                    }}
                    value={selectedShift?.id ?? ""}
                  >
                    {shifts.map((shift) => (
                      <option key={shift.id} value={shift.id}>
                        {shift.template} · {shift.status} · {formatDate(shift.started_at)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <button
                className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-slate-500 hover:text-white"
                onClick={signOut}
                type="button"
              >
                Sign out
              </button>
            </div>
          </div>
        </header>

        {error && (
          <div className="flex items-start justify-between gap-4 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200" role="alert">
            <span>{error}</span>
            <button className="text-rose-100 hover:text-white" onClick={() => setError("")} type="button">
              Dismiss
            </button>
          </div>
        )}
        {notice && <p className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200" role="status">{notice}</p>}

        {activePage === "settings" && socSettings ? (
          <SettingsPage
            settings={socSettings}
            preferences={preferences}
            onChange={updatePreferences}
            onCheckApi={async () => {
              const healthy = await checkApiHealth();
              if (!healthy) throw new Error("SOCForge API health check returned an unhealthy status.");
            }}
          />
        ) : !selectedShift ? (
          <section className="rounded-2xl border border-slate-800 bg-slate-900 p-8 text-center">
            <h2 className="text-2xl font-semibold text-white">Start a training shift</h2>
            <p className="mx-auto mt-2 max-w-xl text-sm text-slate-400">
              Choose a seeded scenario. SOCForge will generate isolated logs and alerts for investigation.
            </p>
            <div className="mx-auto mt-6 flex max-w-lg flex-col gap-3 sm:flex-row">
              <select
                aria-label="Scenario template"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                onChange={(event) =>
                  updatePreferences({
                    ...preferences,
                    defaultTemplate: event.target.value as Shift["template"],
                  })
                }
                value={template}
              >
                {templates.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
              </select>
              <button
                className="rounded-lg bg-emerald-500 px-5 py-2 font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-60"
                disabled={busy}
                onClick={() => void startShift()}
                type="button"
              >
                {busy ? "Starting…" : "Start shift"}
              </button>
            </div>
          </section>
        ) : (
          <>
            <section className="soc-metric-grid grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {[
                { label: "TOTAL ALERTS", value: alerts.length, tone: "cyan", note: "In current shift", glyph: "◎" },
                { label: "HIGH PRIORITY", value: criticalAlerts, tone: "red", note: "Requires triage", glyph: "!" },
                { label: "EVENTS INGESTED", value: logs.length, tone: "amber", note: "Latest 200 events", glyph: "⌁" },
                { label: "SHIFT STATUS", value: selectedShift.status, tone: "green", note: selectedShift.template.replaceAll("_", " "), glyph: "◉" },
              ].map((item) => (
                <div key={item.label} className={`soc-metric soc-metric-${item.tone} rounded-xl border border-slate-800 bg-slate-900 p-5`}>
                  <div className="flex items-start justify-between">
                    <p className="soc-metric-label">{item.label}</p>
                    <span className="soc-metric-glyph">{item.glyph}</span>
                  </div>
                  <p className="soc-metric-value capitalize">{item.value}</p>
                  <p className="soc-metric-note"><span />{item.note}</p>
                </div>
              ))}
            </section>

            <section className="grid gap-5 xl:grid-cols-[1.35fr_0.65fr]">
              <div className="soc-panel rounded-2xl border border-slate-800 bg-slate-900 p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <p className="soc-panel-kicker">DETECTION STREAM</p>
                    <h2 className="text-lg font-semibold text-white">Alert queue</h2>
                  </div>
                  <span className="soc-count-pill"><span className="soc-live-dot" />{alerts.length} EVENTS</span>
                </div>
                {alerts.length === 0 ? (
                  <p className="text-sm text-slate-400">No alerts returned for this shift.</p>
                ) : (
                  <div className="space-y-3">
                    {alerts.map((alert) => (
                      <article key={alert.id} className={`soc-alert-row soc-alert-${alert.severity} rounded-xl border border-slate-800 bg-slate-950/70 p-4`}>
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="soc-panel-kicker">{alert.source} <span>/</span> DETECTION</p>
                            <h3 className="mt-2 text-base font-semibold text-white">{alert.title}</h3>
                            {alert.description && <p className="mt-1 text-sm text-slate-300">{alert.description}</p>}
                          </div>
                          <span className="soc-severity-badge rounded-full border px-2 py-1 text-xs font-medium capitalize">
                            {alert.severity}
                          </span>
                        </div>
                        <p className="mt-3 text-sm text-slate-400">Time: {formatDate(alert.occurred_at)}</p>
                      </article>
                    ))}
                  </div>
                )}
              </div>

              <div className="soc-panel soc-shift-panel rounded-2xl border border-slate-800 bg-slate-900 p-5">
                <p className="soc-panel-kicker">MISSION CONTROL</p>
                <h2 className="text-lg font-semibold text-white">Active investigation</h2>
                <div className="soc-shift-banner">
                  <span className="soc-live-dot" />
                  <span><strong>{selectedShift.status.toUpperCase()}</strong><small>ISOLATED TRAINING SHIFT</small></span>
                  <span className="soc-shift-clock">{selectedShift.duration_minutes}<small>MIN</small></span>
                </div>
                <dl className="mt-4 space-y-3 text-sm">
                  <div className="soc-detail-line flex justify-between gap-3"><dt>SCENARIO</dt><dd>{selectedShift.template.replaceAll("_", " ")}</dd></div>
                  <div className="soc-detail-line flex justify-between gap-3"><dt>STARTED</dt><dd>{formatDate(selectedShift.started_at)}</dd></div>
                  <div className="soc-detail-line flex justify-between gap-3"><dt>EVENTS</dt><dd>{selectedShift.log_count.toLocaleString()}</dd></div>
                  <div className="soc-detail-line flex justify-between gap-3"><dt>SCENARIO SEED</dt><dd>{selectedShift.seed}</dd></div>
                </dl>
                <div className="mt-6 border-t border-slate-800 pt-5">
                  <label className="block text-sm font-medium text-white" htmlFor="new-template">Start another shift</label>
                  <div className="mt-2 flex gap-2">
                    <select
                      id="new-template"
                      className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                      onChange={(event) =>
                        updatePreferences({
                          ...preferences,
                          defaultTemplate: event.target.value as Shift["template"],
                        })
                      }
                      value={template}
                    >
                      {templates.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
                    </select>
                    <button
                      className="rounded-lg bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-60"
                      disabled={busy}
                      onClick={() => void startShift()}
                      type="button"
                    >
                      Start
                    </button>
                  </div>
                </div>
              </div>
            </section>

            <section className="grid gap-5 xl:grid-cols-[1.05fr_0.95fr]">
              <div className="soc-panel rounded-2xl border border-slate-800 bg-slate-900 p-5">
                <p className="soc-panel-kicker">TELEMETRY</p>
                <h2 className="text-lg font-semibold text-white">Event stream</h2>
                <div className="mt-4 overflow-x-auto rounded-xl border border-slate-800">
                  <table className="soc-event-table min-w-full divide-y divide-slate-800 text-left text-sm">
                    <thead className="bg-slate-800/80 text-slate-300">
                      <tr>
                        <th className="px-3 py-2 font-medium">Time</th>
                        <th className="px-3 py-2 font-medium">Host</th>
                        <th className="px-3 py-2 font-medium">Source</th>
                        <th className="px-3 py-2 font-medium">Event details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-950/60 text-slate-200">
                      {logs.slice(-30).map((log) => (
                        <tr key={log.id}>
                          <td className="whitespace-nowrap px-3 py-2 text-slate-400">{new Date(log.occurred_at).toLocaleTimeString()}</td>
                          <td className="px-3 py-2">{log.host ?? "—"}</td>
                          <td className="px-3 py-2">{log.source_type}</td>
                          <td className="min-w-56 px-3 py-2 text-slate-400">{summarizeLog(log)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {logs.length > 30 && <p className="mt-2 text-xs text-slate-500">Showing the latest 30 of {logs.length} fetched events.</p>}
              </div>

              <div className="soc-panel soc-query-panel rounded-2xl border border-slate-800 bg-slate-900 p-5">
                <p className="soc-panel-kicker">HUNT CONSOLE</p>
                <h2 className="text-lg font-semibold text-white">Query workspace</h2>
                <p className="mt-1 text-sm text-slate-400">Run a SPL-like query against this shift’s logs.</p>
                <form className="mt-4 space-y-3" onSubmit={submitQuery}>
                  <label className="sr-only" htmlFor="log-query">Log query</label>
                  <textarea
                    id="log-query"
                    className="min-h-24 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-emerald-400"
                    onChange={(event) => setQuery(event.target.value)}
                    required
                    value={query}
                  />
                  <button
                    className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60"
                    disabled={busy || selectedShift.status !== "active"}
                    type="submit"
                  >
                    {busy ? "Working…" : "Run query"}
                  </button>
                </form>
                {queryResult && (
                  <div className="mt-4">
                    <p className="text-sm text-slate-300">
                      {queryResult.result_count} results
                      {queryResult.truncated ? " (display limited to 100)" : ""}
                    </p>
                    <pre className="mt-2 max-h-72 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-emerald-200">
                      {JSON.stringify(queryResult.results, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </section>
          </>
        )}
        {busy && <p className="text-right text-xs text-slate-500" role="status">Syncing with the API…</p>}
        <footer className="soc-footer">
          <span>SOCFORGE <i /> TIER 1–2 ANALYST TRAINING</span>
          <span>SIMULATED DATA · SAFE BY DESIGN</span>
        </footer>
        </div>
      </div>
    </main>
  );
}
