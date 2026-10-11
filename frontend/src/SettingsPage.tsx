import { useState } from "react";
import type { SOCSettings } from "./api";
import type { SOCPreferences } from "./preferences";

type SettingsPageProps = {
  settings: SOCSettings;
  preferences: SOCPreferences;
  onChange: (preferences: SOCPreferences) => void;
  onCheckApi: () => Promise<void>;
};

const sourceLabels: Record<string, string> = {
  windows_security: "Windows Security",
  sysmon: "Sysmon",
  dns: "DNS",
  proxy: "Web proxy",
  firewall: "Firewall",
  edr: "Endpoint detection (EDR)",
  email_gateway: "Email gateway",
};

export default function SettingsPage({
  settings,
  preferences,
  onChange,
  onCheckApi,
}: SettingsPageProps) {
  const [checking, setChecking] = useState(false);
  const [connectionMessage, setConnectionMessage] = useState("");

  async function checkConnection() {
    setChecking(true);
    try {
      await onCheckApi();
      setConnectionMessage("SOCForge API is reachable.");
    } catch (error) {
      setConnectionMessage(error instanceof Error ? error.message : "API health check failed.");
    } finally {
      setChecking(false);
    }
  }

  return (
    <section className="space-y-6" aria-labelledby="settings-title">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-emerald-400">
          SOC workspace
        </p>
        <h2 id="settings-title" className="mt-2 text-3xl font-bold text-white">
          SOC settings
        </h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-400">
          Tune your training shifts and monitoring workflow. Organization-wide controls remain server-managed.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="text-lg font-semibold text-white">Training shift defaults</h3>
          <p className="mt-1 text-sm text-slate-400">
            These preferences apply when you start your next shift.
          </p>
          <div className="mt-5 space-y-5">
            <label className="block text-sm text-slate-300">
              Default scenario
              <select
                className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                onChange={(event) =>
                  onChange({
                    ...preferences,
                    defaultTemplate: event.target.value as SOCPreferences["defaultTemplate"],
                  })
                }
                value={preferences.defaultTemplate}
              >
                <option value="phishing_macro">Phishing with macro</option>
                <option value="brute_force">Brute-force login</option>
                <option value="ransomware_precursor">Ransomware precursor</option>
              </select>
            </label>
            <label className="block text-sm text-slate-300">
              Shift duration: <strong className="text-white">{preferences.defaultDurationMinutes} min</strong>
              <input
                className="mt-3 block w-full accent-emerald-400"
                max={240}
                min={5}
                onChange={(event) =>
                  onChange({
                    ...preferences,
                    defaultDurationMinutes: Number(event.target.value),
                  })
                }
                step={5}
                type="range"
                value={preferences.defaultDurationMinutes}
              />
              <span className="mt-1 flex justify-between text-xs text-slate-500">
                <span>5 min</span><span>240 min</span>
              </span>
            </label>
            <label className="block text-sm text-slate-300">
              Background telemetry: <strong className="text-white">{preferences.defaultNoisePerMinute} events/min</strong>
              <input
                className="mt-3 block w-full accent-emerald-400"
                max={100}
                min={0}
                onChange={(event) =>
                  onChange({
                    ...preferences,
                    defaultNoisePerMinute: Number(event.target.value),
                  })
                }
                type="range"
                value={preferences.defaultNoisePerMinute}
              />
              <span className="mt-1 flex justify-between text-xs text-slate-500">
                <span>Quiet</span><span>Busy SOC</span>
              </span>
            </label>
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="text-lg font-semibold text-white">Monitoring workflow</h3>
          <p className="mt-1 text-sm text-slate-400">
            Keep the analyst console synchronized with the active shift.
          </p>
          <label className="mt-5 flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
            <input
              checked={preferences.autoRefresh}
              className="mt-1 accent-emerald-400"
              onChange={(event) =>
                onChange({ ...preferences, autoRefresh: event.target.checked })
              }
              type="checkbox"
            />
            <span>
              <span className="block text-sm font-medium text-white">Auto-refresh alerts and logs</span>
              <span className="mt-1 block text-xs text-slate-400">
                Refresh the active shift periodically without reloading the page.
              </span>
            </span>
          </label>
          <label className="mt-4 block text-sm text-slate-300">
            Refresh interval
            <select
              className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white disabled:opacity-50"
              disabled={!preferences.autoRefresh}
              onChange={(event) =>
                onChange({
                  ...preferences,
                  refreshSeconds: Number(event.target.value) as SOCPreferences["refreshSeconds"],
                })
              }
              value={preferences.refreshSeconds}
            >
              <option value={15}>15 seconds</option>
              <option value={30}>30 seconds</option>
              <option value={60}>60 seconds</option>
            </select>
          </label>
          <button
            className="mt-5 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-emerald-400 disabled:opacity-50"
            disabled={checking}
            onClick={() => void checkConnection()}
            type="button"
          >
            {checking ? "Checking…" : "Check API connection"}
          </button>
          {connectionMessage && (
            <p className="mt-3 text-sm text-slate-300" role="status">
              {connectionMessage}
            </p>
          )}
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="text-lg font-semibold text-white">SOC operating policy</h3>
          <p className="mt-1 text-sm text-slate-400">
            Read-only server policy used for training and query safety.
          </p>
          <dl className="mt-5 divide-y divide-slate-800">
            <div className="flex justify-between gap-4 py-3 text-sm">
              <dt className="text-slate-400">Critical-alert response SLA</dt>
              <dd className="font-medium text-white">{Math.round(settings.critical_alert_sla_seconds / 60)} min</dd>
            </div>
            <div className="flex justify-between gap-4 py-3 text-sm">
              <dt className="text-slate-400">Maximum rows per investigation query</dt>
              <dd className="font-medium text-white">{settings.max_query_rows.toLocaleString()}</dd>
            </div>
            <div className="flex justify-between gap-4 py-3 text-sm">
              <dt className="text-slate-400">Server default shift</dt>
              <dd className="font-medium text-white">{settings.default_shift_duration_minutes} min</dd>
            </div>
            <div className="flex justify-between gap-4 py-3 text-sm">
              <dt className="text-slate-400">Server default background events</dt>
              <dd className="font-medium text-white">{settings.default_noise_events_per_minute}/min</dd>
            </div>
          </dl>
          <p className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs leading-5 text-amber-100/80">
            JWT keys, database credentials, CORS, and production host policy are never exposed in the browser. Set them on the server through environment variables.
          </p>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="text-lg font-semibold text-white">Telemetry & scenarios</h3>
          <p className="mt-1 text-sm text-slate-400">
            Event families and attack chains available to this SOC training workspace.
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {settings.log_sources.map((source) => (
              <span key={source} className="rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-1.5 text-xs text-cyan-100">
                {sourceLabels[source] ?? source}
              </span>
            ))}
          </div>
          <div className="mt-5 border-t border-slate-800 pt-4">
            <h4 className="text-sm font-medium text-slate-200">Attack scenarios</h4>
            <ul className="mt-2 space-y-2 text-sm text-slate-400">
              {settings.attack_templates.map((template) => (
                <li key={template} className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  {template.replaceAll("_", " ")}
                </li>
              ))}
            </ul>
          </div>
        </section>
      </div>
    </section>
  );
}
