import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

describe("App", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("signs in, starts a shift, and displays data returned by the API", async () => {
    const shift = {
      id: "shift-1",
      scenario_id: "scenario-1",
      template: "phishing_macro",
      seed: 42,
      status: "active",
      started_at: "2026-10-11T10:00:00Z",
      ended_at: null,
      duration_minutes: 30,
      log_count: 1,
      alert_count: 1,
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith("/auth/login")) {
        return Response.json({ access_token: "test-token", expires_at: "2026-10-11T11:00:00Z" });
      }
      if (url.endsWith("/auth/me")) {
        return Response.json({
          id: "user-1",
          email: "analyst@example.org",
          display_name: "SOC Analyst",
          role: "trainee",
          is_active: true,
        });
      }
      if (url.endsWith("/settings/soc")) {
        return Response.json({
          default_shift_duration_minutes: 45,
          default_noise_events_per_minute: 8,
          critical_alert_sla_seconds: 600,
          max_query_rows: 100000,
          log_sources: ["windows_security", "sysmon", "edr"],
          attack_templates: ["phishing_macro", "brute_force", "ransomware_precursor"],
        });
      }
      if (url.endsWith("/shifts") && init?.method !== "POST") {
        return Response.json([]);
      }
      if (url.endsWith("/shifts") && init?.method === "POST") {
        return Response.json(shift, { status: 201 });
      }
      if (url.endsWith("/shifts/shift-1/alerts?limit=200")) {
        return Response.json([
          {
            id: "alert-1",
            chain_id: "chain-1",
            title: "Suspicious attachment delivered",
            description: "",
            severity: "high",
            source: "email",
            occurred_at: "2026-10-11T10:01:00Z",
            details: {},
          },
        ]);
      }
      if (url.endsWith("/shifts/shift-1/logs?limit=200")) {
        return Response.json([
          {
            id: "log-1",
            index_name: "email",
            source_type: "email_gateway",
            occurred_at: "2026-10-11T10:01:00Z",
            host: "TRAINING-WS",
            username: "training.user",
            src_ip: null,
            dst_ip: null,
            event_data: { subject: "Updated supplier invoice" },
          },
        ]);
      }
      return Response.json({ detail: `Unexpected request: ${url}` }, { status: 404 });
    });

    render(<App />);
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "analyst@example.org" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText(/Signed in as SOC Analyst/)).toBeInTheDocument();
    expect(window.sessionStorage.getItem("socforge.session_token")).toBe("test-token");
    expect(window.localStorage.getItem("socforge.access_token")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /SOC settings/ }));
    expect(await screen.findByText("Critical-alert response SLA")).toBeInTheDocument();
    expect(screen.getByText("10 min")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Operations/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start shift" }));

    expect(await screen.findByText("Suspicious attachment delivered")).toBeInTheDocument();
    expect(await screen.findByText(/subject: Updated supplier invoice/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/shifts",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ Authorization: "Bearer test-token" }),
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/shifts",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          template: "phishing_macro",
          duration_minutes: 45,
          noise_events_per_minute: 8,
        }),
      }),
    );

    fetchMock.mockRestore();
  });
});
