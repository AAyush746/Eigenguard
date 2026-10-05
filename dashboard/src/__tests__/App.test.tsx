import { render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import App from "../App"
import type { Session, Stats } from "../types/api"

/**
 * Contract test: the dashboard is rendered against a payload shaped exactly
 * like the honeypot API's, and every field the components read must exist.
 *
 * The original dashboard asked for `/api/attacks` and read `flow_duration`,
 * `syn_flag_count` and `username`, none of which the API returned, so it
 * rendered nothing at all. Asserting on real field names is what stops that
 * from silently coming back.
 */

const NOW = "2026-03-01T12:30:00"

function makeStats(overrides: Partial<Stats> = {}): Stats {
  return {
    total_sessions: 42,
    total_attempts: 137,
    sessions_today: 7,
    attempts_today: 19,
    unique_ips: 5,
    unique_countries: 3,
    bruteforce_sessions: 9,
    top_countries: [{ name: "China", count: 12 }],
    top_usernames: [{ name: "root", count: 88 }],
    top_passwords: [{ name: "123456", count: 30 }],
    avg_flow_duration: 4.25,
    max_flow_rate: 2048,
    avg_packet_size: 175.5,
    avg_attempts_per_session: 3.26,
    first_seen: "2026-03-01T00:00:00",
    last_seen: NOW,
    ...overrides,
  }
}

function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    id: 1,
    started_at: NOW,
    ended_at: NOW,
    duration_seconds: 4.25,
    src_ip: "203.0.113.10",
    src_port: 55512,
    dst_port: 2222,
    country: "China",
    country_code: "CN",
    city: "Shanghai",
    region: "Shanghai",
    latitude: 31.23,
    longitude: 121.47,
    geo_source: "geoip2",
    client_version: "SSH-2.0-OpenSSH_8.2p1",
    kex_algorithm: "curve25519-sha256",
    host_key_type: "ssh-ed25519",
    auth_methods_offered: "password,keyboard-interactive",
    auth_methods_tried: "password",
    total_fwd_packets: 12,
    total_bwd_packets: 30,
    total_length_fwd_packets: 900,
    total_length_bwd_packets: 4200,
    flow_bytes_per_second: 1200,
    flow_packets_per_second: 9.8,
    fwd_packet_length_max: 96,
    fwd_packet_length_mean: 75,
    fwd_packet_length_std: 12,
    fwd_packet_length_min: 34,
    bwd_packet_length_max: 400,
    bwd_packet_length_mean: 140,
    bwd_packet_length_std: 30,
    bwd_packet_length_min: 22,
    flow_iat_mean: 0.21,
    flow_iat_std: 0.04,
    flow_iat_max: 0.9,
    flow_iat_min: 0.01,
    fwd_iat_mean: 0.3,
    fwd_iat_std: 0.1,
    fwd_iat_max: 1.2,
    bwd_iat_mean: 0.15,
    bwd_iat_std: 0.02,
    bwd_iat_max: 0.5,
    down_up_ratio: 2.5,
    average_packet_size: 175.5,
    avg_fwd_segment_size: 75,
    avg_bwd_segment_size: 140,
    attempt_count: 3,
    label: "ssh-bruteforce",
    detection_reason: "3 failed auth attempts (threshold 3)",
    attempts: [
      {
        id: 1,
        session_id: 1,
        username: "root",
        password: "123456",
        auth_method: "password",
        success: false,
        attempted_at: NOW,
      },
      {
        id: 2,
        session_id: 1,
        username: "root",
        password: "admin",
        auth_method: "password",
        success: false,
        attempted_at: NOW,
      },
    ],
    ...overrides,
  }
}

const HEALTH = {
  status: "ok",
  geoip: {
    enabled: true,
    available: true,
    database_path: "/data/GeoLite2-City.mmdb",
    error: null,
  },
}

function mockApi(sessions: Session[], stats: Stats = makeStats()) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)

    if (url.includes("/api/stats")) {
      return new Response(JSON.stringify(stats), { status: 200 })
    }
    if (url.includes("/api/health")) {
      return new Response(JSON.stringify(HEALTH), { status: 200 })
    }
    if (url.includes("/api/sessions")) {
      return new Response(
        JSON.stringify({ total: sessions.length, limit: 100, offset: 0, results: sessions }),
        { status: 200 },
      )
    }
    return new Response("not found", { status: 404 })
  })
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn())
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("App against a real API payload", () => {
  it("requests the endpoints the honeypot actually serves", async () => {
    const fetchMock = mockApi([makeSession()])
    vi.stubGlobal("fetch", fetchMock)

    render(<App />)
    await waitFor(() => expect(screen.getByText(/Sessions captured/i)).toBeTruthy())

    const urls = fetchMock.mock.calls.map((call) => String(call[0]))
    expect(urls.some((url) => url.includes("/api/sessions"))).toBe(true)
    expect(urls.some((url) => url.includes("/api/stats"))).toBe(true)
    // The endpoint the old dashboard called, which has never existed.
    expect(urls.some((url) => url.includes("/api/attacks"))).toBe(false)
  })

  it("renders sessions, locations and credentials from the response", async () => {
    vi.stubGlobal("fetch", mockApi([makeSession()]))

    const { container } = render(<App />)

    await waitFor(() => expect(screen.getByText("203.0.113.10:55512")).toBeTruthy())
    // Scoped to the table: the map renders a tooltip <title> with the city too.
    const table = container.querySelector("table")
    expect(table).toBeTruthy()
    expect(table?.textContent).toContain("Shanghai, China")
    expect(table?.textContent).toContain("root:123456")
    expect(table?.textContent).toContain("Brute force")
    // 4.25 seconds, not the microsecond conversion the old table assumed.
    expect(table?.textContent).toContain("4.25s")
  })

  it("shows counters from the stats payload", async () => {
    vi.stubGlobal("fetch", mockApi([makeSession()]))

    render(<App />)

    await waitFor(() => expect(screen.getByText("42")).toBeTruthy())
    expect(screen.getByText("Sessions captured")).toBeTruthy()
    expect(screen.getByText("137")).toBeTruthy()
    expect(screen.getByText("Credential attempts")).toBeTruthy()
  })

  it("links the CSV export to the endpoint the API serves", async () => {
    vi.stubGlobal("fetch", mockApi([makeSession()]))

    render(<App />)

    const link = await screen.findByRole("link", { name: /export csv/i })
    expect(link.getAttribute("href")).toBe("/api/export/attempts.csv")
  })

  it("shows an empty state instead of crashing with no data", async () => {
    vi.stubGlobal("fetch", mockApi([], makeStats({
      total_sessions: 0,
      total_attempts: 0,
      sessions_today: 0,
      attempts_today: 0,
      unique_ips: 0,
      unique_countries: 0,
      bruteforce_sessions: 0,
      top_countries: [],
      top_usernames: [],
      top_passwords: [],
      avg_flow_duration: 0,
      max_flow_rate: 0,
      avg_packet_size: 0,
      avg_attempts_per_session: 0,
      first_seen: null,
      last_seen: null,
    })))

    render(<App />)

    await waitFor(() => expect(screen.getByText(/No sessions captured yet/i)).toBeTruthy())
  })

  it("keeps showing the last good data when a poll fails", async () => {
    const healthy = mockApi([makeSession()])
    let failing = false

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (failing) return new Response("boom", { status: 500 })
      return healthy(input)
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<App />)
    await waitFor(() => expect(screen.getByText("203.0.113.10:55512")).toBeTruthy())

    // Break the API, then ask the dashboard to poll again.
    failing = true
    screen.getByRole("button", { name: /refresh/i }).click()

    await waitFor(() => expect(screen.getByText(/API unreachable/i)).toBeTruthy())
    // The previous reading is still on screen rather than blanked out.
    expect(screen.getByText("203.0.113.10:55512")).toBeTruthy()
  })
})