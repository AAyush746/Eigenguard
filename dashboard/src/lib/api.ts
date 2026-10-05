// Typed access to the honeypot API.
//
// The base URL defaults to the page's own origin. `vite.config.ts` proxies
// `/api` to the honeypot, so development and `vite preview` work without CORS
// and without a hard-coded port. Set `VITE_API_BASE` when the bundle is served
// from a different host than the API, or `window.__EIGENGUARD_API__` to change
// it after the bundle has loaded.
import type { Health, Paginated, Session, Stats } from "../types/api"

declare global {
  interface Window {
    __EIGENGUARD_API__?: string
  }
}

export const API_BASE: string = (
  window.__EIGENGUARD_API__ ?? import.meta.env.VITE_API_BASE ?? ""
).replace(/\/+$/, "")

/** Human-readable origin for the status badge. */
export const API_ORIGIN: string =
  API_BASE || (typeof window === "undefined" ? "same origin" : window.location.origin)

export const CSV_EXPORT_URL = `${API_BASE}/api/export/attempts.csv`

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    signal,
    headers: { Accept: "application/json" },
  })

  if (!response.ok) {
    throw new ApiError(
      response.status,
      `GET ${path} failed with ${response.status} ${response.statusText}`,
    )
  }

  return (await response.json()) as T
}

/**
 * Recent honeypot sessions, newest first.
 *
 * `include_attempts` embeds each session's credentials so the table can render
 * them from this one response instead of issuing a request per row.
 */
export function fetchSessions(
  options: { limit?: number; includeAttempts?: boolean; signal?: AbortSignal } = {},
): Promise<Paginated<Session>> {
  const { limit = 100, includeAttempts = true, signal } = options
  const query = new URLSearchParams({
    limit: String(limit),
    include_attempts: String(includeAttempts),
  })
  return getJson<Paginated<Session>>(`/api/sessions?${query}`, signal)
}

export function fetchStats(signal?: AbortSignal): Promise<Stats> {
  return getJson<Stats>("/api/stats", signal)
}

export function fetchHealth(signal?: AbortSignal): Promise<Health> {
  return getJson<Health>("/api/health", signal)
}