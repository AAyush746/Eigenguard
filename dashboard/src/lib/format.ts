// Pure formatting and aggregation helpers.
//
// These are deliberately free of React so the unit conversions can be tested
// directly. The previous version of this dashboard assumed flow durations were
// in microseconds (the unit some CIC-IDS2017 dumps use) while the honeypot
// records seconds, which rendered every connection as `0.00s`.
import type { Attempt, Session, Stats } from "../types/api"

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0ms"
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`
  if (seconds < 60) return `${seconds.toFixed(2)}s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${Math.round(seconds % 60)}s`
}

export function formatBytesPerSecond(bytesPerSecond: number): string {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return "0 B/s"
  if (bytesPerSecond < 1024) return `${bytesPerSecond.toFixed(0)} B/s`
  if (bytesPerSecond < 1024 * 1024) {
    return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`
  }
  return `${(bytesPerSecond / (1024 * 1024)).toFixed(2)} MB/s`
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B"
  if (bytes < 1024) return `${bytes.toFixed(0)} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

/** Collapse long client identifiers so a table row stays readable. */
export function truncate(value: string | null | undefined, max = 28): string {
  if (!value) return "-"
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}

/** `root:123456, root:admin` — a compact credential summary for one row. */
export function summariseCredentials(
  attempts: Attempt[] | undefined,
  limit = 3,
): string {
  if (!attempts || attempts.length === 0) return "-"
  const pairs = attempts
    .filter((attempt) => attempt.username || attempt.password)
    .map((attempt) => `${attempt.username || "?"}:${attempt.password || "?"}`)
  if (pairs.length === 0) return "-"
  const shown = pairs.slice(0, limit).join(", ")
  return pairs.length > limit ? `${shown} +${pairs.length - limit}` : shown
}

/** Sessions carrying usable coordinates and a real country code. */
export function mappableSessions(sessions: Session[]): Session[] {
  return sessions.filter(
    (session) =>
      session.latitude !== null &&
      session.longitude !== null &&
      session.country_code !== null &&
      session.country_code !== "XX" &&
      session.country_code !== "LAN",
  )
}

/**
 * Count sessions per hour across a trailing window, oldest first.
 *
 * Buckets are generated up front so quiet hours appear as zero instead of
 * silently vanishing from the chart and shifting the x-axis.
 */
export function hourlyBuckets(
  sessions: Session[],
  windowHours = 24,
  now: Date = new Date(),
): { time: string; sessions: number }[] {
  const buckets = Array.from({ length: windowHours }, (_, index) => {
    const hour = new Date(now)
    hour.setHours(hour.getHours() - (windowHours - 1 - index), 0, 0, 0)
    return { start: hour, time: hour.toLocaleTimeString([], { hour: "2-digit" }), sessions: 0 }
  })

  for (const session of sessions) {
    const started = new Date(session.started_at)
    if (Number.isNaN(started.getTime())) continue

    for (const bucket of buckets) {
      const end = bucket.start.getTime() + 3_600_000
      if (started.getTime() >= bucket.start.getTime() && started.getTime() < end) {
        bucket.sessions += 1
        break
      }
    }
  }

  return buckets.map(({ time, sessions: count }) => ({ time, sessions: count }))
}

/** The username attackers tried most often, or an empty string. */
export function mostCommonUsername(stats: Stats | null): string {
  return stats?.top_usernames?.[0]?.name ?? ""
}

/** A label a human can read for each honeypot classification. */
export function labelText(label: string): string {
  switch (label) {
    case "ssh-bruteforce":
      return "Brute force"
    case "ssh-recon":
      return "Reconnaissance"
    default:
      return label || "unknown"
  }
}