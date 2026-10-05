// Polls the honeypot API and keeps the last good payload on screen.
//
// A failed poll never blanks the dashboard: a honeypot API restart would
// otherwise make every panel flash empty, which reads as data loss during a
// demo. Errors are surfaced separately so the header can show them.
import { useCallback, useEffect, useRef, useState } from "react"

import { fetchHealth, fetchSessions, fetchStats } from "../lib/api"
import type { Health, Session, Stats } from "../types/api"

const POLL_INTERVAL_MS = 3_000

export interface HoneypotState {
  sessions: Session[]
  stats: Stats | null
  health: Health | null
  loading: boolean
  /** Set when the most recent poll failed; previous data is still shown. */
  error: string | null
  refresh: () => void
}

export function useHoneypotData(
  limit = 100,
  intervalMs = POLL_INTERVAL_MS,
): HoneypotState {
  const [sessions, setSessions] = useState<Session[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)

  // Kept in a ref so an in-flight poll is not restarted on every render.
  const inFlight = useRef<AbortController | null>(null)

  const refresh = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    const controller = new AbortController()
    inFlight.current?.abort()
    inFlight.current = controller
    let cancelled = false

    const poll = async () => {
      try {
        const [sessionPage, nextStats, nextHealth] = await Promise.all([
          fetchSessions({ limit, signal: controller.signal }),
          fetchStats(controller.signal),
          fetchHealth(controller.signal),
        ])
        if (cancelled) return

        setSessions(sessionPage.results)
        setStats(nextStats)
        setHealth(nextHealth)
        setError(null)
      } catch (caught) {
        if (cancelled || controller.signal.aborted) return
        const message =
          caught instanceof Error ? caught.message : "unknown error"
        setError(message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void poll()
    const timer = setInterval(() => void poll(), intervalMs)

    return () => {
      cancelled = true
      controller.abort()
      clearInterval(timer)
    }
  }, [limit, intervalMs, nonce])

  return { sessions, stats, health, loading, error, refresh }
}