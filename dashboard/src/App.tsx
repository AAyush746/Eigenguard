import { useState } from "react"

import AttackTable from "./components/AttackTable"
import AttackTimeline from "./components/AttackTimeline"
import CountryMap from "./components/CountryMap"
import SessionDetail from "./components/SessionDetail"
import StatsCards from "./components/StatsCards"
import TopCredentials from "./components/TopCredentials"
import { useHoneypotData } from "./hooks/useHoneypotData"
import { API_ORIGIN, CSV_EXPORT_URL } from "./lib/api"
import type { Session } from "./types/api"

const ROW_LIMIT = 100

export default function App() {
  const { sessions, stats, health, loading, error, refresh } = useHoneypotData(ROW_LIMIT)
  const [selected, setSelected] = useState<Session | null>(null)
  const [labelFilter, setLabelFilter] = useState<string>("all")

  const filtered =
    labelFilter === "all"
      ? sessions
      : sessions.filter((session) => session.label === labelFilter)

  const bruteForceCount = sessions.filter(
    (session) => session.label === "ssh-bruteforce",
  ).length
  const geoipReady = health?.geoip?.available ?? false

  return (
    <div className="mx-auto min-h-screen max-w-7xl space-y-6 px-4 py-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">EigenGuard Honeypot</h1>
          <p className="mt-1 text-sm text-gray-400">
            Real-time SSH credential capture with CIC-style flow analysis
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <span
            className={`flex items-center gap-1.5 rounded border px-2 py-1 ${
              error
                ? "border-red-800 bg-red-950/40 text-red-300"
                : "border-emerald-800 bg-emerald-950/40 text-emerald-300"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                error ? "bg-red-400" : "animate-pulse bg-emerald-400"
              }`}
            />
            {error ? "API unreachable" : `live · ${API_ORIGIN}`}
          </span>

          {!geoipReady && health !== null && (
            <span className="rounded border border-amber-800 bg-amber-950/40 px-2 py-1 text-amber-300">
              GeoIP offline
            </span>
          )}

          <button
            onClick={refresh}
            className="rounded border border-gray-700 px-3 py-1 text-gray-300 hover:bg-gray-800"
          >
            Refresh
          </button>

          <a
            href={CSV_EXPORT_URL}
            className="rounded border border-gray-700 px-3 py-1 text-gray-300 hover:bg-gray-800"
          >
            Export CSV
          </a>
        </div>
      </header>

      {error && (
        <div className="rounded border border-red-900 bg-red-950/30 px-4 py-2 text-xs text-red-300">
          {error} — showing the last successful reading.
        </div>
      )}

      <StatsCards stats={stats} />

      <div className="grid gap-6 lg:grid-cols-2">
        <AttackTimeline sessions={sessions} />
        <CountryMap sessions={sessions} />
      </div>

      <TopCredentials stats={stats} />

      <section>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">
            Recent sessions
            <span className="ml-2 text-sm font-normal text-gray-400">
              {bruteForceCount} brute force of {sessions.length} shown
            </span>
          </h2>

          <div className="flex gap-2 text-xs">
            {(
              [
                ["all", "All"],
                ["ssh-bruteforce", "Brute force"],
                ["ssh-recon", "Recon"],
              ] as const
            ).map(([value, text]) => (
              <button
                key={value}
                onClick={() => setLabelFilter(value)}
                className={`rounded border px-3 py-1 ${
                  labelFilter === value
                    ? "border-cyan-600 bg-cyan-950/50 text-cyan-300"
                    : "border-gray-700 text-gray-400 hover:bg-gray-800"
                }`}
              >
                {text}
              </button>
            ))}
          </div>
        </div>

        {loading && sessions.length === 0 ? (
          <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-10 text-center text-gray-500">
            Loading sessions…
          </div>
        ) : (
          <AttackTable sessions={filtered} onSelect={setSelected} />
        )}
      </section>

      <footer className="border-t border-gray-800 pt-4 text-xs text-gray-500">
        Captured sessions and credentials stay on this host. Authentication is
        always refused: the honeypot never grants a shell.
      </footer>

      {selected && (
        <SessionDetail session={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}