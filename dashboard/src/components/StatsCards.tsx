import { formatBytesPerSecond, formatDuration } from "../lib/format"
import type { Stats } from "../types/api"

interface CardProps {
  value: string
  caption: string
  accent: string
  sub?: string
}

function Card({ value, caption, accent, sub }: CardProps) {
  return (
    <div className={`rounded-lg border p-5 ${accent}`}>
      <div className="text-3xl font-bold tabular-nums">{value}</div>
      <div className="mt-1 text-sm text-gray-300">{caption}</div>
      {sub ? <div className="mt-0.5 text-xs text-gray-400">{sub}</div> : null}
    </div>
  )
}

export default function StatsCards({ stats }: { stats: Stats | null }) {
  if (!stats) {
    return (
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {Array.from({ length: 8 }, (_, index) => (
          <div
            key={index}
            className="h-[92px] animate-pulse rounded-lg border border-gray-800 bg-gray-800/40"
          />
        ))}
      </div>
    )
  }

  const topCountry = stats.top_countries[0]
  const topUsername = stats.top_usernames[0]

  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      <Card
        value={stats.total_sessions.toLocaleString()}
        caption="Sessions captured"
        accent="border-orange-800 bg-orange-900/40"
        sub={`${stats.bruteforce_sessions.toLocaleString()} brute force`}
      />
      <Card
        value={stats.total_attempts.toLocaleString()}
        caption="Credential attempts"
        accent="border-red-800 bg-red-900/40"
        sub={`${stats.attempts_today.toLocaleString()} today`}
      />
      <Card
        value={stats.unique_ips.toLocaleString()}
        caption="Unique source IPs"
        accent="border-cyan-800 bg-cyan-900/40"
        sub={`${stats.unique_countries.toLocaleString()} countries`}
      />
      <Card
        value={formatBytesPerSecond(stats.max_flow_rate)}
        caption="Peak flow rate"
        accent="border-purple-800 bg-purple-900/40"
        sub={`${stats.avg_packet_size.toFixed(0)} B avg packet`}
      />
      <Card
        value={formatDuration(stats.avg_flow_duration)}
        caption="Average session"
        accent="border-indigo-800 bg-indigo-900/40"
        sub={`${stats.avg_attempts_per_session.toFixed(1)} attempts/session`}
      />
      <Card
        value={`${stats.sessions_today.toLocaleString()}`}
        caption="Sessions today"
        accent="border-emerald-800 bg-emerald-900/40"
        sub={stats.last_seen ? `last seen ${stats.last_seen.slice(0, 19).replace("T", " ")}Z` : undefined}
      />
      <Card
        value={topCountry ? topCountry.count.toLocaleString() : "0"}
        caption="Top source country"
        accent="border-amber-800 bg-amber-900/40"
        sub={topCountry?.name ?? "no data yet"}
      />
      <Card
        value={topUsername?.name ?? "-"}
        caption="Most targeted user"
        accent="border-pink-800 bg-pink-900/40"
        sub={topUsername ? `${topUsername.count.toLocaleString()} attempts` : "no data yet"}
      />
    </div>
  )
}