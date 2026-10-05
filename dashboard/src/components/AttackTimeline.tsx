import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

import { hourlyBuckets } from "../lib/format"
import type { Session } from "../types/api"

export default function AttackTimeline({
  sessions,
  windowHours = 24,
}: {
  sessions: Session[]
  windowHours?: number
}) {
  const data = hourlyBuckets(sessions, windowHours)
  const total = data.reduce((sum, bucket) => sum + bucket.sessions, 0)

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
      <div className="mb-4 flex items-baseline justify-between">
        <h3 className="text-base font-semibold text-white">
          Sessions · last {windowHours}h
        </h3>
        <span className="text-xs text-gray-400">
          {total} in window
        </span>
      </div>

      <ResponsiveContainer width="100%" height={260}>
        <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis
            dataKey="time"
            stroke="#9ca3af"
            fontSize={11}
            interval="preserveStartEnd"
            minTickGap={24}
          />
          <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} width={44} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#111827",
              border: "1px solid #374151",
              borderRadius: "0.5rem",
              fontSize: "0.75rem",
            }}
            labelStyle={{ color: "#e5e7eb" }}
            formatter={(value) => [Number(value ?? 0), "sessions"]}
          />
          <Line
            type="monotone"
            dataKey="sessions"
            stroke="#ef4444"
            strokeWidth={2}
            dot={{ fill: "#ef4444", r: 2 }}
            activeDot={{ r: 5 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </section>
  )
}