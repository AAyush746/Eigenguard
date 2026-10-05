import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"

import type { Counted, Stats } from "../types/api"

function RankedBarList({
  title,
  accent,
  items,
  emptyText,
}: {
  title: string
  accent: string
  items: Counted[]
  emptyText: string
}) {
  const data = items.slice(0, 8)

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
      <h3 className={`mb-3 text-base font-semibold ${accent}`}>{title}</h3>

      {data.length === 0 ? (
        <p className="py-6 text-center text-sm text-gray-500">{emptyText}</p>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(180, data.length * 34)}>
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 16, bottom: 0, left: 8 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
            <XAxis type="number" stroke="#9ca3af" fontSize={11} allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="name"
              stroke="#9ca3af"
              fontSize={11}
              width={110}
            />
            <Tooltip
              cursor={{ fill: "#1f2937" }}
              contentStyle={{
                backgroundColor: "#111827",
                border: "1px solid #374151",
                borderRadius: "0.5rem",
                fontSize: "0.75rem",
              }}
              formatter={(value) => [Number(value ?? 0).toLocaleString(), "attempts"]}
            />
            <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </section>
  )
}

export default function TopCredentials({ stats }: { stats: Stats | null }) {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <RankedBarList
        title="Most targeted usernames"
        accent="text-red-400"
        items={stats?.top_usernames ?? []}
        emptyText="No credentials captured yet."
      />
      <RankedBarList
        title="Most used passwords"
        accent="text-orange-400"
        items={stats?.top_passwords ?? []}
        emptyText="No credentials captured yet."
      />
    </div>
  )
}