import {
  formatBytesPerSecond,
  formatDuration,
  labelText,
  summariseCredentials,
  truncate,
} from "../lib/format"
import type { Session } from "../types/api"

function clockOf(timestamp: string): string {
  const parsed = new Date(timestamp)
  if (Number.isNaN(parsed.getTime())) return "-"
  return parsed.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

export default function AttackTable({
  sessions,
  onSelect,
}: {
  sessions: Session[]
  onSelect?: (session: Session) => void
}) {
  if (sessions.length === 0) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-10 text-center text-gray-400">
        <p className="font-medium text-gray-300">No sessions captured yet</p>
        <p className="mt-1 text-sm">
          Point an SSH client at the honeypot, or run{" "}
          <code className="text-cyan-300">scripts/simulate_ssh_attacks.py</code>.
        </p>
      </div>
    )
  }

  return (
    <div className="max-h-[32rem] overflow-auto rounded-lg border border-gray-800">
      <table className="w-full text-xs">
        <thead className="sticky top-0 z-10 border-b border-gray-700 bg-gray-900">
          <tr className="text-left text-gray-400">
            <th className="p-3 font-medium">Time</th>
            <th className="p-3 font-medium">Source</th>
            <th className="p-3 font-medium">Location</th>
            <th className="p-3 font-medium">Credentials</th>
            <th className="p-3 text-right font-medium">Class</th>
            <th className="p-3 text-right font-medium">Duration</th>
            <th className="p-3 text-right font-medium">Pkts fwd/bwd</th>
            <th className="p-3 text-right font-medium">Flow rate</th>
            <th className="p-3 text-right font-medium">Bytes</th>
            <th className="p-3 font-medium">Client</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => {
            const bruteForce = session.label === "ssh-bruteforce"
            return (
              <tr
                key={session.id}
                onClick={() => onSelect?.(session)}
                className={`border-t border-gray-800 transition-colors hover:bg-gray-800/60 ${
                  onSelect ? "cursor-pointer" : ""
                }`}
              >
                <td className="p-3 font-mono text-gray-300">
                  {clockOf(session.started_at)}
                </td>
                <td className="p-3 font-mono text-cyan-400">
                  {session.src_ip}:{session.src_port}
                </td>
                <td className="p-3 text-gray-300">
                  {session.city && session.city !== "Unknown"
                    ? `${session.city}, ${session.country ?? "?"}`
                    : (session.country ?? "Unknown")}
                </td>
                <td className="max-w-[16rem] truncate p-3 font-mono text-red-300">
                  {summariseCredentials(session.attempts)}
                </td>
                <td className="p-3 text-right">
                  <span
                    className={`rounded px-2 py-0.5 font-medium ${
                      bruteForce
                        ? "bg-red-900 text-red-300"
                        : "bg-gray-800 text-gray-400"
                    }`}
                  >
                    {labelText(session.label)}
                  </span>
                </td>
                <td className="p-3 text-right font-mono text-yellow-300">
                  {formatDuration(session.duration_seconds)}
                </td>
                <td className="p-3 text-right font-mono text-gray-300">
                  {session.total_fwd_packets} / {session.total_bwd_packets}
                </td>
                <td className="p-3 text-right font-mono text-orange-300">
                  {formatBytesPerSecond(session.flow_bytes_per_second)}
                </td>
                <td className="p-3 text-right font-mono text-green-400">
                  {(
                    session.total_length_fwd_packets +
                    session.total_length_bwd_packets
                  ).toLocaleString()}
                </td>
                <td className="p-3 font-mono text-gray-500">
                  {truncate(session.client_version, 24)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}