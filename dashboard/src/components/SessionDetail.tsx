import { useEffect } from "react"

import {
  formatBytes,
  formatBytesPerSecond,
  formatDuration,
  labelText,
} from "../lib/format"
import type { Session } from "../types/api"

interface RowProps {
  label: string
  value: React.ReactNode
}

function Row({ label, value }: RowProps) {
  return (
    <div className="flex justify-between gap-4 border-b border-gray-800/70 py-1.5 text-xs last:border-0">
      <span className="text-gray-400">{label}</span>
      <span className="text-right font-mono text-gray-200">{value}</span>
    </div>
  )
}

export default function SessionDetail({
  session,
  onClose,
}: {
  session: Session
  onClose: () => void
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  const bruteForce = session.label === "ssh-bruteforce"

  return (
    <div
      className="fixed inset-0 z-20 flex items-start justify-center overflow-y-auto bg-black/70 p-4 sm:p-10"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Session detail"
    >
      <div
        className="w-full max-w-3xl rounded-lg border border-gray-700 bg-gray-900 p-6"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Session #{session.id}
            </h2>
            <p className="font-mono text-sm text-cyan-400">
              {session.src_ip}:{session.src_port} → {session.dst_port}
            </p>
          </div>
          <button
            onClick={onClose}
            className="rounded border border-gray-700 px-2 py-1 text-sm text-gray-400 hover:bg-gray-800"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <div className="mb-4 flex flex-wrap gap-2 text-xs">
          <span
            className={`rounded px-2 py-1 font-medium ${
              bruteForce ? "bg-red-900 text-red-300" : "bg-gray-800 text-gray-300"
            }`}
          >
            {labelText(session.label)}
          </span>
          {session.country ? (
            <span className="rounded bg-gray-800 px-2 py-1 text-gray-300">
              {session.city ?? "?"} · {session.country}
              {session.latitude !== null && ` (${session.latitude.toFixed(2)}, ${session.longitude?.toFixed(2)})`}
            </span>
          ) : null}
          <span className="rounded bg-gray-800 px-2 py-1 text-gray-400">
            {session.geo_source ?? "unknown source"}
          </span>
        </div>

        {session.detection_reason ? (
          <p className="mb-4 rounded border border-gray-800 bg-gray-800/40 px-3 py-2 text-xs text-gray-300">
            {session.detection_reason}
          </p>
        ) : null}

        <div className="grid gap-6 md:grid-cols-2">
          <div>
            <h3 className="mb-1 text-sm font-semibold text-gray-200">Handshake</h3>
            <Row label="Client version" value={session.client_version ?? "-"} />
            <Row label="KEX algorithm" value={session.kex_algorithm ?? "-"} />
            <Row label="Host key" value={session.host_key_type ?? "-"} />
            <Row label="Auth offered" value={session.auth_methods_offered ?? "-"} />
            <Row label="Auth tried" value={session.auth_methods_tried ?? "-"} />
          </div>

          <div>
            <h3 className="mb-1 text-sm font-semibold text-gray-200">Flow</h3>
            <Row label="Duration" value={formatDuration(session.duration_seconds)} />
            <Row
              label="Packets fwd / bwd"
              value={`${session.total_fwd_packets} / ${session.total_bwd_packets}`}
            />
            <Row
              label="Bytes fwd / bwd"
              value={`${formatBytes(session.total_length_fwd_packets)} / ${formatBytes(session.total_length_bwd_packets)}`}
            />
            <Row
              label="Flow rate"
              value={formatBytesPerSecond(session.flow_bytes_per_second)}
            />
            <Row
              label="Packets / s"
              value={session.flow_packets_per_second.toFixed(2)}
            />
            <Row
              label="Avg packet size"
              value={`${session.average_packet_size.toFixed(1)} B`}
            />
            <Row label="Down / up ratio" value={session.down_up_ratio.toFixed(3)} />
            <Row label="Flow IAT mean" value={`${session.flow_iat_mean.toFixed(4)} s`} />
            <Row label="Flow IAT max" value={`${session.flow_iat_max.toFixed(4)} s`} />
          </div>
        </div>

        <div className="mt-6">
          <h3 className="mb-2 text-sm font-semibold text-gray-200">
            Captured credentials ({session.attempt_count})
          </h3>
          {session.attempts && session.attempts.length > 0 ? (
            <div className="max-h-64 overflow-auto rounded border border-gray-800">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-gray-800 text-gray-400">
                  <tr>
                    <th className="p-2 text-left font-medium">Username</th>
                    <th className="p-2 text-left font-medium">Password</th>
                    <th className="p-2 text-left font-medium">Method</th>
                    <th className="p-2 text-right font-medium">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {session.attempts.map((attempt) => (
                    <tr key={attempt.id} className="border-t border-gray-800/70">
                      <td className="p-2 font-mono text-cyan-300">{attempt.username || "-"}</td>
                      <td className="p-2 font-mono text-red-300">{attempt.password || "-"}</td>
                      <td className="p-2 font-mono text-gray-400">{attempt.auth_method}</td>
                      <td className="p-2 text-right font-mono text-gray-500">
                        {attempt.success ? "accepted" : "refused"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="rounded border border-gray-800 px-3 py-2 text-xs text-gray-500">
              {session.attempt_count === 0
                ? "Banner exchange only — no authentication was attempted."
                : "Request the full attempt list from /api/sessions/{id}."}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}