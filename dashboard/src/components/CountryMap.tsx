import { geoEqualEarth, geoPath } from "d3-geo"
import { useEffect, useMemo, useState } from "react"
import { feature } from "topojson-client"
import type { GeometryCollection, Topology } from "topojson-specification"

import { mappableSessions } from "../lib/format"
import type { Session } from "../types/api"

const ATLAS_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

const WIDTH = 800
const HEIGHT = 400

type Status = "idle" | "loading" | "ready" | "error"

/** Equirectangular-ish projection fitted to the fixed viewBox dimensions. */
const projection = geoEqualEarth().fitExtent(
  [
    [4, 4],
    [WIDTH - 4, HEIGHT - 4],
  ],
  { type: "Sphere" },
)

const pathGenerator = geoPath(projection)

interface AtlasShape {
  id: string
  d: string | null
}

export default function CountryMap({ sessions }: { sessions: Session[] }) {
  const [status, setStatus] = useState<Status>("idle")
  const [shapes, setShapes] = useState<AtlasShape[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setStatus("loading")

    fetch(ATLAS_URL, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`world atlas responded ${response.status}`)
        }
        return response.json()
      })
      .then((topology: Topology) => {
        const countries = topology.objects.countries as GeometryCollection<{ name?: string }>
        const land = feature(topology, countries)
        setShapes(
          land.features.map((country, index) => ({
            id: String(country.id ?? country.properties?.name ?? index),
            d: pathGenerator(country),
          })),
        )
        setStatus("ready")
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setError(caught instanceof Error ? caught.message : "failed to load map")
        setStatus("error")
      })

    return () => controller.abort()
  }, [])

  const markers = useMemo(() => mappableSessions(sessions), [sessions])

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-base font-semibold text-white">Attacker geolocation</h3>
        <span className="text-xs text-gray-400">
          {markers.length} located
          {markers.length < sessions.length && sessions.length > 0
            ? ` · ${sessions.length - markers.length} unlocated`
            : ""}
        </span>
      </div>

      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="w-full"
        role="img"
        aria-label="World map of honeypot attack sources"
      >
        {status === "loading" && (
          <text x={WIDTH / 2} y={HEIGHT / 2} textAnchor="middle" fill="#6b7280" fontSize={14}>
            Loading map…
          </text>
        )}

        {status === "error" && (
          <>
            <text x={WIDTH / 2} y={HEIGHT / 2 - 8} textAnchor="middle" fill="#f87171" fontSize={14}>
              Map unavailable
            </text>
            <text x={WIDTH / 2} y={HEIGHT / 2 + 14} textAnchor="middle" fill="#6b7280" fontSize={12}>
              {error}
            </text>
          </>
        )}

        {shapes.map((shape) =>
          shape.d ? (
            <path key={shape.id} d={shape.d} fill="#1f2937" stroke="#374151" strokeWidth={0.4} />
          ) : null,
        )}

        {markers.map((session) => {
          const point = projection([session.longitude as number, session.latitude as number])
          if (!point) return null
          const [x, y] = point
          const bruteForce = session.label === "ssh-bruteforce"

          return (
            <g key={session.id} transform={`translate(${x}, ${y})`}>
              <title>
                {`${session.src_ip} — ${session.city ?? session.country ?? "unknown"} (${session.attempt_count} attempts)`}
              </title>
              <circle
                r={bruteForce ? 5 : 3.5}
                fill={bruteForce ? "#ef4444" : "#f59e0b"}
                fillOpacity={0.85}
                stroke="#7f1d1d"
                strokeWidth={1}
              />
              <circle r={bruteForce ? 5 : 3.5} fill="none" stroke={bruteForce ? "#ef4444" : "#f59e0b"} strokeWidth={1}>
                <animate attributeName="r" values="3;11;3" dur="2.4s" repeatCount="indefinite" />
                <animate
                  attributeName="stroke-opacity"
                  values="0.9;0;0.9"
                  dur="2.4s"
                  repeatCount="indefinite"
                />
              </circle>
            </g>
          )
        })}
      </svg>

      {status === "ready" && markers.length === 0 && (
        <p className="mt-2 text-center text-xs text-gray-500">
          No geolocated sources yet. Private and unresolvable addresses are
          excluded.
        </p>
      )}
    </section>
  )
}