// Types mirroring the honeypot REST API in `honeypot/eigenguard/api.py`.
//
// These were previously hand-written guesses: the dashboard requested
// `/api/attacks` with fields such as `flow_duration` (microseconds),
// `syn_flag_count` and `command`, none of which the honeypot ever recorded or
// exposed. Every field below maps to a real column, so a type error here is a
// genuine contract mismatch rather than a naming coincidence.

/** One credential an attacker actually submitted. */
export interface Attempt {
  id: number
  session_id: number
  username: string
  password: string
  auth_method: string
  success: boolean
  attempted_at: string
}

/**
 * One SSH connection, with flow metrics in the CIC naming convention.
 *
 * Flow values are computed from bytes the honeypot actually read off the
 * socket, so they describe real traffic rather than an estimate. Note that
 * `duration_seconds` is **seconds**, not the microseconds some published
 * CIC-IDS2017 dumps use.
 */
export interface Session {
  id: number
  started_at: string
  ended_at: string | null
  duration_seconds: number

  src_ip: string
  src_port: number
  dst_port: number

  country: string | null
  country_code: string | null
  city: string | null
  region: string | null
  latitude: number | null
  longitude: number | null
  geo_source: string | null

  client_version: string | null
  kex_algorithm: string | null
  host_key_type: string | null
  auth_methods_offered: string | null
  auth_methods_tried: string | null

  total_fwd_packets: number
  total_bwd_packets: number
  total_length_fwd_packets: number
  total_length_bwd_packets: number

  flow_bytes_per_second: number
  flow_packets_per_second: number

  fwd_packet_length_max: number
  fwd_packet_length_mean: number
  fwd_packet_length_std: number
  fwd_packet_length_min: number

  bwd_packet_length_max: number
  bwd_packet_length_mean: number
  bwd_packet_length_std: number
  bwd_packet_length_min: number

  flow_iat_mean: number
  flow_iat_std: number
  flow_iat_max: number
  flow_iat_min: number

  fwd_iat_mean: number
  fwd_iat_std: number
  fwd_iat_max: number

  bwd_iat_mean: number
  bwd_iat_std: number
  bwd_iat_max: number

  down_up_ratio: number
  average_packet_size: number
  avg_fwd_segment_size: number
  avg_bwd_segment_size: number

  attempt_count: number
  /** `ssh-bruteforce` once a session crosses the attempt threshold. */
  label: string
  detection_reason: string | null

  /** Only present when the request passes `include_attempts=true`. */
  attempts?: Attempt[]
}

export interface Paginated<T> {
  total: number
  limit: number
  offset: number
  results: T[]
}

export interface Counted {
  name: string
  count: number
}

export interface Stats {
  total_sessions: number
  total_attempts: number
  sessions_today: number
  attempts_today: number
  unique_ips: number
  unique_countries: number
  bruteforce_sessions: number
  top_countries: Counted[]
  top_usernames: Counted[]
  top_passwords: Counted[]
  avg_flow_duration: number
  max_flow_rate: number
  avg_packet_size: number
  avg_attempts_per_session: number
  first_seen: string | null
  last_seen: string | null
}

/** Status reported by `GET /api/health`. */
export interface Health {
  status: string
  geoip: {
    enabled: boolean
    available: boolean
    database_path: string
    error: string | null
  }
}