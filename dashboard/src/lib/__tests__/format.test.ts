import { describe, expect, it } from "vitest"

import {
  formatBytes,
  formatBytesPerSecond,
  formatDuration,
  hourlyBuckets,
  labelText,
  mappableSessions,
  summariseCredentials,
  truncate,
} from "../format"
import type { Attempt, Session } from "../../types/api"

function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    id: 1,
    started_at: "2026-01-01T00:00:00",
    duration_seconds: 1,
    country_code: "NL",
    latitude: 52.37,
    longitude: 4.89,
    ...overrides,
  } as Session
}

describe("formatDuration", () => {
  it("renders sub-second sessions in milliseconds", () => {
    expect(formatDuration(0.25)).toBe("250ms")
  })

  it("keeps seconds in seconds", () => {
    // The honeypot stores seconds. Treating them as microseconds, which some
    // CIC dumps use, made every connection render as "0.00s".
    expect(formatDuration(4.2)).toBe("4.20s")
    expect(formatDuration(1)).toBe("1.00s")
  })

  it("rolls over to minutes past 60s", () => {
    expect(formatDuration(75)).toBe("1m 15s")
  })

  it("does not emit NaN for missing or zero values", () => {
    expect(formatDuration(0)).toBe("0ms")
    expect(formatDuration(Number.NaN)).toBe("0ms")
  })
})

describe("formatBytesPerSecond", () => {
  it("scales through the unit boundaries", () => {
    expect(formatBytesPerSecond(512)).toBe("512 B/s")
    expect(formatBytesPerSecond(2048)).toBe("2.0 KB/s")
    expect(formatBytesPerSecond(5 * 1024 * 1024)).toBe("5.00 MB/s")
  })

  it("does not emit NaN for zero", () => {
    expect(formatBytesPerSecond(0)).toBe("0 B/s")
  })
})

describe("formatBytes", () => {
  it("formats byte counts", () => {
    expect(formatBytes(900)).toBe("900 B")
    expect(formatBytes(2048)).toBe("2.0 KB")
    expect(formatBytes(3 * 1024 * 1024)).toBe("3.00 MB")
  })
})

describe("truncate", () => {
  it("leaves short values alone", () => {
    expect(truncate("root")).toBe("root")
  })

  it("elides long values", () => {
    const long = "SSH-2.0-OpenSSH_9.6p1-Ubuntu-3ubuntu13"
    expect(truncate(long, 10)).toBe("SSH-2.0-O…")
    expect(truncate(long, 10)).toHaveLength(10)
  })

  it("renders missing values as a dash", () => {
    expect(truncate(null)).toBe("-")
    expect(truncate(undefined)).toBe("-")
  })
})

describe("summariseCredentials", () => {
  const attempt = (over: Partial<Attempt>): Attempt =>
    ({ id: 1, session_id: 1, username: "root", password: "admin", auth_method: "password", success: false, attempted_at: "", ...over }) as Attempt

  it("pairs username with password", () => {
    expect(summariseCredentials([attempt({ username: "root", password: "123456" })])).toBe(
      "root:123456",
    )
  })

  it("lists several attempts and counts the remainder", () => {
    const many = [1, 2, 3, 4, 5].map((i) =>
      attempt({ id: i, username: "root", password: `pw${i}` }),
    )
    const summary = summariseCredentials(many, 2)
    expect(summary).toBe("root:pw1, root:pw2 +3")
  })

  it("handles sessions with no attempts", () => {
    expect(summariseCredentials(undefined)).toBe("-")
    expect(summariseCredentials([])).toBe("-")
  })

  it("keeps recon sessions that only offered a public key", () => {
    const keyAttempt = attempt({ username: "", password: "ssh-rsa-abc123", auth_method: "publickey" })
    expect(summariseCredentials([keyAttempt])).toBe("?:ssh-rsa-abc123")
  })
})

describe("mappableSessions", () => {
  it("keeps sessions with coordinates and a real country code", () => {
    const rows = [makeSession(), makeSession({ id: 2 })]
    expect(mappableSessions(rows)).toHaveLength(2)
  })

  it("drops sessions without coordinates", () => {
    expect(mappableSessions([makeSession({ latitude: null })])).toHaveLength(0)
    expect(mappableSessions([makeSession({ longitude: null })])).toHaveLength(0)
  })

  it("drops unknown and private-network sessions", () => {
    // 127.0.0.1 is recorded as "LAN"/"XX"; plotting it on a world map would
    // put a marker in the Atlantic.
    expect(mappableSessions([makeSession({ country_code: "XX" })])).toHaveLength(0)
    expect(mappableSessions([makeSession({ country_code: "LAN" })])).toHaveLength(0)
    expect(mappableSessions([makeSession({ country_code: null })])).toHaveLength(0)
  })
})

describe("hourlyBuckets", () => {
  const now = new Date("2026-03-01T12:30:00Z")

  it("always returns one bucket per hour of the window", () => {
    expect(hourlyBuckets([], 24, now)).toHaveLength(24)
    expect(hourlyBuckets([], 6, now)).toHaveLength(6)
  })

  it("places a session inside the bucket that contains it", () => {
    // Buckets are aligned to local hours, so the test derives the expected
    // bucket the same way instead of assuming UTC.
    const startOfCurrentHour = new Date(now)
    startOfCurrentHour.setHours(startOfCurrentHour.getHours(), 0, 0, 0)
    const inside = new Date(startOfCurrentHour.getTime() + 60_000)

    const buckets = hourlyBuckets(
      [makeSession({ started_at: inside.toISOString() })],
      24,
      now,
    )
    expect(buckets[buckets.length - 1].sessions).toBe(1)
    expect(buckets.reduce((sum, bucket) => sum + bucket.sessions, 0)).toBe(1)
  })

  it("counts each session exactly once", () => {
    const when = new Date(now.getTime() - 30 * 60 * 1000)
    const sessions = [1, 2, 3].map((id) =>
      makeSession({ id, started_at: when.toISOString() }),
    )
    const buckets = hourlyBuckets(sessions, 24, now)
    expect(buckets.reduce((sum, bucket) => sum + bucket.sessions, 0)).toBe(3)
  })

  it("ignores sessions outside the window and unparseable timestamps", () => {
    const old = new Date(now.getTime() - 48 * 3600 * 1000).toISOString()
    const buckets = hourlyBuckets(
      [makeSession({ started_at: old }), makeSession({ id: 2, started_at: "not-a-date" })],
      24,
      now,
    )
    expect(buckets.reduce((sum, bucket) => sum + bucket.sessions, 0)).toBe(0)
  })
})

describe("labelText", () => {
  it("maps honeypot labels to readable text", () => {
    expect(labelText("ssh-bruteforce")).toBe("Brute force")
    expect(labelText("ssh-recon")).toBe("Reconnaissance")
  })

  it("passes unknown labels through", () => {
    expect(labelText("ssh-newthing")).toBe("ssh-newthing")
    expect(labelText("")).toBe("unknown")
  })
})