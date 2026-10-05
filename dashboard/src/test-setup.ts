// `globals: false` means Testing Library's automatic cleanup never registers,
// so previous renders would otherwise leak into the next test and every
// query would match two elements.
import { cleanup } from "@testing-library/react"
import { afterEach } from "vitest"

afterEach(() => {
  cleanup()
})

// jsdom does not implement matchMedia, which the animated map markers and
// Recharts rely on. Stubbing it here keeps every test file free of setup code.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as typeof window.matchMedia
}

// Recharts measures its container, which jsdom reports as zero-sized. A fixed
// box keeps responsive charts from rendering nothing.
if (typeof HTMLElement !== "undefined") {
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
    configurable: true,
    value: 800,
  })
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
    configurable: true,
    value: 400,
  })
}