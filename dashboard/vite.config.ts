import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

const API_TARGET = process.env.VITE_API_PROXY ?? "http://localhost:8000"

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    open: true,
    // Proxying the API in dev means the dashboard talks to a relative origin, so
    // there is no hard-coded localhost:8000 and no CORS round trip.
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Recharts and d3 dominate the bundle; splitting them keeps the app
        // chunk small enough to stay under the default warning threshold.
        manualChunks: {
          react: ["react", "react-dom"],
          charts: ["recharts"],
          geo: ["d3-geo", "topojson-client"],
        },
      },
    },
  },
})