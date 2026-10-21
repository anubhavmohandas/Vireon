import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The FastAPI backend runs on :8000. We proxy /api and /health through Vite's
// dev server so the frontend can call same-origin paths in development without
// fighting CORS. In production, set VITE_API_URL to the deployed API origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
