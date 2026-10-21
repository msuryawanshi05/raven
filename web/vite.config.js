import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies API + WS to the FastAPI backend on :8080.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://localhost:8080", "/ws": { target: "ws://localhost:8080", ws: true } } },
  build: { outDir: "dist" },
});
