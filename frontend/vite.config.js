import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The SPA is served by the FastAPI process in production; during development
// Vite proxies /api to the local uvicorn server so both stay same-origin.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
