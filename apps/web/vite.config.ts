// The NOC UI build (ADR 0044). The API serves `dist/` from the same
// origin, so the page needs no CORS and the session cookie just works.
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    // No inline scripts or styles: the Content-Security-Policy forbids them.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    // `npm run dev` proxies the API, so development also runs same-origin.
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
  test: {
    environment: "jsdom",
    globals: true,
  },
});
