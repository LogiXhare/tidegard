// End-to-end tests against a real API, its PostgreSQL and the built UI
// (Phase 6D-4). CI starts the stack and sets E2E_BASE_URL and E2E_TOKEN;
// nothing here starts a server or reaches the internet.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env["E2E_BASE_URL"] ?? "http://127.0.0.1:8080",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
