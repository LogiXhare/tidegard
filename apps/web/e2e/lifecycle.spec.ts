// The Phase 6D exit criterion: the UI drives an incident from open to
// closed, notes included, against a real API and PostgreSQL, and T-08 holds
// in a real browser under the real Content-Security-Policy.
//
// CI seeds one open incident whose title is hostile markup, creates a
// noc_lead token, and passes it in E2E_TOKEN. The token is typed into the
// sign-in form once, as an operator would.
import { expect, test } from "@playwright/test";

const TOKEN = process.env["E2E_TOKEN"] ?? "";
const HOSTILE_NOTE = '<img src=x onerror="window.__pwned=1">note';

test("an operator signs in, works an incident to closed, and signs out", async ({
  page,
  context,
}) => {
  test.skip(TOKEN === "", "E2E_TOKEN is not set: run against a live stack");

  // The page is served under the strict policy, with no framing.
  const first = await page.goto("/");
  const headers = first?.headers() ?? {};
  expect(headers["content-security-policy"]).toContain("script-src 'self'");
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["x-frame-options"]).toBe("DENY");

  // --- Sign in: the token becomes a session, and the page keeps no copy ---
  await page.getByLabel("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const [session] = (await context.cookies()).filter((cookie) => cookie.name === "wnm_session");
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain(TOKEN);
  expect(await page.evaluate(() => document.cookie)).not.toContain("wnm_session");

  // --- The seeded incident: its hostile title is text ---
  await page.getByRole("link", { name: "Incidents" }).click();
  await page.getByRole("link", { name: /^WNM-/ }).first().click();
  await expect(page.getByText("<img", { exact: false }).first()).toBeVisible();

  // --- A hostile note is stored and shown as text, and never runs ---
  await page.getByLabel("Add note").fill(HOSTILE_NOTE);
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText(HOSTILE_NOTE)).toBeVisible();
  expect(await page.locator("article img").count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>)["__pwned"])).toBeUndefined();

  // --- The lifecycle: each step sends the version the page saw ---
  const state = page.locator(".facts");
  await page.getByRole("button", { name: "Acknowledge" }).click();
  await expect(state).toContainText("acknowledged");
  await page.getByRole("button", { name: "Investigate" }).click();
  await expect(state).toContainText("investigating");
  await page.getByRole("button", { name: "Resolve" }).click();
  await expect(state).toContainText("resolved");

  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByLabel("Closure reason").selectOption("false_positive");
  await page.getByRole("button", { name: "Close" }).click();
  await expect(state).toContainText("closed");

  // The timeline recorded every step.
  const timeline = page.getByRole("region", { name: "Timeline" });
  await expect(timeline).toContainText("state_changed");
  await expect(timeline).toContainText("note_added");

  // --- Sign out: the session ends and the cookie goes ---
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByLabel("API token")).toBeVisible();
  expect((await context.cookies()).some((cookie) => cookie.name === "wnm_session" && cookie.value !== "")).toBe(false);
  const after = await page.request.get("/api/v1/session");
  expect(after.status()).toBe(401);
});

test("a request without the CSRF value is refused even with the cookie", async ({ page }) => {
  test.skip(TOKEN === "", "E2E_TOKEN is not set: run against a live stack");
  await page.goto("/");
  await page.getByLabel("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  // The browser sends the cookie; the forged request lacks the header.
  const forged = await page.request.delete("/api/v1/session");
  expect(forged.status()).toBe(403);
  expect((await forged.json()).error).toBe("api.csrf_rejected");
  await page.getByRole("button", { name: "Sign out" }).click();
});
