// The Phase 7E exit criterion: the UI drives a mitigation from request to
// withdrawal against a real API, its PostgreSQL, the mitigator and a real
// gobgpd (ADR 0050).
//
// CI starts gobgpd on loopback with its BGP port closed, so no route can
// leave the runner, and allowlists only 203.0.113.0/24 (TEST-NET-3) for
// acme. Two people act, as the four-eyes rule needs: a senior operator
// (E2E_OPERATOR_TOKEN) requests and a NOC lead (E2E_TOKEN) approves.
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const LEAD = process.env["E2E_TOKEN"] ?? "";
const OPERATOR = process.env["E2E_OPERATOR_TOKEN"] ?? "";
const PREFIX = "203.0.113.77/32";
/** The mitigator polls every half second in CI and the page every five. */
const MITIGATOR_TIMEOUT = 30_000;

async function signIn(page: Page, token: string) {
  await page.goto("/");
  await page.getByLabel("API token").fill(token);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Mitigations" }).click();
  await expect(page.getByRole("heading", { name: "Mitigations" })).toBeVisible();
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByLabel("API token")).toBeVisible();
}

test("a mitigation goes from request to withdrawal through GoBGP", async ({ page }) => {
  test.skip(LEAD === "" || OPERATOR === "", "E2E tokens are not set: run against a live stack");
  const row = page.locator("tr", { hasText: PREFIX });

  // --- A senior operator requests; nothing is announced yet ---
  await signIn(page, OPERATOR);
  await expect(page.getByRole("region", { name: "Kill switch" })).toContainText("released");
  const form = page.getByRole("form", { name: "Request a mitigation" });
  await form.getByLabel("Prefix").fill(PREFIX);
  await form.getByLabel("Action").selectOption("rtbh");
  await form.getByLabel("Minutes").fill("10");
  await form.getByLabel("Request reason").fill("e2e: UDP flood on a test host");
  await form.getByRole("button", { name: "Request" }).click();
  await expect(row).toContainText("requested");
  // A senior operator may request but not approve.
  await expect(row.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await signOut(page);

  // --- The lead approves; the mitigator announces it to gobgpd ---
  await signIn(page, LEAD);
  page.once("dialog", (dialog) => {
    expect(dialog.message()).toContain(`Approve rtbh of ${PREFIX}`);
    void dialog.accept();
  });
  await row.getByRole("button", { name: "Approve" }).click();
  await expect(row.locator(".state")).toHaveText("active", { timeout: MITIGATOR_TIMEOUT });
  await expect(row).not.toContainText("dry-run");
  await expect(page.getByRole("region", { name: "BGP peers" })).toBeVisible();

  // --- Withdrawn: the route comes down and it leaves the live view ---
  page.once("dialog", (dialog) => void dialog.accept());
  await row.getByLabel("Withdraw").fill("e2e: attack over");
  await row.getByRole("button", { name: "Withdraw" }).click();
  await expect(row).toHaveCount(0, { timeout: MITIGATOR_TIMEOUT });
  await page.getByRole("button", { name: "all", exact: true }).click();
  await expect(row.locator(".state")).toHaveText("withdrawn");
  await signOut(page);
});
