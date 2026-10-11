// Every package's licence must be on its allowlist (ADR 0044, R22). Reads
// package-lock.json, so it checks exactly what `npm ci` installs and needs
// no extra tool to trust.
//
// What ships in the bundle (runtime dependencies) must be permissive.
// Build tools that never ship may also be MPL-2.0, a file-level copyleft
// that places no obligation on code that only runs them: Vite's CSS
// minifier, lightningcss, is the case today.
import { readFileSync } from "node:fs";

const PERMISSIVE = [
  "MIT",
  "ISC",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "BlueOak-1.0.0",
  "CC0-1.0",
  "CC-BY-4.0",
  "Python-2.0",
  "MIT-0",
];
const RUNTIME = new Set(PERMISSIVE);
const BUILD_ONLY = new Set([...PERMISSIVE, "MPL-2.0"]);

/** `(MIT OR Apache-2.0)` passes if any alternative is allowed. */
function allowed(expression, set) {
  return expression
    .replace(/[()]/g, "")
    .split(/\s+OR\s+/)
    .some((alternative) => alternative.split(/\s+AND\s+/).every((part) => set.has(part.trim())));
}

const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const problems = [];
let runtime = 0;
let build = 0;
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  if (path === "") continue;
  const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
  const licence = entry.license ?? null;
  const set = entry.dev ? BUILD_ONLY : RUNTIME;
  if (entry.dev) build += 1;
  else runtime += 1;
  if (licence === null || !allowed(licence, set)) {
    problems.push(
      `${name}@${entry.version} (${entry.dev ? "build only" : "ships"}): ${licence ?? "no licence"}`,
    );
  }
}

if (runtime === 0) {
  console.error("package-lock.json lists no runtime packages");
  process.exit(1);
}
if (problems.length > 0) {
  console.error(`licences outside the allowlist:\n${problems.join("\n")}`);
  process.exit(1);
}
console.log(`${runtime} shipped and ${build} build-only packages, every licence allowed`);
