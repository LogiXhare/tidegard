#!/usr/bin/env node
// Writes the third-party licence notices of the NOC UI's production
// dependencies (FU-53): the packages its bundle is built from. Every
// package must carry a licence file; one that does not stops the
// release, to be looked at rather than shipped without its notice.
//
//   node scripts/web-licenses.mjs <apps/web, with node_modules installed>
//
// Prints to standard output. Node's standard library only.
import { execSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const app = resolve(process.argv[2] ?? "apps/web");
// A fixed command line, so it runs the same through every platform's shell.
const paths = execSync("npm ls --omit=dev --all --parseable", { cwd: app, encoding: "utf8" })
  .split(/\r?\n/)
  .filter((path) => path && resolve(path) !== app);

const licenceFile = /^(licen[cs]e|copying|notice)([-._].*)?$/i;
const packages = new Map();
for (const path of paths) {
  const manifest = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
  const key = `${manifest.name}@${manifest.version}`;
  if (packages.has(key)) continue;
  const files = readdirSync(path).filter((file) => licenceFile.test(file)).sort();
  if (files.length === 0) {
    console.error(`${key} carries no licence file`);
    process.exit(1);
  }
  packages.set(key, {
    manifest,
    texts: files.map((file) => readFileSync(join(path, file), "utf8").trimEnd()),
  });
}

const out = [
  "THIRD-PARTY SOFTWARE NOTICES",
  "Tidegard NOC UI (share/web)",
  "",
  "The NOC UI's bundle is built from the following third-party packages.",
  "Each package's licence is reproduced as its terms require.",
];
for (const [key, { manifest, texts }] of [...packages].sort(([a], [b]) => a.localeCompare(b))) {
  out.push("", "=".repeat(60), `${key} (${manifest.license ?? "see below"})`, "=".repeat(60), "");
  out.push(texts.join("\n\n"));
}
process.stdout.write(`${out.join("\n")}\n`);
