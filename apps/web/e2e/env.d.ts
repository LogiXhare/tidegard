// Playwright runs under Node; the page code never sees `process`. Declared
// here rather than adding @types/node for two reads of the environment.
declare const process: { env: Record<string, string | undefined> };
