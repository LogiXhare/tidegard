// Lint rules for the NOC UI (ADR 0044). The restricted syntax below is the
// T-08 control: untrusted text is only ever rendered as text, so no code
// may hand raw HTML to the DOM.
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export const UNTRUSTED_HTML = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: "Never render HTML: untrusted text is shown as text (T-08).",
  },
  {
    selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]",
    message: "Never assign HTML to the DOM (T-08).",
  },
  {
    selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
    message: "Never insert HTML into the DOM (T-08).",
  },
  {
    selector: "CallExpression[callee.object.name='document'][callee.property.name='write']",
    message: "Never write HTML into the document (T-08).",
  },
];

export default tseslint.config(
  { ignores: ["dist", "node_modules", "coverage"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-restricted-syntax": ["error", ...UNTRUSTED_HTML],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: globals.node },
  },
);
