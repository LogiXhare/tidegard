// The T-08 lint rule is a control, so it is tested like one: code that
// hands raw HTML to the DOM must fail the lint.
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const FORBIDDEN = [
  "export const A = () => <div dangerouslySetInnerHTML={{ __html: window.name }} />;",
  "document.body.innerHTML = window.name;",
  "document.body.insertAdjacentHTML('beforeend', window.name);",
  "document.write(window.name);",
];

describe("the untrusted-HTML lint rule", () => {
  it("refuses every way of handing HTML to the DOM", async () => {
    const eslint = new ESLint();
    for (const code of FORBIDDEN) {
      const [result] = await eslint.lintText(code, { filePath: "src/probe.tsx" });
      const rules = (result?.messages ?? []).map((message) => message.ruleId);
      expect(rules, code).toContain("no-restricted-syntax");
    }
  });

  it("allows text", async () => {
    const eslint = new ESLint();
    const [result] = await eslint.lintText(
      "export const A = ({ title }: { title: string }) => <div>{title}</div>;\n",
      { filePath: "src/probe.tsx" },
    );
    expect(result?.messages.filter((message) => message.ruleId === "no-restricted-syntax")).toEqual(
      [],
    );
  });
});
