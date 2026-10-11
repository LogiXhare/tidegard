// A severity is never colour alone (FR-10.2): the word is always shown,
// with a distinct shape, and the colours come from a colour-blind-safe
// palette.
const SHAPES: Record<string, string> = {
  critical: "▲",
  major: "◆",
  minor: "●",
  info: "○",
};

export function Severity({ value }: { value: string }) {
  const known = Object.hasOwn(SHAPES, value);
  return (
    <span className={`severity severity-${known ? value : "unknown"}`}>
      <span aria-hidden="true">{known ? SHAPES[value] : "?"}</span> {value}
    </span>
  );
}
