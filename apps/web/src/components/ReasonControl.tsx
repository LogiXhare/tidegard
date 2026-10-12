import { useState } from "react";

/** One line of text and a button: a reason, a note, a new body. */
export function ReasonControl({
  label,
  busy,
  initial = "",
  onSubmit,
}: {
  label: string;
  busy: boolean;
  initial?: string;
  onSubmit: (text: string) => void;
}) {
  const [text, setText] = useState(initial);
  return (
    <form
      className="inline"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(text.trim());
        setText("");
      }}
    >
      <input
        aria-label={label}
        value={text}
        maxLength={16000}
        onChange={(event) => setText(event.target.value)}
      />
      <button type="submit" disabled={busy || text.trim() === ""}>
        {label}
      </button>
    </form>
  );
}
