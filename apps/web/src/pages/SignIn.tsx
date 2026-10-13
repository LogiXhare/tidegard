// Sign in with an API token, once. The token goes to the API in the body
// of one request and is then forgotten: the field is cleared, and nothing
// is written to storage (ADR 0043).
import { useState } from "react";
import type { FormEvent } from "react";

import { ApiError } from "../api";
import { useSession } from "../session";

export function SignIn() {
  const { signIn } = useSession();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(token.trim());
    } catch (failure) {
      setError(
        failure instanceof ApiError && failure.problem.status === 401
          ? "That token is not valid, or it has expired or been revoked."
          : failure instanceof ApiError && failure.problem.status === 429
            ? "Too many failed sign-ins from here. Wait a minute and try again."
            : "The API could not be reached.",
      );
    } finally {
      setToken("");
      setBusy(false);
    }
  }

  return (
    <main className="sign-in">
      <h1>Tidegard NOC</h1>
      <form onSubmit={(event) => void submit(event)}>
        <label htmlFor="token">API token</label>
        <input
          id="token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={token}
          onChange={(event) => setToken(event.target.value)}
          placeholder="wnm_…"
          required
        />
        <button type="submit" disabled={busy || token.trim() === ""}>
          Sign in
        </button>
        {error !== null && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
      </form>
      <p className="hint">
        The token is used once to start a session and is not stored by this page.
      </p>
    </main>
  );
}
