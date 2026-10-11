import { Navigate, Route, Routes } from "react-router-dom";

import { IncidentDetail } from "./pages/IncidentDetail";
import { Incidents } from "./pages/Incidents";
import { SignIn } from "./pages/SignIn";
import { useSession } from "./session";

export function App() {
  const { session, loading, signOut } = useSession();

  if (loading) {
    return <p className="loading">Loading…</p>;
  }
  if (session === null) {
    return <SignIn />;
  }
  return (
    <div className="shell">
      <header className="top">
        <h1>WetechiNetMon NOC</h1>
        <p className="who">
          <span>{session.actor_id}</span> · <span>{session.role}</span> ·{" "}
          <span>{session.tenant_id}</span>
        </p>
        <button type="button" onClick={() => void signOut()}>
          Sign out
        </button>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Navigate to="/incidents" replace />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
          <Route path="*" element={<Navigate to="/incidents" replace />} />
        </Routes>
      </main>
    </div>
  );
}
