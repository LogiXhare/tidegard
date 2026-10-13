import { Navigate, NavLink, Route, Routes } from "react-router-dom";

import { IncidentDetail } from "./pages/IncidentDetail";
import { Incidents } from "./pages/Incidents";
import { Mitigations } from "./pages/Mitigations";
import { Overview } from "./pages/Overview";
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
        <h1>Tidegard NOC</h1>
        <nav aria-label="Main">
          <NavLink to="/" end>
            Overview
          </NavLink>{" "}
          <NavLink to="/incidents">Incidents</NavLink>{" "}
          <NavLink to="/mitigations">Mitigations</NavLink>
        </nav>
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
          <Route path="/" element={<Overview />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
          <Route path="/mitigations" element={<Mitigations />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
