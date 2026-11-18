import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import { LoginPage } from "./pages/LoginPage";
import { SessionProvider, useSession } from "./services/session";

// Pages are code-split so the login screen and light pages do not download Cytoscape or the chart library.
const page = <T extends Record<string, unknown>>(load: () => Promise<T>, name: keyof T) =>
  lazy(async () => ({ default: (await load())[name] as React.ComponentType }));
const OverviewPage = page(() => import("./pages/OverviewPage"), "OverviewPage");
const ImportsPage = page(() => import("./pages/ImportsPage"), "ImportsPage");
const IdentityPage = page(() => import("./pages/IdentityPage"), "IdentityPage");
const PathsPage = page(() => import("./pages/PathsPage"), "PathsPage");
const RiskPage = page(() => import("./pages/RiskPage"), "RiskPage");
const SimulatorPage = page(() => import("./pages/SimulatorPage"), "SimulatorPage");
const ComparePage = page(() => import("./pages/ComparePage"), "ComparePage");
const ReportsPage = page(() => import("./pages/ReportsPage"), "ReportsPage");
const SettingsPage = page(() => import("./pages/SettingsPage"), "SettingsPage");
const HealthPage = page(() => import("./pages/HealthPage"), "HealthPage");

function Routed() {
  const { user, loading } = useSession();
  if (loading) return <div className="p-8"><Spinner label="Starting AEGIS" /></div>;
  if (!user) return <LoginPage />;
  return (
    <Suspense fallback={<div className="p-8"><Spinner /></div>}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="imports" element={<ImportsPage />} />
          <Route path="identities" element={<IdentityPage />} />
          <Route path="paths" element={<PathsPage />} />
          <Route path="risk" element={<RiskPage />} />
          <Route path="simulator" element={<SimulatorPage />} />
          <Route path="compare" element={<ComparePage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="health" element={<HealthPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <SessionProvider><Routed /></SessionProvider>
    </BrowserRouter>
  );
}
