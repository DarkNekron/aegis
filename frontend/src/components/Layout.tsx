import { NavLink, Outlet } from "react-router-dom";
import {
  Activity, BarChart3, Database, FileText, GitCompare, LayoutDashboard, LogOut, MoonStar, Network, Route, Settings, Shield,
  Users, Wand2,
} from "lucide-react";
import { useSession } from "../services/session";
import { cx } from "./ui";
import { SelectionBar } from "./SelectionBar";
import { useNekron } from "./Nekron";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/imports", label: "Data Imports", icon: Database },
  { to: "/identities", label: "Identity Explorer", icon: Users },
  { to: "/paths", label: "Attack Paths", icon: Route },
  { to: "/risk", label: "Risk Intelligence", icon: BarChart3 },
  { to: "/simulator", label: "Remediation Simulator", icon: Wand2 },
  { to: "/compare", label: "Historical Comparison", icon: GitCompare },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/health", label: "System Health", icon: Activity },
];

export function Layout() {
  const { user, logout } = useSession();
  const nekron = useNekron();
  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-surface-1">
        <div className="flex items-center gap-2 px-5 py-5">
          <Shield className="h-6 w-6 text-accent" />
          <div>
            <div className="text-base font-bold tracking-[0.25em] text-text">AEGIS</div>
            <div className="text-[10px] uppercase tracking-wider text-muted">Attack path intelligence</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}
              className={({ isActive }) => cx("flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                isActive ? "bg-surface-3 text-text" : "text-muted hover:bg-surface-2 hover:text-text",
                nekron.highlight === to && "ring-2 ring-accent-2 ring-offset-1 ring-offset-surface-1")}>
              <Icon className="h-4 w-4" />{label}
            </NavLink>
          ))}
        </nav>
        <div className="px-3 pb-3">
          <button onClick={() => nekron.open()} title="Open the guide (press ?)"
            className="flex w-full items-center gap-2.5 rounded-md border border-accent/30 bg-accent/5 px-3 py-2 text-sm text-text hover:bg-accent/10">
            <MoonStar className="h-4 w-4 text-accent-2" />Nekron · Help
            <span className="ml-auto rounded border border-border px-1 font-mono text-[10px] text-muted">?</span>
          </button>
        </div>
        <div className="border-t border-border px-4 py-3 text-xs">
          <div className="flex items-center gap-2 text-muted"><Network className="h-3.5 w-3.5" />Offline · read-only analysis</div>
          <div className="mt-3 flex items-center justify-between">
            <div><div className="text-text">{user?.username}</div><div className="text-muted capitalize">{user?.role}</div></div>
            <button onClick={() => void logout()} title="Sign out" className="rounded p-1.5 text-muted hover:bg-surface-2 hover:text-text">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <SelectionBar />
        <main className="flex-1 overflow-y-auto px-6 py-6"><Outlet /></main>
      </div>
    </div>
  );
}
