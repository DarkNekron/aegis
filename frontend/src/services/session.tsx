// Authentication state plus the analyst's working selection (snapshot + analysis), shared by every page.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setCsrfToken, setUnauthenticatedHandler } from "./api";
import type { Role, User } from "./types";

const RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

interface SessionState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (role: Role) => boolean;
  snapshotId: number | null;
  analysisId: number | null;
  select: (snapshotId: number | null, analysisId?: number | null) => void;
  /** Incremented when snapshots/analyses change so selectors re-fetch. */
  dataVersion: number;
  bump: () => void;
}

const SessionContext = createContext<SessionState | null>(null);
const SELECTION_KEY = "aegis.selection"; // ids only: never secrets or directory data

function readSelection(): { snapshotId: number | null; analysisId: number | null } {
  try {
    const parsed = JSON.parse(localStorage.getItem(SELECTION_KEY) ?? "{}");
    return { snapshotId: Number.isInteger(parsed.snapshotId) ? parsed.snapshotId : null,
             analysisId: Number.isInteger(parsed.analysisId) ? parsed.analysisId : null };
  } catch {
    return { snapshotId: null, analysisId: null };
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [selection, setSelection] = useState(readSelection);
  const [dataVersion, setDataVersion] = useState(0);
  const bump = useCallback(() => setDataVersion((v) => v + 1), []);

  useEffect(() => {
    setUnauthenticatedHandler(() => { setCsrfToken(null); setUser(null); });
    api.get<{ user: User }>("/api/auth/me")
      .then(async ({ user }) => {
        const { csrf_token } = await api.get<{ csrf_token: string }>("/api/auth/csrf");
        setCsrfToken(csrf_token);
        setUser(user);
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const result = await api.post<{ user: User; csrf_token: string }>("/api/auth/login", { username, password });
    setCsrfToken(result.csrf_token);
    setUser(result.user);
  }, []);

  const logout = useCallback(async () => {
    try { await api.post("/api/auth/logout"); } finally { setCsrfToken(null); setUser(null); }
  }, []);

  const select = useCallback((snapshotId: number | null, analysisId: number | null = null) => {
    const next = { snapshotId, analysisId };
    localStorage.setItem(SELECTION_KEY, JSON.stringify(next));
    setSelection(next);
  }, []);

  const value = useMemo<SessionState>(() => ({
    user, loading, login, logout,
    can: (role: Role) => (user ? RANK[user.role] >= RANK[role] : false),
    snapshotId: selection.snapshotId, analysisId: selection.analysisId, select, dataVersion, bump,
  }), [user, loading, login, logout, selection, select, dataVersion, bump]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside SessionProvider");
  return ctx;
}
