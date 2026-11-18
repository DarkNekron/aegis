// Global working context: which snapshot and which analysis every page shows.

import { useEffect } from "react";
import { api } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { Analysis, Page, Snapshot } from "../services/types";
import { Select, Tag } from "./ui";

export function SelectionBar() {
  const { snapshotId, analysisId, select, dataVersion } = useSession();
  const snapshots = useLoad(() => api.get<Page<Snapshot>>("/api/snapshots", { limit: 200 }), [dataVersion]);
  const analyses = useLoad(
    () => (snapshotId ? api.get<Page<Analysis>>(`/api/snapshots/${snapshotId}/analyses`, { limit: 50 })
                      : Promise.resolve({ total: 0, items: [] })), [snapshotId, dataVersion]);

  // Default to the newest snapshot, and to its newest successful analysis.
  useEffect(() => {
    const items = snapshots.data?.items ?? [];
    if (items.length && (snapshotId === null || !items.some((s) => s.id === snapshotId))) select(items[0]!.id, null);
  }, [snapshots.data, snapshotId, select]);
  useEffect(() => {
    const done = (analyses.data?.items ?? []).filter((a) => a.status === "succeeded");
    if (snapshotId && done.length && (analysisId === null || !done.some((a) => a.id === analysisId))) select(snapshotId, done[0]!.id);
  }, [analyses.data, snapshotId, analysisId, select]);

  const current = snapshots.data?.items.find((s) => s.id === snapshotId);
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border bg-surface-1/60 px-6 py-2.5 text-sm">
      <span className="text-xs uppercase tracking-wider text-muted">Snapshot</span>
      <Select value={snapshotId ?? ""} onChange={(e) => select(e.target.value ? Number(e.target.value) : null, null)} className="min-w-56">
        {!snapshots.data?.items.length && <option value="">No snapshots yet</option>}
        {snapshots.data?.items.map((s) => <option key={s.id} value={s.id}>#{s.id} {s.name}</option>)}
      </Select>
      <span className="text-xs uppercase tracking-wider text-muted">Analysis</span>
      <Select value={analysisId ?? ""} onChange={(e) => select(snapshotId, e.target.value ? Number(e.target.value) : null)} className="min-w-48">
        {!analyses.data?.items.some((a) => a.status === "succeeded") && <option value="">None yet</option>}
        {analyses.data?.items.filter((a) => a.status === "succeeded").map((a) => (
          <option key={a.id} value={a.id}>#{a.id} · {a.paths_total ?? 0} paths · {new Date(a.created_at).toLocaleDateString()}</option>
        ))}
      </Select>
      {current?.is_sample && <Tag tone="warn">sample data</Tag>}
      <button className="ml-auto text-xs text-muted hover:text-text" onClick={() => { snapshots.reload(); analyses.reload(); }}>Refresh</button>
    </div>
  );
}
