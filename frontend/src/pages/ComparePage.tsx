import { useState } from "react";
import { api, errorMessage } from "../services/api";
import { useLoad } from "../services/hooks";
import type { Comparison, Page, Snapshot } from "../services/types";
import { Button, Card, Empty, ErrorBanner, PageHeader, Select, SeverityBadge, Spinner, Stat, Tag } from "../components/ui";

export function ComparePage() {
  const snapshots = useLoad(() => api.get<Page<Snapshot>>("/api/snapshots", { limit: 200 }), []);
  const [oldId, setOldId] = useState<number | "">("");
  const [newId, setNewId] = useState<number | "">("");
  const [report, setReport] = useState<Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function compare() {
    setBusy(true); setError(null); setReport(null);
    try { setReport(await api.get<Comparison>("/api/comparisons", { old_snapshot: oldId || undefined, new_snapshot: newId || undefined })); }
    catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  }

  const items = snapshots.data?.items ?? [];
  return (
    <>
      <PageHeader title="Historical Comparison" subtitle="Changes between two assessments, matched on stable identifiers (SIDs/GUIDs survive renames)." />
      <div className="space-y-5">
        <Card>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="text-muted">Earlier</span>
            <Select value={oldId} onChange={(e) => setOldId(e.target.value ? Number(e.target.value) : "")}>
              <option value="">Select…</option>{items.map((s) => <option key={s.id} value={s.id}>#{s.id} {s.name}</option>)}
            </Select>
            <span className="text-muted">Later</span>
            <Select value={newId} onChange={(e) => setNewId(e.target.value ? Number(e.target.value) : "")}>
              <option value="">Select…</option>{items.map((s) => <option key={s.id} value={s.id}>#{s.id} {s.name}</option>)}
            </Select>
            <Button variant="primary" busy={busy} disabled={!oldId || !newId} onClick={() => void compare()}>Compare</Button>
          </div>
        </Card>
        <ErrorBanner message={error} />
        {busy && <Spinner label="Comparing" />}
        {!report && !busy && <Empty>Choose two snapshots of the same environment. Attack-path changes need a completed analysis on both.</Empty>}
        {report && <ComparisonView r={report} />}
      </div>
    </>
  );
}

function List({ title, items, tone }: { title: string; items: string[]; tone?: string }) {
  return (
    <div>
      <div className={`mb-1 text-xs uppercase tracking-wider ${tone ?? "text-muted"}`}>{title} ({items.length})</div>
      {items.length === 0 ? <div className="text-xs text-muted">none</div> : items.slice(0, 20).map((n) => <div key={n} className="text-sm text-text">{n}</div>)}
    </div>
  );
}

function ComparisonView({ r }: { r: Comparison }) {
  const paths = r.attack_paths;
  return (
    <>
      <Card title="Summary">
        <ul className="list-disc space-y-1 pl-5 text-sm text-text">{r.summary.map((s, i) => <li key={i}>{s}</li>)}</ul>
      </Card>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Objects added / removed" value={`${r.objects.added.count} / ${r.objects.removed.count}`} hint={`${r.objects.changed.count} changed`} />
        <Stat label="Relationships added / removed" value={`${r.relationships.added.count} / ${r.relationships.removed.count}`} />
        <Stat label="Attack paths" value={paths.available ? `${paths.old_total} → ${paths.new_total}` : "n/a"} hint={paths.available ? `${paths.appeared?.count} new, ${paths.resolved?.count} resolved` : paths.reason} />
        <Stat label="Environment risk" value={r.risk.change === null ? "n/a" : `${r.risk.change > 0 ? "+" : ""}${r.risk.change}`}
          hint={r.risk.old && r.risk.new ? `${r.risk.old.score} → ${r.risk.new.score}` : undefined} tone={r.risk.change !== null && r.risk.change > 0 ? "Critical" : "accent"} />
      </div>
      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Accounts & groups">
          <div className="grid gap-3">
            <List title="New accounts" items={r.objects.users_added} tone="text-sev-medium" />
            <List title="Removed accounts" items={r.objects.users_removed} />
            <List title="New groups" items={r.objects.groups_added} />
            <List title="Newly tier-0" items={r.privilege.newly_tier0} tone="text-sev-critical" />
          </div>
        </Card>
        <Card title="Exposure">
          {paths.available ? (
            <div className="grid gap-3">
              <List title="Newly exposed identities" items={paths.newly_exposed ?? []} tone="text-sev-critical" />
              <List title="No longer exposed" items={paths.no_longer_exposed ?? []} tone="text-sev-low" />
            </div>
          ) : <p className="text-sm text-muted">{paths.reason}</p>}
        </Card>
        <Card title="New attack paths">
          {(paths.appeared?.items ?? []).slice(0, 10).map((p, i) => <div key={i} className="flex items-start gap-2 py-1 text-xs"><SeverityBadge severity={p.severity} /><span className="text-text">{p.summary}</span></div>)}
          {!paths.appeared?.items.length && <p className="text-sm text-muted">None.</p>}
        </Card>
      </div>
      <Card title="Relationship changes by category">
        <div className="grid gap-5 lg:grid-cols-2">
          {(["added", "removed"] as const).map((side) => (
            <div key={side}>
              <div className="mb-2 text-xs uppercase tracking-wider text-muted">{side}</div>
              {Object.entries(r.relationships[side].categories).map(([cat, c]) => (
                <div key={cat} className="mb-3">
                  <div className="text-sm text-text">{cat.replaceAll("_", " ")} <Tag>{c.count}</Tag></div>
                  {c.items.slice(0, 8).map((i, n) => (
                    <div key={n} className="ml-3 text-xs"><span className="text-text">{i.src.name}</span> <span className="font-mono text-accent-2">-[{i.kind}]→</span> <span className="text-text">{i.dst.name}</span></div>
                  ))}
                </div>
              ))}
              {Object.keys(r.relationships[side].categories).length === 0 && <p className="text-sm text-muted">None.</p>}
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
