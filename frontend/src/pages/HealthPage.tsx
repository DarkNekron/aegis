import { useEffect } from "react";
import { api } from "../services/api";
import { useLoad } from "../services/hooks";
import type { Health, Job } from "../services/types";
import { Card, ErrorBanner, formatBytes, formatDate, PageHeader, Spinner, Stat, Table, Tag } from "../components/ui";

function Meter({ label, used, total, unit = "MB" }: { label: string; used: number; total: number; unit?: string }) {
  const pct = total ? Math.round((used / total) * 100) : 0;
  return (
    <div>
      <div className="flex justify-between text-xs text-muted"><span>{label}</span><span className="tabular-nums">{used.toLocaleString()} / {total.toLocaleString()} {unit} · {pct}%</span></div>
      <div className="mt-1 h-2 overflow-hidden rounded bg-surface-3">
        <div className={`h-full ${pct > 85 ? "bg-sev-critical" : pct > 70 ? "bg-sev-medium" : "bg-accent"}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function HealthPage() {
  const health = useLoad(() => api.get<Health>("/api/system/health"), []);
  const jobs = useLoad(() => api.get<{ items: Job[] }>("/api/jobs"), []);
  useEffect(() => {  // lightweight polling while the page is open
    const timer = setInterval(() => { health.reload(); jobs.reload(); }, 10_000);
    return () => clearInterval(timer);
  }, [health.reload, jobs.reload]);

  const h = health.data;
  if (health.loading && !h) return <Spinner />;
  if (!h) return <ErrorBanner message={health.error} />;
  const r = h.resources;
  return (
    <>
      <PageHeader title="System Health" subtitle={`AEGIS ${h.version} · ${h.environment} · up ${Math.floor(h.uptime_seconds / 60)} min · refreshes every 10 s`} />
      <div className="space-y-5">
        {h.warnings.map((w, i) => <ErrorBanner key={i} message={w} />)}
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Status" value={h.status} tone={h.status === "ok" ? "accent" : "Medium"} />
          <Stat label="AEGIS memory" value={`${r.process_rss_mb} MB`} hint="resident set size" />
          <Stat label="CPU" value={`${r.cpu_percent}%`} hint={`${r.cpu_physical} cores / ${r.cpu_logical} threads`} />
          <Stat label="Database" value={h.database.ok ? "ok" : "down"} hint={`${h.database.engine} · ${formatBytes(h.database.size_bytes)}`} />
        </div>
        <div className="grid gap-5 xl:grid-cols-2">
          <Card title="Machine resources">
            <div className="space-y-4">
              <Meter label="Memory in use" used={r.total_ram_mb - r.available_ram_mb} total={r.total_ram_mb} />
              <Meter label="Disk in use (data directory)" used={r.disk_total_mb - r.disk_free_mb} total={r.disk_total_mb} />
              <div className="text-xs text-muted">Heavy analyses are refused when free memory drops below {h.limits.min_free_ram_mb} MB.</div>
            </div>
          </Card>
          <Card title="Jobs & graph cache">
            <div className="flex flex-wrap gap-2 text-xs">
              {Object.entries(h.jobs).map(([k, v]) => <Tag key={k}>{k.replace("_", " ")}: {v}</Tag>)}
            </div>
            <div className="mt-3 text-xs text-muted">Graph cache: {h.graph_cache.entries}/{h.graph_cache.capacity} graphs · {h.graph_cache.builds} builds · {h.graph_cache.hits} hits</div>
            <Table head={["Job", "Status", "Started", "Finished"]}>
              {(jobs.data?.items ?? []).slice(0, 8).map((j) => (
                <tr key={j.id}><td className="px-2 py-1 text-text">{j.name}</td><td className="px-2 py-1"><Tag tone={j.status === "succeeded" ? "accent" : j.status === "failed" ? "warn" : "muted"}>{j.status}</Tag></td>
                  <td className="px-2 py-1 text-xs text-muted">{formatDate(j.created_at)}</td><td className="px-2 py-1 text-xs text-muted">{formatDate(j.finished_at)}</td></tr>
              ))}
            </Table>
          </Card>
          <Card title="Configured limits" className="xl:col-span-2">
            <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-4">
              {Object.entries(h.limits).map(([k, v]) => <div key={k} className="flex justify-between gap-2 border-b border-border/50 py-1"><span className="text-muted">{k.replaceAll("_", " ")}</span><span className="tabular-nums text-text">{v.toLocaleString()}</span></div>)}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
