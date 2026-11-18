import { useState } from "react";
import { Play, Plus, Scissors, X } from "lucide-react";
import { api, errorMessage, waitForJob } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { AdObject, Analysis, Job, Page, Simulation, SimulationResult } from "../services/types";
import { SEVERITY_COLOR } from "../components/charts";
import {
  Button, Card, Empty, ErrorBanner, formatDate, Input, JobProgress, PageHeader, SeverityBadge, Spinner, Table, Tag,
} from "../components/ui";

type Action = { type: string; label: string; payload: Record<string, unknown> };

export function SimulatorPage() {
  const { analysisId, snapshotId, can } = useSession();
  const analysis = useLoad(() => (analysisId ? api.get<Analysis>(`/api/analyses/${analysisId}`) : Promise.resolve(null)), [analysisId]);
  const history = useLoad(() => (analysisId ? api.get<Page<Simulation>>(`/api/analyses/${analysisId}/simulations`) : Promise.resolve(null)), [analysisId]);
  const [actions, setActions] = useState<Action[]>([]);
  const [job, setJob] = useState<Job | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [found, setFound] = useState<AdObject[]>([]);

  if (!analysisId) return <Empty>No completed analysis for this snapshot yet.</Empty>;
  const s = analysis.data?.summary;
  const add = (a: Action) => setActions((list) => (list.some((x) => x.label === a.label) ? list : [...list, a]));

  async function findIdentities() {
    if (!snapshotId || !search.trim()) return;
    try { setFound((await api.get<Page<AdObject>>(`/api/snapshots/${snapshotId}/objects`, { q: search.trim(), limit: 8 })).items); }
    catch (e) { setError(errorMessage(e)); }
  }

  async function run(list: Action[]) {
    setError(null);
    setResult(null);
    try {
      const { job } = await api.post<{ job: Job }>(`/api/analyses/${analysisId}/simulations`, { actions: list.map((a) => a.payload) });
      setJob(job);
      const done = await waitForJob(job.id, setJob);
      const id = done.result?.simulation_id;
      if (done.status === "succeeded" && typeof id === "number") {
        setResult((await api.get<Simulation>(`/api/simulations/${id}`)).result ?? null);
        history.reload();
      }
    } catch (e) { setError(errorMessage(e)); }
  }

  return (
    <>
      <PageHeader title="Remediation Simulator" subtitle="What-if analysis on an isolated in-memory view. Nothing in Active Directory or in the stored data is changed." />
      <div className="space-y-5">
        <ErrorBanner message={error} />
        <div className="grid gap-5 xl:grid-cols-2">
          <Card title="Build a scenario" actions={can("analyst") && <>
            <Button onClick={() => void run([{ type: "apply_min_cut", label: "min cut", payload: { type: "apply_min_cut" } }])}><Scissors className="h-3.5 w-3.5" />Simulate minimum cut</Button>
            <Button variant="primary" disabled={!actions.length} onClick={() => void run(actions)}><Play className="h-3.5 w-3.5" />Run scenario</Button>
          </>}>
            {!can("analyst") && <p className="mb-3 text-xs text-muted">Viewers can review saved simulations; running one requires the analyst role.</p>}
            {analysis.loading && !s ? <Spinner /> : s && (
              <div className="space-y-4">
                <div>
                  <div className="mb-1.5 text-xs uppercase tracking-wider text-muted">Remove a relationship (minimum cut & choke points)</div>
                  <div className="max-h-56 space-y-1 overflow-y-auto">
                    {[...s.min_cut.steps.map((c) => ({ ...c, cut: true })), ...s.choke_points.map((c) => ({ ...c, cut: false }))]
                      .filter((c, i, all) => all.findIndex((x) => x.src.id === c.src.id && x.dst.id === c.dst.id) === i)
                      .map((c, i) => {
                      const label = `${c.src.name} -[${c.kinds.join(", ")}]-> ${c.dst.name}`;
                      return (
                        <button key={i} onClick={() => add({ type: "remove_step", label: `remove ${label}`, payload: { type: "remove_step", src: c.src.id, dst: c.dst.id } })}
                          className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-surface-2">
                          <Plus className="h-3 w-3 text-muted" /><span className="text-text">{label}</span>{c.cut && <Tag tone="accent">min cut</Tag>}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div>
                  <div className="mb-1.5 text-xs uppercase tracking-wider text-muted">Disable an identity / remove its sessions</div>
                  <form onSubmit={(e) => { e.preventDefault(); void findIdentities(); }} className="flex gap-2">
                    <Input placeholder="Search name…" value={search} onChange={(e) => setSearch(e.target.value)} className="flex-1" />
                    <Button type="submit">Find</Button>
                  </form>
                  {found.map((o) => (
                    <div key={o.id} className="mt-1 flex items-center justify-between rounded px-2 py-1 text-xs hover:bg-surface-2">
                      <span className="text-text">{o.name} <span className="text-muted">{o.kind}</span></span>
                      <span className="flex gap-1">
                        <Button variant="ghost" onClick={() => add({ type: "disable_identity", label: `disable ${o.name}`, payload: { type: "disable_identity", object: o.id } })}>disable</Button>
                        {["User", "ServiceAccount"].includes(o.kind) && <Button variant="ghost" onClick={() => add({ type: "remove_session", label: `remove all sessions of ${o.name}`, payload: { type: "remove_session", user: o.id } })}>no sessions</Button>}
                      </span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="mb-1.5 text-xs uppercase tracking-wider text-muted">Scenario ({actions.length})</div>
                  {actions.length === 0 ? <p className="text-xs text-muted">Add changes above.</p> : actions.map((a) => (
                    <div key={a.label} className="flex items-center justify-between rounded bg-surface-2 px-2 py-1 text-xs">
                      <span className="font-mono text-text">{a.label}</span>
                      <button onClick={() => setActions((l) => l.filter((x) => x.label !== a.label))} className="text-muted hover:text-text"><X className="h-3.5 w-3.5" /></button>
                    </div>
                  ))}
                </div>
                <JobProgress job={job} />
              </div>
            )}
          </Card>
          {result ? <SimulationView result={result} /> : <Empty>Run a scenario to compare attack paths, exposure and risk before and after.</Empty>}
        </div>
        <Card title="Saved simulations">
          {!history.data?.items.length ? <Empty>No simulations yet.</Empty> : (
            <Table head={["#", "When", "Changes", "Paths", "Risk change", ""]}>
              {history.data.items.map((sim) => (
                <tr key={sim.id}>
                  <td className="px-2 py-1.5 text-muted">{sim.id}</td>
                  <td className="px-2 py-1.5 text-xs text-muted">{formatDate(sim.created_at)}</td>
                  <td className="px-2 py-1.5 font-mono text-xs">{sim.actions.map((a) => String(a.type)).join(", ")}</td>
                  <td className="px-2 py-1.5 tabular-nums">{sim.paths_before} → {sim.paths_after}</td>
                  <td className="px-2 py-1.5 tabular-nums">{sim.environment_risk_change}</td>
                  <td className="px-2 py-1.5"><Button variant="ghost" onClick={() => void api.get<Simulation>(`/api/simulations/${sim.id}`).then((r) => setResult(r.result ?? null))}>view</Button></td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}

function Delta({ label, before, after, digits = 0 }: { label: string; before: number; after: number; digits?: number }) {
  const better = after < before;
  return (
    <div className="rounded-lg border border-border bg-surface-0 px-3 py-2">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-1 text-lg tabular-nums text-text">{before.toFixed(digits)} <span className="text-muted">→</span> <span className={better ? "text-sev-low" : after > before ? "text-sev-critical" : ""}>{after.toFixed(digits)}</span></div>
    </div>
  );
}

function SimulationView({ result: r }: { result: SimulationResult }) {
  return (
    <Card title="Simulation result">
      <div className="grid grid-cols-3 gap-3">
        <Delta label="Attack paths" before={r.paths_before} after={r.paths_after} />
        <Delta label="Exposed identities" before={r.exposed_before} after={r.exposed_after} />
        <Delta label="Environment risk" before={r.environment_risk_before.score} after={r.environment_risk_after.score} digits={1} />
      </div>
      <div className="mt-3 flex gap-1">
        {(["Critical", "High", "Medium", "Low"] as const).map((sev) => (
          <div key={sev} className="flex-1 rounded border border-border px-2 py-1 text-xs">
            <span style={{ color: SEVERITY_COLOR[sev] }}>{sev}</span> <span className="tabular-nums text-text">{r.severity_before[sev]} → {r.severity_after[sev]}</span>
          </div>
        ))}
      </div>
      {r.baseline_is_current === false && <p className="mt-2 text-xs text-sev-medium">The data changed since the baseline analysis; both sides were recomputed on current data.</p>}
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div><div className="mb-1 text-xs uppercase tracking-wider text-sev-low">Identities secured ({r.identities_secured.length})</div>
          {r.identities_secured.slice(0, 15).map((o) => <div key={o.id} className="text-sm text-text">{o.name}</div>)}</div>
        <div><div className="mb-1 text-xs uppercase tracking-wider text-sev-high">Still exposed ({r.identities_still_exposed.length})</div>
          {r.identities_still_exposed.slice(0, 15).map((o) => <div key={o.id} className="text-sm text-text">{o.name}</div>)}</div>
      </div>
      {r.remaining.length > 0 && (
        <div className="mt-4"><div className="mb-1 text-xs uppercase tracking-wider text-muted">Remaining paths</div>
          {r.remaining.slice(0, 8).map((p, i) => <div key={i} className="flex items-start gap-2 py-0.5 text-xs"><SeverityBadge severity={p.severity} /><span className="text-text">{p.summary}</span></div>)}</div>
      )}
    </Card>
  );
}
