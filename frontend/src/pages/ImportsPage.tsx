import { useRef, useState, type FormEvent } from "react";
import { Play, Trash2, Upload } from "lucide-react";
import { api, errorMessage, waitForJob } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { Job, Snapshot, SnapshotDetail } from "../services/types";
import {
  Button, Card, Empty, ErrorBanner, formatBytes, formatDate, Input, JobProgress, PageHeader, SampleBanner, Spinner,
  Table, Tag,
} from "../components/ui";

export function ImportsPage() {
  const { snapshotId, select, can, bump } = useSession();
  const detail = useLoad(() => (snapshotId ? api.get<SnapshotDetail>(`/api/snapshots/${snapshotId}`) : Promise.resolve(null)), [snapshotId]);
  const [name, setName] = useState("");
  const [isSample, setIsSample] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const analyst = can("analyst");

  async function createSnapshot(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const snap = await api.post<Snapshot>("/api/snapshots", { name, is_sample: isSample });
      setName("");
      select(snap.id, null);
      bump();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function runJob(start: () => Promise<{ job: Job }>, after?: (job: Job) => void) {
    setError(null);
    setBusy(true);
    try {
      const { job } = await start();
      setJob(job);
      const finished = await waitForJob(job.id, setJob);
      after?.(finished);
      detail.reload();
      bump();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function upload(file: File) {
    if (!snapshotId) return;
    void runJob(() => api.upload<{ job: Job }>(`/api/snapshots/${snapshotId}/imports`, file, { filename: file.name }));
  }

  function analyse() {
    if (!snapshotId) return;
    void runJob(() => api.post<{ job: Job }>(`/api/snapshots/${snapshotId}/analyses`), (j) => {
      const id = j.result?.analysis_id;
      if (typeof id === "number") select(snapshotId, id);
    });
  }

  async function remove() {
    if (!detail.data || !confirm(`Delete snapshot "${detail.data.name}" and all of its data, analyses and reports?`)) return;
    try {
      await api.del(`/api/snapshots/${detail.data.id}`);
      select(null, null);
      bump();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const snap = detail.data;
  return (
    <>
      <PageHeader title="Data Imports" subtitle="Snapshots hold one point-in-time collection. Upload SharpHound / BloodHound CE ZIP or JSON, AEGIS JSON or CSV inventories." />
      <div className="space-y-5">
        <ErrorBanner message={error} />
        {analyst && (
          <Card title="New snapshot">
            <form onSubmit={createSnapshot} className="flex flex-wrap items-center gap-3">
              <Input placeholder="e.g. CORP.LOCAL – November 2026" value={name} onChange={(e) => setName(e.target.value)} className="min-w-80 flex-1" required maxLength={200} />
              <label className="flex items-center gap-2 text-sm text-muted">
                <input type="checkbox" checked={isSample} onChange={(e) => setIsSample(e.target.checked)} />Synthetic sample data
              </label>
              <Button type="submit" variant="primary">Create snapshot</Button>
            </form>
          </Card>
        )}
        {detail.loading && !snap ? <Spinner /> : !snap ? <Empty>Create a snapshot to start importing data.</Empty> : (
          <Card title={<>Snapshot #{snap.id} · {snap.name} <Tag tone={snap.status === "ready" ? "accent" : "muted"}>{snap.status}</Tag></>}
            actions={<>
              {analyst && <Button onClick={() => fileInput.current?.click()} disabled={busy}><Upload className="h-3.5 w-3.5" />Upload data</Button>}
              {analyst && <Button variant="primary" onClick={analyse} disabled={busy || snap.status !== "ready"}><Play className="h-3.5 w-3.5" />Run analysis</Button>}
              {can("admin") && <Button variant="danger" onClick={() => void remove()} disabled={busy}><Trash2 className="h-3.5 w-3.5" /></Button>}
            </>}>
            <input ref={fileInput} type="file" accept=".zip,.json,.csv" className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = ""; }} />
            <div className="space-y-4">
              <SampleBanner show={snap.is_sample} />
              <JobProgress job={job} />
              <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                <div><div className="text-xs text-muted">Objects</div>{snap.stats.objects_total?.toLocaleString() ?? 0}</div>
                <div><div className="text-xs text-muted">Relationships</div>{snap.stats.relationships_total?.toLocaleString() ?? 0}</div>
                <div><div className="text-xs text-muted">Collected</div>{formatDate(snap.collected_at)}</div>
                <div><div className="text-xs text-muted">Source</div>{snap.source_kind ?? "–"}</div>
              </div>
              {snap.imports.length === 0 ? <Empty>No files imported yet.</Empty> : (
                <Table head={["File", "Status", "Size", "Objects", "Relationships", "Gaps", "Issues", "Imported"]}>
                  {snap.imports.map((i) => (
                    <tr key={i.id} className="align-top">
                      <td className="px-2 py-2"><div className="text-text">{i.filename}</div><div className="font-mono text-[10px] text-muted">{i.sha256.slice(0, 16)}…</div></td>
                      <td className="px-2 py-2"><Tag tone={i.status === "succeeded" ? "accent" : i.status === "partial" ? "warn" : "muted"}>{i.status}</Tag></td>
                      <td className="px-2 py-2 text-muted">{formatBytes(i.size_bytes)}</td>
                      <td className="px-2 py-2 tabular-nums">{i.summary?.objects_inserted ?? "–"}</td>
                      <td className="px-2 py-2 tabular-nums">{i.summary?.relationships_inserted ?? "–"}</td>
                      <td className="px-2 py-2 tabular-nums" title="objects referenced but not collected">{i.summary?.placeholders_created ?? "–"}</td>
                      <td className="max-w-md px-2 py-2 text-xs">
                        {(i.errors ?? []).map((e, n) => <div key={n} className="text-sev-critical">{e}</div>)}
                        {(i.summary?.errors ?? []).slice(0, 3).map((e, n) => <div key={n} className="text-sev-medium">{e.file} {e.location}: {e.message}</div>)}
                        {(i.summary?.warnings ?? []).slice(0, 3).map((w, n) => <div key={n} className="text-muted">{w}</div>)}
                      </td>
                      <td className="px-2 py-2 text-xs text-muted">{formatDate(i.created_at)}</td>
                    </tr>
                  ))}
                </Table>
              )}
            </div>
          </Card>
        )}
      </div>
    </>
  );
}
