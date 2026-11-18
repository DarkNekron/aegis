import { useState } from "react";
import { Download, FileText } from "lucide-react";
import { api, errorMessage, waitForJob } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { Job, Page, ReportItem, Snapshot } from "../services/types";
import { Button, Card, Empty, ErrorBanner, formatDate, JobProgress, PageHeader, Select, Table, Tag } from "../components/ui";

const FORMATS = ["pdf", "html", "json"] as const;

export function ReportsPage() {
  const { snapshotId, analysisId, can } = useSession();
  const reports = useLoad(() => (snapshotId ? api.get<Page<ReportItem>>("/api/reports", { snapshot_id: snapshotId }) : Promise.resolve(null)), [snapshotId]);
  const snapshots = useLoad(() => api.get<Page<Snapshot>>("/api/snapshots", { limit: 200 }), []);
  const [formats, setFormats] = useState<string[]>([...FORMATS]);
  const [previous, setPrevious] = useState<number | "">("");
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function generate() {
    setError(null);
    try {
      const { job } = await api.post<{ job: Job }>(`/api/analyses/${analysisId}/reports`,
        { formats, previous_snapshot_id: previous || null });
      setJob(job);
      await waitForJob(job.id, setJob);
      reports.reload();
    } catch (e) { setError(errorMessage(e)); }
  }

  return (
    <>
      <PageHeader title="Reports" subtitle="Penetration-test reports with executive summary, findings, evidence, risk, remediation and simulation results." />
      <div className="space-y-5">
        <ErrorBanner message={error} />
        {can("analyst") && (
          <Card title="Generate report">
            {!analysisId ? <p className="text-sm text-muted">Run an analysis on this snapshot first.</p> : (
              <div className="flex flex-wrap items-center gap-4 text-sm">
                {FORMATS.map((f) => (
                  <label key={f} className="flex items-center gap-1.5 uppercase text-muted">
                    <input type="checkbox" checked={formats.includes(f)}
                      onChange={(e) => setFormats((list) => (e.target.checked ? [...list, f] : list.filter((x) => x !== f)))} />{f}
                  </label>
                ))}
                <span className="text-muted">Compare with</span>
                <Select value={previous} onChange={(e) => setPrevious(e.target.value ? Number(e.target.value) : "")}>
                  <option value="">no previous assessment</option>
                  {snapshots.data?.items.filter((s) => s.id !== snapshotId).map((s) => <option key={s.id} value={s.id}>#{s.id} {s.name}</option>)}
                </Select>
                <Button variant="primary" disabled={!formats.length} onClick={() => void generate()}><FileText className="h-3.5 w-3.5" />Generate</Button>
              </div>
            )}
            <div className="mt-3"><JobProgress job={job} /></div>
          </Card>
        )}
        <Card title="Generated reports">
          {!reports.data?.items.length ? <Empty>No reports for this snapshot yet.</Empty> : (
            <Table head={["#", "Format", "Analysis", "Created", "SHA-256", ""]}>
              {reports.data.items.map((r) => (
                <tr key={r.id}>
                  <td className="px-2 py-1.5 text-muted">{r.id}</td>
                  <td className="px-2 py-1.5"><Tag tone="accent">{r.format.toUpperCase()}</Tag></td>
                  <td className="px-2 py-1.5">#{r.analysis_id}</td>
                  <td className="px-2 py-1.5 text-xs text-muted">{formatDate(r.created_at)}</td>
                  <td className="px-2 py-1.5 font-mono text-[10px] text-muted" title={r.sha256}>{r.sha256.slice(0, 20)}…</td>
                  <td className="px-2 py-1.5"><a href={`/api/reports/${r.id}/download`} className="inline-flex items-center gap-1 text-accent hover:underline"><Download className="h-3.5 w-3.5" />Download</a></td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
