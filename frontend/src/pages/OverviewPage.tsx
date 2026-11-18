import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { AttackPath, Dashboard, Page } from "../services/types";
import { RiskGauge, SeverityChart } from "../components/charts";
import { Card, Empty, ErrorBanner, PageHeader, SampleBanner, SeverityBadge, Spinner, Stat, Table } from "../components/ui";

export function OverviewPage() {
  const { snapshotId, analysisId } = useSession();
  const dash = useLoad(() => api.get<Dashboard>("/api/dashboard", { snapshot_id: snapshotId }), [snapshotId]);
  const top = useLoad(() => (analysisId ? api.get<Page<AttackPath>>(`/api/analyses/${analysisId}/paths`, { limit: 6 })
                                        : Promise.resolve(null)), [analysisId]);

  if (dash.loading && !dash.data) return <Spinner />;
  if (dash.error) return <ErrorBanner message={dash.error} />;
  const d = dash.data;
  if (!d?.snapshot || !d.stats) {
    return (
      <>
        <PageHeader title="Overview" subtitle="Directory exposure at a glance" />
        <Empty>No assessment data yet. <Link to="/imports" className="text-accent">Create a snapshot and import SharpHound / BloodHound data</Link> to begin.</Empty>
      </>
    );
  }
  const env = d.analysis?.environment_risk;
  const f = d.findings;
  return (
    <>
      <PageHeader title="Overview" subtitle={`${d.snapshot.name} · collected ${d.snapshot.collected_at ? new Date(d.snapshot.collected_at).toLocaleDateString() : "date unknown"}`} />
      <div className="space-y-5">
        <SampleBanner show={d.snapshot.is_sample} />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <Stat label="Identities" value={d.stats.identities.toLocaleString()} hint="users, groups, computers" />
          <Stat label="Users" value={d.stats.users.toLocaleString()} hint={`${d.stats.service_accounts} service accounts`} />
          <Stat label="Groups" value={d.stats.groups.toLocaleString()} />
          <Stat label="Computers" value={d.stats.computers.toLocaleString()} />
          <Stat label="Privileged accounts" value={d.stats.privileged_accounts} hint="tier-0 users & service accounts" tone="accent" />
        </div>
        {f ? (
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Attack paths" value={f.attack_paths} hint={`${f.exposed_identities} identities exposed`} />
            <Stat label="Critical paths" value={f.critical_paths} tone="Critical" />
            <Stat label="High-risk relationships" value={f.high_risk_relationships} hint="on attack paths, severity ≥ 0.85" tone="High" />
            <Stat label="Unresolved findings" value={f.unresolved_findings} hint="Critical + High paths" />
          </div>
        ) : (
          <Empty>This snapshot has not been analysed yet. Run an analysis from <Link to="/imports" className="text-accent">Data Imports</Link>.</Empty>
        )}
        {env && d.analysis?.paths_by_severity && (
          <div className="grid gap-4 lg:grid-cols-3">
            <Card title="Environment risk">
              <RiskGauge score={env.score} severity={env.severity} />
              <dl className="mt-4 grid grid-cols-3 gap-2 text-xs">
                <div><dt className="text-muted">Worst path</dt><dd className="text-text">{env.components.worst_path}</dd></div>
                <div><dt className="text-muted">Exposure mass</dt><dd className="text-text">{env.components.exposure_mass}</dd></div>
                <div><dt className="text-muted">Breadth</dt><dd className="text-text">{env.components.breadth}</dd></div>
              </dl>
            </Card>
            <Card title="Paths by severity" className="lg:col-span-2"><SeverityChart counts={d.analysis.paths_by_severity} /></Card>
          </div>
        )}
        {top.data && top.data.items.length > 0 && (
          <Card title="Highest-risk attack paths" actions={<Link to="/paths" className="text-xs text-accent">All paths →</Link>}>
            <Table head={["Severity", "Score", "Hops", "Path"]}>
              {top.data.items.map((p) => (
                <tr key={p.id} className="hover:bg-surface-2">
                  <td className="px-2 py-2"><SeverityBadge severity={p.severity} /></td>
                  <td className="px-2 py-2 tabular-nums">{p.score.toFixed(1)}</td>
                  <td className="px-2 py-2">{p.hops}</td>
                  <td className="px-2 py-2"><Link to={`/paths?path=${p.id}`} className="text-text hover:text-accent">{p.summary}</Link></td>
                </tr>
              ))}
            </Table>
          </Card>
        )}
      </div>
    </>
  );
}
