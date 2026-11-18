import { api } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { Analysis } from "../services/types";
import { RiskGauge, SeverityChart } from "../components/charts";
import { Card, Empty, ErrorBanner, PageHeader, Spinner, Stat, Table, Tag } from "../components/ui";

export function RiskPage() {
  const { analysisId } = useSession();
  const analysis = useLoad(() => (analysisId ? api.get<Analysis>(`/api/analyses/${analysisId}`) : Promise.resolve(null)), [analysisId]);
  if (!analysisId) return <Empty>No completed analysis for this snapshot yet.</Empty>;
  if (analysis.loading && !analysis.data) return <Spinner />;
  const s = analysis.data?.summary;
  if (!s) return <ErrorBanner message={analysis.error ?? "Analysis summary unavailable."} />;
  const env = s.environment_risk;
  return (
    <>
      <PageHeader title="Risk Intelligence" subtitle="Where exposure concentrates, what the cheapest complete fix is, and how scores are composed." />
      <div className="space-y-5">
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Environment risk">
            <RiskGauge score={env.score} severity={env.severity} />
            <Table head={["Component", "Value", "Weight"]}>
              <tr><td className="px-2 py-1">Worst path</td><td className="px-2 py-1 tabular-nums">{env.components.worst_path}</td><td className="px-2 py-1 text-muted">50%</td></tr>
              <tr><td className="px-2 py-1">Exposure mass</td><td className="px-2 py-1 tabular-nums">{env.components.exposure_mass}</td><td className="px-2 py-1 text-muted">30%</td></tr>
              <tr><td className="px-2 py-1">Breadth</td><td className="px-2 py-1 tabular-nums">{env.components.breadth}</td><td className="px-2 py-1 text-muted">20%</td></tr>
            </Table>
          </Card>
          <Card title="Severity distribution" className="lg:col-span-2"><SeverityChart counts={s.paths_by_severity} height={210} /></Card>
        </div>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Exposed identities" value={`${s.exposed_sources} / ${s.sources_total}`} hint={`${(env.components.exposed_fraction * 100).toFixed(1)}% of starting identities`} />
          <Stat label="Minimum cut" value={s.min_cut.size} hint="changes that break every path" tone="accent" />
          <Stat label="Tier-0 objects" value={s.graph.tier0} hint={`${s.graph.nodes.toLocaleString()} objects analysed`} />
          <Stat label="Beyond depth limit" value={s.beyond_depth} hint={s.truncated ? "path list truncated" : "identities not shown"} />
        </div>
        <Card title="Minimum cut: the smallest set of changes that disconnects every exposed identity from tier-0">
          {s.min_cut.steps.length === 0 ? <Empty>No paths to cut.</Empty> : (
            <Table head={["#", "From", "Relationship", "To"]}>
              {s.min_cut.steps.map((c, i) => (
                <tr key={i}><td className="px-2 py-1.5 text-muted">{i + 1}</td><td className="px-2 py-1.5 text-text">{c.src.name}</td>
                  <td className="px-2 py-1.5 font-mono text-xs text-accent-2">{c.kinds.join(", ")}</td><td className="px-2 py-1.5 text-text">{c.dst.name}</td></tr>
              ))}
            </Table>
          )}
        </Card>
        <div className="grid gap-5 xl:grid-cols-2">
          <Card title="Choke points (relationships carried by most paths)">
            <Table head={["Relationship", "Paths"]}>
              {s.choke_points.slice(0, 12).map((c, i) => (
                <tr key={i}><td className="px-2 py-1.5"><span className="text-text">{c.src.name}</span> <span className="font-mono text-xs text-accent-2">-[{c.kinds.join(", ")}]→</span> <span className="text-text">{c.dst.name}</span></td>
                  <td className="px-2 py-1.5 tabular-nums">{c.paths}</td></tr>
              ))}
            </Table>
          </Card>
          <Card title="Exposed tier-0 targets">
            <Table head={["Target", "Type", "Identities reaching it"]}>
              {s.targets.map((t) => <tr key={t.id}><td className="px-2 py-1.5 text-text">{t.name}</td><td className="px-2 py-1.5 text-muted">{t.kind}</td><td className="px-2 py-1.5 tabular-nums">{t.sources}</td></tr>)}
            </Table>
          </Card>
          <Card title="Central objects (betweenness on attack-relevant subgraph)">
            <Table head={["Object", "Betweenness", ""]}>
              {s.centrality.slice(0, 12).map((c) => <tr key={c.id}><td className="px-2 py-1.5 text-text">{c.name}</td><td className="px-2 py-1.5 tabular-nums">{c.betweenness}</td><td className="px-2 py-1.5">{c.tier0 && <Tag tone="warn">tier-0</Tag>}</td></tr>)}
            </Table>
          </Card>
          <Card title="Analysis run">
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-muted">Graph</dt><dd>{s.graph.nodes.toLocaleString()} nodes · {s.graph.edges.toLocaleString()} edges ({s.graph.traversable_edges.toLocaleString()} traversable)</dd>
              <dt className="text-muted">Graph build</dt><dd>{s.graph.build_seconds}s</dd>
              {Object.entries(s.timings).map(([k, v]) => <div key={k} className="contents"><dt className="text-muted capitalize">{k.replaceAll("_", " ")}</dt><dd className="tabular-nums">{v}s</dd></div>)}
            </dl>
          </Card>
        </div>
      </div>
    </>
  );
}
