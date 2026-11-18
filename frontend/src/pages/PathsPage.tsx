import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import { SEVERITIES, type AttackPath, type EvidenceStep, type GraphElements, type Page } from "../services/types";
import { CytoscapeGraph, GraphLegend } from "../graph/CytoscapeGraph";
import {
  Button, Card, Empty, ErrorBanner, Input, PageHeader, Pagination, Select, SeverityBadge, Spinner, Table, Tag,
} from "../components/ui";

const LIMIT = 25;
const CLASSIFICATIONS: Record<string, string> = {
  potential_privilege_escalation: "Potential privilege escalation",
  conditional_attack_path: "Conditional attack path",
  validated_security_exposure: "Validated security exposure",
};

export function PathsPage() {
  const { analysisId } = useSession();
  const [params, setParams] = useSearchParams();
  const [severity, setSeverity] = useState("");
  const [classification, setClassification] = useState("");
  const [offset, setOffset] = useState(0);
  const selected = params.get("path") ? Number(params.get("path")) : null;
  const list = useLoad(() => (analysisId ? api.get<Page<AttackPath>>(`/api/analyses/${analysisId}/paths`,
    { severity, classification, offset, limit: LIMIT }) : Promise.resolve(null)), [analysisId, severity, classification, offset]);
  useEffect(() => setOffset(0), [analysisId, severity, classification]);

  if (!analysisId) return <Empty>No completed analysis for this snapshot yet. Run one from Data Imports.</Empty>;
  return (
    <>
      <PageHeader title="Attack Path Explorer" subtitle="Routes from ordinary identities to tier-0, ranked by transparent risk score. A path shows what the data supports; it is not proof of exploitation." />
      <div className="grid gap-5 2xl:grid-cols-[minmax(420px,2fr)_3fr]">
        <Card title="Paths" actions={<>
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </Select>
          <Select value={classification} onChange={(e) => setClassification(e.target.value)}>
            <option value="">All classifications</option>
            {Object.entries(CLASSIFICATIONS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </Select>
        </>}>
          <ErrorBanner message={list.error} />
          {list.loading && !list.data ? <Spinner /> : list.data && list.data.items.length === 0 ? <Empty>No paths match.</Empty> : list.data && (
            <>
              <Table head={["", "Score", "Hops", "From → to"]}>
                {list.data.items.map((p) => (
                  <tr key={p.id} onClick={() => setParams({ path: String(p.id) })}
                    className={`cursor-pointer ${selected === p.id ? "bg-surface-3" : "hover:bg-surface-2"}`}>
                    <td className="px-2 py-2"><SeverityBadge severity={p.severity} /></td>
                    <td className="px-2 py-2 tabular-nums">{p.score.toFixed(1)}</td>
                    <td className="px-2 py-2">{p.hops}</td>
                    <td className="px-2 py-2"><div className="text-text">{p.source?.name}</div>
                      <div className="text-xs text-muted">→ {p.target?.name}{p.classification !== "potential_privilege_escalation" && <> · {CLASSIFICATIONS[p.classification]}</>}</div></td>
                  </tr>
                ))}
              </Table>
              <Pagination offset={offset} limit={LIMIT} total={list.data.total} onChange={setOffset} />
            </>
          )}
        </Card>
        {selected ? <PathDetail key={selected} pathId={selected} onChanged={list.reload} />
                  : <Empty>Select a path to see its route, explanation, evidence and score breakdown.</Empty>}
      </div>
    </>
  );
}

function PathDetail({ pathId, onChanged }: { pathId: number; onChanged: () => void }) {
  const { can } = useSession();
  const path = useLoad(() => api.get<AttackPath>(`/api/paths/${pathId}`), [pathId]);
  const graph = useLoad(() => api.get<{ elements: GraphElements }>(`/api/paths/${pathId}/graph`), [pathId]);
  const [evidence, setEvidence] = useState<EvidenceStep[] | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function loadEvidence() {
    try { setEvidence((await api.get<{ steps: EvidenceStep[] }>(`/api/paths/${pathId}/evidence`)).steps); }
    catch (e) { setError(errorMessage(e)); }
  }
  async function validate() {
    try {
      await api.post(`/api/paths/${pathId}/validate`, { note });
      setNote("");
      path.reload();
      onChanged();
    } catch (e) { setError(errorMessage(e)); }
  }

  const p = path.data;
  if (path.loading && !p) return <Spinner />;
  if (!p) return <ErrorBanner message={path.error} />;
  const factors = Object.entries(p.score_breakdown?.factors ?? {});
  return (
    <div className="space-y-5">
      <Card title={<><SeverityBadge severity={p.severity} /> <span className="ml-2">{p.score.toFixed(2)}</span> <span className="ml-2 text-xs font-normal text-muted">{p.hops} step(s) · confidence {p.confidence}</span></>}
        actions={<Tag tone={p.classification === "potential_privilege_escalation" ? "accent" : "warn"}>{CLASSIFICATIONS[p.classification]}</Tag>}>
        <p className="mb-3 text-sm text-text">{p.summary}</p>
        {graph.data && <CytoscapeGraph elements={graph.data.elements} layout="path" height={260} />}
        <div className="mt-2"><GraphLegend /></div>
      </Card>
      <Card title="How the path works">
        <ol className="space-y-2 text-sm">
          {p.steps?.map((s, i) => (
            <li key={i} className="flex gap-3">
              <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-surface-3 text-xs text-accent-2">{i + 1}</span>
              <div><div className="text-text">{s.explanation}</div>
                <div className="text-xs text-muted">{s.technique} · <span className="font-mono">{s.kind}</span>{s.alternatives.length > 0 && ` · also via ${s.alternatives.join(", ")}`}{s.conditional && " · conditional"}</div></div>
            </li>
          ))}
        </ol>
        {p.target_reasons && p.target_reasons.length > 0 && <p className="mt-3 text-xs text-muted">Target is tier-0 because: {p.target_reasons.join("; ")}.</p>}
        {p.conditions && p.conditions.length > 0 && (
          <div className="mt-4 rounded-md border border-sev-medium/40 bg-sev-medium/5 p-3">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-sev-medium">Conditions to validate</div>
            <ul className="list-disc space-y-1 pl-5 text-sm text-text">{p.conditions.map((c, i) => <li key={i}>{c}</li>)}</ul>
          </div>
        )}
        <p className="mt-3 text-xs text-muted">{p.narrative?.[p.narrative.length - 1]}</p>
      </Card>
      <Card title="Score breakdown" actions={p.score_breakdown?.capped_by_classification ? <Tag tone="warn">capped: conditional</Tag> : null}>
        <Table head={["Factor", "Value", "Weight", "Points", "Why"]}>
          {factors.map(([name, f]) => (
            <tr key={name}>
              <td className="px-2 py-1.5 capitalize text-text">{name.replaceAll("_", " ")}</td>
              <td className="px-2 py-1.5 tabular-nums">{f.value}</td>
              <td className="px-2 py-1.5 tabular-nums text-muted">{f.weight}</td>
              <td className="px-2 py-1.5 tabular-nums">{f.points}</td>
              <td className="px-2 py-1.5 text-xs text-muted">{f.why}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="Evidence" actions={!evidence && <Button onClick={() => void loadEvidence()}>Load evidence</Button>}>
        <ErrorBanner message={error} />
        {evidence ? evidence.map((e, i) => (
          <div key={i} className="mb-3">
            <div className="text-sm text-text">{i + 1}. {e.step}{e.derived && <Tag tone="accent">derived from both replication rights</Tag>}</div>
            {e.records.map((r) => (
              <div key={r.edge_id} className="ml-5 font-mono text-[11px] text-muted">
                {r.kind} · {String(r.evidence?.source_file ?? "")} · {String(r.evidence?.field ?? "")} · {r.data_source}
                {r.is_inherited !== null && ` · inherited=${r.is_inherited}`} · confidence {r.confidence}
              </div>
            ))}
          </div>
        )) : <p className="text-sm text-muted">Shows the collected records (file, field, data source) behind each step.</p>}
      </Card>
      {can("analyst") && p.classification !== "validated_security_exposure" && (
        <Card title="Record validation">
          <p className="mb-2 text-xs text-muted">Only after confirming this path in an authorised test. The path is rescored without the conditional cap.</p>
          <div className="flex gap-2">
            <Input placeholder="How it was validated (e.g. lab test reference)" value={note} onChange={(e) => setNote(e.target.value)} className="flex-1" maxLength={500} />
            <Button variant="primary" disabled={note.trim().length < 3} onClick={() => void validate()}>Mark validated</Button>
          </div>
        </Card>
      )}
    </div>
  );
}
