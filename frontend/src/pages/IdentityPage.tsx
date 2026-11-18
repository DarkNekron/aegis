import { useEffect, useState } from "react";
import { api, errorMessage } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { AdObject, GraphElements, Page, Relationship } from "../services/types";
import { CytoscapeGraph, GraphLegend } from "../graph/CytoscapeGraph";
import {
  Button, Card, Empty, ErrorBanner, Input, PageHeader, Pagination, Select, Spinner, Table, Tag,
} from "../components/ui";

const KINDS = ["", "User", "ServiceAccount", "Group", "Computer", "Domain", "OU", "GPO", "Container"];
const LIMIT = 25;

function mergeElements(a: GraphElements, b: GraphElements): GraphElements {
  const nodes = new Map(a.nodes.map((n) => [n.data.id, n]));
  b.nodes.forEach((n) => nodes.set(n.data.id, n));
  const edges = new Map(a.edges.map((e) => [e.data.id, e]));
  b.edges.forEach((e) => edges.set(e.data.id, e));
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

export function IdentityPage() {
  const { snapshotId } = useSession();
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("");
  const [tier0, setTier0] = useState(false);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const list = useLoad(() => (snapshotId ? api.get<Page<AdObject>>(`/api/snapshots/${snapshotId}/objects`,
    { q: query, kind, tier0: tier0 ? true : undefined, offset, limit: LIMIT }) : Promise.resolve(null)),
    [snapshotId, query, kind, tier0, offset]);
  useEffect(() => { setOffset(0); setSelected(null); }, [snapshotId, query, kind, tier0]);

  if (!snapshotId) return <Empty>Select or create a snapshot first.</Empty>;
  return (
    <>
      <PageHeader title="Identity Explorer" subtitle="Search users, groups, computers and other directory objects; inspect relationships and their neighbourhood." />
      <div className="grid gap-5 xl:grid-cols-[minmax(380px,2fr)_3fr]">
        <Card title="Directory objects">
          <form onSubmit={(e) => { e.preventDefault(); setQuery(q.trim()); }} className="mb-3 flex flex-wrap gap-2">
            <Input placeholder="Name or SID…" value={q} onChange={(e) => setQ(e.target.value)} className="flex-1" />
            <Select value={kind} onChange={(e) => setKind(e.target.value)}>
              {KINDS.map((k) => <option key={k} value={k}>{k || "All types"}</option>)}
            </Select>
            <label className="flex items-center gap-1.5 text-xs text-muted"><input type="checkbox" checked={tier0} onChange={(e) => setTier0(e.target.checked)} />tier-0</label>
            <Button type="submit">Search</Button>
          </form>
          <ErrorBanner message={list.error} />
          {list.loading && !list.data ? <Spinner /> : list.data && list.data.items.length === 0 ? <Empty>No matching objects.</Empty> : list.data && (
            <>
              <Table head={["Name", "Type", ""]}>
                {list.data.items.map((o) => (
                  <tr key={o.id} onClick={() => setSelected(o.id)}
                    className={`cursor-pointer ${selected === o.id ? "bg-surface-3" : "hover:bg-surface-2"}`}>
                    <td className="px-2 py-1.5"><div className="text-text">{o.name}</div><div className="font-mono text-[10px] text-muted">{o.object_id}</div></td>
                    <td className="px-2 py-1.5 text-muted">{o.kind}</td>
                    <td className="px-2 py-1.5 text-right">
                      {o.tier0 && <Tag tone="warn">tier-0</Tag>} {o.placeholder && <Tag>not collected</Tag>} {o.enabled === false && <Tag>disabled</Tag>}
                    </td>
                  </tr>
                ))}
              </Table>
              <Pagination offset={offset} limit={LIMIT} total={list.data.total} onChange={setOffset} />
            </>
          )}
        </Card>
        {selected ? <ObjectDetail key={selected} snapshotId={snapshotId} objectId={selected} onSelect={setSelected} />
                  : <Empty>Select an object to see its details, relationships and neighbourhood graph.</Empty>}
      </div>
    </>
  );
}

function ObjectDetail({ snapshotId, objectId, onSelect }: { snapshotId: number; objectId: number; onSelect: (id: number) => void }) {
  const obj = useLoad(() => api.get<AdObject>(`/api/objects/${objectId}`), [objectId]);
  const [direction, setDirection] = useState<"out" | "in">("out");
  const rels = useLoad(() => api.get<Page<Relationship>>(`/api/objects/${objectId}/relationships`, { direction, limit: 100 }), [objectId, direction]);
  const [depth, setDepth] = useState(1);
  const [traversable, setTraversable] = useState(false);
  const [graph, setGraph] = useState<GraphElements | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);

  useEffect(() => {
    setGraph(null);
    setGraphError(null);
    api.get<{ elements: GraphElements; truncated: boolean }>(`/api/snapshots/${snapshotId}/graph/neighborhood`,
      { node: objectId, depth, traversable_only: traversable })
      .then((r) => { setGraph(r.elements); setTruncated(r.truncated); })
      .catch((e) => setGraphError(errorMessage(e)));
  }, [snapshotId, objectId, depth, traversable]);

  async function expand(id: number) {
    try {
      const r = await api.get<{ elements: GraphElements; truncated: boolean }>(`/api/snapshots/${snapshotId}/graph/neighborhood`,
        { node: id, depth: 1, traversable_only: traversable });
      setGraph((g) => (g ? mergeElements(g, r.elements) : r.elements));
      setTruncated((t) => t || r.truncated);
    } catch (e) {
      setGraphError(errorMessage(e));
    }
  }

  const o = obj.data;
  return (
    <div className="space-y-5">
      <Card title={o ? <>{o.name} <span className="ml-2 text-xs font-normal text-muted">{o.kind}</span></> : "Object"}>
        {obj.loading && !o ? <Spinner /> : o && (
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap gap-2">
              {o.tier0 && <Tag tone="warn">tier-0: {o.tier0_reason}</Tag>}
              {o.placeholder && <Tag>referenced but not collected</Tag>}
              {o.enabled !== null && <Tag tone={o.enabled ? "accent" : "muted"}>{o.enabled ? "enabled" : "disabled"}</Tag>}
              <span className="font-mono text-xs text-muted">{o.object_id}</span>
            </div>
            {o.properties && Object.keys(o.properties).length > 0 && (
              <dl className="grid grid-cols-[180px_1fr] gap-x-3 gap-y-1 text-xs">
                {Object.entries(o.properties).map(([k, v]) => (
                  <div key={k} className="contents"><dt className="text-muted">{k}</dt><dd className="break-all text-text">{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>
                ))}
              </dl>
            )}
          </div>
        )}
      </Card>
      <Card title="Neighbourhood" actions={<>
        <Select value={depth} onChange={(e) => setDepth(Number(e.target.value))}>{[1, 2, 3].map((d) => <option key={d} value={d}>depth {d}</option>)}</Select>
        <label className="flex items-center gap-1.5 text-xs text-muted"><input type="checkbox" checked={traversable} onChange={(e) => setTraversable(e.target.checked)} />attack-relevant only</label>
      </>}>
        <ErrorBanner message={graphError} />
        {truncated && <div className="mb-2 text-xs text-sev-medium">Display limit reached; narrow the view or expand individual objects.</div>}
        {graph ? <CytoscapeGraph elements={graph} layout="concentric" center={objectId} height={460} onNodeSelect={() => undefined} onNodeExpand={(id) => void expand(id)} /> : !graphError && <Spinner />}
        <div className="mt-2 flex items-center justify-between"><GraphLegend /><span className="text-xs text-muted">double-click a node to expand</span></div>
      </Card>
      <Card title="Relationships" actions={
        <Select value={direction} onChange={(e) => setDirection(e.target.value as "out" | "in")}>
          <option value="out">Outgoing (what it can affect)</option><option value="in">Incoming (what can affect it)</option>
        </Select>}>
        {rels.loading && !rels.data ? <Spinner /> : rels.data && rels.data.items.length === 0 ? <Empty>No relationships.</Empty> : rels.data && (
          <Table head={["Relationship", direction === "out" ? "Target" : "Source", "Evidence", "Confidence"]}>
            {rels.data.items.map((r) => (
              <tr key={r.id} className="hover:bg-surface-2">
                <td className="px-2 py-1.5 font-mono text-xs text-accent-2">{r.kind}{r.is_inherited ? " (inherited)" : ""}</td>
                <td className="px-2 py-1.5"><button className="text-left text-text hover:text-accent" onClick={() => onSelect(r.other.id)}>{r.other.name}</button>
                  <span className="ml-2 text-xs text-muted">{r.other.kind}</span></td>
                <td className="px-2 py-1.5 font-mono text-[10px] text-muted">{String(r.evidence?.source_file ?? "")} · {r.data_source}</td>
                <td className="px-2 py-1.5 tabular-nums">{r.confidence}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
