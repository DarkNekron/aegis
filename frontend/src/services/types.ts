// Shapes returned by the AEGIS API (see docs/API.md). Only the fields the UI uses are typed.

export type Role = "admin" | "analyst" | "viewer";
export type Severity = "Critical" | "High" | "Medium" | "Low";
export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

export interface User { id: number; username: string; role: Role }
export interface Page<T> { total: number; items: T[] }

export interface Snapshot {
  id: number; name: string; description: string | null; status: string; is_sample: boolean;
  source_kind: string | null; created_at: string; collected_at: string | null;
  stats: { objects_total?: number; relationships_total?: number; objects_by_kind?: Record<string, number>;
           relationships_by_kind?: Record<string, number> };
}
export interface ImportRecord {
  id: number; filename: string; size_bytes: number; sha256: string; status: string; format: string | null;
  created_at: string; finished_at: string | null; errors: string[] | null;
  summary: { objects_inserted?: number; relationships_inserted?: number; placeholders_created?: number;
             item_errors?: number; warnings?: string[]; errors?: { file: string; location: string; message: string }[] } | null;
}
export interface SnapshotDetail extends Snapshot { imports: ImportRecord[] }

export interface Job {
  id: string; name: string; kind: string; status: "queued" | "running" | "succeeded" | "failed" | "cancelled" | "timed_out";
  progress: number; message: string; error: string | null; error_code: string | null;
  created_at: string; finished_at: string | null; result?: Record<string, unknown>;
}

export interface AdObject {
  id: number; object_id: string; kind: string; name: string; domain: string | null; enabled: boolean | null;
  tier0: boolean; tier0_reason: string | null; placeholder: boolean;
  properties?: Record<string, unknown>; relationship_counts?: { outgoing: number; incoming: number };
}
export interface Relationship {
  id: number; kind: string; other: AdObject; data_source: string; collected_at: string | null;
  is_inherited: boolean | null; confidence: number; evidence: Record<string, unknown> | null;
}

export interface EnvironmentRisk {
  score: number; severity: Severity;
  components: { worst_path: number; exposure_mass: number; breadth: number; exposed_fraction: number };
  paths_by_severity?: Record<Severity, number>;
}
export interface ObjRef { id: number; object_id: string; name: string; kind: string }
export interface AnalysisSummary {
  environment_risk: EnvironmentRisk; paths_total: number; paths_by_severity: Record<Severity, number>;
  sources_total: number; exposed_sources: number; beyond_depth: number; truncated: boolean;
  targets: (ObjRef & { sources: number })[];
  choke_points: { src: ObjRef; dst: ObjRef; kinds: string[]; edge_keys: (number | string)[]; paths: number }[];
  choke_nodes: (ObjRef & { paths: number })[];
  min_cut: { size: number; steps: { src: ObjRef; dst: ObjRef; kinds: string[]; edge_keys: (number | string)[] }[] };
  centrality: (ObjRef & { betweenness: number; tier0: boolean })[];
  graph: { nodes: number; edges: number; traversable_edges: number; tier0: number; sources: number; build_seconds: number };
  timings: Record<string, number>;
}
export interface Analysis {
  id: number; snapshot_id: number; status: string; error: string | null; created_at: string;
  finished_at: string | null; environment_risk: EnvironmentRisk | null; paths_total: number | null;
  paths_by_severity: Record<Severity, number> | null; summary?: AnalysisSummary;
}

export interface PathNode { id: number; object_id: string; name: string; kind: string; tier0: boolean }
export interface PathStep {
  src: number; dst: number; edge_key: number | string; kind: string; alternatives: string[]; conditional: boolean;
  technique: string; explanation: string; severity: number; confidence: number;
}
export interface ScoreFactor { value: number; weight: number; points: number; why: string }
export interface AttackPath {
  id: number; analysis_id: number; score: number; severity: Severity; hops: number; classification: string;
  confidence: number; signature: string; source: PathNode | null; target: PathNode | null; summary: string;
  validated_at: string | null;
  nodes?: PathNode[]; steps?: PathStep[]; conditions?: string[]; narrative?: string[]; target_reasons?: string[];
  score_breakdown?: { factors: Record<string, ScoreFactor>; capped_by_classification: boolean };
}
export interface EvidenceStep {
  step: string; src: number; dst: number; derived: boolean;
  records: { edge_id: number; kind: string; data_source: string; collected_at: string | null;
             is_inherited: boolean | null; confidence: number; evidence: Record<string, unknown> | null }[];
}

export interface CyElement { data: Record<string, unknown> & { id: string } }
export interface GraphElements { nodes: CyElement[]; edges: CyElement[] }

export interface SimulationResult {
  actions: { type: string; relationships?: { src: ObjRef; dst: ObjRef; kind: string }[]; object?: ObjRef }[];
  paths_before: number; paths_after: number; paths_eliminated: number; exposed_before: number; exposed_after: number;
  identities_secured: ObjRef[]; identities_still_exposed: ObjRef[];
  tier0_still_reachable: (ObjRef & { sources: number })[];
  severity_before: Record<Severity, number>; severity_after: Record<Severity, number>;
  environment_risk_before: EnvironmentRisk; environment_risk_after: EnvironmentRisk; environment_risk_change: number;
  eliminated: { summary: string; score: number; severity: Severity; hops: number }[];
  remaining: { summary: string; score: number; severity: Severity; hops: number }[];
  baseline_is_current?: boolean;
}
export interface Simulation {
  id: number; analysis_id: number; created_at: string; actions: Record<string, unknown>[];
  paths_before: number | null; paths_after: number | null; environment_risk_change: number | null;
  result?: SimulationResult;
}

export interface Dashboard {
  snapshot: Snapshot | null;
  stats: { identities: number; users: number; service_accounts: number; groups: number; computers: number;
           privileged_accounts: number; objects_by_kind: Record<string, number> } | null;
  analysis: Analysis | null;
  findings?: { attack_paths: number; critical_paths: number; high_risk_relationships: number;
               unresolved_findings: number; exposed_identities: number } | null;
  definitions?: Record<string, string>;
}

export interface ReportItem { id: number; snapshot_id: number; analysis_id: number; format: string; sha256: string; created_at: string }

export interface Health {
  status: string; version: string; environment: string; uptime_seconds: number;
  platform: Record<string, string>;
  resources: { total_ram_mb: number; available_ram_mb: number; ram_percent: number; cpu_percent: number;
               cpu_logical: number; cpu_physical: number; process_rss_mb: number; disk_total_mb: number; disk_free_mb: number };
  limits: Record<string, number>; jobs: Record<string, number>;
  graph_cache: { entries: number; capacity: number; builds: number; hits: number };
  database: { ok: boolean; engine: string; size_bytes: number | null }; warnings: string[];
}

export interface ComparisonItem { src: { object_id: string; name: string }; kind: string; dst: { object_id: string; name: string } }
export interface Comparison {
  old: { id: number; name: string; analysis_id: number | null }; new: { id: number; name: string; analysis_id: number | null };
  objects: { added: { count: number; by_kind: Record<string, number>; items: { name: string; kind: string }[] };
             removed: { count: number; by_kind: Record<string, number>; items: { name: string; kind: string }[] };
             changed: { count: number; items: { name: string; changes: Record<string, [unknown, unknown]> }[] };
             users_added: string[]; users_removed: string[]; groups_added: string[]; groups_removed: string[] };
  relationships: Record<"added" | "removed", { count: number; by_kind: Record<string, number>;
                                              categories: Record<string, { count: number; items: ComparisonItem[] }> }>;
  privilege: { newly_tier0: string[]; no_longer_tier0: string[]; reliable: boolean };
  attack_paths: { available: boolean; reason?: string; old_total?: number; new_total?: number; persisting?: number;
                  appeared?: { count: number; items: { summary: string; score: number; severity: Severity }[] };
                  resolved?: { count: number; items: { summary: string; score: number; severity: Severity }[] };
                  newly_exposed?: string[]; no_longer_exposed?: string[] };
  risk: { old: EnvironmentRisk | null; new: EnvironmentRisk | null; change: number | null };
  summary: string[];
}
