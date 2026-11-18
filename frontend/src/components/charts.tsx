import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITIES, type Severity } from "../services/types";

export const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "#e5484d", High: "#f76b15", Medium: "#f5c24c", Low: "#4cc38a",
};

export function SeverityChart({ counts, height = 180 }: { counts: Record<Severity, number>; height?: number }) {
  const data = SEVERITIES.map((s) => ({ severity: s, paths: counts[s] ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
        <XAxis dataKey="severity" tick={{ fill: "#8b95a5", fontSize: 12 }} axisLine={{ stroke: "#262d39" }} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fill: "#8b95a5", fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "#1f2530" }} contentStyle={{ background: "#171b22", border: "1px solid #262d39", borderRadius: 6, color: "#e3e8ef" }} />
        <Bar dataKey="paths" radius={[4, 4, 0, 0]}>
          {data.map((d) => <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function RiskGauge({ score, severity }: { score: number; severity: Severity }) {
  return (
    <div className="flex items-center gap-4">
      <div className="text-4xl font-semibold tabular-nums" style={{ color: SEVERITY_COLOR[severity] }}>{score.toFixed(1)}</div>
      <div className="flex-1">
        <div className="h-2 overflow-hidden rounded bg-surface-3">
          <div className="h-full rounded" style={{ width: `${Math.min(100, score)}%`, backgroundColor: SEVERITY_COLOR[severity] }} />
        </div>
        <div className="mt-1 text-xs text-muted">Environment risk · {severity}</div>
      </div>
    </div>
  );
}
