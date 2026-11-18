import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import type { Job, Severity } from "../services/types";

export function cx(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

export function Card({ title, actions, children, className }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cx("rounded-lg border border-border bg-surface-1", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold tracking-wide text-text">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: Severity | "accent" }) {
  const color = tone === "accent" ? "text-accent-2" : tone ? SEVERITY_TEXT[tone] : "text-text";
  return (
    <div className="rounded-lg border border-border bg-surface-1 px-4 py-3">
      <div className="text-xs uppercase tracking-wider text-muted">{label}</div>
      <div className={cx("mt-1 text-2xl font-semibold tabular-nums", color)}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export const SEVERITY_TEXT: Record<Severity, string> = {
  Critical: "text-sev-critical", High: "text-sev-high", Medium: "text-sev-medium", Low: "text-sev-low",
};
const SEVERITY_BADGE: Record<Severity, string> = {
  Critical: "border-sev-critical/50 bg-sev-critical/10 text-sev-critical",
  High: "border-sev-high/50 bg-sev-high/10 text-sev-high",
  Medium: "border-sev-medium/50 bg-sev-medium/10 text-sev-medium",
  Low: "border-sev-low/50 bg-sev-low/10 text-sev-low",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cx("inline-block rounded border px-1.5 py-0.5 text-xs font-semibold", SEVERITY_BADGE[severity])}>{severity}</span>;
}

export function Tag({ children, tone = "muted" }: { children: ReactNode; tone?: "muted" | "accent" | "warn" }) {
  const tones = { muted: "border-border text-muted", accent: "border-accent/50 text-accent", warn: "border-sev-medium/50 text-sev-medium" };
  return <span className={cx("inline-block rounded border px-1.5 py-0.5 text-[11px]", tones[tone])}>{children}</span>;
}

export function Button({ variant = "secondary", busy, className, children, ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost"; busy?: boolean }) {
  const variants = {
    primary: "bg-accent text-white hover:bg-accent/90 border-accent",
    secondary: "bg-surface-2 text-text hover:bg-surface-3 border-border",
    danger: "bg-transparent text-sev-critical hover:bg-sev-critical/10 border-sev-critical/50",
    ghost: "bg-transparent text-muted hover:text-text border-transparent",
  };
  return (
    <button {...props} disabled={props.disabled || busy}
      className={cx("inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50", variants[variant], className)}>
      {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
      {children}
    </button>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx("rounded-md border border-border bg-surface-0 px-2.5 py-1.5 text-sm text-text placeholder:text-muted focus:border-accent focus:outline-none", props.className)} />;
}

export function Select({ children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx("rounded-md border border-border bg-surface-0 px-2.5 py-1.5 text-sm text-text focus:border-accent focus:outline-none", props.className)}>{children}</select>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <div className="flex items-center gap-2 py-6 text-sm text-muted"><Loader2 className="h-4 w-4 animate-spin" />{label}…</div>;
}

export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" className="flex items-start gap-2 rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /><span>{message}</span>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">{children}</div>;
}

export function Table({ head, children }: { head: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead><tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted">
          {head.map((h, i) => <th key={i} className="px-2 py-2 font-medium">{h}</th>)}
        </tr></thead>
        <tbody className="divide-y divide-border/60">{children}</tbody>
      </table>
    </div>
  );
}

export function Pagination({ offset, limit, total, onChange }: { offset: number; limit: number; total: number; onChange: (offset: number) => void }) {
  if (total <= limit) return null;
  return (
    <div className="mt-3 flex items-center justify-between text-xs text-muted">
      <span>{offset + 1}–{Math.min(offset + limit, total)} of {total}</span>
      <div className="flex gap-2">
        <Button variant="secondary" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</Button>
        <Button variant="secondary" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</Button>
      </div>
    </div>
  );
}

export function JobProgress({ job }: { job: Job | null }) {
  if (!job) return null;
  const done = !["queued", "running"].includes(job.status);
  const pct = Math.round((job.status === "succeeded" ? 1 : job.progress) * 100);
  return (
    <div className="rounded-md border border-border bg-surface-0 px-3 py-2 text-sm">
      <div className="flex justify-between text-xs text-muted">
        <span>{job.name}</span>
        <span className={job.status === "succeeded" ? "text-sev-low" : done ? "text-sev-critical" : ""}>{job.status.replace("_", " ")}{!done && ` · ${pct}%`}</span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded bg-surface-3">
        <div className={cx("h-full transition-all", job.status === "failed" ? "bg-sev-critical" : "bg-accent")} style={{ width: `${done ? 100 : pct}%` }} />
      </div>
      {job.error && <div className="mt-1.5 text-xs text-sev-critical">{job.error}</div>}
    </div>
  );
}

export function SampleBanner({ show }: { show: boolean | undefined }) {
  if (!show) return null;
  return <div className="rounded-md border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-xs text-sev-medium">Sample data: synthetic AEGISLAB.LOCAL environment, not a real organisation.</div>;
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-text">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}</div>
    </div>
  );
}

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function formatDate(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "–";
}
