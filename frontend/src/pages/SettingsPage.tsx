import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage } from "../services/api";
import { useLoad } from "../services/hooks";
import { useSession } from "../services/session";
import type { Page, Role } from "../services/types";
import { Button, Card, ErrorBanner, formatDate, Input, PageHeader, Select, Table, Tag } from "../components/ui";

interface AnalysisConfig { tier0_categories: string[]; custom_tier0_object_ids: string[]; trust_input_hints: boolean; traverse_trusts: boolean }
interface RiskConfig { weights: Record<string, number>; bands: Record<string, number>; hop_decay: number; conditional_factor: number;
                       [key: string]: unknown }
interface UserRow { id: number; username: string; role: Role; is_active: boolean; locked: boolean; last_login_at: string | null }
interface AuditRow { id: number; ts: string; username: string | null; action: string; outcome: string; target_type: string | null;
                     target_id: string | null; ip: string | null }

function useFeedback() {
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  return {
    message,
    async run(action: () => Promise<unknown>, success: string) {
      try { await action(); setMessage({ ok: true, text: success }); } catch (e) { setMessage({ ok: false, text: errorMessage(e) }); }
    },
  };
}

function Feedback({ message }: { message: { ok: boolean; text: string } | null }) {
  if (!message) return null;
  return message.ok ? <div className="mt-2 text-xs text-sev-low">{message.text}</div> : <div className="mt-2"><ErrorBanner message={message.text} /></div>;
}

export function SettingsPage() {
  const { can } = useSession();
  return (
    <>
      <PageHeader title="Settings" subtitle="Analysis scope, risk model, users and audit trail." />
      <div className="grid gap-5 xl:grid-cols-2">
        <PasswordCard />
        {can("analyst") && <AnalysisCard editable={can("admin")} />}
        {can("analyst") && <RiskCard editable={can("admin")} />}
        {can("admin") && <UsersCard />}
        {can("admin") && <AuditCard />}
      </div>
    </>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const fb = useFeedback();
  function submit(e: FormEvent) {
    e.preventDefault();
    void fb.run(async () => {
      await api.post("/api/auth/change-password", { current_password: current, new_password: next });
      setCurrent(""); setNext("");
    }, "Password changed; your other sessions were signed out.");
  }
  return (
    <Card title="Your password">
      <form onSubmit={submit} className="flex flex-wrap gap-2">
        <Input type="password" placeholder="Current password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        <Input type="password" placeholder="New password (12+ characters)" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} />
        <Button type="submit">Change</Button>
      </form>
      <Feedback message={fb.message} />
    </Card>
  );
}

function AnalysisCard({ editable }: { editable: boolean }) {
  const loaded = useLoad(() => api.get<{ config: AnalysisConfig; categories: Record<string, string> }>("/api/settings/analysis"), []);
  const [config, setConfig] = useState<AnalysisConfig | null>(null);
  const fb = useFeedback();
  useEffect(() => { if (loaded.data) setConfig(loaded.data.config); }, [loaded.data]);
  if (!config || !loaded.data) return <Card title="Tier-0 & traversal"><ErrorBanner message={loaded.error} /></Card>;
  const toggle = (c: string) => setConfig({ ...config, tier0_categories: config.tier0_categories.includes(c)
    ? config.tier0_categories.filter((x) => x !== c) : [...config.tier0_categories, c] });
  return (
    <Card title="Tier-0 & traversal" actions={editable && <Button variant="primary" onClick={() => void fb.run(() => api.put("/api/settings/analysis", config), "Saved. Re-run analyses to apply.")}>Save</Button>}>
      <fieldset disabled={!editable} className="space-y-3 text-sm">
        <div className="grid gap-1 sm:grid-cols-2">
          {Object.entries(loaded.data.categories).map(([key, description]) => (
            <label key={key} className="flex items-start gap-2"><input type="checkbox" className="mt-1" checked={config.tier0_categories.includes(key)} onChange={() => toggle(key)} />
              <span><span className="text-text">{key.replaceAll("_", " ")}</span><span className="block text-xs text-muted">{description}</span></span></label>
          ))}
        </div>
        <label className="block text-xs text-muted">Additional tier-0 objects (one SID/GUID per line)
          <textarea className="mt-1 h-20 w-full rounded-md border border-border bg-surface-0 p-2 font-mono text-xs text-text"
            value={config.custom_tier0_object_ids.join("\n")} onChange={(e) => setConfig({ ...config, custom_tier0_object_ids: e.target.value.split(/\s+/).filter(Boolean) })} />
        </label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={config.trust_input_hints} onChange={(e) => setConfig({ ...config, trust_input_hints: e.target.checked })} />Trust imported "high value" flags as tier-0</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={config.traverse_trusts} onChange={(e) => setConfig({ ...config, traverse_trusts: e.target.checked })} />Traverse domain trusts (as conditional steps)</label>
      </fieldset>
      <Feedback message={fb.message} />
    </Card>
  );
}

function RiskCard({ editable }: { editable: boolean }) {
  const loaded = useLoad(() => api.get<{ config: RiskConfig }>("/api/settings/risk"), []);
  const [config, setConfig] = useState<RiskConfig | null>(null);
  const fb = useFeedback();
  useEffect(() => { if (loaded.data) setConfig(loaded.data.config); }, [loaded.data]);
  if (!config) return <Card title="Risk model"><ErrorBanner message={loaded.error} /></Card>;
  const total = Object.values(config.weights).reduce((a, b) => a + b, 0);
  return (
    <Card title="Risk model weights" actions={editable && <Button variant="primary" onClick={() => void fb.run(() => api.put("/api/settings/risk", config), "Saved. New analyses use these weights.")}>Save</Button>}>
      <fieldset disabled={!editable} className="space-y-2 text-sm">
        {Object.entries(config.weights).map(([factor, weight]) => (
          <div key={factor} className="grid grid-cols-[1fr_80px_60px] items-center gap-2">
            <span className="capitalize text-text">{factor.replaceAll("_", " ")}</span>
            <Input type="number" step="0.01" min={0} value={weight} onChange={(e) => setConfig({ ...config, weights: { ...config.weights, [factor]: Number(e.target.value) } })} />
            <span className="text-right text-xs tabular-nums text-muted">{total ? ((weight / total) * 100).toFixed(0) : 0}%</span>
          </div>
        ))}
        <div className="grid grid-cols-3 gap-2 pt-2">
          {(["Critical", "High", "Medium"] as const).map((band) => (
            <label key={band} className="text-xs text-muted">{band} ≥
              <Input type="number" value={config.bands[band]} onChange={(e) => setConfig({ ...config, bands: { ...config.bands, [band]: Number(e.target.value) } })} className="mt-1 w-full" />
            </label>
          ))}
        </div>
      </fieldset>
      <p className="mt-2 text-xs text-muted">Weights are normalised. Each analysis records the weights it used. See docs/RISK_SCORING.md.</p>
      <Feedback message={fb.message} />
    </Card>
  );
}

function UsersCard() {
  const users = useLoad(() => api.get<{ items: UserRow[] }>("/api/users"), []);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" as Role });
  const fb = useFeedback();
  const act = (fn: () => Promise<unknown>, msg: string) => void fb.run(async () => { await fn(); users.reload(); }, msg);
  return (
    <Card title="Users">
      <form onSubmit={(e) => { e.preventDefault(); act(() => api.post("/api/users", form), `Created ${form.username}.`); }} className="mb-3 flex flex-wrap gap-2">
        <Input placeholder="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        <Input type="password" placeholder="initial password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={12} />
        <Select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
          <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="admin">admin</option>
        </Select>
        <Button type="submit" variant="primary">Add user</Button>
      </form>
      <Feedback message={fb.message} />
      <Table head={["User", "Role", "Status", "Last login", ""]}>
        {users.data?.items.map((u) => (
          <tr key={u.id}>
            <td className="px-2 py-1.5 text-text">{u.username}</td>
            <td className="px-2 py-1.5">
              <Select value={u.role} onChange={(e) => act(() => api.patch(`/api/users/${u.id}`, { role: e.target.value }), `Updated ${u.username}.`)}>
                <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="admin">admin</option>
              </Select>
            </td>
            <td className="px-2 py-1.5">{u.is_active ? <Tag tone="accent">active</Tag> : <Tag>disabled</Tag>} {u.locked && <Tag tone="warn">locked</Tag>}</td>
            <td className="px-2 py-1.5 text-xs text-muted">{formatDate(u.last_login_at)}</td>
            <td className="px-2 py-1.5"><Button variant="ghost" onClick={() => act(() => api.patch(`/api/users/${u.id}`, { is_active: !u.is_active }), `Updated ${u.username}.`)}>{u.is_active ? "disable" : "enable"}</Button></td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

function AuditCard() {
  const log = useLoad(() => api.get<Page<AuditRow>>("/api/audit", { limit: 50 }), []);
  return (
    <Card title="Audit log (latest 50)" actions={<Button variant="ghost" onClick={log.reload}>Refresh</Button>}>
      <Table head={["When", "User", "Action", "Outcome", "Target", "IP"]}>
        {log.data?.items.map((a) => (
          <tr key={a.id}>
            <td className="px-2 py-1 text-xs text-muted">{formatDate(a.ts)}</td><td className="px-2 py-1 text-text">{a.username}</td>
            <td className="px-2 py-1 font-mono text-xs">{a.action}</td>
            <td className="px-2 py-1">{a.outcome === "success" ? <Tag tone="accent">success</Tag> : <Tag tone="warn">{a.outcome}</Tag>}</td>
            <td className="px-2 py-1 text-xs text-muted">{a.target_type} {a.target_id}</td><td className="px-2 py-1 text-xs text-muted">{a.ip}</td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
