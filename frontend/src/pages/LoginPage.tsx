import { useState, type FormEvent } from "react";
import { Shield } from "lucide-react";
import { errorMessage } from "../services/api";
import { useSession } from "../services/session";
import { Button, ErrorBanner, Input } from "../components/ui";

export function LoginPage() {
  const { login } = useSession();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-border bg-surface-1 p-8">
        <div className="mb-6 flex items-center gap-3">
          <Shield className="h-8 w-8 text-accent" />
          <div>
            <div className="text-lg font-bold tracking-[0.3em] text-text">AEGIS</div>
            <div className="text-xs text-muted">Active Directory attack path intelligence</div>
          </div>
        </div>
        <label className="mb-1 block text-xs text-muted" htmlFor="username">Username</label>
        <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} className="mb-4 w-full" required />
        <label className="mb-1 block text-xs text-muted" htmlFor="password">Password</label>
        <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="mb-5 w-full" required />
        <ErrorBanner message={error} />
        <Button type="submit" variant="primary" busy={busy} className="mt-4 w-full justify-center">Sign in</Button>
        <p className="mt-6 text-center text-[11px] leading-relaxed text-muted">
          Offline, read-only analysis of collected directory data. Use only on environments you are authorised to assess.
        </p>
      </form>
    </div>
  );
}
