import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Check, Circle, Eye, EyeOff, KeyRound, Shield, Terminal } from "lucide-react";
import { api, errorMessage } from "../services/api";
import { useSession } from "../services/session";
import { Button, cx, ErrorBanner, Input, Spinner } from "../components/ui";

/** Sign-in page. On a brand-new installation (no accounts yet) it becomes the first-run setup screen instead. */
export function LoginPage() {
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  useEffect(() => {
    api.get<{ needs_setup: boolean }>("/api/auth/setup-status")
      .then((r) => setNeedsSetup(r.needs_setup))
      .catch(() => setNeedsSetup(false));
  }, []);

  return (
    <div className="flex min-h-full items-center justify-center bg-surface-0 px-4 py-10">
      {needsSetup === null ? <Spinner label="Starting AEGIS" /> : needsSetup ? <SetupForm /> : <SignInForm />}
    </div>
  );
}

function Brand({ subtitle }: { subtitle: string }) {
  return (
    <div className="mb-6 flex items-center gap-3">
      <Shield className="h-8 w-8 text-accent" />
      <div>
        <div className="text-lg font-bold tracking-[0.3em] text-text">AEGIS</div>
        <div className="text-xs text-muted">{subtitle}</div>
      </div>
    </div>
  );
}

function PasswordInput({ id, value, onChange, autoComplete }: {
  id: string; value: string; onChange: (v: string) => void; autoComplete: string;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div className="relative">
      <Input id={id} type={shown ? "text" : "password"} autoComplete={autoComplete} value={value}
        onChange={(e) => onChange(e.target.value)} className="w-full pr-9" required />
      <button type="button" onClick={() => setShown(!shown)} aria-label={shown ? "Hide password" : "Show password"}
        className="absolute inset-y-0 right-0 grid w-9 place-items-center text-muted hover:text-text">
        {shown ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  );
}

const Label = ({ htmlFor, children }: { htmlFor: string; children: ReactNode }) => (
  <label className="mb-1 mt-4 block text-xs text-muted first:mt-0" htmlFor={htmlFor}>{children}</label>
);

const Footer = () => (
  <p className="mt-6 text-center text-[11px] leading-relaxed text-muted">
    Offline, read-only analysis of collected directory data. Use only on environments you are authorised to assess.
  </p>
);

function SignInForm() {
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
    <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-border bg-surface-1 p-8">
      <Brand subtitle="Active Directory attack path intelligence" />
      <Label htmlFor="username">Username</Label>
      <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full" required />
      <Label htmlFor="password">Password</Label>
      <PasswordInput id="password" autoComplete="current-password" value={password} onChange={setPassword} />
      <div className="mt-5"><ErrorBanner message={error} /></div>
      <Button type="submit" variant="primary" busy={busy} className="mt-4 w-full justify-center">Sign in</Button>
      <p className="mt-4 text-center text-[11px] text-muted">Forgotten your password? Ask an AEGIS administrator to reset your account.</p>
      <Footer />
    </form>
  );
}

// Mirrors the server policy (backend/app/security/passwords.py). The server always re-checks.
const MIN_LENGTH = 12;
function passwordChecks(password: string, confirm: string, username: string) {
  const name = username.trim().toLowerCase();
  return [
    { ok: password.length >= MIN_LENGTH, text: `At least ${MIN_LENGTH} characters` },
    { ok: password.length > 0 && new Set(password).size >= 5, text: "Not repetitive (5+ different characters)" },
    { ok: password.length > 0 && !(name && password.toLowerCase().includes(name)), text: "Does not contain the username" },
    { ok: confirm.length > 0 && password === confirm, text: "Both passwords match" },
  ];
}

function SetupForm() {
  const { completeSetup } = useSession();
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const checks = passwordChecks(password, confirm, username);
  const ready = code.trim() && username.trim() && checks.every((c) => c.ok);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await completeSetup(code, username, password);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="w-full max-w-md rounded-xl border border-border bg-surface-1 p-8">
      <Brand subtitle="First-run setup" />
      <h1 className="text-base font-semibold text-text">Create your administrator account</h1>
      <p className="mt-1 text-sm leading-relaxed text-muted">
        AEGIS has no default accounts. Choose your own username and password. You can add more people later under
        Settings → Users.
      </p>

      <div className="mt-5 flex gap-2.5 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2.5 text-[13px] leading-relaxed text-muted">
        <Terminal className="mt-0.5 h-4 w-4 shrink-0 text-accent-2" />
        <div>
          To prove you own this installation, enter the one-time <strong className="text-text">setup code</strong>. It is
          shown in the <strong className="text-text">AEGIS server window</strong>, and saved in{" "}
          <code className="font-mono text-[12px] text-text">data\first-run-setup-code.txt</code>.
        </div>
      </div>

      <Label htmlFor="setup-code">Setup code</Label>
      <div className="relative">
        <KeyRound className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input id="setup-code" autoComplete="one-time-code" spellCheck={false} placeholder="XXXX-XXXX-XXXX-XXXX"
          value={code} onChange={(e) => setCode(e.target.value.toUpperCase())}
          className="w-full pl-8 font-mono tracking-wider" required />
      </div>

      <Label htmlFor="new-username">Username</Label>
      <Input id="new-username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)}
        placeholder="e.g. jsmith" className="w-full" required />
      <p className="mt-1 text-[11px] text-muted">3–64 characters: lower-case letters, digits, “.”, “_” or “-”.</p>

      <Label htmlFor="new-password">Password</Label>
      <PasswordInput id="new-password" autoComplete="new-password" value={password} onChange={setPassword} />
      <Label htmlFor="confirm-password">Confirm password</Label>
      <PasswordInput id="confirm-password" autoComplete="new-password" value={confirm} onChange={setConfirm} />

      <ul className="mt-3 grid grid-cols-1 gap-1 text-xs sm:grid-cols-2">
        {checks.map((c) => (
          <li key={c.text} className={cx("flex items-center gap-1.5", c.ok ? "text-sev-low" : "text-muted")}>
            {c.ok ? <Check className="h-3.5 w-3.5" /> : <Circle className="h-3 w-3" />}{c.text}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[11px] text-muted">
        Tip: a passphrase of four or more random words is strong and easy to remember. Your password is stored only
        as a salted Argon2id hash, never in plain text.
      </p>

      <div className="mt-5"><ErrorBanner message={error} /></div>
      <Button type="submit" variant="primary" busy={busy} disabled={!ready} className="mt-4 w-full justify-center">
        Create account and sign in
      </Button>
      <Footer />
    </form>
  );
}
