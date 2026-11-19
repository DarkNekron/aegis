// Nekron: the built-in guide. A step-by-step walkthrough of AEGIS that opens on a user's first visit, can be
// skipped at any time, and can be called back from the sidebar, the floating button or the "?" key.
// It only reads and writes one localStorage flag per user (never directory data).

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, Keyboard, Lightbulb, ListOrdered, MoonStar, X } from "lucide-react";
import { useSession } from "../services/session";
import { cx } from "./ui";

interface Step {
  id: string;
  /** Page the step explains. The guide opens that page and highlights it in the sidebar. */
  route?: string;
  title: string;
  intro: string;
  points?: ReactNode[];
  tip?: ReactNode;
}

const Key = ({ children }: { children: ReactNode }) => (
  <kbd className="rounded border border-border bg-surface-3 px-1.5 py-0.5 font-mono text-[11px] text-text">{children}</kbd>
);
const B = ({ children }: { children: ReactNode }) => <strong className="font-semibold text-text">{children}</strong>;

const HOW_TO_CALL: ReactNode[] = [
  <>Click <B>Nekron · Help</B> at the bottom of the left sidebar.</>,
  <>Click the round <B>moon button</B> in the bottom-right corner of any page.</>,
  <>Press the <Key>?</Key> key anywhere (when you are not typing in a box).</>,
];

export const STEPS: Step[] = [
  {
    id: "welcome",
    title: "Hi, I'm Nekron, your AEGIS guide",
    intro:
      "AEGIS shows how an ordinary account in Active Directory could end up with domain-admin power by chaining " +
      "permissions together, and the smallest changes that stop it. I'll walk you through every page. It takes about three minutes.",
    points: [
      <>Use <B>Next</B> and <B>Back</B>, or the <Key>→</Key> and <Key>←</Key> arrow keys.</>,
      <>Click <B>Skip</B> or press <Key>Esc</Key> to close me at any time. Nothing breaks.</>,
      <>Want me back later? {HOW_TO_CALL.length} ways: the sidebar <B>Nekron · Help</B> link, the <B>moon button</B> bottom-right, or the <Key>?</Key> key.</>,
    ],
  },
  {
    id: "workflow",
    title: "How AEGIS works, in 5 steps",
    intro: "Every assessment follows the same flow. Keep it in mind and the rest of the app makes sense.",
    points: [
      <><B>1. Import</B> data collected from a domain (SharpHound / BloodHound files).</>,
      <><B>2. Analyse</B> it. AEGIS finds every route to the most powerful accounts.</>,
      <><B>3. Explore</B> the attack paths and why each one exists.</>,
      <><B>4. Fix</B>: try changes in the simulator before touching anything real.</>,
      <><B>5. Report</B>: export a PDF, HTML or JSON report.</>,
    ],
    tip: (
      <>Words you will see: a <B>snapshot</B> is one data collection at a point in time. <B>Tier-0</B> means the most
      powerful accounts and servers, such as Domain Admins and domain controllers. An <B>attack path</B> is a chain of permissions
      leading to tier-0.</>
    ),
  },
  {
    id: "selection",
    route: "/",
    title: "The bar at the top: what you are looking at",
    intro: "The Snapshot and Analysis menus at the top decide which data every page shows.",
    points: [
      <><B>Snapshot</B>: pick which data collection to look at.</>,
      <><B>Analysis</B>: pick which analysis run of that snapshot to show (the newest is chosen for you).</>,
      <>A yellow <B>sample data</B> tag means it is made-up practice data, safe to play with.</>,
      <><B>Refresh</B> (far right) reloads the menus after new imports.</>,
    ],
  },
  {
    id: "overview",
    route: "/",
    title: "Overview: the dashboard",
    intro: "Start here. It summarises how exposed the domain is.",
    points: [
      <>The top cards count <B>identities</B>, <B>privileged accounts</B> and <B>attack paths</B>. Red numbers need attention first.</>,
      <><B>Environment risk</B> is a 0 to 100 score for the whole domain. Higher is worse.</>,
      <><B>Paths by severity</B> shows how many paths are Critical, High, Medium or Low.</>,
      <>Scroll down for the <B>highest-risk attack paths</B>. Click one to open it.</>,
    ],
  },
  {
    id: "imports",
    route: "/imports",
    title: "Data Imports: bring in your data",
    intro: "This is where a new assessment starts.",
    points: [
      <><B>Create snapshot</B>: give the collection a name, for example “ACME July 2026”.</>,
      <><B>Upload data</B>: choose the SharpHound / BloodHound CE ZIP or JSON files (CSV inventories work too).</>,
      <>When the import finishes, click <B>Run analysis</B>. The results appear on every page.</>,
    ],
    tip: <>Only collect data from domains you are <B>authorised</B> to assess. Viewers can look but not import. That needs the Analyst or Admin role.</>,
  },
  {
    id: "identities",
    route: "/identities",
    title: "Identity Explorer: look anyone up",
    intro: "Search for any user, group or computer and see what it is connected to.",
    points: [
      <>Type a name in the search box and press <B>Search</B>.</>,
      <>Select a result to see its <B>relationships</B> (memberships, permissions, logons).</>,
      <>The <B>Neighbourhood</B> graph draws those connections. Drag to move, scroll to zoom.</>,
    ],
  },
  {
    id: "paths",
    route: "/paths",
    title: "Attack Paths: the main findings",
    intro: "Every route from an ordinary identity to tier-0, ranked with the most dangerous first.",
    points: [
      <>Click a path to see it as a <B>graph</B>, with a plain-English <B>“How the path works”</B> explanation of each step.</>,
      <><B>Score breakdown</B> shows exactly why it got its score. No black box.</>,
      <><B>Load evidence</B> shows the raw records each step is based on.</>,
      <>After you confirm a path is real, use <B>Mark validated</B> and add a note.</>,
    ],
    tip: <>A path shows what the data <B>allows</B>. It is not proof that someone has already used it.</>,
  },
  {
    id: "risk",
    route: "/risk",
    title: "Risk Intelligence: where to fix first",
    intro: "This page turns many paths into a short list of fixes.",
    points: [
      <><B>Choke points</B>: single permissions that many paths rely on. Fixing one removes many paths.</>,
      <><B>Minimum cut</B>: the smallest set of changes that cuts <i>every</i> exposed identity off from tier-0.</>,
      <><B>Central objects</B> and <B>exposed tier-0 targets</B> show where the danger concentrates.</>,
    ],
  },
  {
    id: "simulator",
    route: "/simulator",
    title: "Remediation Simulator: try fixes safely",
    intro: "Ask “what if we changed this?” and see the result instantly. Nothing real is changed.",
    points: [
      <>Add changes to a scenario: remove a risky permission, <B>disable</B> an account, or clear its <B>sessions</B>.</>,
      <>Or click <B>Simulate minimum cut</B> to test the recommended fix in one go.</>,
      <>Click <B>Run scenario</B> to compare risk, paths and exposed identities before and after.</>,
    ],
    tip: <>Simulations never touch Active Directory or your stored data. Experiment freely.</>,
  },
  {
    id: "compare",
    route: "/compare",
    title: "Historical Comparison: is it getting better?",
    intro: "Compare two snapshots of the same domain, for example last month vs. this month.",
    points: [
      <>Pick the <B>older</B> and <B>newer</B> snapshot, then click <B>Compare</B>.</>,
      <>See new and removed accounts, <B>new attack paths</B>, and who is newly exposed or newly safe.</>,
      <>Renamed accounts are still matched correctly using their security IDs.</>,
    ],
  },
  {
    id: "reports",
    route: "/reports",
    title: "Reports: share the results",
    intro: "Produce a professional report for managers and the teams who will fix things.",
    points: [
      <>Tick the formats you need (<B>PDF</B>, <B>HTML</B>, <B>JSON</B>) and click <B>Generate</B>.</>,
      <>Optionally choose an earlier snapshot to include a “what changed” section.</>,
      <>Download finished reports from the <B>Generated reports</B> list.</>,
    ],
  },
  {
    id: "settings",
    route: "/settings",
    title: "Settings: users, your password and the risk model",
    intro: "Account and configuration options. What you see depends on your role.",
    points: [
      <><B>Your password</B>: change it here. Do this first if someone gave you a temporary one.</>,
      <><B>Users</B> (admins): add people as Viewer (read-only), Analyst (can import and analyse) or Admin.</>,
      <><B>Tier-0 & traversal</B> and <B>Risk model weights</B> tune the analysis. <B>Audit log</B> records who did what.</>,
    ],
  },
  {
    id: "health",
    route: "/health",
    title: "System Health: is AEGIS OK?",
    intro: "Shows memory, CPU, disk, running jobs and configured limits. It refreshes every 10 seconds.",
    points: [
      <>If an analysis is refused for low memory, check here and close heavy programs.</>,
      <>Warnings here (for example a missing secret key) tell you what to fix in the setup.</>,
    ],
  },
  {
    id: "call",
    title: "That's the tour! Here is how to call me back",
    intro: "Whenever you are unsure, call me. I open the help for the page you are on.",
    points: HOW_TO_CALL,
    tip: <>Good first move: open <B>Attack Paths</B> on the sample data and click the top path.</>,
  },
];

const PAGE_STEP: Record<string, string> = {
  "/": "overview", "/imports": "imports", "/identities": "identities", "/paths": "paths", "/risk": "risk",
  "/simulator": "simulator", "/compare": "compare", "/reports": "reports", "/settings": "settings", "/health": "health",
};

interface NekronState {
  /** Opens the guide: at a given step, or at the help for the current page (welcome on first use). */
  open: (stepId?: string) => void;
  /** Route of the page the current step explains (the sidebar highlights it). */
  highlight: string | null;
}
const NekronContext = createContext<NekronState>({ open: () => {}, highlight: null });
export const useNekron = () => useContext(NekronContext);

const seenKey = (username: string) => `aegis.nekron.seen.v1:${username}`;
const isTyping = (t: EventTarget | null) =>
  t instanceof HTMLElement && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName));

export function NekronProvider({ children }: { children: ReactNode }) {
  const { user } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [index, setIndex] = useState<number | null>(null);
  const [showContents, setShowContents] = useState(false);

  const close = useCallback(() => {
    if (user) localStorage.setItem(seenKey(user.username), "1");
    setIndex(null);
    setShowContents(false);
  }, [user]);

  const go = useCallback((i: number) => {
    const step = STEPS[Math.max(0, Math.min(STEPS.length - 1, i))]!;
    setIndex(STEPS.indexOf(step));
    setShowContents(false);
    if (step.route && step.route !== location.pathname) navigate(step.route);
  }, [location.pathname, navigate]);

  const open = useCallback((stepId?: string) => {
    const seen = user ? localStorage.getItem(seenKey(user.username)) === "1" : false;
    const id = stepId ?? (seen ? PAGE_STEP[location.pathname] ?? "welcome" : "welcome");
    go(Math.max(0, STEPS.findIndex((s) => s.id === id)));
  }, [go, location.pathname, user]);

  // First visit of each user: say hello automatically.
  useEffect(() => {
    if (user && localStorage.getItem(seenKey(user.username)) !== "1") setIndex(0);
  }, [user]);

  // Keyboard: "?" opens; Esc closes; arrows move between steps.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e.target) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (index === null) {
        if (e.key === "?") { e.preventDefault(); open(); }
        return;
      }
      if (e.key === "Escape") close();
      else if (e.key === "ArrowRight") { if (index < STEPS.length - 1) go(index + 1); else close(); }
      else if (e.key === "ArrowLeft" && index > 0) go(index - 1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [index, open, close, go]);

  const step = index === null ? null : STEPS[index]!;
  const value = useMemo(() => ({ open, highlight: step?.route ?? null }), [open, step]);
  return (
    <NekronContext.Provider value={value}>
      {children}
      {step && index !== null
        ? <Panel step={step} index={index} go={go} close={close} showContents={showContents} setShowContents={setShowContents} />
        : <Launcher onClick={() => open()} />}
    </NekronContext.Provider>
  );
}

function Avatar({ size = "h-9 w-9" }: { size?: string }) {
  return (
    <div className={cx("grid shrink-0 place-items-center rounded-full bg-gradient-to-br from-accent to-accent-2 text-white shadow-lg shadow-accent/30", size)}>
      <MoonStar className="h-1/2 w-1/2" />
    </div>
  );
}

function Launcher({ onClick }: { onClick: () => void }) {
  return (
    <button onClick={onClick} title="Ask Nekron for help (press ?)" aria-label="Open Nekron, the help guide"
      className="group fixed bottom-5 right-5 z-40 flex items-center gap-2 rounded-full border border-border bg-surface-2 py-1.5 pl-1.5 pr-4 text-sm text-text shadow-xl transition hover:border-accent/60 hover:bg-surface-3">
      <Avatar size="h-8 w-8" />
      <span>Ask Nekron</span>
    </button>
  );
}

function Panel({ step, index, go, close, showContents, setShowContents }: {
  step: Step; index: number; go: (i: number) => void; close: () => void;
  showContents: boolean; setShowContents: (v: boolean) => void;
}) {
  const last = index === STEPS.length - 1;
  const first = index === 0;
  const nextRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { nextRef.current?.focus(); }, [index]);

  // The welcome is centred over a dimmed page. The page steps dock bottom-right so the page itself stays visible.
  const centred = first;
  return (
    <>
      {centred && <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[2px]" onClick={close} />}
      <div role="dialog" aria-modal={centred} aria-labelledby="nekron-title"
        className={cx("fixed z-50 flex max-h-[calc(100vh-2.5rem)] w-[26rem] max-w-[calc(100vw-2.5rem)] flex-col rounded-xl border border-border bg-surface-1 shadow-2xl shadow-black/60",
          centred ? "left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2" : "bottom-5 right-5")}>
        <header className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Avatar />
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold text-text">Nekron</div>
            <div className="text-[11px] text-muted">Your AEGIS guide · step {index + 1} of {STEPS.length}</div>
          </div>
          <button onClick={() => setShowContents(!showContents)} title="Jump to a topic" aria-label="Show all topics"
            className={cx("rounded p-1.5 hover:bg-surface-3 hover:text-text", showContents ? "bg-surface-3 text-text" : "text-muted")}>
            <ListOrdered className="h-4 w-4" />
          </button>
          <button onClick={close} title="Close (Esc)" aria-label="Close Nekron" className="rounded p-1.5 text-muted hover:bg-surface-3 hover:text-text">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="h-1 bg-surface-3">
          <div className="h-1 bg-gradient-to-r from-accent to-accent-2 transition-all" style={{ width: `${((index + 1) / STEPS.length) * 100}%` }} />
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 text-sm leading-relaxed text-muted">
          {showContents ? (
            <ol className="space-y-0.5">
              {STEPS.map((s, i) => (
                <li key={s.id}>
                  <button onClick={() => go(i)}
                    className={cx("flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-surface-2",
                      i === index ? "bg-surface-3 text-text" : "text-muted")}>
                    <span className="w-5 text-right text-xs tabular-nums">{i + 1}</span>{s.title}
                  </button>
                </li>
              ))}
            </ol>
          ) : (
            <>
              <h2 id="nekron-title" className="mb-2 text-base font-semibold text-text">{step.title}</h2>
              <p>{step.intro}</p>
              {step.points && (
                <ul className="mt-3 space-y-2">
                  {step.points.map((p, i) => (
                    <li key={i} className="flex gap-2"><ChevronRight className="mt-1 h-3.5 w-3.5 shrink-0 text-accent-2" /><span>{p}</span></li>
                  ))}
                </ul>
              )}
              {step.tip && (
                <div className="mt-4 flex gap-2 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2.5 text-[13px]">
                  <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-accent-2" /><div>{step.tip}</div>
                </div>
              )}
              {step.route && (
                <p className="mt-4 text-[11px]">You are on this page now. Its sidebar entry is highlighted on the left.</p>
              )}
            </>
          )}
        </div>

        <footer className="flex items-center gap-2 border-t border-border px-4 py-3">
          {!last && <button onClick={close} className="text-xs text-muted hover:text-text">Skip tour</button>}
          <span className="hidden items-center gap-1 text-[11px] text-muted sm:flex"><Keyboard className="h-3 w-3" />← →</span>
          <div className="ml-auto flex gap-2">
            {!first && (
              <button onClick={() => go(index - 1)} className="flex items-center gap-1 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text hover:bg-surface-3">
                <ChevronLeft className="h-3.5 w-3.5" />Back
              </button>
            )}
            <button ref={nextRef} onClick={() => (last ? close() : go(index + 1))}
              className="flex items-center gap-1 rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:bg-accent/90">
              {first ? "Start the tour" : last ? "Got it, finish" : "Next"}{!last && <ChevronRight className="h-3.5 w-3.5" />}
            </button>
          </div>
        </footer>
      </div>
    </>
  );
}
