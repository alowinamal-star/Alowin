import {
  AlertTriangle,
  BarChart3,
  FileSearch,
  Firewall as FirewallIcon,
  FlaskConical,
  History as HistoryIcon,
  LayoutDashboard,
  Layers,
  Link2,
  LogOut,
  Mail,
  Menu,
  Settings as SettingsIcon,
  ShieldCheck,
  X,
} from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { useAuth } from "../auth";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/scanner/document", label: "Document Scanner", icon: FileSearch },
  { to: "/scanner/email", label: "Email Scanner", icon: Mail },
  { to: "/scanner/url", label: "URL Scanner", icon: Link2 },
  { to: "/threats", label: "Threat Analysis", icon: AlertTriangle },
  { to: "/history", label: "Attack History", icon: HistoryIcon },
  { to: "/analytics", label: "Security Analytics", icon: BarChart3 },
  { to: "/cross-document", label: "Cross-Document", icon: Layers },
  { to: "/firewall", label: "Firewall & Actions", icon: FirewallIcon },
  { to: "/testing", label: "Testing Laboratory", icon: FlaskConical },
  { to: "/settings", label: "User Settings", icon: SettingsIcon },
];

const TITLES = {
  "/": ["Security Operations Dashboard", "Live posture across every scanned source"],
  "/scanner/document": ["Document Scanner", "Upload a PDF, TXT, HTML or EML file for extraction and analysis"],
  "/scanner/email": ["Email Scanner", "Analyse raw messages including headers and hidden content"],
  "/scanner/url": ["URL Scanner", "Fetch a public page (SSRF-guarded) and inspect visible and hidden text"],
  "/threats": ["Threat Analysis", "Explainable evidence, risk scoring and analyst workflow"],
  "/history": ["Attack History", "Every scan with its decision, score and actor"],
  "/analytics": ["Security Analytics", "Trends, score distribution and detector quality"],
  "/cross-document": ["Cross-Document Analysis", "Detect coordinated instructions spread across documents"],
  "/firewall": ["Firewall & Action Control", "Independent validation of every AI tool call"],
  "/testing": ["Adaptive Testing Laboratory", "Measure the detector against held-out suites and a keyword baseline"],
  "/settings": ["User Settings", "Account, runtime information and audit trail"],
};

export default function Layout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [title, subtitle] = TITLES[location.pathname] || ["PromptShield AI", "AI security operations"];

  const roleTone =
    user?.role === "admin"
      ? "badge-purple"
      : user?.role === "analyst"
        ? "badge-info"
        : user?.role === "viewer"
          ? "badge-neutral"
          : "badge-medium";

  return (
    <div className="flex min-h-screen">
      {/* sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-[248px] shrink-0 border-r border-white/10 bg-navy-950/85 px-3 py-4 backdrop-blur-xl transition-transform lg:static lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
        style={{ background: "linear-gradient(180deg, rgba(9,14,28,0.96), rgba(4,7,15,0.98))" }}
      >
        <div className="mb-5 flex items-center justify-between px-2">
          <div className="flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-cyan-400 to-purple-600 text-navy-950 shadow-glow">
              <ShieldCheck size={19} strokeWidth={2.4} />
            </span>
            <div>
              <p className="text-[13.5px] font-bold leading-tight tracking-tight text-slate-50">PromptShield AI</p>
              <p className="text-[10px] uppercase tracking-[0.14em] text-slate-500">Injection Defense</p>
            </div>
          </div>
          <button type="button" className="text-slate-400 lg:hidden" onClick={() => setOpen(false)} aria-label="Close navigation">
            <X size={18} />
          </button>
        </div>

        <nav className="space-y-0.5">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setOpen(false)}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
            >
              <item.icon size={16} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="mt-6 rounded-xl border border-white/10 bg-white/[0.03] p-3">
          <p className="text-[10px] uppercase tracking-[0.14em] text-slate-500">Defense pipeline</p>
          <ol className="mt-2 space-y-1 text-[11px] text-slate-400">
            <li>1 · Extract untrusted content</li>
            <li>2 · Detect &amp; score contextually</li>
            <li>3 · Isolate / quarantine</li>
            <li>4 · Validate every tool call</li>
          </ol>
        </div>
      </aside>

      {open ? (
        <button type="button" aria-label="Close navigation overlay" className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setOpen(false)} />
      ) : null}

      {/* main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b border-white/10 bg-navy-950/70 px-4 py-3 backdrop-blur-xl sm:px-6">
          <div className="flex items-center gap-3">
            <button type="button" className="btn btn-ghost !px-2.5 !py-2 lg:hidden" onClick={() => setOpen(true)} aria-label="Open navigation">
              <Menu size={16} />
            </button>
            <div className="min-w-0 flex-1">
              <h1 className="truncate text-[15px] font-semibold tracking-tight text-slate-100">{title}</h1>
              <p className="truncate text-[11.5px] text-slate-500">{subtitle}</p>
            </div>
            <div className="flex items-center gap-2.5">
              <div className="hidden text-right sm:block">
                <p className="text-[12.5px] font-medium leading-tight text-slate-200">{user?.name || user?.email || "Operator"}</p>
                <p className="text-[10.5px] text-slate-500">{user?.email}</p>
              </div>
              <span className={`badge ${roleTone}`}>{user?.role || "guest"}</span>
              <button type="button" className="btn btn-ghost !px-2.5 !py-2" onClick={logout} title="Sign out" aria-label="Sign out">
                <LogOut size={15} />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 px-4 py-5 sm:px-6 sm:py-6">
          <div className="mx-auto w-full max-w-[1320px] animate-fade-up">
            <Outlet />
          </div>
        </main>

        <footer className="border-t border-white/5 px-4 py-3 text-[10.5px] text-slate-600 sm:px-6">
          PromptShield AI · risk scores are application-specific heuristics, not a certified security standard · untrusted content never controls tool execution
        </footer>
      </div>
    </div>
  );
}
