import { ArrowRight, Lock, ShieldCheck, UserPlus } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { api, pretty } from "../api";
import { useAuth } from "../auth";
import { Card, ErrorNotice, Spinner } from "../components/ui";

export default function Login() {
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ email: "", password: "", name: "" });
  const [demo, setDemo] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .demoAccounts()
      .then((data) => {
        if (!active) return;
        const list = data?.accounts || data?.users || data?.demo_accounts || [];
        setDemo(Array.isArray(list) ? list : []);
      })
      .catch(() => setDemo([]));
    return () => {
      active = false;
    };
  }, []);

  const update = (key) => (event) => setForm((prev) => ({ ...prev, [key]: event.target.value }));

  async function submit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "login") {
        await login(form.email.trim(), form.password);
      } else {
        await register({ email: form.email.trim(), password: form.password, name: form.name.trim() });
      }
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function useDemo(account) {
    setMode("login");
    setError("");
    setForm({ email: account.email, password: account.password || "", name: "" });
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center px-4 py-10">
      <div className="pointer-events-none absolute inset-0 opacity-60">
        <div className="absolute left-[8%] top-[12%] h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute right-[10%] top-[22%] h-72 w-72 rounded-full bg-purple-600/10 blur-3xl" />
        <div className="absolute bottom-[8%] left-[38%] h-64 w-64 rounded-full bg-blue-600/10 blur-3xl" />
      </div>

      <div className="relative grid w-full max-w-5xl gap-8 lg:grid-cols-[1.05fr_1fr]">
        <div className="hidden flex-col justify-center lg:flex">
          <div className="mb-5 flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-2xl bg-gradient-to-br from-cyan-400 to-purple-600 text-navy-950 shadow-glow">
              <ShieldCheck size={22} strokeWidth={2.4} />
            </span>
            <div>
              <p className="text-lg font-bold tracking-tight text-slate-50">PromptShield AI</p>
              <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Injection Defense Platform</p>
            </div>
          </div>
          <h1 className="text-[30px] font-semibold leading-tight tracking-tight">
            <span className="title-grad">Stop untrusted content</span>
            <br />
            from controlling your AI.
          </h1>
          <p className="mt-4 max-w-md text-[13px] leading-relaxed text-slate-400">
            Context-aware detection of direct and indirect prompt injection across PDFs, emails, web pages and
            multilingual documents — with an independent firewall that validates every tool call the model attempts.
          </p>
          <ul className="mt-6 space-y-2.5 text-[12.5px] text-slate-400">
            {[
              "Hybrid rules + learned classifier, with English, Tamil and Hindi coverage",
              "Explainable evidence for every decision, not just a score",
              "Cross-document campaign analysis for distributed attacks",
              "Four-eyes approval for sensitive actions such as external email",
            ].map((item) => (
              <li key={item} className="flex items-start gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <Card className="p-6">
          <div className="mb-5 flex items-center gap-2">
            <button
              type="button"
              className={`btn flex-1 !py-2 !text-[12.5px] ${mode === "login" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setMode("login")}
            >
              <Lock size={14} /> Sign in
            </button>
            <button
              type="button"
              className={`btn flex-1 !py-2 !text-[12.5px] ${mode === "register" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setMode("register")}
            >
              <UserPlus size={14} /> Register
            </button>
          </div>

          <ErrorNotice error={error} className="mb-4" />

          <form onSubmit={submit} className="space-y-3.5">
            {mode === "register" ? (
              <div>
                <label className="label" htmlFor="name">
                  Full name
                </label>
                <input id="name" className="input" value={form.name} onChange={update("name")} placeholder="Security Analyst" required />
              </div>
            ) : null}
            <div>
              <label className="label" htmlFor="email">
                Work email
              </label>
              <input
                id="email"
                type="email"
                className="input"
                value={form.email}
                onChange={update("email")}
                placeholder="analyst@promptshield.ai"
                autoComplete="username"
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                className="input"
                value={form.password}
                onChange={update("password")}
                placeholder="••••••••••"
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                minLength={8}
                required
              />
            </div>
            <button type="submit" className="btn btn-primary w-full" disabled={busy}>
              {busy ? <Spinner size={14} /> : <ArrowRight size={15} />}
              {mode === "login" ? "Enter security console" : "Create analyst account"}
            </button>
          </form>

          <div className="mt-5 border-t border-white/10 pt-4">
            <p className="eyebrow mb-2">Demo accounts</p>
            {demo.length ? (
              <div className="space-y-1.5">
                {demo.map((account) => (
                  <button
                    key={account.email}
                    type="button"
                    onClick={() => useDemo(account)}
                    className="flex w-full items-center justify-between gap-3 rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-left text-[11.5px] transition hover:border-cyan-400/40 hover:bg-white/[0.06]"
                  >
                    <span className="min-w-0">
                      <span className="block truncate text-slate-200">{account.email}</span>
                      <span className="block text-[10px] text-slate-500">
                        {account.password ? `password: ${account.password}` : "seeded account"}
                      </span>
                    </span>
                    <span className="badge badge-info shrink-0">{pretty(account.role)}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-slate-500">Start the API to load seeded accounts.</p>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
