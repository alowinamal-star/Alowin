import { AlertTriangle, CheckCircle2, Copy, Info, Loader2, RefreshCw, ShieldAlert, X } from "lucide-react";
import { useState } from "react";
import { RISK_BADGE, decisionClass, pretty } from "../api";

export function Card({ className = "", children, hover = false, ...rest }) {
  return (
    <div className={`card ${hover ? "card-hover" : ""} ${className}`} {...rest}>
      {children}
    </div>
  );
}

export function SectionHeading({ title, subtitle, actions, icon: Icon }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
      <div className="flex items-start gap-3">
        {Icon ? (
          <span className="mt-0.5 grid h-9 w-9 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-400/10 text-cyan-300">
            <Icon size={17} />
          </span>
        ) : null}
        <div>
          <h2 className="text-[15px] font-semibold tracking-tight text-slate-100">{title}</h2>
          {subtitle ? <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-slate-400">{subtitle}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function StatCard({ label, value, hint, icon: Icon, tone = "cyan", loading = false }) {
  const tones = {
    cyan: "from-cyan-400/18 to-transparent text-cyan-300 border-cyan-400/25",
    blue: "from-blue-500/18 to-transparent text-blue-300 border-blue-400/25",
    purple: "from-purple-500/18 to-transparent text-purple-300 border-purple-400/25",
    danger: "from-rose-500/18 to-transparent text-rose-300 border-rose-400/25",
    amber: "from-amber-500/18 to-transparent text-amber-300 border-amber-400/25",
    emerald: "from-emerald-500/18 to-transparent text-emerald-300 border-emerald-400/25",
  };
  return (
    <Card className="relative overflow-hidden p-4" hover>
      <div className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${tones[tone] || tones.cyan} opacity-70`} />
      <div className="relative flex items-start justify-between gap-3">
        <div>
          <p className="eyebrow">{label}</p>
          {loading ? (
            <div className="skeleton mt-2 h-7 w-16" />
          ) : (
            <p className="mt-1.5 text-2xl font-semibold tracking-tight text-slate-50 tabular-nums">{value}</p>
          )}
          {hint ? <p className="mt-1 text-[11px] text-slate-400">{hint}</p> : null}
        </div>
        {Icon ? (
          <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl border bg-white/5 ${tones[tone] || tones.cyan}`}>
            <Icon size={16} />
          </span>
        ) : null}
      </div>
    </Card>
  );
}

export function Badge({ children, tone = "neutral", className = "" }) {
  const map = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
    info: "badge-info",
    purple: "badge-purple",
    neutral: "badge-neutral",
  };
  return <span className={`badge ${map[tone] || map.neutral} ${className}`}>{children}</span>;
}

export function RiskBadge({ band }) {
  if (!band) return <Badge>Unknown</Badge>;
  return <span className={`badge ${RISK_BADGE[band] || "badge-neutral"}`}>{band} risk</span>;
}

export function DecisionBadge({ decision, label }) {
  return <span className={`badge ${decisionClass(decision)}`}>{label || pretty(decision)}</span>;
}

export function Spinner({ size = 16, className = "" }) {
  return <Loader2 size={size} className={`animate-spin ${className}`} />;
}

export function LoadingBlock({ label = "Loading…", rows = 3 }) {
  return (
    <div className="space-y-3" role="status" aria-live="polite">
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Spinner /> {label}
      </div>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton h-12 w-full" />
      ))}
    </div>
  );
}

export function ErrorNotice({ error, onRetry, className = "" }) {
  if (!error) return null;
  return (
    <div className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border border-rose-400/35 bg-rose-500/10 px-3.5 py-2.5 text-sm text-rose-200 ${className}`} role="alert">
      <span className="flex items-center gap-2">
        <ShieldAlert size={15} /> {error}
      </span>
      {onRetry ? (
        <button type="button" className="btn btn-ghost !py-1.5 !px-3 !text-xs" onClick={onRetry}>
          <RefreshCw size={13} /> Retry
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ icon: Icon = Info, title, message, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-slate-600/40 bg-white/[0.015] px-6 py-12 text-center">
      <span className="grid h-11 w-11 place-items-center rounded-2xl border border-slate-600/40 bg-white/5 text-slate-400">
        <Icon size={19} />
      </span>
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {message ? <p className="max-w-md text-xs leading-relaxed text-slate-400">{message}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function Notice({ notice, onClose }) {
  if (!notice) return null;
  const ok = notice.type === "success";
  return (
    <div
      className={`mb-4 flex items-start justify-between gap-3 rounded-xl border px-3.5 py-2.5 text-sm ${
        ok ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-200" : "border-rose-400/35 bg-rose-500/10 text-rose-200"
      }`}
      role={ok ? "status" : "alert"}
    >
      <span className="flex items-center gap-2">
        {ok ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />} {notice.message}
      </span>
      {onClose ? (
        <button type="button" onClick={onClose} aria-label="Dismiss" className="text-current opacity-60 hover:opacity-100">
          <X size={14} />
        </button>
      ) : null}
    </div>
  );
}

/** Circular 0-100 risk gauge (application-specific score, not a security standard). */
export function RiskGauge({ score = 0, band = "low", size = 132, label = "Risk score" }) {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, Number(score) || 0));
  const dash = (clamped / 100) * circumference;
  const color =
    band === "critical" ? "#f43f5e" : band === "high" ? "#fb923c" : band === "medium" ? "#fbbf24" : "#34d399";
  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="rgba(148,163,184,0.16)" strokeWidth="9" fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth="9"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
      </svg>
      <div className="-mt-[calc(50%+6px)] mb-[calc(50%-18px)] flex flex-col items-center">
        <span className="text-2xl font-semibold tabular-nums text-slate-50">{Math.round(clamped)}</span>
        <span className="text-[10px] uppercase tracking-[0.16em] text-slate-400">{label}</span>
      </div>
    </div>
  );
}

export function Meter({ value = 0, max = 100, tone = "cyan", label }) {
  const pct = max ? Math.min(100, Math.round((Number(value) / max) * 100)) : 0;
  const colors = { cyan: "bg-cyan-400", blue: "bg-blue-500", purple: "bg-purple-500", danger: "bg-rose-500", emerald: "bg-emerald-400", amber: "bg-amber-400" };
  return (
    <div>
      {label ? (
        <div className="mb-1 flex items-center justify-between text-[11px] text-slate-400">
          <span>{label}</span>
          <span className="tabular-nums">{pct}%</span>
        </div>
      ) : null}
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
        <div className={`h-full rounded-full ${colors[tone] || colors.cyan}`} style={{ width: `${pct}%`, transition: "width .5s ease" }} />
      </div>
    </div>
  );
}

export function EvidenceList({ evidence = [] }) {
  if (!evidence.length) return <p className="text-xs text-slate-500">No specific evidence spans recorded.</p>;
  return (
    <ul className="space-y-2">
      {evidence.map((item, index) => (
        <li key={item.id || index} className="rounded-xl border border-white/10 bg-black/25 p-3">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <Badge tone="info">{pretty(item.category)}</Badge>
            <span className="mono text-[10.5px] text-slate-500">
              {item.pattern_id || item.rule_id || "pattern"} · {(item.language || "en").toUpperCase()}
            </span>
            {item.score ? <span className="ml-auto text-[10.5px] text-slate-400">weight {item.score}</span> : null}
          </div>
          <p className="mono text-[12px] leading-relaxed text-slate-300">
            “<span className="evidence-mark">{item.text || item.snippet || ""}</span>”
          </p>
          {item.reason ? <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-400">{item.reason}</p> : null}
          {item.context_note ? <p className="mt-1 text-[11px] italic text-slate-500">{item.context_note}</p> : null}
        </li>
      ))}
    </ul>
  );
}

export function CopyButton({ value, label = "Copy" }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(String(value ?? ""));
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        } catch {
          setCopied(false);
        }
      }}
    >
      <Copy size={12} /> {copied ? "Copied" : label}
    </button>
  );
}

export function KeyValue({ rows = [] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2.5 sm:grid-cols-2">
      {rows.filter(Boolean).map((row) => (
        <div key={row.label} className="flex items-baseline justify-between gap-3 border-b border-white/5 pb-1.5">
          <dt className="text-[11px] uppercase tracking-[0.1em] text-slate-500">{row.label}</dt>
          <dd className="text-right text-[12.5px] text-slate-200">{row.value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
