import { Activity, AlertOctagon, Ban, FileCheck2, Gauge, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { Link } from "react-router";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, formatDate, pretty } from "../api";
import { Badge, Card, DecisionBadge, EmptyState, ErrorNotice, LoadingBlock, Meter, RiskBadge, SectionHeading, StatCard } from "../components/ui";
import { useAsync } from "../hooks";

const tooltipStyle = {
  background: "#0b1222",
  border: "1px solid rgba(148,163,184,0.22)",
  borderRadius: 12,
  fontSize: 12,
  color: "#e2e8f0",
};

const PIE_COLORS = ["#22d3ee", "#3b82f6", "#a855f7", "#f59e0b", "#34d399"];

export default function Dashboard() {
  const { data, loading, error, reload } = useAsync(() => api.statistics(), []);

  if (loading && !data) return <LoadingBlock label="Loading security posture…" rows={4} />;
  if (error) return <ErrorNotice error={error} onRetry={reload} />;
  if (!data) return <EmptyState title="No statistics available" message="Scan content to populate the dashboard." />;

  const firewall = data.firewall || {};
  const activity = data.activity || [];
  const categories = (data.by_category || []).slice(0, 6);
  const sources = data.by_source || [];
  const recent = data.recent_activity || [];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="low">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Pipeline online
          </Badge>
          <Badge tone="neutral">storage: {data.storage?.backend || data.storage?.backend_name || "connected"}</Badge>
          <Badge tone="info">{data.total_scans} scans analysed</Badge>
        </div>
        <button type="button" className="btn btn-ghost !py-2 !text-xs" onClick={reload}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <StatCard label="Files scanned" value={data.total_scans} icon={FileCheck2} tone="cyan" hint="All sources, all time" />
        <StatCard label="Attacks detected" value={data.attacks_detected} icon={ShieldAlert} tone="amber" hint="Content with injection signals" />
        <StatCard label="Attacks blocked" value={data.attacks_blocked} icon={Ban} tone="danger" hint={`Block rate ${data.block_rate}%`} />
        <StatCard label="Safe documents" value={data.safe_documents} icon={ShieldCheck} tone="emerald" hint="Allowed as untrusted data" />
        <StatCard label="Critical alerts" value={data.critical_alerts} icon={AlertOctagon} tone="purple" hint={`${data.open_threats} open in queue`} />
        <StatCard label="Detection rate" value={`${data.detection_rate}%`} icon={Gauge} tone="blue" hint={`Avg risk ${data.average_risk_score}`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.6fr_1fr]">
        <Card className="p-4">
          <SectionHeading
            icon={Activity}
            title="14-day activity"
            subtitle="Scans, threats and blocks recorded by the detection pipeline."
            actions={<Badge tone="neutral">real scan data</Badge>}
          />
          <div className="h-[230px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activity} margin={{ top: 4, right: 6, left: -22, bottom: 0 }}>
                <defs>
                  <linearGradient id="scansGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#f43f5e" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
                <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(v) => String(v).slice(5)} />
                <YAxis tick={{ fill: "#64748b", fontSize: 10 }} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "#94a3b8" }} />
                <Area type="monotone" dataKey="scans" stroke="#22d3ee" strokeWidth={2} fill="url(#scansGrad)" name="Scans" />
                <Area type="monotone" dataKey="threats" stroke="#f43f5e" strokeWidth={2} fill="url(#threatsGrad)" name="Threats" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="p-4">
          <SectionHeading icon={ShieldCheck} title="Firewall posture" subtitle="Independent validation of AI tool calls." />
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2.5">
              <div className="panel-sunken p-2.5">
                <p className="eyebrow">Evaluated</p>
                <p className="text-xl font-semibold text-slate-50 tabular-nums">{firewall.actions_evaluated ?? 0}</p>
              </div>
              <div className="panel-sunken p-2.5">
                <p className="eyebrow">Blocked</p>
                <p className="text-xl font-semibold text-rose-300 tabular-nums">{firewall.actions_blocked ?? 0}</p>
              </div>
              <div className="panel-sunken p-2.5">
                <p className="eyebrow">Held for approval</p>
                <p className="text-xl font-semibold text-amber-300 tabular-nums">{firewall.actions_held ?? 0}</p>
              </div>
              <div className="panel-sunken p-2.5">
                <p className="eyebrow">Pending</p>
                <p className="text-xl font-semibold text-cyan-300 tabular-nums">{firewall.pending_approvals ?? 0}</p>
              </div>
            </div>
            <Meter label="Block rate on detected attacks" value={data.block_rate} tone="danger" />
            <Meter label="Detection rate" value={data.detection_rate} tone="cyan" />
            <Link to="/firewall" className="btn btn-ghost w-full !py-2 !text-xs">
              Open firewall console
            </Link>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="p-4">
          <SectionHeading title="Threat categories" subtitle="Most frequent detections." />
          {categories.length ? (
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categories} layout="vertical" margin={{ top: 0, right: 8, left: 4, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#64748b", fontSize: 10 }} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="category"
                    width={104}
                    tick={{ fill: "#94a3b8", fontSize: 10 }}
                    tickFormatter={(v) => pretty(v)}
                  />
                  <Tooltip contentStyle={tooltipStyle} formatter={(value) => [value, "Detections"]} />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]} fill="#a855f7" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState title="No categories yet" message="Detections will be grouped here by attack technique." />
          )}
        </Card>

        <Card className="p-4">
          <SectionHeading title="Source mix" subtitle="Where untrusted content arrives from." />
          {sources.length ? (
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sources} dataKey="count" nameKey="source_type" innerRadius={44} outerRadius={70} paddingAngle={3} stroke="none">
                    {sources.map((entry, index) => (
                      <Cell key={entry.source_type} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} formatter={(value, name) => [value, pretty(name)]} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState title="No sources yet" message="Upload or paste content to populate this chart." />
          )}
          <div className="mt-1 flex flex-wrap gap-1.5">
            {sources.map((entry, index) => (
              <span key={entry.source_type} className="flex items-center gap-1.5 text-[10.5px] text-slate-400">
                <span className="h-2 w-2 rounded-full" style={{ background: PIE_COLORS[index % PIE_COLORS.length] }} />
                {pretty(entry.source_type)} · {entry.count}
              </span>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <SectionHeading title="Language coverage" subtitle="Detected source languages." />
          <div className="space-y-3">
            {(data.by_language || []).map((entry) => (
              <div key={entry.language}>
                <div className="mb-1 flex items-center justify-between text-[11.5px]">
                  <span className="text-slate-300">{pretty(entry.language)}</span>
                  <span className="tabular-nums text-slate-500">{entry.count}</span>
                </div>
                <Meter value={entry.count} max={data.total_scans || 1} tone="cyan" />
              </div>
            ))}
            {!(data.by_language || []).length ? (
              <p className="text-xs text-slate-500">No language signals recorded yet.</p>
            ) : null}
            <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.06] p-2.5 text-[11px] leading-relaxed text-cyan-200/85">
              Multilingual rules cover English, Tamil and Hindi, including mixed-language content in a single document.
            </div>
          </div>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="p-4 pb-0">
          <SectionHeading
            title="Recent security activity"
            subtitle="Latest scans with their decision and risk band."
            actions={<Link to="/history" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]">View all</Link>}
          />
        </div>
        {recent.length ? (
          <div className="overflow-x-auto scroll-thin">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Risk</th>
                  <th>Decision</th>
                  <th>Summary</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((row) => (
                  <tr key={row.id}>
                    <td className="max-w-[220px] truncate font-medium text-slate-200">{row.source_name}</td>
                    <td><Badge tone="neutral">{pretty(row.source_type)}</Badge></td>
                    <td>
                      <div className="flex items-center gap-2">
                        <RiskBadge band={row.risk_band} />
                        <span className="text-[11px] tabular-nums text-slate-400">{row.risk_score}</span>
                      </div>
                    </td>
                    <td><DecisionBadge decision={row.decision} label={row.decision_label} /></td>
                    <td className="max-w-[320px] truncate text-[12px] text-slate-400">{row.summary}</td>
                    <td className="whitespace-nowrap text-[11.5px] text-slate-500">{formatDate(row.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-4">
            <EmptyState
              title="No scans recorded yet"
              message="Open a scanner to analyse your first document, email or URL."
              action={<Link to="/scanner/document" className="btn btn-primary !py-2 !text-xs">Scan a document</Link>}
            />
          </div>
        )}
      </Card>

      <p className="text-[11px] leading-relaxed text-slate-500">{data.score_disclaimer}</p>
    </div>
  );
}
