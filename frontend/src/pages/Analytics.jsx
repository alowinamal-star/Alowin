import { BarChart3, Gauge, Languages, RefreshCw, ShieldAlert, Target } from "lucide-react";
import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, pretty } from "../api";
import { Badge, Card, ErrorNotice, KeyValue, LoadingBlock, Meter, SectionHeading, StatCard } from "../components/ui";
import { useAsync } from "../hooks";

const BAND_COLOR = { low: "#34d399", medium: "#f59e0b", high: "#fb7185", critical: "#f43f5e" };
const SERIES = ["#22d3ee", "#818cf8", "#a855f7", "#f59e0b", "#34d399", "#fb7185"];

function pct(value) {
  const number = Number(value ?? 0);
  return `${(number * 100).toFixed(1)}%`;
}

export default function Analytics() {
  const [days, setDays] = useState(14);
  const query = useAsync(() => api.analytics(days), [days]);

  const data = query.data;
  const stats = data?.statistics;
  const run = data?.latest_evaluation;
  const hybrid = run?.overall;
  const baseline = run?.keyword_baseline_overall;
  const distribution = (data?.score_distribution || []).map((bucket) => ({ ...bucket, label: pretty(bucket.band) }));
  const activity = (stats?.activity || []).map((point) => ({ ...point, label: (point.date || "").slice(5) }));
  const categories = (stats?.by_category || []).map((row) => ({ ...row, label: pretty(row.category) }));
  const languages = (stats?.by_language || []).map((row) => ({ ...row, label: String(row.language).toUpperCase() }));
  const sources = (stats?.by_source || []).map((row) => ({ ...row, label: pretty(row.source_type) }));

  if (query.loading && !data) return <LoadingBlock label="Computing analytics…" rows={5} />;
  if (query.error) return <ErrorNotice error={query.error} onRetry={query.reload} />;

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <SectionHeading
          icon={BarChart3}
          title="Security analytics"
          subtitle="Derived from stored scans, threats, firewall actions and evaluation runs."
          actions={
            <>
              <select className="select !w-auto !py-1.5 !text-xs" value={days} onChange={(event) => setDays(Number(event.target.value))}>
                <option value={7}>Last 7 days</option>
                <option value={14}>Last 14 days</option>
                <option value={30}>Last 30 days</option>
              </select>
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={query.reload}>
                <RefreshCw size={12} /> Refresh
              </button>
            </>
          }
        />
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Total scans" value={stats?.total_scans ?? 0} icon={Target} hint="All sources analysed" />
          <StatCard label="Detection rate" value={pct(stats?.detection_rate)} icon={ShieldAlert} tone="rose" hint="Attacks found / total scans" />
          <StatCard label="Block rate" value={pct(stats?.block_rate)} icon={Gauge} tone="amber" hint="Blocked or quarantined" />
          <StatCard label="Average risk" value={(stats?.average_risk_score ?? 0).toFixed?.(1) ?? stats?.average_risk_score ?? 0} icon={Gauge} tone="violet" hint="Mean score across scans" />
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="p-4">
          <SectionHeading title="Risk score distribution" subtitle="How analysed content falls across the four bands." />
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={distribution}>
                <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 10, fontSize: 12 }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {distribution.map((entry) => (
                    <Cell key={entry.band} fill={BAND_COLOR[entry.band] || "#22d3ee"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="p-4">
          <SectionHeading title="Scan volume" subtitle={`Daily submissions over the last ${days} days.`} />
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={activity}>
                <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 10, fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 11, color: "#94a3b8" }} />
                <Line type="monotone" dataKey="scans" name="Scans" stroke="#22d3ee" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="attacks" name="Attacks" stroke="#f43f5e" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="p-4">
          <SectionHeading title="Threat categories" subtitle="Detected categories across all scans." />
          {categories.length ? (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categories} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid stroke="rgba(148,163,184,0.12)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="label" width={130} tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 10, fontSize: 12 }} />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]} fill="#a855f7" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="py-10 text-center text-xs text-slate-500">No categories recorded yet.</p>
          )}
        </Card>

        <Card className="p-4">
          <SectionHeading icon={Languages} title="Language & source mix" subtitle="Multilingual detections and input channels." />
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={languages} dataKey="count" nameKey="label" innerRadius={34} outerRadius={58} paddingAngle={2}>
                    {languages.map((entry, index) => (
                      <Cell key={entry.label} fill={SERIES[index % SERIES.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 10, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sources} dataKey="count" nameKey="label" innerRadius={34} outerRadius={58} paddingAngle={2}>
                    {sources.map((entry, index) => (
                      <Cell key={entry.label} fill={SERIES[(index + 2) % SERIES.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 10, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {languages.map((row, index) => (
              <Badge key={`lang-${row.label}`} tone="purple">
                <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full" style={{ background: SERIES[index % SERIES.length] }} />
                {row.label} · {row.count}
              </Badge>
            ))}
            {sources.map((row, index) => (
              <Badge key={`src-${row.label}`} tone="info">
                <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full" style={{ background: SERIES[(index + 2) % SERIES.length] }} />
                {row.label} · {row.count}
              </Badge>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <Card className="p-4">
          <SectionHeading
            title="Latest evaluation"
            subtitle={run ? `${run.suites?.length ?? 0} suites · ${run.total_samples ?? hybrid?.samples ?? 0} test samples` : "No evaluation stored yet."}
          />
          {hybrid ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Metric label="Precision" value={hybrid.precision} />
                <Metric label="Recall" value={hybrid.recall} />
                <Metric label="F1" value={hybrid.f1} />
                <Metric label="False positive" value={hybrid.false_positive_rate} tone="rose" />
              </div>
              <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <p className="eyebrow">Hybrid vs keyword baseline</p>
                  <Badge tone="info">recall delta {pct(run?.delta?.recall ?? 0)}</Badge>
                </div>
                <table className="data-table !text-[11.5px]">
                  <thead>
                    <tr>
                      <th>Detector</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>F1</th>
                      <th>FPR</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td className="text-slate-200">Hybrid (rules + model)</td>
                      <td className="tabular-nums">{pct(hybrid.precision)}</td>
                      <td className="tabular-nums">{pct(hybrid.recall)}</td>
                      <td className="tabular-nums">{pct(hybrid.f1)}</td>
                      <td className="tabular-nums">{pct(hybrid.false_positive_rate)}</td>
                    </tr>
                    <tr>
                      <td className="text-slate-400">Keyword baseline</td>
                      <td className="tabular-nums">{pct(baseline?.precision)}</td>
                      <td className="tabular-nums">{pct(baseline?.recall)}</td>
                      <td className="tabular-nums">{pct(baseline?.f1)}</td>
                      <td className="tabular-nums">{pct(baseline?.false_positive_rate)}</td>
                    </tr>
                  </tbody>
                </table>
                <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
                  Measured on the reproducible held-out test split. These numbers describe this bundled dataset only — not a
                  universal detector benchmark.
                </p>
              </div>
            </div>
          ) : (
            <p className="py-8 text-center text-xs text-slate-500">Run the testing laboratory to generate an evaluation.</p>
          )}
        </Card>

        <Card className="p-4">
          <SectionHeading icon={Gauge} title="Detector & storage" subtitle="Runtime facts reported by the backend." />
          <KeyValue
            rows={[
              { label: "Model", value: data?.detector?.model?.available === false ? "rules only" : "hybrid rules + logistic regression" },
              { label: "Rules version", value: data?.detector?.rules_version || "—" },
              { label: "Storage", value: stats?.storage?.backend || stats?.storage?.backend_name || "—" },
              { label: "Documents", value: stats?.storage?.counts?.scans ?? stats?.total_scans ?? 0 },
              { label: "Firewall actions", value: stats?.firewall?.actions_evaluated ?? 0 },
              { label: "Pending approvals", value: stats?.firewall?.pending_approvals ?? 0 },
            ]}
          />
          <div className="mt-3 space-y-2">
            <Meter label="Blocked actions" value={stats?.firewall?.actions_blocked ?? 0} max={Math.max(1, stats?.firewall?.actions_evaluated ?? 1)} tone="rose" />
            <Meter label="Held for approval" value={stats?.firewall?.actions_held ?? 0} max={Math.max(1, stats?.firewall?.actions_evaluated ?? 1)} tone="amber" />
          </div>
        </Card>
      </div>
    </div>
  );
}

function Metric({ label, value, tone = "cyan" }) {
  const colors = { cyan: "text-cyan-300", rose: "text-rose-300", amber: "text-amber-300" };
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-2.5">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-lg font-semibold tabular-nums ${colors[tone] || colors.cyan}`}>{pct(value)}</p>
    </div>
  );
}
