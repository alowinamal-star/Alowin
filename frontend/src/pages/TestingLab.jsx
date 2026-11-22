import { Beaker, FlaskConical, Gauge, Play, RefreshCw, Target, TrendingUp } from "lucide-react";
import { useState } from "react";
import { api, formatDate, pretty } from "../api";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  KeyValue,
  LoadingBlock,
  Meter,
  SectionHeading,
  Spinner,
} from "../components/ui";
import { useAsync, useNotice } from "../hooks";

const pct = (value) => `${((Number(value) || 0) * 100).toFixed(1)}%`;

function MetricRow({ label, hybrid, baseline }) {
  return (
    <div className="grid grid-cols-[1fr_auto_auto] items-center gap-2 border-b border-white/5 py-1.5 last:border-0">
      <span className="text-[11.5px] text-slate-400">{label}</span>
      <span className="w-16 text-right text-[11.5px] font-medium tabular-nums text-cyan-200">{pct(hybrid)}</span>
      <span className="w-16 text-right text-[11.5px] tabular-nums text-slate-500">{pct(baseline)}</span>
    </div>
  );
}

export default function TestingLab() {
  const dataset = useAsync(() => api.dataset(), []);
  const runs = useAsync(() => api.testingRuns(10), []);
  const { notice, success, error: noticeError, clear } = useNotice();

  const [mutate, setMutate] = useState(true);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  const data = dataset.data;
  const splits = data?.splits || {};

  async function run() {
    setBusy(true);
    setError("");
    setReport(null);
    try {
      const result = await api.runEvaluation({ subsets: ["all"], mutate, compare_baseline: true });
      setReport(result);
      runs.reload();
      success(`Evaluated ${result.overall?.samples ?? 0} samples across ${(result.suites || []).length} suites.`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const overall = report?.overall;
  const baseline = report?.keyword_baseline_overall;
  const delta = report?.delta;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
        <Card className="p-4">
          <SectionHeading
            icon={FlaskConical}
            title="Adaptive testing laboratory"
            subtitle="Runs the detector against the held-out split, multilingual samples, mutated wording and benign look-alikes."
          />
          <div className="space-y-2.5">
            <label className="flex cursor-pointer items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-2">
              <input type="checkbox" className="accent-cyan-400" checked={mutate} onChange={(event) => setMutate(event.target.checked)} />
              <span className="text-[11.5px] text-slate-300">Include obfuscation / paraphrase mutation suites</span>
            </label>
            <button type="button" className="btn btn-primary w-full" onClick={run} disabled={busy}>
              {busy ? <Spinner size={13} /> : <Play size={13} />} Run evaluation
            </button>
            <p className="text-[10.5px] leading-relaxed text-slate-500">
              This is an evaluation harness, not online learning: the model and rule weights are not updated by a run. Scores
              describe this repository&apos;s synthetic dataset only.
            </p>
          </div>

          <div className="mt-3 border-t border-white/10 pt-3">
            <p className="eyebrow mb-2">Bundled dataset</p>
            {dataset.loading && !data ? (
              <LoadingBlock label="Loading dataset summary…" />
            ) : dataset.error ? (
              <ErrorNotice error={dataset.error} onRetry={dataset.reload} />
            ) : (
              <>
                <KeyValue
                  rows={[
                    { label: "Total samples", value: data?.total ?? "—" },
                    { label: "Attack samples", value: data?.malicious ?? "—" },
                    { label: "Benign samples", value: data?.benign ?? "—" },
                    { label: "Families", value: data?.families ?? "—" },
                    { label: "License", value: data?.license || "Synthetic, repository-authored" },
                  ]}
                />
                <div className="mt-2 grid grid-cols-2 gap-1.5">
                  {Object.entries(splits).map(([name, split]) => (
                    <div key={name} className="rounded-lg border border-white/10 bg-white/[0.03] px-2 py-1.5">
                      <p className="text-[10px] uppercase tracking-wider text-slate-500">{pretty(name)}</p>
                      <p className="text-[12.5px] font-medium tabular-nums text-slate-200">
                        {typeof split === "object" ? split.count ?? split.total ?? JSON.stringify(split) : split}
                      </p>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </Card>

        <Card className="p-4">
          <SectionHeading
            icon={Target}
            title="Latest results"
            subtitle="Hybrid detector vs. a plain keyword baseline on identical samples."
            actions={report ? <Badge tone="info">{report.actor}</Badge> : null}
          />
          <ErrorNotice error={error} />
          {notice ? (
            <div className={`mb-2 rounded-lg border px-3 py-2 text-[11.5px] ${notice.type === "success" ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-200" : "border-rose-400/35 bg-rose-500/10 text-rose-200"}`}>
              <button type="button" onClick={clear} className="float-right opacity-60">×</button>
              {notice.message}
            </div>
          ) : null}

          {busy ? (
            <LoadingBlock label="Evaluating suites…" />
          ) : overall ? (
            <>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {[
                  { label: "Precision", value: overall.precision, hint: delta?.precision },
                  { label: "Recall", value: overall.recall, hint: delta?.recall },
                  { label: "F1", value: overall.f1 },
                  { label: "Accuracy", value: overall.accuracy },
                ].map((metric) => (
                  <div key={metric.label} className="rounded-xl border border-white/10 bg-white/[0.03] p-2 text-center">
                    <p className="text-[16px] font-semibold tabular-nums text-slate-100">{pct(metric.value)}</p>
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">{metric.label}</p>
                    {typeof metric.hint === "number" ? (
                      <p className={`mt-0.5 text-[10px] tabular-nums ${metric.hint >= 0 ? "text-emerald-300" : "text-rose-300"}`}>
                        {metric.hint >= 0 ? "+" : ""}{(metric.hint * 100).toFixed(1)} vs baseline
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>

              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-2.5">
                  <p className="eyebrow mb-1">Error rates</p>
                  <MetricRow label="False positive rate" hybrid={overall.false_positive_rate} baseline={baseline?.false_positive_rate} />
                  <MetricRow label="False negative rate" hybrid={overall.false_negative_rate} baseline={baseline?.false_negative_rate} />
                  <MetricRow label="Samples scored" hybrid={1} baseline={1} />
                </div>
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-2.5">
                  <p className="eyebrow mb-1">Confusion matrix</p>
                  <div className="grid grid-cols-2 gap-1.5 text-center">
                    {[
                      ["TP", overall.tp],
                      ["FP", overall.fp],
                      ["FN", overall.fn],
                      ["TN", overall.tn],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded border border-white/5 bg-black/25 py-1">
                        <p className="text-[12px] font-semibold tabular-nums text-slate-200">{value}</p>
                        <p className="text-[9.5px] uppercase tracking-wider text-slate-500">{label}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-3 overflow-auto scroll-thin">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Suite</th>
                      <th>n</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>FPR</th>
                      <th>Baseline recall</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(report.suites || []).map((suite) => (
                      <tr key={suite.suite} className="!cursor-default">
                        <td className="whitespace-nowrap text-[11.5px] text-slate-300">{pretty(suite.suite)}</td>
                        <td className="text-[11px] tabular-nums text-slate-500">{suite.hybrid?.samples}</td>
                        <td className="text-[11px] tabular-nums text-cyan-200">{pct(suite.hybrid?.precision)}</td>
                        <td className="text-[11px] tabular-nums text-cyan-200">{pct(suite.hybrid?.recall)}</td>
                        <td className="text-[11px] tabular-nums text-slate-400">{pct(suite.hybrid?.false_positive_rate)}</td>
                        <td className="text-[11px] tabular-nums text-slate-500">{pct(suite.keyword_baseline?.recall)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {(report.suites || []).some((suite) => (suite.failures || []).length) ? (
                <div className="mt-3">
                  <p className="eyebrow mb-1.5">Misclassified samples</p>
                  <div className="max-h-48 space-y-1 overflow-auto scroll-thin">
                    {(report.suites || []).flatMap((suite) => (suite.failures || []).map((failure) => ({ ...failure, suite: suite.suite }))).slice(0, 20).map((failure, index) => (
                      <div key={`${failure.sample_id}-${index}`} className="rounded border border-white/10 bg-white/[0.02] px-2 py-1.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Badge tone={failure.expected === "malicious" ? "critical" : "low"}>{failure.expected}</Badge>
                          <span className="text-slate-600">→</span>
                          <Badge tone="neutral">{failure.predicted}</Badge>
                          <span className="mono text-[10px] text-slate-500">{failure.family}</span>
                          <span className="ml-auto text-[10px] tabular-nums text-slate-500">{Math.round(failure.score)}</span>
                        </div>
                        <p className="mt-1 truncate text-[10.5px] text-slate-500">{failure.excerpt}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              <p className="mt-3 rounded-lg border border-white/10 bg-black/25 p-2 text-[10.5px] leading-relaxed text-slate-400">{report.notes}</p>
            </>
          ) : (
            <EmptyState
              icon={Beaker}
              title="No evaluation loaded"
              message="Run an evaluation to score the detector, or open a previous run below. Results are measured on the bundled dataset, not production traffic."
            />
          )}
        </Card>
      </div>

      <Card className="p-4">
        <SectionHeading
          icon={Gauge}
          title="Evaluation history"
          subtitle="Stored runs with their aggregate metrics."
          actions={
            <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={runs.reload}>
              <RefreshCw size={11} /> Refresh
            </button>
          }
        />
        {runs.loading && !(runs.data?.runs || []).length ? (
          <LoadingBlock label="Loading runs…" />
        ) : runs.error ? (
          <ErrorNotice error={runs.error} onRetry={runs.reload} />
        ) : (runs.data?.runs || []).length ? (
          <div className="overflow-auto scroll-thin">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Run</th>
                  <th>When</th>
                  <th>n</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th>Actor</th>
                </tr>
              </thead>
              <tbody>
                {(runs.data?.runs || []).map((run) => (
                  <tr key={run.id} onClick={() => setReport(run)}>
                    <td className="mono text-[10.5px] text-slate-400">{run.id?.slice(0, 10)}</td>
                    <td className="whitespace-nowrap text-[11px] text-slate-500">{formatDate(run.created_at)}</td>
                    <td className="text-[11px] tabular-nums text-slate-400">{run.overall?.samples}</td>
                    <td className="text-[11px] tabular-nums text-cyan-200">{pct(run.overall?.precision)}</td>
                    <td className="text-[11px] tabular-nums text-cyan-200">{pct(run.overall?.recall)}</td>
                    <td className="text-[11px] tabular-nums text-slate-300">{pct(run.overall?.f1)}</td>
                    <td className="text-[11px] text-slate-500">{run.actor}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={Gauge} title="No stored runs" message="Run the laboratory once to record a baseline evaluation." />
        )}
      </Card>
    </div>
  );
}
