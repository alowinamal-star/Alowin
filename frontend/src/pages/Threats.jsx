import { AlertTriangle, Filter, RefreshCw, ShieldCheck, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import { api, formatDate, pretty } from "../api";
import {
  Badge,
  Card,
  DecisionBadge,
  EmptyState,
  ErrorNotice,
  EvidenceList,
  KeyValue,
  LoadingBlock,
  RiskBadge,
  RiskGauge,
  SectionHeading,
  Spinner,
} from "../components/ui";
import { useAsync, useNotice } from "../hooks";

const STATUSES = ["open", "reviewing", "mitigated", "dismissed"];

export default function Threats() {
  const [filters, setFilters] = useState({ risk_band: "", status: "", category: "" });
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [simulation, setSimulation] = useState(null);
  const [busy, setBusy] = useState(false);
  const { notice, success, error: noticeError, clear } = useNotice();

  const list = useAsync(() => api.threats({ limit: 100, ...filters }), [filters.risk_band, filters.status, filters.category]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return undefined;
    }
    let active = true;
    setDetailLoading(true);
    setSimulation(null);
    api
      .threat(selectedId)
      .then((data) => active && setDetail(data))
      .catch((err) => active && noticeError(err.message))
      .finally(() => active && setDetailLoading(false));
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  async function setStatus(status) {
    if (!detail) return;
    setBusy(true);
    try {
      const updated = await api.updateThreat(detail.id, { status, note: `Moved to ${status} from the analyst console.` });
      setDetail(updated);
      success(`Threat marked as ${status}.`);
      list.reload();
    } catch (err) {
      noticeError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function simulate() {
    if (!detail) return;
    setBusy(true);
    try {
      setSimulation(await api.simulateAiCall(detail.id));
    } catch (err) {
      noticeError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const threats = list.data?.threats || [];

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <SectionHeading
          icon={Filter}
          title="Threat queue"
          subtitle="Every scan with a security-relevant decision, newest first."
          actions={
            <>
              <select className="select !w-auto !py-1.5 !text-xs" value={filters.risk_band} onChange={(e) => setFilters((f) => ({ ...f, risk_band: e.target.value }))}>
                <option value="">All bands</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select className="select !w-auto !py-1.5 !text-xs" value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}>
                <option value="">All statuses</option>
                {STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {pretty(status)}
                  </option>
                ))}
              </select>
              <input
                className="input !w-40 !py-1.5 !text-xs"
                placeholder="category filter"
                value={filters.category}
                onChange={(e) => setFilters((f) => ({ ...f, category: e.target.value }))}
              />
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={list.reload}>
                <RefreshCw size={12} /> Refresh
              </button>
            </>
          }
        />

        {notice ? (
          <div className={`mb-3 rounded-lg border px-3 py-2 text-[12px] ${notice.type === "success" ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-200" : "border-rose-400/35 bg-rose-500/10 text-rose-200"}`}>
            <button type="button" onClick={clear} className="float-right text-current opacity-60">×</button>
            {notice.message}
          </div>
        ) : null}

        {list.loading && !threats.length ? (
          <LoadingBlock label="Loading threats…" />
        ) : list.error ? (
          <ErrorNotice error={list.error} onRetry={list.reload} />
        ) : threats.length ? (
          <div className="overflow-x-auto scroll-thin">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Risk</th>
                  <th>Decision</th>
                  <th>Status</th>
                  <th>Categories</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((threat) => (
                  <tr key={threat.id} onClick={() => setSelectedId(threat.id)} className={selectedId === threat.id ? "bg-cyan-400/[0.07]" : ""}>
                    <td className="max-w-[220px]">
                      <p className="truncate font-medium text-slate-200">{threat.source_name}</p>
                      <p className="text-[10.5px] text-slate-500">{pretty(threat.source_type)}</p>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <RiskBadge band={threat.risk_band} />
                        <span className="text-[11px] tabular-nums text-slate-400">{threat.risk_score}</span>
                      </div>
                    </td>
                    <td><DecisionBadge decision={threat.decision} label={threat.decision_label} /></td>
                    <td><Badge tone={threat.status === "open" ? "medium" : threat.status === "mitigated" ? "low" : "neutral"}>{pretty(threat.status || "open")}</Badge></td>
                    <td className="max-w-[220px]">
                      <div className="flex flex-wrap gap-1">
                        {(threat.threat_categories || []).slice(0, 3).map((category) => (
                          <Badge key={category} tone="purple">{pretty(category)}</Badge>
                        ))}
                        {(threat.threat_categories || []).length > 3 ? <Badge>+{threat.threat_categories.length - 3}</Badge> : null}
                      </div>
                    </td>
                    <td className="whitespace-nowrap text-[11.5px] text-slate-500">{formatDate(threat.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={AlertTriangle}
            title="No threats match these filters"
            message="Clear the filters or scan content to populate the queue."
          />
        )}
      </Card>

      {selectedId ? (
        <Card className="p-4">
          {detailLoading ? (
            <LoadingBlock label="Loading threat detail…" />
          ) : detail ? (
            <>
              <SectionHeading
                icon={ShieldCheck}
                title={detail.source_name}
                subtitle={`${pretty(detail.source_type)} · ${formatDate(detail.created_at)} · ${detail.id}`}
                actions={
                  <div className="flex flex-wrap items-center gap-1.5">
                    {STATUSES.map((status) => (
                      <button
                        key={status}
                        type="button"
                        disabled={busy || (detail.status || "open") === status}
                        className={`btn !py-1.5 !px-2.5 !text-[11px] ${(detail.status || "open") === status ? "btn-primary" : "btn-ghost"}`}
                        onClick={() => setStatus(status)}
                      >
                        {pretty(status)}
                      </button>
                    ))}
                    <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={simulate} disabled={busy}>
                      {busy ? <Spinner size={11} /> : <Zap size={11} />} Simulate tool call
                    </button>
                  </div>
                }
              />

              <div className="grid gap-4 lg:grid-cols-[auto_1fr]">
                <div className="flex items-center justify-center">
                  <RiskGauge score={detail.risk_score} band={detail.risk_band} />
                </div>
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <RiskBadge band={detail.risk_band} />
                    <DecisionBadge decision={detail.decision} label={detail.decision_label} />
                    <Badge tone="neutral">{pretty(detail.status || "open")}</Badge>
                  </div>
                  <p className="text-[12.5px] leading-relaxed text-slate-300">{detail.summary}</p>
                  <KeyValue
                    rows={[
                      { label: "Recommended action", value: detail.recommended_action },
                      { label: "Categories", value: (detail.threat_categories || []).map(pretty).join(", ") || "none" },
                      { label: "Languages", value: (detail.languages_detected || []).map((l) => String(l).toUpperCase()).join(", ") || "en" },
                      { label: "Actor", value: detail.actor || "system" },
                      { label: "Source type", value: pretty(detail.source_type) },
                      { label: "Batch", value: detail.batch_id || "—" },
                    ]}
                  />
                </div>
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div>
                  <p className="eyebrow mb-2">Evidence</p>
                  <EvidenceList evidence={detail.evidence} />
                </div>
                <div>
                  <p className="eyebrow mb-2">Sanitized content</p>
                  <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-black/35 p-3 text-[11px] leading-relaxed text-slate-300 scroll-thin">
                    {detail.sanitized_content || "(empty)"}
                  </pre>
                </div>
              </div>

              {simulation ? (
                <div className="mt-4 rounded-xl border border-white/10 bg-black/25 p-3">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <Badge tone="purple">{pretty(simulation.requested_action?.action_type)}</Badge>
                    <Badge tone={simulation.firewall?.decision === "block" ? "critical" : simulation.firewall?.decision === "allow" ? "low" : "high"}>
                      {pretty(simulation.firewall?.decision)}
                    </Badge>
                    <span className="text-[11px] text-slate-500">risk {simulation.firewall?.risk_level}</span>
                  </div>
                  <p className="text-[12px] text-slate-300">{simulation.firewall?.reason || simulation.firewall?.summary}</p>
                </div>
              ) : null}
            </>
          ) : (
            <EmptyState title="Threat unavailable" message="It may have been removed. Select another row." />
          )}
        </Card>
      ) : null}
    </div>
  );
}
