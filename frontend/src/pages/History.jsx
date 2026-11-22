import { FileClock, RefreshCw, X } from "lucide-react";
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
  SectionHeading,
} from "../components/ui";
import { useAsync } from "../hooks";

const DECISIONS = ["", "allow", "flag", "quarantine", "block", "require_human_approval"];
const SOURCES = ["", "text", "pdf", "email", "url", "html"];

export default function History() {
  const [filters, setFilters] = useState({ source_type: "", decision: "" });
  const [openId, setOpenId] = useState(null);
  const [record, setRecord] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");

  const list = useAsync(() => api.history({ limit: 200, ...filters }), [filters.source_type, filters.decision]);

  useEffect(() => {
    if (!openId) {
      setRecord(null);
      return undefined;
    }
    let active = true;
    setDetailLoading(true);
    api
      .getScan(openId)
      .then((data) => active && setRecord(data))
      .catch((err) => active && setError(err.message))
      .finally(() => active && setDetailLoading(false));
    return () => {
      active = false;
    };
  }, [openId]);

  const rows = list.data?.history || [];

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <SectionHeading
          icon={FileClock}
          title="Attack history"
          subtitle="Immutable log of every analysed source with its final decision."
          actions={
            <>
              <select
                className="select !w-auto !py-1.5 !text-xs"
                value={filters.source_type}
                onChange={(event) => setFilters((f) => ({ ...f, source_type: event.target.value }))}
              >
                {SOURCES.map((source) => (
                  <option key={source || "all"} value={source}>
                    {source ? pretty(source) : "All sources"}
                  </option>
                ))}
              </select>
              <select
                className="select !w-auto !py-1.5 !text-xs"
                value={filters.decision}
                onChange={(event) => setFilters((f) => ({ ...f, decision: event.target.value }))}
              >
                {DECISIONS.map((decision) => (
                  <option key={decision || "all"} value={decision}>
                    {decision ? pretty(decision) : "All decisions"}
                  </option>
                ))}
              </select>
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={list.reload}>
                <RefreshCw size={12} /> Refresh
              </button>
            </>
          }
        />

        {list.loading && !rows.length ? (
          <LoadingBlock label="Loading history…" />
        ) : list.error ? (
          <ErrorNotice error={list.error} onRetry={list.reload} />
        ) : rows.length ? (
          <div className="overflow-x-auto scroll-thin">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Risk</th>
                  <th>Decision</th>
                  <th>Actor</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((scan) => (
                  <tr key={scan.id} onClick={() => setOpenId(scan.id)} className={openId === scan.id ? "bg-cyan-400/[0.07]" : ""}>
                    <td className="whitespace-nowrap text-[11.5px] text-slate-500">{formatDate(scan.created_at)}</td>
                    <td className="max-w-[240px]"><p className="truncate text-slate-200">{scan.source_name}</p></td>
                    <td><Badge tone="neutral">{pretty(scan.source_type)}</Badge></td>
                    <td>
                      <div className="flex items-center gap-2">
                        <RiskBadge band={scan.risk_band} />
                        <span className="text-[11px] tabular-nums text-slate-400">{scan.risk_score}</span>
                      </div>
                    </td>
                    <td><DecisionBadge decision={scan.decision} label={scan.decision_label} /></td>
                    <td className="text-[11.5px] text-slate-400">{scan.actor || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={FileClock} title="No scans recorded" message="Scanned content appears here with its decision and actor." />
        )}
      </Card>

      {openId ? (
        <Card className="p-4">
          <SectionHeading
            title="Scan detail"
            subtitle={record ? `${record.source_name} · ${formatDate(record.created_at)}` : "Loading…"}
            actions={
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={() => setOpenId(null)}>
                <X size={12} /> Close
              </button>
            }
          />
          {detailLoading ? (
            <LoadingBlock label="Loading scan…" />
          ) : error ? (
            <ErrorNotice error={error} />
          ) : record ? (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <RiskBadge band={record.risk_band} />
                  <DecisionBadge decision={record.decision} label={record.decision_label} />
                  <Badge tone="neutral">{pretty(record.source_type)}</Badge>
                </div>
                <p className="text-[12.5px] leading-relaxed text-slate-300">{record.summary}</p>
                <KeyValue
                  rows={[
                    { label: "Scan ID", value: record.id },
                    { label: "Score", value: `${record.risk_score} / 100` },
                    { label: "Categories", value: (record.threat_categories || []).map(pretty).join(", ") || "none" },
                    { label: "Recommended action", value: record.recommended_action },
                    { label: "Actor", value: record.actor || "system" },
                    { label: "Batch", value: record.batch_id || "—" },
                  ]}
                />
              </div>
              <div>
                <p className="eyebrow mb-2">Evidence</p>
                <EvidenceList evidence={record.evidence} />
              </div>
            </div>
          ) : null}
        </Card>
      ) : null}
    </div>
  );
}
