import { FileStack, Layers, Play, Plus, ShieldAlert, Trash2, UploadCloud } from "lucide-react";
import { useRef, useState } from "react";
import { api, formatDate, pretty } from "../api";
import {
  Badge,
  Card,
  ErrorNotice,
  KeyValue,
  LoadingBlock,
  Meter,
  RiskBadge,
  RiskGauge,
  SectionHeading,
  Spinner,
} from "../components/ui";
import { useNotice } from "../hooks";

export default function CrossDocument() {
  const [docs, setDocs] = useState([]); // {key, name, text, type, file, scan, error}
  const [label, setLabel] = useState("campaign-review");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [batch, setBatch] = useState(null);
  const [error, setError] = useState("");
  const [loadingSamples, setLoadingSamples] = useState(false);
  const inputRef = useRef(null);
  const { notice, success, error: noticeError, clear } = useNotice();

  function addFiles(files) {
    const next = Array.from(files || []).map((file, index) => ({
      key: `file-${Date.now()}-${index}`,
      name: file.name,
      file,
      type: "file",
      text: "",
      scan: null,
      error: "",
    }));
    setDocs((current) => [...current, ...next]);
  }

  function addDraft() {
    if (draft.trim().length < 20) {
      noticeError("Paste at least 20 characters of document text.");
      return;
    }
    setDocs((current) => [
      ...current,
      {
        key: `text-${Date.now()}`,
        name: `pasted-${current.length + 1}.txt`,
        text: draft,
        type: "text",
        file: null,
        scan: null,
        error: "",
      },
    ]);
    setDraft("");
  }

  async function loadSamples() {
    setLoadingSamples(true);
    try {
      const data = await api.samples();
      const chosen = (data?.samples || []).filter((sample) => ["C", "D", "B"].includes(sample.scenario));
      setDocs((current) => [
        ...current,
        ...chosen.map((sample) => ({
          key: `sample-${sample.id}`,
          name: sample.source_name || `${sample.id}.txt`,
          text: sample.content,
          type: "text",
          file: null,
          scan: null,
          error: "",
        })),
      ]);
      success(`Added ${chosen.length} demonstration documents.`);
    } catch (err) {
      noticeError(err.message);
    } finally {
      setLoadingSamples(false);
    }
  }

  async function scanAll() {
    setError("");
    setBatch(null);
    if (docs.length < 2) {
      setError("Add at least two documents before running cross-document analysis.");
      return;
    }
    setBusy(true);
    const scans = [];
    const updated = [...docs];
    for (let index = 0; index < updated.length; index += 1) {
      const doc = updated[index];
      try {
        const record =
          doc.type === "file"
            ? await api.scanFile(doc.file)
            : await api.scanText({ content: doc.text, source_name: doc.name, declared_type: "text", notes: "Cross-document batch" });
        updated[index] = { ...doc, scan: record, error: "" };
        scans.push(record);
      } catch (err) {
        updated[index] = { ...doc, scan: null, error: err.message };
      }
      setDocs([...updated]);
    }
    if (scans.length < 2) {
      setBusy(false);
      setError("At least two documents must scan successfully before the batch can be compared.");
      return;
    }
    try {
      const result = await api.analyzeMultiple({ scan_ids: scans.map((scan) => scan.id), label });
      setBatch(result);
      success(`Compared ${scans.length} documents.`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const scanned = docs.filter((doc) => doc.scan).length;

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <SectionHeading
          icon={FileStack}
          title="Build a document set"
          subtitle="Each document is scanned independently, then relationships between suspicious instructions are analysed."
          actions={
            <>
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={loadSamples} disabled={loadingSamples}>
                {loadingSamples ? <Spinner size={11} /> : <Layers size={12} />} Load demo set
              </button>
              <button type="button" className="btn btn-primary !py-1.5 !px-2.5 !text-[11px]" onClick={scanAll} disabled={busy || docs.length < 2}>
                {busy ? <Spinner size={11} /> : <Play size={12} />} Scan &amp; compare ({scanned}/{docs.length})
              </button>
            </>
          }
        />

        <ErrorNotice error={error} className="mb-3" />
        {notice ? (
          <div className={`mb-3 rounded-lg border px-3 py-2 text-[12px] ${notice.type === "success" ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-200" : "border-rose-400/35 bg-rose-500/10 text-rose-200"}`}>
            <button type="button" onClick={clear} className="float-right opacity-60">×</button>
            {notice.message}
          </div>
        ) : null}

        <div className="grid gap-3 lg:grid-cols-2">
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              addFiles(event.dataTransfer.files);
            }}
            className="cursor-pointer rounded-xl border border-dashed border-slate-600/50 bg-white/[0.02] p-4 text-center transition hover:border-cyan-400/40"
            role="button"
            tabIndex={0}
            onKeyDown={(event) => event.key === "Enter" && inputRef.current?.click()}
          >
            <input ref={inputRef} type="file" multiple accept=".pdf,.txt,.html,.htm,.eml,.md" className="hidden" onChange={(event) => addFiles(event.target.files)} />
            <UploadCloud size={20} className="mx-auto mb-2 text-cyan-300" />
            <p className="text-[12.5px] font-medium text-slate-200">Add multiple documents</p>
            <p className="mt-1 text-[11px] text-slate-500">PDF · TXT · HTML · EML · MD</p>
          </div>

          <div className="space-y-2">
            <textarea
              className="textarea !min-h-[86px] !text-[12px]"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder="…or paste one more document body here"
            />
            <div className="flex gap-2">
              <input className="input !py-1.5 !text-xs" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="batch label" />
              <button type="button" className="btn btn-ghost !py-1.5 !px-3 !text-[11px] whitespace-nowrap" onClick={addDraft}>
                <Plus size={12} /> Add text
              </button>
            </div>
          </div>
        </div>

        {docs.length ? (
          <div className="mt-3 space-y-1.5">
            {docs.map((doc, index) => (
              <div key={doc.key} className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2">
                <span className="mono w-5 text-[10px] text-slate-500">{index + 1}</span>
                <span className="min-w-0 flex-1 truncate text-[12px] text-slate-200">{doc.name}</span>
                {doc.error ? (
                  <Badge tone="critical">failed</Badge>
                ) : doc.scan ? (
                  <>
                    <RiskBadge band={doc.scan.risk_band} />
                    <span className="text-[11px] tabular-nums text-slate-400">{doc.scan.risk_score}</span>
                  </>
                ) : (
                  <Badge tone="neutral">not scanned</Badge>
                )}
                <button
                  type="button"
                  className="rounded p-1 text-slate-500 transition hover:bg-rose-500/10 hover:text-rose-300"
                  onClick={() => setDocs((current) => current.filter((item) => item.key !== doc.key))}
                  aria-label={`Remove ${doc.name}`}
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="mt-3 text-[11.5px] text-slate-500">
            Add at least two documents — or load the demo set, which contains two related attack documents and one benign
            look-alike so the correlation logic is visible.
          </p>
        )}
      </Card>

      {busy ? <Card className="p-4"><LoadingBlock label="Scanning documents and correlating findings…" /></Card> : null}

      {batch ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
          <Card className="p-4">
            <SectionHeading icon={ShieldAlert} title="Campaign assessment" subtitle={batch.summary} />
            <div className="flex flex-col items-center gap-3">
              <RiskGauge score={batch.campaign_risk} band={batch.requires_review ? "critical" : "low"} label="Campaign risk" />
              <Badge tone={batch.requires_review ? "critical" : "low"}>
                {batch.requires_review ? "Escalation required" : "No coordinated pattern"}
              </Badge>
            </div>
            <div className="mt-3 rounded-xl border border-white/10 bg-black/25 p-3 text-[12px] leading-relaxed text-slate-300">
              {batch.recommendation}
            </div>
            <div className="mt-3">
              <KeyValue
                rows={[
                  { label: "Batch", value: batch.id },
                  { label: "Label", value: batch.label || "untitled" },
                  { label: "Documents", value: `${batch.documents?.length ?? 0}` },
                  { label: "Relationships flagged", value: `${(batch.relationships || []).filter((rel) => rel.relationship !== "independent").length}` },
                  { label: "Clusters", value: `${(batch.clusters || []).length}` },
                  { label: "Created", value: formatDate(batch.created_at) },
                ]}
              />
            </div>
            {batch.shared_indicators && Object.keys(batch.shared_indicators).length ? (
              <div className="mt-3">
                <p className="eyebrow mb-2">Shared indicators</p>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(batch.shared_indicators).map(([kind, values]) =>
                    (values || []).map((value) => (
                      <Badge key={`${kind}-${value}`} tone="purple">
                        {pretty(kind)}: {value}
                      </Badge>
                    )),
                  )}
                </div>
              </div>
            ) : null}
          </Card>

          <div className="space-y-4">
            <Card className="p-4">
              <SectionHeading title="Per-document findings" subtitle="Each document scored independently before correlation." />
              <div className="space-y-2">
                {(batch.documents || []).map((doc) => (
                  <div key={doc.scan_id} className="rounded-lg border border-white/10 bg-white/[0.03] p-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-slate-200">{doc.source_name}</span>
                      <RiskBadge band={doc.risk_score >= 80 ? "critical" : doc.risk_score >= 60 ? "high" : doc.risk_score >= 30 ? "medium" : "low"} />
                      <span className="text-[11px] tabular-nums text-slate-400">{Math.round(doc.risk_score)}</span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {(doc.categories || []).map((category) => (
                        <Badge key={category} tone="purple">{pretty(category)}</Badge>
                      ))}
                      {(doc.languages || []).map((language) => (
                        <Badge key={language} tone="info">{String(language).toUpperCase()}</Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="p-4">
              <SectionHeading title="Relationships" subtitle="Similar wording alone is not treated as coordination." />
              <div className="space-y-2">
                {(batch.relationships || []).map((rel) => (
                  <div key={`${rel.document_a}-${rel.document_b}`} className="rounded-lg border border-white/10 bg-white/[0.03] p-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[11.5px] text-slate-300">{rel.source_a}</span>
                      <span className="text-slate-600">↔</span>
                      <span className="text-[11.5px] text-slate-300">{rel.source_b}</span>
                      <Badge tone={rel.relationship === "coordinated" ? "critical" : rel.relationship === "suspicious_overlap" ? "high" : "neutral"}>
                        {pretty(rel.relationship)}
                      </Badge>
                    </div>
                    <div className="mt-2">
                      <Meter value={Math.round((rel.score || 0) * 100)} label={`correlation ${Math.round((rel.score || 0) * 100)}%`} tone={rel.relationship === "coordinated" ? "rose" : "cyan"} />
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{rel.explanation}</p>
                    {rel.shared_rules?.length ? (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {rel.shared_rules.map((rule) => (
                          <Badge key={rule} tone="neutral">{rule}</Badge>
                        ))}
                      </div>
                    ) : null}
                  </div>
                ))}
                {!(batch.relationships || []).length ? (
                  <p className="py-6 text-center text-xs text-slate-500">No pairwise relationships were computed.</p>
                ) : null}
              </div>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
}
