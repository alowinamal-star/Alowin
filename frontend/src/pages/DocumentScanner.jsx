import { FileUp, FileText, Sparkles, UploadCloud } from "lucide-react";
import { useRef, useState } from "react";
import { api } from "../api";
import ScanResult from "../components/ScanResult";
import { Badge, Card, ErrorNotice, SectionHeading, Spinner } from "../components/ui";

const ACCEPT = ".pdf,.txt,.html,.htm,.eml,.md";

export default function DocumentScanner() {
  const [tab, setTab] = useState("upload");
  const [file, setFile] = useState(null);
  const [text, setText] = useState("");
  const [declared, setDeclared] = useState("text");
  const [sourceName, setSourceName] = useState("");
  const [result, setResult] = useState(null);
  const [aiResult, setAiResult] = useState(null);
  const [simulation, setSimulation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [samples, setSamples] = useState([]);
  const inputRef = useRef(null);

  async function loadSamples() {
    if (samples.length) return;
    try {
      const data = await api.samples();
      setSamples((data?.samples || []).filter((s) => s.kind !== "email"));
    } catch {
      setSamples([]);
    }
  }

  function pickFile(next) {
    if (!next) return;
    setFile(next);
    setSourceName(next.name);
    setError("");
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    setAiResult(null);
    setSimulation(null);
    try {
      const record =
        tab === "upload"
          ? await api.scanFile(file)
          : await api.scanText({
              content: text,
              source_name: sourceName || (declared === "html" ? "pasted.html" : "pasted-text.txt"),
              declared_type: declared,
              notes: "Submitted from the document scanner",
            });
      setResult(record);
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  async function runAi() {
    if (!result) return;
    setBusy(true);
    setError("");
    try {
      setAiResult(await api.aiProcess(result.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function runSimulation() {
    if (!result) return;
    setBusy(true);
    setError("");
    try {
      setSimulation(await api.simulateAiCall(result.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const ready = tab === "upload" ? Boolean(file) : text.trim().length >= 10;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
      <div className="space-y-4">
        <Card className="p-4">
          <SectionHeading icon={UploadCloud} title="Submit content" subtitle="Everything is treated as untrusted input." />

          <div className="mb-3 flex gap-2">
            <button type="button" className={`btn flex-1 !py-2 !text-xs ${tab === "upload" ? "btn-primary" : "btn-ghost"}`} onClick={() => setTab("upload")}>
              <FileUp size={13} /> Upload file
            </button>
            <button type="button" className={`btn flex-1 !py-2 !text-xs ${tab === "paste" ? "btn-primary" : "btn-ghost"}`} onClick={() => setTab("paste")}>
              <FileText size={13} /> Paste text
            </button>
          </div>

          <ErrorNotice error={error} className="mb-3" />

          <form onSubmit={submit} className="space-y-3">
            {tab === "upload" ? (
              <div
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault();
                  setDragging(false);
                  pickFile(event.dataTransfer.files?.[0]);
                }}
                onClick={() => inputRef.current?.click()}
                className={`cursor-pointer rounded-xl border border-dashed p-6 text-center transition ${
                  dragging ? "border-cyan-400/70 bg-cyan-400/[0.08]" : "border-slate-600/50 bg-white/[0.02] hover:border-cyan-400/40"
                }`}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => event.key === "Enter" && inputRef.current?.click()}
              >
                <input
                  ref={inputRef}
                  type="file"
                  accept={ACCEPT}
                  className="hidden"
                  onChange={(event) => pickFile(event.target.files?.[0])}
                />
                <UploadCloud size={22} className="mx-auto mb-2 text-cyan-300" />
                <p className="text-[13px] font-medium text-slate-200">{file ? file.name : "Drop a document or click to browse"}</p>
                <p className="mt-1 text-[11px] text-slate-500">PDF · TXT · HTML · EML · MD — max 10 MB</p>
                {file ? <p className="mt-2 text-[11px] text-cyan-300">{(file.size / 1024).toFixed(1)} KB selected</p> : null}
              </div>
            ) : (
              <>
                <div>
                  <label className="label" htmlFor="doc-text">
                    Content
                  </label>
                  <textarea
                    id="doc-text"
                    className="textarea"
                    value={text}
                    onChange={(event) => setText(event.target.value)}
                    placeholder="Paste document text or raw HTML here…"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="label" htmlFor="declared">
                      Declared type
                    </label>
                    <select id="declared" className="select" value={declared} onChange={(event) => setDeclared(event.target.value)}>
                      <option value="text">Plain text</option>
                      <option value="html">HTML</option>
                    </select>
                  </div>
                  <div>
                    <label className="label" htmlFor="source-name">
                      Source name
                    </label>
                    <input
                      id="source-name"
                      className="input"
                      value={sourceName}
                      onChange={(event) => setSourceName(event.target.value)}
                      placeholder="report.txt"
                    />
                  </div>
                </div>
              </>
            )}

            <button type="submit" className="btn btn-primary w-full" disabled={busy || !ready}>
              {busy ? <Spinner size={14} /> : <Sparkles size={14} />} Analyse document
            </button>
          </form>
        </Card>

        <Card className="p-4">
          <SectionHeading
            title="Demo samples"
            subtitle="Bundled scenario payloads pushed through the real pipeline."
            actions={
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={loadSamples}>
                Load
              </button>
            }
          />
          {samples.length ? (
            <div className="space-y-1.5">
              {samples.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => {
                    setTab("paste");
                    setText(sample.content);
                    setSourceName(sample.source_name);
                    setDeclared(sample.kind === "html" ? "html" : "text");
                  }}
                  className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-left transition hover:border-cyan-400/40 hover:bg-white/[0.06]"
                >
                  <span className="flex items-center gap-2">
                    <Badge tone="info">Scenario {sample.scenario}</Badge>
                    <span className="truncate text-[11.5px] text-slate-200">{sample.label}</span>
                  </span>
                  <span className="mt-1 block text-[10.5px] text-slate-500">{sample.expected}</span>
                </button>
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-slate-500">Load the bundled samples to populate the editor.</p>
          )}
        </Card>
      </div>

      <div>
        {result ? (
          <ScanResult
            result={result}
            busy={busy}
            aiResult={aiResult}
            simulation={simulation}
            onAiProcess={runAi}
            onSimulate={runSimulation}
          />
        ) : (
          <Card className="grid min-h-[420px] place-items-center p-8 text-center">
            <div>
              <span className="mx-auto mb-3 grid h-12 w-12 place-items-center rounded-2xl border border-cyan-400/25 bg-cyan-400/10 text-cyan-300">
                <FileText size={20} />
              </span>
              <p className="text-sm font-medium text-slate-200">No document analysed yet</p>
              <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-slate-500">
                Upload a file or paste text to see the risk score, evidence spans, security decision and the untrusted
                envelope that would be handed to the model.
              </p>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
