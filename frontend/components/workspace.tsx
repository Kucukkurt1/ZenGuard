"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { FileUp, LoaderCircle, Trash2 } from "lucide-react";
import { ApiError, deleteAnalysis, listAnalyses, rescanAnalysis, startAnalysis, uploadAnalysis, type AnalysisSummary } from "@/lib/api";
import { formatBytes, formatWhen, shortHash } from "@/lib/format";
import { bandLabel, isTerminal, threatTone } from "@/lib/score";
import { AppShell } from "@/components/app-shell";
import { Inspector } from "@/components/inspector";
import { ScanDialog, type ScanJob } from "@/components/scan-dialog";
import { StatusBadge } from "@/components/status-badge";
import { useHealth } from "@/components/use-health";

const BAR: Record<string, string> = {
  safe: "bg-emerald-500",
  watch: "bg-amber-500",
  threat: "bg-rose-500",
  pending: "bg-slate-200",
};

function isClean(item: AnalysisSummary) {
  if (item.status === "rejected" || item.status === "failed") return false;
  if (item.risk_band === "clean" || item.risk_band === "low") return true;
  return item.risk_score !== null && item.risk_score <= 29;
}

function isThreat(item: AnalysisSummary) {
  if (item.status === "rejected") return true;
  if (item.risk_band === "high" || item.risk_band === "critical") return true;
  return item.risk_score !== null && item.risk_score >= 70;
}

export function Workspace({
  initialId = null,
  crumb = ["Analiz Merkezi", "Yeni Tarama"],
}: {
  initialId?: string | null;
  crumb?: string[];
}) {
  const { health } = useHealth();
  const [items, setItems] = useState<AnalysisSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [listError, setListError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(initialId);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [scanJob, setScanJob] = useState<ScanJob | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    setSelectedId(initialId);
  }, [initialId]);

  useEffect(() => {
    let cancelled = false;

    async function pull() {
      try {
        const page = await listAnalyses({ limit: 50 });
        if (cancelled) return;
        setItems(page.items);
        setTotal(page.total);
        setListError(null);
      } catch (err) {
        if (cancelled) return;
        setListError(err instanceof ApiError ? err.message : "Liste alınamadı.");
      }
    }

    pull();
    const timer = window.setInterval(pull, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter(
      (item) =>
        item.original_filename.toLowerCase().includes(needle) ||
        item.sha256.toLowerCase().includes(needle),
    );
  }, [items, query]);

  const clean = items.filter(isClean).length;
  const threats = items.filter(isThreat).length;
  const engines = health?.clamav === "ok" ? "ClamAV + YARA + Sandbox" : "YARA + Sandbox · ClamAV down";

  const selected = items.find((item) => item.id === selectedId) ?? null;
  const selectedCanRun = selected !== null && selected.status === "queued";

  async function refreshList() {
    const page = await listAnalyses({ limit: 50 });
    setItems(page.items);
    setTotal(page.total);
  }

  function openScan(filename: string, size: number, id: string | null = null) {
    setScanError(null);
    setScanJob({
      key: Date.now(),
      id,
      filename,
      size,
    });
  }

  async function send(next: File, forceRescan = false) {
    setBusy(true);
    setUploadError(null);
    openScan(next.name, next.size);
    try {
      const created = await uploadAnalysis(next, forceRescan);
      setSelectedId(created.id);
      setFile(null);
      setScanJob((current) =>
        current
          ? {
              ...current,
              id: created.id,
              filename: created.original_filename,
              size: created.size_bytes,
            }
          : current,
      );
      if (created.status === "queued") {
        await startAnalysis(created.id);
      }
      await refreshList();
    } catch (err) {
      const message =
        err instanceof ApiError && err.status === 413
          ? "Dosya 50 MiB yükleme sınırını aşıyor."
          : err instanceof ApiError
            ? err.message
            : "Yükleme tamamlanamadı.";
      setUploadError(message);
      setScanError(message);
    } finally {
      setBusy(false);
    }
  }

  async function runSelected() {
    if (!selectedCanRun || !selected) return;
    setBusy(true);
    setUploadError(null);
    openScan(selected.original_filename, selected.size_bytes, selected.id);
    try {
      await startAnalysis(selected.id);
      await refreshList();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Tarama başlatılamadı.";
      setUploadError(message);
      setScanError(message);
    } finally {
      setBusy(false);
    }
  }

  const selectedCanRescan = selected !== null && isTerminal(selected.status);

  async function rescanSelected() {
    if (!selectedCanRescan || !selected) return;
    setBusy(true);
    setUploadError(null);
    openScan(selected.original_filename, selected.size_bytes);
    try {
      const created = await rescanAnalysis(selected.id);
      setSelectedId(created.id);
      setScanJob((current) =>
        current
          ? {
              ...current,
              id: created.id,
              filename: created.original_filename,
              size: created.size_bytes,
            }
          : current,
      );
      await refreshList();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Yeniden tarama başlatılamadı.";
      setUploadError(message);
      setScanError(message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(item: AnalysisSummary) {
    if (item.status === "running" || deletingId) return;
    setDeletingId(item.id);
    setUploadError(null);
    try {
      await deleteAnalysis(item.id);
      if (selectedId === item.id) setSelectedId(null);
      if (scanJob?.id === item.id) setScanJob(null);
      await refreshList();
    } catch (err) {
      setUploadError(err instanceof ApiError ? err.message : "Kayıt silinemedi.");
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <AppShell
      crumb={crumb}
      search={query}
      onSearch={setQuery}
      uploading={busy}
      onQuickUpload={(next) => void send(next, false)}
    >
      <div className="flex h-full min-h-0">
        <section className="flex min-w-0 flex-1 flex-col">
          <div className="zg-panel zg-line zg-muted flex h-9 shrink-0 items-center gap-3 border-b px-4 font-mono text-[11px]">
            <span>Toplam {total}</span>
            <span className="text-emerald-700/60">|</span>
            <span className="text-emerald-400">Temiz {clean}</span>
            <span className="text-emerald-700/60">|</span>
            <span className="text-rose-400">Tehdit {threats}</span>
            <span className="text-emerald-700/60">|</span>
            <span>Motorlar {engines}</span>
          </div>

          <label
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              const next = event.dataTransfer.files?.[0];
              if (next) setFile(next);
            }}
            className={`zg-glow mx-4 mt-3 flex cursor-pointer items-center gap-3 rounded-lg border border-dashed px-3 py-2.5 ${
              dragging ? "border-emerald-300" : "border-emerald-800/50"
            }`}
          >
            <FileUp className="h-4 w-4 shrink-0 text-emerald-400" />
            <span className="zg-muted min-w-0 flex-1 text-sm">
              {file ? (
                <span className="zg-title font-medium">
                  {file.name}{" "}
                  <span className="zg-hash font-mono text-xs">{formatBytes(file.size)}</span>
                </span>
              ) : (
                "Dosyayı bırakın veya seçin · 50 MiB"
              )}
            </span>
            <input
              type="file"
              className="sr-only"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
          </label>

          <div className="flex items-center justify-end gap-2 px-4 py-2">
            <button
              type="button"
              disabled={busy || !selectedCanRescan}
              onClick={() => void rescanSelected()}
              className="zg-muted inline-flex h-8 items-center rounded-md border border-emerald-800/40 px-3 text-xs font-semibold disabled:cursor-not-allowed disabled:opacity-40"
            >
              Yeniden tara
            </button>
            <button
              type="button"
              disabled={busy || (!file && !selectedCanRun)}
              onClick={() => {
                if (file) void send(file);
                else void runSelected();
              }}
              className="zg-btn inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-xs font-semibold shadow-sm disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : null}
              {busy ? "Başlatılıyor" : "Dosyayı Tara"}
            </button>
          </div>

          {uploadError ? (
            <p className="mx-4 mb-2 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-800">
              {uploadError}
            </p>
          ) : null}

          <div className="min-h-0 flex-1 overflow-auto px-4 pb-4">
            <div className="zg-panel overflow-hidden rounded-lg border border-emerald-800/50">
              <div className="zg-line flex h-9 items-center justify-between border-b px-3">
                <p className="zg-title text-xs font-semibold">Analiz kuyruğu</p>
                <p className="zg-faint font-mono text-[11px]">{visible.length} satır</p>
              </div>
              {listError ? (
                <p className="px-3 py-3 text-xs text-rose-700">{listError}</p>
              ) : null}
              {!listError && visible.length === 0 ? (
                <p className="zg-muted px-3 py-8 text-center text-sm">Kuyruk boş.</p>
              ) : null}
              {visible.length > 0 ? (
                <table className="w-full text-left text-xs">
                  <thead className="zg-thead text-[10px] uppercase tracking-[0.12em]">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Dosya</th>
                      <th className="px-3 py-2 font-semibold">SHA-256</th>
                      <th className="px-3 py-2 font-semibold">Motor</th>
                      <th className="px-3 py-2 font-semibold">Risk</th>
                      <th className="px-3 py-2 font-semibold">Tarih</th>
                      <th className="px-2 py-2 text-right font-semibold">Rapor</th>
                      <th className="w-10 px-2 py-2 font-semibold">
                        <span className="sr-only">Sil</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((item) => {
                      const tone = threatTone(item.risk_score);
                      const width = item.risk_score === null ? 0 : item.risk_score;
                      const selected = item.id === selectedId;
                      return (
                        <tr
                          key={item.id}
                          onClick={() => setSelectedId(item.id)}
                          className={`zg-row cursor-pointer border-t ${selected ? "zg-row-on" : ""}`}
                        >
                          <td className="max-w-[220px] px-3 py-2">
                            <span className="zg-title block truncate font-medium">
                              {item.original_filename}
                            </span>
                            <span className="zg-faint whitespace-nowrap font-mono text-[10px]">
                              {formatBytes(item.size_bytes)}
                            </span>
                          </td>
                          <td className="zg-hash px-3 py-2 font-mono text-[11px]" title={item.sha256}>
                            {shortHash(item.sha256)}
                          </td>
                          <td className="px-3 py-2">
                            <StatusBadge status={item.status} />
                          </td>
                          <td className="w-40 px-3 py-2">
                            {!isTerminal(item.status) ? (
                              <div>
                                <div className="mb-1 flex items-center justify-between font-mono text-[10px]">
                                  <span className="zg-muted truncate pr-2">
                                    {item.progress_stage || "Kuyrukta"}
                                  </span>
                                  <span className="zg-accent">{item.progress_percent ?? 5}%</span>
                                </div>
                                <div className="h-1.5 overflow-hidden rounded-sm bg-emerald-100">
                                  <div
                                    className="h-full bg-gradient-to-r from-emerald-500 to-teal-500 transition-all duration-500"
                                    style={{ width: `${item.progress_percent ?? 5}%` }}
                                  />
                                </div>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2">
                                <div className="h-1 flex-1 overflow-hidden rounded-sm bg-emerald-100">
                                  <div className={`h-full ${BAR[tone]}`} style={{ width: `${width}%` }} />
                                </div>
                                <span className="zg-accent w-10 text-right font-mono text-[11px]">
                                  {item.risk_score === null ? "—" : item.risk_score}
                                  <span className="zg-faint block font-sans text-[10px]">
                                    {bandLabel(item.risk_band)}
                                  </span>
                                </span>
                              </div>
                            )}
                          </td>
                          <td className="zg-faint whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                            {formatWhen(item.created_at)}
                          </td>
                          <td className="px-2 py-2 text-right">
                            <Link
                              href={`/analyses/${item.id}`}
                              onClick={(event) => event.stopPropagation()}
                              className="zg-accent whitespace-nowrap text-[11px] font-semibold"
                            >
                              Detaylı rapor
                            </Link>
                          </td>
                          <td className="px-2 py-2 text-right">
                            <button
                              type="button"
                              title={
                                item.status === "running"
                                  ? "Tarama bitmeden silinemez"
                                  : "Kuyruktan sil"
                              }
                              disabled={item.status === "running" || deletingId === item.id}
                              onClick={(event) => {
                                event.stopPropagation();
                                void remove(item);
                              }}
                              className="zg-faint inline-flex h-7 w-7 items-center justify-center rounded-md hover:bg-rose-50 hover:text-rose-600 disabled:cursor-not-allowed disabled:opacity-30"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : null}
            </div>
          </div>
        </section>
        <Inspector id={selectedId} />
      </div>
      <ScanDialog job={scanJob} error={scanError} onClose={() => setScanJob(null)} />
    </AppShell>
  );
}
