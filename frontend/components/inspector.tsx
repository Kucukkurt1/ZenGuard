"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ApiError, getAnalysis, type AnalysisDetail } from "@/lib/api";
import { isTerminal } from "@/lib/score";
import { ScoreBreakdown } from "@/components/score-breakdown";
import { RiskGauge } from "@/components/risk-gauge";
import { FindingCards } from "@/components/finding-cards";
import { ScanProgress } from "@/components/scan-progress";

const TABS = ["Özet & Skor", "ClamAV & YARA", "Ham JSON"] as const;

export function Inspector({ id }: { id: string | null }) {
  const [tab, setTab] = useState<(typeof TABS)[number]>("Özet & Skor");
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    setTab("Özet & Skor");
    setAnalysis(null);
    setError(null);
    setMissing(false);
    if (!id) return;

    let cancelled = false;
    let timer = 0;

    async function pull() {
      try {
        const next = await getAnalysis(id as string);
        if (cancelled) return;
        setAnalysis(next);
        setError(null);
        setMissing(false);
        if (!isTerminal(next.status)) timer = window.setTimeout(pull, 1000);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setMissing(true);
          setError(err.message);
          return;
        }
        setError(err instanceof ApiError ? err.message : "Ağ hatası. Kayıt kimliği duruyor.");
        timer = window.setTimeout(pull, 1000);
      }
    }

    pull();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [id]);

  if (!id) {
    return (
      <aside className="zg-inspector flex h-full w-[35%] min-w-[320px] flex-col border-l">
        <div className="zg-muted flex h-10 items-center border-b border-emerald-800/50 px-3 text-xs font-semibold uppercase tracking-[0.14em]">
          İnceleme
        </div>
        <p className="zg-muted px-4 py-8 text-sm">Kuyruktan bir kayıt seçin.</p>
      </aside>
    );
  }

  return (
    <aside className="zg-inspector flex h-full w-[35%] min-w-[320px] flex-col border-l">
      <div className="flex h-10 shrink-0 items-center gap-1 border-b border-emerald-800/50 px-2">
        {TABS.map((item) => (
          <button
            key={item}
            type="button"
            onClick={() => setTab(item)}
            className={`rounded-md px-2 py-1 text-xs font-medium ${
              tab === item ? "bg-emerald-500/15 text-emerald-200" : "zg-muted hover:text-emerald-200"
            }`}
          >
            {item}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {missing ? <p className="text-sm text-amber-800">Kayıt bulunamadı. {id}</p> : null}
        {error && !missing ? (
          <p className="mb-3 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-800">
            {error} Kimlik: {analysis?.id ?? id}
          </p>
        ) : null}
        {!analysis && !missing && !error ? <p className="zg-muted text-sm">Kayıt okunuyor…</p> : null}

        {analysis && tab === "Özet & Skor" ? (
          <div className="space-y-4">
            {!isTerminal(analysis.status) ? (
              <ScanProgress
                percent={analysis.progress_percent ?? (analysis.status === "queued" ? 5 : 30)}
                stage={analysis.progress_stage || (analysis.status === "queued" ? "Kuyrukta" : "Taranıyor")}
                active
              />
            ) : null}
            <div>
              <p className="zg-title truncate text-sm font-semibold">{analysis.original_filename}</p>
              <p className="zg-hash mt-1 break-all font-mono text-[11px]">{analysis.sha256}</p>
              <p className="zg-muted mt-1 text-xs">
                {analysis.status}
                {analysis.error_code ? ` · ${analysis.error_code}` : ""}
                {analysis.error_message ? ` · ${analysis.error_message}` : ""}
              </p>
              <Link href={`/analyses/${analysis.id}`} className="zg-accent mt-2 inline-block text-xs font-semibold">
                Detaylı raporu aç
              </Link>
            </div>
            <RiskGauge score={analysis.risk_score} band={analysis.risk_band} status={analysis.status} />
            <ScoreBreakdown report={analysis.report} />
          </div>
        ) : null}

        {analysis && tab === "ClamAV & YARA" ? <FindingCards report={analysis.report} /> : null}

        {analysis && tab === "Ham JSON" ? (
          <pre className="overflow-auto rounded-md border border-emerald-100 bg-emerald-950 p-3 font-mono text-[11px] leading-relaxed text-emerald-100">
            {analysis.report ? JSON.stringify(analysis.report, null, 2) : "{\n  \"report\": null\n}"}
          </pre>
        ) : null}
      </div>
    </aside>
  );
}
