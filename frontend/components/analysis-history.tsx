"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Copy, Check, Inbox } from "lucide-react";
import { ApiError, listAnalyses, type AnalysisSummary } from "@/lib/api";
import { formatBytes, formatWhen, shortHash } from "@/lib/format";
import { bandLabel, threatTone } from "@/lib/score";
import { StatusBadge } from "@/components/status-badge";

const FILTERS = [
  { id: "", label: "Tümü" },
  { id: "queued", label: "Kuyrukta" },
  { id: "running", label: "Çalışıyor" },
  { id: "completed", label: "Tamamlandı" },
  { id: "failed", label: "Başarısız" },
  { id: "rejected", label: "Reddedildi" },
];

const BAR: Record<string, string> = {
  safe: "bg-emerald-500",
  watch: "bg-amber-500",
  threat: "bg-rose-500",
  pending: "bg-slate-200",
};

export function AnalysisHistory() {
  const router = useRouter();
  const [status, setStatus] = useState("");
  const [items, setItems] = useState<AnalysisSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function pull() {
      try {
        const page = await listAnalyses({
          limit: 20,
          status: status || undefined,
        });
        if (cancelled) return;
        setItems(page.items);
        setTotal(page.total);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Liste alınamadı.");
      }
    }

    pull();
    const timer = window.setInterval(pull, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [status]);

  async function copyHash(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(value);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);
    }
  }

  return (
    <section className="overflow-hidden rounded-2xl border border-emerald-100 bg-white shadow-[0_24px_50px_-36px_rgba(6,78,59,0.65)]">
      <div className="flex flex-col gap-3 bg-gradient-to-r from-emerald-700 to-teal-600 px-5 py-4 text-white sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold">Son analizler</h2>
          <p className="text-xs text-emerald-50/80">{total} kayıt · satıra tıklayınca ayrıntı açılır</p>
        </div>
        <label className="text-xs font-medium text-emerald-50">
          Durum
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className="ml-2 rounded-lg border border-white/30 bg-white/15 px-3 py-1.5 text-sm text-white outline-none backdrop-blur-md"
          >
            {FILTERS.map((item) => (
              <option key={item.id || "all"} value={item.id} className="text-slate-800">
                {item.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error ? (
        <p className="m-5 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
          {error}
        </p>
      ) : null}

      {!error && items.length === 0 ? (
        <div className="flex flex-col items-center px-6 py-16 text-center">
          <span className="mb-3 grid h-12 w-12 place-items-center rounded-2xl bg-emerald-50 text-emerald-700">
            <Inbox className="h-5 w-5" />
          </span>
          <p className="text-sm font-semibold text-emerald-950">Henüz analiz yok</p>
          <p className="mt-1 max-w-sm text-xs leading-relaxed text-slate-500">
            İlk dosyayı üstteki tarama alanına bıraktığınızda kayıt burada görünür.
          </p>
        </div>
      ) : null}

      {items.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-emerald-950/[0.04] text-[11px] uppercase tracking-[0.14em] text-teal-900/70">
              <tr>
                <th className="px-5 py-3 font-semibold">Dosya</th>
                <th className="px-3 py-3 font-semibold">SHA-256</th>
                <th className="px-3 py-3 font-semibold">Durum</th>
                <th className="px-3 py-3 font-semibold">Risk</th>
                <th className="px-5 py-3 font-semibold">Zaman</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const tone = threatTone(item.risk_score);
                const width = item.risk_score === null ? 0 : item.risk_score;
                return (
                  <tr
                    key={item.id}
                    onClick={() => router.push(`/analyses/${item.id}`)}
                    className="cursor-pointer border-t border-emerald-50 transition hover:bg-emerald-50/80"
                  >
                    <td className="max-w-[280px] px-5 py-3.5">
                      <span className="block truncate font-semibold text-emerald-950">
                        {item.original_filename}
                      </span>
                      <span className="text-xs text-slate-400">{formatBytes(item.size_bytes)}</span>
                    </td>
                    <td className="px-3 py-3.5">
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          void copyHash(item.sha256);
                        }}
                        className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-600 hover:text-teal-800"
                        title={item.sha256}
                      >
                        {shortHash(item.sha256)}
                        {copied === item.sha256 ? (
                          <Check className="h-3.5 w-3.5 text-emerald-600" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </td>
                    <td className="px-3 py-3.5">
                      <StatusBadge status={item.status} />
                    </td>
                    <td className="min-w-[160px] px-3 py-3.5">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-emerald-50">
                          <div
                            className={`h-full rounded-full ${BAR[tone]}`}
                            style={{ width: `${width}%` }}
                          />
                        </div>
                        <span className="w-14 text-right text-xs font-semibold text-slate-700">
                          {item.risk_score === null ? "—" : item.risk_score}
                          <span className="block font-normal text-slate-400">
                            {bandLabel(item.risk_band)}
                          </span>
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-3.5 text-xs text-slate-500">
                      {formatWhen(item.created_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
