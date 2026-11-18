"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ApiError, listAnalyses, type AnalysisSummary } from "@/lib/api";
import { formatBytes, formatWhen, shortHash } from "@/lib/format";
import { bandLabel } from "@/lib/score";
import { AppShell } from "@/components/app-shell";
import { StatusBadge } from "@/components/status-badge";

const LIMIT = 20;

export function HistoryBrowser() {
  const router = useRouter();
  const [items, setItems] = useState<AnalysisSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listAnalyses({ limit: LIMIT, offset })
      .then((page) => {
        if (cancelled) return;
        setItems(page.items);
        setTotal(page.total);
        setError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Liste alınamadı.");
      });
    return () => {
      cancelled = true;
    };
  }, [offset]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter(
      (item) =>
        item.original_filename.toLowerCase().includes(needle) || item.sha256.toLowerCase().includes(needle),
    );
  }, [items, query]);

  const page = Math.floor(offset / LIMIT) + 1;
  const pages = Math.max(1, Math.ceil(total / LIMIT));

  return (
    <AppShell crumb={["Analiz Geçmişi", "Detaylı raporlar"]} search={query} onSearch={setQuery}>
      <div className="flex h-full min-h-0 flex-col px-4 py-4">
        <div className="mb-3">
          <h1 className="zg-title text-lg font-semibold">Analiz geçmişi</h1>
        </div>

        <div className="zg-panel min-h-0 flex-1 overflow-auto rounded-lg border">
          <div className="zg-line flex h-9 items-center justify-between border-b px-3">
            <p className="zg-title text-xs font-semibold">Tüm taramalar</p>
            <p className="zg-faint font-mono text-[11px]">{total} kayıt</p>
          </div>
          {error ? <p className="px-3 py-3 text-xs text-rose-700">{error}</p> : null}
          {!error && visible.length === 0 ? (
            <p className="zg-muted px-3 py-8 text-center text-sm">
              Bu sayfada kayıt yok.{" "}
              <Link href="/" className="zg-accent font-semibold">
                Tarama merkezinden
              </Link>{" "}
              dosya yükleyin.
            </p>
          ) : null}
          {visible.length > 0 ? (
            <table className="w-full text-left text-xs">
              <thead className="zg-thead text-[10px] uppercase tracking-[0.12em]">
                <tr>
                  <th className="px-3 py-2 font-semibold">Dosya</th>
                  <th className="px-3 py-2 font-semibold">SHA-256</th>
                  <th className="px-3 py-2 font-semibold">Durum</th>
                  <th className="px-3 py-2 font-semibold">Skor</th>
                  <th className="px-3 py-2 font-semibold">Tarih</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => router.push(`/analyses/${item.id}`)}
                    className="zg-row cursor-pointer border-t"
                  >
                    <td className="max-w-[280px] px-3 py-2">
                      <span className="zg-title block truncate font-medium">{item.original_filename}</span>
                      <span className="zg-faint font-mono text-[10px]">{formatBytes(item.size_bytes)}</span>
                    </td>
                    <td className="zg-hash px-3 py-2 font-mono text-[11px]" title={item.sha256}>
                      {shortHash(item.sha256)}
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge status={item.status} />
                    </td>
                    <td className="px-3 py-2 font-mono">
                      <span className="zg-accent font-semibold">
                        {item.risk_score === null ? "—" : item.risk_score}
                      </span>
                      <span className="zg-faint ml-2 font-sans text-[10px]">{bandLabel(item.risk_band)}</span>
                    </td>
                    <td className="zg-faint whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                      {formatWhen(item.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </div>

        <div className="mt-3 flex items-center justify-end gap-2">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset((current) => Math.max(0, current - LIMIT))}
            className="zg-muted h-8 rounded-md px-3 text-xs font-semibold disabled:opacity-40"
          >
            Önceki
          </button>
          <span className="zg-faint font-mono text-[11px]">
            {page} / {pages}
          </span>
          <button
            type="button"
            disabled={offset + LIMIT >= total}
            onClick={() => setOffset((current) => current + LIMIT)}
            className="zg-muted h-8 rounded-md px-3 text-xs font-semibold disabled:opacity-40"
          >
            Sonraki
          </button>
        </div>
      </div>
    </AppShell>
  );
}
