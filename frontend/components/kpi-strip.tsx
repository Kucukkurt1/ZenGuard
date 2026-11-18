"use client";

import { useEffect, useState } from "react";
import { Activity, Radar, ShieldAlert, ShieldCheck } from "lucide-react";
import { getHealth, listAnalyses, type AnalysisSummary } from "@/lib/api";

function isClean(item: AnalysisSummary): boolean {
  if (item.status === "rejected" || item.status === "failed") return false;
  if (item.risk_band === "clean" || item.risk_band === "low") return true;
  return item.risk_score !== null && item.risk_score <= 29;
}

function isThreat(item: AnalysisSummary): boolean {
  if (item.status === "rejected") return true;
  if (item.risk_band === "high" || item.risk_band === "critical") return true;
  return item.risk_score !== null && item.risk_score >= 70;
}

export function KpiStrip() {
  const [total, setTotal] = useState<number | null>(null);
  const [clean, setClean] = useState(0);
  const [threats, setThreats] = useState(0);
  const [engines, setEngines] = useState("3");
  const [engineNote, setEngineNote] = useState("ClamAV · YARA · Sandbox");

  useEffect(() => {
    let cancelled = false;

    async function pull() {
      try {
        const [page, health] = await Promise.all([
          listAnalyses({ limit: 100 }),
          getHealth(),
        ]);
        if (cancelled) return;
        setTotal(page.total);
        setClean(page.items.filter(isClean).length);
        setThreats(page.items.filter(isThreat).length);
        const clamavUp = health.clamav === "ok";
        setEngines(clamavUp ? "3" : "2");
        setEngineNote(clamavUp ? "ClamAV · YARA · Sandbox" : "ClamAV kapalı · YARA · Sandbox");
      } catch {
        if (!cancelled) setTotal(null);
      }
    }

    pull();
    const timer = window.setInterval(pull, 8000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const cards = [
    {
      label: "Toplam tarama",
      value: total === null ? "—" : String(total),
      note: "Kuyruğa alınan örnekler",
      icon: Radar,
      accent: "from-emerald-500 to-teal-500",
      valueClass: "text-emerald-950",
    },
    {
      label: "Temiz dosyalar",
      value: String(clean),
      note: "Skor 0–29 veya düşük bant",
      icon: ShieldCheck,
      accent: "from-emerald-400 to-emerald-600",
      valueClass: "text-emerald-700",
    },
    {
      label: "Tespit edilen tehditler",
      value: String(threats),
      note: "Skor 70+ , yüksek bant veya red",
      icon: ShieldAlert,
      accent: "from-orange-400 to-rose-500",
      valueClass: "text-rose-700",
    },
    {
      label: "Aktif motorlar",
      value: engines,
      note: engineNote,
      icon: Activity,
      accent: "from-cyan-400 to-teal-500",
      valueClass: "text-cyan-800",
    },
  ];

  return (
    <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <article
          key={card.label}
          className="relative overflow-hidden rounded-2xl border border-emerald-100/80 bg-white px-5 py-4 shadow-[0_18px_40px_-28px_rgba(6,78,59,0.55)]"
        >
          <span className={`absolute inset-y-0 left-0 w-1 bg-gradient-to-b ${card.accent}`} />
          <div className="flex items-start justify-between gap-3 pl-2">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-teal-800/70">
                {card.label}
              </p>
              <p className={`mt-2 text-3xl font-semibold tracking-tight ${card.valueClass}`}>
                {card.value}
              </p>
              <p className="mt-1 text-xs text-slate-500">{card.note}</p>
            </div>
            <span className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-50 text-teal-700">
              <card.icon className="h-5 w-5" />
            </span>
          </div>
        </article>
      ))}
    </section>
  );
}
