"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Check,
  CircleX,
  ExternalLink,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  TriangleAlert,
  X,
  type LucideIcon,
} from "lucide-react";
import { ApiError, getAnalysis, type AnalysisDetail, type FindingReason } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { bandLabel, collectFindings, isTerminal } from "@/lib/score";

export type ScanJob = {
  key: number;
  id: string | null;
  filename: string;
  size: number;
};

const MARKS = ["Dosya", "ClamAV", "YARA", "Skor"] as const;

const RING = 2 * Math.PI * 58;

type Verdict = {
  title: string;
  subtitle: string;
  icon: LucideIcon;
  hero: string;
  halo: string;
  chip: string;
  meter: string;
  ink?: string;
};

const VERDICT: Record<"clean" | "low" | "watch" | "threat" | "rejected" | "failed", Verdict> = {
  clean: {
    title: "TEMİZ",
    subtitle: "Hiçbir motor tehdit bulmadı.",
    icon: ShieldCheck,
    hero: "from-emerald-500 via-emerald-600 to-teal-600",
    halo: "bg-emerald-300/40",
    chip: "bg-white/20 text-white",
    meter: "bg-emerald-500",
  },
  low: {
    title: "DÜŞÜK RİSK",
    subtitle: "Zayıf işaretler var, tehdit imzası yok.",
    icon: ShieldCheck,
    hero: "from-teal-500 via-cyan-600 to-sky-700",
    halo: "bg-cyan-200/40",
    chip: "bg-white/20 text-white",
    meter: "bg-cyan-500",
  },
  watch: {
    title: "ŞÜPHELİ",
    subtitle: "Dikkat gerektiren işaretler var.",
    icon: TriangleAlert,
    hero: "from-yellow-300 via-yellow-400 to-amber-400",
    halo: "bg-yellow-200/70",
    chip: "bg-amber-950/10 text-amber-950",
    meter: "bg-yellow-500",
    ink: "text-amber-950",
  },
  threat: {
    title: "TEHDİT TESPİT EDİLDİ",
    subtitle: "Bu dosyayı açmayın.",
    icon: ShieldAlert,
    hero: "from-rose-500 via-rose-600 to-red-700",
    halo: "bg-rose-300/50",
    chip: "bg-white/20 text-white",
    meter: "bg-rose-500",
  },
  rejected: {
    title: "ENGELLENDİ",
    subtitle: "Arşiv güvenlik politikasını ihlal ediyor.",
    icon: ShieldBan,
    hero: "from-rose-600 via-red-700 to-rose-900",
    halo: "bg-rose-300/50",
    chip: "bg-white/20 text-white",
    meter: "bg-rose-600",
  },
  failed: {
    title: "TARAMA BAŞARISIZ",
    subtitle: "Sonuç yok. Skor verilmedi.",
    icon: CircleX,
    hero: "from-slate-500 via-slate-600 to-slate-700",
    halo: "bg-slate-300/40",
    chip: "bg-white/20 text-white",
    meter: "bg-slate-500",
  },
};

const SIGNAL_LABEL: Record<string, string> = {
  entropy_high: "Yüksek entropi (paketlenmiş olabilir)",
  packer_section: "Paketleyici bölümü",
  double_extension: "Çift uzantı",
  office_macro: "Office makrosu",
  pe_rwe_section: "Yazılabilir + çalıştırılabilir bölüm",
  pe_tls_callback: "TLS geri çağrısı",
  pe_no_imports: "İçe aktarım tablosu yok",
  script_exec: "Komut çalıştıran betik",
  encrypted_archive: "Şifreli arşiv",
  extension_mismatch: "Uzantı ile içerik uyuşmuyor",
  nested_depth_max: "Arşiv derinlik sınırında",
  high_file_count: "Çok sayıda arşiv üyesi",
  suspicious_ratio: "Şüpheli sıkıştırma oranı",
  static_error: "Statik analiz hatası",
  ZIP_BOMB: "Zip bombası",
  SIZE_LIMIT: "Açılmış boyut sınırı aşıldı",
  ARCHIVE_COUNT: "Üye sayısı sınırı aşıldı",
  ARCHIVE_DEPTH: "Arşiv derinliği sınırı aşıldı",
  PATH_TRAVERSAL: "Dışarı kaçan üye yolu",
  UNSAFE_MEMBER: "Sembolik bağ",
};

function verdictOf(detail: AnalysisDetail): Verdict {
  if (detail.status === "failed") return VERDICT.failed;
  if (detail.status === "rejected") return VERDICT.rejected;
  if (detail.risk_band === "high" || detail.risk_band === "critical") return VERDICT.threat;
  if (detail.risk_band === "medium") return VERDICT.watch;
  if (detail.risk_band === "low") return VERDICT.low;
  return VERDICT.clean;
}

function findingLabel(reason: FindingReason): { engine: string; text: string } {
  const code = reason.code ?? "";
  if (code === "malware_signature" || code === "pua_heuristic") {
    const signature = reason.evidence?.signature;
    return {
      engine: "ClamAV",
      text: typeof signature === "string" && signature ? signature : code,
    };
  }
  if (reason.rule) {
    return { engine: "YARA", text: `${reason.rule}${reason.severity ? ` · ${reason.severity}` : ""}` };
  }
  return { engine: "Sinyal", text: SIGNAL_LABEL[code] ?? code };
}

function markIndex(percent: number): number {
  if (percent >= 96) return 3;
  if (percent >= 62) return 2;
  if (percent >= 28) return 1;
  return 0;
}

export function ScanDialog({
  job,
  error,
  onClose,
}: {
  job: ScanJob | null;
  error: string | null;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<AnalysisDetail | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [shown, setShown] = useState(0);
  const [stage, setStage] = useState("Dosya yükleniyor");

  useEffect(() => {
    setDetail(null);
    setPollError(null);
    setShown(0);
    setStage("Dosya yükleniyor");
  }, [job?.key]);

  useEffect(() => {
    if (!job?.id) return;
    const id = job.id;
    let cancelled = false;
    let timer = 0;

    async function pull() {
      try {
        const next = await getAnalysis(id);
        if (cancelled) return;
        setDetail(next);
        if (!isTerminal(next.status) && next.progress_stage) {
          setStage(next.progress_stage);
        }
        if (isTerminal(next.status)) {
          window.clearInterval(timer);
        }
      } catch (err) {
        if (cancelled) return;
        setPollError(err instanceof ApiError ? err.message : "Tarama durumu alınamadı.");
      }
    }

    void pull();
    timer = window.setInterval(() => void pull(), 400);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [job?.id]);

  const liveTarget = !job?.id
    ? 8
    : detail && isTerminal(detail.status)
      ? 100
      : (detail?.progress_percent ?? 6);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setShown((current) => {
        if (current >= liveTarget) return current;
        const step = Math.max(1, Math.round((liveTarget - current) * 0.08));
        return Math.min(liveTarget, current + step);
      });
    }, 70);
    return () => window.clearInterval(timer);
  }, [liveTarget]);

  if (!job) return null;

  const done = Boolean(detail && isTerminal(detail.status) && shown >= 100);
  const problem = error || pollError;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-emerald-950/45 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-dialog-title"
        className="zg-panel zg-pop w-full max-w-md overflow-hidden rounded-2xl border shadow-2xl"
      >
        {done && detail ? (
          <ResultView detail={detail} filename={job.filename} size={job.size} onClose={onClose} />
        ) : (
          <ProgressView
            filename={job.filename}
            size={job.size}
            percent={shown}
            stage={stage}
            problem={problem}
            onClose={onClose}
          />
        )}
      </div>
    </div>
  );
}

function ProgressView({
  filename,
  size,
  percent,
  stage,
  problem,
  onClose,
}: {
  filename: string;
  size: number;
  percent: number;
  stage: string;
  problem: string | null;
  onClose: () => void;
}) {
  const width = Math.max(0, Math.min(100, percent));
  const offset = RING - (width / 100) * RING;
  const activeMark = markIndex(width);

  return (
    <div className="px-6 pb-5 pt-6">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="zg-accent text-[11px] font-semibold uppercase tracking-[0.16em]">Canlı tarama</p>
          <h2 id="scan-dialog-title" className="zg-title mt-1 truncate text-base font-semibold">
            {filename}
          </h2>
          <p className="zg-faint font-mono text-[11px]">{formatBytes(size)}</p>
        </div>
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-emerald-100 text-emerald-700">
          <ShieldCheck className="h-4 w-4" />
        </span>
      </div>

      <div className="relative mx-auto grid h-44 w-44 place-items-center">
        <svg viewBox="0 0 140 140" className="h-44 w-44 -rotate-90 text-emerald-500">
          <circle cx="70" cy="70" r="58" fill="none" stroke="currentColor" strokeOpacity="0.15" strokeWidth="10" />
          <circle
            cx="70"
            cy="70"
            r="58"
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={RING}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute text-center">
          <p className="zg-title font-mono text-4xl font-semibold leading-none">{width}%</p>
          <p className="zg-muted mt-1 text-[11px] font-medium">ilerleme</p>
        </div>
      </div>

      <p className="zg-title mt-4 text-center text-sm font-semibold">
        {problem ? "Tarama başlatılamadı" : stage}
      </p>
      {problem ? <p className="mt-2 text-center text-xs text-rose-700">{problem}</p> : null}

      <ol className="mt-5 grid grid-cols-4 gap-2">
        {MARKS.map((label, index) => {
          const reached = index < activeMark || (index === activeMark && width > 0);
          const current = index === activeMark;
          return (
            <li key={label} className="text-center">
              <span
                className={`mx-auto grid h-6 w-6 place-items-center rounded-full border text-[10px] ${
                  reached ? "border-emerald-500 bg-emerald-500 text-white" : "border-emerald-200 text-emerald-700/50"
                } ${current ? "animate-pulse" : ""}`}
              >
                {reached && !current ? <Check className="h-3 w-3" /> : index + 1}
              </span>
              <span className={`mt-1 block text-[10px] font-medium ${reached ? "zg-accent" : "zg-faint"}`}>
                {label}
              </span>
            </li>
          );
        })}
      </ol>

      <div className="mt-5 flex justify-end">
        {problem ? (
          <button
            type="button"
            onClick={onClose}
            className="zg-btn inline-flex h-9 items-center gap-1.5 rounded-md px-3 text-xs font-semibold"
          >
            <X className="h-3.5 w-3.5" />
            Kapat
          </button>
        ) : (
          <button
            type="button"
            onClick={onClose}
            className="zg-muted h-9 rounded-md px-3 text-xs font-medium hover:bg-emerald-50"
          >
            Arka planda bırak
          </button>
        )}
      </div>
    </div>
  );
}

function ResultView({
  detail,
  filename,
  size,
  onClose,
}: {
  detail: AnalysisDetail;
  filename: string;
  size: number;
  onClose: () => void;
}) {
  const verdict = verdictOf(detail);
  const Icon = verdict.icon;
  const score = detail.risk_score;
  const findings = collectFindings(detail.report)
    .filter((reason) => (reason.points ?? 0) > 0)
    .sort((a, b) => (b.points ?? 0) - (a.points ?? 0))
    .slice(0, 4);
  const subtitle = detail.error_message || verdict.subtitle;

  return (
    <div>
      <div className={`relative bg-gradient-to-br ${verdict.hero} px-6 pb-7 pt-8 text-center ${verdict.ink ?? "text-white"}`}>
        <button
          type="button"
          onClick={onClose}
          aria-label="Kapat"
          className="absolute right-3 top-3 grid h-8 w-8 place-items-center rounded-full text-white/80 hover:bg-white/15 hover:text-white"
        >
          <X className="h-4 w-4" />
        </button>

        <div className="relative mx-auto grid h-24 w-24 place-items-center">
          <span className={`absolute inset-0 animate-ping rounded-full ${verdict.halo}`} />
          <span className="zg-stamp relative grid h-24 w-24 place-items-center rounded-full bg-white/15 ring-4 ring-white/40">
            <Icon className="h-12 w-12" strokeWidth={2.25} />
          </span>
        </div>

        <h2 id="scan-dialog-title" className="zg-stamp mt-5 text-3xl font-extrabold tracking-wide">
          {verdict.title}
        </h2>
        <p className={`mt-1 text-sm ${verdict.ink ? "opacity-80" : "text-white/90"}`}>{subtitle}</p>

        <div className="mt-4 flex items-center justify-center gap-2">
          <span className={`rounded-full px-3 py-1 font-mono text-sm font-semibold ${verdict.chip}`}>
            {score === null ? "Skor yok" : `${score}/100`}
          </span>
          {detail.risk_band ? (
            <span className={`rounded-full px-3 py-1 text-xs font-semibold ${verdict.chip}`}>
              {bandLabel(detail.risk_band)}
            </span>
          ) : null}
        </div>
      </div>

      <div className="px-6 pb-5 pt-4">
        <div className="flex items-center justify-between gap-3">
          <p className="zg-title min-w-0 truncate text-sm font-semibold" title={filename}>
            {filename}
          </p>
          <p className="zg-faint shrink-0 font-mono text-[11px]">{formatBytes(size)}</p>
        </div>

        {score !== null ? (
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200/70">
            <div className={`h-full rounded-full ${verdict.meter}`} style={{ width: `${Math.max(score, 2)}%` }} />
          </div>
        ) : null}

        {findings.length > 0 ? (
          <ul className="mt-4 space-y-1.5">
            {findings.map((reason, index) => {
              const label = findingLabel(reason);
              return (
                <li
                  key={`${reason.code}-${index}`}
                  className="zg-line flex items-center gap-2 rounded-lg border px-3 py-2 text-xs"
                >
                  <span className="zg-accent w-14 shrink-0 font-semibold">{label.engine}</span>
                  <span className="zg-title min-w-0 flex-1 truncate font-mono text-[11px]" title={label.text}>
                    {label.text}
                  </span>
                  <span className="shrink-0 font-mono text-[11px] font-semibold text-rose-600">
                    +{reason.points}
                  </span>
                </li>
              );
            })}
          </ul>
        ) : detail.status === "completed" ? (
          <p className="zg-muted mt-4 rounded-lg bg-emerald-50 px-3 py-2 text-xs">
            ClamAV, YARA ve statik analiz bu dosyada bulgu üretmedi.
          </p>
        ) : null}

        <div className="mt-5 flex justify-end gap-2">
          <Link
            href={`/analyses/${detail.id}`}
            className="zg-muted inline-flex h-9 items-center gap-1.5 rounded-md px-3 text-xs font-medium hover:bg-emerald-50"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Raporu aç
          </Link>
          <button
            type="button"
            onClick={onClose}
            className="zg-btn inline-flex h-9 items-center gap-1.5 rounded-md px-4 text-xs font-semibold"
          >
            Tamam
          </button>
        </div>
      </div>
    </div>
  );
}
