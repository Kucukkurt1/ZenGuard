"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { ApiError, getAnalysis, type AnalysisDetail } from "@/lib/api";
import { formatBytes, formatWhen, statusLabel } from "@/lib/format";
import { actionSteps, narrate, type Narrative } from "@/lib/explain";
import { bandLabel, isTerminal } from "@/lib/score";
import { AppShell } from "@/components/app-shell";
import { ScoreBreakdown } from "@/components/score-breakdown";
import { ScanProgress } from "@/components/scan-progress";

const TABS = ["Özet", "Neden riskli", "Ne yapmalısınız", "Kayıt"] as const;

type Tab = (typeof TABS)[number];

function banner(detail: AnalysisDetail, narrative: Narrative): { gradient: string; ink: string; chip: string } {
  const onlyTest = narrative.stories.length > 0 && narrative.stories.every((story) => story.key === "eicar");
  if (onlyTest) {
    return {
      gradient: "from-amber-500 to-orange-600",
      ink: "text-white",
      chip: "bg-white/20 text-white",
    };
  }
  if (detail.status === "failed") {
    return { gradient: "from-slate-600 to-slate-800", ink: "text-white", chip: "bg-white/20 text-white" };
  }
  if (detail.status === "queued" || detail.status === "running") {
    return { gradient: "from-teal-600 to-emerald-800", ink: "text-white", chip: "bg-white/20 text-white" };
  }
  if (detail.status === "rejected" || detail.risk_band === "critical") {
    return { gradient: "from-red-700 to-red-950", ink: "text-white", chip: "bg-white/20 text-white" };
  }
  if (detail.risk_band === "high") {
    return { gradient: "from-red-600 to-rose-700", ink: "text-white", chip: "bg-white/20 text-white" };
  }
  if (detail.risk_band === "medium") {
    return {
      gradient: "from-yellow-300 via-yellow-400 to-amber-400",
      ink: "text-amber-950",
      chip: "bg-amber-950/10 text-amber-950",
    };
  }
  if (detail.risk_band === "low") {
    return { gradient: "from-cyan-600 to-sky-800", ink: "text-white", chip: "bg-white/20 text-white" };
  }
  return { gradient: "from-emerald-600 to-teal-700", ink: "text-white", chip: "bg-white/20 text-white" };
}

export function ReportView({ id }: { id: string }) {
  const [detail, setDetail] = useState<AnalysisDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const [tab, setTab] = useState<Tab>("Özet");

  useEffect(() => {
    let cancelled = false;
    let timer = 0;

    async function pull() {
      try {
        const next = await getAnalysis(id);
        if (cancelled) return;
        setDetail(next);
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
        setError(err instanceof ApiError ? err.message : "Rapor alınamadı.");
        timer = window.setTimeout(pull, 2000);
      }
    }

    void pull();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [id]);

  const narrative = detail ? narrate(detail) : null;

  return (
    <AppShell crumb={["Analiz Geçmişi", detail?.original_filename || "Rapor"]}>
      <div className="h-full overflow-auto px-4 py-4">
        <Link href="/history" className="zg-accent mb-3 inline-flex items-center gap-1.5 text-xs font-semibold">
          <ArrowLeft className="h-3.5 w-3.5" />
          Analiz geçmişine dön
        </Link>

        {missing ? (
          <p className="zg-panel rounded-lg border px-4 py-6 text-sm text-amber-800">
            Bu kayıt yok. Silinmiş olabilir.
          </p>
        ) : null}
        {error && !missing ? (
          <p className="mb-3 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-800">{error}</p>
        ) : null}
        {!detail && !missing ? <p className="zg-muted text-sm">Rapor okunuyor…</p> : null}

        {detail && narrative ? (
          <article className={`zg-panel overflow-hidden rounded-xl border`}>
            <header className={`bg-gradient-to-br ${banner(detail, narrative).gradient} px-6 py-6 ${banner(detail, narrative).ink}`}>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] opacity-80">
                {statusLabel(detail.status)}
                {detail.risk_band ? ` · ${bandLabel(detail.risk_band)}` : ""}
              </p>
              <h1 className="mt-2 max-w-3xl text-2xl font-extrabold leading-tight">{narrative.headline}</h1>
              <p className="mt-2 max-w-3xl text-sm opacity-90">{narrative.situation}</p>
              {narrative.stories.length === 0 && detail.status === "completed" ? (
                <p className="mt-3 max-w-3xl text-sm">
                  ClamAV, YARA ve biçim incelemesi bu dosyada bulgu üretmedi.
                </p>
              ) : null}
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <span className={`rounded-full px-3 py-1 font-mono text-sm font-semibold ${banner(detail, narrative).chip}`}>
                  {detail.risk_score === null ? "Skor yok" : `${detail.risk_score}/100`}
                </span>
                <span className={`truncate rounded-full px-3 py-1 text-xs ${banner(detail, narrative).chip}`} title={detail.original_filename}>
                  {detail.original_filename}
                </span>
                <span className={`rounded-full px-3 py-1 font-mono text-xs ${banner(detail, narrative).chip}`}>
                  {formatBytes(detail.size_bytes)}
                </span>
              </div>
            </header>

            {!isTerminal(detail.status) ? (
              <div className="px-6 pt-4">
                <ScanProgress
                  percent={detail.progress_percent ?? (detail.status === "queued" ? 5 : 30)}
                  stage={detail.progress_stage || "Taranıyor"}
                  active
                />
              </div>
            ) : null}

            <div className="zg-line flex gap-1 border-b px-4 pt-3">
              {TABS.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setTab(item)}
                  className={`rounded-t-md px-3 py-2 text-sm font-semibold ${
                    tab === item ? "bg-emerald-500/15 zg-accent" : "zg-muted hover:text-emerald-800"
                  }`}
                >
                  {item}
                </button>
              ))}
            </div>

            <div className="px-6 py-5">
              {tab === "Özet" ? <Summary detail={detail} narrative={narrative} /> : null}
              {tab === "Neden riskli" ? <Why detail={detail} narrative={narrative} /> : null}
              {tab === "Ne yapmalısınız" ? <Actions detail={detail} narrative={narrative} /> : null}
              {tab === "Kayıt" ? <Record detail={detail} /> : null}
            </div>
          </article>
        ) : null}
      </div>
    </AppShell>
  );
}

function isShape(engine: string) {
  return engine === "Biçim" || engine === "Paket kuralı";
}

function Summary({ detail, narrative }: { detail: AnalysisDetail; narrative: Narrative }) {
  const members = detail.report?.members ?? [];
  const motor = narrative.stories.filter((story) => !isShape(story.engine));
  const shape = narrative.stories.filter((story) => isShape(story.engine));
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_280px]">
      <div className="space-y-4">
        <p className="zg-title text-sm leading-relaxed">{narrative.lead}</p>
        {motor.length > 0 ? (
          <ul className="space-y-2">
            {narrative.stories.reduce((sum, story) => sum + story.points, 0) !== (detail.risk_score ?? 0) ? (
              <li className="zg-muted text-xs leading-relaxed">
                {detail.report?.score?.floor
                  ? `Karttaki puan kuralın tarifesidir. Skor ${detail.risk_score}, çünkü zararlı gövde görülmedi ve şüphe tabanı ${detail.report.score.floor}.`
                  : `Karttaki puan kuralın tarifesidir. Skora giren ${detail.risk_score ?? 0}.`}
              </li>
            ) : null}
            {motor.map((story) => (
              <li key={story.key} className="zg-line rounded-lg border px-3 py-2">
                <div className="flex items-baseline justify-between gap-3">
                  <p className="zg-title text-sm font-semibold">{story.title}</p>
                  <span className="shrink-0 font-mono text-xs font-semibold text-rose-600">+{story.points}</span>
                </div>
                <p className="zg-muted mt-1 text-xs">
                  {story.engine} · {story.where}
                </p>
              </li>
            ))}
          </ul>
        ) : null}
        {shape.length > 0 ? (
          <div>
            <h2 className="zg-title mb-2 text-sm font-semibold">Biçim ve paket</h2>
            <ul className="space-y-2">
              {shape.map((story) => (
                <li key={story.key} className="zg-line rounded-lg border px-3 py-2">
                  <div className="flex items-baseline justify-between gap-3">
                    <p className="zg-title text-sm font-semibold">{story.title}</p>
                    <span className="shrink-0 font-mono text-xs font-semibold text-rose-600">+{story.points}</span>
                  </div>
                  <p className="zg-muted mt-1 text-xs">
                    {story.engine} · {story.where}
                  </p>
                  <p className="zg-title mt-2 text-sm leading-relaxed">{story.why}</p>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {members.length > 0 ? (
          <div>
            <h2 className="zg-title mb-2 text-sm font-semibold">Dosyanın içi</h2>
            <ul className="space-y-1">
              {members.map((member) => (
                <li key={`${member.path}:${member.sha256}`} className="zg-faint font-mono text-[11px]">
                  {member.path || "(kök)"} · {formatBytes(member.size_bytes)} · derinlik {member.depth} · {member.mime_type}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
      <ScoreBreakdown report={detail.report} />
    </div>
  );
}

function lineNote(text: string): string {
  const value = text.toLowerCase();
  if (value.includes("eicar")) return "Antivirüs test cümlesi. Çalışan bir program değil.";
  if (value.includes("getasynckeystate") || value.includes("setwindowshookex")) {
    return "Tuş okuyan çağrıların adı bu satırda geçiyor.";
  }
  if (value.includes("downloadstring") || value.includes("-enc") || value.includes("powershell")) {
    return "Başka bir yerden indirip çalıştırmaya benzeyen kalıp.";
  }
  if (value.includes("sifrelendi") || value.includes("bitcoin")) return "Fidye notunda geçen ifade.";
  if (value.includes("vbaproject")) return "Belgenin içinde makro izi var.";
  return "Kuralın aradığı dizi bu satırda.";
}

function MatchedLines({
  lines,
}: {
  lines: NonNullable<NonNullable<AnalysisDetail["report"]>["lines"]>;
}) {
  return (
    <div className="overflow-hidden rounded-xl bg-emerald-950 text-white">
      <p className="px-4 pt-3 text-xs font-semibold">Eşleşen satırlar</p>
      <ul className="space-y-3 px-4 py-3">
        {lines.map((row) => (
          <li key={`${row.rule}-${row.line}`}>
            <p className="font-mono text-[12px] leading-relaxed">
              <span className="mr-2 text-emerald-300">{row.line}</span>
              {row.text}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-emerald-50">{lineNote(row.text)}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Why({ detail, narrative }: { detail: AnalysisDetail; narrative: Narrative }) {
  if (narrative.stories.length === 0) {
    return (
      <p className="zg-title text-sm leading-relaxed">
        {detail.status === "completed"
          ? "Puan yazılacak bir bulgu yok. Skorun sıfır olması, çalışan motorların eşleşme üretmediği anlamına gelir. Dosya adı, uzantı ve 'virus' kelimesi bu karara girmez."
          : narrative.lead}
      </p>
    );
  }
  const lines = detail.report?.lines ?? [];
  const motor = narrative.stories.filter((story) => !isShape(story.engine));
  const shape = narrative.stories.filter((story) => isShape(story.engine));
  return (
    <div className="space-y-4">
      {detail.risk_band === "high" || detail.risk_band === "critical" ? (
        lines.length === 0 ? (
          <p className="zg-title text-sm">Dosya metin değil. Eşleşen satır çıkarılamadı.</p>
        ) : (
          <p className="zg-title text-sm leading-relaxed">
            Skor yüksek ve dosyanın içi okunabildiği için kuralın tuttuğu satırlar aşağıda. Dosya çalıştırılmadı.
          </p>
        )
      ) : null}
      {lines.length > 0 ? <MatchedLines lines={lines} /> : null}
      {motor.length > 0 ? <h2 className="zg-title text-sm font-semibold">ClamAV ve YARA</h2> : null}
      {motor.map((story) => (
        <section key={story.key} className="zg-line rounded-xl border px-4 py-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="zg-title text-base font-semibold">{story.title}</h2>
            <span className="rounded-full bg-rose-50 px-2.5 py-0.5 font-mono text-xs font-semibold text-rose-700">
              {story.engine} · +{story.points}
            </span>
          </div>
          <p className="zg-faint mt-1 font-mono text-[11px]">Nerede: {story.where}</p>
          <p className="zg-title mt-3 text-sm leading-relaxed">{story.why}</p>
          <p className="zg-muted mt-2 text-sm leading-relaxed">{story.means}</p>
        </section>
      ))}
      {shape.length > 0 ? <h2 className="zg-title pt-2 text-sm font-semibold">Biçim ve paket</h2> : null}
      {shape.map((story) => (
        <section key={story.key} className="zg-line rounded-xl border px-4 py-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="zg-title text-base font-semibold">{story.title}</h2>
            <span className="rounded-full bg-rose-50 px-2.5 py-0.5 font-mono text-xs font-semibold text-rose-700">
              {story.engine} · +{story.points}
            </span>
          </div>
          <p className="zg-faint mt-1 font-mono text-[11px]">Nerede: {story.where}</p>
          <p className="zg-title mt-3 text-sm leading-relaxed">{story.why}</p>
          <p className="zg-muted mt-2 text-sm leading-relaxed">{story.means}</p>
        </section>
      ))}
    </div>
  );
}

function Actions({ detail, narrative }: { detail: AnalysisDetail; narrative: Narrative }) {
  const shared = narrative.stories.length === 0 ? actionSteps(detail, narrative) : [];
  return (
    <div className="space-y-5">
      <p className="zg-title text-sm leading-relaxed">{narrative.situation}</p>
      {shared.length > 0 ? (
        <ol className="space-y-3">
          {shared.map((step, index) => (
            <li key={step.title} className="zg-line rounded-xl border px-4 py-3">
              <p className="zg-accent text-xs font-semibold">Adım {index + 1}</p>
              <h2 className="zg-title mt-1 text-sm font-semibold">{step.title}</h2>
              <p className="zg-muted mt-1 text-sm leading-relaxed">{step.detail}</p>
            </li>
          ))}
        </ol>
      ) : (
        [...narrative.stories.filter((story) => !isShape(story.engine)), ...narrative.stories.filter((story) => isShape(story.engine))].map((story, index, all) => (
          <section key={story.key}>
            {isShape(story.engine) && (index === 0 || !isShape(all[index - 1].engine)) ? (
              <h2 className="zg-title mb-2 text-sm font-semibold">Biçim ve paket</h2>
            ) : null}
            <h2 className="zg-title text-sm font-semibold">{story.title}</h2>
            {all.length > 1 ? (
              <p className="zg-faint mt-0.5 text-xs">Bu bulgu için. Diğer bulguların adımları ayrı.</p>
            ) : null}
            <ol className="mt-2 space-y-2">
              {story.steps.map((step, index) => (
                <li key={step.title} className="zg-line rounded-xl border px-4 py-3">
                  <p className="zg-accent text-xs font-semibold">
                    {index + 1}. {step.title}
                  </p>
                  <p className="zg-muted mt-1 text-sm leading-relaxed">{step.detail}</p>
                </li>
              ))}
            </ol>
          </section>
        ))
      )}
    </div>
  );
}

function Record({ detail }: { detail: AnalysisDetail }) {
  const rows = [
    ["SHA-256", detail.sha256],
    ["Tür", detail.mime_type],
    ["Boyut", formatBytes(detail.size_bytes)],
    ["Yüklendi", formatWhen(detail.created_at)],
    ["Bitti", formatWhen(detail.finished_at)],
    ["Kapsam", detail.coverage || "—"],
    ["Kural sürümü", detail.ruleset_version || "—"],
    ["Hata kodu", detail.error_code || "—"],
  ];
  return (
    <div className="space-y-4">
      <dl className="grid gap-3 sm:grid-cols-2">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt className="zg-faint text-[11px] font-semibold uppercase tracking-[0.12em]">{label}</dt>
            <dd className="zg-title mt-1 break-all font-mono text-xs">{value}</dd>
          </div>
        ))}
      </dl>
      <pre className="overflow-auto rounded-lg bg-emerald-950 p-4 font-mono text-[11px] leading-relaxed text-emerald-100">
        {detail.report ? JSON.stringify(detail.report, null, 2) : "{\n  \"report\": null\n}"}
      </pre>
    </div>
  );
}
