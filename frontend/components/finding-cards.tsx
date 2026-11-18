import type { AnalysisReport, FindingReason } from "@/lib/api";
import { collectFindings, isPolicyOverride } from "@/lib/score";

function evidenceText(evidence: Record<string, unknown> | undefined): string {
  if (!evidence || Object.keys(evidence).length === 0) return "";
  try {
    return JSON.stringify(evidence);
  } catch {
    return "";
  }
}

function FindingCard({ reason, policy }: { reason: FindingReason; policy?: boolean }) {
  return (
    <article
      className={`zg-panel rounded-lg border p-3 ${
        policy ? "border-rose-400/40" : "border-emerald-800/50"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <h3 className="zg-title text-sm font-semibold">
          {reason.code || reason.rule || "Bulgu"}
        </h3>
        <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-semibold text-emerald-800">
          {reason.points ?? 0} puan
        </span>
      </div>
      {reason.rule ? (
        <p className="mt-2 text-xs text-slate-600">
          Kural: <span className="font-medium">{reason.rule}</span>
          {reason.severity ? ` · ${reason.severity}` : ""}
        </p>
      ) : null}
      {reason.member_path ? (
        <p className="mt-1 break-all text-xs text-slate-500">Üye: {reason.member_path}</p>
      ) : null}
      {evidenceText(reason.evidence) ? (
        <p className="zg-hash mt-2 break-all rounded-md bg-emerald-950/40 px-3 py-2 font-mono text-[11px]">
          {evidenceText(reason.evidence)}
        </p>
      ) : null}
      {policy ? (
        <p className="mt-2 text-xs font-medium text-rose-700">Politika reddi · policy_override</p>
      ) : null}
    </article>
  );
}

export function FindingCards({ report }: { report: AnalysisReport | null }) {
  const policy = isPolicyOverride(report);
  const findings = collectFindings(report);
  const signature = report?.engines?.clamav?.signature;
  const yaraCount = report?.engines?.yara?.matches?.length ?? 0;
  const staticCount = report?.engines?.static?.signals?.length ?? 0;

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2 border-b border-emerald-50 pb-3">
        <h2 className="zg-title text-base font-semibold">Bulgular</h2>
        <p className="zg-muted text-xs">
          ClamAV {signature ? signature : "imza yok"} · YARA {yaraCount} · statik {staticCount}
        </p>
      </div>
      {policy && findings.length === 0 ? (
        <FindingCard
          policy
          reason={{
            code: "policy_override",
            points: report?.score?.value ?? 100,
            evidence: { mode: "policy_override" },
          }}
        />
      ) : null}
      {findings.length === 0 && !policy ? (
        <div className="zg-muted rounded-lg border border-dashed border-emerald-800/50 px-4 py-8 text-center text-sm">
          Henüz gerekçe yok. Skor yazıldığında ClamAV, YARA ve statik kartları burada açılır.
        </div>
      ) : null}
      <div className="grid gap-3 md:grid-cols-2">
        {findings.map((reason, index) => (
          <FindingCard key={`${reason.code ?? "f"}-${index}`} reason={reason} policy={policy} />
        ))}
      </div>
    </section>
  );
}
