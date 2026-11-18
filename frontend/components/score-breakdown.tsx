import type { AnalysisReport } from "@/lib/api";
import {
  COMPONENT_LABEL,
  COMPONENT_MAX,
  type ComponentKey,
  componentOf,
} from "@/lib/score";

const KEYS: ComponentKey[] = ["clamav", "yara", "static", "archive"];

const MODE_LABEL: Record<string, string> = {
  weighted_sum: "Parça toplamı",
  policy_override: "Politika durdurması",
  certainty_sure: "Gövde görüldü",
  certainty_indicator: "Kalıp görüldü",
};

export function ScoreBreakdown({ report }: { report: AnalysisReport | null }) {
  const clipped = report?.score?.clipped ?? 0;
  const mode = report?.score?.mode;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="zg-title text-sm font-semibold">Bileşen kırılımı</h3>
        {mode ? (
          <span className="rounded-full bg-teal-50 px-2.5 py-1 text-[11px] font-semibold text-teal-800">
            {MODE_LABEL[mode] ?? mode}
          </span>
        ) : null}
      </div>
      {KEYS.map((key) => {
        const part = componentOf(report, key);
        const max = part.max || COMPONENT_MAX[key];
        const width = Math.max(0, Math.min(100, (part.awarded / max) * 100));
        return (
          <div key={key}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="zg-muted font-medium">{COMPONENT_LABEL[key]}</span>
              <span className="zg-accent font-mono font-semibold">
                {part.awarded}
                <span className="zg-faint font-normal"> / {max}</span>
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-emerald-100">
              <div
                className="h-full rounded-full bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500"
                style={{ width: `${width}%` }}
              />
            </div>
          </div>
        );
      })}
      <p className="zg-muted text-xs">
        Parça toplamı:{" "}
        <span className="zg-accent font-mono font-semibold">{report?.score?.evidence_sum ?? "—"}</span>
        {report?.score?.floor ? (
          <>
            {" "}
            · şüphe tabanı <span className="zg-accent font-mono font-semibold">{report.score.floor}</span>
          </>
        ) : null}
        {clipped > 0 ? (
          <>
            {" "}
            · kırpılan <span className="zg-accent font-mono font-semibold">{clipped}</span>
          </>
        ) : null}
      </p>
    </div>
  );
}
