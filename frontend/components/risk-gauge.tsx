import { statusLabel } from "@/lib/format";
import { THREAT_LABEL, bandLabel, threatTone } from "@/lib/score";

const STROKE: Record<string, string> = {
  safe: "#059669",
  watch: "#d97706",
  threat: "#e11d48",
  pending: "#5eead4",
};

const BAND_CHIP: Record<string, string> = {
  clean: "bg-emerald-50 text-emerald-800 border-emerald-200",
  low: "bg-teal-50 text-teal-800 border-teal-200",
  medium: "bg-amber-50 text-amber-800 border-amber-200",
  high: "bg-orange-50 text-orange-800 border-orange-200",
  critical: "bg-rose-50 text-rose-800 border-rose-200",
};

export function RiskGauge({
  score,
  band,
  status,
}: {
  score: number | null;
  band: string | null;
  status: string;
}) {
  const tone = threatTone(score);
  const radius = 58;
  const circ = 2 * Math.PI * radius;
  const shown = score === null ? 0 : Math.max(0, Math.min(100, score));
  const dash = (shown / 100) * circ;

  return (
    <div className="flex flex-col items-center">
      <div className="relative h-40 w-40">
        <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90">
          <circle cx="70" cy="70" r={radius} fill="none" stroke="#a7f3d0" strokeWidth="12" />
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={STROKE[tone]}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circ}`}
          />
        </svg>
        <div className="absolute inset-0 grid place-items-center text-center">
          {score === null ? (
            <span className="zg-title px-6 text-sm font-semibold">{statusLabel(status)}</span>
          ) : (
            <span>
              <span className="zg-accent block font-mono text-4xl font-semibold tracking-tight">
                {score}
              </span>
              <span className="zg-faint text-[11px] font-medium uppercase tracking-wider">
                / 100
              </span>
            </span>
          )}
        </div>
      </div>
      <p className="zg-title mt-2 text-sm font-semibold">{THREAT_LABEL[tone]}</p>
      <p className="zg-muted mt-1 text-xs">0–29 güvenli · 30–69 şüpheli · 70–100 yüksek tehdit</p>
      {band ? (
        <span
          className={`mt-3 inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${
            BAND_CHIP[band] ?? "border-slate-200 bg-slate-50 text-slate-600"
          }`}
        >
          Bant: {bandLabel(band)}
        </span>
      ) : null}
    </div>
  );
}
