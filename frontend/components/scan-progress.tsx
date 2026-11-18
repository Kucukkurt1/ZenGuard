export function ScanProgress({
  percent,
  stage,
  active,
}: {
  percent: number;
  stage: string;
  active: boolean;
}) {
  const width = Math.max(0, Math.min(100, percent));
  return (
    <div className="rounded-lg border border-emerald-200/80 bg-white/80 px-3 py-2.5">
      <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
        <span className="zg-title min-w-0 truncate font-semibold">
          {active ? stage || "Taranıyor" : "Tarama bitti"}
        </span>
        <span className="zg-accent shrink-0 font-mono text-sm font-semibold">{width}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-emerald-100">
        <div
          className={`h-full rounded-full bg-gradient-to-r from-emerald-500 to-teal-500 transition-all duration-500 ${
            active ? "animate-pulse" : ""
          }`}
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}
