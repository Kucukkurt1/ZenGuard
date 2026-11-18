import type { AnalysisReport, FindingReason, ScoreComponent } from "@/lib/api";

export const COMPONENT_MAX = {
  clamav: 55,
  yara: 40,
  static: 15,
  archive: 10,
} as const;

export type ComponentKey = keyof typeof COMPONENT_MAX;

export const COMPONENT_LABEL: Record<ComponentKey, string> = {
  clamav: "ClamAV",
  yara: "YARA",
  static: "Statik",
  archive: "Arşiv",
};

export type ThreatTone = "safe" | "watch" | "threat" | "pending";

export function threatTone(score: number | null): ThreatTone {
  if (score === null || score === undefined) return "pending";
  if (score <= 29) return "safe";
  if (score <= 69) return "watch";
  return "threat";
}

export const THREAT_LABEL: Record<ThreatTone, string> = {
  safe: "Güvenli",
  watch: "Şüpheli",
  threat: "Yüksek tehdit",
  pending: "Skor bekleniyor",
};

export const BAND_LABEL: Record<string, string> = {
  clean: "Temiz",
  low: "Düşük",
  medium: "Orta",
  high: "Yüksek",
  critical: "Kritik",
};

export function bandLabel(band: string | null | undefined): string {
  if (!band) return "—";
  return BAND_LABEL[band] ?? band;
}

const TERMINAL = new Set(["completed", "failed", "rejected"]);

export function isTerminal(status: string): boolean {
  return TERMINAL.has(status);
}

export function componentOf(
  report: AnalysisReport | null | undefined,
  key: ComponentKey,
): ScoreComponent {
  const found = report?.score?.components?.[key];
  return {
    awarded: found?.awarded ?? 0,
    max: found?.max ?? COMPONENT_MAX[key],
    reasons: found?.reasons ?? [],
  };
}

export function collectFindings(report: AnalysisReport | null | undefined): FindingReason[] {
  if (!report?.score) return [];
  const keys: ComponentKey[] = ["clamav", "yara", "static", "archive"];
  return keys.flatMap((key) => componentOf(report, key).reasons ?? []);
}

export function isPolicyOverride(report: AnalysisReport | null | undefined): boolean {
  return report?.score?.mode === "policy_override";
}
