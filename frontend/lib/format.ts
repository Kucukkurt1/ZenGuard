export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes === 0) return "0 KB";
  if (bytes < 1024) {
    const kb = Math.max(bytes / 1024, 0.01);
    return `${kb.toFixed(2)} KB`;
  }
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

export function fileExtension(name: string): string {
  const base = name.split(/[/\\]/).pop() ?? name;
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "uzantı yok";
  return base.slice(dot + 1).toLowerCase();
}

export function shortHash(sha256: string): string {
  if (sha256.length < 16) return sha256;
  return `${sha256.slice(0, 8)}…${sha256.slice(-6)}`;
}

export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("tr-TR", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export const STATUS_LABEL: Record<string, string> = {
  queued: "Kuyrukta",
  running: "Çalışıyor",
  completed: "Tamamlandı",
  failed: "Başarısız",
  rejected: "Reddedildi",
};

export function statusLabel(status: string): string {
  return STATUS_LABEL[status] ?? status;
}
