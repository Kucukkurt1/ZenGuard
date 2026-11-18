"use client";

import { useEffect, useState } from "react";
import { ApiError, getHealth, type HealthResponse } from "@/lib/api";

const LABELS = [
  { key: "api", label: "API" },
  { key: "db", label: "PostgreSQL" },
  { key: "redis", label: "Redis" },
  { key: "clamav", label: "ClamAV" },
] as const;

export function HealthPills() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function pull() {
      try {
        const next = await getHealth();
        if (cancelled) return;
        setHealth(next);
        setOffline(false);
      } catch (error) {
        if (cancelled) return;
        setOffline(true);
        if (!(error instanceof ApiError)) setHealth(null);
      }
    }

    pull();
    const timer = window.setInterval(pull, 10000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {LABELS.map((item) => {
        const value = offline ? "down" : health?.[item.key] ?? "unknown";
        const ok = value === "ok";
        const unknown = value === "unknown";
        return (
          <span
            key={item.key}
            className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-3 py-1.5 text-xs font-medium text-emerald-50 shadow-sm backdrop-blur-md"
          >
            <span
              className={`h-2 w-2 rounded-full ${
                ok
                  ? "bg-emerald-300 shadow-[0_0_10px_rgba(110,231,183,0.95)]"
                  : unknown
                    ? "bg-white/40"
                    : "bg-rose-400 shadow-[0_0_10px_rgba(251,113,133,0.9)]"
              }`}
            />
            {item.label}
          </span>
        );
      })}
    </div>
  );
}
