"use client";

import { useEffect, useState } from "react";
import { ApiError, getHealth, type HealthResponse } from "@/lib/api";

export function useHealth() {
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

  return { health, offline };
}
