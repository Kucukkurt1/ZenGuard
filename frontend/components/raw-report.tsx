"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

export function RawReport({ value }: { value: unknown }) {
  const [open, setOpen] = useState(false);
  const text = value ? JSON.stringify(value, null, 2) : "{\n  \"report\": null\n}";

  return (
    <section className="overflow-hidden rounded-2xl border border-emerald-100 bg-white shadow-[0_24px_50px_-36px_rgba(6,78,59,0.45)]">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-center justify-between px-5 py-4 text-left"
      >
        <span>
          <span className="block text-sm font-semibold text-emerald-950">Ham JSON</span>
          <span className="block text-xs text-slate-500">Raporun tamamı</span>
        </span>
        <ChevronDown className={`h-4 w-4 text-teal-700 transition ${open ? "rotate-180" : ""}`} />
      </button>
      {open ? (
        <pre className="max-h-[420px] overflow-auto border-t border-emerald-50 bg-slate-950/95 px-5 py-4 text-xs leading-relaxed text-emerald-100">
          {text}
        </pre>
      ) : null}
    </section>
  );
}
