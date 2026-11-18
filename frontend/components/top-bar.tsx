"use client";

import { FormEvent, useRef } from "react";
import { LoaderCircle, Moon, Search, Sun, Upload } from "lucide-react";
import { useTheme } from "@/components/theme";

export function TopBar({
  crumb,
  search,
  onSearch,
  onQuickUpload,
  uploading = false,
}: {
  crumb: string[];
  search?: string;
  onSearch?: (value: string) => void;
  onQuickUpload?: (file: File) => void;
  uploading?: boolean;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const { theme, toggle } = useTheme();

  function submitSearch(event: FormEvent) {
    event.preventDefault();
  }

  return (
    <header className="zg-topbar flex h-14 shrink-0 items-center gap-4 border-b px-4">
      <p className="zg-muted hidden min-w-0 shrink-0 text-sm sm:block">
        {crumb.map((part, index) => (
          <span key={part}>
            {index > 0 ? <span className="px-1.5 text-emerald-400/50">/</span> : null}
            <span className={index === crumb.length - 1 ? "zg-title font-medium" : ""}>
              {part}
            </span>
          </span>
        ))}
      </p>

      {onSearch ? (
        <form onSubmit={submitSearch} className="relative mx-auto w-full max-w-md">
          <Search className="zg-faint pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2" />
          <input
            value={search ?? ""}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="SHA-256 veya dosya adı"
            className="zg-input h-8 w-full rounded-md border pl-8 pr-3 font-mono text-xs outline-none placeholder:font-sans placeholder:text-emerald-200/40 focus:border-emerald-400"
          />
        </form>
        ) : (
        <div className="flex-1" />
      )}

      <button
        type="button"
        onClick={toggle}
        title={theme === "soft" ? "Koyu zümrüt moda geç" : "Yumuşak nane moda geç"}
        className="zg-line zg-muted inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border hover:text-emerald-300"
      >
        {theme === "soft" ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
      </button>

      {onQuickUpload ? (
        <>
          <input
            ref={inputRef}
            type="file"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              event.target.value = "";
              if (file) onQuickUpload(file);
            }}
          />
          <button
            type="button"
            disabled={uploading}
            onClick={() => inputRef.current?.click()}
            className="zg-btn inline-flex h-8 shrink-0 items-center gap-1.5 rounded-md px-3 text-xs font-semibold disabled:opacity-60"
          >
            {uploading ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
            Hızlı Dosya Yükle
          </button>
        </>
      ) : null}
    </header>
  );
}
