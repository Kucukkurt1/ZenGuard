"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { FileUp, LoaderCircle, ScanLine } from "lucide-react";
import { ApiError, uploadAnalysis } from "@/lib/api";
import { fileExtension, formatBytes } from "@/lib/format";

export function UploadDropzone() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [rescan, setRescan] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<"limit" | "generic" | null>(null);

  function take(next: File | null) {
    setFile(next);
    setError(null);
    setErrorKind(null);
  }

  async function submit() {
    if (!file || busy) return;
    setBusy(true);
    setError(null);
    setErrorKind(null);
    try {
      const created = await uploadAnalysis(file, rescan);
      router.push(`/analyses/${created.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 413) {
        setErrorKind("limit");
        setError(err.message);
      } else if (err instanceof ApiError) {
        setErrorKind("generic");
        setError(err.message);
      } else {
        setErrorKind("generic");
        setError("Yükleme tamamlanamadı.");
      }
      setBusy(false);
    }
  }

  return (
    <div className="rounded-3xl border border-white/15 bg-white/10 p-4 shadow-2xl shadow-emerald-950/30 backdrop-blur-lg sm:p-5">
      <label
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          take(event.dataTransfer.files?.[0] ?? null);
        }}
        className={`flex min-h-[210px] cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed px-4 py-8 text-center transition ${
          dragging
            ? "border-white bg-white/20 shadow-[0_0_40px_rgba(153,246,228,0.35)]"
            : "border-emerald-300/60 bg-emerald-950/20 hover:border-white hover:bg-white/10"
        }`}
      >
        <span className="mb-3 grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-emerald-300 to-cyan-300 text-emerald-950 shadow-lg shadow-cyan-900/30">
          <FileUp className="h-6 w-6" />
        </span>
        <span className="text-base font-semibold text-white">Dosyayı sürükleyin veya seçin</span>
        <span className="mt-1 text-sm text-emerald-100/80">Üst sınır 50 MiB · tüm dosya türleri</span>
        <input
          type="file"
          className="sr-only"
          onChange={(event) => take(event.target.files?.[0] ?? null)}
        />
      </label>

      {file ? (
        <div className="mt-4 flex flex-col gap-3 rounded-2xl border border-white/20 bg-white/10 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-white">{file.name}</p>
            <p className="text-xs text-emerald-100/80">
              {formatBytes(file.size)} · .{fileExtension(file.name)}
            </p>
          </div>
          <button
            type="button"
            onClick={() => take(null)}
            className="text-xs font-semibold text-cyan-100 underline-offset-2 hover:underline"
          >
            Kaldır
          </button>
        </div>
      ) : null}

      <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <label className="inline-flex items-center gap-2 text-sm text-emerald-50">
          <input
            type="checkbox"
            checked={rescan}
            onChange={(event) => setRescan(event.target.checked)}
            className="h-4 w-4 rounded border-white/40 bg-white/10 text-emerald-400 focus:ring-cyan-200"
          />
          Yeniden tara
        </label>
        <button
          type="button"
          disabled={!file || busy}
          onClick={submit}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-300 px-5 py-2.5 text-sm font-semibold text-emerald-950 shadow-lg shadow-cyan-900/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ScanLine className="h-4 w-4" />}
          {busy ? "Gönderiliyor" : "Dosyayı Tara"}
        </button>
      </div>

      {error ? (
        <p
          className={`mt-4 rounded-2xl border px-4 py-3 text-sm ${
            errorKind === "limit"
              ? "border-amber-200/40 bg-amber-100/90 text-amber-950"
              : "border-rose-200/40 bg-rose-100/90 text-rose-900"
          }`}
        >
          {errorKind === "limit" ? "Boyut sınırı. " : null}
          {error}
        </p>
      ) : null}
    </div>
  );
}
