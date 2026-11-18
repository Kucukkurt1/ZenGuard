"use client";

import { SiteHeader } from "@/components/site-header";
import { UploadDropzone } from "@/components/upload-dropzone";
import { KpiStrip } from "@/components/kpi-strip";
import { AnalysisHistory } from "@/components/analysis-history";

export function Dashboard() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50/90 via-teal-50/50 to-white">
      <section className="hero-surface relative overflow-hidden text-white">
        <div className="pointer-events-none absolute -left-24 top-10 h-72 w-72 rounded-full bg-emerald-400/20 blur-3xl" />
        <div className="pointer-events-none absolute right-0 top-0 h-80 w-80 rounded-full bg-cyan-300/20 blur-3xl" />
        <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <SiteHeader />
          <div className="grid items-center gap-8 pb-20 pt-2 lg:grid-cols-[minmax(0,1fr)_minmax(420px,0.9fr)] lg:pb-24">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-100/90">
                Kurumsal tehdit operasyonları
              </p>
              <h1 className="mt-3 max-w-xl text-4xl font-semibold leading-tight tracking-tight text-white sm:text-5xl">
                Dosyayı tarayın.
                <span className="mt-1 block text-emerald-100">Riski gerekçesiyle görün.</span>
              </h1>
              <p className="mt-4 max-w-lg text-sm leading-relaxed text-emerald-50/85 sm:text-base">
                Örnek yerelde özetlenir, kuyruğa alınır ve birleşik skor hazır olunca
                aynı konsolda açılır. ClamAV, YARA ve kum havuzu tek hatta durur.
              </p>
              <div className="mt-6 flex flex-wrap gap-2 text-xs font-semibold text-emerald-50">
                {["SHA-256", "Kuyruk", "İmza", "0–100 skor"].map((item) => (
                  <span
                    key={item}
                    className="rounded-full border border-white/20 bg-white/10 px-3 py-1 backdrop-blur-md"
                  >
                    {item}
                  </span>
                ))}
              </div>
            </div>
            <UploadDropzone />
          </div>
        </div>
      </section>

      <main className="relative z-10 mx-auto -mt-12 max-w-7xl space-y-8 px-4 pb-16 sm:px-6 lg:px-8">
        <KpiStrip />
        <AnalysisHistory />
      </main>
    </div>
  );
}
