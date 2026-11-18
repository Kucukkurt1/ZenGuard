import { ShieldCheck } from "lucide-react";

export function BrandMark() {
  return (
    <div className="flex items-center gap-3">
      <span className="grid h-11 w-11 place-items-center rounded-xl bg-gradient-to-br from-emerald-300 via-teal-300 to-cyan-200 text-emerald-950 shadow-lg shadow-cyan-900/40">
        <ShieldCheck className="h-6 w-6" strokeWidth={2} />
      </span>
      <span className="leading-tight">
        <span className="block text-lg font-semibold tracking-tight text-white">ZenGuard</span>
        <span className="mt-0.5 inline-flex rounded-full border border-cyan-200/30 bg-white/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-100">
          Threat Intelligence & Sandbox
        </span>
      </span>
    </div>
  );
}
