"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bell, CircleHelp, ClipboardList, FolderLock, History, ScanSearch, Settings, Users } from "lucide-react";
import { useHealth } from "@/components/use-health";

const NAV = [
  { href: "/", label: "Tarama Merkezi", icon: ScanSearch },
  { href: "/history", label: "Analiz Geçmişi", icon: History },
  { href: "/karantina", label: "Karantina", icon: FolderLock },
  { href: "/denetim", label: "Denetim kaydı", icon: ClipboardList },
  { href: "/kullanicilar", label: "Kullanıcılar", icon: Users },
  { href: "/bildirimler", label: "Bildirimler", icon: Bell },
  { href: "/ayarlar", label: "Ayarlar", icon: Settings },
  { href: "/sss", label: "Sıkça Sorulan Sorular", icon: CircleHelp },
];

const SERVICES = [
  { key: "api", label: "API" },
  { key: "db", label: "PostgreSQL" },
  { key: "redis", label: "Redis" },
  { key: "clamav", label: "ClamAV" },
] as const;

function active(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  if (href === "/history") return pathname === "/history" || pathname.startsWith("/analyses");
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function Sidebar() {
  const pathname = usePathname();
  const { health, offline } = useHealth();

  return (
    <aside className="zg-sidebar flex h-screen w-64 shrink-0 flex-col border-r border-emerald-900/40 text-white">
      <div className="border-b border-white/10 px-3 py-3">
        <img
          src="/logo.jpg"
          alt="ZenGuard"
          className="h-20 w-full rounded-lg object-cover object-center"
        />
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
        {NAV.map((item) => {
          const on = active(pathname, item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm ${
                on
                  ? "border-l-2 border-emerald-400 bg-gradient-to-r from-emerald-600/30 to-teal-600/20 text-white"
                  : "border-l-2 border-transparent text-emerald-100/80 hover:bg-white/5 hover:text-white"
              }`}
            >
              <item.icon className="h-4 w-4 shrink-0" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-white/10 px-3 pb-16 pt-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-teal-200/70">
          Motorlar
        </p>
        <ul className="space-y-1.5">
          {SERVICES.map((service) => {
            const value = offline ? "down" : health?.[service.key] ?? "unknown";
            const ok = value === "ok";
            return (
              <li key={service.key} className="flex items-center justify-between text-xs text-emerald-100/90">
                <span>{service.label}</span>
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      ok ? "bg-emerald-400" : value === "unknown" ? "bg-white/30" : "bg-rose-400"
                    }`}
                  />
                  {ok ? "ok" : value === "unknown" ? "…" : "down"}
                </span>
              </li>
            );
          })}
        </ul>
      </div>
    </aside>
  );
}
