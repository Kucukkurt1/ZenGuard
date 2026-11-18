"use client";

import { BlankPage } from "@/components/blank-page";

export default function SettingsPage() {
  return (
    <BlankPage
      title="Ayarlar"
      names={["Tema", "Dil", "En büyük dosya boyutu", "Karantina süresi", "Oturum süresi", "E-posta bildirimi"]}
    />
  );
}
