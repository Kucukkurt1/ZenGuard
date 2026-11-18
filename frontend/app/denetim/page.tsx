"use client";

import { BlankPage } from "@/components/blank-page";

export default function AuditPage() {
  return (
    <BlankPage
      title="Denetim kaydı"
      names={["Oturum açma", "Dosya yükleme", "Tarama", "Kayıt silme", "Ayar değişikliği"]}
    />
  );
}
