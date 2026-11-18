"use client";

import { BlankPage } from "@/components/blank-page";

export default function QuarantinePage() {
  return (
    <BlankPage
      title="Karantina"
      names={["Karantinaya alınan dosyalar", "Geri yükle", "Kalıcı sil", "Karantina süresi"]}
    />
  );
}
