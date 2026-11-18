"use client";

import { AppShell } from "@/components/app-shell";

const LOREM =
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";

const QUESTIONS = [
  "Tarama bir dosyada ne arıyor?",
  "Temiz çıktı. Dosyayı açabilir miyim?",
  "Skor 90 görünüyor, ClamAV ise 0. Bu bir hata mı?",
  "0, düşük, orta, yüksek ve kritik ne demek?",
  "Adını virus koyduğum boş dosya neden temiz çıktı?",
  "Motorun gerçekten baktığını nasıl anlarım?",
  "Neden her dosyaya aynı uyarı yazılmıyor?",
  "Raporu nereden açarım?",
  "Tarama bitmeden skor boşsa dosya temiz midir?",
  "Yüklediğim dosya nereye gidiyor?",
];

export default function FaqPage() {
  return (
    <AppShell crumb={["Sıkça Sorulan Sorular"]}>
      <div className="h-full overflow-auto px-4 py-4">
        <h1 className="zg-title mb-4 text-lg font-semibold">Sıkça sorulan sorular</h1>
        <div className="max-w-3xl space-y-2">
          {QUESTIONS.map((question) => (
            <details key={question} className="zg-panel rounded-lg border px-4 py-3">
              <summary className="zg-title cursor-pointer text-sm font-semibold">{question}</summary>
              <p className="zg-muted mt-2 text-sm leading-relaxed">{LOREM}</p>
            </details>
          ))}
        </div>
      </div>
    </AppShell>
  );
}
