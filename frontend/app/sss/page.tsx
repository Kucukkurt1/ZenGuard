"use client";

import { AppShell } from "@/components/app-shell";

const QUESTIONS = [
  {
    q: "ZenGuard dosyaya nasıl karar veriyor?",
    a: "Dosya çalıştırılmaz. Dört bakış vardır. ClamAV, bilinen zararlı bayt kalıplarını arar (en fazla 55 puan). YARA, elimizdeki kuralların aradığı metinleri arar (en fazla 40). Statik analiz, programın yapısına bakar: makro, çift uzantı, paketleyici, yüksek entropi (en fazla 15). Arşiv politikası, zip bombası, dışarı yazma ve aşırı derinlik gibi durumlarda taramayı keser. Toplam 100'de kesilir. Dosya adı puana girmez.",
  },
  {
    q: "Temiz çıktı. Dosya kesin güvenli mi?",
    a: "Hayır. Sıfır puan, çalışan motorların eşleşme yazmadığı anlamına gelir. İmzası henüz olmayan bir zararlı görünmez. Dosya da çalıştırılıp ne yaptığı izlenmez. Beklemediğiniz bir eki, temiz çıksa bile açmayın. Windows Defender açık kalsın.",
  },
  {
    q: "virus.exe diye boş bir dosya attım, güvenli dedi. Bozuk mu?",
    a: "Karar dosyanın adına bakmaz. Not Defteri çoğu zaman dosyayı virus.exe.txt diye kaydeder ve içi boştur. Boş bir metinde imza, YARA eşleşmesi veya şüpheli bir yapı olmaz. Sonuç doğrudur. Gerçek bir deneme için EICAR metnini kullanın.",
  },
  {
    q: "Tehdit içeren bir dosyayı nasıl denerim?",
    a: "EICAR metnini kullanın. Zararsızdır, bütün antivirüsler onu test için tanır. Metin şudur: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* — Windows Defender bu dosyayı diske yazarken silebilir. Yazamıyorsanız metni doğrudan tarama kutusuna değil, proje klasöründen backend konteynerine gönderin. Raporda 'Bu bir virüs değil' yazması gerekir. Skor yüksek çıkar, çünkü motorlar metni tanıdı. Bu bir bulaşma değildir.",
  },
  {
    q: "Neden her şüpheli dosyaya aynı şeyi söylemiyorsunuz?",
    a: "Makrolu bir belge ile bilinen bir zararlı imzası aynı şey değildir. Makroda 'İçeriği Etkinleştir'e basmayın yeterlidir. Bilinen imzada, dosya zaten çalıştıysa şifreleri başka bir cihazdan değiştirmek gerekir. EICAR'da ise hiçbir temizleme gerekmez. Rapor, her bulgunun altına yalnızca o bulguya ait adımı yazar.",
  },
  {
    q: "YARA kuralları ne işe yarıyor? Menüden neden kalktı?",
    a: "YARA, dosyanın içinde belirli bir metin veya bayt kalıbı var mı diye bakan kurallardır. EICAR cümlesi ve gizlenmiş PowerShell kalıbı bu kurallarla bulunur. Eşleşen kural, puanı ve nerede durduğu raporun içinde yazılır. Kuralların düz listesi bir karar vermez, bu yüzden menüden kalktı.",
  },
  {
    q: "Raporlara nereden bakacağım?",
    a: "Analiz Geçmişi, taradığınız her dosyayı listeler. Satıra tıklayınca rapor ayrı bir sayfada açılır. Tarama Merkezi yalnızca yeni dosya yüklemek içindir. İkisi aynı sayfa değildir.",
  },
  {
    q: "Skor bantları ne demek?",
    a: "0 temiz. 1–24 düşük. 25–49 orta. 50–79 yüksek. 80–100 kritik. Bant, puanın hangi aralığa düştüğüdür. Yüksek bant her zaman 'virüs çalıştı' demek değildir. EICAR testinde de kritik çıkar, çünkü imza motoru onu bilerek tanır. Raporun başlığı bu ayrımı yazar.",
  },
  {
    q: "Tarama başarısız olursa dosya temiz mi?",
    a: "Hayır. Motor durursa skor boş bırakılır. Boş skor sıfır puan değildir. Sol alttaki ClamAV satırı down ise imza motoru kapalıdır. Ok olunca dosyayı yeniden yükleyin.",
  },
  {
    q: "Yüklediğim dosya nerede duruyor?",
    a: "Karantina klasöründe durur. ZenGuard onu çalıştırmaz, açmaz, ağda bir yere göndermez. Kayıt silinince, aynı dosyadan başka kayıt yoksa karantina kopyası da silinir.",
  },
];

export default function FaqPage() {
  return (
    <AppShell crumb={["Sıkça Sorulan Sorular"]}>
      <div className="h-full overflow-auto px-4 py-4">
        <div className="mb-4 max-w-2xl">
          <h1 className="zg-title text-lg font-semibold">Sıkça sorulan sorular</h1>
          <p className="zg-muted mt-1 text-sm">
            Skorun ne anlama geldiği, temiz kararının sınırı ve bir bulgu çıktığında neden her dosyaya aynı cevabın
            verilmediği.
          </p>
        </div>
        <div className="max-w-3xl space-y-2">
          {QUESTIONS.map((item) => (
            <details key={item.q} className="zg-panel group rounded-lg border px-4 py-3">
              <summary className="zg-title cursor-pointer text-sm font-semibold">{item.q}</summary>
              <p className="zg-muted mt-2 text-sm leading-relaxed">{item.a}</p>
            </details>
          ))}
        </div>
      </div>
    </AppShell>
  );
}
