import type { AnalysisDetail, FindingReason } from "@/lib/api";
import { bandLabel } from "@/lib/score";

export type ActionStep = {
  title: string;
  detail: string;
};

export type FindingStory = {
  key: string;
  engine: string;
  title: string;
  where: string;
  points: number;
  why: string;
  means: string;
  steps: ActionStep[];
  headline?: string;
  situation?: string;
};

export type Narrative = {
  headline: string;
  lead: string;
  stories: FindingStory[];
  situation: string;
};

const SEVERITY_TR: Record<string, string> = {
  info: "bilgi",
  low: "düşük",
  medium: "orta",
  high: "yüksek",
  critical: "kritik",
};

function whereOf(reason: FindingReason): string {
  return reason.member_path?.trim() || "Yüklenen dosyanın kendisi";
}

function signatureOf(reason: FindingReason): string {
  const value = reason.evidence?.signature;
  return typeof value === "string" ? value : "";
}

function isEicar(reason: FindingReason): boolean {
  const rule = (reason.rule || reason.code || "").toLowerCase();
  if (rule === "eicar" || rule === "eicar_test") return true;
  return /eicar/i.test(signatureOf(reason));
}

function eicarStory(reasons: FindingReason[]): FindingStory {
  const engines = new Set<string>();
  let clam = 0;
  let yara = 0;
  for (const reason of reasons) {
    if (reason.code === "malware_signature" || reason.code === "pua_heuristic") {
      clam += reason.points ?? 0;
      engines.add("ClamAV");
    } else {
      yara += reason.points ?? 0;
      engines.add("YARA");
    }
  }
  const points = clam + Math.min(40, yara);
  const names = [...engines].join(" ve ");
  return {
    key: "eicar",
    engine: names,
    title: "EICAR test metni",
    where: whereOf(reasons[0]),
    points,
    why:
      "Dosyanın içinde, antivirüslerin birbirini denemek için kullandığı standart EICAR cümlesi var. " +
      "Bu cümle bir program değildir. Çalıştırılsa bile bir işlem başlatmaz. " +
      `${names} bu metni tanıdığı için puan yazdı. ` +
      "Aynı analizde YARA payı 40 puanda kesilir; birden fazla EICAR kuralı skoru iki kez şişirmez. " +
      "ClamAV payı ise imza puanıdır ve 55'tir.",
    means:
      "Bilgisayarınızda bir bulaşma olduğu anlamına gelmez. ZenGuard'ın imza motorunun çalıştığını gösterir. " +
      "Dosyayı başkasına gönderirseniz onların antivirüsü de alarm verir, çünkü metin bilerek bu iş için yazılmıştır.",
    steps: [
      {
        title: "Bilgisayarı bu dosya yüzünden temizlemeyin",
        detail:
          "Tam tarama, şifre değiştirme veya ağ kablosunu çekmek gerekmez. Dosya kasıtlı bir testtir.",
      },
      {
        title: "Testi bitirdiyseniz dosyayı silin",
        detail:
          "Diskte durursa Windows Defender da onu karantinaya alabilir. Silmek güvenlidir.",
      },
      {
        title: "Başkasına göndermeyin",
        detail:
          "Karşı tarafın antivirüsü dosyayı gerçek bir alarm gibi gösterir ve posta kutusu kilidi yiyebilir.",
      },
    ],
  };
}

function malwareStory(reason: FindingReason): FindingStory {
  const signature = signatureOf(reason) || "adsız imza";
  return {
    key: `malware:${signature}`,
    engine: "ClamAV",
    title: `Bilinen zararlı imza: ${signature}`,
    where: whereOf(reason),
    points: reason.points ?? 55,
    why:
      `ClamAV, dosyanın baytlarında "${signature}" imzasıyla eşleşen bir dizi buldu. ` +
      "İmza, daha önce zararlı olarak sınıflanmış bir dosya ailesinden alınmış kısa bir bayt kalıbıdır. " +
      "ZenGuard dosyayı çalıştırmaz; karar, dosyanın içeriğindeki bu kalıba dayanır. " +
      "Dosya adı bu karara girmez. Kalıp hangi bayt aralığında duruyorsa bulgu oradadır: " +
      whereOf(reason) +
      ".",
    means:
      "Bu, sezgi değil, bilinen bir zararlıyla eşleşmedir. İmza adı aileyi söyler. " +
      "Dosyanın ekranda ne göstereceğini veya kime bağlanacağını bu tarama söylemez, çünkü dosya çalıştırılmadı.",
    steps: [
      {
        title: "Dosyayı açmayın ve çalıştırmayın",
        detail:
          "Çift tıklamayın, arşivden dışarı çıkarmayın, e-postada yeniden eklemeyin. ZenGuard dosyayı karantinada tutar ve çalıştırmaz.",
      },
      {
        title: "Zaten çalıştırdıysanız bağlantıyı kesin",
        detail:
          "İnterneti kapatın. Banka, posta ve iş hesaplarının şifresini bu bilgisayardan değil, telefonunuzdan veya başka bir temiz cihazdan değiştirin. Oturum açık kalan tarayıcıyı de kullanmayın.",
      },
      {
        title: "Windows Güvenliği ile tam tarama yaptırın",
        detail:
          `İmza adı "${signature}". Defender veya kullandığınız antivirüs aynı aileyi başka dosyalarda da aramalı. Yalnızca bu dosyayı silmek, çalıştıysa yetmeyebilir.`,
      },
      {
        title: "E-postayla geldiyse gönderene güvenmeyin",
        detail:
          "Gönderen tanıdık olsa bile cevap yazıp eki açmayın. Hesabı ele geçirilmiş olabilir. Konuyu telefon veya başka bir kanal üzerinden sorun.",
      },
    ],
  };
}

function puaStory(reason: FindingReason): FindingStory {
  const signature = signatureOf(reason) || "PUA";
  return {
    key: `pua:${signature}`,
    engine: "ClamAV",
    title: `İstenmeyen yazılım işareti: ${signature}`,
    where: whereOf(reason),
    points: reason.points ?? 25,
    why:
      `ClamAV bu dosyayı "${signature}" olarak işaretledi. PUA (potentially unwanted application), ` +
      "virüs imzası değildir. Reklam yazılımı, tarayıcı eklentisi, paketleyici veya kullanıcıya haber vermeden kurulan bir araç olabilir. " +
      "Puan 25'tir ve tek başına dosyayı kritik banda taşımaz.",
    means:
      "Dosya yasa dışı bir zararlı olmak zorunda değil. Yine de siz bilerek kurmadıysanız istenmeyen bir şey yapıyor olabilir: ana sayfa değiştirmek, ek program kurmak, reklam göstermek.",
    steps: [
      {
        title: "Kurmayı siz istemediyseniz çalıştırmayın",
        detail:
          "İndirme klasöründeyse silin. Kurulum sihirbazı açıksa İptal deyin, 'ek öneriler' kutularını işaretlemeyin.",
      },
      {
        title: "Bilerek indirdiyseniz yayımcıyı doğrulayın",
        detail:
          "Resmi sitenin adresiyle indirdiğiniz adresi karşılaştırın. Reklamlı bir aynadan geldiyse resmi kopyayı yeniden indirin.",
      },
    ],
  };
}

const YARA_KNOWN: Record<
  string,
  { title: string; why: string; means: string; steps: ActionStep[]; headline?: string; situation?: string }
> = {
  suspicious_powershell: {
    title: "Gizlenmiş PowerShell komutu",
    headline: "İndirici betik kalıbı. Çalışan bir truva atı değil.",
    situation:
      "Dosya bir program değil. Metninde PowerShell ile gizlenmiş indirme kalıbı var. Gerçek bir truva atı bu kalıpla ikinci bir dosya indirir.",
    why:
      "YARA kuralı dosyada hem 'powershell' hem de gizleme veya indirme kalıplarından birini gördü: " +
      "-enc, -encodedcommand, -executionpolicy bypass, -windowstyle hidden, Invoke-Expression, DownloadString veya Invoke-WebRequest. " +
      "Kuralın önemi yüksek olduğu için 20 puan yazar. Aynı kural adı bu dosyada bir kez sayılır.",
    means:
      "Birisi betiğin ne yaptığı okunmasın diye komutu kodlamış veya PowerShell'in güvenlik ilkesini kapatmış olabilir. " +
      "Yöneticilerin kullandığı meşru bir kurulum betiği de aynı kelimeleri taşıyabilir. Fark, dosyayı siz mi yazdığınızda.",
    steps: [
      {
        title: "Betiği çalıştırmadan önce düz metin olarak okuyun",
        detail:
          "Not Defteri ile açın. -enc ile başlayan uzun bir blok görürseniz komut gizlenmiştir. Ne yaptığını bilmiyorsanız çalıştırmayın.",
      },
      {
        title: "E-posta veya sohbetten geldiyse silin",
        detail:
          "Fatura, kargo veya 'hesabınız kilitlendi' mesajına ekli bir betik beklenen bir dosya değildir. Gönderen tanıdık görünse bile eki açmayın.",
      },
      {
        title: "Siz yazdıysanız gizlemeyi kaldırın",
        detail:
          "ExecutionPolicy bypass ve pencere gizleme, betiği denetimden kaçırır. Komutları açık yazın ki sonraki tarama da sizin betiğinizi okuyabilsin.",
      },
    ],
  },
  benign_static_marker: {
    title: "ZenGuard deneme işareti",
    why:
      "Dosyada ZENG_BENIGN_STATIC_MARKER metni var. Bu metni yalnızca ZenGuard'ın kendi deneme kuralı arar. Zararlı bir aileye ait değildir.",
    means: "Orta önemde bir kural olduğu için puana katkısı sınırlıdır. Gerçek bir tehdit kararı değildir.",
    steps: [
      {
        title: "Ek bir işlem yapmayın",
        detail: "Bu işaret bir testi işaretler. Dosyada başka bulgu yoksa çalıştırmanızın önünde bu kural durmaz.",
      },
    ],
  },
  fixture_keylogger: {
    title: "Klavye dinleme kalıbı",
    headline: "Keylogger kalıbı bulundu. Bu dosya tuşları kaydetmiyor.",
    situation:
      "Dosya düz metin. İçinde klavye dinlemek için kullanılan iki API adı ve ZenGuard deneme işareti var. Çalışan bir keylogger değil.",
    why:
      "Kural, ZENG_FIXTURE_KEYLOGGER işaretini GetAsyncKeyState ve SetWindowsHookEx adlarıyla birlikte aradı. " +
      "Bu iki ad, bir programın tuşları okumak veya klavye kancası kurmak için kullandığı Windows çağrılarıdır. " +
      "Burada yalnızca metin olarak duruyorlar. Kuralın önemi kritik olduğu için 40 puan yazar. ClamAV bir zararlı ailesi adı yazmadı.",
    means:
      "Gerçek bir keylogger bu çağrıları bir programın içinde yapar ve yazdığınız parolaları dışarı gönderir. " +
      "Bu kopya o program değil. Rapor, aynı kalıp gerçek bir dosyada çıksaydı ne yapacağınızı göstermek için duruyor.",
    steps: [
      {
        title: "Bu deneme dosyasını çalıştırmayın, silmeniz yeterli",
        detail:
          "Metin bir program başlatmaz. Testi bitirdiyseniz kaydı ve dosyayı silin. Bilgisayarı bu dosya yüzünden temizlemeniz gerekmez.",
      },
      {
        title: "Aynı kalıp tanıdığınız bir programda çıkarsa onu çalıştırmayın",
        detail:
          "İmzası olmayan bir .exe içinde bu iki API varsa tuşları okuyor olabilir. Kaynağını bilmiyorsanız açmayın.",
      },
      {
        title: "Gerçek bir keylogger çalıştıysa parolaları başka cihazdan değiştirin",
        detail:
          "Posta, banka ve iş hesaplarının şifresini bu bilgisayardan değil, telefonunuzdan değiştirin. Windows'ta başlangıç klasörüne ve zamanlanmış görevlere tanımadığınız bir kayıt var mı bakın.",
      },
    ],
  },
  fixture_ransom_note: {
    title: "Fidye notu metni",
    headline: "Fidye notu metni. Dosyalarınız bu denemeyle şifrelenmedi.",
    situation:
      "Dosya bir not. Şifreleme programı yok, bitcoin adresi yok, diske dokunulmadı. Metin, fidye notlarının kullandığı cümleleri denemek için yazıldı.",
    why:
      "Kural, ZENG_FIXTURE_RANSOM işaretini 'dosyalarınız şifrelendi' ve 'bitcoin' kelimeleriyle birlikte gördü. " +
      "Fidye yazılımı kurbanın ekranına bu tür bir not bırakır. Bu dosya o yazılım değil, notun kendisi. Kritik önem 40 puan yazar.",
    means:
      "Notu okumak dosyaları şifrelemez. Gerçek bir olayda not, şifreleme bittikten sonra bırakılır. Ödeme, anahtarı getirmenin garantisi değildir.",
    steps: [
      {
        title: "Bu deneme notu için ödeme yapmayın ve ağı kesmeyin",
        detail: "Hiçbir dosyanız şifrelenmedi. Notu silmeniz yeterli.",
      },
      {
        title: "Gerçek bir not görürseniz bitcoin göndermeyin",
        detail:
          "Notu kapatıp ödeme sitesini açmayın. İnterneti kesin, dosyaları yeniden adlandırmayın ve yedekten dönmeden önce neyin şifrelendiğini yazın.",
      },
      {
        title: "Gerçek bir olayda başka bir bilgisayardan yardım isteyin",
        detail:
          "Aynı ağdaki disklere dokunmayın. Yedeğiniz varsa şifrelenmiş makineyi açmadan önce yedeğin de şifrelenmediğini kontrol edin.",
      },
    ],
  },
};

function yaraStory(reason: FindingReason): FindingStory {
  const rule = reason.rule || reason.code || "yara";
  const known = YARA_KNOWN[rule];
  const severity = SEVERITY_TR[reason.severity || "medium"] || reason.severity || "orta";
  if (known) {
    return {
      key: `yara:${rule}`,
      engine: "YARA",
      title: known.title,
      where: whereOf(reason),
      points: reason.points ?? 0,
      why: `${known.why} Eşleşme yeri: ${whereOf(reason)}.`,
      means: known.means,
      steps: known.steps,
      headline: known.headline,
      situation: known.situation,
    };
  }
  return {
    key: `yara:${rule}`,
    engine: "YARA",
    title: `YARA kuralı: ${rule}`,
    where: whereOf(reason),
    points: reason.points ?? 0,
    why:
      `YARA, dosyada önceden yazılmış bir metin veya bayt kalıbı arar. "${rule}" kuralı eşleşti. ` +
      `Kuralın önemi ${severity}. Puan cetveli: bilgi 0, düşük 5, orta 10, yüksek 20, kritik 40. ` +
      "Aynı kural adı bu analizde bir kez sayılır, YARA'nın toplam payı 40'ı geçmez. " +
      `Eşleşen üye: ${whereOf(reason)}.`,
    means:
      "Kural eşleşmesi, dosyanın o kalıbı taşıdığını söyler. Kalıp zararlı bir aileye ait de olabilir, sizin koyduğunuz bir metin de. " +
      "Kuralın tam olarak hangi metni aradığını rules/yara klasöründeki aynı adlı dosyada görebilirsiniz.",
    steps: [
      {
        title: "Kuralın aradığı metni okuyun",
        detail: `"${rule}" kuralını açın. Aradığı dize sizin koyduğunuz bir kelimeyse bu bir yanlış alarmdır. Değilse dosyayı çalıştırmayın.`,
      },
      {
        title: "Kaynağını bilmiyorsanız çalıştırmayın",
        detail:
          "E-posta eki, indirme veya mesajdan gelen bir dosyada tanımadığınız bir kural eşleşmesi, dosyayı açmak için yeterli sebep değildir.",
      },
    ],
  };
}

const STATIC: Record<
  string,
  { title: string; why: string; means: string; steps: ActionStep[]; headline?: string; situation?: string }
> = {
  entropy_high: {
    title: "İçerik sıkıştırılmış veya şifrelenmiş görünüyor",
    why:
      "Dosyanın bayt dağılımı çok düzensiz (entropi 7.2 ve üzeri) ve dosya en az 4 KB. " +
      "Düz metin ve sıradan belgeler bu kadar düzensiz olmaz. Paketlenmiş bir program, şifreli bir gövde veya gömülü bir yük bu görüntüyü verir.",
    means:
      "Tek başına virüs kanıtı değildir. Kurulum dosyaları da paketlenir. Kaynağını bilmediğiniz bir dosyada ise içindeki asıl program gizlenmiş olabilir.",
    steps: [
      {
        title: "Tanımadığınız bir programsa çalıştırmayın",
        detail:
          "Paketleyici, asıl kodu tarayıcıdan saklar. Yayımcıyı doğrulamadan çalıştırmayın.",
      },
    ],
  },
  packer_section: {
    title: "Paketleyici bölümü",
    why:
      "Dosya bir Windows programı ve içinde UPX, ASPack, MPRESS veya PECompact gibi bir paketleyicinin bölüm adı var. " +
      "Paketleyici programı küçültür; zararlılar da aynı aracı analizden kaçmak için kullanır.",
    means:
      "UPX ile paketlenmiş meşru programlar da vardır. Bu bulgu 'bu bir virüs' demez, 'içerik düz haliyle durmuyor' der.",
    steps: [
      {
        title: "Kaynağı doğrulayın",
        detail:
          "Resmi siteden inen bir kurulumsa paketli olması normaldir. Tanımadığınız bir ekteyse açmayın.",
      },
    ],
  },
  double_extension: {
    title: "Çift uzantı",
    headline: "Dosya adı belge gibi duruyor, son uzantı program.",
    situation:
      "Bu bir virüs imzası değil. Adın kendisi yanıltıcı. Gerçek tür en sondaki uzantıdır. İçerik ayrıca taranır.",
    why:
      "Dosya adında iki uzantı var ve sondaki uzantı çalıştırılabilir bir tür (.exe, .scr, .js, .bat ve benzeri), ondan önceki ise belge gibi duruyor. " +
      "Windows varsayılan olarak bilinen uzantıyı gizlediğinde kullanıcı yalnızca ilk adı görür.",
    means:
      "Adı fatura.pdf olan dosya aslında bir program olabilir. Gerçek tür, en sondaki uzantıdır.",
    steps: [
      {
        title: "Açmayın",
        detail:
          "Belge beklerken program gelmiş demektir. Gönderenden dosyayı yeniden ve tek uzantıyla isteyin. Gelen kutusu üzerinden 'uzantıyı göster' açık olsun.",
      },
    ],
  },
  office_macro: {
    title: "Belgede makro var",
    headline: "Belgenin içinde makro izi var. Makro henüz çalışmadı.",
    situation:
      "Office belgesi açılıp içerik etkinleştirilmeden makro kodu çalışmaz. Bu kopya çalışan bir makro değil; gövdede makro projesinin adı duruyor.",
    why:
      "Dosya bir Office belgesi ve içinde VBA projesi duruyor (vbaProject.bin veya _VBA_PROJECT). " +
      "Makro, belge açılıp içerik etkinleştirilince kod çalıştırır.",
    means:
      "Makro her zaman zararlı değildir. Muhasebe şablonları makro taşıyabilir. Beklemediğiniz bir fatura veya kargo belgesi makro taşıyorsa bu, belgenin asıl işi değildir.",
    steps: [
      {
        title: "İçeriği Etkinleştir'e basmayın",
        detail:
          "Word veya Excel korumalı görünümde açarsa sarı çubuktaki düğmeyi kullanmayın. Makro çalışmadan belgeyi okuyabilirsiniz.",
      },
      {
        title: "Makroyu bekliyorsanız göndereni başka kanaldan doğrulayın",
        detail:
          "Aynı e-postadaki 'lütfen makroyu açın' cümlesine güvenmeyin. Kişiyi telefonla veya bilinen bir adresten sorun.",
      },
    ],
  },
  pe_rwe_section: {
    title: "Hem yazılabilen hem çalıştırılabilen bölüm",
    why:
      "Windows programının bir bölümünde hem yazma hem çalıştırma izni var. Normal programlar kodu çalıştırır, veriyi ayrı yerde tutar. " +
      "İkisi bir aradaysa program çalışma anında kendi kodunu değiştirebilir. Bu, çözülen (unpack) zararlılarda sık görülür.",
    means:
      "Dosya henüz çalışmadı. Bulgu, dosyanın bu şekilde derlendiğini söyler.",
    steps: [
      {
        title: "Çalıştırmayın",
        detail:
          "Yayımcısı olmayan bir programda bu izin, kodun gizlendiğini düşündürür. Kaynak doğrulanmadan açmayın.",
      },
    ],
  },
  pe_tls_callback: {
    title: "Program başlamadan kod çalışacak",
    why:
      "Dosyanın TLS dizininde bir geri çağrı var. Windows, programın asıl giriş noktasından önce bu kodu çalıştırır. " +
      "Zararlılar asıl işi burada yapıp giriş noktasını masum gösterir.",
    means:
      "Çift tıklama, gördüğünüz 'ana program'dan önce başka bir kodun çalışması demektir.",
    steps: [
      {
        title: "Çalıştırmayın",
        detail:
          "Ne yaptığını görmek için dosyayı açmak, o kodu da çalıştırır. Statik rapor yeterli değilse dosyayı ayrı bir ortamda inceleyin, kendi oturumunuzda değil.",
      },
    ],
  },
  pe_no_imports: {
    title: "Program dışarıdan hiçbir işlev çağırmıyor",
    why:
      "Çalıştırılabilir bir Windows dosyasında içe aktarma tablosu boş. Normal bir program en azından sistemden işlev çağırmak zorundadır. " +
      "Tablo boşsa çağrılar sonradan, çalışma anında kuruluyor demektir. Paketlenmiş zararlılar böyle gizlenir.",
    means:
      "Dosya bir program gibi duruyor ama sistemi nasıl kullanacağı baştan görünmüyor.",
    steps: [
      {
        title: "Çalıştırmayın",
        detail: "İçe aktarma tablosu boş bir dosyayı, yayımcısını bilmeden açmayın.",
      },
    ],
  },
  script_exec: {
    title: "Betik başka bir komut çalıştırıyor",
    why:
      "Dosya bir betik ve gövdesinde komut çalıştıran bir kalıp var: PowerShell, cmd.exe, WScript.Shell, CreateObject, eval, FromBase64String, DownloadString, os.system veya /bin/sh. " +
      "Kalıp, betiğin kendi metninin dışında bir şey başlatacağını gösterir.",
    means:
      "Betik okunmadan çalıştırılırsa indirme yapabilir veya başka bir program açabilir. Her betik zararlı değildir; kurulum betikleri de bu kelimeleri kullanır.",
    steps: [
      {
        title: "Önce metin olarak okuyun",
        detail:
          "Çift tıklamayın. Not Defteri ile açıp indirme adresi ve çalıştırdığı dosya adını bulun. Adresi tanımıyorsanız çalıştırmayın.",
      },
    ],
  },
  encrypted_archive: {
    title: "Arşiv şifreli, içi okunamadı",
    why:
      "Arşivin bir üyesi parola istiyor. ZenGuard parolayı kırmaya çalışmaz. İçerideki dosyalar listelenmedi ve taranmadı. " +
      "Bu yüzden kapsam kısmi: 'temiz' kararı şifreli üyeyi kapsamaz.",
    means:
      "Şifreli arşiv, taramadan kaçmak için kullanılır. Tanıdığınız birinin gönderdiği meşru bir dosya da olabilir.",
    steps: [
      {
        title: "Parolayı e-postanın içinden kopyalamayın",
        detail:
          "Parola aynı iletide yazıyorsa bu, tarayıcıyı atlatmak için kurulmuş bir düzendir. Parolayı önceden bildiğiniz bir kanaldan doğrulayın.",
      },
      {
        title: "Açmadan önce gönderene sorun",
        detail:
          "Beklemediğiniz bir şifreli arşivi açmayın. Açarsanız çıkan dosyayı yeniden ZenGuard'a yükleyin. Bu tarama içini görmedi.",
      },
    ],
  },
  extension_mismatch: {
    title: "Uzantı ile içerik uyuşmuyor",
    why:
      "Dosya adının uzantısı bir tür söylüyor, dosyanın başındaki baytlar başka bir tür. Örneğin adı .txt olan bir dosyanın içi ZIP olabilir.",
    means:
      "Ada güvenilmez. Sistem dosyayı uzantıya göre açarsa yanlış program çalışır veya arşiv belge sanılır.",
    steps: [
      {
        title: "Ada göre açmayın",
        detail:
          "Rapordaki gerçek türe bakın. Beklediğiniz tür değilse gönderenden dosyayı yeniden isteyin.",
      },
    ],
  },
  nested_depth_max: {
    title: "Arşiv iç içe, sınırda",
    why:
      "Arşivin içinde arşiv var ve derinlik izin verilen son kata (3) dayanmış. Daha derini açılmadı. Boş bir iç arşiv puan alır, dolu bir iç arşiv taramayı reddeder.",
    means:
      "Derin iç içe arşiv, tarayıcıların sabrını tüketmek için kullanılır. Meşru yedekler de katmanlı olabilir.",
    steps: [
      {
        title: "Hepsini birden dışarı dökmeyin",
        detail:
          "Kaynağı bilmiyorsanız arşivi açmayın. Açmanız gerekiyorsa her katmanı ayrı ayrı yeniden taratın.",
      },
    ],
  },
  high_file_count: {
    title: "Arşivde çok sayıda dosya var",
    why:
      "Arşivde 100'den fazla dosya üyesi var, üst sınır olan 200'ün altında. Çok üye, tek bir zararlıyı kalabalığın içine gizleyebilir.",
    means:
      "Kalabalık tek başına zararlı demek değildir. Yine de hepsini gözden geçirmeden çalıştırmayın.",
    steps: [
      {
        title: "Üye listesine bakın",
        detail:
          "Rapordaki dosya listesinde beklemediğiniz .exe, .js veya çift uzantı var mı kontrol edin. Varsa arşivi toplu açmayın.",
      },
    ],
  },
  suspicious_ratio: {
    title: "Sıkıştırma oranı çok yüksek",
    why:
      "Açılan bayt, sıkıştırılmış boyunun en az 100 katı. 1000 katına çıkınca tarama zip bombası sayıp durur. Bu dosya o sınırın altında kaldığı için açıldı ve işaretlendi.",
    means:
      "Yüksek oran, ya çok tekrarlı masum bir dosyadır ya da diski doldurmak üzere hazırlanmış bir arşivin eşiğidir.",
    steps: [
      {
        title: "Büyük bir diske güvenerek açmayın",
        detail:
          "Kaynağı yoksa arşivi açmayın. Açmanız gerekiyorsa çıktının boyutunu izleyin, diski doldurursa durdurun.",
      },
    ],
  },
  static_error: {
    title: "Bir üye statik olarak okunamadı",
    why:
      "Bir üyenin yapısı okunurken hata oldu. Bu hata taramayı düşürmez. O üye için statik puan yazılmaz ve kapsam kısmi kalır.",
    means: "O üye hakkında 'temiz' denemez. Diğer üyeler taranmış olabilir.",
    steps: [
      {
        title: "O üyeyi ayrıca ele alın",
        detail:
          "Hata veren yolu rapordan bulun. Arşivden tek başına çıkarıp yeniden yükleyin. Çıkmıyorsa arşivi açmayın.",
      },
    ],
  },
};

const POLICY: Record<string, { title: string; why: string; means: string; steps: ActionStep[] }> = {
  ZIP_BOMB: {
    title: "Zip bombası",
    why:
      "Açılırken sıkıştırılmış boyunun 1000 katı ve daha fazlası yazılmak istendi. ZenGuard yazmayı kesti, klasörü sildi ve motorları çalıştırmadı. " +
      "Skor bu yüzden 100 ve bant kritik. Bu bir imza eşleşmesi değil, politika durdurmasıdır.",
    means: "Arşiv, açan aracın diskini doldurmak için hazırlanmış olabilir. İçinde ne olduğu bilinmiyor.",
    steps: [
      {
        title: "Arşivi hiçbir araçla açmayın",
        detail:
          "Windows Gezgini, 7-Zip veya WinRAR ile açmak aynı şişmeyi sizin diskinizde yapar. Dosyayı silin.",
      },
    ],
  },
  SIZE_LIMIT: {
    title: "Açılmış boyut sınırı aşıldı",
    why:
      "Arşivin açılmış hali 100 MiB sınırını geçti. Sınır, başlıktaki iddiaya göre değil, gerçekten yazılan bayta göre uygulandı. Motorlar çalışmadı.",
    means: "İçerik taranmadı. Büyük olması tek başına zararlı demek değildir, ama bu tarama içini görmedi.",
    steps: [
      {
        title: "Bu kopyayı açmayın",
        detail:
          "Gerçekten büyük bir yedekse gönderenden parçalanmış halini isteyin ve her parçayı ayrı taratın.",
      },
    ],
  },
  ARCHIVE_COUNT: {
    title: "Üye sayısı sınırı aşıldı",
    why: "Arşivde 200'den fazla dosya üyesi var. 201. dosyada tarama durdu, klasör silindi, motorlar çalışmadı.",
    means: "Kalabalık bir arşivin içi bu taramada görülmedi.",
    steps: [
      {
        title: "Toplu açmayın",
        detail: "Gönderenden ne olduğunu sorun. Listeyi görmeden hepsini bir klasöre dökmek, içindeki programı da çıkarır.",
      },
    ],
  },
  ARCHIVE_DEPTH: {
    title: "Arşiv çok derin",
    why:
      "İzin verilen derinlik 3. Bundan daha içteki bir arşivde dosya vardı. ZenGuard o katmanı açmadı ve motorları çalıştırmadı.",
    means: "Derinlik, tarayıcıyı yormak için artırılmış olabilir. İçerik hakkında karar yok.",
    steps: [
      {
        title: "İç içe açmayın",
        detail:
          "Her katmanı elle açıp ayrı taratmak isterseniz bunu yapın. Otomatik 'hepsini çıkar' kullanmayın.",
      },
    ],
  },
  PATH_TRAVERSAL: {
    title: "Arşiv klasörün dışına yazmaya çalışıyor",
    why:
      "Bir üyenin adı .., / veya sürücü harfi ile başlıyor. Açan araç bunu olduğu gibi uygularsa dosya arşiv klasörünün dışına, hatta başka bir klasörün üstüne yazılır.",
    means: "Bu, arşivi açtığınızda kendi dosyalarınızın değişebileceği bir düzendir.",
    steps: [
      {
        title: "Gezgin veya sıradan bir arşiv aracıyla açmayın",
        detail: "Dosyayı silin. 'Yine de çıkar' seçeneği olan araçlar bu adı uygular.",
      },
    ],
  },
  UNSAFE_MEMBER: {
    title: "Arşivde sembolik bağ veya özel dosya var",
    why:
      "Bir üye normal dosya değil: sembolik bağ, aygıt dosyası veya yönlendirme. Açılırsa bağ, arşivin dışındaki bir dosyayı gösterebilir.",
    means: "Çıkarma işlemi, sizin başka bir dosyanızı değiştirebilir veya okuyabilir.",
    steps: [
      {
        title: "Çıkarmayın",
        detail: "Bağın nereyi gösterdiği açmadan güvenilir biçimde bilinmez. Dosyayı silin.",
      },
    ],
  },
};

function staticStory(reason: FindingReason): FindingStory {
  const code = reason.code || "sinyal";
  const known = STATIC[code];
  if (!known) {
    return {
      key: `static:${code}`,
      engine: "Biçim",
      title: code,
      where: whereOf(reason),
      points: reason.points ?? 0,
      why: `Biçim incelemesi "${code}" işaretini ${whereOf(reason)} üzerinde yazdı.`,
      means: "İşaret, dosya çalıştırılmadan görülen bir yapı özelliğidir.",
      steps: [
        {
          title: "Kaynağını bilmiyorsanız çalıştırmayın",
          detail: "İşaretin ne aradığını rapordaki kodla karşılaştırın.",
        },
      ],
    };
  }
  return {
    key: `static:${code}`,
    engine: "Biçim",
    title: known.title,
    where: whereOf(reason),
    points: reason.points ?? 0,
    why: `${known.why} Yer: ${whereOf(reason)}.`,
    means: known.means,
    steps: known.steps,
    headline: known.headline,
    situation: known.situation,
  };
}

function policyStory(reason: FindingReason): FindingStory {
  const code = reason.code || "POLICY";
  const known = POLICY[code];
  if (!known) {
    return staticStory(reason);
  }
  return {
    key: `policy:${code}`,
    engine: "Paket kuralı",
    title: known.title,
    where: whereOf(reason),
    points: reason.points ?? 100,
    why: known.why,
    means: known.means,
    steps: known.steps,
  };
}

function storyFor(reason: FindingReason, engine: "yara" | "static" | "archive" | "clamav"): FindingStory {
  if (engine === "clamav") {
    if (reason.code === "pua_heuristic") return puaStory(reason);
    return malwareStory(reason);
  }
  if (engine === "yara") return yaraStory(reason);
  if (reason.code && reason.code in POLICY) return policyStory(reason);
  return staticStory(reason);
}

const CLEAN_STEPS: ActionStep[] = [
  {
    title: "Temiz, her şeye izin demek değildir",
    detail:
      "ClamAV bilinen imzaları, YARA elimizdeki kuralları, statik analiz ise dosyanın yapısını okudu. Dosya çalıştırılmadı. Yeni bir zararlı, imzası henüz yoksa bu taramada görünmez.",
  },
  {
    title: "Beklemediğiniz bir dosyaysa yine açmayın",
    detail:
      "Tanımadığınız bir gönderenin eki temiz çıksa bile açmayın. Karar, dosyanın kimden geldiğiyle birlikte okunur.",
  },
  {
    title: "Windows Defender açık kalsın",
    detail: "ZenGuard onun yerine geçmez. Dosyayı çift tıkladığınızda işletim sisteminin koruması duruyor olmalı.",
  },
];

const FAILED_STEPS: ActionStep[] = [
  {
    title: "Skor yok diye temiz saymayın",
    detail:
      "Motor bitmeden puan yazılmaz. Boş skor, 'risk yok' demek değildir. Dosyayı bu sonuca güvenip açmayın.",
  },
  {
    title: "Aynı dosyayı yeniden yükleyin",
    detail:
      "Sol alttaki ClamAV satırı 'down' ise imza motoru kapalıdır. O satır 'ok' olunca dosyayı tekrar yükleyin. YARA veya disk hatası da aynı sonucu verir. Hata kodu raporun başındadır.",
  },
];

function coverageSentence(coverage: string | null): string {
  if (coverage === "full") return "Açılabilen her üye tarandı.";
  if (coverage === "partial") {
    return "Kapsam kısmi: şifreli bir üye veya okunamayan bir parça taramaya girmedi. Temiz kararı o parçayı kapsamaz.";
  }
  if (coverage === "none") return "İçerik taranmadı. Motorlar ya hiç çalışmadı ya da politika taramayı kesti.";
  return "Kapsam bilgisi yok.";
}

export function narrate(detail: AnalysisDetail): Narrative {
  if (detail.status === "queued" || detail.status === "running") {
    return {
      headline: "Tarama henüz bitmedi",
      lead: "Motorlar sonuç yazınca bu sayfa bulgunun yerini, puanını ve ne yapmanız gerektiğini ayrı ayrı gösterecek. Bitmeden skor yoktur.",
      stories: [],
      situation: "Tarama sürüyor.",
    };
  }

  if (detail.status === "failed" || !detail.report?.score) {
    return {
      headline: "Tarama tamamlanamadı",
      lead:
        (detail.error_message || "Bir motor sonucu yazamadan durdu.") +
        " " +
        coverageSentence(detail.coverage) +
        (detail.error_code ? ` Hata kodu: ${detail.error_code}.` : ""),
      stories: [],
      situation: "Sonuç yok. Dosya temiz kabul edilmez.",
    };
  }

  const report = detail.report;
  const components = report.score?.components;
  const eicarReasons: FindingReason[] = [];
  const stories: FindingStory[] = [];

  const buckets = [
    ["clamav", components?.clamav?.reasons],
    ["yara", components?.yara?.reasons],
    ["static", components?.static?.reasons],
    ["archive", components?.archive?.reasons],
  ] as const;

  for (const [engine, reasons] of buckets) {
    for (const reason of reasons ?? []) {
      if (isEicar(reason)) {
        eicarReasons.push(reason);
        continue;
      }
      if ((reason.points ?? 0) <= 0 && reason.code !== "static_error") continue;
      stories.push(storyFor(reason, engine));
    }
  }

  if (eicarReasons.length > 0) {
    stories.unshift(eicarStory(eicarReasons));
  }

  const onlyEicar = stories.length > 0 && stories.every((story) => story.key === "eicar");
  const hasMalware = stories.some((story) => story.key.startsWith("malware:"));
  const hasPolicy = detail.status === "rejected" || stories.some((story) => story.key.startsWith("policy:"));
  const band = bandLabel(detail.risk_band);
  const score = detail.risk_score ?? report.score?.value ?? 0;

  let headline: string;
  let situation: string;
  if (onlyEicar) {
    headline = "Bu bir virüs değil. Antivirüs test metni.";
    situation = "EICAR, motorların çalıştığını denemek için kullanılan zararsız bir metindir.";
  } else if (hasPolicy) {
    headline = "Dosya açılmadı. Arşiv kuralı taramayı kesti.";
    situation = "İçerik taranmadı. Aşağıdaki kural, dosyayı neden açmadığımızı anlatır.";
  } else if (hasMalware) {
    headline = "Bilinen bir zararlı imzası bulundu.";
    situation = "Bu bir sezgi değil. ClamAV dosyanın içinde daha önce zararlı sayılmış bir bayt kalıbı gördü.";
  } else if (stories[0]?.headline) {
    headline = stories[0].headline;
    situation = stories[0].situation || "Bu bulguya ait adımlar diğerlerinden ayrı yazılır.";
  } else if (stories.length > 0 && (detail.risk_band === "high" || detail.risk_band === "critical")) {
    headline = "Kesin bir imza yok, yapı yüksek riskli.";
    situation = "Zararlı aile adı çıkmadı. Puan, dosyanın yapısındaki işaretlerden toplandı.";
  } else if (stories.length > 0) {
    headline = "Zararlı imza yok. Bazı işaretler dikkat istiyor.";
    situation = "Her işaretin altında neden puan aldığı ve sizin ne yapmanız gerektiği ayrı yazılır. Hepsi için aynı uyarı verilmez.";
  } else {
    headline = "Taranan içerikte tehdit bulunamadı.";
    situation = "Sıfır puan, çalışan motorların eşleşme yazmadığı anlamına gelir.";
  }

  const evidence = report.score?.evidence_sum;
  const floor = report.score?.floor;
  const lifted =
    report.score?.mode === "certainty_sure"
      ? " ClamAV bilinen zararlı gövdeyi gördüğü için skor 100'e çıkarıldı."
      : typeof floor === "number" && typeof evidence === "number" && floor > evidence
        ? ` Parça toplamı ${evidence}. Zararlı kalıp var, çalışan gövde yok: şüphe tabanı ${floor}.`
        : "";
  const lead = `${headline} Skor ${score}/100, bant ${band}. ${coverageSentence(detail.coverage)}${lifted}`;

  return { headline, lead, stories, situation };
}

export function actionSteps(detail: AnalysisDetail, narrative: Narrative): ActionStep[] {
  if (detail.status === "failed" || (detail.status !== "queued" && detail.status !== "running" && !detail.report?.score)) {
    return FAILED_STEPS;
  }
  if (narrative.stories.length === 0 && detail.status === "completed") return CLEAN_STEPS;
  return narrative.stories.flatMap((story) => story.steps);
}
