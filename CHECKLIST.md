# ZenGuard — Geliştirme Kontrol Listesi

Faz 0 mimarisi `ARCHITECTURE.md` içindedir. Bu liste uygulama işidir. Her madde, o faz bitmeden sonrakine geçilmeyecek şekilde sıralıdır. Limit, katsayı ve durum adları mimari belgeden sapmaz.

## Faz 1 — Monorepo, Compose ve konfigürasyon

Amaç: PostgreSQL, Redis ve ClamAV yerelde ayağa kalksın. Uygulama kodu bu fazda yok.

- [x] **1.1** Kök ağacı oluştur: `backend/app`, `frontend`, `sandbox`, `rules/yara`, `samples/fixtures`
- [x] **1.2** `docker-compose.yml` içine `zenguard` ağını, `postgres:16`, `redis:7` ve `clamav/clamav:stable` servislerini ekle
- [x] **1.3** Postgres: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, volume `pgdata`, sağlık kontrolü `pg_isready`, port yalnızca `127.0.0.1:5432`
- [x] **1.4** Redis: AOF açık, volume `redisdata`, parola `REDIS_URL` ile aynı kaynaktan, port yalnızca `127.0.0.1:6379`
- [x] **1.5** ClamAV: imza volume `clamav-db`, soket volume `clamav-run`, iç ağda TCP 3310, Unix soket `/run/clamav/clamd.sock`, `freshclam` başlangıçta çalışsın
- [x] **1.6** Üç servis için sağlık kontrolü yeşil olmadan bağımlı servis başlamasın diye `depends_on.condition: service_healthy` kalıbını şimdiden yaz
- [x] **1.7** `.env.example` dosyasına `ARCHITECTURE.md` bölüm 13'teki her değişkeni, örnek değer ve tek satırlık açıklamayla ekle
- [x] **1.8** `.gitignore`: `.env`, `__pycache__/`, `.venv/`, `node_modules/`, `.next/`, karantina dizini, ClamAV veri dizinleri
- [x] **1.9** Kök `README.md`: yalnızca `docker compose up` ile üç servisin nasıl doğrulanacağı ve port tablosu
- [x] **1.10** `docker compose up` sonrası Postgres kabul ediyor, Redis `PONG` dönüyor, ClamAV TCP üzerinden `PONG` dönüyor

## Faz 2 — FastAPI, modeller ve SHA-256 yükleme

Amaç: dosya diske yazılsın, özeti hesaplansın, `queued` satır oluşsun. Motor ve Celery henüz yok.

- [x] **2.1** `backend/pyproject.toml` (veya `requirements.txt`): FastAPI, Uvicorn, SQLModel, SQLAlchemy 2, asyncpg, psycopg, Pydantic Settings, Alembic
- [x] **2.2** `app/core/config.py`: bölüm 13 değişkenlerini `pydantic-settings` ile oku; eksik zorunlu değişkende süreç açılmasın
- [x] **2.3** `app/main.py`: uygulama fabrikası, `/api/v1` yönlendiricisi, yereldeki frontend kökeni için CORS
- [x] **2.4** `app/db/session.py`: API için async oturum, worker'ın sonraki fazda kullanacağı senkron oturum fabrikası
- [x] **2.5** `app/db/models.py`: `analyses` tablosu, `CHECK` kısıtları ve `ARCHITECTURE.md` bölüm 8 sütunları
- [x] **2.6** Alembic ilk göç: tablo, durum/bant kontrolleri, `sha256`, `status`, `created_at DESC`, `risk_score` indeksleri ve `report` GIN indeksi
- [x] **2.7** `services/hashing.py`: akıştan SHA-256; tüm dosyayı belleğe toplamadan
- [x] **2.8** `services/storage.py`: karantina yolu `{sha256[0:2]}/{sha256}`; 50 MiB aşımında kısmi dosyayı sil
- [x] **2.9** `POST /api/v1/analyses`: multipart `file`, taban ad, `413` gövde sınırı, `202` gövdesi (`id`, `sha256`, `status`, `original_filename`, `size_bytes`)
- [x] **2.10** Aynı özette `queued`/`running` kayıt varsa yeni satır açma; uç durumdaysa `rescan=true` olmadıkça mevcut kaydı dön
- [x] **2.11** `GET /api/v1/analyses/{id}` ve `GET /api/v1/analyses` (`limit`, `offset`, `sha256`, `status`)
- [x] **2.12** `GET /api/v1/health`: `api` ve `db`. Redis ile ClamAV bu fazda `down` dönebilir; uç cevap şeması dörtlüdür
- [x] **2.13** Birim test: bilinen bayt dizisinin SHA-256 değeri ve boyut aşımında dosyanın kalmaması

## Faz 3 — İzole analiz motoru

Amaç: açma, ClamAV, YARA ve statik motorlar saf fonksiyonlar olarak test edilsin. Kuyruk henüz yok. Testler `ZENG_SANDBOX_MODE=inprocess` kullanır; bu mod izolasyon iddiası taşımaz.

- [x] **3.1** `engines/archive.py`: zip, tar, tar.gz, tar.bz2, 7z. Derinlik 0 kök, en fazla derinlik 3
- [x] **3.2** Açarken akan sayaç: açılmış bayt `104857600`, üye `200`, oran `>= 1000` olursa dur, iş dizinini sil, kodu döndür (`SIZE_LIMIT`, `ARCHIVE_COUNT`, `ZIP_BOMB`)
- [x] **3.3** Üye yolunda `..`, mutlak yol veya sürücü öneki varsa `PATH_TRAVERSAL`. Sembolik bağ varsa `UNSAFE_MEMBER`
- [x] **3.4** Oran `100`–`999` ise `suspicious_ratio`. Derinlik 3'te açılmayan arşiv üyesi varsa `nested_depth_max`. Şifreli arşivde `encrypted_archive` ve kapsam `partial`
- [x] **3.5** Arşiv testleri: derinlik 4 reddi, 201. üye reddi, yol kaçışı reddi, yüksek oranlı sıfır dolgulu sentetik zip reddi, şifreli zip kısmi kapsam
- [x] **3.6** `engines/clamav.py`: Unix soket üzerinden `INSTREAM`. Sağlık için TCP `PING`. Sonuç: temiz, yalnızca PUA/Heuristic, zararlı imza veya motor hatası
- [x] **3.7** `rules/yara/eicar.yar`: EICAR test dizesi, `severity = critical`. İkinci bir kural dosyasında zararsız bir statik dize örneği (`medium`)
- [x] **3.8** `engines/yara_scan.py`: kuralları süreç başında derle, `ruleset_version` olarak kural içeriklerinin SHA-256 değerini üret, aynı kural adını bir kez kaydet
- [x] **3.9** `engines/static.py`: bölüm 11 sinyal tablosu. Ağ çağrısı yok. Üye başına sinyal kimliği bir kez
- [x] **3.10** Motorları yan yana çağıran `scan_bytes` / `scan_tree` fonksiyonu: ClamAV veya YARA hatasında istisna; tek üyede statik hatada `static_error` ve devam
- [x] **3.11** Birim test: EICAR baytı ClamAV (soket varsa) ve YARA kritik kuralıyla eşleşir; temiz metin sıfır sinyal döner

## Faz 4 — Celery işçisi ve birleşik risk skoru

Amaç: `POST` hemen dönsün; skor worker'da yazılsın. İzolasyon sınırı `docker` modudur.

- [ ] **4.1** `services/scoring.py`: bölüm 12 formülü. Girdi motor JSON'u, çıktı `score` nesnesi (`mode`, `value`, `band`, `raw_sum`, `clipped`, `components`)
- [ ] **4.2** Skor testleri, mimarideki sekiz senaryoyu tek tek doğrular: temiz 0, PUA 25, kritik YARA 40, statik tavan 15, YARA+statik 55, EICAR 95, dört tavan 100 (`clipped` 20), politika reddi 100 ve `policy_override`
- [ ] **4.3** `workers/celery_app.py`: broker ve sonuç backend `REDIS_URL`, sonuç ömrü `CELERY_RESULT_TTL_SECONDS`, görev adı `zenguard.analyze_sample`
- [ ] **4.4** Görev durum makinesi: `queued` → `running` → `completed` | `failed` | `rejected`. Uç durumdan çıkış yok
- [ ] **4.5** ClamAV veya YARA çökerse `failed`, `risk_score` boş, `error_code` dolu. Zip/yol limiti `rejected` ve skor 100
- [ ] **4.6** `sandbox/Dockerfile`: kök olmayan kullanıcı, YARA ve arşiv kütüphaneleri, salt okunur kök. `sandbox/README.md` içinde başlatma bayraklarının listesi
- [ ] **4.7** `sandbox/runner.py`: `docker` modunda tek seferlik konteyner; `network_mode=none`, CPU `0.5`, bellek `512m`, PID `128`, `cap_drop=ALL`, `no-new-privileges`, örnek ve kurallar salt okunur, ClamAV soketi takılı. Argümanlar kabuk dizesi olmadan
- [ ] **4.8** Süre 120 saniyeyi aşarsa konteyneri durdur, analizi `failed` yaz
- [ ] **4.9** Compose'a `worker` servisi: backend imajı, Celery komutu, `quarantine` volume, yalnızca bu serviste Docker soketi, Postgres ve Redis sağlıklıysa başlar
- [ ] **4.10** `POST` satırı `queued` yazar ve görevi kuyruğa bırakır. Worker bitince `report`, `risk_score`, `risk_band`, `coverage`, `ruleset_version`, `engine_versions` dolu olur

## Faz 5 — Analist arayüzü

Amaç: analist dosyayı bırakır, yoklamayla skoru ve gerekçeyi görür.

- [x] **5.1** `frontend`: Next.js App Router, TypeScript, Tailwind CSS, Lucide Icons
- [x] **5.2** `NEXT_PUBLIC_API_BASE` ile konuşan `lib/api.ts`: yükleme, tek kayıt, liste
- [x] **5.3** Sürükle-bırak yükleme alanı. Kabul sırasında dosya adı ve boyut görünsün. `202` sonrası ayrıntı sayfasına geç
- [x] **5.4** 2 saniyelik yoklama. `completed`, `failed`, `rejected` olunca dur. Ağ hatasında son hatayı göster, kimliği unutma
- [x] **5.5** 0–100 risk göstergesi. Bant renkleri: `clean`, `low`, `medium`, `high`, `critical`. Skor boşken gösterge sayı yerine durum yazar
- [x] **5.6** Bileşen kırılımı: ClamAV 55, YARA 40, statik 15, arşiv 10 üzerinden verilen puan ve `clipped`
- [x] **5.7** Bulgu kartları: `code`, puan, üye yolu, kanıt. Politika reddinde tek kart, `policy_override` olduğu okunur
- [x] **5.8** Geçmiş tablosu: zaman, ad, kısa özet, bant, duruma göre filtre
- [x] **5.9** Boş liste, `404`, `failed` ve `413` için ayrı kısa durumlar
- [x] **5.10** Compose'a `frontend` servisi, port yalnızca `127.0.0.1:3000`
- [x] **5.11** Arayüz doğrulaması: dosya bırak, yoklama bitsin, gösterge ve kartlar aynı API kaydındaki skorla eşleşsin. Masaüstü ve dar genişlikte yükleme alanı kullanılabilir kalsın

## Faz 6 — Uçtan uca test ve demo

Amaç: sentetik gereçlerle beklenen skorlar tutsun. Repoda gerçek zararlı örnek bulunmaz.

- [ ] **6.1** `samples/fixtures` içine EICAR test dosyası. Beklenen skor 95, bant `critical`, mod `weighted_sum`
- [ ] **6.2** EICAR'ı içeren düz bir zip. İç üye taranır, skor yine kritik banda düşer, kapsam `full`
- [ ] **6.3** Derinlik 4 zinciri (`a.zip` → … → derinlik 4). Beklenen: `rejected`, `ARCHIVE_DEPTH`, skor 100, `policy_override`
- [ ] **6.4** Oranı `>= 1000` olan sıfır dolgulu küçük zip. Beklenen: `ZIP_BOMB`, skor 100, karantina dışında açılmış artık yok
- [ ] **6.5** Üye adı `../kacak.txt` olan zip. Beklenen: `PATH_TRAVERSAL`, skor 100
- [ ] **6.6** Şifreli zip. Beklenen: `completed`, kapsam `partial`, arşiv puanında `encrypted_archive`, iç dosya taranmış görünmez
- [ ] **6.7** Pytest: API'ye bu gereçleri yükle, uç duruma kadar bekle, skor tablosuyla karşılaştır
- [ ] **6.8** `README.md` demo bölümü: compose sırası, sağlık kontrolü, EICAR yükleme, beklenen gösterge değeri 95
- [ ] **6.9** Demo provası: arayüzden EICAR ve derinlik reddi fixtures'larının ikisi de doğru bant ve gerekçe kodunu gösterir
