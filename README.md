# ZenGuard

Birleşik tehdit ve statik analiz platformu. Mimari: [`ARCHITECTURE.md`](ARCHITECTURE.md). Geliştirme fazları: [`CHECKLIST.md`](CHECKLIST.md).

## Faz 1 — Altyapıyı ayağa kaldırma

### Önkoşul

- Docker Engine ve Docker Compose v2
- Kökte `.env` dosyası (`.env.example` kopyası)

```powershell
copy .env.example .env
```

`.env` içindeki `change_me_*` değerlerini yerel geliştirme için değiştirin.

### Servisler ve portlar

| Servis   | Compose adı | Host erişimi        | Not                          |
| -------- | ----------- | ------------------- | ---------------------------- |
| Postgres | `postgres`  | `127.0.0.1:5432`    | volume `zenguard-pgdata`     |
| Redis    | `redis`     | `127.0.0.1:6379`    | AOF açık, parola zorunlu     |
| ClamAV   | `clamav`    | yalnız iç ağ `:3310`| İlk açılışta imza indirme uzun sürebilir |
| Backend  | `backend`   | `127.0.0.1:8000`    | profile `app`, Faz 2+        |
| Worker   | `worker`    | yayınlanmaz         | profile `app`, Faz 4+        |

Tüm servisler `zenguard` Docker ağındadır.

### Başlatma

Yalnız altyapı (Faz 1 doğrulaması):

```powershell
docker compose up -d postgres redis clamav
```

Backend ve worker iskeleti (Faz 2 öncesi yer tutucu `sleep`):

```powershell
docker compose --profile app up -d
```

### Doğrulama

**Postgres**

```powershell
docker compose exec postgres pg_isready -U zenguard -d zenguard
```

**Redis**

```powershell
docker compose exec redis redis-cli -a "%REDIS_PASSWORD%" ping
```

(Windows PowerShell'de parolayı `.env` dosyasından okuyun veya:)

```powershell
docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" ping'
```

Beklenen: `PONG`

**ClamAV (TCP)**

```powershell
docker compose exec clamav sh -c "echo PING | nc -w 2 127.0.0.1 3310"
```

Beklenen yanıtta `PONG` (imza güncellemesi bitmeden servis `starting` kalabilir; `docker compose ps` ile `healthy` olunmasını bekleyin).

**Sağlık durumu**

```powershell
docker compose ps
```

`postgres`, `redis`, `clamav` satırlarında `healthy` görünmelidir.

### Durdurma

```powershell
docker compose down
```

Volume'ları silmeden durdurur. Veriyi sıfırlamak için: `docker compose down -v` (dikkat: Postgres ve Redis verisi silinir).
