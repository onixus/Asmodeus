# ASMODEUS — Архитектура

**Статус**: канонический документ. При расхождении с `FTT.md` / `TT.md` приоритет у этого файла.
**Кодовая база**: Rust workspace (monorepo `Asmodeus`).
**Место в экосистеме**: наступательный (offensive) компонент платформы **APEX DEFENSE**.

---

## 1. Решения, зафиксированные этим документом

| # | Решение | Обоснование |
| :-- | :--- | :--- |
| D1 | **Базовый язык — Rust**, единый toolchain на всё дерево крейтов | Весь системный слой экосистемы уже на Rust (Ferrum, Lariska, BSDM-Proxy, Pulse). `TT.md §6` даёт Rust 10/10 по критичным критериям: память без GC для точного MTTD, статический musl-бинарник, прямой доступ к cgroups/namespaces/eBPF. |
| D2 | **Asmodeus не содержит собственного Python-рантайма.** Отдаёт REST (OpenAPI 3.1), который потребляет уже существующий FastAPI-шлюз APEX | Python и Next.js в экосистеме живут только на уровне агрегатора (`unified-platform`). Дублировать рантайм внутри Asmodeus не нужно. |
| D3 | **Async-стек: tokio + axum (REST) + tonic (gRPC)** | Ровно как в Ferrum. Не плодим зоопарк рантаймов. |
| D4 | **Расширение TTP — встроенные Rust-модули на технику (MVP).** Плагинную WASM-песочницу вводим позже, переиспользуя `ferrum-wasm-abi` / `ferrum-wasm-host` | Наступательным действиям нужна жёсткая изоляция WASM, а не встраиваемый скриптовый рантайм (Rhai из Pulse здесь не подходит). |
| D5 | **RBAC-инвариант обеспечивает control-plane, а не шлюз** | CISO / Auditor / SecOps получают `403` на любой запуск/инъекцию даже с валидным JWT. Control-plane не доверяет `X-Apex-Role` слепо. |
| D6 | **REST принимает только `scenario_id`, не тело сценария** | Источник истины — подписанный манифест в каталоге. API лишь запускает предварительно провалидированный и подписанный сценарий. |
| D7 | **eBPF-инъекция сетевого хаоса через `aya`**, откат правил — обязательный шаг `CLEANUP` | Как в Ferrum / BSDM. Никакого shelling-out в `tc`/`iptables`. |

---

## 2. Позиционирование в экосистеме APEX

```
                 REST / OpenAPI 3.1
   Asmodeus ───────────────────────────► APEX Unified Gateway (FastAPI)
   Control Plane                                   │
        │                                          ▼
        │ gRPC / mTLS                       APEX Web Console (Next.js 14)
        ▼
   Asmodeus Runners ──── инъекция ────► Целевая инфраструктура
   (DaemonSet / Job)                    • Lariska  (endpoint agent)
        │                               • Ferrum   (eBPF / K8s admission)
        │ телеметрия обнаружения        • BSDM-Proxy (SWG / DNS RPZ)
        ▼
   ClickHouse (общая шина телеметрии экосистемы)
```

Asmodeus — наступательный спарринг-партнёр: инъецирует контролируемую атаку или сбой, а защитные компоненты (Ferrum, Lariska, BSDM) должны обнаружить и сдержать. Телеметрия обнаружения возвращается в Asmodeus для замера MTTD/MTTR.

---

## 3. Декомпозиция на крейты

Workspace зеркалит конвенции Ferrum: те же суффиксы `-common`, `-proto`, `-crypto`, `-cli`, `-testkit`, чтобы команда переносила знание один-в-один.

| Крейт | Тип | Роль | Аналог в Ferrum |
| :--- | :--- | :--- | :--- |
| `asmodeus-common` | lib | Общие типы (`Role`, `RunState`), ошибки, конфиг, теги учений | `ferrum-common` |
| `asmodeus-proto` | lib | gRPC/protobuf контракты control↔runner, REST DTO | `ferrum-proto` |
| `asmodeus-crypto` | lib | Подпись/верификация Ed25519 манифестов | `ferrum-crypto` |
| `asmodeus-dsl` | lib | Парсинг манифестов, валидация типов, whitelisting путей/портов | — |
| `asmodeus-safety` | lib | Circuit Breaker, Dead-Man switch, контроль ресурсов, rollback | часть `lariska` watchdog |
| `asmodeus-runner` | **bin** | Исполнительный зонд, атомарные действия сценария | `ferrum-agent` |
| `asmodeus-control-plane` | **bin** | REST+gRPC сервер, RBAC-движок, стейт-машина, каталог | `ferrum-controller` + `-api` |
| `asmodeus-telemetry` | lib | MTTD/MTTR, теги, Prometheus/OTel экспорт | `ferrum-metrics` |
| `asmodeus-cli` | **bin** | Подпись сценариев, dry-run, генерация cURL/CLI для CI/CD | `ferrum-cli` |
| `asmodeus-testkit` | lib | Полигон, canary-фикстуры, e2e-гарнир | `ferrum-testkit` |

Граф зависимостей ацикличен: `common` — корень, `control-plane` и `runner` — листья-бинарники.

---

## 4. Канонический автомат жизненного цикла

Единый источник истины (снимает расхождение `FTT.md` ↔ `TT.md`):

```
[ IDLE ]
   │  валидация DSL + проверка подписи Ed25519
[ VALIDATED ]
   │  проверка роли RBAC (admin / red_team / devsecops)
[ ARMED ]
   │  инициализация canary-песочницы + запуск Dead-Man switch
[ INJECTING ] ───────────────┐  превышение лимитов / таймаут / потеря heartbeat
   │  замер MTTD             ▼
[ DETECTED ]          [ CIRCUIT_BREAKER_TRIPPED ]
   │  замер MTTR             │
[ CONTAINED ]               │
   │                        │
   ▼                        ▼
[ CLEANUP ]  ◄──────────────┘  удаление canary, сброс сетевых правил (безусловно)
   │
[ COMPLETED / ARCHIVED ]
```

**Инварианты переходов:**
- В `INJECTING` нельзя войти без пройденной верификации подписи **и** RBAC-проверки.
- Любой сбой сети, зависание раннера или срабатывание breaker'а ведёт в `CLEANUP` безусловно.
- Время в `INJECTING` ограничено `max_duration_sec` (по умолчанию ≤ 120 с, максимум 300 с).

Реализация автомата — в `asmodeus-control-plane`; состояния объявлены в `asmodeus-common::RunState`.

---

## 5. Инварианты безопасности

Живут в `asmodeus-safety` и `asmodeus-dsl`, проверяются до и во время исполнения:

1. **Никаких реальных payload.** Только синтетические маркеры: canary-файлы, псевдо-шифрование в тестовой папке, безопасные сетевые сигналы.
2. **Blast Radius whitelisting.** Файловые операции — только внутри `/var/tmp/asmodeus-canary/*` или `/tmp/asmodeus-canary/*` (`asmodeus_dsl::path_in_scope`). Сеть — только loopback и тестовые подсети RFC 1918.
3. **Подпись сценариев Ed25519.** Раннер отказывает в исполнении при отсутствующей/битой подписи (`asmodeus_crypto::verify_manifest`).
4. **Dead-Man switch.** Heartbeat control↔runner каждые 1000 мс; при потере 3 подряд раннер глушит все процессы и откатывает сетевые правила (`asmodeus_proto::stub`, `asmodeus_safety::should_trip`).
5. **Circuit Breaker.** CPU цели > 85%, исчерпание памяти или потеря управляющего канала — немедленный переход в `CLEANUP`.

---

## 6. Бюджет ресурсов

| Компонент | CPU | RAM | Диск | Сеть |
| :--- | :---: | :---: | :---: | :---: |
| `asmodeus-runner` | ≤ 5% ядра | ≤ 32 MB | ≤ 20 MB | ≤ 100 КБ/с |
| `asmodeus-control-plane` | ≤ 10% ядра | ≤ 128 MB | ≤ 50 MB | пренебрежимо |

Release-профиль (`Cargo.toml`) настроен на минимальный бинарник: `opt-level="z"`, `lto=true`, `panic="abort"`, `strip=true`. Целевой раннер — статический musl (`x86_64/aarch64-unknown-linux-musl`), ~5 MB.

---

## 7. Внешние зависимости (по мере вживления)

Скелет собирается офлайн только на path-зависимостях. Реальные crates.io-зависимости добавляются в `[workspace.dependencies]` по этой карте:

| Область | Крейты |
| :--- | :--- |
| Async-рантайм | `tokio` |
| REST-сервер | `axum`, `tower`, `utoipa` (OpenAPI 3.1) |
| gRPC | `tonic`, `prost`, `tonic-build` |
| Крипто | `ed25519-compact` (как в Ferrum) |
| DSL | `serde`, `serde_yaml`, `serde_json`, `jsonschema` |
| eBPF | `aya`, `aya-log` (как в Ferrum / BSDM) |
| Низкий уровень | `libc`, `nix`, `caps` |
| Телеметрия | `prometheus`, `opentelemetry`, `tracing`, `tracing-subscriber` |
| Ошибки | `thiserror`, `anyhow` |

---

## 8. Целевые платформы

- **Linux**: x86_64, aarch64 (Ubuntu 20.04+, RHEL/Rocky 8+, Alpine 3.18+, ядра ≥ 5.4).
- **Kubernetes**: 1.25+ (managed, OpenShift, k3s) — раннер как DaemonSet / Job.
- **macOS**: Apple Silicon и Intel — только локальная разработка и валидация агентов.

---

## 9. Сборка

```bash
cargo build --workspace        # весь скелет
cargo run -p asmodeus-cli      # операторский CLI
cargo run -p asmodeus-control-plane
cargo run -p asmodeus-runner
```

Toolchain закреплён в `rust-toolchain.toml` (1.90, с `rustfmt` и `clippy`).
