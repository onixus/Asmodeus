# ASMODEUS — Архитектура

**Статус**: канонический документ. При расхождении с `FTT.md` / `TT.md` приоритет у этого файла.
**Кодовая база**: Rust workspace (monorepo `Asmodeus`).
**Место в экосистеме**: наступательный (offensive) компонент платформы **APEX DEFENSE**.

---

## 0. Корневой инвариант: Synthetic-Only

> [!IMPORTANT]
> **INV-0 — Asmodeus строго синтетичен. Всё, что выходит за эту границу, находится ВНЕ области проекта.**

Asmodeus — движок валидации защиты (BAS / Red Team / Chaos), а не арсенал. Он **имитирует** техники злоумышленника, чтобы замерить реакцию Blue Team, и никогда не несёт боевой способности.

**Разрешено (in-scope):**
- Синтетические маркеры: canary-файлы, псевдо-шифрование (xor/aes-stream) **только** в canary-директории.
- Benign-пробы: попытка действия ради проверки детектора (напр. спавн шелла для реакции Ferrum), а не реальный результат.
- Имитация сети: beacon к тестовым доменам, DNS-запросы к синкхолу, задержки/дропы в тестовом сегменте.

**Вне области проекта (out-of-scope, не принимается в кодовую базу):**
- Реальное вредоносное ПО или ransomware, шифрующий фактические данные пользователя.
- Рабочие эксплойты и настоящий container-escape (0-day, реальный побег из namespace).
- Обход/evasion средств защиты (Ferrum, Lariska, BSDM), цель которого — реально их победить.
- Наведение на цели вне canary-scope, mass-targeting, supply-chain-компрометация, C2 для несанкционированного контроля.

**Граница проходит по природе артефакта, не по фазе разработки.** Переход MVP → прод её не двигает. Её пересекает только замена синтетического ядра на боевое: от «имитирует технику для замера MTTD» к «даёт работающую способность нанести ущерб реальной системе». Такой запрос отклоняется на code-review и не мержится.

Этот инвариант — надмножество safety-требований `TT.md §3` и первичен по отношению ко всем остальным решениям ниже.

---

## 1. Решения, зафиксированные этим документом

| # | Решение | Обоснование |
| :-- | :--- | :--- |
| D0 | **Synthetic-only (INV-0)** — см. §0. Первичный инвариант, надмножество safety `TT.md §3` | Asmodeus имитирует техники, а не несёт боевой способности. Граница по природе артефакта, не по фазе. |
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

Живут в `asmodeus-safety` и `asmodeus-dsl`, проверяются до и во время исполнения. Подчинены корневому инварианту **INV-0 (§0)**:

1. **Никаких реальных payload (следствие INV-0).** Только синтетические маркеры: canary-файлы, псевдо-шифрование в тестовой папке, безопасные сетевые сигналы.
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
cargo build --workspace        # весь workspace
cargo test  --workspace        # 46 тестов (ядро, RBAC, крипта, DSL, REST, gRPC, canary, CLI, testkit)
cargo run -p asmodeus-control-plane   # REST на 127.0.0.1:8842 (ASMODEUS_LISTEN)
cargo run -p asmodeus-runner          # gRPC RunnerControl на 127.0.0.1:8850 (ASMODEUS_RUNNER_LISTEN)
cargo run -p asmodeus-cli -- keygen   # операторский CLI: keygen/sign/verify/validate
ASMODEUS_DRY_RUN=1 cargo run -p asmodeus-runner   # локальный синтетический прогон без control-plane
```

Toolchain закреплён в `rust-toolchain.toml` (1.90, с `rustfmt` и `clippy`).

### Реализовано

- **Ядро** (`asmodeus-common`): RBAC-матрица `Role × Capability` (§3, инвариант CISO/SecOps/Auditor → read-only) и стейт-машина `RunState::on(RunEvent)` — тотальная функция без паник, инвариант «нет `Injecting` без `Armed`».
- **Крипта** (`asmodeus-crypto`): реальная верификация Ed25519 на `ed25519-compact`.
- **DSL-гейт** (`asmodeus-dsl`): `validate` отклоняет несинтетические (INV-0) и вне-scope манифесты.
- **Safety** (`asmodeus-safety`): `CircuitBreaker` (CPU/таймаут/heartbeat) и `DeadManSwitch`.
- **Telemetry** (`asmodeus-telemetry`): `Aggregate` — средние MTTD/MTTR, detection rate, экспозиция Prometheus.
- **Control-plane** (`asmodeus-control-plane`): axum-сервер, каталог самоподписанных сценариев, движок прогона. Эндпоинты: `POST /scenarios/:id/run`, `POST /scenarios/abort`, `GET /telemetry/mttd`, `GET /metrics`, `GET /healthz`. RBAC даёт `401/403/404/422` строго по ролям.
- **Runner** (`asmodeus-runner`): синтетический canary-инъектор (обратимый XOR, scope-guard) + gRPC-сервер `RunnerControl` (проверка подписи → INV-0 → инъекция → стрим событий), проверен end-to-end по TCP.
- **Proto** (`asmodeus-proto`): tonic-контракт `RunnerControl`, mTLS-обвязка с fail-closed семантикой (неполная конфигурация даёт ошибку конфигурации вместо отката в plaintext), поддержка независимых env-переменных (`ASMODEUS_RUNNER_TLS_*`, `ASMODEUS_CLIENT_TLS_*`, `ASMODEUS_TLS_DOMAIN`) и in-memory API (`MtlsConfig`, `server_tls_config`, `client_tls_config`).

- **Замкнутый контур**: при заданном `ASMODEUS_RUNNER_ENDPOINT` control-plane диспатчит подписанный сценарий в живой раннер по gRPC (включая сквозной mTLS) и сворачивает поток событий; иначе — in-process симуляция. Проверено сквозным прогоном двух бинарников.

- **CLI** (`asmodeus-cli`): операторский цикл — `keygen`/`sign`/`verify`/`validate` (офлайн, Ed25519, ключ 0600) и `run`/`status` (REST к control-plane).
- **Testkit** (`asmodeus-testkit`): `Polygon` (self-cleaning canary-песочница), `signed_scenario` (фикстура подписанного манифеста) и `TestMtls` (генерация CA, server, client и rogue-сертификатов на `rcgen` для сквозного тестирования mTLS).


- **Сетевой хаос** (`asmodeus-runner::netchaos`): синтетическая имитация
  `LATENCY_SPIKE_VM` (задержка/джиттер/потери) на зарезервированном
  тест-сегменте. INV-0 blast radius для сети (`net_target_in_scope` в DSL:
  только loopback + RFC 5737 TEST-NET), бюджетные лимиты и `NetChaosSession` с
  обязательным откатом через `Drop` (D7). Кросс-платформенный `SimBackend`
  покрыт тестами; aya/TC-бэкенд — за фича-флагом `ebpf` на Linux-стенде.

- **Реестр раннеров и gRPC Heartbeat** (`asmodeus-control-plane::registry`, `asmodeus-runner::service`):
  потокобезопасный `RunnerRegistry` для управления распределёнными зондами с поддержкой
  тегов (`k8s_workload`, `endpoint_agent`, `network_gateway`) и динамической маршрутизации
  по `target_override`. Расширенный gRPC-контракт `Heartbeat` (liveness probe, состояние `IDLE`/`INJECTING`,
  нагрузка CPU, активное упражнение). Интеграция `DeadManSwitch` и `CircuitBreaker` из
  `asmodeus-safety` в цикл исполнения раннера с безусловным срабатыванием `TripBreaker`
  и очисткой. Операторские команды CLI `asmodeus runners list/register/deregister/ping`
  и флаг `--target` для запуска сценариев.

- **Криптографический журнал аудита и оркестрация кампаний** (`asmodeus-telemetry::audit`, `asmodeus-control-plane::campaign`, `asmodeus-control-plane::watchdog`):
  - Нефальсифицируемый журнал `AuditRecord` с канонической цифровой подписью Ed25519 (ключ Red Team Lead) и in-memory хранилищем `AuditTrail`.
  - Эндпоинты REST API: `GET /api/v1/asmodeus/runs`, `GET /api/v1/asmodeus/runs/:id`, `GET /api/v1/asmodeus/runs/:id/verify`.
  - Оркестратор цепочек атак (Playbooks / Campaigns): `CAMP-RANSOMWARE-CHAIN`, `CAMP-K8S-ESCAPE-CHAOS`, `CAMP-PERSISTENCE-EXFIL` с вычислением композитного `ResilienceScore` по всей цепочке.
  - Фоновый `watchdog` в control-plane для периодической проверки доступности раннеров.
  - Операторские команды CLI `asmodeus runs list/get/verify` и `asmodeus campaigns list/run`.

- **Декларативный DSL, Замкнутый Цикл NIST Closed-Loop и Исполнительная Отчётность** (`asmodeus-dsl::manifest`, `asmodeus-telemetry::reporting`, `asmodeus-control-plane`):
  - Полный декларативный парсер и валидатор сценариев (`AttackScenario`, `ChaosExperiment`) по спецификации `FTT.md §5` с поддержкой YAML и JSON, проверкой инварианта `INV-0` и ресурсных лимитов (`POST /scenarios/validate`, `asmodeus validate --manifest`).
  - Замкнутый цикл реагирования (Closed-Loop Feedback): приём оповещений от защитных датчиков (Ferrum/Lariska/SOAR) через `POST /runs/:id/feedback` и `asmodeus runs feedback`, динамический замер MTTD/MTTR и автоматическая криптографическая переподпись аудиторской записи Ed25519.
  - Отчётность кибер-устойчивости NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover) с расчётом SLA (`TARGET_MTTR_MS`), тактическим анализом и генерацией документов в форматах Markdown и JSON (`GET /reports/resilience`, `GET /runs/:id/report`, `asmodeus report`).
  - Политика защиты цепочки поставок (`deny.toml`) для строгой проверки лицензий и безопасности зависимостей в CI. 110 тестов green.

Осталось (только на Linux-стенде): собрать компилируемый BPF-объект и подключить
его к aya/TC-бэкенду (`clsact` + `SchedClassifier`, `--features ebpf`) — на
macOS не проверяется (§8).
