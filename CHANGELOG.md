# Changelog

Все значимые изменения проекта фиксируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [семантического версионирования](https://semver.org/lang/ru/).

## [Unreleased]

### Планируется
- eBPF-инъекция сетевого хаоса в раннере через `aya` (только на Linux-стенде).
- Реестр раннеров и реальный heartbeat/dead-man в gRPC-петле.
- Сквозной mTLS с тестовыми сертификатами.

## [0.1.0] — 2026-09-07

Первый MVP: наступательный компонент **Asmodeus** (Red Team / BAS / Chaos)
платформы APEX DEFENSE на едином Rust-workspace. Замкнутый контур
`CLI → REST → gRPC → синтетическая инъекция → откат`, целиком под инвариантом
**INV-0 (synthetic-only)**.

### Добавлено
- **Ядро** (`asmodeus-common`): RBAC-матрица `Role × Capability` (инвариант
  CISO/SecOps/Auditor → read-only) и стейт-машина `RunState::on(RunEvent)` —
  тотальная функция без паник, инвариант «нет `Injecting` без `Armed`».
- **Крипта** (`asmodeus-crypto`): верификация Ed25519 на `ed25519-compact`.
- **DSL** (`asmodeus-dsl`): гейт INV-0 и whitelisting canary-scope.
- **Safety** (`asmodeus-safety`): circuit breaker (CPU/таймаут/heartbeat) и
  dead-man switch.
- **Telemetry** (`asmodeus-telemetry`): средние MTTD/MTTR, detection rate,
  экспозиция Prometheus.
- **Proto** (`asmodeus-proto`): gRPC-контракт `RunnerControl` (tonic) и
  mTLS-обвязка (сертификаты из env — операторские).
- **Control-plane** (`asmodeus-control-plane`): axum REST (OpenAPI-shape),
  каталог самоподписанных сценариев, движок прогона и gRPC-диспатч в живой
  раннер; эндпоинты `POST /scenarios/:id/run`, `POST /scenarios/abort`,
  `GET /telemetry/mttd`, `GET /metrics`, `GET /healthz`.
- **Runner** (`asmodeus-runner`): gRPC-сервер `RunnerControl` и синтетический
  canary-инъектор (обратимый XOR, scope-guard, обязательная авто-очистка).
- **CLI** (`asmodeus-cli`, бинарь `asmodeus`): `keygen`/`sign`/`verify`/
  `validate` (офлайн) и `run`/`status` (REST к control-plane).
- **Testkit** (`asmodeus-testkit`): `Polygon` (self-cleaning canary-песочница)
  и `signed_scenario` (фикстура подписанного манифеста).
- Документация: `ARCHITECTURE.md` (канонический), `FTT.md`, `TT.md`.

### Безопасность
- **INV-0 (synthetic-only)** как корневой инвариант, закреплённый в коде
  (`ActionNature`-гейт), а не только в документации.
- Blast radius: файловые операции только в `/tmp|/var/tmp/asmodeus-canary`.
- Подпись сценариев Ed25519; отказ исполнения при битой/отсутствующей подписи.
- Продовый ключ подписи и mTLS-сертификаты не хранятся в репозитории.

### Проверка
- 46 тестов зелёные, `clippy --workspace --all-targets` чист.
- gRPC-канал проверен по реальному TCP; сквозной прогон двух бинарников
  (REST → gRPC → 20 canary-файлов → откат без остатка).

[Unreleased]: https://github.com/onixus/Asmodeus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/onixus/Asmodeus/releases/tag/v0.1.0
