# Changelog

Все значимые изменения проекта фиксируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [семантического версионирования](https://semver.org/lang/ru/).

## [Unreleased]

### Добавлено
- **Расширение покрытия MITRE ATT&CK**:
  - **Доменная модель техник** (`asmodeus-dsl::mitre`): типизированные структуры
    `MitreTechnique` с идентификаторами, тактиками, именами и описаниями,
    функции поиска `lookup_technique`.
  - **Каталог расширен до 11 сценариев** (`asmodeus-control-plane::catalog`):
    - 8 сценариев атак по 7 тактикам MITRE ATT&CK: `RANSOMWARE_CANARY_SPIKE` (T1486),
      `K8S_ESCAPE_SIMULATION` (T1611), `C2_BEACONING_SIMULATION` (T1071),
      `CREDENTIAL_ACCESS_CANARY` (T1003), `LOG_TAMPER_CANARY` (T1070),
      `PERSISTENCE_CRON_CANARY` (T1053), `DATA_EXFILTRATION_CANARY` (T1041),
      `DEFENSE_IMPAIRMENT_CANARY` (T1562).
    - 3 сценария инфраструктурного хаоса: `LATENCY_SPIKE_VM`, `AGENT_CRASH_ENDPOINT`,
      `DNS_RPZ_SINKHOLE_DROP`.
    - Все сценарии самоподписаны Ed25519 и генерируют спецификации манифестов с полями MITRE.
  - **Синтетические инъекторы в раннере** (`asmodeus-runner::injectors`):
    модульные исполнители сценариев под строгим инвариантом INV-0 с
    гарантированным `cleanup` в canary-песочнице (безопасные сокет-пробы,
    фиктивные honeytoken-учетки, canary cron-задачи, симуляция усечения логов,
    генерация beaconing).
  - **Новые эндпоинты REST API**:
    - `GET /api/v1/asmodeus/scenarios` — каталог сценариев с детекторами и MITRE-метаданными;
    - `GET /api/v1/asmodeus/scenarios/:id` — детальная спецификация сценария;
    - `GET /api/v1/asmodeus/scenarios/mitre` — матрица покрытия MITRE ATT&CK;
    - `POST /api/v1/asmodeus/scenarios/:id/run` обогащён полями `scenario_name`,
      `mitre_technique`, `mitre_tactic`, `severity`.
  - **Команды CLI** (`asmodeus scenarios`, `asmodeus mitre`): операторский вывод каталога
    и матрицы покрытия через REST API control-plane.
- **Сетевой хаос в раннере** (`asmodeus-runner::netchaos`): синтетическая
  имитация `LATENCY_SPIKE_VM` (FTT §4.2.1) — задержка/джиттер/потери на
  *зарезервированном тест-сегменте* (loopback + RFC 5737 TEST-NET). Движок
  кросс-платформенный и полностью покрыт тестами:
  - INV-0 blast radius для сети: `net_target_in_scope` в `asmodeus-dsl`
    пропускает только тест-блоки; продовые/RFC1918 адреса и широкие суперсети
    (`0.0.0.0/0`) отклоняются. Разбор CIDR без паник на битом вводе.
  - Бюджетные лимиты (`latency ≤ 5000 мс`, `loss ≤ 50%`, `duration ≤ 120 с`) —
    спека сверх бюджета отвергается до установки правила.
  - `NetChaosSession` с гарантированным откатом через `Drop` (обязательный
    `CLEANUP`, D7): даже при панике/раннем возврате правило снимается, остатка
    нет. Дефолтный `SimBackend` фиксирует правила в памяти для проверок.
- **Linux-стенд**: aya/TC-бэкенд (`aya_backend`) за фича-флагом `ebpf`
  (`cfg(all(target_os = "linux", feature = "ebpf"))`) — seam для eBPF-инъекции
  через `clsact` + `SchedClassifier`, без shelling-out в `tc`/`iptables` (D7).
  По умолчанию выключен, поэтому весь workspace собирается и тестируется на
  любой платформе (macOS в т.ч.); реальный BPF-объект собирается на стенде.

- **Сквозной mTLS и безопасная конфигурация**:
  - **Fail-closed семантика** в `asmodeus-proto::tls`: при неполной конфигурации
    переменных окружения (указан сертификат/ключ, но отсутствует CA) система
    завершается с явной ошибкой `TlsError::IncompleteConfig` вместо тихого
    отката на plaintext dev-режим.
  - **Раздельные переменные окружения**: независимая настройка для раннера
    (`ASMODEUS_RUNNER_TLS_*`) и control-plane (`ASMODEUS_CLIENT_TLS_*`) с fallback
    на общие `ASMODEUS_TLS_*`, а также переопределение целевого домена `ASMODEUS_TLS_DOMAIN`.
  - **In-memory programmatic API**: структуры `MtlsConfig`, `server_tls_config` и
    `client_tls_config` для конфигурирования TLS напрямую из PEM-байтов без диска.
  - **Фикстуры генерации сертификатов в `asmodeus-testkit`**: `TestMtls`
    генерирует на лету валидные пары CA/Server/Client и rogue-сертификаты на базе `rcgen`
    для надежного тестирования без статических ключей в git.
  - **Сквозные и негативные тесты mTLS**: в `asmodeus-runner` и `asmodeus-control-plane`
    протестированы успешный прогон сценария по mTLS, отклонение клиентов без сертификата
    или с недоверенным сертификатом.

### Исправлено (ревью)
- **Path traversal в canary-scope**: `path_in_scope` теперь отклоняет любые
  `..`-компоненты до prefix-проверки — путь с `..` больше не выходит за
  blast-radius (INV-0).
- **Паника CLI `from_hex`** на не-ASCII вводе: разбор по байтам вместо среза
  строки — некорректный hex даёт `BadHex`, а не панику.
- **Ложный COMPLETED при диспатче**: control-plane требует терминальное
  событие `Completed` от раннера; иначе прогон не считается успешным.
- **Ресурсные лимиты раннера**: `Execute` отклоняет запросы сверх бюджета
  (`file_count`/`chunk_size_kb`/суммарный объём) до аллокаций и записи.
- **Resilience Score отражает MTTR**: recovery-компонент считается из mean MTTR
  против цели `TARGET_MTTR_MS` (300 мс), а не хардкод-константы 100.
- **Дедупликация тестов**: тесты раннера используют `asmodeus-testkit`
  (`Polygon`, `signed_scenario`) вместо ручной генерации ключей и путей.

### Планируется
- eBPF-инъекция сетевого хаоса в раннере через `aya` (только на Linux-стенде).
- Реестр раннеров и реальный heartbeat/dead-man в gRPC-петле.


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
