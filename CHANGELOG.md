# Changelog

Все значимые изменения проекта фиксируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [семантического версионирования](https://semver.org/lang/ru/).

## [Unreleased]

### Добавлено
- **Спецификация OpenAPI 3.1.0 (`asmodeus-control-plane::openapi`)**:
  - Канонический генератор схемы OpenAPI 3.1.0 (`openapi.json`) для бесшовной интеграции с APEX Unified Gateway (FastAPI) и веб-консолью управления хаос-инженерией (`/chaos`).
  - Полное описание схем (`AuditRecord`, `Measurements`, `Campaign`, `Scenario`, `ResilienceReport`), эндпоинтов, схем аутентификации (`X-Apex-Role`) и кодов возврата (401, 403, 404, 422).
  - **Эндпоинт REST API**:
    - `GET /api/v1/asmodeus/openapi.json` — машиночитаемая спецификация OpenAPI 3.1.0.
- **Персистентное хранилище и потоковый экспорт журнала аудита (`AuditTrail`)**:
  - Потокобезопасная персистенция в файл в формате JSON Lines (JSONL) через переменную окружения `ASMODEUS_AUDIT_LOG`.
  - Автоматическое добавление записей при прогонах и сохранение обновлений при замкнутом цикле реагирования Blue Team (`run_feedback`).
  - Потоковый экспорт журнала аудита с валидацией RBAC (`Capability::ViewReports`):
    - `GET /api/v1/asmodeus/audit/export?format=jsonl|json` — экспорт нефальсифицируемого журнала в форматах JSON Lines или JSON array.
- **Динамическое управление кампаниями и плейбуками атак (Dynamic Attack Campaigns DSL)**:
  - Методы динамической регистрации и дерегистрации в `CampaignCatalog` (`register`, `deregister`).
  - Потокобезопасный доступ через `Arc<RwLock<CampaignCatalog>>` в `AppState`.
  - **Эндпоинты REST API**:
    - `POST /api/v1/asmodeus/campaigns` — регистрация кастомной цепочки атак (`Admin`, `RedTeam`);
    - `DELETE /api/v1/asmodeus/campaigns/:id` — удаление кампании по идентификатору (`Admin`, `RedTeam`).
- **Автоматическая загрузка внешних подписанных манифестов сценариев из директории**:
  - Метод `Catalog::load_from_dir(&mut self, dir: &Path)`: рекурсивное сканирование YAML/JSON манифестов, проверка инварианта INV-0 через `asmodeus_dsl::manifest::parse_manifest`, криптографическая подпись и постановка в каталог сценариев.
  - Поддержка переменной окружения `ASMODEUS_SCENARIOS_DIR` при инициализации `Catalog::seeded()`.
- **Расширение операторского CLI (`asmodeus-cli`)**:
  - `asmodeus campaigns register --manifest <PATH> [--role <ROLE>]` — регистрация кампании из файла YAML/JSON;
  - `asmodeus campaigns delete --id <CAMPAIGN_ID> [--role <ROLE>]` — удаление зарегистрированной кампании;
  - `asmodeus runs export [--format jsonl|json] [--out <PATH>]` — выгрузка криптографического журнала аудита в файл или stdout.
- **Декларативный парсер и валидатор манифестов сценариев (`asmodeus-dsl::manifest`)**:
  - **Типизированные структуры манифестов** по FTT §5 и TT §1.1: `ScenarioManifest`, `ManifestKind`,
    `ManifestMetadata`, `TargetScope`, `SafetySpec`, `ActionSpec`, `ExpectedOutcome`.
  - **Двойной парсер для YAML и JSON** (`parse_and_validate_manifest`) со строгой валидацией инварианта
    INV-0 (`ActionNature::Synthetic`), белых списков canary-каталогов (`path_in_scope`), тестовых
    подсетей RFC 5737 (`net_target_in_scope`), ресурсных бюджетов (CPU ≤ 85%, время ≤ 300с, лимиты
    файлов/размеров) и верификацией идентификаторов техник MITRE ATT&CK.
  - **Эндпоинт REST API**:
    - `POST /api/v1/asmodeus/scenarios/validate` — пре-валидация манифестов перед подписью и постановкой в каталог.
- **Движок валидации замкнутого цикла реагирования (NIST Closed-Loop & SOAR Feedback)**:
  - **Приём событий реагирования Blue Team / SOAR** (`POST /api/v1/asmodeus/runs/:id/feedback`):
    фиксация факта обнаружения (Ferrum eBPF, Lariska agent, BSDM proxy) и сдерживания (SOAR SIGKILL,
    quarantine), расчет фактических задержек MTTD и MTTR.
  - **Криптографическая переподпись записей аудита Ed25519**: обновление `AuditRecord` с сохранением
    нефальсифицируемости и актуализацией статуса (`CONTAINED`, `UNCONTAINED`).
  - **Динамический пересчёт метрик**: обновление скользящих агрегатов `Aggregate` и индекса
    `ResilienceScore` с учётом реального времени реагирования защитного контура.
- **Движок исполнительной отчётности NIST CSF 2.0 (`asmodeus-telemetry::reporting`)**:
  - **Маппинг на 6 функций фреймворка NIST CSF 2.0**: Govern (GV), Identify (ID), Protect (PR),
    Detect (DE), Respond (RS), Recover (RC).
  - **Оценка устойчивости**: аудит соблюдения SLA (`TARGET_MTTR_MS = 300 мс`), процент детекции
    по тактикам MITRE ATT&CK, формирование адресных рекомендаций для Blue Team.
  - **Генерация отчётов** в форматах Markdown (структурированный документ с бейджами и таблицами)
    и JSON (для интеграции с APEX FastAPI Gateway).
  - **Эндпоинты REST API**:
    - `GET /api/v1/asmodeus/reports/resilience` — сводный исполнительный отчёт устойчивости экосистемы;
    - `GET /api/v1/asmodeus/runs/:id/report` — детальный отчёт по конкретному прогону учений.
- **Расширение инструментов оператора в CLI (`asmodeus-cli`)**:
  - `asmodeus validate [--target-dir <DIR> | --manifest <PATH>]` — валидация каталогов или полных декларативных манифестов;
  - `asmodeus report [--format text|json]` — отображение исполнительного отчёта устойчивости NIST CSF 2.0;
  - `asmodeus runs feedback --id <RUN_ID> --detected <bool> [--detector <SRC>] [--mttd-ms <MS>] --contained <bool> [--containment-action <ACT>] [--mttr-ms <MS>]` — передача отклика Blue Team;
  - `asmodeus runs report --id <RUN_ID> [--format text|json]` — вывод детального отчёта по прогону.
- **Политика защиты цепочки поставок (`deny.toml`)**:
  - Конфигурация для `cargo-deny` в корне проекта (проверка открытых лицензий, запрет небезопасных
    источников, контроль уязвимостей через RustSec Advisory Database).
- **Криптографический Журнал Аудита (Signed Audit Trail Engine)**:
  - **Структура и подпись записей аудита** (`asmodeus-telemetry::audit`): структура `AuditRecord`
    со всеми параметрами прогона (run_id, scenario_id, category, mitre_technique, severity, tag,
    initiator, runner_id, status, measurements MTTD/MTTR, detection_source, containment_action,
    cleanup_status, timestamp_utc) и детерминированным каноническим представлением байтов.
  - **Цифровая подпись Ed25519**: подпись закрытым ключом Red Team Lead и верификация по публичному ключу
    (`AuditRecord::sign`, `AuditRecord::verify`), предотвращающие подделку факта проведения учений.
  - **Журнал `AuditTrail`**: потокобезопасная коллекция для хранения и фильтрации записей аудита.
  - **Эндпоинты REST API**:
    - `GET /api/v1/asmodeus/runs` — история прогонов с фильтрацией по лимиту, сценарию и статусу;
    - `GET /api/v1/asmodeus/runs/:id` — детальный отчёт о прогоне;
    - `GET /api/v1/asmodeus/runs/:id/verify` — независимая криптографическая проверка подписи записи аудита.
- **Оркестрация Кампаний и Плейбуков (Multi-Stage Attack Campaigns & Kill-Chains)**:
  - **Доменные модели кампаний** (`asmodeus-control-plane::campaign`): `Campaign`, `CampaignStep`,
    `CampaignStepResult`, `CampaignRunResult`.
  - **Предустановленный каталог кампаний** (`CampaignCatalog::seeded`):
    - `CAMP-RANSOMWARE-CHAIN`: цепочка вымогателя (Credential Dumping ➔ Persistence ➔ C2 ➔ Ransomware Spike);
    - `CAMP-K8S-ESCAPE-CHAOS`: побег из контейнера K8s в сочетании с сетевым хаосом и отказом DNS RPZ;
    - `CAMP-PERSISTENCE-EXFIL`: закрепление, зачистка логов и эксфильтрация данных по C2.
  - **Движок исполнения цепочек**: последовательное выполнение шагов, агрегация промежуточных замеров
    MTTD/MTTR, вычисление интегрального индекса устойчивости `ResilienceScore` по всей цепочке.
  - **Эндпоинты REST API**:
    - `GET /api/v1/asmodeus/campaigns` — список зарегистрированных кампаний;
    - `POST /api/v1/asmodeus/campaigns/:id/run` — запуск комплексной цепочки атак с поддержкой `target_override`.
- **Фоновый Heartbeat Watchdog** (`asmodeus-control-plane::watchdog`):
  - Асинхронный воркер в control-plane, периодически опрашивающий зонды по gRPC Heartbeat и
    актуализирующий их статус доступности (`Active` vs `Unresponsive`).
- **Инструменты оператора в CLI (`asmodeus-cli`)**:
  - `asmodeus runs list [--limit <N>] [--scenario <ID>] [--status <ST>]` — просмотр истории прогонов;
  - `asmodeus runs get --id <RUN_ID>` — детали записи аудита;
  - `asmodeus runs verify --id <RUN_ID>` — криптографическая проверка подписи записи аудита;
  - `asmodeus campaigns list` — просмотр каталога цепочек атак;
  - `asmodeus campaigns run --id <CAMPAIGN_ID> [--target <TARGET>]` — запуск многоэтапного учения.
- **Реестр раннеров, динамическая диспетчеризация и gRPC Heartbeat**:
  - **Реестр зондов** (`asmodeus-control-plane::registry`): потокобезопасный `RunnerRegistry`
    для динамического управления распределёнными раннерами с поддержкой тегов
    (`k8s_workload`, `endpoint_agent`, `network_gateway`), статусов (`Active`, `Unresponsive`, `Draining`)
    и сопоставления по `target_override` вместо одного статического эндпоинта.
  - **Эндпоинты REST API управления зондами**:
    - `GET /api/v1/asmodeus/runners` — список зарегистрированных зондов с их статусами и метриками;
    - `POST /api/v1/asmodeus/runners` — динамическая регистрация зонда с проверкой роли RBAC;
    - `DELETE /api/v1/asmodeus/runners/:id` — снятие зонда с регистрации;
    - `GET /api/v1/asmodeus/runners/:id/ping` — активный опрос доступности (liveness probe) через gRPC Heartbeat.
  - **Маршрутизация сценариев по `target_override`**: запуск через `POST /scenarios/:id/run`
    принимает JSON с целевым узлом или тегом и диспетчеризирует сценарий на соответствующий зонд.
  - **Расширение gRPC контракта `Heartbeat`** (`asmodeus-proto`): передача состояния раннера
    (`Idle`, `Injecting`), флага здоровья, нагрузки CPU, идентификатора активного упражнения и версии.
  - **Интеграция Dead-Man Switch & Circuit Breaker в раннер** (`asmodeus-runner::service`):
    контроль времени и ресурсов во время инъекции с безусловным срабатыванием `TripBreaker`
    и автоматической очисткой, фиксация сердцебиений для защиты от отказа управляющего контура.
  - **Команды CLI** (`asmodeus runners list/register/deregister/ping` и `--target` в `asmodeus run`):
    полный операторский цикл взаимодействия с распределёнными зондами.
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
