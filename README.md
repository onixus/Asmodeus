# ASMODEUS

> **Adversary Emulation (BAS), Red Team Cyber Exercises & Chaos Engineering Engine**  
> Наступательный компонент экосистемы **APEX DEFENSE** для непрерывной валидации замкнутого цикла киберзащиты (NIST CSF 2.0).

---

## 🎯 Назначение проекта

**Asmodeus** — автономный движок моделирования действий злоумышленников (Breach and Attack Simulation, BAS), проведения санкционированных кибер-учений (Red Team) и стресс-тестирования инфраструктуры (Chaos Engineering).

В единой экосистеме киберзащиты Asmodeus выступает **наступательным спарринг-партнером** для защитных компонентов:
- Сенсоров ядра **Ferrum** (eBPF и K8s Admission Webhook);
- Сетевого барьера **BSDM-Proxy** (SWG, DNS Sinkhole RPZ);
- Агентов рабочих станций **Lariska** (CPU/E-cores affinity, watchdog);
- Корпоративных сканеров **PT MaxPatrol VM**, **PT XSpider** и автоматизации **SOAR**.

---

## 🧭 Документация Проекта

Вся архитектура и спецификации формализованы в нормативных документах:

1. 📋 **[Функционально-Технические Требования (FTT.md)](FTT.md)**:
   - Бизнес-цели и назначение системы;
   - Ролевая модель доступа (RBAC: Admin, Red Team, DevSecOps, CISO, Auditor);
   - Сценарии атак по MITRE ATT&CK: 8 сценариев, покрывающих 7 тактик (`T1486 Ransomware`, `T1611 K8s Escape`, `T1071 C2 Beaconing`, `T1003 Honeytokens`, `T1070 Log Tamper`, `T1053 Persistence Cron`, `T1041 Exfiltration`, `T1562 Impair Defenses`);
   - Инфраструктурный хаос (`LATENCY_SPIKE_VM`, `AGENT_CRASH_ENDPOINT`, `DNS_RPZ_SINKHOLE_DROP`);
   - Защитные барьеры (Blast Radius, Circuit Breaker, Auto-Rollback);
   - Замер метрик реакции Blue Team (MTTD, MTTR, Resilience Score).

2. ⚙️ **[Технические Требования (TT.md)](TT.md)**:
   - Декомпозиция компонентов (`control-plane`, `runner`, `dsl`, `safety`, `telemetry`);
   - Конечный автомат жизненного цикла (`IDLE` ➔ `ARMED` ➔ `INJECTING` ➔ `CONTAINED` ➔ `CLEANUP`);
   - Инварианты безопасности (строго синтетические canary-файлы, подпись Ed25519, Dead-man switch);
   - Бюджет системных ресурсов (RAM &lt; 32 MB для раннера, CPU &lt; 5%);
   - Контракты REST API (OpenAPI 3.1) и gRPC mTLS;
   - Сравнительная матрица оценки языков реализации (Rust vs Go vs Python).

3. 🏛️ **[Архитектура (ARCHITECTURE.md)](ARCHITECTURE.md)** — канонический документ:
   - Зафиксированные решения (базовый язык **Rust**, единый workspace, границы с APEX);
   - Декомпозиция на 10 крейтов и ацикличный граф зависимостей;
   - Единый автомат жизненного цикла (снимает расхождение FTT ↔ TT);
   - Карта внешних зависимостей (tokio, axum, tonic, aya, ed25519-compact).

4. 📝 **[История изменений (CHANGELOG.md)](CHANGELOG.md)** — версии и релизы.

---

## 🔄 Место в Замкнутом Цикле APEX

```
   ┌──────────────────────┐                     ┌──────────────────────┐
   │       ASMODEUS       │ ──[ Учения / Атака ]─> │     ИНФРАСТРУКТУРА   │
   │   (Red Team Engine)  │                     │   Ferrum / BSDM /    │
   └──────────────────────┘                     │   Lariska / K8s      │
              ▲                                 └──────────┬───────────┘
              │                                            │
              │ Замер метрик                               │ Детекция &
              │ MTTD / MTTR                                │ Сдерживание
              │                                            ▼
   ┌──────────┴───────────┐                     ┌──────────────────────┐
   │  APEX UNIFIED CONSOLE│ <──[ Алерты & SOAR ]┤      BLUE TEAM       │
   │  🔴 [RED TEAM]       │                     │    (Замкнутый контур │
   │  ⚡ [CHAOS TEST]     │                     │     NIST CSF 2.0)    │
   └──────────────────────┘                     └──────────────────────┘
```

---

## 🚦 Статус разработки

- [x] Инициализация репозитория
- [x] Разработка Функционально-Технических Требований ([FTT.md](FTT.md))
- [x] Разработка Технических Требований ([TT.md](TT.md))
- [x] Выбор технологического стека и архитектуры ([ARCHITECTURE.md](ARCHITECTURE.md)) — **Rust**, единый workspace
- [x] Скелет workspace: 10 крейтов, собирается (`cargo build --workspace`)
- [x] MVP-ядро: стейт-машина жизненного цикла, RBAC-матрица, верификация Ed25519 (24 теста)
- [x] Control-plane: axum REST-сервер, каталог подписанных сценариев, движок прогона
- [x] Runner: синтетический canary-инъектор (обратимый XOR, scope-guard, авто-очистка)
- [x] Safety: circuit breaker + dead-man switch; Telemetry: MTTD/MTTR + экспортёр Prometheus
- [x] gRPC/mTLS канал: proto-контракт (tonic), RunnerControl-сервер в раннере, mTLS-обвязка
- [x] Замкнутый контур: control-plane диспатчит подписанный сценарий в живой раннер по gRPC (REST → gRPC → инъекция → откат)
- [x] Операторский CLI (`asmodeus`): `keygen`/`sign`/`verify`/`validate` — офлайн-подпись сценариев (Ed25519)
- [x] CLI `run`/`status` (REST к control-plane) и `asmodeus-testkit` (полигон + фикстуры подписи)
- [x] Сетевой хаос в раннере (`LATENCY_SPIKE_VM`): INV-0 сетевой scope (только тест-блоки RFC 5737 + loopback), бюджетные лимиты, `NetChaosSession` с обязательным откатом (D7); кросс-платформенный `SimBackend`
- [x] **Расширение покрытия MITRE ATT&CK**: 11 сценариев (8 атак на 7 тактик + 3 хаоса), синтетические инъекторы в раннере под INV-0, REST-эндпоинты матрицы (`/api/v1/asmodeus/scenarios`, `/scenarios/mitre`), CLI команды `asmodeus scenarios`/`mitre`, 94 теста
- [x] **Реестр раннеров, gRPC Heartbeat и динамическая маршрутизация**: потокобезопасный `RunnerRegistry`, диспетчеризация по `target_override` и тегам целевого окружения, REST API зондов (`/api/v1/asmodeus/runners`), интеграция `DeadManSwitch` и `CircuitBreaker` в раннер, CLI команды `asmodeus runners list/register/deregister/ping`, 100 тестов
- [x] **Криптографический Журнал Аудита, Оркестрация Кампаний и Watchdog**: нефальсифицируемый `AuditRecord` с цифровой подписью Ed25519, REST эндпоинты `/runs`, `/runs/:id`, `/runs/:id/verify`, оркестратор комплексных цепочек атак (Playbooks / Campaigns: `CAMP-RANSOMWARE-CHAIN`, `CAMP-K8S-ESCAPE-CHAOS`, `CAMP-PERSISTENCE-EXFIL`), фоновый воркер опроса зондов `watchdog`, команды CLI `asmodeus runs` и `asmodeus campaigns`, 104 теста
- [x] **Декларативный DSL, Замкнутый Цикл NIST Closed-Loop и Исполнительная Отчётность**: типизированный парсер и валидатор YAML/JSON манифестов (`asmodeus-dsl::manifest`, `POST /scenarios/validate`), приём обратной связи детекции и сдерживания Blue Team / SOAR (`POST /runs/:id/feedback`, `asmodeus runs feedback`), переподпись аудита Ed25519, генератор исполнительных отчётов кибер-устойчивости NIST CSF 2.0 (`/reports/resilience`, `/runs/:id/report`, `asmodeus report`), политика защиты цепочки поставок `deny.toml`, 110 тестов
- [x] **OpenAPI 3.1 Gateway Contract, Persistent JSONL Audit & Dynamic Attack Campaigns**: канонический генератор OpenAPI 3.1 (`GET /api/v1/asmodeus/openapi.json`), персистентное append-only хранилище записей аудита (`ASMODEUS_AUDIT_LOG`) и потоковый экспорт (`GET /api/v1/asmodeus/audit/export?format=jsonl|json`), динамическая регистрация и удаление кампаний атак (`POST/DELETE /api/v1/asmodeus/campaigns`), авто-загрузка подписанных манифестов из директории (`ASMODEUS_SCENARIOS_DIR`), расширение CLI (`asmodeus campaigns register/delete`, `asmodeus runs export`), 119 тестов
- [x] **Наблюдаемость дрейфа детекции и восстановление метрик после рестарта**: непрерывный BAS-планировщик теперь ведёт ограниченную историю прогонов (`run_history`) и нефальсифицируемый журнал алертов дрейфа MTTD (`DriftAlert`), доступный операторам; новые REST-эндпоинты `GET /api/v1/asmodeus/schedules/:id` (детализация + таймлайн дрейфа), `GET /api/v1/asmodeus/schedules/alerts` (список регрессий детекции), `PATCH /api/v1/asmodeus/schedules/:id` (пауза/возобновление без удаления); восстановление Prometheus-агрегата (`Aggregate::from_records`) из персистентного журнала аудита при старте — `/metrics`, `/telemetry/mttd` и отчёт устойчивости больше не обнуляются после рестарта; команды CLI `asmodeus schedules get/alerts/toggle`, 143 теста
- [x] **Типизированная runtime-конфигурация control-plane**: переменные `ASMODEUS_LISTEN`, `ASMODEUS_WATCHDOG_INTERVAL_SEC` и `ASMODEUS_SCHEDULER_INTERVAL_SEC` теперь разбираются централизованно и fail-fast при неверных значениях; интервалы фоновых циклов больше не захардкожены в `main.rs`; добавлены детерминированные unit-тесты конфигурации.
- [ ] *Следующий этап (Linux-стенд)*: подключить компилируемый BPF-объект к aya/TC-бэкенду (`--features ebpf`) — на macOS не проверяется

## Надёжность и постоянный аудит

Результаты текущей проверки, исправления и ограничения production описаны в
[архитектурном обзоре от 22 сентября 2026](docs/architecture-review-2026-09-22.ru.md).
Emergency abort и dead-man switch пока не обеспечивают подтверждённую удалённую
отмену; показатели детекции до Blue Team feedback остаются синтетическими.

Для сохранения проверяемого аудита между рестартами задайте **оба** параметра:

- `ASMODEUS_AUDIT_LOG` — путь к JSONL-журналу, один writer-процесс на файл.
- `ASMODEUS_AUDIT_SIGNING_KEY` — путь к постоянному Ed25519 secret key в hex
  (формат `asmodeus keygen --name <path>`; файл `<path>.key`).

Ключ храните как secret вне репозитория и сохраняйте между рестартами. При
повреждённом журнале или неверном ключе сервис откажется запускаться. Старый
журнал, подписанный утраченным временным demo-ключом, требует отдельного
архивирования; автоматически доверять ему или переподписывать его сервис не будет.
Feedback добавляет подписанную ревизию; API и экспорт показывают последнюю
ревизию каждого прогона. Ошибка сохранения возвращается клиенту, а метрики
обновляются только после успешной записи.
