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
- [ ] *Следующий этап (Linux-стенд)*: подключить компилируемый BPF-объект к aya/TC-бэкенду (`--features ebpf`) — на macOS не проверяется