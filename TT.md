# ASMODEUS — Технические Требования (ТТ)
## Архитектурные, Системные и Эксплуатационные Требования к Платформе

**Версия документа**: 1.0.0-DRAFT  
**Статус**: Утверждение технических спецификаций  
**Кодовая база**: monorepo `Asmodeus`

---

## 1. Архитектура Системы и Декомпозиция Компонентов

Платформа проектируется по распределенной микроядерной архитектуре с четким разделением управляющего контура (Control Plane) и исполнительных зондов (Runners / Probes).

```
┌────────────────────────────────────────────────────────────────────────┐
│                      ASMODEUS CORE ARCHITECTURE                        │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                 asmodeus-control-plane                         │   │
│   │   • REST & gRPC API Server                                     │   │
│   │   • Scenario Catalog & DSL Validator                           │   │
│   │   • Role-Based Access Controller (RBAC Engine)                 │   │
│   │   • Run State Machine Manager                                  │   │
│   │   • Cryptographic Scenario Verifier (Ed25519)                  │   │
│   └───────────────┬────────────────────────────────┬───────────────┘   │
│                   │                                │                   │
│         gRPC / mTLS Control Channel      REST API Telemetry Stream     │
│                   │                                │                   │
│   ┌───────────────▼───────────────┐  ┌─────────────▼───────────────┐   │
│   │      asmodeus-runner          │  │     asmodeus-telemetry      │   │
│   │  • Synthetic Canary Injector  │  │  • MTTD/MTTR Engine         │   │
│   │  • Network Jitter/Drop Engine │  │  • Tagging & Event Injector │   │
│   │  • Process Lifecycle Fuzzer   │  │  • Prometheus / OTel Exporter│  │
│   │  • Circuit Breaker Watchdog   │  │  • Audit Trail Logger       │   │
│   └───────────────────────────────┘  └─────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.1. Компоненты Системы

1. **`asmodeus-control-plane`**:
   - Центральный координирующий сервис.
   - Хранит каталог проверенных сценариев атак (MITRE TTPs) и конфигураций инфраструктурного хаоса.
   - Обеспечивает строгую аутентификацию и авторизацию по ролям (`admin`, `red_team`, `devsecops`, `ciso`, `auditor`).
   - Поддерживает жизненный цикл сессий тестирования и управляет распределением команд на раннеры.

2. **`asmodeus-runner` (Исполнительный зонд)**:
   - Минималистичный агент, запускаемый локально на целевом хосте, в виде DaemonSet/Job в Kubernetes или в выделенном контейнере.
   - Выполняет атомарные действия сценария (инъекция canary-шифрования, спавн тестовых процессов, сетевая эмуляция).
   - Включает аппаратный сторожевой таймер (**Circuit Breaker**), автоматически сбрасывающий любое воздействие при возникновении сбоя.

3. **`asmodeus-dsl` (Спецификация и валидация сценариев)**:
   - Библиотека парсинга декларативных манифестов сценариев (`AttackScenario`, `ChaosExperiment`).
   - Валидация типов параметров, ограничений безопасности (белые списки путей и портов).
   - Проверка цифровой подписи манифеста перед запуском.

4. **`asmodeus-safety` (Модуль изоляции и отказоустойчивости)**:
   - Независимый поток контроля ресурсов: отслеживает CPU, память, дескрипторы файлов целевого узла.
   - Гарантирует изоляцию воздействий исключительно в canary-сегментах.

5. **`asmodeus-telemetry` (Подсистема аналитики и интеграции)**:
   - Замеряет метрики задержки обнаружения (**MTTD**) и времени сдерживания (**MTTR**).
   - Экспортирует метрики в формате Prometheus / OpenTelemetry.
   - Формирует журнал событий с цифровой подписью для последующего аудита.

---

## 2. Конечный Автомат Исполнения (Scenario State Machine)

Каждый сценарий кибер-учений или хаос-теста обязан следовать строгому детерминированному жизненному циклу:

```
  [ IDLE ] 
     │
     ▼ (Валидация DSL + Проверка подписи Ed25519)
  [ VALIDATED ]
     │
     ▼ (Проверка роли RBAC: admin / red_team / devsecops)
  [ ARMED ] 
     │
     ▼ (Инициализация canary-песочницы + Dead-man Switch)
  [ INJECTING ] ────────┐
     │                  │ (Превышение лимитов ресурсов / Таймаут)
     ▼ (Замер MTTD)     │
  [ DETECTED ]          ▼
     │              [ CIRCUIT_BREAKER_TRIPPED ]
     ▼ (Замер MTTR)     │
  [ CONTAINED ]         │
     │                  │
     ▼                  ▼
  [ CLEANUP / ROLLBACK ] (Удаление canary-файлов, сброс сетевых правил)
     │
     ▼
  [ COMPLETED / ARCHIVED ]
```

### Инварианты переходов:
- Запрещен переход в `INJECTING` без предварительного успешного прохождения проверки `ARMED` и верификации цифровой подписи сценария.
- Любой сбой сети или зависание раннера инициирует автоматический безусловный переход в `CLEANUP / ROLLBACK`.
- Время нахождения в состоянии `INJECTING` жестко ограничено параметром `max_duration_sec` (по умолчанию не более 120 секунд).

---

## 3. Требования к Безопасности и Изоляции (Safety Invariants)

1. **Запрет на использование реальных вредоносных нагрузок**:
   - Asmodeus **не содержит** и **не использует** реальное вредоносное ПО, эксплойты нулевого дня или деструктивные payload.
   - Все техники имитируются исключительно через синтетические маркеры (Canary files, псевдо-шифрование в тестовой папке, безопасные сетевые ping-сигналы).
2. **Белый список областей воздействия (Scope Whitelisting)**:
   - Файловые операции разрешены **только** внутри путей: `/var/tmp/asmodeus-canary/*` или `/tmp/asmodeus-canary/*`.
   - Сетевые операции разрешены **только** на локальные порты или адреса из белого списка тестового полигона (`127.0.0.1`, RFC 1918 тестовые подсети).
3. **Подпись сценариев (Cryptographic Integrity)**:
   - Все сценарии подписываются ключом Red Team Lead (Ed25519).
   - Раннер отказывается исполнять сценарий с нарушенной или отсутствующей подписью.
4. **Защита от отказа управляющего контура (Dead-Man Switch)**:
   - Раннер поддерживает периодический heartbeat с Control Plane (интервал: 1000 мс).
   - При потере 3 heartbeat подряд раннер мгновенно глушит все запущенные процессы и откатывает сетевые правила.

---

## 4. Системные и Эксплуатационные Требования

### 4.1. Ресурсные ограничения (Resource Budget)
| Компонент | Макс. CPU | Макс. RAM | Дисковое пространство | Сетевой оверхед |
| :--- | :---: | :---: | :---: | :---: |
| **`asmodeus-runner`** | &le; 5% от одного ядра | &le; 32 MB | &le; 20 MB | &le; 100 КБ/с (телеметрия) |
| **`asmodeus-control-plane`** | &le; 10% от одного ядра | &le; 128 MB | &le; 50 MB | Пренебрежимо мал |

### 4.2. Целевые платформы и ОС
- **Linux**: x86_64, aarch64 (Ubuntu 20.04+, RHEL/Rocky 8+, Alpine 3.18+, ядра Linux &ge; 5.4).
- **Kubernetes**: 1.25+ (управляемые кластеры k8s, OpenShift, k3s).
- **macOS**: Apple Silicon (M1/M2/M3/M4) и Intel (для локального тестирования и валидации агентов).

### 4.3. Сетевые протоколы и интерфейсы
1. **gRPC / Protocol Buffers (v3)**:
   - Внутренний управляющий канал между Control Plane и Runner;
   - Стриминг логов и событий в режиме реального времени;
   - Аутентификация по взаимным сертификатам (mTLS).
2. **REST API (HTTP/1.1 & HTTP/2)**:
   - Внешний интерфейс для интеграции с `unified-platform/gateway` платформы Apex;
   - Спецификация OpenAPI 3.1;
   - Передача ролевого контекста через заголовок `X-Apex-Role` и Bearer JWT токены.
3. **Prometheus Metrics Exporter**:
   - Эндпоинт `/metrics`:
     - `asmodeus_resilience_score` (gauge 0..100);
     - `asmodeus_mttd_seconds` (gauge);
     - `asmodeus_mttr_seconds` (gauge);
     - `asmodeus_scenarios_executed_total` (counter, labels: `category`, `initiator`, `status`).

---

## 5. Модель Данных API (Контракты REST & gRPC)

### 5.1. JSON-схема Запуска Сценария (`POST /api/v1/asmodeus/scenarios/{id}/run`)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ScenarioRunRequest",
  "type": "object",
  "required": ["scenario_id", "initiator_role"],
  "properties": {
    "scenario_id": {
      "type": "string",
      "enum": [
        "RANSOMWARE_CANARY_SPIKE",
        "K8S_ESCAPE_SIMULATION",
        "C2_BEACONING_SIMULATION",
        "CREDENTIAL_ACCESS_CANARY",
        "LOG_TAMPER_CANARY",
        "PERSISTENCE_CRON_CANARY",
        "DATA_EXFILTRATION_CANARY",
        "DEFENSE_IMPAIRMENT_CANARY",
        "LATENCY_SPIKE_VM",
        "AGENT_CRASH_ENDPOINT",
        "DNS_RPZ_SINKHOLE_DROP"
      ]
    },
    "initiator_role": {
      "type": "string",
      "enum": ["admin", "red_team", "devsecops"]
    },
    "target_override": {
      "type": "string",
      "description": "Опциональный целевой узел или под (в пределах разрешенного пула)"
    },
    "timeout_sec": {
      "type": "integer",
      "default": 60,
      "maximum": 300
    }
  }
}
```

### 5.2. JSON-схема Результата Запуска
```json
{
  "run_id": "run_98f41e2a",
  "scenario_id": "RANSOMWARE_CANARY_SPIKE",
  "tag": "🔴 [RED TEAM EXERCISE]",
  "initiator": "Red Team (Operator: red_team)",
  "status": "COMPLETED",
  "measurements": {
    "mttd_ms": 142,
    "mttr_ms": 280,
    "blue_team_detected": true,
    "detection_source": "ferrum_ebpf_kernel_probe",
    "containment_action": "SIGKILL via SOAR Policy"
  },
  "cleanup_status": "SUCCESS (50 canary files removed, 0 host side-effects)",
  "timestamp": "2026-09-04T03:50:00Z"
}
```

---

## 6. Критерии Выбора Технологического Стека (Оценка для Этапа 2)

| Критерий оценки | 🦀 Rust | 🔷 Go | 🐍 Python |
| :--- | :---: | :---: | :---: |
| **Совместимость с компонентами (Ferrum, Lariska, BSDM)** | **10 / 10** (единая экосистема, единый toolchain) | 7 / 10 | 6 / 10 |
| **Безопасность памяти и отсутствие GC** | **10 / 10** (нулевые задержки при замере MTTD) | 8 / 10 (GC паузы до 1-5 мс) | 4 / 10 (GIL, сборщик мусора) |
| **Низкоуровневое манипулирование (cgroups, namespaces, сокеты)** | **10 / 10** (прямой вызов libc/nix, eBPF через aya) | 9 / 10 (syscall package) | 6 / 10 (через ctypes/cffi) |
| **Размер и автономность бинарника раннера** | **10 / 10** (статический musl бинарник ~5 MB) | 9 / 10 (статический бинарник ~15 MB) | 3 / 10 (требует venv/runtime ~80 MB) |
| **Скорость разработки базового прототипа** | 7 / 10 (строгая система типов) | 9 / 10 | **10 / 10** |

> Решение по выбору языка и библиотек будет утверждено на следующем этапе в соответствии с указанием пользователя.
