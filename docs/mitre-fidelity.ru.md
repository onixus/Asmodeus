# MITRE-разметка и модель fidelity (S01)

> Задача [#26 (MITRE S01)](https://github.com/onixus/Asmodeus/issues/26). Документ
> фиксирует закреплённую (pinned) таксономию ATT&CK, модель достоверности
> сценариев (**fidelity**) и таблицу перехода «старый mapping → новый mapping».
>
> **Границы.** S01 вводит модель и честные флаги покрытия. Реальный
> protection-gate (пересчёт prevention/containment в исполнительном отчёте и
> приёмке кампаний) этой задачей **не** закрывается — это S02/S03/S04.

## 1. Закреплённая таксономия

Таблица техник — это закреплённое, вручную выверенное подмножество матрицы
MITRE ATT&CK Enterprise, помеченное версией `ATTACK_VERSION`
(`crates/asmodeus-dsl/src/mitre.rs`). Это не живой импорт STIX: включены только
техники и суб-техники, на которые реально ссылаются сценарии Asmodeus.

- Каждая запись несёт канонический `id`, `name`, **основную** тактику `tactic`
  (для обратной совместимости с подписанным аудитом/wire/ClickHouse) и **полный**
  набор тактик `tactics` (техника может принадлежать нескольким тактикам —
  например `T1053`: Persistence/Execution/Privilege Escalation).
- Суб-техника (`T1071.001`) ссылается на базовую технику через `parent`.
- Любой `id`, которого нет в таблице, не проходит валидацию манифеста и ловится
  CI (`is_known_id`, тесты `*_ids_are_known`, `every_mapped_control_technique_is_known`).

Изменение канонической строки техники — это ревизия таксономии: оно меняет
подписываемые встроенные манифесты и преимидж аудита, поэтому требует поднятия
`ATTACK_VERSION` и повторного прогона затронутых signature-тестов.

## 2. Модель fidelity

INV-0 (ARCHITECTURE.md §0): Asmodeus **имитирует** технику, а не несёт боевой
способности. `Fidelity` фиксирует, насколько точно синтетический сценарий
воспроизводит технику, и, следовательно, **какое покрытие он вправе заявлять**.

| Fidelity | Что делает | Что вправе заявлять |
| :--- | :--- | :--- |
| `unspecified` | legacy / не объявлено (манифест `v1alpha1`) | ничего сверх marker-only; **никогда не повышается** |
| `marker_only` | создаёт/читает синтетический маркер (decoy-файл, honeytoken, pulse, beacon-лог) | только наличие индикатора; **не** behavioral, **не** prevention |
| `behavioral` | выполняет представительное синтетическое поведение в canary/тест-скоупе (обратимый XOR, сетевая пертурбация на тест-сетях) | behavioral-сигнал; prevention/containment — только при подтверждённом Blue Team feedback |

Уровня «weaponized»/реального воздействия не существует — он запрещён INV-0.
`marker_only` и `unspecified` **никогда** не дают behavioral/prevention покрытия
(`Fidelity::claims_behavioral` / `permits_prevention_claim`).

## 3. Версионирование манифестов

- `asmodeus.io/v1alpha1` — legacy. Читается совместимо, но **не повышается**:
  какой бы `fidelity` он ни объявил, эффективная достоверность —
  `unspecified` (`ScenarioManifest::effective_fidelity`).
- `asmodeus.io/v1alpha2` — текущая схема. Может нести `fidelity` и список
  `mitre_techniques` (мульти-техника, per-technique fidelity, primary — первый).
  Объявленная per-technique достоверность зажимается сверху эффективной
  достоверностью манифеста и фактически реализованным action: marker-инъекторы
  не повышаются декларацией `behavioral`; behavioral T1486 доступен только
  `synthetic_canary_encrypt`. Primary-проекция берётся из первого элемента
  `mitre_techniques`; противоречащий ему `mitre_technique` отклоняется.

Оба значения принимаются валидатором; все ссылки на техники (и одиночная
`mitre_technique`, и список) обязаны разрешаться в таксономии.

## 4. Таблица перехода: старый → новый mapping

Fidelity назначена по инъектору, который сценарий реально запускает
(`asmodeus-runner::injectors::create_injector`). Поведенчески исполняются только
обратимый XOR-инъектор и сетевой chaos; остальное пишет/читает маркер.

| Сценарий | Старый mapping (подразумевал полное покрытие) | Новый mapping (техники @ fidelity) | Fidelity | Ключевое ограничение |
| :--- | :--- | :--- | :--- | :--- |
| `RANSOMWARE_CANARY_SPIKE` | T1486 | T1486 | **behavioral** | обратимый XOR по синтетическим canary-докам; не реальное шифрование |
| `K8S_ESCAPE_SIMULATION` | T1611 | T1611 | **marker_only** | только маркер-файлы; **не** выполняет реальный escape to host |
| `C2_BEACONING_SIMULATION` | T1071 | T1071, T1071.001, T1071.004, T1568 | **marker_only** | пишет beacon-события в canary-лог; реального egress/DNS нет |
| `CREDENTIAL_ACCESS_CANARY` | T1003 | T1003 | **marker_only** | только synthetic honeytoken; реальных кредов не касается |
| `LOG_TAMPER_CANARY` | T1070 | T1070 | **marker_only** | truncate собственного canary-лога; реальные индикаторы не удаляются |
| `PERSISTENCE_CRON_CANARY` | T1053 | T1053 | **marker_only** | decoy cron-файл в canary; реальный планировщик не меняется |
| `DATA_EXFILTRATION_CANARY` | T1041 | T1041 | **marker_only** | synthetic blob в canary; данные не покидают хост |
| `DEFENSE_IMPAIRMENT_CANARY` | T1562 | T1562, T1562.001 | **marker_only** | benign pulse-маркер; реальные средства защиты не отключаются |
| `LATENCY_SPIKE_VM` | — (chaos) | — | **behavioral** | chaos на тест-сетях; к технике ATT&CK не относится |
| `AGENT_CRASH_ENDPOINT` | T1562 (chaos) | T1562 | **marker_only** | pulse-маркер для проверки watchdog; средства защиты не трогает |
| `DNS_RPZ_SINKHOLE_DROP` | — (chaos) | — | **behavioral** | chaos на loopback тест-сегменте; к технике ATT&CK не относится |

Источник истины для таблицы — `crates/asmodeus-control-plane/src/scenario_profile.rs`
(каждая запись несёт также procedure ID/revision, платформы, preconditions, scope
безопасности и ожидаемые observable).

## 5. Честность в API/CLI/отчёте

- `GET /scenarios` и `/scenarios/:id` отдают `fidelity`,
  `claims_behavioral_coverage`, а `:id` — полный `technique_refs` и `profile`
  (procedure id/revision, platforms, observables, limitations).
- `GET /scenarios/mitre`: `covered_techniques_count` сохранён для совместимости и
  означает «**упомянутые** техники», а не покрытие. Честные поля —
  `behavioral_coverage_count` и `marker_only_techniques_count`; каждая строка
  несёт `fidelity`, `claims_behavioral_coverage` и `limitations`, плюс
  `coverage_note` и `attack_version`.
- Отчёт соответствия помечает контроль как `behavioural` или `⚠️ marker-only`
  (`prevention_eligible`, `coverage_note`); marker-only не выдаётся за prevention.
- CLI печатает ответ сервера дословно и наследует эти поля.

## 6. Что НЕ сделано в S01

- Пересчёт NIST «Protect/Respond»-столбов исполнительного отчёта по fidelity —
  S04 (вместе с campaign acceptance и моделью evidence).
- Разделённые detection/prevention/containment и доверенная корреляция Blue Team
  feedback — S03.
- Шесть фиксированных воспроизводимых procedure-slots — S02, реализовано:
  см. [`docs/mitre-fidelity-s02.ru.md`](./mitre-fidelity-s02.ru.md).
