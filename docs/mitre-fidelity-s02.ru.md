# Воспроизводимые процедуры первой MITRE-волны (S02)

> Задача [#27 (MITRE S02)](https://github.com/onixus/Asmodeus/issues/27).
> Опирается на модель fidelity из [S01](./mitre-fidelity.ru.md) (закреплённая
> таксономия, `Fidelity`, honest coverage).
>
> **Границы.** S02 вводит фиксированный versioned corpus из шести synthetic-only
> procedure-slots, их инъекторы/валидаторы, safety-харнесс и manifest
> выполненных локальных процедур. S02 **не** меняет подписанный аудит-преимидж
> (`AuditRecord::canonical_bytes` — это S03), не расширяет разрешения на
> production и не выполняет реальных разрушительных действий. Полное закрытие
> дополнительно зависит от эпика `onixus/unified-platform#45` и независимого
> reviewer-а.

## 1. Что такое procedure slot

Slot — это единица, которую оператор реально запускает на стенде. Каждый slot
закреплён в `asmodeus-dsl::procedures` (чистые данные) и честно разделяет три
вещи, которые отчёты обычно смешивают:

- **на какие техники ATT&CK он ссылается и в какой роли** —
  `behavioral_candidate` (может воспроизвести представительное поведение) или
  `precondition_signal` (только измеряемая предпосылка/сигнал). `T1611`
  промаркирован как `precondition_signal`: достижимость тестового runtime-сокета
  — это сигнал-предпосылка, **не** обещание реального escape to host;
- **в каком `ExecutionMode` он выполняется** — `marker` / `replay` /
  `behavioral`; режим ограничивает заявляемую `Fidelity` (marker/replay →
  только indicator-only, тот же гейт, что в S01);
- **поддерживается ли он в текущем окружении**. Неподдерживаемый slot — это
  `NOT_RUN`; он остаётся в знаменателе покрытия и **никогда** не удаляется ради
  зелёного результата.

Источник истины — `crates/asmodeus-dsl/src/procedures.rs`
(`CORPUS_VERSION = "asmodeus-mitre-wave1-v2"`). Исполнение, safety-харнесс и
manifest — `crates/asmodeus-runner/src/procedures.rs`.

## 2. Шесть slots (corpus v2)

| Slot | Procedure | Техника (роль) | Платформы | Требование | Локальный режим | Что проверяет / ограничение |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `WAVE1-EXEC-CONTAINER` | `ASMOD-WAVE1-0001` | T1609 (behavioral_candidate) | containers/k8s/linux | canary admin-сокет стенда | marker (иначе NOT_RUN) | синтетическая exec-команда в canary-сокет; реальный рантайм не трогается |
| `WAVE1-EXEC-SHELL` | `ASMOD-WAVE1-0002` | T1059.004 (behavioral_candidate) | linux/macos | canary FS | marker | транскрипт shell-команды в canary; реальный shell локально не запускается |
| `WAVE1-EXEC-RUNTIME-SOCKET` | `ASMOD-WAVE1-0003` | T1611 (**precondition_signal**) | containers/linux | canary runtime-сокет стенда | marker (иначе NOT_RUN) | сигнал достижимости тест-сокета; **не** escape и не доступ к хосту |
| `WAVE1-C2-HTTP-BEACON` | `ASMOD-WAVE1-0004` | T1071.001 (behavioral_candidate) | network/linux | loopback test-receiver | behavioral | реальный loopback-round-trip с синтетическим beacon; egress наружу нет |
| `WAVE1-C2-DNS` | `ASMOD-WAVE1-0005` | T1071.004 (behavioral_candidate) | network/linux | loopback test-receiver | behavioral | корректный DNS TXT question в loopback UDP; внешнего резолва нет |
| `WAVE1-EXFIL-TRANSFER` | `ASMOD-WAVE1-0006` | T1041 (behavioral_candidate) | network/linux | loopback test-receiver | behavioral | реальная loopback-передача canary-блоба; данные хост не покидают |

Каждый slot дополнительно несёт: `preconditions`, `expected_observables`,
`limitations`, `safety_scope`, **benign paired control** (ожидаемое поведение
продукта + как проверить фактический эффект) и `ResourceBudget`
(`max_duration_ms`/`max_bytes`/`max_files`). Ресурсы резервируются до
создания файла и отправки payload; превышение лимита не выполняет запись.
DNS procedure revision 2 отправляет корректный DNS wire-format (TXT/IN).
Повышение corpus до v2 требует нового прогона; результаты v1 не переносятся.

## 3. Режимы исполнения и потолок fidelity

| ExecutionMode | Что делает | Потолок fidelity |
| :--- | :--- | :--- |
| `marker` | создаёт/читает синтетический маркер или командную запись | `marker_only` |
| `replay` | повторно отдаёт ранее записанный набор observables без живого поведения | `marker_only` |
| `behavioral` | представительное синтетическое поведение в canary/loopback-скоупе (реальный loopback-round-trip к in-process test-receiver) | `behavioral` |

`marker` и `replay` **никогда** не дают behavioral/prevention покрытия
(`ExecutionMode::fidelity_ceiling`, тот же `Fidelity::claims_behavioral` из S01).
`behavioral` в attempt-manifest помечается `claims_behavioral: true`, но это сигнал
на loopback-стенде, а не реальное воздействие (INV-0).

## 4. Synthetic-only invariant и safety-харнесс

Каждый attempt идёт через харнесс (`asmodeus-runner::procedures`), который:

- **отклоняет out-of-scope цели до создания артефактов** — путь вне canary
  (`path_in_scope`), сетевой назначение вне loopback/RFC 5737
  (`net_target_in_scope`), сокет/namespace вне canary. См. негативные тесты
  `out_of_scope_targets_are_rejected`;
- применяет **timeout, cancellation, kill switch и ресурсный бюджет** — timeout и
  потерю heartbeat через `asmodeus-safety::CircuitBreaker`, бюджет байт/файлов
  поверх него, кооперативную отмену через `CancelToken`;
- **гарантирует cleanup на всех путях** — success / failure / crash / cancel —
  через `WorkDirGuard` (Drop-бэкстоп) + явную проверку, что каталог attempt-а
  удалён (`cleanup_verified`);
- даёт каждому attempt уникальный `attempt_id` и собственный canary-каталог, так
  что **повторный запуск не присваивает себе артефакты предыдущего attempt**.

Loopback test-receiver — это in-process `TcpListener`/`UdpSocket` на `127.0.0.1:0`
(в scope тест-блоков), ограниченный по времени; реальных credentials, разрушения
или внешней эксфильтрации нет.

## 5. Manifest выполненных процедур

`asmodeus-runner` c `ASMODEUS_MITRE_WAVE1=1` печатает JSON-manifest локального
прогона corpus (а с `ASMODEUS_MITRE_WAVE1=stand` — запрос стендового режима).
Canary-сокеты задаются явно: `ASMODEUS_MITRE_ADMIN_SOCKET` и
`ASMODEUS_MITRE_RUNTIME_SOCKET`. При отсутствии endpoint соответствующий slot
остаётся `NOT_RUN`; без обоих endpoint результат помечается `local-canary`.
Несуществующий endpoint, обычный файл или выход из canary scope отклоняется.
Runner не создаёт подставные runtime/admin-сокеты. Сам факт соединения с
предоставленным тестовым сокетом остаётся marker/precondition evidence и не
подтверждает реальное container exec или escape. Каждый attempt несёт: `attempt_id`, `procedure_id`
+ `procedure_revision`, environment manifest (`stand`, `os`, capabilities),
`started/stopped_unix_ms`, `mode`, реальные `observations`, `bytes_written` /
`files_created`, `fidelity_ceiling`, `claims_behavioral`, `cleanup_verified`.

Итог (`coverage`) всегда содержит фиксированный `denominator` (= число slots) и
счётчики `behavioral_pass` / `marker_pass` / `failed` / `not_run`. В плейн-окружении
(`local-canary`): 3 behavioral (сеть) + 1 marker (shell) PASS, 2 NOT_RUN
(container-exec, runtime-socket) — знаменатель остаётся 6.

**Локальный mock/marker PASS не заменяет выполнение на runtime-стенде.** Поле
`stand` и `mode` фиксируют это: marker/replay и локальный прогон никогда не
выдаются за behavioral-покрытие техники на стенде. genuine escape / credential
dumping для получения зелёного результата не добавляются.

## 6. Границы и условия закрытия

- Изменение `CORPUS_VERSION` после проверки требует impact review и повторного
  прогона затронутых процедур; результат одной процедуры не переносится на всю
  технику.
- `NOT_RUN`, skipped, marker-only, mock и отсутствие evidence не считаются
  подтверждённой защитой.
- Закрытие задачи требует независимого reviewer-а и зависит от внешнего эпика
  `onixus/unified-platform#45`. Документальный/контрактный gate не заменяет
  обязательных runtime-проверок на стенде.
