# Доверенная validation evidence и приёмка кампании (S03, S04)

Связано с задачами [Asmodeus #28](https://github.com/onixus/Asmodeus/issues/28) и
[Asmodeus #29](https://github.com/onixus/Asmodeus/issues/29). Это не закрывает
X01: runtime Ferrum/BSDM этим срезом не исполняется (`X01: NOT RUN`).
Закрытие S01 по-прежнему ждёт каталог C02 unified-platform #47.

Источник истины остаётся подписанный audit Asmodeus. `ValidationObservation`
schema `1.0` — проекция. На границе экспорта дополнительные поля запрещены.
Повторный экспорт тех же ревизий не меняет байты. Cursor и limit режут страницу,
но не создают новую ревизию.

Новые поля аудита лежат только в расширении `validation-v1`. Исторические
записи без него сохраняют прежний `canonical_bytes` (`evidence-v1` не менялся).
`POST /runs/:id/feedback` остаётся прежним и **не** поднимает legacy
`RunEvidence` до `PASSED`.

Новый приём: `POST /api/v1/asmodeus/runs/:id/validation`.
Экспорт: `GET /api/v1/asmodeus/validation/observations`.
Приёмка шести слотов первой волны (`container-exec`, `shell-execution`,
`runtime-socket-prerequisite`, `http-beacon`, `dns-pattern`,
`synthetic-transfer`): `GET /api/v1/asmodeus/reports/campaign-acceptance`.

Корреляция требует tenant, environment, asset, run, attempt, procedure и окно
времени. Совпадение только technique id связь не создаёт. Подпись сверяется с
доверенным ключом control-plane (`verify_with_key`); подмена
`public_key_hex` доверия не даёт. Поздний feedback — новая ревизия
(`supersedes`), предыдущая строка журнала не переписывается. После reload
aggregate и stage читают одну и ту же trusted revision.

`fidelity=marker` не даёт prevention/containment `PASSED` и не даёт behavioral
coverage. detection `PASSED` возможен только при telemetry `AVAILABLE` и
доверенном producer. Нет feedback, telemetry `UNAVAILABLE`/`UNKNOWN`, потеря
очереди или timeout — это `INCONCLUSIVE` или `NOT_RUN`, не PASS. Подтверждённый
пропуск при живом сенсоре — detection `FAILED`. MTTD — число только если оба
timestamp валидны и |observed_at − occurred_at| ≤ 300 с; иначе MTTD =
`INCONCLUSIVE`. detect-then-kill — containment, не prevention.

Знаменатель приёмки — 6 слотов корпуса, даже если часть `UNSUPPORTED` или
`NOT_RUN`. Отчёт содержит scope, attack release, варианты, пробелы, ссылки на
evidence и условия применимости. `protection_gate` всегда `NOT_CLAIMED`:
зелёная приёмка evidence не заявляется как protection gate. Пропуск обязательной
процедуры не является успехом. Намеренно проваленная процедура даёт gate
`FAILED`.

В этой ревизии корпуса все шесть слотов остаются `UNSUPPORTED`. Локальный
fixture S02 не становится продуктовым доказательством. Экспорт редактирует key
material, значения honeytoken и сырые пути хоста в синтетические
`urn:apex:evidence:asmodeus:ref:…`.
