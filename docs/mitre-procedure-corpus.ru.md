# Корпус процедур первой MITRE-волны (S02)

Связано с [задачей #27](https://github.com/onixus/Asmodeus/issues/27).
Это контракт подготовки процедур. Он фиксирует знаменатель до исполнения и
показывает, чего ещё не хватает для допуска к запуску.

`GET /api/v1/asmodeus/procedures` и `asmodeus procedures` возвращают один
версионированный корпус из `asmodeus-dsl::procedure`. Доступ требует
`ViewReports`, как чтение каталога сценариев. Корпус не принимает команды,
адреса или пути от клиента и не запускает действия.

## Шесть обязательных slots

| Slot | Кандидат ATT&CK | Граница |
| --- | --- | --- |
| Container exec | T1609 | Только изолированный тестовый контейнер; адаптера исполнения пока нет |
| Shell execution | T1059.004 | Только заранее фиксированная синтетическая команда; произвольный shell запрещён |
| Test runtime socket | T1611 | Только тестовая предпосылка/сигнал; доступ к сокету не доказывает escape |
| HTTP beacon | T1071.001 | Только собственный тестовый получатель на loopback |
| DNS C2 pattern | T1071.004 | Только собственный тестовый DNS receiver и синтетические имена |
| Synthetic transfer | T1041 | Только синтетические байты в собственный тестовый receiver |

Для каждого slot заданы revision, positive/benign control, preconditions,
ожидаемые observable, ожидаемая реакция продукта и способ проверки эффекта,
ограничения ресурсов, scope и требования cleanup. Ссылка на ATT&CK описывает
планируемую процедуру, а не измеренное покрытие техники.

В этой версии **все шесть slots имеют `UNSUPPORTED`** с явной причиной.
Они остаются в знаменателе `6`; ни наличие определения, ни `planned_mode` не подтверждают исполнение, detection, prevention или containment.
Повторное чтение корпуса не создаёт attempt и не меняет существующие runs.
Marker/replay/behavioral различаются в модели, но API корпуса не выдаёт
исполнительный evidence manifest.

## Локальный исполнитель fixtures

`asmodeus procedure-local` выполняет три локальных опыта: `http-beacon`,
`dns-pattern`, `synthetic-transfer`. Он создаёт собственные TCP/UDP receivers
на `127.0.0.1:0`; внешние адреса, команды, payload и пути через CLI не задаются.
DNS-пакеты идут непосредственно в собственный UDP receiver, без обращения
к системному DNS. У каждой процедуры есть `positive` и `benign-control`.

```sh
asmodeus procedure-local --procedure http-beacon --variant positive \
  --attempt-id local-http-001 --output local-http-001.json
```

Attempt ID обязателен и не переиспользуется. До открытия сокетов исполнитель
создаёт постоянную запись владения
`/tmp/asmodeus-canary/local-procedures/<attempt-id>.ownership.json`.
Эта запись сохраняется после cleanup; повторный запуск с тем же ID отклоняется.
Эфемерная директория `<attempt-id>/` принадлежит только этому запуску.

JSON содержит локальные наблюдения, ревизии, окружение, временные отметки,
фактически принятые данные и результат cleanup. `--output` отказывается
перезаписывать существующий файл. Evidence **не подписан** и не является
доверенным producer feedback. Его можно отдельно подписать существующей
офлайн-командой `asmodeus sign`; подпись сама по себе не доказывает реакцию
защитного продукта.

Общий deadline ограничен 10 секундами; `--timeout-ms` может его сократить.
Ctrl-C запрашивает отмену и штатную очистку. SIGKILL не позволяет подтвердить
filesystem cleanup: запись владения остаётся с `crash_cleanup=NOT_VERIFIED`,
чужие/предыдущие attempts автоматически не удаляются.

Локальные fixtures не выполняют контейнерные и продуктовые preconditions
корпуса v1. Поэтому каталог сохраняет все шесть `UNSUPPORTED`, а protection
остаётся неподтверждённым даже при успешном локальном исполнении. Container exec,
shell и runtime socket этой командой не исполняются.

`python3 scripts/procedure_smoke.py` проверяет парные TCP/UDP receipts,
идемпотентный отказ от повторного ID, экспорт, timeout, Ctrl-C и SIGKILL.
Переменная `ASMODEUS_PROCEDURE_EVIDENCE_OUT` сохраняет JSON-архив результатов;
script удаляет только созданные им attempts после проверок. Этот smoke включён
в основной `Jenkinsfile`, а его локальный запуск не заменяет Jenkins на точном SHA.

## Следующий этап S02

Исполнитель должен сохранить существующие проверки подписи, deadline,
cancellation, dead-man switch, CPU budget и эксклюзивный canary sandbox.
До допуска необходимы:

- Привязка attempt ID, procedure revision и environment manifest к подписанным
  данным; реальные start/stop и observable, без присвоения чужих артефактов.
- Проверка принадлежности loopback receiver текущему attempt, запрет
  redirects/внешнего DNS и настоящих Docker/containerd sockets.
- Отрицательные scope-тесты и проверка очистки после success/failure/cancel.
- Crash subprocess/recovery tests: `Drop` сам по себе не доказывает очистку
  после SIGKILL.
- Отдельные runtime-прогоны на стенде с Ferrum/BSDM; локальный mock не
  подтверждает реакцию защитного продукта.

Эта поставка не закрывает #27. Доверенная корреляция feedback (S03), отчёт
приёмки кампании (S04) и интеграционная приёмка X01 остаются отдельными gates.
