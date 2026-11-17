# Field Intelligence — дизайн экрана и модели данных (Sentinel Atlas)

> **DESIGN ONLY.** Экран, поля, события, метрики, AQL и связи ниже — синтетический демо-концепт. Ни один пример не является реальной телеметрией, подтверждённым QRadar-поиском, фактом подключения клиента, приватным event payload или результатом вызова Threadlinqs. Пометка DESIGN ONLY распространяется на все приложенные демо-артефакты (концепт/mockup HTML, design ZIP, staged YAML/CSV). Импорт в доверенный инвентарь, деплой правил и публикация отчётов не выполняются.

## 1. Статус и источники

| Аспект | Значение |
|---|---|
| Тип документа | DESIGN ONLY / design reference |
| SPEC | §10 (tenant), §11 (QRadar Data Inventory), §12 (Detection Coverage), §13 (Hunt Hypothesis), §18 (UI) |
| Визуальный референс | `config/imports/2026-07-11/field_intelligence_concept_v4.html` (V4, synthetic) |
| Staged правила/поля | `config/imports/2026-07-11/full_rules85.yaml`, `shared_bbs.yaml`, `fields.yaml`, `qradar_rules_bb_sysmon.csv` |
| Provenance | `config/imports/2026-07-11/PROVENANCE.md`, `SHA256SUMS.txt` |
| Код / конфиги | не изменяются; PR содержит только этот документ |
| Интеграции | QRadar и Threadlinqs — NOT VERIFIED (PoC нет) |

Детерминированная проверка исходников: все 5 SHA256 из `SHA256SUMS.txt` совпадают с фактическими файлами (результат — в ARTIFACTS ответа). Совпадение хэшей не делает данные доверенными: `PROVENANCE.md` фиксирует MISMATCH заявленных и фактических счётчиков. Staged-файлы — untracked evidence, не источник истины для `config/rules_inventory.yaml` и `config/custom_fields_qradar.yaml`.

## 2. Трассируемость требований

| Требование дизайна | SPEC | Секция |
|---|---|---|
| Иерархия Domain → DSM → Log Source Type → QID → Fields | §11.2, §11.4, §18.8 | §3 |
| Статусы AQL VERIFIED / CANDIDATE / UNKNOWN | §11.2, §13.4, §13.5 | §4 |
| Raw-only payload vs searchable custom property | §11.2, §13.5 | §4.2 |
| Client ↔ Domain только после подтверждения администратором | §10.4, §11.4, §18.8 | §5 |
| AQL черновик + ручная проверка | §13.5, §18.6 | §6 |
| Coverage COVERED / PARTIAL / NOT_COVERED / UNKNOWN | §12.2, §12.3, §18.7 | §7 |
| Sigma/KQL/SPL не подтверждают coverage | §12.3 | §7.2 |
| Crosswalk Threadlinqs → Field Intelligence → M7-D | §6.2, §13.2, §18.3 | §8 |
| Экран, вкладки, метрики | §18, §18.7, §18.8 | §9 |

## 3. Иерархия данных

`Domain → DSM → Log Source Type → QID → Fields`. Терминология IBM из референса: `domainid`, `devicetype`, `logsourceid`, `qid`, `QIDNAME(qid)`, normalised events, CEP, payload.

| Уровень | Ключ | Храним | Источник истины | Правило |
|---|---|---|---|---|
| Domain | `domainid` | ID домена QRadar | глобальный инвентарь | не выводится из client автоматически (§5) |
| DSM / Product | `devicetype` | тип продукта | inventory | только реальные значения; не выдумывать (§11.2) |
| Log Source Type | `logsourceid` | источник | inventory | глобальный, не дублируется по клиентам (§10.2) |
| QID / Event | `qid`, `QIDNAME(qid)` | событие | inventory | демо-записи помечены SYNTHETIC |
| Fields | `(name, log_sources)` | поле | Global Fields Inventory (§11.2) | см. §4 |

Natural key поля — `(name, log_sources)`, не `name`. `PROVENANCE.md` фиксирует дубликаты в `fields.yaml`: `proc_file_path` (3), `proc_usr_sid` (2), `event_description` (2), `task_name` (2). Валидатор обязан отклонить импорт до записи, а не дедуплицировать молча (principle fix-root-causes).

Пример строки реестра (DESIGN ONLY, синтетические значения из V4):

```text
domainid=1 · DSM=Microsoft Windows Security Event Log · logsourceid=101
qid=500102 · QIDNAME=Failed Logon · eventID=4625 · MITRE=T1078
fields: sourceip, username, Status, IpAddress
```

## 4. Статусы полей

Три состояния: `AQL VERIFIED`, `CANDIDATE`, `UNKNOWN`.

| Статус | Meaning | Доказательство | Что разрешено |
|---|---|---|---|
| AQL VERIFIED | поиск по полю подтверждён в QRadar вручную | отдельная проверка аналитика в QRadar | использовать в AQL draft |
| CANDIDATE | поле найдено в экспорте/сэмпле, поиск не проверен | name + log_sources из staged evidence | только кандидат, не AQL |
| UNKNOWN | тип/происхождение не определены | нет | ничего; не добавлять в SELECT |

Переходы:

- Загрузка raw sample сама по себе статус не меняет: `CANDIDATE` не становится `AQL VERIFIED`.
- `AQL VERIFIED` требует отдельного ручного подтверждения поиска в QRadar (SPEC §13.5); демо-отметка `DEMO VERIFIED` не является таким подтверждением.
- Tenant-подтверждение и AQL-подтверждение — независимые события.

### 4.1. Raw-only payload vs searchable custom property

| Происхождение | Где живёт | В AQL |
|---|---|---|
| Normalized / custom property | инвентарь полей, CEP | доступно, если статус AQL VERIFIED |
| Raw-only payload | сырой payload события | недоступно для поиска, пока не настроена custom property и не проверен поиск |

Найденный ключ в payload ещё не означает доступную custom property в AQL. `fields.yaml` фиксирует этот разрыв через `availability: full|partial` (например, `proc_file_path` — partial: есть в логе, но в QRadar парсится как N/A). Status и availability — разные оси: availability describes данные, status describes подтверждённую возможность поиска.

## 5. Client ↔ Domain binding

Привязка клиента к `domainid` устанавливается **только после подтверждения администратором** (ADMINISTRATOR, SPEC §10.4 / §18.8). До подтверждения экран показывает `Domain-bound sample` и предупреждение `Tenant confirmation · REVIEW REQUIRED`.

| Правило | Обоснование в SPEC | Детерминированная проверка |
|---|---|---|
| привязка требует записи об одобрении администратора | §10.4, §11.4 | assert: approval record presence |
| client-scoped запрос содержит `client_id` | AGENTS.md, §10.4 | tenant-scoped query test |
| глобальные поля/правила не дублируются по клиентам | §10.2 | uniqueness check |
| нет cross-tenant доступа через API/MCP/RAG | §10.4 | cross-tenant security test |
| действие аудируется без секретов | AGENTS.md | audit/redaction test |

Элементы scope-бара (DESIGN ONLY): QRadar Instance (`QRadar Primary · Demo`), Atlas Client (`Alpha Corp · DEMO`, `Beta Energy · DEMO`), Domain ID (`1`, `2`). Смена client не должна автоматически переключать Domain до подтверждения привязки.

## 6. AQL — только черновик

Согласно SPEC §13.5: поля только из Global Fields Inventory; не выдумывать имена; объяснять каждое условие; ссылка на исходную Hunt Hypothesis; не выполнять автоматически в MVP; требовать проверки аналитиком.

Шаблон из референса (DESIGN ONLY · DRAFT ONLY, не выполнять):

```sql
SELECT starttime, qid, QIDNAME(qid) AS EventName, sourceip, username
FROM events
WHERE domainid = 1 AND logsourceid = 101
LAST 24 HOURS
```

Ограничение дизайна: `LogonType` нельзя автоматически добавлять в `SELECT`, пока неизвестны имя CEP и результат проверки в QRadar. Поле `username` в демо — `CANDIDATE`, поэтому его присутствие в шаблоне не означает готовность запроса. AQL draft не меняет coverage и не является доказательством detection.

## 7. Coverage

### 7.1. Статусы (SPEC §12.2)

| Статус | Определение |
|---|---|
| COVERED | подходящее правило есть и подтверждены необходимые предпосылки проверки |
| PARTIAL | обнаруживается только часть требуемого поведения |
| NOT_COVERED | подходящего правила в инвентаризации нет |
| UNKNOWN | недостаточно информации для вывода |

### 7.2. Разделение признаков и запрет ложного подтверждения

Статус вычисляется только после раздельного учёта (SPEC §12.3): Rule Exists → Required Fields Available → Telemetry Available → Rule Tested → Detection Observed. Наличие правила в библиотеке не является доказательством эффективного обнаружения.

- Наличие Sigma / KQL / SPL detection в CTI-источнике **не** подтверждает coverage.
- Отсутствие событий **не** трактуется как отсутствие угрозы; статусы клиентской телеметрии: `CONNECTED`, `NOT_CONNECTED`, `NO_RECENT_EVENTS`, `UNKNOWN` (§11.4).
- AQL draft и STATUS `CANDIDATE` не повышают coverage.
- Coverage для демо-сценария `Suspicious logon activity`: `GAPS · DRAFT ONLY`.

## 8. Crosswalk Threadlinqs → Field Intelligence → M7-D

```text
External CTI (Threadlinqs)          [NOT VERIFIED · без приватных payload]
   ├─ Technique / IOC
   ├─ Detection requirements
   └─ Provenance + refs
            ↓
Client / Domain scope (Atlas)       [только после подтверждения администратором]
            ↓
DSM → QID → Event → Fields          [статусы §4]
            ↓
Hunt readiness + gaps               [§7]
            ↓
M7-D Hypothesis / Hunt Plan DRAFT   [§13]
```

Интеграция с external CTI обогащает гипотезу публичными TTP, IOC, detection metadata и provenance. Приватные event payloads во внешний сервис не импортируются. Доступ и тариф MCP требуют проверки в учётной записи; макет вызовов не выполняет. AI предлагает, аналитик подтверждает (SPEC §13.3/§13.4, Quality Gate).

## 9. Экран (UI)

Раздел `Field Intelligence (CONCEPT)` дополняет меню SPEC §18 рядом с `Detection Coverage` (§18.7) и `QRadar Inventory` (§18.8). Вкладки референса V4:

| Вкладка | Содержимое | SPEC |
|---|---|---|
| Telemetry Catalog | Events/Sources, поиск, фильтры Product/DSM, Event, Field status, MITRE; Context Inspector с иерархией §3 | §18.8 |
| Field Registry | FIELD NAME, ORIGIN, DATA TYPE, EVENT/SCOPE, PROOF, VERDICT (§4) | §11.2 |
| Auto Ingestion | Select scope → Upload → Auto extract → Analyst review; локальный разбор, temporary preview | §11.5 |
| Hunt Readiness | M7-D observation path, required source/event, статусы полей, AQL draft, overall readiness | §18.6, §13 |
| Threat Intel Links | crosswalk §8, предупреждение про Sigma/KQL/SPL | §18.3 |

Правила отображения:

- Метрики считаются только из загруженного демо-каталога; при отсутствии данных фиктивные метрики не показываются (§18.1).
- Catalog и Inspector помечают записи как `SYNTHETIC`; сэмплы — `[REDACTED]`.
- Auto Ingestion: в проде raw samples маскируются до загрузки; браузерный preview не является сертифицированной защитой PII. Система предлагает кандидатов, а не присваивает VERIFIED.
- Export manifest формирует локальный черновик со статусом `UNVERIFIED` и disclaimer о ручной проверке, tenant verification и AQL-тестах.

## 10. Инварианты как проверки (pstack)

Урок кодируется проверкой/линтером/тестом, а не текстом-оправданием; чинится первое место разрыва.

| Инвариант | Детерминированная проверка |
|---|---|
| уникальность `(name, log_sources)` | validator до импорта |
| поле в AQL есть в Global Fields Inventory | validator AQL draft |
| `CANDIDATE`/`UNKNOWN` не попадают в STATUS `AQL VERIFIED` без ручного доказательства | statechart/unit test переходов |
| client↔domain без одобрения ADMINISTRATOR не активен | audit-assert |
| coverage не повышается от Sigma/KQL/SPL | coverage rule test |
| в логах/аудите нет секретов и приватных payload | redaction/secret-leak test |
| отсутствие событий не меняет статус угрозы | telemetry-status test |

## 11. Human-in-the-loop и NOT VERIFIED

Требуют явного «да» человека: деплой правил в QRadar, публикация отчётов, изменение доверенных знаний и подтверждение привязки client↔Domain. Интеграции без PoC помечаются NOT VERIFIED; результаты тестов не выдумываются. Настоящий документ не меняет код, конфиги и доверенный инвентарь и не создаёт телеметрию.

## Приложение A — ссылки

- `TECHNICAL_SPECIFICATION.md` §§10, 11, 12, 13, 18 (строки 900–1196, 1452–1690).
- `AGENTS.md`:tenant isolation,auditing, human approval.
- `docs/TEAM_SETUP.md`: pstack-принципы и правила work/PR.
- `config/imports/2026-07-11/`: staged evidence (DESIGN ONLY, untracked).
