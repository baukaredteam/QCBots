 MSSP INTELLIGENCE WORKBENCH
## Финальное техническое задание (Technical Specification)

**Версия:** 1.0  
**Статус:** Final Specification / Implementation Baseline  
**Тип проекта:** On-premise AI-powered CTI, Threat Hunting & Detection Intelligence Platform  
**Основные пользователи:** SOC Analysts, CTI Analysts, Threat Hunters, Detection Engineers, SOC Management  
**Целевая среда:** Внутренняя инфраструктура компании  
**Основной язык интерфейса:** English (с возможностью последующей локализации)  
**Основной язык документации:** English  
**Предполагаемый инструмент разработки:** OpenCode  
**Основной принцип:** Human-in-the-Loop, Tenant Isolation, Evidence-Based Intelligence

---

# 1. PROJECT OVERVIEW

## 1.1. Назначение проекта

MSSP Intelligence Workbench — внутренняя интеллектуальная платформа для автоматизации и улучшения процессов Cyber Threat Intelligence (CTI), Threat Hunting, Detection Engineering и анализа угроз в MSSP-среде.

Платформа должна объединять:

- Threat Intelligence из внешних и внутренних источников.
- AI-powered CTI analysis.
- Adversary Brains — структурированные модели поведения threat actors.
- Анализ релевантности угроз для секторов и клиентов MSSP.
- Генерацию проверяемых Threat Hunting Hypotheses.
- Анализ доступности телеметрии и возможностей существующих QRadar Detection Rules.
- Поддержку нескольких AI Harness.
- Централизованное хранение результатов аналитики.
- Feedback Loop с обязательным подтверждением решений аналитиком.
- Формирование аналитических отчётов для SOC и руководства.

Платформа не должна быть просто чат-интерфейсом поверх LLM.

Она должна выступать как централизованная система управления CTI-знаниями, аналитическими процессами, AI-агентами и результатами расследований.

## 1.2. Основная бизнес-задача

Сейчас аналитики получают информацию о новых APT-группах, кампаниях, IOC, TTP, CVE и инструментах атакующих из различных источников.

Однако наличие нового CTI-отчёта само по себе не означает, что содержащаяся в нём информация применима к конкретному клиенту MSSP.

Платформа должна автоматически отвечать на следующие вопросы:

1. Какая угроза описана в полученном отчёте?
2. Какие threat actors и кампании упоминаются?
3. Какие TTP, IOC, CVE и инструменты используются?
4. Какие отрасли и типы организаций находятся под угрозой?
5. Какие клиенты MSSP потенциально подвержены этой угрозе?
6. Какие технологии и инфраструктурные компоненты клиента могут быть затронуты?
7. Какие необходимые источники логов уже подключены?
8. Какие QRadar Detection Rules способны обнаружить соответствующую активность?
9. Какие поведенческие признаки пока не покрываются существующими правилами?
10. Какие Threat Hunting Hypotheses следует передать SOC-аналитику?

## 1.3. Целевой результат

После обработки нового CTI-материала Workbench должен сформировать структурированный аналитический результат:

- CTI Report Summary.
- Threat Actor / Campaign Profile.
- IOC Inventory.
- MITRE ATT&CK Mapping.
- Adversary Brain.
- Sector Relevance Assessment.
- MSSP Client Relevance Assessment.
- Required Telemetry.
- Existing Detection Coverage.
- Detection Gaps.
- Hunt Hypotheses.
- Evidence and Source References.
- Analyst Review Status.

---

# 2. ARCHITECTURAL PRINCIPLES

Обязательные архитектурные принципы:

1. On-premise first.
2. No mandatory cloud dependency.
3. Multi-Harness architecture.
4. Provider-independent LLM architecture.
5. Human-in-the-Loop.
6. Evidence-Based Intelligence.
7. Multi-Tenant Data Isolation.
8. Centralized Knowledge Management.
9. Auditable AI Execution.
10. Modular and Replaceable Components.
11. Read-only integration with QRadar in MVP.
12. No automatic modification of trusted knowledge without analyst approval.

## 2.1. Infrastructure Restrictions

Компания запрещает использование Git в рабочем процессе.

Поэтому реализация должна предусматривать:

- Локальное хранение исходного кода.
- Передачу исходников через разрешённые внутренние механизмы.
- Локальное управление версиями артефактов без обязательной зависимости от Git.
- Версионирование конфигурационных файлов.
- Database migrations.
- Backup and restore.
- Экспорт и импорт YAML/JSON.
- Контрольные суммы артефактов.
- Журнал изменений конфигураций.

Не использовать GitHub, GitLab или другие внешние Git-сервисы как обязательную часть runtime или deployment.

Не загружать исходный код, конфигурации, клиентские данные или внутреннюю документацию во внешние сервисы без отдельного разрешения.

## 2.2. Network Restrictions

Все основные компоненты должны работать во внутренней инфраструктуре.

Внешние соединения должны быть явно контролируемыми и отключаемыми.

Отдельно проверить:

- ThreadLinqs MCP.
- Внешние LLM API.
- Model download endpoints.
- Container registries.
- Harness package managers.
- Telemetry and update endpoints.
- External IOC enrichment services.

Default policy: deny outbound connections unless explicitly approved.

Локальный deployment сам по себе не гарантирует отсутствие внешней передачи данных.

---

# 3. HIGH-LEVEL ARCHITECTURE

## 3.1. Logical Architecture

Платформа должна состоять из следующих логических компонентов:

1. Frontend Application.
2. Backend API.
3. Authentication and Authorization.
4. MSSP Tenant Management.
5. CTI Ingestion Engine.
6. CTI Processing Engine.
7. Adversary Brain Engine.
8. Sector Relevance Engine.
9. Hunt Hypothesis Engine.
10. Detection Coverage Engine.
11. Knowledge Management.
12. AI Orchestration Layer.
13. Harness Integration Layer.
14. MCP Integration Layer.
15. Model Provider Adapter.
16. Audit and Monitoring.
17. Reporting Engine.

## 3.2. Recommended Technology Stack

### Frontend

- React.
- TypeScript.
- Vite.
- Tailwind CSS.
- Component-based UI.
- REST API integration.
- WebSocket or Server-Sent Events for execution streaming.

### Backend

Предпочтительный вариант:

- Go.
- REST API.
- OpenAPI specification.
- Background job processing.
- Structured logging.

Python допускается для отдельных аналитических модулей, если это действительно упрощает реализацию.

Не создавать микросервисную архитектуру без необходимости.

На MVP предпочтительна модульная архитектура с чёткими интерфейсами компонентов.

### Database

MVP:

- SQLite.
- WAL mode.
- Foreign keys enabled.
- Database migrations.
- Transactional writes.

Production:

- PostgreSQL.
- pgvector при необходимости семантического поиска.

Не делать vector database обязательной зависимостью первой версии.

### File Storage

Локальное файловое хранилище:

- CTI Reports.
- PDF Documents.
- HTML Reports.
- Imported JSON.
- Analyst Attachments.
- Generated Reports.
- Evidence Files.

Файлы должны иметь контрольные суммы, метаданные и ссылки на соответствующие записи базы данных.

### Deployment

- Docker / Docker Compose при разрешении внутренней инфраструктурой.
- Локальные конфигурационные файлы.
- Internal network.
- Persistent volumes.
- Backup procedures.
- Health checks.

Kubernetes не является обязательным для MVP.

---

# 4. MAIN SYSTEM COMPONENTS

## 4.1. Workbench Backend

Backend является центральным управляющим компонентом.

Он отвечает за:

- Authentication.
- Authorization.
- Tenant isolation.
- Business logic.
- CTI records.
- Adversary Brain records.
- Hunt hypotheses.
- Detection inventory.
- AI task orchestration.
- Execution history.
- Analyst decisions.
- Audit logs.
- Reporting.

Ни один AI Harness не должен иметь прямого доступа к основной базе данных Workbench.

Взаимодействие должно происходить через разрешённые API или MCP-инструменты.

## 4.2. AI Orchestration Layer

Центральный механизм управления аналитическими задачами.

Он должен:

- Создавать AI tasks.
- Выбирать подходящий harness.
- Передавать контекст.
- Контролировать execution status.
- Получать результаты.
- Обрабатывать ошибки.
- Поддерживать retry policies.
- Сохранять execution history.
- Передавать результаты в Quality Gate.
- Обеспечивать Human-in-the-Loop.

Оркестрация должна быть независима от конкретного AI Harness.

## 4.3. Model Provider Adapter

Необходимо предусмотреть возможность использования:

- Local LLM.
- OpenAI-compatible API.
- Других одобренных внешних LLM API.

Конкретный LLM Provider пока не выбран.

Поэтому модельный провайдер должен подключаться через конфигурацию и отдельный адаптер.

Нельзя жёстко привязывать бизнес-логику Workbench к одной модели или API.

---

# 5. MULTI-HARNESS ARCHITECTURE

## 5.1. Objective

Workbench должен поддерживать несколько AI Harness одновременно.

Пользователи могут использовать разные harness, а сама платформа должна предоставлять единый механизм управления их задачами.

Предполагаемые интеграции:

- Tencent Octop.
- HarnessRouter.
- OpenCode.
- Claude Code.
- Codex.
- DeepSeek Harness.
- Custom Harness.
- Другие совместимые решения.

Наличие названия в этом списке не означает подтверждённую техническую совместимость. Каждая интеграция должна пройти PoC.

## 5.2. HarnessRouter

HarnessRouter должен быть рассмотрен как основной кандидат на роль унифицированного слоя запуска и управления harness.

Его задачи:

- Предоставление единого API.
- Запуск поддерживаемых harness.
- Управление сессиями.
- Получение результатов.
- Streaming.
- Отмена выполнения.
- Обработка ошибок.

Workbench должен взаимодействовать с HarnessRouter через его документированный интерфейс.

Запрещается делать HarnessRouter обязательной частью бизнес-логики.

Если HarnessRouter будет заменён, остальные компоненты Workbench должны продолжать работать.

## 5.3. Harness Adapter Interface

Backend должен иметь внутренний интерфейс:

```go
type HarnessAdapter interface {
    Name() string

    HealthCheck(ctx context.Context) error

    GetCapabilities(
        ctx context.Context,
    ) ([]Capability, error)

    SubmitTask(
        ctx context.Context,
        task HarnessTask,
    ) (Execution, error)

    GetExecution(
        ctx context.Context,
        executionID string,
    ) (Execution, error)

    StreamExecution(
        ctx context.Context,
        executionID string,
    ) (<-chan ExecutionEvent, error)

    CancelExecution(
        ctx context.Context,
        executionID string,
    ) error
}
```

Это внутренний контракт Workbench, а не утверждение, что все внешние harness предоставляют одинаковые методы.

Каждый адаптер самостоятельно преобразует внутренний контракт в API конкретного продукта.

## 5.4. Integration Methods

Поддержать следующие способы подключения:

1. HarnessRouter API.
2. Native REST API.
3. A2A Protocol.
4. MCP integration, если harness выступает MCP client/server в соответствующем сценарии.
5. CLI/SDK Adapter для разрешённых локальных инструментов.

Не предполагать, что Claude Code, Codex или OpenCode автоматически предоставляют совместимый A2A endpoint.

Для каждого продукта проверить официально поддерживаемые способы интеграции и ограничения лицензирования.

## 5.5. A2A Protocol

A2A может использоваться для взаимодействия независимых agent systems.

В рамках Workbench A2A является дополнительным интеграционным механизмом.

Не делать A2A обязательным условием для подключения каждого harness.

## 5.6. MCP Protocol

MCP предназначен для предоставления агентам инструментов и контекста.

Workbench должен предоставлять собственный защищённый MCP Server.

Предполагаемые MCP Tools:

```text
get_client_profile
get_client_sector
get_client_technologies
get_available_log_sources
get_global_qradar_fields
get_detection_rules
get_detection_rule_details
search_cti_reports
get_adversary_brain
search_iocs
get_mitre_technique
create_hunt_hypothesis_draft
get_hypothesis_evidence
get_detection_coverage
```

Все инструменты должны:

- Проверять identity вызывающего harness.
- Проверять разрешения.
- Проверять client_id.
- Проверять тип операции.
- Ограничивать объём возвращаемых данных.
- Создавать audit records.

MCP Server не должен предоставлять произвольный SQL-доступ.

## 5.7. Agent Registry

Создать страницу Agent Registry.

Поля:

```text
agent_id
agent_name
harness_type
integration_type
endpoint
version
status
capabilities
allowed_clients
allowed_tools
permission_profile
trust_level
created_at
updated_at
last_seen_at
```

Функции:

- Register Harness.
- Edit Configuration.
- Enable / Disable.
- Health Check.
- View Capabilities.
- View Execution History.
- View Permissions.

## 5.8. Capability Registry

Каждый harness должен иметь перечень разрешённых capabilities.

Примеры:

```text
CTI_ANALYSIS
IOC_EXTRACTION
IOC_PIVOTING
MITRE_MAPPING
ADVERSARY_BRAIN_GENERATION
ACH_ANALYSIS
SECTOR_RELEVANCE
HYPOTHESIS_GENERATION
DETECTION_COVERAGE
AQL_DRAFT_GENERATION
REPORT_GENERATION
```

Task Router должен проверять capabilities перед отправкой задачи.

## 5.9. Task Routing

Поддержать режимы:

```text
AUTO
MANUAL
USER_PREFERRED
WORKFLOW_DEFINED
```

Описание:

- AUTO — выбор подходящего доступного harness.
- MANUAL — аналитик выбирает harness.
- USER_PREFERRED — используется предпочтение пользователя.
- WORKFLOW_DEFINED — harness определяется конфигурацией процесса.

При ошибке допускается переключение на альтернативный harness только при сохранении исходного контекста и соблюдении ограничений безопасности.

Все попытки выполнения должны сохраняться.

## 5.10. Unified Task Contract

Пример:

```json
{
  "task_id": "task-001",
  "task_type": "CTI_ANALYSIS",
  "client_id": "client-001",
  "priority": "normal",
  "input": {},
  "expected_output": [
    "summary",
    "iocs",
    "ttps",
    "sources"
  ],
  "human_review_required": true
}
```

Результат:

```json
{
  "task_id": "task-001",
  "agent_id": "agent-001",
  "status": "completed",
  "result": {},
  "sources": [],
  "warnings": [],
  "errors": [],
  "execution_id": "execution-001"
}
```

Это внутренний формат Workbench. Адаптер обязан преобразовывать ответы внешних систем в данный формат.

## 5.11. Execution Modes

Поддержать два режима.

**Harness-managed:**

Octop или другой harness самостоятельно координирует собственные subagents. Workbench получает статус, результаты и доступную execution telemetry.

**Workbench-managed:**

Workbench самостоятельно разбивает задачу на этапы и маршрутизирует их между разными harness.

Для MVP реализовать Harness-managed mode через один подтверждённо совместимый harness.

Workbench-managed mode — следующий этап.

---

# 6. CTI INGESTION ENGINE

## 6.1. Objective

Автоматическое получение, импорт и нормализация CTI-материалов.

Источники:

- ThreadLinqs MCP.
- Ручной импорт PDF.
- Ручной импорт HTML.
- JSON.
- STIX/TAXII, если источник поддерживает соответствующий формат.
- Внутренние CTI Reports.

## 6.2. ThreadLinqs Integration

ThreadLinqs MCP должен рассматриваться как один из источников CTI.

Интеграция должна:

- Подключаться через поддерживаемый MCP transport.
- Получать доступные отчёты и данные.
- Сохранять исходный материал или доступную ссылку.
- Сохранять дату получения.
- Сохранять название источника.
- Обеспечивать дедупликацию.
- Сохранять provenance.

ThreadLinqs не должен выступать основной базой данных Workbench.

Внешняя MCP-интеграция должна быть отдельно согласована с политикой сетевой безопасности компании.

По умолчанию запрещается передавать ThreadLinqs необработанные клиентские логи и конфиденциальную внутреннюю информацию.

## 6.3. CTI Report Lifecycle

```text
NEW
  |
INGESTED
  |
NORMALIZED
  |
ANALYSIS_PENDING
  |
ANALYZED
  |
QUALITY_REVIEW
  |
APPROVED
  |
ARCHIVED
```

Допускается статус REJECTED.

## 6.4. CTI Extraction

Из каждого отчёта необходимо извлекать:

```text
report_id
title
source
author
publication_date
collection_date
threat_actors
campaigns
target_sectors
target_regions
malware
tools
iocs
ttps
cves
attack_patterns
victimology
references
confidence
```

Каждое извлечённое утверждение должно иметь ссылку на источник.

Нельзя создавать IOC, TTP или CVE, которых нет в исходном материале или в отдельно указанном подтверждённом источнике.

---

# 7. ADVERSARY BRAIN ENGINE

## 7.1. Objective

Реализовать структурированную модель поведения threat actor или кампании.

Adversary Brain должен объединять:

- Threat Actor Profile.
- Campaign Information.
- TTP.
- IOC.
- Malware.
- Tools.
- CVE.
- Infrastructure.
- Relationships.
- Evidence.
- Confidence.
- Historical Changes.

Главный принцип: анализировать не только отдельные IOC, но и взаимосвязанные поведенческие признаки.

Adversary Brain не должен автоматически утверждать, что наблюдаемая активность принадлежит конкретному threat actor только на основании одного совпадения.

## 7.2. Adversary Brain Data Structure

Предлагаемые таблицы:

```text
adversary_brains
brain_versions
brain_sources
brain_hypotheses
brain_observables
brain_relationships
brain_evidence
brain_assessments
```

Каждая запись должна поддерживать provenance.

## 7.3. Logical Signatures

Необходимо поддержать логические связи между признаками.

Пример концептуальной структуры:

```text
Threat Actor
    |
Campaign
    |
    +-- TTP A
    |
    +-- TTP B
    |
    +-- Malware
    |
    +-- Infrastructure
    |
    +-- Target Sector
```

Поддержать типы отношений:

```text
USES
TARGETS
ASSOCIATED_WITH
EXPLOITS
COMMUNICATES_WITH
OBSERVED_IN
RELATED_TO
```

Не считать любую связь доказанной без соответствующего источника.

## 7.4. Analysis of Competing Hypotheses (ACH)

ACH должен позволять сравнивать несколько объяснений наблюдаемой активности.

Например:

- H1: активность связана с известной APT-кампанией.
- H2: активность связана с легитимной административной операцией.
- H3: активность является независимой вредоносной активностью без установленной атрибуции.

Для каждой гипотезы сохранять:

- Supporting Evidence.
- Contradicting Evidence.
- Missing Evidence.
- Source Reliability.
- Information Credibility.
- Analyst Assessment.
- Current Status.

AI может предлагать оценку, но не должен самостоятельно утверждать окончательную атрибуцию.

---

# 8. ADMIRALTY SYSTEM

Использовать Admiralty System для оценки качества CTI-информации.

Оценка должна включать два независимых параметра.

## 8.1. Source Reliability

```text
A — Completely reliable
B — Usually reliable
C — Fairly reliable
D — Not usually reliable
E — Unreliable
F — Reliability cannot be judged
```

## 8.2. Information Credibility

```text
1 — Confirmed by other sources
2 — Probably true
3 — Possibly true
4 — Doubtful
5 — Improbable
6 — Truth cannot be judged
```

Пример:

```text
Source Reliability: B
Information Credibility: 2
```

Оценка относится к конкретному источнику и утверждению.

Не назначать одну неизменную оценку всему CTI-каналу.

Хранить:

```text
source_id
claim_id
reliability_rating
credibility_rating
assessment_reason
assessed_by
assessment_date
```

AI может предложить предварительную оценку, аналитик подтверждает её.

---

# 9. SECTOR RELEVANCE ENGINE

## 9.1. Objective

Автоматически определять, насколько конкретная угроза релевантна секторам и клиентам MSSP.

Примеры секторов:

```text
ENERGY
FINANCE
GOVERNMENT
TELECOMMUNICATIONS
HEALTHCARE
MANUFACTURING
TRANSPORTATION
EDUCATION
RETAIL
```

Справочник должен быть расширяемым.

При необходимости предусмотреть маппинг на используемую компанией отраслевую классификацию.

## 9.2. Client Sector Mapping

Каждый клиент может иметь один или несколько секторов.

Пример:

```text
Client A:
  - ENERGY

Client B:
  - FINANCE

Client C:
  - TELECOMMUNICATIONS
  - GOVERNMENT
```

## 9.3. Relevance Assessment

При оценке релевантности учитывать:

- Target Sector.
- Target Geography.
- Victimology.
- Client Technologies.
- Exposed Products.
- Known Vulnerabilities.
- Threat Actor Activity.
- Available Telemetry.
- Existing Detection Coverage.

Результат:

```text
HIGH
MEDIUM
LOW
UNKNOWN
```

Также обязательно выводить объяснение.

Нельзя присваивать HIGH только потому, что в отчёте упоминается отрасль клиента.

## 9.4. Client Relevance Output

```json
{
  "client_id": "client-001",
  "sector": "ENERGY",
  "relevance": "HIGH",
  "reasons": [],
  "matching_technologies": [],
  "relevant_ttps": [],
  "relevant_cves": [],
  "missing_information": [],
  "evidence": []
}
```

---

# 10. MSSP TENANT MANAGEMENT

## 10.1. Objective

Поддержка нескольких клиентов MSSP с гарантированной изоляцией данных.

## 10.2. Important QRadar Constraint

В текущей инфраструктуре MSSP:

- QRadar Fields являются общими.
- Detection Rules являются общими.
- Правила одинаково развёрнуты для клиентов.
- Не требуется создавать отдельные копии глобального справочника полей и правил для каждого клиента.

Поэтому Workbench должен использовать единую глобальную библиотеку.

При этом наличие и поступление телеметрии необходимо учитывать отдельно для каждого клиента.

## 10.3. Data Separation

Глобальные сущности:

```text
global_fields
field_mappings
detection_rules
rule_field_requirements
mitre_mappings
log_source_types
```

Клиентские сущности:

```text
clients
client_sector_mapping
client_technologies
client_log_source_status
client_asset_context
client_hypothesis_reviews
client_investigations
```

Не дублировать глобальные QRadar Rules и Fields для каждого клиента.

## 10.4. Tenant Isolation

Все клиентские операции должны проверять:

```text
user_id
role
client_id
permissions
```

Обязательные меры:

- Server-side authorization.
- Tenant-scoped database queries.
- Tenant-scoped MCP tools.
- Tenant-scoped RAG retrieval.
- Tenant-scoped AI context.
- Audit logging.

Запрещено полагаться только на фильтрацию данных в Frontend.

---

# 11. QRADAR DATA INVENTORY

## 11.1. Objective

Создать единую библиотеку полей и правил QRadar.

Источники:

- Excel Inventory.
- CSV.
- JSON.
- Ручное добавление.

## 11.2. Global Fields

Предлагаемые поля:

```text
field_id
field_name
field_type
field_description
source_type
normalized_name
aliases
is_active
```

Необходимо учитывать реальные названия и идентификаторы полей, используемые в существующем QRadar.

Не создавать фиктивные поля.

## 11.3. Detection Rules

```text
rule_id
rule_name
rule_description
rule_type
mitre_tactics
mitre_techniques
required_fields
required_log_sources
rule_status
rule_version
last_updated
```

## 11.4. Client Telemetry Status

```text
client_id
log_source_type
connection_status
last_event_timestamp
event_volume_status
field_availability
last_checked_at
```

Возможные статусы:

```text
CONNECTED
NOT_CONNECTED
NO_RECENT_EVENTS
UNKNOWN
```

Нельзя трактовать отсутствие событий как отсутствие угрозы.

## 11.5. Inventory Import

Создать интерфейс импорта.

Пользователь должен иметь возможность:

1. Загрузить Excel/CSV.
2. Просмотреть обнаруженные колонки.
3. Сопоставить колонки с внутренней схемой.
4. Проверить дубликаты.
5. Увидеть ошибки.
6. Подтвердить импорт.
7. Просмотреть результат.
8. Отменить импорт при ошибке, если операция ещё не зафиксирована.

Каждый импорт должен сохранять audit record.

---

# 12. DETECTION COVERAGE ENGINE

## 12.1. Objective

Сопоставлять поведение противника с существующими QRadar Detection Rules.

## 12.2. Coverage Status

Использовать четыре состояния:

```text
COVERED
PARTIAL
NOT_COVERED
UNKNOWN
```

Описание:

- COVERED — имеется подходящее правило и подтверждены необходимые предпосылки для проверки покрытия.
- PARTIAL — обнаруживается только часть требуемого поведения.
- NOT_COVERED — подходящего правила в инвентаризации не найдено.
- UNKNOWN — недостаточно информации для вывода.

## 12.3. Coverage Analysis

Для каждого Adversary Brain или Hunt Hypothesis проверять:

1. Какие MITRE techniques присутствуют?
2. Какие логические признаки необходимо наблюдать?
3. Какие QRadar Rules связаны с этими признаками?
4. Какие поля необходимы?
5. Какие log sources необходимы?
6. Подключены ли источники у конкретного клиента?
7. Поступают ли события?
8. Подтверждена ли работоспособность правила?

Наличие правила в библиотеке не является доказательством эффективного обнаружения.

Необходимо различать:

- Rule Exists.
- Required Fields Available.
- Telemetry Available.
- Rule Tested.
- Detection Observed.

---

# 13. HUNT HYPOTHESIS ENGINE

## 13.1. Objective

Автоматически формировать проверяемые Threat Hunting Hypotheses на основе CTI и контекста MSSP.

Гипотеза должна быть конкретной, проверяемой и содержать доказательную базу.

## 13.2. Hypothesis Structure

```text
hypothesis_id
title
description
client_id
sector
threat_actor
campaign
adversary_brain_id
mitre_tactics
mitre_techniques
expected_behavior
required_log_sources
required_fields
existing_detection_rules
coverage_status
evidence
supporting_evidence
contradicting_evidence
assumptions
limitations
confidence
priority
status
created_at
updated_at
```

## 13.3. Hypothesis Workflow

```text
GENERATED
    |
QUALITY_CHECK
    |
PENDING_REVIEW
    |
    +-- APPROVED
    |
    +-- REJECTED
    |
    +-- NEEDS_MORE_DATA
    |
INVESTIGATION
    |
CLOSED
```

## 13.4. Hypothesis Quality Gate

До передачи аналитику каждая гипотеза должна пройти проверку:

- Есть ли исходный CTI source?
- Есть ли подтверждение ключевых утверждений?
- Есть ли MITRE mapping?
- Реально ли существуют указанные QRadar fields?
- Реально ли существуют указанные Detection Rules?
- Подключены ли необходимые log sources?
- Отделены ли факты от предположений?
- Есть ли ограничения анализа?
- Есть ли альтернативные объяснения?

Если необходимых данных нет, гипотеза должна содержать соответствующее предупреждение.

## 13.5. AQL Draft Generation

Допускается создание черновиков QRadar AQL.

Требования:

- Использовать только поля из Global Fields Inventory.
- Не выдумывать названия полей.
- Проверять синтаксическую структуру по известным возможностям QRadar.
- Показывать объяснение каждого условия.
- Сохранять ссылку на исходную Hunt Hypothesis.
- Не выполнять запрос автоматически в MVP.
- Требовать проверки аналитиком.

---

# 14. FEEDBACK LOOP AND CONTROLLED LEARNING

## 14.1. Objective

Создать механизм накопления результатов предыдущих расследований.

Feedback Loop не должен означать автоматическое обучение LLM на всех поступающих данных.

В MVP реализовать контролируемое накопление знаний.

## 14.2. Investigation Feedback

Для каждой проверки гипотезы сохранять:

```text
investigation_id
hypothesis_id
client_id
related_events
affected_assets
time_range
evidence
analyst_findings
final_verdict
verdict_reason
mitigation_notes
analyst_id
review_timestamp
```

Возможные решения:

```text
TRUE_POSITIVE
FALSE_POSITIVE
INCONCLUSIVE
NEEDS_MORE_DATA
```

## 14.3. Important FP/TP Rule

FP/TP нельзя хранить только как глобальную характеристику QRadar Rule.

Одна и та же Detection Rule может давать TP в одном контексте и FP в другом.

Поэтому решение должно быть связано с конкретным расследованием, контекстом, клиентом и доказательствами.

## 14.4. Controlled Knowledge Updates

Процесс:

```text
Analyst Decision
      |
Structured Feedback
      |
Quality Review
      |
Knowledge Update Proposal
      |
Human Approval
      |
Approved Knowledge
```

AI не может самостоятельно:

- Утверждать TP/FP.
- Изменять доверенную Adversary Brain.
- Переписывать проверенные CTI-утверждения.
- Удалять противоречащие доказательства.
- Изменять глобальные Detection Rules.

---

# 15. AI SKILLS AND WORKFLOWS

Не создавать множество независимых агентов без необходимости.

Предпочтительно использовать отдельные Skills/Workflow Stages с чёткими входами и выходами.

## 15.1. Chief CTI Coordinator

Ответственность:

- Принимать аналитические задачи.
- Разбивать их на этапы.
- Выбирать необходимые Skills.
- Определять подходящий harness.
- Контролировать выполнение.
- Объединять результаты.
- Запускать Quality Gate.

## 15.2. CTI Collector

Ответственность:

- Получение CTI-материалов.
- Нормализация.
- Дедупликация.
- Сохранение provenance.

## 15.3. CTI Analyst

Ответственность:

- Анализ отчётов.
- Выявление threat actors.
- Извлечение IOC, TTP, CVE.
- Анализ кампаний.
- Формирование краткого аналитического заключения.

## 15.4. Admiralty Reviewer

Ответственность:

- Предварительная оценка источников.
- Оценка достоверности утверждений.
- Поиск подтверждений.
- Поиск противоречий.

## 15.5. Adversary Brain Builder

Ответственность:

- Построение структурированной модели поведения.
- Связывание TTP, IOC, malware и campaigns.
- Сохранение доказательств.
- Версионирование модели.

## 15.6. ACH Analyst

Ответственность:

- Создание конкурирующих гипотез.
- Сопоставление доказательств.
- Поиск противоречий.
- Формирование неопределённостей.

## 15.7. Sector Relevance Analyst

Ответственность:

- Определение целевых секторов.
- Сопоставление с MSSP-клиентами.
- Объяснение релевантности.
- Указание недостающей информации.

## 15.8. Detection Context Analyst

Ответственность:

- Работа с Global QRadar Inventory.
- Анализ правил и полей.
- Проверка необходимых log sources.
- Выявление detection gaps.

## 15.9. Hunt Hypothesis Generator

Ответственность:

- Формирование проверяемых гипотез.
- Определение необходимых данных.
- Генерация AQL drafts.
- Подготовка рекомендаций аналитику.

## 15.10. Quality Gate

Ответственность:

- Проверка структуры.
- Проверка доказательств.
- Проверка источников.
- Проверка клиентской изоляции.
- Проверка соответствия фактов и выводов.
- Формирование warnings.

---

# 16. ACTIF AND DETECTION ENGINEERING METHODOLOGY

ACTIF следует рассматривать как методологический слой организации аналитического процесса, а не как обязательный runtime или оркестратор.

Для каждого Hunt Hypothesis предусмотреть этапы:

1. Environment Context.
2. Trigger.
3. Hypothesis.
4. Initial Assessment.
5. Feasibility Assessment.
6. Scope and Objectives.
7. Hunt Plan.
8. Execute.
9. Document.
10. Report and Iterate.

Feasibility:

```text
GO
NO_GO
CONDITIONAL
```

Гипотеза должна включать:

- Scope.
- Assumptions.
- Required Telemetry.
- Data Limitations.
- Expected Evidence.
- Success Criteria.
- Investigation Plan.

## 16.1. ADE / Detection Engineering Knowledge

Предусмотреть возможность подключения ADE-подобных Skills и knowledge base для последующей оценки качества detection logic.

Это не является обязательной частью MVP.

---

# 17. KNOWLEDGE MANAGEMENT AND RAG

## 17.1. Source of Truth

Основная база Workbench является источником истины.

Obsidian может использоваться аналитиками для заметок и исследований, но не должен быть единственным источником структурированных данных.

## 17.2. RAG

Предусмотреть RAG для поиска по:

- CTI Reports.
- Adversary Brains.
- Historical Investigations.
- Approved Hunt Hypotheses.
- Detection Documentation.
- Internal Knowledge.

RAG должен использовать только разрешённые пользователю данные.

Все результаты должны учитывать client_id и права доступа.

## 17.3. Vector Search

На MVP допускается обычный полнотекстовый поиск.

Embeddings и vector search добавлять только после появления подтверждённой необходимости.

---

# 18. USER INTERFACE SPECIFICATION

Интерфейс должен быть понятным для SOC Analyst без необходимости работать непосредственно с внутренними API.

Основное меню:

```text
Dashboard
CTI Feed
Threat Intelligence
Adversary Brains
Sector Relevance
Hunt Hypotheses
Detection Coverage
QRadar Inventory
Investigations
Agent Registry
Execution History
Reports
Administration
```

## 18.1. Dashboard

Показывать:

- New CTI Reports.
- Analyzed Reports.
- High Relevance Threats.
- Threats by Sector.
- Active Adversary Brains.
- Pending Hunt Hypotheses.
- Approved Hypotheses.
- Detection Gaps.
- Active Investigations.
- Harness Health Status.

Каждая карточка должна открывать соответствующий раздел с фильтрами.

Не отображать фиктивные метрики при отсутствии данных.

## 18.2. CTI Feed

Экран:

- Report Title.
- Source.
- Publication Date.
- Collection Date.
- Threat Actor.
- Sector.
- Severity / Priority.
- Analysis Status.

Функции:

- Import Report.
- Refresh Feed.
- Analyze.
- View Original Source.
- View Extracted IOCs.
- View TTPs.
- View Evidence.

## 18.3. Threat Intelligence

Отображать:

- Threat Actors.
- Campaigns.
- Malware.
- Tools.
- CVEs.
- IOCs.
- MITRE Techniques.
- Source Assessments.

Предусмотреть поиск и фильтрацию.

## 18.4. Adversary Brains

Отдельная страница для просмотра моделей поведения.

Показывать:

- Threat Actor.
- Associated Campaigns.
- Behavioral Signatures.
- TTP.
- IOC.
- Malware.
- Infrastructure.
- Evidence.
- Confidence.
- Version History.
- Last Updated.

Предусмотреть графическое отображение связей.

Граф должен отображать только реально сохранённые связи.

## 18.5. Sector Relevance

Отображать:

- Threat.
- Target Sector.
- Matching MSSP Clients.
- Relevance Level.
- Matching Technologies.
- Relevant TTPs.
- Relevant CVEs.
- Missing Information.

## 18.6. Hunt Hypotheses

Основная рабочая область SOC Analyst.

Показывать:

- Hypothesis Title.
- Threat Actor.
- Client.
- Sector.
- MITRE Technique.
- Priority.
- Confidence.
- Required Log Sources.
- Required Fields.
- Detection Coverage.
- Evidence.
- Status.

Кнопки:

- View Details.
- Approve.
- Reject.
- Request More Data.
- Start Investigation.
- Generate AQL Draft.
- Export Report.

Approve/Reject должны сохранять identity аналитика и причину решения.

## 18.7. Detection Coverage

Показывать матрицу:

```text
MITRE Technique
Required Telemetry
Required Fields
Existing Rules
Client Availability
Coverage Status
Evidence
```

Фильтры:

- Client.
- Sector.
- MITRE Tactic.
- MITRE Technique.
- Coverage Status.

## 18.8. QRadar Inventory

Вкладки:

- Global Fields.
- Detection Rules.
- Rule-Field Mapping.
- MITRE Mapping.
- Log Source Types.
- Client Telemetry.

Предусмотреть импорт Excel/CSV и журнал изменений.

## 18.9. Agent Registry

Показывать:

- Agent Name.
- Harness.
- Status.
- Version.
- Capabilities.
- Permissions.
- Allowed Clients.
- Last Seen.

Кнопки:

- Add Agent.
- Edit.
- Enable.
- Disable.
- Health Check.
- View Executions.

## 18.10. Execution History

Показывать:

- Task ID.
- Harness.
- Agent.
- Task Type.
- Client.
- Start Time.
- Duration.
- Status.
- Result.
- Error.
- Retry Count.

Предусмотреть просмотр execution events и доступных traces.

## 18.11. Reports

Поддержать генерацию:

- CTI Report.
- Threat Relevance Report.
- Adversary Brain Report.
- Hunt Hypothesis Report.
- Detection Coverage Report.
- Investigation Report.
- Management Summary.

Экспорт:

- PDF.
- JSON.
- CSV.
- Markdown.

---

# 19. AGENT SECURITY CONTROL PLANE

## 19.1. Objective

Реализовать централизованное управление безопасностью AI Harness.

Модель не должна самостоятельно определять собственные права доступа.

Решения о разрешении действий должны приниматься внешними механизмами контроля.

## 19.2. Security Layers

### Model Layer

- Safety instructions.
- Structured output.
- Prompt separation.
- Explicit uncertainty.
- No unsupported claims.

### Harness Layer

- Sandbox.
- Tool allowlist.
- Restricted filesystem.
- Restricted credentials.
- Execution timeout.
- Controlled network access.

### Workbench Control Layer

- Authentication.
- Authorization.
- RBAC.
- Tenant isolation.
- MCP permissions.
- Audit.
- Human Approval.
- Data classification.
- Policy enforcement.

## 19.3. Permission Profiles

Предусмотреть профили:

```text
READ_ONLY
CTI_ANALYST
HYPOTHESIS_WRITER
REPORT_GENERATOR
ADMINISTRATOR
```

Профили должны быть настраиваемыми.

В MVP AI Harness получает READ_ONLY и ограниченные возможности создания черновиков через Workbench API.

## 19.4. Human Approval

Обязательное подтверждение аналитика для:

- Утверждения Hunt Hypothesis.
- Утверждения TP/FP.
- Изменения доверенных Adversary Brains.
- Изменения глобальной Detection Library.
- Публикации официального аналитического отчёта.
- Выполнения любых будущих write/response операций.

## 19.5. Audit Logging

Сохранять:

```text
event_id
user_id
agent_id
harness_id
client_id
action
resource
timestamp
result
source_ip
correlation_id
```

Не записывать секреты и токены в audit logs.

---

# 20. DATABASE SCHEMA

Предлагаемые основные таблицы:

### Identity and MSSP

```text
users
roles
permissions
user_roles
clients
sectors
client_sector_mapping
client_technologies
```

### Telemetry and Detection

```text
log_source_types
client_log_source_status
global_fields
field_mappings
detection_rules
rule_field_requirements
mitre_mappings
```

### CTI

```text
cti_sources
cti_reports
cti_claims
indicators
threat_actors
campaigns
malware
cves
techniques
admiralty_assessments
```

### Adversary Brain

```text
adversary_brains
brain_versions
brain_sources
brain_hypotheses
brain_observables
brain_relationships
brain_evidence
brain_assessments
```

### Hunting

```text
hunt_hypotheses
hypothesis_evidence
hypothesis_reviews
investigations
investigation_evidence
investigation_feedback
```

### AI and Harness

```text
harness_registry
harness_capabilities
harness_permissions
ai_tasks
ai_executions
ai_execution_events
ai_results
ai_runs
```

### System

```text
audit_log
system_settings
import_jobs
file_artifacts
knowledge_documents
knowledge_versions
```

Все таблицы должны иметь:

- Primary Keys.
- Foreign Keys.
- Appropriate Indexes.
- Created At.
- Updated At.
- Transactional Integrity.

Клиентские записи должны иметь tenant ownership, где это применимо.

Глобальные записи не должны искусственно дублироваться для каждого клиента.

---

# 21. API SPECIFICATION

Все API должны документироваться через OpenAPI.

Предполагаемые endpoint:

### Clients

```text
GET    /api/v1/clients
POST   /api/v1/clients
GET    /api/v1/clients/{id}
PUT    /api/v1/clients/{id}
```

### CTI

```text
GET    /api/v1/cti/reports
POST   /api/v1/cti/import
GET    /api/v1/cti/reports/{id}
POST   /api/v1/cti/reports/{id}/analyze
```

### Adversary Brains

```text
GET    /api/v1/adversary-brains
POST   /api/v1/adversary-brains
GET    /api/v1/adversary-brains/{id}
GET    /api/v1/adversary-brains/{id}/versions
```

### Hunt Hypotheses

```text
GET    /api/v1/hypotheses
POST   /api/v1/hypotheses
GET    /api/v1/hypotheses/{id}
POST   /api/v1/hypotheses/{id}/review
POST   /api/v1/hypotheses/{id}/investigate
```

### Detection Coverage

```text
GET    /api/v1/detection/coverage
POST   /api/v1/detection/coverage/analyze
```

### Harness

```text
GET    /api/v1/harness
POST   /api/v1/harness
GET    /api/v1/harness/{id}
POST   /api/v1/harness/{id}/health
POST   /api/v1/harness/{id}/execute
GET    /api/v1/executions/{id}
POST   /api/v1/executions/{id}/cancel
```

### Inventory

```text
GET    /api/v1/inventory/fields
GET    /api/v1/inventory/rules
POST   /api/v1/inventory/import
GET    /api/v1/inventory/import/{id}
```

### Reports

```text
GET    /api/v1/reports
POST   /api/v1/reports/generate
GET    /api/v1/reports/{id}
```

Это рекомендуемые внутренние маршруты. OpenCode должен реализовать их с учётом единой схемы ошибок, валидации, авторизации и tenant isolation.

---

# 22. OBSERVABILITY AND MONITORING

Платформа должна контролировать:

- Backend Health.
- Database Health.
- Harness Availability.
- MCP Availability.
- Model Provider Availability.
- Failed Executions.
- Execution Duration.
- Queue Size.
- CTI Ingestion Failures.
- Import Errors.
- Authorization Failures.
- Outbound Network Activity.

Для каждого AI Execution сохранять:

```text
task_id
harness_id
model_provider
model_name
prompt_version
workflow_version
input_reference
output_reference
start_time
end_time
status
error
```

По возможности сохранять usage metadata, если соответствующий harness предоставляет эти данные.

---

# 23. MVP SCOPE

MVP должен демонстрировать реальную аналитическую ценность, а не просто красивый интерфейс.

## Phase 1 — Foundation

- Project structure.
- Frontend.
- Backend.
- SQLite.
- Authentication.
- RBAC.
- Tenant model.
- Audit logging.
- Configuration management.

## Phase 2 — Inventory

- Clients.
- Sectors.
- Global QRadar Fields.
- Global QRadar Rules.
- Log Source Types.
- Client Telemetry Status.
- Excel/CSV Import.

## Phase 3 — CTI

- ThreadLinqs MCP integration, если разрешена политикой компании.
- Manual PDF/HTML/JSON import.
- CTI normalization.
- IOC extraction.
- TTP extraction.
- MITRE mapping.
- Provenance.
- Admiralty assessment.

## Phase 4 — Multi-Harness Foundation

- Harness Adapter Interface.
- Agent Registry.
- Capability Registry.
- HarnessRouter adapter.
- Execution History.
- Task Routing.
- Health Checks.

Для MVP необходимо подтвердить работоспособность хотя бы одного harness. Второй harness подключить в PoC для демонстрации заменяемости.

Octop должен пройти отдельную проверку совместимости с выбранным интерфейсом интеграции.

## Phase 5 — Adversary Brain

- Brain creation.
- TTP relationships.
- IOC relationships.
- Evidence references.
- Versioning.
- Basic ACH.
- Analyst review.

## Phase 6 — Sector Relevance

- Sector mapping.
- Client mapping.
- Technology relevance.
- Threat relevance assessment.
- Explanation and evidence.

## Phase 7 — Hunt Hypotheses

- Hypothesis generation.
- Required telemetry.
- QRadar fields.
- Detection rules.
- Coverage status.
- Quality Gate.
- Analyst review.
- AQL draft generation.

## Phase 8 — Reporting

- Dashboard.
- CTI Report.
- Sector Relevance Report.
- Adversary Brain Report.
- Hunt Hypothesis Report.
- Detection Coverage Report.

---

# 24. OUT OF SCOPE FOR MVP

Не реализовывать в первой версии:

- Automatic QRadar rule deployment.
- Automatic IOC blocking.
- Automatic endpoint isolation.
- Automatic firewall changes.
- Autonomous incident response.
- Unreviewed TP/FP classification.
- Unreviewed trusted knowledge modification.
- Automatic online LLM training.
- Mandatory graph database.
- Mandatory vector database.
- Kubernetes.
- Large-scale microservices.
- Complex distributed event streaming.
- Mandatory A2A support for every harness.
- Direct access to Octop internal database.
- Unrestricted shell execution by agents.

Эти возможности могут рассматриваться после успешного MVP и отдельного согласования безопасности.

---

# 25. ACCEPTANCE CRITERIA

Реализация MVP считается завершённой только после выполнения следующих проверок.

## 25.1. Platform

- [ ] Workbench запускается во внутренней среде.
- [ ] Нет обязательной зависимости от облачной платформы.
- [ ] Все основные функции работают без внешнего LLM API при наличии настроенной локальной модели и совместимого harness.
- [ ] База данных сохраняется после перезапуска.
- [ ] Работают backup и restore.
- [ ] Работают роли и разрешения.

## 25.2. MSSP

- [ ] Создаются несколько клиентов.
- [ ] Клиентские данные изолированы.
- [ ] Глобальные QRadar Fields общие.
- [ ] Глобальные Detection Rules общие.
- [ ] Статус телеметрии ведётся отдельно для клиентов.
- [ ] AI не может получить данные другого клиента через API или MCP.

## 25.3. CTI

- [ ] Поддерживается ручной импорт отчётов.
- [ ] Поддерживается подключение разрешённого CTI feed.
- [ ] Извлекаются IOC, TTP, CVE и threat actors.
- [ ] Каждый результат имеет provenance.
- [ ] Дубликаты обрабатываются.
- [ ] Сохраняется оригинальный материал.

## 25.4. Adversary Brain

- [ ] Создаётся структурированная модель.
- [ ] Сохраняются связи между признаками.
- [ ] Сохраняются подтверждающие и противоречащие доказательства.
- [ ] Сохраняется история версий.
- [ ] Аналитик может проверить и утвердить изменения.

## 25.5. Hunting

- [ ] Создаются Hunt Hypotheses.
- [ ] Указываются источники доказательств.
- [ ] Используются реальные QRadar Fields.
- [ ] Используются реальные QRadar Rules.
- [ ] Отображаются необходимые Log Sources.
- [ ] Отображаются Detection Gaps.
- [ ] AQL сохраняется как Draft.
- [ ] Аналитик может утвердить или отклонить гипотезу.

## 25.6. Multi-Harness

- [ ] Подключается первый harness.
- [ ] Второй harness проходит интеграционный PoC.
- [ ] Задачи отправляются через единый внутренний контракт.
- [ ] Получаются статусы выполнения.
- [ ] Сохраняется execution history.
- [ ] Поддерживается обработка ошибок.
- [ ] Поддерживается отмена, если её предоставляет адаптер.
- [ ] Можно отключить один harness без остановки всего Workbench.

## 25.7. Security

- [ ] Секреты не хранятся в открытом виде.
- [ ] Все значимые действия записываются в audit log.
- [ ] AI не имеет прямого доступа к основной БД.
- [ ] Действует ограничение сетевого доступа.
- [ ] Клиентские данные не передаются внешнему LLM без разрешения.
- [ ] Write-операции требуют соответствующего разрешения.
- [ ] Важные аналитические решения требуют Human Approval.

---

# 26. TESTING STRATEGY

OpenCode должен реализовать:

### Unit Tests

- Database operations.
- Tenant authorization.
- Data validation.
- CTI parsing.
- IOC normalization.
- Sector mapping.
- Coverage calculations.
- Hypothesis validation.
- Harness adapter contract.

### Integration Tests

- Backend + Database.
- Backend + HarnessRouter.
- Backend + MCP.
- CTI ingestion.
- Inventory import.
- Multi-tenant access checks.

### Security Tests

- Cross-tenant access attempts.
- Unauthorized MCP tool calls.
- Unauthorized API calls.
- Secret leakage.
- Prompt injection handling.
- Untrusted document processing.
- Unauthorized file access.
- Outbound network restrictions.

### Acceptance Tests

Сценарий:

1. Импортировать CTI-отчёт.
2. Извлечь IOC, TTP, CVE.
3. Создать Adversary Brain.
4. Оценить источники.
5. Определить целевой сектор.
6. Найти соответствующих клиентов MSSP.
7. Проверить QRadar Inventory.
8. Проверить доступность телеметрии.
9. Создать Hunt Hypothesis.
10. Сгенерировать AQL Draft.
11. Провести Analyst Review.
12. Сохранить результат расследования.

Все результаты должны быть воспроизводимы по сохранённым исходным материалам, версиям workflow и ссылкам на доказательства.

---

# 27. IMPLEMENTATION INSTRUCTIONS FOR OPENCODE

OpenCode должен выступать в качестве основного AI coding agent.

Не пытаться реализовать всю систему одним большим изменением.

Работать последовательно.

## 27.1. Required Project Documents

Создать следующие файлы:

```text
/docs
    PROJECT_OVERVIEW.md
    PROJECT_ARCHITECTURE.md
    DATABASE_SCHEMA.md
    API_SPECIFICATION.md
    UI_SPECIFICATION.md
    AI_SKILLS_SPEC.md
    MULTI_HARNESS_SPEC.md
    ADVERSARY_BRAIN_SPEC.md
    SECURITY_REQUIREMENTS.md
    TESTING_STRATEGY.md
    IMPLEMENTATION_PLAN.md
    DEPLOYMENT_GUIDE.md

/config
    clients.yaml
    sectors.yaml
    rules_inventory.yaml
    custom_fields_qradar.yaml
    declared_matrix.yaml
    mitre_mapping.yaml
    harness_registry.yaml
    model_providers.yaml

/migrations

/backend

/frontend

/tests

/storage
```

`storage` должен быть persistent runtime directory, а не обязательной частью исходников.

## 27.2. Development Rules

OpenCode обязан:

1. Перед началом работы изучить существующие исходники и окружение.
2. Не перезаписывать существующие конфигурации без анализа.
3. Не придумывать API сторонних продуктов.
4. Использовать официальную документацию и реальные схемы API.
5. Разделять подтверждённые возможности и неподтверждённые интеграции.
6. Не добавлять ненужные зависимости.
7. Не использовать cloud services без разрешения.
8. Не отправлять внутренние данные наружу.
9. Не выполнять реальные операции в QRadar.
10. Не создавать фиктивные данные в production database.
11. Создавать unit и integration tests.
12. Документировать каждый реализованный модуль.
13. Сохранять совместимость с текущими компонентами проекта.
14. Не менять глобальные настройки без явного согласования.
15. Не считать функциональность готовой только потому, что интерфейс отображается.

## 27.3. Definition of Done

Для каждого модуля необходимо предоставить:

- Реализованный код.
- Конфигурацию.
- Database migrations.
- API documentation.
- Unit tests.
- Integration tests.
- UI functionality.
- Error handling.
- Security validation.
- Usage documentation.

Если интеграция не прошла PoC, пометить её как NOT VERIFIED, а не имитировать успешную работу.

## 27.4. Initial Instructions

Первым заданием OpenCode должно быть не написание кода.

Сначала необходимо:

1. Проанализировать доступное окружение.
2. Проверить установленные компоненты.
3. Проверить Octop и HarnessRouter.
4. Определить поддерживаемые интерфейсы интеграции.
5. Проверить ограничения локальной инфраструктуры.
6. Предложить конкретную структуру проекта.
7. Подготовить Implementation Plan.
8. Выявить технические противоречия.
9. Подготовить список неизвестных параметров.
10. После согласования начать Phase 1.

Не считать Octop и HarnessRouter совместимыми без фактического тестирования.

---

# 28. FINAL ARCHITECTURAL DECISIONS

Для реализации использовать следующие исходные решения:

| Область | Решение |
|---|---|
| Platform | MSSP Intelligence Workbench |
| Deployment | On-premise |
| Backend | Go |
| Frontend | React + TypeScript |
| MVP Database | SQLite |
| Production Database | PostgreSQL |
| CTI Feed | ThreadLinqs MCP, subject to approval |
| Harness Integration | Adapter-based |
| Harness Router | HarnessRouter as candidate |
| Existing Harness | Tencent Octop |
| Other Harnesses | OpenCode, Claude Code, Codex, DeepSeek and custom adapters, subject to PoC |
| Agent Interoperability | A2A optional |
| Tool Integration | MCP |
| Internal API | REST/OpenAPI |
| CTI Knowledge | Structured database |
| Adversary Modelling | Adversary Brain |
| Hypothesis Methodology | ACH + ACTIF-inspired workflow |
| Source Assessment | Admiralty System |
| Detection Context | Global QRadar Inventory |
| MSSP Model | Shared global detection inventory + client-specific telemetry |
| Learning | Controlled Feedback Loop |
| Decision Model | Human-in-the-Loop |
| QRadar Actions | Read-only in MVP |
| Source Control | No mandatory Git |
| Cloud | Disabled by default |

---

# 29. PROJECT SUCCESS CRITERIA

Главный критерий успеха — не количество AI-агентов и не количество подключённых моделей.

Успешный MVP должен продемонстрировать следующий сценарий:

**Новый CTI Report → Structured Intelligence → Adversary Brain → Sector Relevance → MSSP Client Matching → QRadar Detection Context → Hunt Hypothesis → Analyst Approval.**

Платформа должна помогать SOC-аналитику отвечать на вопрос:

«Какие новые угрозы действительно релевантны нашим клиентам, что мы можем обнаружить уже сейчас и какие действия должен выполнить SOC для проверки потенциальной угрозы?»

Результаты должны быть доказательными, воспроизводимыми, привязанными к источникам и ограниченными реальными возможностями телеметрии.

**Конечная цель:** создать внутреннюю MSSP Intelligence Platform, которая превращает разрозненную Threat Intelligence в структурированные, проверяемые и применимые к инфраструктуре клиентов Threat Hunting Hypotheses и Detection Intelligence.