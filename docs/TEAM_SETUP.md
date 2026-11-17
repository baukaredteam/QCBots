# Минимальный состав ботов и pstack-скиллы

## Состав

Chief (оркестратор, общая точка контакта) и четыре исполнителя:

| Роль | Ответственность |
|---|---|
| Backend Dev | Go, REST/OpenAPI, SQLite WAL + миграции, tenant-scoped авторизация, HarnessAdapter, MCP без произвольного SQL |
| Frontend Dev | React + TypeScript strict, Vite, Tailwind, SSE; изоляция данных на сервере |
| QA / Verification | Все тесты: unit, integration, security, property-based, statechart/TLA+; артефакты верификации |
| CTI Engineer | Adversary Brain, Admiralty, ATT&CK, ACH, QRadar coverage, черновики AQL/Sigma, FP-оценка, безопасность |

Упразднены: PM, Tech Lead, отдельные CTI Domain Architect и Detection Engineer, а также неиспользуемые роли из `.agents/agents` (ai-integration, code-reviewer, documentation). Их обязанности распределены между Chief и четырьмя ролями выше: доступ к Linear и планирование ведёт Chief, спеки и ревью — Chief вместе с QA, домен и детекты — CTI Engineer.

## Принцип

Больше агентов не равно больше результата. Каждую коррекцию агента кодируем в детерминированную проверку: линтер, тип или тест. Инструкции в тексте soul оставляем только для суждений. Ревью идёт по артефактам верификации, а не по словам «готово».

## Импортированные pstack-скиллы

- `principle-encode-lessons-in-structure` — повторяющуюся правку превращать в линт/проверку, а не в ещё одну инструкцию.
- `principle-fix-root-causes` — чинить первое место, где система пошла не так; guard — не fix.
- `principle-test-behavior-not-implementation` — тестировать наблюдаемое поведение.
- `no-comments` — убирать комментарии-оправдания и кодировать ограничения в структуру.
- `statechart` — TLA+-проверка и Mermaid-диаграмма состояний как артефакт ревью.
- `create-verification-skill` — проектный скилл, который проверяет поведение приложения так, как его видит пользователь.

Источник: https://github.com/cursor/plugins/tree/main/pstack/skills

## Правила работы

- Один issue — одна ветка — один PR; мерж только после одобрения человеком.
- Human-in-the-loop: деплой правил в QRadar, публикация отчётов, изменение доверенных знаний — только после явного «да».
- Tenant isolation на сервере; глобальные поля и правила QRadar не дублируются по клиентам.
- Интеграции без PoC помечаются NOT VERIFIED, результаты тестов не выдумываются.
