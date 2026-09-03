---
title: "Плейбук безопасной разработки с ИИ"
description: "Этот плейбук охватывает использование генеративного ИИ в жизненном цикле разработки ПО: дополнение кода, генерацию кода в чате, AI-ревью кода, агентов IDE и агентов разработки,..."
sidebar:
  order: 50
---
## 1. Область и цель

Этот плейбук охватывает использование генеративного ИИ в жизненном цикле разработки ПО: дополнение кода, генерацию кода в чате, AI-ревью кода, агентов IDE и агентов разработки, которые создают или изменяют код приложения, тесты, зависимости, инфраструктуру как код, процессы CI/CD и документацию.

Используйте документ для:
- onboarding AI coding assistants и определения допустимых режимов работы;
- ревью изменений, полностью или частично созданных моделью;
- контроля релиза кода, созданного ИИ, и pull request, подготовленных агентами;
- защиты исходного кода, секретов, архитектурного контекста и сред разработки;
- проверки dependencies, tests и security подтверждения, предложенных или созданных моделью.

Ответственность документа:
- Этот плейбук отвечает за безопасное применение ИИ при разработке обычного software и за подтверждения, необходимые перед merge/release.
- Общие требования к качеству и безопасности кода находятся в [плейбуке безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/).
- Автономия, tool authorization, memory, sandbox, согласование, rollback и kill switch находятся в [плейбуке безопасности Agentic AI](/Product-security-playbook/ru/ai-security/agentic-ai/playbook/).
- MCP server registry и меры контроля протокола находятся в [плейбуке безопасности MCP](/Product-security-playbook/ru/ai-security/mcp-security/playbook/).

Вне области:
- разработка или обучение foundation models;
- выбор мер контроля для AI-функций, работающих внутри продукта; используйте [обзор безопасности AI](/Product-security-playbook/ru/ai-security/securing-ai/overview/);
- общий secure coding baseline, не зависящий от происхождения кода.

Цель:
- не допустить, чтобы скорость генерации, убедительный вывод модели или автономность coding agent обходили security requirements, ревью ownership и меры контроля релиза.

---

## 2. Модель угроз и классификация изменений

Основные сценарии:
- модель создаёт функционально корректный код с инъекцией, нарушением контроля доступа, небезопасной десериализацией, слабой криптографией или дефектом бизнес-логики;
- большое сгенерированное изменение принимается без понимания потоков данных, границ доверия и побочных эффектов;
- coding assistant получает secrets, proprietary code, customer data или incident artifacts через files, terminal output, logs, diagnostics или tool responses;
- indirect prompt injection из issue, README, dependency documentation, test fixture или web page изменяет поведение agent;
- модель предлагает несуществующий, подмененный, заброшенный или уязвимый package;
- сгенерированные тесты подтверждают текущую реализацию, но не проверяют требования безопасности и сценарии злоупотребления;
- агент меняет аутентификацию, CI/CD, развёртывание, разрешения или зависимости за пределами поставленной задачи.

Классифицируйте изменение по максимальному воздействию:

| Класс | Пример | Минимальное решение |
|---|---|---|
| Low | Документация, комментарии, локальный рефакторинг без изменения поведения | Обычное ревью и стандартный CI |
| Medium | Логика приложения, парсер, API-обработчик, обновление зависимости, генерация тестов | Проверка человеком, тесты безопасности и обязательные сканеры |
| High | Аутентификация, авторизация, криптография, секреты, изоляция tenant, платежи, обработка файлов, CI/CD или IaC | Назначенный проверяющий с компетенцией в домене, сценарии угроз и злоупотреблений, независимая проверка безопасности |
| Critical | Учетные данные рабочей среды, политика подписи или релиза, разрушительная миграция, привилегированная автоматизация или изменения без участия человека в ревью | Не разрешать автономное слияние или выпуск; применять отдельное согласование и меры контроля среды |

Происхождение кода не меняет критичность уязвимости. Изменения, созданные ИИ и человеком, проходят одинаковые контрольные точки безопасности продукта; более высокий уровень контроля нужен там, где способ генерации увеличивает размер diff, автономность или неопределенность ревью.

---

## 3. Базовый профиль для рабочих сред

### 3.1 Управление, инвентаризация и разрешенное использование

`Baseline`:
- Ведите inventory разрешенных coding assistants, models/providers, режим развертывания, data handling terms, retention settings, enabled tools, network access и владельцы.
- Определите, какие repositories, data classes и environments разрешены для каждого инструмента. Consumer accounts и неутвержденные extensions не должны обрабатывать proprietary или regulated material.
- Назначьте ответственного сотрудника для каждого изменения. Модель, поставщик и идентичность агента не могут быть владельцами кода или принятия риска.
- Применяйте защиту веток, обязательные ревью и контрольные точки CI одинаково к веткам, созданным человеком и агентом.
- Не считайте generated-code label самостоятельной мерой контроля. Provenance полезна для triage и metrics, но не доказывает безопасность изменения.

`High-impact/regulated`:
- Требуйте security и data-согласование владельца до включения нового provider, remote code index, repository-wide context, external connector или autonomous write mode.
- Запрещайте прямую отправку изменений и автономное слияние в защищённые ветки.

### 3.2 Границы контекста, данных и секретов

`Baseline`:
- Передавайте модели только минимальный context, необходимый для задачи. Исключайте production data, учетные данные, private keys, session tokens и unrelated repository content.
- Считайте prompts, chat history, code indexes, terminal output, compiler errors, stack traces, tool responses, screenshots и uploaded files отдельными data flows с classification, retention и access rules.
- Используйте enterprise/provider settings, которые запрещают обучение на organization data и задают приемлемую retention policy; проверяйте effective configuration, а не marketing claim.
- Выполняйте поиск секретов до отправки контекста, если средство это поддерживает, и при каждом commit/push. Обнаруженный секрет немедленно отзывайте или ротируйте; удаления строки из diff недостаточно.
- Не считайте `.gitignore`, `.env`, instruction file или просьбу «не читать секреты» границей безопасности. Ограничивайте filesystem scope, environment injection, logs и tool permissions технически.

`High-impact/regulated`:
- Используйте organization-managed gateway/account, auditable access и repository allowlist.
- Отключайте raw prompt/context retention, если нет утвержденной forensic или compliance необходимости.

### 3.3 Постановка задачи и контекст безопасности

`Baseline`:
- До генерации задайте функциональные требования, trust boundaries, data classifications, authorization expectations, prohibited operations и поведение при отказе.
- Для изменений, значимых для безопасности, явно перечисляйте негативные сценарии: межтенантный доступ, повышение привилегий, инъекции, повторное воспроизведение, состояния гонки, небезопасные повторные попытки, частичный отказ и раскрытие чувствительных данных.
- Требуйте минимальный scoped diff. Отдельно согласовывайте изменения public interfaces, schemas, auth flows, dependencies, CI/CD и infrastructure.
- Instruction files и prompt templates могут закреплять workflow и secure defaults, но не являются authorization, sandbox или release control.
- Не полагайтесь на «универсальный безопасный prompt», persona, угрозы модели или повторную генерацию как на подтверждение безопасности.

`High-impact/regulated`:
- Привязывайте задачу к threat model, abuse cases или security acceptance criteria до начала реализации.
- Требуйте plan/preview перед изменением файлов и повторное подтверждение при расширении scope.

### 3.4 Проверка сгенерированного кода

`Baseline`:
- Проверяющий должен понимать измененные потоки данных, границы доверия, решения авторизации и внешние побочные эффекты. Проверки только успешного запуска или поведения интерфейса недостаточно.
- Просматривайте сгенерированный diff построчно. Запрещайте слияние больших непрозрачных изменений, если проверяющий не может объяснить их назначение и последствия.
- Проверяйте не только добавленный код, но и удаленные validations, guards, tests, logging, timeouts и error handling.
- Сверяйте implementation с security requirements независимо от объяснения модели. Уверенный ответ или self-ревью не является подтверждением.
- Используйте [плейбук безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/) для language/framework-specific проверки.

`High-impact/regulated`:
- Требуйте проверяющий, который не был единственным автором prompt и не полагается только на ту же model/session для проверки.
- Изменения auth, cryptography, tenant isolation, CI/CD меры безопасности и signing paths требуют владельца домена ревью.

### 3.5 Зависимости и сгенерированные изменения цепочки поставки ПО

`Baseline`:
- Не устанавливайте package только потому, что его предложила модель. Проверяйте exact name, namespace, registry, publisher/владелец, release history, license, maintenance status и наличие официальной ссылки из trusted project source.
- Считайте несуществующие или неожиданно новые package names потенциальным slopsquatting/typosquatting сигналом. Останавливайте workflow до ручной проверки.
- Разрешайте изменения зависимостей только через manifest/lockfile и утвержденные реестры; CI должен обнаруживать непроверенные изменения manifest, lockfile, реестра и install scripts.
- Применяйте общую базу SCA и поиска секретов из [плейбука безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/). Для изменений зависимостей, сгенерированных ИИ, дополнительно проверяйте репутацию пакета, транзитивные зависимости и lifecycle/install scripts пакетов с высоким воздействием.
- Не принимайте вымышленную версию. Менеджер зависимостей должен подтвердить версию и целостность; релизная сборка использует проверенный lock-файл и неизменяемое значение integrity или digest, если экосистема это поддерживает.

`High-impact/regulated`:
- Coding agent не может автономно устанавливать package или расширять registry/network allowlist.
- Новый пакет для аутентификации, криптографии, сериализации, сборки и релиза либо привилегированной среды выполнения требует отдельного согласования с владельцем.

### 3.6 Тестирование и независимая проверка

`Baseline`:
- После изменения, созданного ИИ, запускайте существующие модульные, интеграционные и регрессионные тесты. Не ослабляйте проверки и контроли ради успешного прохождения пайплайна.
- Добавляйте тесты на основе требований и сценариев злоупотребления, а не только текущей реализации. Проверяйте запрет операций при отказе и неавторизованные пути.
- Выполняйте SAST, SCA и поиск секретов по общей базе [плейбука безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/). Для изменений, сгенерированных ИИ, этот плейбук добавляет независимую проверку сгенерированных тестов, а для IaC, контейнеров и доступных извне путей — применимые доменные сканеры и целевые тесты безопасности.
- Generated tests проходят такой же ревью, как production code. Проверяйте, что они способны упасть при намеренном внесении соответствующего defect.
- Модель может помогать с triage и устранение, но окончательное закрытие замечание требует scanner/test rerun и ревью фактического diff.

`High-impact/regulated`:
- Требуйте независимую security verification, которую не выполняет только та же model/session, создавшая код.
- Для критичных business rules используйте negative integration tests и manual/adversarial ревью.

### 3.7 Агенты разработки и среда выполнения

`Baseline`:
- Coding agents с shell, browser, file write или package installation дополнительно соответствуют [плейбуку безопасности Agentic AI](/Product-security-playbook/ru/ai-security/agentic-ai/playbook/).
- Запускайте agent в ephemeral sandbox с scoped repository checkout, учетными данными вне рабочей среды и deny-by-default-доступом к host filesystem, internal network и cloud metadata.
- Разделяйте чтение недоверенного внешнего content и privileged execution. Issue, PR comment, README, web page и package documentation не могут менять tool authorization.
- Ограничивайте egress allowlist, команды, writable paths, runtime и resource budget. Blocked egress должен fail closed и оставлять audit signal.
- Требуйте предварительный просмотр и согласование установки пакетов, изменения workflow, доступа к секретам, изменения сетевых списков разрешений, разрушительных команд и любых внешних побочных эффектов.

`High-impact/regulated`:
- Используйте disposable environment per task и short-lived, task-specific учетные данные.
- Agent-authored change не должен сам изменять или отключать меры контроля, которые проверяют этот change.

### 3.8 Подтверждения релиза и мониторинг

`Baseline`:
- Сохраняйте задачу, ответственного сотрудника, список измененных файлов, результаты согласований, CI и сканирования безопасности, а также решения по зависимостям. Не сохраняйте исходные чувствительные prompt без необходимости.
- Измеряйте security outcomes, а не только количество accepted suggestions: escaped defects, reopened замечания, vulnerable dependency introductions и ревью churn.
- Отслеживайте drift после model, provider, extension, tool-permission или изменения файлов инструкций.
- Incident response должен уметь найти изменения, созданные конкретным agent/provider period, но не полагайтесь на perfect attribution отдельных строк.

`High-impact/regulated`:
- Фиксируйте model/tool configuration, agent permissions и журнал согласований, достаточные для reconstruction change path.
- Пересматривайте разрешенный режим автономии после security incident или повторяющихся gate bypass attempts.

---

## 4. Проверка

Обязательные подтверждения:
- approved-tool inventory и effective data-handling configuration;
- repository/data/environment access matrix;
- branch protection и required-ревью settings для agent-authored branches;
- пример изменения с использованием ИИ с областью задачи, ответственным сотрудником, проверенным diff и подтверждениями CI;
- подтверждение согласования новой зависимости для нового package;
- scanner configuration и результаты SAST, SCA и secret scanning;
- sandbox, egress и конфигурация согласований для coding agents.

Negative tests:
- секрет в file, terminal output или stack trace блокируется/redacts до передачи модели и обнаруживается при commit;
- instruction в Issue или README не может разрешить forbidden command или exfiltration;
- hallucinated package name не устанавливается автоматически;
- изменение manifest без ожидаемого lockfile или approved registry блокирует pipeline;
- generated authorization code отклоняет horizontal, vertical и cross-tenant access;
- test suite падает после намеренного удаления security check;
- agent не может изменить branch protection, CI security job или scanner suppression без отдельного согласования;
- Изменение с высоким воздействием нельзя сливать, если единственным подтверждением служит самопроверка модели.

Операционные сигналы:
- доля изменений с использованием ИИ, прошедших required human ревью и security gates;
- rate секретов и unapproved dependencies, обнаруженных до merge;
- escaped vulnerability rate для AI-assisted и остальных изменений с сопоставимым risk profile;
- средний размер agent-authored diff и доля изменений, возвращенных из-за uncontrolled scope;
- blocked tool, egress и package-install attempts;
- замечания reopened после AI-generated устранение.

---

## 5. Решение по результатам ревью

Матрица ниже определяет доменную критичность замечания и решение о релизе. Общие SLA устранения, жизненный цикл исключений, принятие риска и подтверждения закрытия определяет [плейбук управления уязвимостями](/Product-security-playbook/ru/review/vulnerability-management/playbook/); при пересечении требований применяется более строгое.

| Severity | Условие | Обязательное действие |
|---|---|---|
| Critical | Agent может merge/release в protected environment без подтверждение человеком и обязательных CI gates | Блокировать режим и восстановить branch/release protection |
| Critical | Coding assistant/agent имеет доступ к production secrets или customer data без утвержденной необходимости и технической изоляции | Отозвать доступ, ротировать раскрытые учетные данные и провести оценку инцидента |
| High | Код с высоким воздействием принят без проверяющего, способного объяснить его защитное поведение и побочные эффекты | Блокировать слияние до независимого ревью |
| High | Agent автономно устанавливает неизвестные packages или меняет registry/egress policy | Блокировать workflow до allowlist и меры подтверждения |
| High | Security verification выполнена только self-ревью той же model/session без независимых tests/scanners | Требовать повторную независимую проверку |
| Medium | Inventory, provenance metadata или AI-use подтверждения неполны, но обычные проверки и release gates работают | Назначить владельца устранения и срок |
| Medium | Generated tests проверяют только happy path | Добавить negative и abuse-case tests до high-impact release |
| Low | AI-assisted label или metrics непоследовательны, но access, ревью и gates не затронуты | Исправить в рамках process improvement |

Релиз считается одобренным, когда accountable human понимает изменение, scope ограничен, dependencies подтверждены, secrets защищены, меры безопасности проверены независимо, а AI не может обойти branch, CI или environment policy.

---

## 6. Связанные материалы

- [Плейбук безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/)
- [Плейбук безопасности Agentic AI](/Product-security-playbook/ru/ai-security/agentic-ai/playbook/)
- [Плейбук безопасности MCP](/Product-security-playbook/ru/ai-security/mcp-security/playbook/)
- [Обзор безопасности AI](/Product-security-playbook/ru/ai-security/securing-ai/overview/)
- [Плейбук моделирования угроз](/Product-security-playbook/ru/review/threat-modeling/playbook/)
- [Плейбук release governance](/Product-security-playbook/ru/review/release-governance/playbook/)
- [Обзор SLSA provenance](/Product-security-playbook/ru/supply-chain/slsa-provenance/overview/)
