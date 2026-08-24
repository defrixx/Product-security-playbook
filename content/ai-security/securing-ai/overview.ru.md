# Безопасность AI: обзор

## 1. Область и цель

Этот обзор направлен на обеспечение безопасности систем в рабочих средах:
- AI/LLM-ассистентов и агентных процессов
- RAG и поиска по базе знаний
- модели для принятия решений (включая antifraud/scoring)
- MLOps/LLMOps и интеграции с бизнес-системами

Цель:
- покрыть все ключевые аспекты безопасности, начиная с `Zero Trust`
- для каждого аспекта дать практические, проверяемые меры контроля

Ответственность документа:
- Этот документ отвечает за общий базовый профиль мер контроля AI-систем в рабочих средах.
- Он связывает AI-риски с практическими мерами контроля, уровнями требований, операционными сигналами и governance-ожиданиями.
- Он использует OWASP LLM Top 10 как таксономию, но не забирает на себя каталог угроз.
- Глубокие требования к автономии агентов, memory, выполнению tools и action traces вынесены в [плейбук безопасности Agentic AI](../agentic-ai/playbook.ru.md).
- MCP server registry, развертывание протокола, OAuth usage и меры контроля дрейфа capability вынесены в [плейбук безопасности MCP](../mcp-security/playbook.ru.md).

---

## 2. Базовые принципы

### 2.1 Zero Trust для AI

**Фокус:**
- не доверять ни одному входу, выходу, интеграции, модели и источнику данных по умолчанию

**Практические меры контроля:**
- `Baseline`: явные границы доверия для потоков `user -> model -> tool -> downstream`
- `Baseline`: `deny-by-default` для выполнения инструментов и доступа к данным
- `Baseline`: непрерывная проверка контекста пользователя (не только на входе сессии)
- `High-impact/regulated`: policy-as-code для авторизации и политик данных
- `Recommended maturity`: регулярное моделирование угроз по изменениям агентных сценариев

**Сигналы проверки:**
- процент вызовов инструментов, заблокированных policy engine
- покрытие сценариев пересечения границ доверия тестами

### 2.2 Уровни мер контроля и предположения по источникам

Метки мер контроля в этом документе описывают профиль требований, а не severity замечаний:
- `Baseline`: минимальная база для рабочих сред для рассматриваемого класса AI-систем.
- `High-impact/regulated`: обязательно для автономных state-changing действий, cross-tenant доступа к данным, финансового/safety/privacy влияния, регулируемых сценариев или внешне доступных AI-возможностей.
- `Recommended maturity`: полезно для зрелой программы, повышенной assurance или будущего усиления защиты, но не является блокером релиза по умолчанию, если это не принято локальной политикой.

---

## 3. Аспекты безопасности и меры контроля

### 3.1 Идентичности и доступ (AI IAM)

**Риски:**
- агенты с избыточными правами
- подмена сервисной идентичности
- межтенантный доступ

**Покрытие OWASP LLM Top 10:**
- `LLM06: Excessive Agency`
- `LLM02: Sensitive Information Disclosure`

**Практические меры контроля:**
- `Baseline`: workload identity вместо статических ключей
- `Baseline`: принцип минимально необходимых привилегий для каждого инструмента и API
- `Baseline`: авторизация с учетом tenant на каждом последующем шаге
- `High-impact/regulated`: короткоживущие токены, ротация, привязка audience
- `Recommended maturity`: SoD для операций с высоким воздействием

**Сигналы проверки:**
- доля сервисов без долгоживущих учетных данных
- число отклоненных попыток по межтенантной политике

### 3.2 Безопасность данных и приватность

**Риски:**
- утечка ПДн/секретов через промпт, контекст или вывод
- несанкционированное использование данных при обучении
- нарушение требований к хранению и регуляторных требований

**Покрытие OWASP LLM Top 10:**
- `LLM02: Sensitive Information Disclosure`
- `LLM07: System Prompt Leakage`

**Практические меры контроля:**
- `Baseline`: классификация данных + матрица обработки данных для AI-сценариев
- `Baseline`: DLP/redaction до модели и перед выдачей пользователю
- `Baseline`: не считать `.env`, `.gitignore`, prompt/instruction files или просьбу модели не читать секреты границей безопасности; ограничивать filesystem, environment injection, tool output, logs и context техническими меры контроля
- `Baseline`: encryption in transit/at rest + tenant isolation
- `Baseline`: classify embeddings, vector stores, memory, cached outputs и interaction logs как sensitive data, даже если raw source text не хранится
- `High-impact/regulated`: строгая минимизация данных для inference/training
- `High-impact/regulated`: принудительно применяемые меры контроля хранения и удаления
- `Recommended maturity`: оценка влияния на приватность для новых AI-функций

**Сигналы проверки:**
- количество DLP-срабатываний на 1k запросов
- SLA на удаление данных и процент выполнений в срок

### 3.3 Безопасность моделей и цепочки поставки

**Риски:**
- компрометированные модели/адаптеры
- уязвимые ML-зависимости
- юридические риски по лицензиям
- unmanaged AI assets вне обычного software и infrastructure inventory

**Покрытие OWASP LLM Top 10:**
- `LLM03: Supply Chain`
- `LLM04: Data and Model Poisoning`

**Практические меры контроля:**
- `Baseline`: trusted registry + provenance checks (hash/signature/publisher)
- `Baseline`: инвентаризация AI assets шире deployed services: model endpoints, prompt/config stores, vector stores, memory stores, evaluation harnesses, tool adapters, MCP servers, provider consoles и local AI runtimes
- `High-impact/regulated`: SBOM/AI-BOM для model artifacts и runtime
- `Baseline`: CVE scanning + gating на критичных уязвимостях
- `High-impact/regulated`: контролируемый процесс продвижения (dev -> staging -> prod) с согласования
- `High-impact/regulated`: юридическое ревью условий сторонних моделей
- `Recommended maturity`: independent red team перед внедрением в рабочую среду

**Сигналы проверки:**
- доля релизов с подписанными артефактами
- покрытие AI assets inventory и полнота владельца и срока пересмотра
- время закрытия критичных CVE в AI-stack

### 3.4 Безопасность промптов, контекста и RAG

**Риски:**
- prompt injection (direct/indirect)
- poisoned knowledge base
- retrieval без ACL и межтенантные утечки

**Покрытие OWASP LLM Top 10:**
- `LLM01: Prompt Injection`
- `LLM08: Vector and Embedding Weaknesses`
- `LLM04: Data and Model Poisoning`

**Практические меры контроля:**
- `Baseline`: строгое разделение контекста (доверенный и недоверенный)
- `Baseline`: retrieval с document-level/tenant-level authorization
- `Baseline`: ingestion security pipeline (malware/content/policy checks)
- `Baseline`: memory write policy для agents; исключайте secrets, tokens, raw regulated data и unnecessary sensitive fields из working memory, long-term memory, checkpoints и summaries
- `High-impact/regulated`: обнаружение jailbreak/инъекционных паттернов
- `High-impact/regulated`: версионирование prompt templates + обязательное проверка безопасности
- `High-impact/regulated`: semantic recovery tests для vector stores и agent memory, чтобы restored context был authorized, current и not poisoned
- `Recommended maturity`: adversarial test suite в CI/CD

**Сигналы проверки:**
- success rate инъекций в red-team тестах
- доля RAG-документов, прошедших проверку по политикам
- memory write rejection rate и результаты vector-store recovery tests

### 3.5 Безопасность вывода и действий агента

**Риски:**
- небезопасное исполнение вывода модели
- нежелательные транзакции и destructive actions
- цепочки эскалации через инструменты

**Покрытие OWASP LLM Top 10:**
- `LLM05: Improper Output Handling`
- `LLM06: Excessive Agency`

**Практические меры контроля:**
- `Baseline`: вывод всегда считать недоверенным вводом
- `Baseline`: валидация схемы + allowlist команд/операций
- `Baseline`: two-step execution для state-changing действий (`preview -> explicit confirm -> execute`)
- `High-impact/regulated`: human-in-the-loop + согласование по принципу четырех глаз для операций с высоким воздействием и необратимых операций
- `High-impact/regulated`: sandbox для code/command execution
- `High-impact/regulated`: лимиты частоты запросов и затрат для публичных и пакетных сценариев; автономные агенты дополнительно используют ограничения шагов, глубины цепочки инструментов и kill switch из [плейбука безопасности Agentic AI](../agentic-ai/playbook.ru.md)
- `Recommended maturity`: transaction risk scoring перед выполнением

Числовые ограничения автономности и целевое время аварийной остановки определяет [плейбук безопасности Agentic AI](../agentic-ai/playbook.ru.md). Лимиты запросов, токенов и стоимости задавайте по модели нагрузки, классу клиента и допустимому ущербу; фиксируйте выбранные значения и сигналы срабатывания в решении по релизу.

**Сигналы проверки:**
- число заблокированных попыток рискованных действий
- доля запросов, заблокированных бюджетными guardrail-лимитами
- время остановки неконтролируемого агента относительно SLO из плейбука Agentic AI

### 3.6 Безопасность MCP и agent tool protocol

**Риски:**
- недоверенные MCP/tool servers попадают в agent runtime
- отравление tool manifest или незаметное расширение tool scopes
- shadow tools, избыточная передача контекста и утечка токенов в protocol logs

**Покрытие OWASP LLM Top 10:**
- `LLM06: Excessive Agency`
- `LLM02: Sensitive Information Disclosure`
- `LLM03: Supply Chain`

**Границы ответственности:**
- [Плейбук безопасности Agentic AI](../agentic-ai/playbook.ru.md) определяет авторизацию действий агента, сохранение контекста полномочий, ограничения автономности, подтверждение опасных действий и аварийную остановку.
- [Плейбук безопасности MCP](../mcp-security/playbook.ru.md) определяет инвентаризацию и доверие к MCP-серверам и инструментам, транспорт, передачу токенов, изменение manifest/capabilities, gateway policy и протокольное журналирование.
- В рамках этого обзора достаточно подтвердить, что применимы оба специализированных плейбука и их решения включены в единое решение по релизу AI-системы.
- Автономия agents, memory, action traces, согласования, rollback и поведение kill switch находятся в [плейбуке безопасности Agentic AI](../agentic-ai/playbook.ru.md).

**Сигналы проверки:**
- покрытие inventory для MCP servers и registered tools
- доля tool calls, проверенных политикой до execution
- alerts по unknown tools, capability drift, redaction failures и abnormal tool sequences

### 3.7 Инфраструктура и безопасность runtime

**Риски:**
- компрометация inference/training окружений
- lateral movement внутри платформы
- неконтролируемый egress

**Покрытие OWASP LLM Top 10:**
- `LLM10: Unbounded Consumption`
- `LLM03: Supply Chain`

**Практические меры контроля:**
- `Baseline`: усиление защиты контейнеров/нод (seccomp, runtime policies)
- `Baseline`: сегментация сети и egress allowlisting
- `Baseline`: secrets management через централизованный vault
- `High-impact/regulated`: EDR/runtime detection для AI workloads
- `High-impact/regulated`: immutable logs + centralized SIEM
- `Recommended maturity`: confidential compute для чувствительных сценариев

**Сигналы проверки:**
- покрытие AI workloads runtime policies
- число egress-deny событий по AI namespace

### 3.8 AppSec для AI-приложения

**Риски:**
- классические web/API уязвимости + AI-специфичные цепочки
- небезопасный frontend rendering model output
- SSRF/XSS/SQLi через LLM-mediated paths
- agent browser, file, email и code-execution tools как недоверенные ingestion и execution paths

**Покрытие OWASP LLM Top 10:**
- `LLM05: Improper Output Handling`
- `LLM01: Prompt Injection` (в LLM-mediated flows)

**Практические меры контроля:**
- `Baseline`: базовый профиль безопасной разработки для web/API code плюс AI-специфичные проверки
- `Baseline`: параметризованные запросы + output encoding с учетом контекста
- `Baseline`: CSP/санитизация HTML для LLM content
- `Baseline`: запускать browser automation, URL fetchers, file parsers и code interpreters в isolated sandboxes с deny-by-default egress и без default access к internal networks, host files, metadata services или учетным данным рабочей среды
- `Baseline`: scanning и sanitization для downloaded files, HTML, PDFs, email content и retrieved web content до попадания в memory, RAG или execution tools
- `High-impact/regulated`: SAST/DAST/IAST профили для AI endpoints
- `High-impact/regulated`: подтверждение человеком перед third-party code execution, package installation, shell commands или file operations вне temporary workspace
- `Recommended maturity`: security contract tests между AI gateway и downstream APIs

**Сигналы проверки:**
- число high-замечаний до релиза
- покрытие AI endpoints в автоматизированных security тестах
- результаты sandbox escape, egress-deny и malicious-content rejection tests

### 3.9 Мониторинг, обнаружение и реагирование на инциденты

**Риски:**
- позднее обнаружение злоупотреблений, атак на промпты и утечек данных
- отсутствие плейбуков для AI-специфичных инцидентов

**Покрытие OWASP LLM Top 10:**
- кросс-функциональное покрытие `LLM01`–`LLM10` через обнаружение и response

**Практические меры контроля:**
- `Baseline`: аудит-трейл для промптов, retrieval, tool calls, решений политики с минимизацией данных на уровне полей
- `Baseline`: action trace для agent workflows, который correlates model calls, retrieval events, memory writes, tool invocations, policy decisions, согласования, downstream actions и final output
- `Baseline`: маскирование/редакция секретов и ПДн в логах до записи
- `Baseline`: журналирование raw payloads промптов, контекста и tools должно быть отключено по умолчанию; для штатной эксплуатации используйте логи с маскированием чувствительных данных и минимальным набором полей
- `Baseline`: ограничивайте raw payload capture только scoped forensic mode с согласование, break-glass доступом, case ID, шифрованием, retention `<=30 days`, подтверждением удаления и DLP/redaction там, где это возможно
- `Baseline`: правила обнаружения для инъекций, privilege misuse, data exfil
- `Baseline`: подтверждать, что provider-managed AI runtimes дают достаточные logs, меры управления сроками хранения, export capability, memory isolation и emergency disablement до production use
- `High-impact/regulated`: AI incident runbooks (containment, rollback, customer comms)
- `High-impact/regulated`: tabletop exercises по realistic AI attack paths
- `Recommended maturity`: continuous purple teaming

**Сигналы проверки:**
- MTTD/MTTR для AI-событий безопасности
- процент инцидентов с корректно отработанным runbook
- доля raw payload логов, удаленных в срок по retention policy
- доля high-impact agent actions, которые можно восстановить по redacted action traces

### 3.10 Управление, риск и соответствие требованиям

**Риски:**
- неконтролируемый rollout AI-фич
- несоответствие внутренним политикам и регуляторным требованиям

**Покрытие OWASP LLM Top 10:**
- кросс-функциональное покрытие `LLM01`-`LLM10` через релизные gates и risk ownership

**Практические меры контроля:**
- `Baseline`: AI risk register с владельцем и сроками устранения
- `Baseline`: релизная проверка по критериям безопасности, приватности и соответствия требованиям
- `High-impact/regulated`: model cards + system cards для high-risk use-cases
- `High-impact/regulated`: third-party risk assessment для AI vendors
- `Recommended maturity`: quarterly control effectiveness ревью

**Сигналы проверки:**
- доля релизов, прошедших AI risk gate без исключения
- количество просроченных задач на устранение

### 3.11 Safety и устойчивость к злоупотреблениям

**Риски:**
- вредный вывод, misuse, abuse бизнес-логики
- в antifraud-сценариях: adversarial adaptation и обход механизмов обнаружения

**Покрытие OWASP LLM Top 10:**
- `LLM09: Misinformation`
- `LLM10: Unbounded Consumption` (abuse/automation loops)
- `LLM04: Data and Model Poisoning` (для model manipulation)

**Практические меры контроля:**
- `Baseline`: фильтры политик для harmful/disallowed intents
- `Baseline`: safeguarded fallback на deterministic бизнес-логику
- `High-impact/regulated`: abuse monitoring по поведению пользователя, устройства и сессии
- `High-impact/regulated`: регулярная калибровка порогов для fraud/risk моделей
- `Recommended maturity`: attacker-in-the-loop simulations

**Сигналы проверки:**
- false negative/false positive по abuse/fraud кейсам
- drift показателей модели и время реакции на drift

---

## 4. Операционная модель внедрения

### 4.1 RACI (минимум)

- Product: владелец бизнес-риска AI-функций
- Security/AppSec: контроль требований безопасности и релизных проверок
- ML/AI Engineering: жизненный цикл модели и технические меры контроля
- Platform/SRE: усиление защиты runtime, observability, готовность к IR
- Legal/Privacy: условия использования данных и меры защиты приватности

### 4.2 Артефакты, обязательные к релизу

- threat model для AI-функции
- матрица политик (`who/what/can-do`)
- поток данных + классификация данных
- запись AI asset inventory, включая владелец, autonomy level, tools, memory/retrieval stores, provider/runtime и срок пересмотра
- model/supply chain provenance package
- action-trace schema и kill-switch/rollback подтверждения для agentic workflows
- тестовые подтверждения (security + abuse + resilience)

### 4.3 LLMSecOps lifecycle gates

**Scope & Plan:**
- `Baseline`: определить бизнес-сценарий, классы данных, группы пользователей, границы доверия и недопустимые действия до выбора модели или vendor
- `Baseline`: провести third-party risk assessment для model/provider/tooling с учетом data usage, retention, training opt-out, residency и incident notification
- `High-impact/regulated`: зафиксировать обоснование выбора модели, пригодность для задачи и fallback strategy для отказа от LLM там, где deterministic logic безопаснее

**Augment, fine-tune, data:**
- `Baseline`: проверять источники training/fine-tuning/RAG данных на право использования, актуальность, malware/content risk и tenant boundary
- `Baseline`: защищать data pipeline и векторную БД как хранилища данных рабочих сред: authz на документном уровне, audit trail, encryption, backup/restore и процесс удаления
- `High-impact/regulated`: вести версионирование datasets, embeddings, prompt templates и retrieval policies, чтобы incident response мог откатить не только код, но и контекст

**Develop & experiment:**
- `Baseline`: применять базовый профиль безопасной разработки к AI gateway, tool adapters, prompt orchestration и downstream integrations, а не только к web/API оболочке
- `Baseline`: регистрировать MCP/tool servers до использования; unregistered local, shadow или developer-only tools не должны быть доступны из рабочей среды agents
- `High-impact/regulated`: вести tracking экспериментов с моделью, параметрами, версией prompt, snapshot датасета, версией evaluator и security-замечаниями
- `High-impact/regulated`: изолировать developer sandbox от данных рабочих сред и инструментов рабочих сред; любые исключения оформлять как временный break-glass доступ

**Test & evaluate:**
- `Baseline`: включить adversarial testing, prompt-injection tests, authorization tests для tools/RAG и output-handling tests в релизные подтверждения
- `High-impact/regulated`: проводить incident simulation и response testing для сценариев утечки данных, runaway agent, compromised model artifact и poisoned RAG source
- `Recommended maturity`: вести benchmark не только по quality/latency/cost, но и по поведение отказов, jailbreak resistance, частоте утечек данных и policy false positives

**Release:**
- `High-impact/regulated`: выпускать AI-BOM/SBOM для model artifacts, datasets там, где это применимо, prompt/runtime components, dependencies и external services
- `Baseline`: подписывать и проверять model/dataset artifacts; promotion в рабочую среду разрешать только из trusted registry
- `High-impact/regulated`: выполнять оценку профиля безопасности модели перед promotion в рабочую среду и при значимой смене модели/provider

**Deploy:**
- `Baseline`: валидировать runtime configuration, secrets, network egress, API exposure, tenant isolation и user/machine access перед включением боевого трафика
- `Baseline`: проверять signatures/provenance артефактов моделей и датасетов во время развертывания, а не только в CI
- `Baseline`: проверять identity, version, transport, scopes и outbound destinations MCP/tool manifest до включения agent access
- `High-impact/regulated`: включать fallback, rollback и kill switch до запуска autonomous или tool flows с высоким воздействием

**Operate:**
- `Baseline`: держать runtime guardrails, rate limits, budget limits, output validation и принудительное применение политик для tools включенными постоянно, включая degraded mode
- `High-impact/regulated`: использовать alerts по patch/update для model providers, AI frameworks, векторных БД, model serving и orchestration components
- `High-impact/regulated`: регулярно пересматривать risk scoring для действий агента на основании реальных denied events и выводов из инцидентов

**Monitor:**
- `Baseline`: собирать security metrics по adversarial input, tool denial, попыткам обхода политик, сигналам утечки данных, аномалиям в agent chains и дрейф поведения модели
- `Baseline`: alerting на unknown MCP servers, tool manifest drift, abnormal tool chains и token/secret patterns в protocol logs
- `High-impact/regulated`: иметь alert routing в Security/SRE/Product с severity, владелец и runbook; AI alerts без владельца быстро превращаются в noise
- `Recommended maturity`: отслеживать ethical/compliance signals там, где они являются риск рабочей среды: bias, unfair denial, regulated advice, unsafe recommendations

**Govern:**
- `Baseline`: проводить user/machine access audits для AI tools, model registries, prompt repositories, vector stores и provider consoles
- `Baseline`: хранить аудиторские подтверждения по model decisions, dataset versions, изменения prompt/system, исключениям и incident governance
- `High-impact/regulated`: пересматривать AI risk register минимум ежеквартально и при major model/provider change

---

## 5. Связанные материалы

- [OWASP LLM Top 10: обзор угроз](../owasp-llm-top-10/overview.ru.md)
- [Плейбук безопасности Agentic AI](../agentic-ai/playbook.ru.md)
- [Плейбук безопасной разработки с ИИ](../ai-assisted-development/playbook.ru.md)
- [Плейбук безопасности MCP](../mcp-security/playbook.ru.md)
- [Плейбук моделирования угроз](../../review/threat-modeling/playbook.ru.md)
- [Плейбук безопасности API](../../application-security/api/api-security-patterns/playbook.ru.md)
- [Плейбук безопасной разработки и ревью кода](../../application-security/secure-coding/code-review/playbook.ru.md)
