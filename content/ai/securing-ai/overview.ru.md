# Безопасность AI: обзор

## 1. Область и цель

Этот обзор направлен на обеспечение безопасности production-систем:
- AI/LLM-ассистентов и агентных процессов
- RAG и поиска по базе знаний
- модели для принятия решений (включая antifraud/scoring)
- MLOps/LLMOps и интеграции с бизнес-системами

Цель:
- покрыть все ключевые аспекты безопасности, начиная с `Zero Trust`
- для каждого аспекта дать практические, проверяемые контроли

---

## 2. Базовые принципы

### 2.1 Zero Trust для AI

**Фокус:**
- не доверять ни одному входу, выходу, интеграции, модели и источнику данных по умолчанию

**Практические контроли:**
- `Baseline`: явные границы доверия для потоков `user -> model -> tool -> downstream`
- `Baseline`: `deny-by-default` для выполнения инструментов и доступа к данным
- `Baseline`: непрерывная проверка контекста пользователя (не только на входе сессии)
- `High-impact/regulated`: policy-as-code для авторизации и политик данных
- `Recommended maturity`: регулярное моделирование угроз по изменениям агентных сценариев

**Сигналы проверки:**
- процент вызовов инструментов, заблокированных policy engine
- покрытие сценариев пересечения границ доверия тестами

### 2.2 Уровни контролей и предположения по источникам

Метки контролей в этом документе описывают профиль требований, а не severity findings:
- `Baseline`: минимальная production-база для рассматриваемого класса AI-систем.
- `High-impact/regulated`: обязательно для автономных state-changing действий, cross-tenant доступа к данным, финансового/safety/privacy влияния, регулируемых сценариев или внешне доступных AI-возможностей.
- `Recommended maturity`: полезно для зрелой программы, повышенной assurance или будущего hardening, но не является release blocker по умолчанию, если это не принято локальной политикой.

---

## 3. Аспекты безопасности и контроли

### 3.1 Идентичности и доступ (AI IAM)

**Риски:**
- агенты с избыточными правами
- подмена сервисной идентичности
- межтенантный доступ

**Покрытие OWASP LLM Top 10:**
- `LLM06: Excessive Agency`
- `LLM02: Sensitive Information Disclosure`

**Практические контроли:**
- `Baseline`: workload identity вместо статических ключей
- `Baseline`: принцип наименьших привилегий для каждого инструмента и API
- `Baseline`: tenant-aware authorization на каждом последующем шаге
- `High-impact/regulated`: короткоживущие токены, ротация, привязка audience
- `Recommended maturity`: SoD для high-impact операций

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

**Практические контроли:**
- `Baseline`: классификация данных + матрица обработки данных для AI-сценариев
- `Baseline`: DLP/redaction до модели и перед выдачей пользователю
- `Baseline`: encryption in transit/at rest + tenant isolation
- `High-impact/regulated`: строгая минимизация данных для inference/training
- `High-impact/regulated`: принудительно применяемые контроли хранения и удаления
- `Recommended maturity`: оценка влияния на приватность для новых AI-функций

**Сигналы проверки:**
- количество DLP-срабатываний на 1k запросов
- SLA на удаление данных и процент выполнений в срок

### 3.3 Безопасность моделей и цепочки поставки

**Риски:**
- компрометированные модели/адаптеры
- уязвимые ML-зависимости
- юридические риски по лицензиям

**Покрытие OWASP LLM Top 10:**
- `LLM03: Supply Chain`
- `LLM04: Data and Model Poisoning`

**Практические контроли:**
- `Baseline`: trusted registry + provenance checks (hash/signature/publisher)
- `High-impact/regulated`: SBOM/AI-BOM для model artifacts и runtime
- `Baseline`: CVE scanning + gating на критичных уязвимостях
- `High-impact/regulated`: контролируемый процесс продвижения (dev -> staging -> prod) с approvals
- `High-impact/regulated`: юридическое ревью условий сторонних моделей
- `Recommended maturity`: independent red team перед production adoption

**Сигналы проверки:**
- доля релизов с подписанными артефактами
- время закрытия критичных CVE в AI-stack

### 3.4 Безопасность промптов, контекста и RAG

**Риски:**
- prompt injection (direct/indirect)
- poisoned knowledge base
- retrieval без ACL и cross-tenant leakage

**Покрытие OWASP LLM Top 10:**
- `LLM01: Prompt Injection`
- `LLM08: Vector and Embedding Weaknesses`
- `LLM04: Data and Model Poisoning`

**Практические контроли:**
- `Baseline`: строгое разделение контекста (доверенный и недоверенный)
- `Baseline`: retrieval с document-level/tenant-level authorization
- `Baseline`: ingestion security pipeline (malware/content/policy checks)
- `High-impact/regulated`: обнаружение jailbreak/injection паттернов
- `High-impact/regulated`: версионирование prompt templates + обязательное security review
- `Recommended maturity`: adversarial test suite в CI/CD

**Сигналы проверки:**
- success rate инъекций в red-team тестах
- доля RAG-документов, прошедших policy scan

### 3.5 Безопасность вывода и действий агента

**Риски:**
- небезопасное исполнение вывода модели
- нежелательные транзакции и destructive actions
- цепочки эскалации через инструменты

**Покрытие OWASP LLM Top 10:**
- `LLM05: Improper Output Handling`
- `LLM06: Excessive Agency`

**Практические контроли:**
- `Baseline`: вывод всегда считать недоверенным вводом
- `Baseline`: валидация схемы + allowlist команд/операций
- `Baseline`: two-step execution для state-changing действий (`preview -> explicit confirm -> execute`)
- `High-impact/regulated`: human-in-the-loop + four-eyes approval для high-impact/необратимых операций
- `High-impact/regulated`: sandbox для code/command execution
- `High-impact/regulated`: rate limits, loop guards, kill switch со стартовыми guardrails (`max tool-chain depth=3`, `max autonomous steps=5`, `request budget=60 req/min per user`, `token budget=20k tokens/request`)
- `Recommended maturity`: transaction risk scoring перед выполнением

Матрица применимости числовых guardrails:

| Класс AI workflow | Стартовый default | Hard cap | Правило исключения | Сигнал проверки |
|---|---|---|---|---|
| Public assistant без state-changing tools | `60 req/min per user`, `20k tokens/request`, автономные tool chains по умолчанию отключены | Tenant/IP cost quota, max context и streaming duration по product tier | Более высокие лимиты требуют abuse/cost model, tenant quota и alert owner | 429 rate, spend per tenant, prompt-flood detection, тесты отклонения context-window overflow |
| Internal copilot с read-only tools | `max tool-chain depth=3`, `max autonomous steps=5`, `20k tokens/request` | Tool calls только в утвержденные read-only systems; без cross-tenant или production-write actions | Более широкий retrieval/tool access требует approval от data owner и audit sampling | Policy-denied tool calls, pass rate retrieval ACL tests, sampled audit events |
| Autonomous state-changing agent | `preview -> explicit confirm -> execute`; autonomous execution по умолчанию отключен для high-impact actions | `max autonomous steps=3` до re-authorization; kill switch SLO `<=60s`; irreversible action только с human approval | Любое no-confirm действие требует owner, expiry, rollback plan и abuse-case tests | Negative tests на unauthorized actions, approval coverage, mean time to kill runaway actions |
| Batch/RAG ingestion или offline processing | Budget по job, tenant, corpus и source; per-chat request budget не применяется напрямую | Max documents, max tokens per document, max runtime, max outbound fetches и quarantine threshold | Больший batch требует staging run, cost estimate, malware/content scan и source trust decision | Poisoned-document test results, ingestion reject rate, job cost variance, quarantine metrics |

Эти числа являются локальной стартовой базой. Уточняйте их по model context window, streaming mode, batch size, tenant tier, cost profile, tool risk и downstream blast radius; фиксируйте выбранные значения в release gate.

**Сигналы проверки:**
- число заблокированных попыток рискованных действий
- доля запросов, заблокированных guardrail budget limits
- mean time to kill для runaway-agent сценариев (SLO: `<=60s`)

### 3.6 Безопасность MCP и agent tool protocol

**Риски:**
- недоверенные MCP/tool servers попадают в agent runtime
- отравление tool manifest или незаметное расширение tool scopes
- shadow tools, context over-sharing и утечка токенов в protocol logs

**Покрытие OWASP LLM Top 10:**
- `LLM06: Excessive Agency`
- `LLM02: Sensitive Information Disclosure`
- `LLM03: Supply Chain`

**Практические контроли:**
- `High-impact/regulated`: утвержденный registry для MCP servers и agent tools с owner, environment, allowed clients и review expiry
- `Baseline`: deny-by-default tool discovery; agents могут использовать только зарегистрированные tools из утвержденных transports и trust boundaries
- `High-impact/regulated`: signed или version-pinned tool manifests с ревью изменений descriptions, input schemas, scopes и outbound destinations
- `Baseline`: явная user/workload authorization для каждого tool call, а не только при создании начальной agent session
- `Baseline`: per-tool scopes и short-lived credentials; не переиспользуйте broad user или platform tokens между unrelated tools
- `Baseline`: не хранить secrets в prompts, tool descriptions, context payloads, MCP traffic logs или protocol traces
- `High-impact/regulated`: detection для unknown MCP servers, новых tool manifests, abnormal tool-chain depth и необычного cross-tool data movement

Предположение:
- MCP-specific controls являются локальными policy recommendations для agentic systems. Они становятся release blockers, когда production agents могут обнаруживать или вызывать внешние tools, tool calls меняют business state или tool traffic может переносить sensitive data.

**Сигналы проверки:**
- покрытие inventory для MCP servers и registered tools
- доля tool calls, проверенных policy до execution
- alerts по unknown tools, manifest drift и сбоям protocol-log redaction

### 3.7 Инфраструктура и безопасность runtime

**Риски:**
- компрометация inference/training окружений
- lateral movement внутри платформы
- неконтролируемый egress

**Покрытие OWASP LLM Top 10:**
- `LLM10: Unbounded Consumption`
- `LLM03: Supply Chain`

**Практические контроли:**
- `Baseline`: харденинг контейнеров/нод (seccomp, runtime policies)
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

**Покрытие OWASP LLM Top 10:**
- `LLM05: Improper Output Handling`
- `LLM01: Prompt Injection` (в LLM-mediated flows)

**Практические контроли:**
- `Baseline`: secure coding baseline для web/API code плюс AI-specific checks
- `Baseline`: parameterized queries + output encoding by context
- `Baseline`: CSP/HTML sanitization для LLM content
- `High-impact/regulated`: SAST/DAST/IAST профили для AI endpoints
- `Recommended maturity`: security contract tests между AI gateway и downstream APIs

**Сигналы проверки:**
- число high findings до релиза
- покрытие AI endpoints в автоматизированных security тестах

### 3.9 Мониторинг, обнаружение и реагирование на инциденты

**Риски:**
- позднее обнаружение abuse/prompt attacks/data leakage
- отсутствие плейбуков для AI-специфичных инцидентов

**Покрытие OWASP LLM Top 10:**
- кросс-функциональное покрытие `LLM01`–`LLM10` через detection и response

**Практические контроли:**
- `Baseline`: аудит-трейл для prompts, retrieval, tool calls, policy decisions с data minimization на уровне полей
- `Baseline`: маскирование/редакция секретов и ПДн в логах до записи
- `Baseline`: логирование raw prompt/context/tool payload должно быть отключено по умолчанию; для штатной эксплуатации используйте redacted/minimized logs
- `Baseline`: ограничивайте raw payload capture только scoped forensic mode с approval, break-glass доступом, case ID, шифрованием, retention `<=30 days`, подтверждением удаления и DLP/redaction там, где это возможно
- `Baseline`: detection rules для injection, privilege misuse, data exfil
- `High-impact/regulated`: AI incident runbooks (containment, rollback, customer comms)
- `High-impact/regulated`: tabletop exercises по realistic AI attack paths
- `Recommended maturity`: continuous purple teaming

**Сигналы проверки:**
- MTTD/MTTR для AI security events
- процент инцидентов с корректно отработанным runbook
- доля raw payload логов, удаленных в срок по retention policy

### 3.10 Управление, риск и соответствие требованиям

**Риски:**
- неконтролируемый rollout AI-фич
- несоответствие внутренним политикам и регуляторным требованиям

**Покрытие OWASP LLM Top 10:**
- кросс-функциональное покрытие `LLM01`–`LLM10` через release gates и risk ownership

**Практические контроли:**
- `Baseline`: AI risk register с owner и remediation due dates
- `Baseline`: релизная проверка по критериям безопасности, приватности и соответствия требованиям
- `High-impact/regulated`: model cards + system cards для high-risk use-cases
- `High-impact/regulated`: third-party risk assessment для AI vendors
- `Recommended maturity`: quarterly control effectiveness review

**Сигналы проверки:**
- доля релизов, прошедших AI risk gate без exception
- количество просроченных remediation action items

### 3.11 Safety и устойчивость к злоупотреблениям

**Риски:**
- вредный вывод, misuse, abuse бизнес-логики
- в antifraud-сценариях: adversarial adaptation и обход детекторов

**Покрытие OWASP LLM Top 10:**
- `LLM09: Misinformation`
- `LLM10: Unbounded Consumption` (abuse/automation loops)
- `LLM04: Data and Model Poisoning` (для model manipulation)

**Практические контроли:**
- `Baseline`: policy filters для harmful/disallowed intents
- `Baseline`: safeguarded fallback на deterministic бизнес-логику
- `High-impact/regulated`: abuse monitoring по user/device/session behavior
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
- ML/AI Engineering: жизненный цикл модели и технические контроли
- Platform/SRE: runtime hardening, observability, готовность к IR
- Legal/Privacy: условия использования данных и контроли приватности

### 4.2 Артефакты, обязательные к релизу

- threat model для AI-функции
- policy matrix (`who/what/can-do`)
- поток данных + классификация данных
- model/supply chain provenance package
- test evidence (security + abuse + resilience)

### 4.3 LLMSecOps lifecycle gates

**Scope & Plan:**
- `Baseline`: определить бизнес-сценарий, классы данных, группы пользователей, границы доверия и недопустимые действия до выбора модели или vendor
- `Baseline`: провести third-party risk assessment для model/provider/tooling с учетом data usage, retention, training opt-out, residency и incident notification
- `High-impact/regulated`: зафиксировать обоснование выбора модели, пригодность для задачи и fallback strategy для отказа от LLM там, где deterministic logic безопаснее

**Augment, fine-tune, data:**
- `Baseline`: проверять источники training/fine-tuning/RAG данных на право использования, актуальность, malware/content risk и tenant boundary
- `Baseline`: защищать data pipeline и vector database как production data store: authz на документном уровне, audit trail, encryption, backup/restore и процесс удаления
- `High-impact/regulated`: вести версионирование datasets, embeddings, prompt templates и retrieval policies, чтобы incident response мог откатить не только код, но и контекст

**Develop & experiment:**
- `Baseline`: применять secure coding baseline к AI gateway, tool adapters, prompt orchestration и downstream integrations, а не только к web/API оболочке
- `Baseline`: регистрировать MCP/tool servers до использования; unregistered local, shadow или developer-only tools не должны быть reachable из production agents
- `High-impact/regulated`: вести tracking экспериментов с моделью, параметрами, версией prompt, snapshot датасета, версией evaluator и security findings
- `High-impact/regulated`: ограничивать developer sandbox от production data и production tools; любые исключения оформлять как временный break-glass доступ

**Test & evaluate:**
- `Baseline`: включить adversarial testing, prompt-injection tests, authorization tests для tools/RAG и output-handling tests в релизные подтверждения
- `High-impact/regulated`: проводить incident simulation и response testing для сценариев data leakage, runaway agent, compromised model artifact и poisoned RAG source
- `Recommended maturity`: вести benchmark не только по quality/latency/cost, но и по refusal behavior, jailbreak resistance, data leakage rate и policy false positives

**Release:**
- `High-impact/regulated`: выпускать AI-BOM/SBOM для model artifacts, datasets where applicable, prompt/runtime components, dependencies и external services
- `Baseline`: подписывать и проверять model/dataset artifacts; promotion в production разрешать только из trusted registry
- `High-impact/regulated`: выполнять model security posture evaluation перед production promotion и при значимой смене модели/provider

**Deploy:**
- `Baseline`: валидировать runtime configuration, secrets, network egress, API exposure, tenant isolation и user/machine access перед включением production-трафика
- `Baseline`: проверять signatures/provenance артефактов моделей и датасетов во время развертывания, а не только в CI
- `Baseline`: проверять identity, version, transport, scopes и outbound destinations MCP/tool manifest до включения agent access
- `High-impact/regulated`: включать fallback, rollback и kill switch до запуска autonomous или high-impact tool flows

**Operate:**
- `Baseline`: держать runtime guardrails, rate limits, budget limits, output validation и tool policy enforcement включенными постоянно, включая degraded mode
- `High-impact/regulated`: использовать alerts по patch/update для model providers, AI frameworks, vector databases, model serving и orchestration components
- `High-impact/regulated`: регулярно пересматривать risk scoring для действий агента на основании реальных denied events и выводов из инцидентов

**Monitor:**
- `Baseline`: собирать security metrics по adversarial input, tool denial, policy bypass attempts, data leakage signals, аномалиям в agent chains и model behavior drift
- `Baseline`: alerting на unknown MCP servers, tool manifest drift, abnormal tool chains и token/secret patterns в protocol logs
- `High-impact/regulated`: иметь alert routing в Security/SRE/Product с severity, owner и runbook; AI alerts без owner быстро превращаются в noise
- `Recommended maturity`: отслеживать ethical/compliance signals там, где они являются production risk: bias, unfair denial, regulated advice, unsafe recommendations

**Govern:**
- `Baseline`: проводить user/machine access audits для AI tools, model registries, prompt repositories, vector stores и provider consoles
- `Baseline`: хранить audit evidence по model decisions, dataset versions, prompt/system changes, exceptions и incident governance
- `High-impact/regulated`: пересматривать AI risk register минимум ежеквартально и при major model/provider change
