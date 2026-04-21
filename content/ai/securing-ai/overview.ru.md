# Securing AI: Обзор

## 1. Область и цель

Этот обзор направлен на обеспечение безопасности production-систем:
- AI/LLM assistant и agentic workflows
- RAG и knowledge retrieval
- модели для принятия решений (включая antifraud/scoring)
- MLOps/LLMOps и интеграции с бизнес-системами

Цель:
- покрыть все ключевые аспекты безопасности, начиная с `Zero Trust`
- для каждого аспекта дать практические, проверяемые контроли

---

## 2. Базовые принципы (foundation)

### 2.1 Zero Trust для AI

**Фокус:**
- не доверять ни одному входу, выходу, интеграции, модели и источнику данных по умолчанию

**Практические контроли:**
- `Critical`: явные trust boundaries для потоков `user -> model -> tool -> downstream`
- `Critical`: `deny-by-default` для tool execution и data access
- `Critical`: непрерывная проверка контекста пользователя (не только на входе сессии)
- `High`: policy-as-code для authz и data policies
- `Recommended`: регулярный threat modeling по изменениям агентных сценариев

**Сигналы проверки:**
- процент вызовов tools, заблокированных policy engine
- покрытие сценариев trust-boundary тестами

---

## 3. Аспекты безопасности и контроли

### 3.1 Идентичности и доступ (AI IAM)

**Риски:**
- over-privileged агенты
- подмена сервисных identity
- межтенантный доступ

**Покрытие OWASP LLM Top 10:**
- `LLM06: Excessive Agency`
- `LLM02: Sensitive Information Disclosure`

**Практические контроли:**
- `Critical`: workload identity вместо статических ключей
- `Critical`: least privilege для каждого tool и API
- `Critical`: tenant-aware authorization на каждом downstream-шаге
- `High`: short-lived tokens, rotation, audience binding
- `Recommended`: SoD для high-impact операций

**Сигналы проверки:**
- доля сервисов без long-lived credentials
- число denied attempts по cross-tenant policy

### 3.2 Безопасность данных и privacy

**Риски:**
- утечка ПДн/секретов через prompt/context/output
- несанкционированное использование данных в training
- нарушение retention/regulatory требований

**Покрытие OWASP LLM Top 10:**
- `LLM02: Sensitive Information Disclosure`
- `LLM07: System Prompt Leakage`

**Практические контроли:**
- `Critical`: data classification + data handling matrix для AI use-cases
- `Critical`: DLP/redaction до модели и перед выдачей пользователю
- `Critical`: encryption in transit/at rest + tenant isolation
- `High`: строгое data minimization для inference/training
- `High`: enforceable retention/deletion controls
- `Recommended`: privacy impact assessment для новых AI-фич

**Сигналы проверки:**
- количество DLP-срабатываний на 1k запросов
- SLA на удаление данных и процент выполнений в срок

### 3.3 Безопасность моделей и supply chain

**Риски:**
- компрометированные модели/адаптеры
- уязвимые ML-зависимости
- юридические риски по лицензиям

**Покрытие OWASP LLM Top 10:**
- `LLM03: Supply Chain`
- `LLM04: Data and Model Poisoning`

**Практические контроли:**
- `Critical`: trusted registry + provenance checks (hash/signature/publisher)
- `Critical`: SBOM/AI-BOM для model artifacts и runtime
- `Critical`: CVE scanning + gating на критичных уязвимостях
- `High`: controlled promotion flow (dev -> staging -> prod) с approvals
- `High`: legal review для third-party model terms
- `Recommended`: independent red team перед production adoption

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
- `Critical`: strict context separation (trusted vs untrusted)
- `Critical`: retrieval с document-level/tenant-level authorization
- `Critical`: ingestion security pipeline (malware/content/policy checks)
- `High`: detection для jailbreak/injection паттернов
- `High`: versioning prompt templates + mandatory security review
- `Recommended`: adversarial test suite в CI/CD

**Сигналы проверки:**
- success rate инъекций в red-team тестах
- доля RAG-документов, прошедших policy scan

### 3.5 Безопасность output и действий агента

**Риски:**
- unsafe execution model output
- нежелательные транзакции и destructive actions
- цепочки эскалации через tools

**Покрытие OWASP LLM Top 10:**
- `LLM05: Improper Output Handling`
- `LLM06: Excessive Agency`

**Практические контроли:**
- `Critical`: output считать untrusted input всегда
- `Critical`: schema validation + allowlist команд/операций
- `Critical`: two-step execution для state-changing действий (`preview -> explicit confirm -> execute`)
- `Critical`: human-in-the-loop + four-eyes approval для high-impact/необратимых операций
- `High`: sandbox для code/command execution
- `High`: rate limits, loop guards, kill switch с дефолтами (`max tool-chain depth=3`, `max autonomous steps=5`, `request budget=60 req/min per user`, `token budget=20k tokens/request`)
- `Recommended`: transaction risk scoring перед выполнением

**Сигналы проверки:**
- число заблокированных рискованных action attempts
- доля запросов, заблокированных guardrail budget limits
- mean time to kill для runaway-agent сценариев (SLO: `<=60s`)

### 3.6 Инфраструктура и runtime security

**Риски:**
- компрометация inference/training окружений
- lateral movement внутри platform
- неконтролируемый egress

**Покрытие OWASP LLM Top 10:**
- `LLM10: Unbounded Consumption`
- `LLM03: Supply Chain`

**Практические контроли:**
- `Critical`: hardening контейнеров/нод (seccomp, runtime policies)
- `Critical`: сегментация сети и egress allowlisting
- `Critical`: secrets management через централизованный vault
- `High`: EDR/runtime detection для AI workloads
- `High`: immutable logs + centralized SIEM
- `Recommended`: confidential compute для чувствительных сценариев

**Сигналы проверки:**
- покрытие AI workloads runtime policies
- число egress-deny событий по AI namespace

### 3.7 AppSec для AI-приложения

**Риски:**
- классические web/API уязвимости + AI-специфичные цепочки
- небезопасный frontend rendering model output
- SSRF/XSS/SQLi через LLM-mediated paths

**Покрытие OWASP LLM Top 10:**
- `LLM05: Improper Output Handling`
- `LLM01: Prompt Injection` (в LLM-mediated flows)

**Практические контроли:**
- `Critical`: secure coding baseline (OWASP ASVS + AI-specific checks)
- `Critical`: parameterized queries + output encoding by context
- `Critical`: CSP/HTML sanitization для LLM content
- `High`: SAST/DAST/IAST профили для AI endpoints
- `Recommended`: security contract tests между AI gateway и downstream APIs

**Сигналы проверки:**
- число high findings до релиза
- покрытие AI endpoints в автоматизированных security тестах

### 3.8 Monitoring, detection и incident response

**Риски:**
- позднее обнаружение abuse/prompt attacks/data leakage
- отсутствие playbooks для AI-специфичных инцидентов

**Покрытие OWASP LLM Top 10:**
- кросс-функциональное покрытие `LLM01`–`LLM10` через detection и response

**Практические контроли:**
- `Critical`: аудит-трейл для prompts, retrieval, tool calls, policy decisions с data minimization на уровне полей
- `Critical`: маскирование/редакция секретов и ПДн в логах до записи
- `Critical`: raw payload хранить только для forensics, в зашифрованном виде, с жестким доступом и retention `<=30 days`
- `Critical`: detection rules для injection, privilege misuse, data exfil
- `High`: AI incident runbooks (containment, rollback, customer comms)
- `High`: tabletop exercises по realistic AI attack paths
- `Recommended`: continuous purple teaming

**Сигналы проверки:**
- MTTD/MTTR для AI security events
- процент инцидентов с корректно отработанным runbook
- доля raw payload логов, удаленных в срок по retention policy

### 3.9 Governance, risk и compliance

**Риски:**
- неконтролируемый rollout AI-фич
- несоответствие внутренним политикам и регуляторным требованиям

**Покрытие OWASP LLM Top 10:**
- кросс-функциональное покрытие `LLM01`–`LLM10` через release gates и risk ownership

**Практические контроли:**
- `Critical`: AI risk register с owner и remediation due dates
- `Critical`: release gate по security/privacy/compliance criteria
- `High`: model cards + system cards для high-risk use-cases
- `High`: third-party risk assessment для AI vendors
- `Recommended`: quarterly control effectiveness review

**Сигналы проверки:**
- доля релизов, прошедших AI risk gate без exception
- количество просроченных remediation action items

### 3.10 Safety и abuse-resilience

**Риски:**
- harmful output, misuse, business logic abuse
- в antifraud-сценариях: adversarial adaptation и обход детекторов

**Покрытие OWASP LLM Top 10:**
- `LLM09: Misinformation`
- `LLM10: Unbounded Consumption` (abuse/automation loops)
- `LLM04: Data and Model Poisoning` (для model manipulation)

**Практические контроли:**
- `Critical`: policy filters для harmful/disallowed intents
- `Critical`: safeguarded fallback на deterministic бизнес-логику
- `High`: abuse monitoring по user/device/session behavior
- `High`: регулярная калибровка порогов для fraud/risk моделей
- `Recommended`: attacker-in-the-loop simulations

**Сигналы проверки:**
- false negative/false positive по abuse/fraud кейсам
- drift показателей модели и время реакции на drift

---

## 4. Операционная модель внедрения

### 4.1 RACI (минимум)

- Product: владелец бизнес-риска AI-фич
- Security/AppSec: контроль security requirements и release gates
- ML/AI Engineering: model lifecycle и technical controls
- Platform/SRE: runtime hardening, observability, IR readiness
- Legal/Privacy: data usage terms и privacy controls

### 4.2 Артефакты, обязательные к релизу

- threat model для AI-фичи
- policy matrix (`who/what/can-do`)
- data flow + data classification
- model/supply chain provenance package
- test evidence (security + abuse + resilience)
