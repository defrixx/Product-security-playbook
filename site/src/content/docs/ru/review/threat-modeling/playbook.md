---
title: "Плейбук по моделированию угроз"
description: "Моделирование угроз нужно, чтобы заранее понять, как система может быть атакована, какие активы и бизнес-операции пострадают, какие меры контроля уже снижают риск, где есть разр..."
sidebar:
  order: 20
---
## 1. Область, цель и результат

Моделирование угроз нужно, чтобы заранее понять, как система может быть атакована, какие активы и бизнес-операции пострадают, какие меры контроля уже снижают риск, где есть разрывы и какие решения нужно принять до релиза.

Используйте этот плейбук для:
- проектирования новых систем и крупных архитектурных изменений;
- ревью internet-facing сервисов, identity-flow, payment-flow, AI/ML-функций, цепочки поставки и платформенных компонентов;
- подготовки security-замечаний, плана тестирования, компенсирующих мер и принятого риска.

Минимальный результат упражнения по моделированию угроз:
- модель системы: компоненты, данные, потоки, границы доверия, внешние зависимости;
- список реалистичных сценариев атак и злоупотребления;
- привязка сценариев к активам, уязвимостям, слабостям и контролям;
- оценка риска с явным impact/likelihood и остаточным риском;
- план действий: mitigation, validation, владелец, срок и релизное решение.

Моделирование угроз должно выполняться итеративно: ранний эскиз на стадии дизайна, уточнение перед реализацией, проверка перед релизом и обновление после значимых изменений, инцидентов или появления новых данных threat intelligence.

---

## 2. Входные и выходные артефакты

### Входные артефакты

Обязательные входы:
- краткое описание системы, бизнес-цели и критичных user journeys;
- архитектурная диаграмма или C4/DFD с границами доверия;
- описание данных: классы данных, места хранения, передачи и обработки;
- список external dependencies: IdP, платежные провайдеры, SaaS, third-party API, package registries, CI/CD, cloud services;
- список точек входа и привилегированных операций;
- authentication/authorization/session model;
- актуальные меры безопасности: WAF/API gateway, mTLS, OAuth/OIDC, rate limiting, secrets management, audit logging, обнаружение, runtime policy;
- результаты SAST/DAST/SCA/IaC/container scans, pentest, incident history и данные из [плейбука управления уязвимостями](/Product-security-playbook/ru/review/vulnerability-management/playbook/);
- regulatory/compliance constraints, если они влияют на требования;
- владельцы компонентов и допустимый risk appetite.

Желательные входы:
- sequence diagrams для критичных операций;
- threat intelligence по индустрии, продукту, стеку и похожим инцидентам;
- реестр crown jewels и business impact analysis;
- access-control matrix или policy model;
- текущие runbooks detection/response;
- known abuse patterns из support, fraud, SOC и incident response.

### Выходные артефакты

Минимальные выходы:
- Область threat model: что включено, что исключено, какие assumptions приняты;
- DFD/C4/architecture rendering с границами доверия, хранилищами данных, external entities и меры безопасности;
- Таблица сценариев угроз;
- Путь атаки или attack tree для рисков `High`/`Critical`;
- Реестр рисков с inherent risk, существующие меры контроля, residual risk и решением;
- Backlog mitigation с владельцем, сроком и методом проверки;
- План тестирования: negative tests, abuse-case tests, control validation, проверки logging/detection;
- Decision log: принятые риски, исключения, tradeoffs.

Пример минимальной строки risk register:

| ID | Сценарий | Актив | Существующие меры контроля | Residual risk | Решение | Проверка |
|---|---|---|---|---|---|---|
| TM-001 | Атакующий повторно использует украденный refresh token на token endpoint BFF | Пользовательская сессия, API access | HttpOnly cookie, refresh rotation | Medium | Добавить reuse detection и отзыв token family | Integration test + проверка audit event |

---

## 3. Практический workflow

Выбирайте методологию только после того, как понятны обязательные выходные артефакты. Ревью полезно, когда оно дает сценарии атак, подтверждения по контролям, остаточный риск и релизное решение; методология — это способ прийти к этим артефактам, а не самостоятельный результат.

### 3.1 Упрощенный путь

Упрощенный путь допустим только если одновременно верно:
- нет новых границ доверия;
- нет новых внешних интеграций;
- нет изменений authN/authZ/session/cryptography;
- нет новых sensitive data или regulated flows;
- нет новых internet-facing точек входа;
- ожидаемое влияние не выше `Medium`.

Минимальный упрощенный процесс:
1. Обновить DFD или текстовое описание потока данных.
2. Пройти STRIDE-LM по измененным компонентам/потокам.
3. Добавить минимум один abuse case на каждую новую точку входа.
4. Проверить меры контроля по релевантному плейбуку, стандарту или vendor guidance.
5. Зафиксировать остаточный риск и проверку.

Эскалация на полный путь обязательна, если найден потенциальный `High|Critical`, появилась новая граница доверия, есть privacy/safety/payment impact или команда не может доказать эффективность контроля.

### 3.2 Рекомендуемый путь

Рекомендуемый путь ниже - локальный workflow этого репозитория, а не отдельная внешняя методология. Он опирается на четыре вопроса Threat Modeling Manifesto, DFD/C4, STRIDE-LM, abuse cases, OWASP/Microsoft практику, domain-specific attack libraries, проверку мер контроля и релизное решение. PASTA, LINDDUN и NIST SP 800-154 используйте как overlays только там, где контекст действительно требует дополнительной глубины.

Используйте этот путь по умолчанию для:
- новых сервисов и крупных изменений функций;
- изменений authN/authZ/session/token flows;
- новых внешних интеграций и inbound webhooks;
- обработки `Confidential`, `Secret`, PII, платежных, медицинских или regulated данных;
- изменений CI/CD, artifact provenance, развертывания, платформы и Kubernetes control plane;
- AI/agentic workflows, где важны утечки данных, prompt injection, tool abuse и autonomous actions.

Триггеры эскалации для AI и MCP:
- добавление или изменение MCP server, tool, resource, reusable prompt, gateway policy, transport, OAuth scope или authorization flow;
- включение local `stdio` tools, remote Streamable HTTP MCP, third-party MCP servers, browser tools, URL fetchers, email/file integrations, code interpreters или shell execution;
- появление agent memory, long-running autonomous workflows, checkpoints, multi-agent delegation или shared tool access;
- расширение retrieval sources, vector-store scope, resource URI patterns, tool schemas, outbound destinations или agent autonomy level;
- изменение поведения модели, поставщика или среды выполнения, если logs, retention, memory isolation, tool access или emergency disablement отличаются от утвержденного дизайна.

Шаги рекомендуемого пути:

1. Инвентаризация и диаграмма.
- Соберите компоненты, данные, точки входа, зависимости, границы доверия, владельцев.
- Артефакт: DFD/C4 + component inventory.
- Пример: для BFF/API/DB/IdP/queue/webhook gateway фиксируются протоколы, метод аутентификации, классы данных и окружения.

2. Цели безопасности и приватности.
- Определите CIA, privacy goals, compliance constraints и abuse-sensitive operations.
- Артефакт: требования безопасности и критерии риска.
- Пример: payment capture требует integrity и non-repudiation; profile export требует confidentiality и privacy transparency.

3. Генерация угроз.
- Пройдитесь по STRIDE-LM, abuse cases, OWASP Top 10/API, CAPEC, ATT&CK, domain-specific libraries и релевантным overlays из раздела 4.4.
- Артефакт: таблица threat scenarios.
- Пример: для webhook добавляются spoofing, replay, idempotency bypass, event-order tampering, fraud abuse.

4. Моделирование сценариев атаки.
- Для top scenarios опишите путь атаки, предусловия, exploited weakness, affected asset, меры контроля и gaps.
- Артефакт: attack tree/path для каждого `High`/`Critical`.
- Пример: replay webhook -> повторный capture -> ledger inconsistency -> refund abuse.

5. Привязка мер контроля.
- Сопоставьте шаги атаки с превентивными мерами, мерами обнаружения и реагирования.
- Используйте релевантные плейбуки репозитория, MASVS, Kubernetes/NIST/CIS/CNCF guidance, D3FEND, vendor docs.
- Артефакт: control coverage matrix.
- Пример: signature verification предотвращает spoofing, idempotency/state machine снижает replay, alert на duplicate event обнаруживает abuse.

6. Анализ риска.
- Рассчитайте inherent и residual risk. Для CVE добавьте CVSS v4.0, EPSS, KEV и SSVC decision.
- Артефакт: risk register.
- Пример: inherent risk `High`, residual risk `Medium` после timestamp window `<=5m`, idempotency и state guard; релиз разрешен только при наличии detection и rollback runbook.

7. Проверка и релизный gate.
- Привяжите каждую меру снижения риска к тесту или другому подтверждению.
- Артефакт: test plan, замечания, release verdict.
- Пример: automated test отклоняет stale webhook, duplicate event, invalid signature и out-of-order transition; audit event виден в SIEM.

Для Agentic AI и MCP release gate должен включать negative tests для prompt injection into tool use, retrieval или memory poisoning, unauthorized tool invocation, capability drift, wrong-audience/wrong-scope tokens, sandbox egress и kill-switch execution.

### 3.3 Единый пример: PSP webhook attack modeling

Область:
- `payment-bff`, `checkout-api`, `webhook-gateway`, PSP, `payments-db`, internal ledger topic.
- Критичные активы: payment state, authorization/capture decision, customer PII, merchant balance.
- Границы доверия: public internet to webhook gateway, gateway to internal API, API to database/topic.

Сценарий:
- Атакующий повторно отправляет валидный PSP webhook, чтобы вызвать duplicate capture или неконсистентное payment state.

Путь атаки:
1. Атакующий получает старый webhook payload и подпись из утекших логов, скомпрометированного observability-доступа или partner-side exposure.
2. Атакующий отправляет старый payload на `/webhooks/psp`.
3. Gateway принимает timestamp skew больше операционной необходимости.
4. Checkout API считает событие новым, потому что idempotency key отсутствует или неправильно scoped.
5. Payment state переходит из `authorized` в `captured` дважды, либо ledger выпускает duplicate credit event.

Анализ риска:
- Влияние: `High`, потому что могут пострадать payment integrity и merchant/customer balance.
- Вероятность: `Medium`, потому что valid payload может утечь через logs/support tooling, но signature material не генерируется тривиально.
- Изначальный риск: `High`.
- Существующие меры контроля: TLS, IP allowlist, HMAC signature validation.
- Разрывы: нет strict timestamp window, слабая idempotency, недостаточный state transition guard, нет alert на duplicate event.
- Целевой остаточный риск: `Low|Medium`, в зависимости от fraud exposure.

Рекомендуемые меры контроля:
- HMAC signature validation с точной canonicalization и key rotation.
- Timestamp freshness window `<=5m`; отклонять future timestamps за пределами clock skew `<=60s`.
- Single-use event id, scoped на PSP account + environment + event type.
- State machine guard: `capture` только из `authorized`, никогда из terminal states.
- Хранить raw event hash и normalized event id для обнаружения replay.
- Audit event для accepted/rejected webhook с reason code и correlation_id.
- Alert на duplicate event id, всплески invalid signature и попытки out-of-order transition.
- Негативные тесты для stale timestamp, duplicate event, modified amount, wrong merchant id, invalid signature и out-of-order events.

Релизный gate:
- `Rejected`, если duplicate capture возможен.
- `Approved with risks` только если duplicate capture заблокирован, но alert/runbook неполный, с владельцем и сроком.
- `Approved`, когда меры контроля и тесты доказывают, что replay не может изменить финансовое состояние, и есть обнаружение попытки replay.

---

## 4. Справочник методологий

### 4.1 Microsoft Threat Modeling

Суть:
- Define security requirements.
- Diagram the application.
- Identify threats.
- Mitigate threats.
- Проверьте меры снижения риска.

Когда применять:
- быстрый и понятный базовый процесс для SDLC;
- команды уже используют Microsoft Threat Modeling Tool;
- нужен общий язык для DFD, trust boundaries и STRIDE.

Сильные стороны:
- простая последовательность;
- хорошо ложится в инженерный процесс;
- понятные артефакты для архитектурного ревью.

Ограничения:
- STRIDE не является полной методологией и может давать поверхностные сценарии;
- без attack libraries и risk analysis результат часто превращается в generic checklist.

Пример использования:
- Для нового сервиса загрузки файлов команда строит DFD: browser, upload API, object storage, malware scanner, metadata DB. STRIDE выявляет tampering файла, information disclosure через public bucket, DoS через большие загрузки и EoP через service role. Для каждого сценария добавляются меры контроля и тесты.

### 4.2 STRIDE и STRIDE-LM

STRIDE - это таксономия угроз, а не полноценная методология.

Категории:
- Spoofing -> authenticity;
- Tampering -> integrity;
- Repudiation -> non-repudiation/accountability;
- Information Disclosure -> confidentiality;
- Denial of Service -> availability;
- Elevation of Privilege -> authorization;
- Lateral Movement в STRIDE-LM -> segmentation/least privilege.

Когда применять:
- как быстрый проход по DFD elements;
- как облегченный вариант для low-risk изменений;
- как стартовый вариант для команд, которые только внедряют моделирование угроз.

Ограничения:
- плохо раскрывает business logic abuse, fraud, privacy и supply chain без дополнительных техник;
- не дает risk scoring и control validation.

Пример использования:
- Для эндпоинта `POST /admin/users/{id}/role` STRIDE подсказывает подмену идентичности администратора, несанкционированное изменение роли, невозможность установить автора изменения, раскрытие списка ролей, DoS массовыми запросами и повышение привилегий через отсутствующую проверку авторизации.

### 4.3 OWASP Threat Modeling Process

OWASP TMP предлагает структурированный application threat modeling:
- scope/decompose the application;
- determine threats;
- определить контрмеры и способы снижения риска;
- assess the work.

Когда применять:
- web/API applications;
- команды используют OWASP Top 10, API Security Top 10 и web/API playbooks из репозитория;
- нужен практичный middle ground между STRIDE и тяжелыми risk-centric подходами.

Сильные стороны:
- понятные input artifacts: entry points, exit points, assets, trust levels, DFD;
- хорошо связывается с checklist мер контроля web/API и подтверждениями тестирования;
- подходит для проверки безопасности приложений.

Ограничения:
- риск generic output, если ограничиться Top 10;
- DREAD, который часто упоминается рядом с OWASP TMP, устарел и субъективен.

Пример использования:
- Для GraphQL API команда фиксирует entry points (`/graphql`, admin console), assets (PII, billing data), trust levels (anonymous, user, admin), генерирует threats: утечки через introspection, batching DoS, IDOR, overbroad resolver authorization, затем мапит меры контроля API и tests.

### 4.4 Overlays для специальных контекстов

Используйте эти overlays поверх рекомендуемого пути из раздела 3.2. Они не заменяют базовую модель системы, сценарии атак, mapping мер контроля и проверку перед релизом.

#### PASTA для high-risk/payment/identity/regulated

PASTA (Process for Attack Simulation and Threat Analysis) - risk-centric и threat-focused методология из семи стадий:
1. Define Objectives.
2. Define Technical Scope.
3. Application Decomposition.
4. Threat Analysis.
5. Vulnerability and Weakness Analysis.
6. Attack Modeling.
7. Risk and Impact Analysis.

Когда применять:
- high-risk системы, платежи, identity, regulated workloads;
- нужно связать бизнес-влияние, CTI, данные об уязвимостях и пути атаки;
- нужен серьезный реестр рисков для decision makers.

Сильные стороны:
- хорошая связка business objectives -> attack scenarios -> risk treatment;
- поддерживает CTI, каталоги уязвимостей и attack trees;
- заставляет думать о likelihood и impact на основе подтверждений.

Ограничения:
- высокий LoE при полном исполнении;
- требует фасилитации и зрелых входных данных.

Пример использования:
- Для internet banking transfer flow PASTA начинается с бизнес-цели "prevent unauthorized transfer", затем декомпозирует mobile app, API, risk engine, core banking, добавляет CTI по захвату учетной записи и malware, строит attack tree для session hijack + mule transfer, оценивает риск fraud loss и выбирает step-up auth, transaction signing и velocity rules.

#### LINDDUN для privacy/data/AI/telemetry

LINDDUN - privacy threat modeling framework:
- model the system;
- elicit privacy threats;
- manage threats.

Категории:
- Linkability;
- Identifiability;
- Non-repudiation;
- Detectability;
- Disclosure of information;
- Unawareness;
- Non-compliance.

Когда применять:
- PII, telemetry, analytics, AI datasets, user tracking, consent и retention;
- privacy-by-design ревью;
- продукты с GDPR/CCPA/HIPAA-like obligations.

Сильные стороны:
- закрывает blind spots, которые STRIDE обычно пропускает;
- предоставляет privacy threat trees и mitigation strategies;
- хорошо работает вместе с DFD.

Ограничения:
- не заменяет security threat modeling;
- модель оценки риска нужно выбирать отдельно.

Пример использования:
- Для mobile analytics SDK LINDDUN выявляет linkability device_id с email, detectability наличия medical condition по API calls, unawareness из-за неполного consent text и non-compliance из-за indefinite retention.

#### NIST SP 800-154 для проверок, ориентированных на данные

NIST SP 800-154 описывает data-centric threat modeling как форму risk assessment, сфокусированную на защите конкретных данных в системе. На 17 июня 2026 года публикация все еще обозначена NIST как initial public draft, но NIST указывает план финализировать ее.

Шаги:
1. Identify and characterize the system and data of interest.
2. Identify and select attack vectors.
3. Охарактеризуйте меры снижения рисков для каждого вектора атаки.
4. Analyze the threat model.

Когда применять:
- главный риск связан с данными: PII, secrets, financial records, training data, telemetry;
- нужно понять, где данные хранятся, передаются, обрабатываются, выводятся;
- нужен контроль negative implications: cost, usability, performance, operational burden.

Сильные стороны:
- заставляет отслеживать data lifecycle;
- хорошо дополняет DFD и privacy ревью;
- учитывает feasibility и побочные эффекты меры контроля.

Ограничения:
- не покрывает все system-level атаки;
- финальная risk-analysis часть менее практична, чем у PASTA/FAIR/OWASP.

Пример использования:
- Для secrets scanning platform моделируются secret values как data of interest: source repositories, CI logs, alert DB, ticket exports. Attack vectors включают unauthorized analyst access, log disclosure, webhook exfiltration. Controls: field-level encryption, token redaction, RBAC, retention limits.

### 4.5 Domain-specific и будущие подходы

Дополнительные подходы и библиотеки полезны как domain overlays:
- MAESTRO: layer-based threat library для agentic AI; лучше рассматривать как attack/control library, а не полную методологию.
- EMB3D: threat model для embedded devices.
- MITRE medical device playbook: практический набор принципов для safety-critical medical devices.

Пример использования:
- Для agentic AI workflow основной процесс остается recommended path, но threat generation дополняется OWASP LLM Top 10, MITRE ATLAS и MAESTRO для сценариев prompt injection, tool misuse, memory poisoning и agent privilege abuse.

---

## 5. Вспомогательные ресурсы

### 5.1 Фреймворки мер контроля

Фреймворки мер контроля дают требования, safeguards и countermeasures. Используйте их после генерации сценариев, а не вместо нее.

Рекомендуемый baseline:
- OWASP MASVS для mobile;
- OWASP API Security Top 10 для API abuse classes;
- NIST SSDF SP 800-218 для меры безопасного SDLC;
- NIST CSF 2.0 для enterprise cybersecurity risk management;
- NIST SP 800-53 Rev. 5 для меры контроля уровня организации и системы;
- CIS Benchmarks для усиления защиты;
- CNCF/Kubernetes guidance для cloud-native workloads;
- MITRE D3FEND для defensive technique vocabulary;
- LINDDUN mitigation strategies для меры защиты приватности;
- vendor docs для меры контроля конкретной технологии.

Пример использования:
- Threat scenario "attacker steals access token from SPA localStorage" мапится на OAuth BCP/меры контроля OIDC, BFF pattern из identity playbook, web/API playbooks и D3FEND defensive techniques around credential protection/detection.

### 5.2 Библиотеки атак

Библиотеки атак помогают не изобретать attack patterns заново.

Используйте:
- MITRE ATT&CK для тактик, техник и процедур, применяемых реальными субъектами угроз;
- MITRE CAPEC для software attack patterns;
- OWASP Top 10, API Security Top 10, LLM Top 10 для domain-specific application risks;
- MITRE ATLAS для AI-enabled systems;
- OSC&R для сценариев атак на цепочку поставки ПО;
- cloud/provider threat libraries для AWS/Azure/GCP-specific paths;
- MAESTRO/PLOT4AI для AI/privacy overlays;

Пример использования:
- Для CI/CD threat model команда берет OSC&R для dependency confusion и malicious build script, ATT&CK для credential access/lateral movement, CAPEC для command injection и OWASP Top 10 для insecure design.

### 5.3 Каталоги уязвимостей

Каталоги уязвимостей нужны для связи threat model с реальными weaknesses и эксплуатируемыми уязвимостями.

Используйте:
- CVE/MITRE для идентификаторов публичных уязвимостей;
- NVD/NIST для enrichment, CVSS и SCAP data;
- CWE/MITRE для weakness classes и root cause mapping;
- CISA KEV для уязвимостей, эксплуатируемых in the wild;
- OSV для уязвимостей open source dependencies;
- GitHub Advisory Database, Go Vulnerability Database, RustSec, Snyk DB как ecosystem-specific sources;
- базы уязвимостей cloud providers для cloud provider/service issues.

Пример использования:
- Attack path "RCE in exposed file converter" получает CWE mapping (deserialization или command injection), CVE if known, CVSS v4.0 technical severity, EPSS likelihood, KEV status и asset criticality. Risk decision строится не только на CVSS.

### 5.4 Модели оценки риска

Risk models помогают приоритизировать устранение проблем. Не смешивайте technical severity, exploitation likelihood и business impact в один непрозрачный балл.

Практичный набор:
- OWASP Risk Rating: простая application-level матрица likelihood x impact;
- NIST SP 800-30: formal risk assessment context;
- CVSS v4.0: техническая серьезность уязвимости, не business risk;
- EPSS: вероятность эксплуатации CVE in the wild;
- CISA KEV: факт known exploitation;
- SSVC: decision-oriented приоритизация уязвимостей;
- FAIR: количественная финансовая оценка риска для зрелых организаций;
- DREAD: исторически известен, но не рекомендуется как основной scoring из-за субъективности и слабой воспроизводимости.

Пример использования:
- CVE с CVSS 9.8 на non-internet-facing dev tool может иметь lower release risk, чем CVSS 7.5 в internet-facing auth proxy с KEV и высоким EPSS. Решение должно учитывать exposure, asset criticality, exploit activity и компенсирующие меры.

### 5.5 CTI

Threat intelligence повышает реалистичность сценариев. Минимально учитывайте:
- intent: зачем actor атакует систему;
- opportunity: доступная attack surface и уязвимости;
- capability: tooling, infrastructure, TTPs, exploit maturity.

Данные для анализа:
- internal incidents, SOC alerts, fraud/support cases;
- CISA, vendor advisories, cloud provider advisories;
- MITRE ATT&CK groups/software/campaign mappings;
- ISAC/industry reports, DBIR-like reports;
- MISP/OpenCTI, если есть зрелый CTI process.

Пример использования:
- После серии credential stuffing incidents в индустрии likelihood для сценариев захвата учетной записи повышается, а меры контроля включают bot detection, breached password checks, MFA step-up и alert на impossible travel/session anomalies.

---

## 6. Матрица выбора

| Подход | Лучший контекст | Не использовать как | Пример |
|---|---|---|---|
| STRIDE-LM | быстрый проход по DFD | полноценную методологию оценки риска | ревью отдельного endpoint |
| Microsoft TM | базовый SDLC-процесс | глубокую симуляцию атаки | новый web service |
| OWASP TMP | web/API appsec ревью | enterprise risk program | GraphQL/API ревью |
| PASTA | системы высокого риска, где решения опираются на подтверждения | легкий checklist | banking/payment flow |
| LINDDUN | privacy/data processing | замену security threat modeling | analytics SDK |
| NIST 800-154 | data-centric systems | full system TM | secrets/PII data lifecycle |
---

## 7. Связанные материалы

- [Чеклист ревью архитектуры безопасности](/Product-security-playbook/ru/review/architecture/checklist/)
- [Плейбук безопасности API](/Product-security-playbook/ru/application-security/api/api-security-patterns/playbook/)
- [Обзор OWASP LLM Top 10](/Product-security-playbook/ru/ai-security/owasp-llm-top-10/overview/)
- [Обзор безопасности AI](/Product-security-playbook/ru/ai-security/securing-ai/overview/)
- [Плейбук безопасности Agentic AI](/Product-security-playbook/ru/ai-security/agentic-ai/playbook/)
- [Плейбук безопасности MCP](/Product-security-playbook/ru/ai-security/mcp-security/playbook/)
