# Плейбук по моделированию угроз

## 1. Область, цель и результат

Моделирование угроз нужно, чтобы заранее понять, как система может быть атакована, какие активы и бизнес-операции пострадают, какие контроли уже снижают риск, где есть разрывы и какие решения нужно принять до релиза.

Используйте этот плейбук для:
- проектирования новых систем и крупных архитектурных изменений;
- ревью internet-facing сервисов, identity-flow, payment-flow, AI/ML-функций, цепочки поставки и платформенных компонентов;
- подготовки security findings, плана тестирования, компенсирующих контролей и принятого риска.

Минимальный результат упражнения по моделированию угроз:
- модель системы: компоненты, данные, потоки, границы доверия, внешние зависимости;
- список реалистичных сценариев атак и злоупотребления;
- привязка сценариев к активам, уязвимостям, слабостям и контролям;
- оценка риска с явным impact/likelihood и остаточным риском;
- план действий: mitigation, validation, владелец, срок и релизное решение.

Моделирование угроз должно выполняться итеративно: ранний эскиз на стадии дизайна, уточнение перед реализацией, проверка перед релизом и обновление после значимых изменений, инцидентов или появления новой threat intelligence.

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
- актуальные контроли безопасности: WAF/API gateway, mTLS, OAuth/OIDC, rate limiting, secrets management, audit logging, detection, runtime policy;
- результаты SAST/DAST/SCA/IaC/container scans, pentest, incident history и vulnerability management;
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
- DFD/C4/architecture rendering с границами доверия, хранилищами данных, external entities и security controls;
- Таблица сценариев угроз;
- Путь атаки или attack tree для рисков `High`/`Critical`;
- Реестр рисков с inherent risk, existing controls, residual risk и решением;
- Backlog mitigation с владельцем, сроком и методом проверки;
- План тестирования: negative tests, abuse-case tests, control validation, logging/detection checks;
- Decision log: принятые риски, исключения, tradeoffs.

Пример минимальной строки risk register:

| ID | Сценарий | Актив | Existing controls | Residual risk | Решение | Проверка |
|---|---|---|---|---|---|---|
| TM-001 | Атакующий повторно использует украденный refresh token на token endpoint BFF | Пользовательская сессия, API access | HttpOnly cookie, refresh rotation | Medium | Добавить reuse detection и отзыв token family | Integration test + проверка audit event |

---

## 3. Практический workflow

Выбирайте методологию только после того, как понятны обязательные выходные артефакты. Ревью полезно, когда оно дает сценарии атак, evidence по контролям, остаточный риск и релизное решение; методология — это способ прийти к этим артефактам, а не самостоятельный результат.

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
4. Проверить контроли по релевантному плейбуку, стандарту или vendor guidance.
5. Зафиксировать остаточный риск и проверку.

Эскалация на полный путь обязательна, если найден потенциальный `High|Critical`, появилась новая граница доверия, есть privacy/safety/payment impact или команда не может доказать эффективность контроля.

### 3.2 Рекомендуемый путь

Для большинства продуктовых команд оптимален гибридный процесс: легкая база из Microsoft/OWASP, threat-driven глубина из PASTA/IDDIL, privacy coverage из LINDDUN и приоритизация риска на основе OWASP/NIST/CVSS/EPSS/SSVC. STRIDE используйте как быструю таксономию, а не как самостоятельную методологию.

Используйте этот путь по умолчанию для:
- новых сервисов и крупных изменений функций;
- изменений authN/authZ/session/token flows;
- новых внешних интеграций и inbound webhooks;
- обработки `Confidential`, `Secret`, PII, платежных, медицинских или regulated данных;
- изменений CI/CD, artifact provenance, развертывания, платформы и Kubernetes control plane;
- AI/agentic workflows, где важны data leakage, prompt injection, tool abuse и autonomous actions.

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
- Пройдитесь по STRIDE-LM, LINDDUN, OWASP Top 10/API, CAPEC, ATT&CK, domain-specific libraries.
- Артефакт: таблица threat scenarios.
- Пример: для webhook добавляются spoofing, replay, idempotency bypass, event-order tampering, fraud abuse.

4. Моделирование сценариев атаки.
- Для top scenarios опишите путь атаки, предусловия, exploited weakness, affected asset, controls и gaps.
- Артефакт: attack tree/path для каждого `High`/`Critical`.
- Пример: replay webhook -> повторный capture -> ledger inconsistency -> refund abuse.

5. Привязка контролей.
- Сопоставьте шаги атаки с preventive, detective и responsive controls.
- Используйте релевантные плейбуки репозитория, MASVS, Kubernetes/NIST/CIS/CNCF guidance, D3FEND, vendor docs.
- Артефакт: control coverage matrix.
- Пример: signature verification предотвращает spoofing, idempotency/state machine снижает replay, alert на duplicate event обнаруживает abuse.

6. Анализ риска.
- Рассчитайте inherent и residual risk. Для CVE добавьте CVSS v4.0, EPSS, KEV и SSVC decision.
- Артефакт: risk register.
- Пример: inherent risk `High`, residual risk `Medium` после timestamp window `<=5m`, idempotency и state guard; релиз разрешен только при наличии detection и rollback runbook.

7. Проверка и релизный gate.
- Привяжите каждый mitigation к test/evidence.
- Артефакт: test plan, findings, release verdict.
- Пример: automated test отклоняет stale webhook, duplicate event, invalid signature и out-of-order transition; audit event виден в SIEM.

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
- Существующие контроли: TLS, IP allowlist, HMAC signature validation.
- Разрывы: нет strict timestamp window, слабая idempotency, недостаточный state transition guard, нет alert на duplicate event.
- Целевой остаточный риск: `Low|Medium`, в зависимости от fraud exposure.

Рекомендуемые контроли:
- HMAC signature validation с точной canonicalization и key rotation.
- Timestamp freshness window `<=5m`; отклонять future timestamps за пределами clock skew `<=60s`.
- Single-use event id, scoped на PSP account + environment + event type.
- State machine guard: `capture` только из `authorized`, никогда из terminal states.
- Хранить raw event hash и normalized event id для replay detection.
- Audit event для accepted/rejected webhook с reason code и correlation_id.
- Alert на duplicate event id, всплески invalid signature и попытки out-of-order transition.
- Негативные тесты для stale timestamp, duplicate event, modified amount, wrong merchant id, invalid signature и out-of-order events.

Релизный gate:
- `Rejected`, если duplicate capture возможен.
- `Approved with risks` только если duplicate capture заблокирован, но alert/runbook неполный, с владельцем и сроком.
- `Approved`, когда контроли и тесты доказывают, что replay не может изменить финансовое состояние, и есть обнаружение попытки replay.

---

## 4. Справочник методологий

### 4.1 Microsoft Threat Modeling

Суть:
- Define security requirements.
- Diagram the application.
- Identify threats.
- Mitigate threats.
- Validate mitigations.

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
- Для нового сервиса загрузки файлов команда строит DFD: browser, upload API, object storage, malware scanner, metadata DB. STRIDE выявляет tampering файла, information disclosure через public bucket, DoS через большие загрузки и EoP через service role. Для каждого сценария добавляются контроли и тесты.

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
- Для endpoint `POST /admin/users/{id}/role` STRIDE подсказывает spoofing admin identity, tampering role payload, repudiation role changes, disclosure списка ролей, DoS массовыми запросами и EoP через отсутствующую проверку авторизации.

### 4.3 PASTA

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
- поддерживает CTI, vulnerability catalogs и attack trees;
- заставляет думать о likelihood и impact на основе подтверждений.

Ограничения:
- высокий LoE при полном исполнении;
- требует фасилитации и зрелых входных данных.

Пример использования:
- Для internet banking transfer flow PASTA начинается с бизнес-цели "prevent unauthorized transfer", затем декомпозирует mobile app, API, risk engine, core banking, добавляет CTI по account takeover и malware, строит attack tree для session hijack + mule transfer, оценивает риск fraud loss и выбирает step-up auth, transaction signing и velocity rules.

### 4.4 OCTAVE, OCTAVE-S, OCTAVE Allegro

OCTAVE - organization-focused подход для идентификации и управления information security risks. Классический OCTAVE включает организационную перспективу, технологическую перспективу и стратегию защиты. OCTAVE-S упрощает процесс для малых организаций. OCTAVE Allegro сильнее фокусируется на information assets и risk measurement criteria.

Когда применять:
- нужно подняться над отдельным приложением и оценить организационные риски;
- нет зрелого реестра critical assets и risk criteria;
- требуется связать threat modeling с enterprise risk management.

Сильные стороны:
- хорошо выявляет high-priority assets и business impact categories;
- полезен для построения risk measurement criteria;
- подходит для программной, а не только продуктовой оценки.

Ограничения:
- тяжелый процесс для feature-level threat modeling;
- слабее работает без внешней threat intelligence и security expertise.

Пример использования:
- Организация выбирает три critical information assets: customer PII, signing keys, billing ledger. OCTAVE Allegro фиксирует containers: database, backups, support exports, analytics pipeline. Для каждого контейнера оцениваются disclosure/tampering risks и приоритеты защиты.

### 4.5 Trike

Trike строится вокруг формальной модели требований:
- Requirements Model: actors, assets, actions, rules через actor-asset-action matrix;
- Implementation Model: DFD, technologies, protocols, trust boundaries, controls;
- Threat Model: threats как отклонения от intended actions;
- Risk Model: количественная оценка impact и likelihood.

Когда применять:
- критична authorization correctness;
- система хорошо описывается actors/assets/actions/rules;
- нужна repeatability и формальная access-control matrix.

Сильные стороны:
- сильная defensive perspective;
- хорошо выявляет missing/incorrect authorization rules;
- дает детерминированность при качественных входах.

Ограничения:
- трудоемко для больших систем;
- tooling и экосистема менее живые, чем у более популярных подходов;
- attack trees и DFD все равно требуют ручной работы.

Пример использования:
- Для SaaS CRM строится матрица: tenant admin, support agent, end user x customer record, invoice, API token x CRUD. Любое действие за пределами матрицы становится threat. Это быстро выявляет риск support agent reading cross-tenant invoices.

### 4.6 LINDDUN

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

### 4.7 VAST

VAST (Visual, Agile, Simple Threat) фокусируется на масштабировании threat modeling через визуализацию, автоматизацию, self-service и интеграцию в Agile/DevOps. Обычно различает application threat models и operational threat models.

Когда применять:
- много команд и сервисов;
- нужна repeatable pipeline-integrated практика;
- организация готова поддерживать tool-driven threat library.

Сильные стороны:
- масштабируемость;
- понятная визуализация для разных ролей;
- хорошо подходит для continuous threat modeling.

Ограничения:
- качество сильно зависит от tooling и threat library;
- глубина анализа может снижаться, если процесс полностью self-service без security review.

Пример использования:
- Platform team добавляет template-driven threat models в onboarding сервиса: команда выбирает "public REST API + PostgreSQL + Kafka", инструмент генерирует базовые угрозы и обязательные контроли, security reviewer смотрит только отклонения и high-risk flows.

### 4.8 NIST SP 800-154 Data-Centric Threat Modeling

NIST SP 800-154 описывает data-centric threat modeling как форму risk assessment, сфокусированную на защите конкретных данных в системе. На 30 апреля 2026 года публикация все еще обозначена NIST как initial public draft, но NIST указывает план финализировать ее.

Шаги:
1. Identify and characterize the system and data of interest.
2. Identify and select attack vectors.
3. Characterize controls for mitigating attack vectors.
4. Analyze the threat model.

Когда применять:
- главный риск связан с данными: PII, secrets, financial records, training data, telemetry;
- нужно понять, где данные хранятся, передаются, обрабатываются, выводятся;
- нужен контроль negative implications: cost, usability, performance, operational burden.

Сильные стороны:
- заставляет отслеживать data lifecycle;
- хорошо дополняет DFD и privacy review;
- учитывает feasibility и побочные эффекты controls.

Ограничения:
- не покрывает все system-level атаки;
- финальная risk-analysis часть менее практична, чем у PASTA/FAIR/OWASP.

Пример использования:
- Для secrets scanning platform моделируются secret values как data of interest: source repositories, CI logs, alert DB, ticket exports. Attack vectors включают unauthorized analyst access, log disclosure, webhook exfiltration. Controls: field-level encryption, token redaction, RBAC, retention limits.

### 4.9 OWASP Threat Modeling Process

OWASP TMP предлагает структурированный application threat modeling:
- scope/decompose the application;
- determine threats;
- determine countermeasures and mitigation;
- assess the work.

Когда применять:
- web/API applications;
- команды используют OWASP Top 10, API Security Top 10 и web/API playbooks из репозитория;
- нужен практичный middle ground между STRIDE и PASTA.

Сильные стороны:
- понятные input artifacts: entry points, exit points, assets, trust levels, DFD;
- хорошо связывается с web/API control checklists и test evidence;
- подходит для application security review.

Ограничения:
- риск generic output, если ограничиться Top 10;
- DREAD, который часто упоминается рядом с OWASP TMP, устарел и субъективен.

Пример использования:
- Для GraphQL API команда фиксирует entry points (`/graphql`, admin console), assets (PII, billing data), trust levels (anonymous, user, admin), генерирует threats: introspection leakage, batching DoS, IDOR, overbroad resolver authorization, затем мапит API controls и tests.

### 4.10 TARA

В контексте обзора важно различать:
- MITRE TARA (Threat Assessment and Remediation Analysis): методика выбора countermeasures через managed attack-to-control catalog;
- Intel TARA (Threat Agent Risk Assessment): threat-agent-driven оценка риска.

MITRE TARA workflow:
- Cyber Threat Susceptibility Analysis;
- Cyber Risk Remediation Assessment;
- Knowledge Management.

Когда применять:
- mission assurance, acquisition, complex systems;
- нужен catalog-based выбор countermeasures;
- команда готова поддерживать актуальную attack/control knowledge base.

Сильные стороны:
- хорошо связывает attack vectors с controls;
- учитывает utility/cost countermeasures;
- knowledge management делает процесс адаптивным.

Ограничения:
- поддержка собственного threat-to-control catalog дорогая;
- для обычной продуктовой команды может быть тяжеловесно.

Пример использования:
- Для satellite ground segment TARA связывает attack vector "compromise command uplink workstation" с controls: privileged access workstation, command signing, network segmentation, operator dual control, anomaly detection. Затем выбирается набор controls с лучшим utility/cost.

### 4.11 IDDIL/ATC

IDDIL/ATC - threat-driven подход Lockheed Martin:
- Identify the assets;
- Define the attack surface;
- Decompose the system;
- Identify attack vectors;
- List threat actors and objectives;
- Analysis;
- Assessment and triage;
- Controls.

Когда применять:
- нужно сместить фокус с compliance checklist на реальные threats;
- важны threat actors, attack surface и control effectiveness;
- хочется получить architectural rendering с наложенными threats and controls.

Сильные стороны:
- strong threat-driven framing;
- полезные артефакты: threat profiles, functional controls hierarchy, controls scorecard, architectural rendering;
- STRIDE-LM добавляет lateral movement.

Ограничения:
- много ручных матриц и документации;
- без автоматизации может плохо масштабироваться.

Пример использования:
- Для Kubernetes platform IDDIL фиксирует assets (secrets, cluster-admin, workloads), attack surface (API server, CI deploy token, ingress), actors (external attacker, compromised developer, malicious workload), attack vectors (stolen kubeconfig, admission bypass, container escape) и мапит controls на architectural rendering.

### 4.12 hTMM

Hybrid Threat Modeling Method объединяет STRIDE, Security Cards и Persona non Grata:
- identify target system;
- brainstorm threats with Security Cards;
- filter scenarios using realistic personas;
- summarize threats with actor, purpose, target, action, result, impact, threat type;
- assess risk.

Когда применять:
- нужна фасилитируемая workshop-сессия;
- команда хочет включить developers, product, users и security;
- мало CTI, но важно расширить воображение команды.

Сильные стороны:
- помогает не-security участникам генерировать threat ideas;
- PnG делает сценарии более реалистичными;
- подходит для ранней стадии дизайна.

Ограничения:
- не требует DFD явно, поэтому модель системы может быть слабой;
- требует отдельного risk scoring и control mapping.

Пример использования:
- Для collaboration platform команда создает Persona non Grata "disgruntled contractor with workspace access" и через Security Cards генерирует сценарии: bulk export before offboarding, secret exfiltration from shared docs, reputational damage through malicious public link.

### 4.13 Security Cards

Security Cards - техника threat brainstorming, а не самостоятельная методология. Карты покрывают:
- human impact;
- adversary motivations;
- adversary resources;
- adversary methods.

Когда применять:
- early design;
- workshop с mixed audience;
- поиск нестандартных abuse cases.

Пример использования:
- На воркшопе по детскому приложению карта human impact заставляет команду рассмотреть stalking, harassment и parental consent abuse, которые не появились бы из обычного STRIDE pass.

### 4.14 Persona non Grata

Persona non Grata описывает нежелательных или злонамеренных personas как архетипы пользователей с мотивами, ресурсами и целями.

Когда применять:
- insider threat;
- fraud/abuse;
- social features и marketplaces;
- нет надежной CTI, но можно описать реалистичных actors.

Пример использования:
- Persona "merchant abusing refund workflow" помогает выявить сценарий: создать заказ, инициировать partial refund, использовать race condition в webhook status update, вывести средства до reconciliation.

### 4.15 QTMM

Quantitative Threat Modeling Methodology использует attack trees и количественную агрегацию риска. В описанном privacy-by-design варианте комбинируются DFD, STRIDE, privacy protection goals, misuse cases, quantified attack trees и security/privacy requirements.

Когда применять:
- нужно сравнивать alternative designs количественно;
- есть зрелые данные по likelihood, impact, control effectiveness;
- privacy/security risks нужно пересчитывать после controls.

Сильные стороны:
- поддерживает before/after scoring;
- attack tree помогает видеть, какой control ломает какой path;
- хорошо подходит для обоснования expensive controls.

Ограничения:
- качество результата зависит от качества численных оценок;
- DREAD как scoring model лучше заменить на более зрелую модель.

Пример использования:
- Для data sharing platform команда строит attack tree re-identification. После добавления k-anonymity, aggregation thresholds и access review пересчитывается residual risk и сравниваются два дизайна экспорта.

### 4.16 ID methodology

ID из исходного обзора - практичный гибрид:
1. Inventory System Components.
2. Diagram Architecture.
3. Identify Threats.
4. Decompose Application.
5. Illustrate Threats.
6. Document Risk.

Когда применять:
- нужен реалистичный, масштабируемый и не слишком академичный путь;
- команда хочет смешать PASTA, IDDIL/ATC, NIST data-centric, LINDDUN и VAST;
- важны архитектурные визуализации с threats and controls.

Сильные стороны:
- pragmatic mix;
- хорошая точка старта для внутреннего стандарта;
- сохраняет threat-driven фокус без полного PASTA overhead.

Ограничения:
- это не стандарт и не широко верифицированная методология;
- organization-specific tailoring обязателен.

Пример использования:
- Для нового AI assistant команда инвентаризирует tools, memory, vector DB, model gateway, строит DFD, генерирует threats через OWASP LLM Top 10 + LINDDUN, иллюстрирует prompt injection -> tool abuse attack path и документирует residual risk после tool allowlist, human approval и audit.

### 4.17 Domain-specific и будущие подходы

Дополнительные подходы и библиотеки полезны как domain overlays:
- MAESTRO: layer-based threat library для agentic AI; лучше рассматривать как attack/control library, а не полную методологию.
- EMB3D: threat model для embedded devices.
- MITRE medical device playbook: практический набор принципов для safety-critical medical devices.
- KTH TMM / PASTA+FAIR inspired approaches: полезны там, где нужна более сильная risk quantification.
- VerSprite OTM: organizational threat modeling approach с PASTA/FAIR influence.

Пример использования:
- Для agentic AI workflow основной процесс остается recommended path, но threat generation дополняется OWASP LLM Top 10, MITRE ATLAS и MAESTRO для сценариев prompt injection, tool misuse, memory poisoning и agent privilege abuse.

---

## 5. Вспомогательные ресурсы

### 5.1 Фреймворки контролей

Фреймворки контролей дают требования, safeguards и countermeasures. Используйте их после генерации сценариев, а не вместо нее.

Рекомендуемый baseline:
- OWASP MASVS для mobile;
- OWASP API Security Top 10 для API abuse classes;
- NIST SSDF SP 800-218 для secure SDLC controls;
- NIST CSF 2.0 для enterprise cybersecurity risk management;
- NIST SP 800-53 Rev. 5 для organization/system controls;
- CIS Benchmarks для hardening;
- CNCF/Kubernetes guidance для cloud-native workloads;
- MITRE D3FEND для defensive technique vocabulary;
- LINDDUN mitigation strategies для privacy controls;
- vendor docs для technology-specific controls.

Пример использования:
- Threat scenario "attacker steals access token from SPA localStorage" мапится на OAuth BCP/OIDC controls, BFF pattern из identity playbook, web/API playbooks и D3FEND defensive techniques around credential protection/detection.

### 5.2 Библиотеки атак

Библиотеки атак помогают не изобретать attack patterns заново.

Используйте:
- MITRE ATT&CK для real-world adversary tactics, techniques and procedures;
- MITRE CAPEC для software attack patterns;
- OWASP Top 10, API Security Top 10, LLM Top 10 для domain-specific application risks;
- MITRE ATLAS для AI-enabled systems;
- OSC&R для software supply chain attack behaviors;
- cloud/provider threat libraries для AWS/Azure/GCP-specific paths;
- MAESTRO/PLOT4AI для AI/privacy overlays;
- Security Cards и PnG для brainstorming.

Пример использования:
- Для CI/CD threat model команда берет OSC&R для dependency confusion и malicious build script, ATT&CK для credential access/lateral movement, CAPEC для command injection и OWASP Top 10 для insecure design.

### 5.3 Каталоги уязвимостей

Каталоги уязвимостей нужны для связи threat model с реальными weaknesses и exploited vulnerabilities.

Используйте:
- CVE/MITRE для идентификаторов публичных vulnerabilities;
- NVD/NIST для enrichment, CVSS и SCAP data;
- CWE/MITRE для weakness classes и root cause mapping;
- CISA KEV для vulnerabilities exploited in the wild;
- OSV для open source dependency vulnerabilities;
- GitHub Advisory Database, Go Vulnerability Database, RustSec, Snyk DB как ecosystem-specific sources;
- cloud vulnerability databases для cloud provider/service issues.

Пример использования:
- Attack path "RCE in exposed file converter" получает CWE mapping (deserialization или command injection), CVE if known, CVSS v4.0 technical severity, EPSS likelihood, KEV status и asset criticality. Risk decision строится не только на CVSS.

### 5.4 Модели оценки риска

Risk models помогают приоритизировать remediation. Не смешивайте technical severity, exploitation likelihood и business impact в один непрозрачный балл.

Практичный набор:
- OWASP Risk Rating: простая application-level матрица likelihood x impact;
- NIST SP 800-30: formal risk assessment context;
- CVSS v4.0: technical vulnerability severity, не business risk;
- EPSS: вероятность эксплуатации CVE in the wild;
- CISA KEV: факт known exploitation;
- SSVC: decision-oriented vulnerability prioritization;
- FAIR: количественная финансовая оценка риска для зрелых организаций;
- OCTAVE risk criteria: business impact categories;
- DREAD: исторически известен, но не рекомендуется как основной scoring из-за субъективности и слабой воспроизводимости.

Пример использования:
- CVE с CVSS 9.8 на non-internet-facing dev tool может иметь lower release risk, чем CVSS 7.5 в internet-facing auth proxy с KEV и высоким EPSS. Решение должно учитывать exposure, asset criticality, exploit activity и компенсирующие controls.

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
- После серии credential stuffing incidents в индустрии likelihood для account takeover scenarios повышается, а controls включают bot detection, breached password checks, MFA step-up и alert на impossible travel/session anomalies.

---

## 6. Матрица выбора

| Подход | Лучший контекст | Не использовать как | Пример |
|---|---|---|---|
| STRIDE-LM | быстрый проход по DFD | полноценную методологию оценки риска | ревью отдельного endpoint |
| Microsoft TM | базовый SDLC-процесс | глубокую симуляцию атаки | новый web service |
| OWASP TMP | web/API appsec review | enterprise risk program | GraphQL/API review |
| PASTA | системы высокого риска, где решения опираются на evidence | легкий checklist | banking/payment flow |
| LINDDUN | privacy/data processing | замену security threat modeling | analytics SDK |
| NIST 800-154 | data-centric systems | full system TM | secrets/PII data lifecycle |
| OCTAVE/Allegro | enterprise/asset risk | feature-level review | оценка crown jewels |
| Trike | authorization-heavy systems | быстрый workshop | SaaS RBAC matrix |
| VAST | scale and automation | deep manual analysis | service onboarding at scale |
| TARA | mission assurance/control selection | low-effort product review | aerospace/defense system |
| IDDIL/ATC | threat-driven architecture | fully automated practice | Kubernetes platform |
| hTMM | brainstorming workshop | evidence-based risk analysis | early product concept |
| QTMM | количественное сравнение вариантов | субъективную spreadsheet-оценку | privacy export design |
