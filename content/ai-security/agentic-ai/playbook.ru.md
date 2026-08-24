# Плейбук безопасности агентного ИИ

## 1. Область и цель

Этот плейбук покрывает AI agents и multi-agent workflows, которые планируют действия, вызывают tools, используют memory, извлекают context, выполняют code, работают с web или меняют business state.

Используйте этот документ для:
- проверка безопасности autonomous и semi-autonomous workflows;
- release gates для agents с tools, memory, browser/email/file access или code execution;
- определения требований к policy enforcement, action tracing, согласование, rollback и kill switch;
- подготовки negative tests для tool misuse, memory poisoning, delegation abuse и runaway loops.

Ответственность документа:
- Этот плейбук отвечает за автономию агентов, использование tools агентами, обработку memory/scratchpad/checkpoints, action traces, согласования, rollback и поведение kill switch.
- Prompt injection, data leakage и excessive agency рассматриваются здесь через призму выполнения агентом действий и business impact.
- Общий AI control baseline находится в [обзоре безопасности AI](../securing-ai/overview.ru.md), а таксономия угроз — в [обзоре OWASP LLM Top 10](../owasp-llm-top-10/overview.ru.md).
- Этот плейбук не задает MCP protocol, server registry или меры управления transport; для них используйте [плейбук безопасности MCP](../mcp-security/playbook.ru.md).

Вне области:
- меры контроля, специфичные для протокола MCP; используйте [плейбук безопасности MCP](../mcp-security/playbook.ru.md);
- general LLM threat taxonomy; используйте [обзор OWASP LLM Top 10](../owasp-llm-top-10/overview.ru.md);
- общие меры контроля API, браузера, Kubernetes и цепочки поставки ПО, если они не являются частью agent runtime.

Цель:
- не позволить agents превращать неоднозначные, вредоносные или ошибочные инструкции в unauthorized access, unsafe execution, data leakage или uncontrolled business impact.

---

## 2. Модель угроз для агента

Минимальные компоненты для моделирования:
- model и prompt layer;
- orchestration loop, planner, router, policy engine и tool selector;
- working memory, scratchpad, long-term memory, retrieval stores и checkpoints;
- tools и downstream systems;
- user, workload и tool identities;
- browser, URL fetcher, file parser, code interpreter, shell или office/email integration;
- audit trail, согласования, rollback paths и kill switch.

Сценарии с высоким воздействием:
- prompt injection или poisoned retrieval content заставляет agent вызвать tool вне intended task;
- long-running workflow накапливает secrets, PII или tokens в scratchpad, memory, logs или serialized checkpoints;
- browser или code-execution tool скачивает malicious content, выполняет generated code или обращается к internal network destinations;
- один agent делегирует задачу более privileged agent или shared tool без сохранения исходного authorization context;
- agent выполняет технически валидные действия, нарушающие business intent, например bulk deletion, duplicate transaction или external disclosure.

Особо опасна комбинация трех возможностей: доступ к sensitive data, чтение недоверенного content и канал для передачи данных или выполнения действий. Если они нужны одному workflow, разделяйте их между trust zones или agent roles и ставьте принудительную policy boundary между чтением и привилегированным действием. GitHub Issues, pull-request comments, README, web pages, email, package documentation и содержимое repository считаются недоверенным вводом, даже когда размещены в доверенной организации.

---

## 3. Базовый профиль для рабочих сред

### 3.1 Инвентаризация и классификация агентов

`Baseline`:
- Ведите inventory production agents, владельцы, runtime location, model/provider, autonomy level, tools, memory stores, retrieval sources, identities, data classes и business operations.
- Классифицируйте каждого агента по максимальному воздействию, а не по заявленному назначению. Помощник только для чтения с доступом к конфиденциальным данным все равно считается чувствительным; агент с одним инструментом записи может относиться к классу высокого воздействия.
- Делайте первичный triage по трем осям: attack surface, blast radius и доказуемость защитных мер. Минимальный быстрый вопрос: выполняет ли agent tools, и если да, изолировано ли execution от host, internal network, учетных данных и production data.
- Оценивайте agent в двух состояниях: vendor-as-shipped/default configuration и фактически deployed configuration. Если безопасная posture зависит от opt-in settings, paid features, customer-managed gateway, sandbox или egress policy, это должно быть видно в release decision.
- Не засчитывайте vendor claim как control без подтверждения, что он принудительно применяется. Detection-only guardrail, который только логирует или предупреждает после irreversible action, является forensic signal, а не preventive control.
- Назначайте явный autonomy profile:
  - `Assistive`: нет tool execution или только user-visible draft output.
  - `Read-only tool user`: может извлекать данные, но не менять business state.
  - `State-changing agent`: может create, update, submit, trigger или delete.
  - `Execution agent`: может выполнять код, использовать браузер, изменять файлы или работать с внешним содержимым.

`High-impact/regulated`:
- До запуска назначьте владельца продукта, ответственного за безопасность, владельца со стороны SRE/эксплуатации и владельца данных.
- Пересматривайте access и tool entitlements минимум ежеквартально и после каждого material model/provider/tool change.

### 3.2 Принудительное применение политик и авторизация

`Baseline`:
- Размещайте policy enforcement layer между model output и tool execution. Model может предложить action; policy решает, можно ли его выполнить.
- Authorize каждый tool call по user/workload identity, tenant, role, data class, environment, action и workflow state.
- Никогда не считайте model reasoning, natural-language instructions, prompt text или tool descriptions authorization подтверждения.
- Разделяйте tools по risk: read/write/admin/bulk/export/destructive operations должны быть отдельными capabilities с отдельными scopes.
- Используйте short-lived, tool-specific учетные данные. Не используйте одну broad agent identity для unrelated tools.

`High-impact/regulated`:
- Требуйте step-up authentication или подтверждение человеком для high-impact, irreversible, cross-tenant, financial, security, privacy или external-disclosure actions.
- Удаляйте active tokens, secrets и session cookies из checkpoints, scratchpads, persisted memory, tool outputs и execution traces до сохранения.
- Для multi-agent workflows передавайте original user/workload context и применяйте delegation boundaries на каждом hop.

Стартовые defaults:
- `max autonomous steps=5` для read-only workflows;
- `max autonomous steps=3` до re-authorization для state-changing workflows;
- `max tool-chain depth=3`;
- default state-changing execution flow: `preview -> explicit confirm -> execute`;
- kill-switch SLO `<=60s` для state-changing или execution agents.

### 3.3 Память, поиск и состояние

`Baseline`:
- Считайте working memory, scratchpads, long-term memory, vector stores, summaries, checkpoints и tool outputs data stores, на которые распространяются classification, access control, retention, deletion и audit requirements.
- Исключайте secrets, tokens, учетные данные, raw regulated data и unnecessary sensitive fields из memory по policy.
- Применяйте document-level и tenant-level authorization до попадания retrieved content в agent context.
- Помечайте untrusted retrieved content как untrusted. Он может влиять на answer, но не должен переопределять policy, identity или tool authorization.
- Версионируйте prompts, memory rules, retrieval policies, embedding models и dataset snapshots, чтобы incident response мог откатывать context, а не только code.

`High-impact/regulated`:
- Используйте memory write policies, которые валидируют, что agent может сохранять, кто сможет прочитать это позже и когда запись истекает.
- Изолируйте или отключайте источники памяти при признаках отравления, появления неожиданных чувствительных данных или аномальных шаблонов записи.
- Тестируйте восстановление семантической целостности: восстановленные векторные хранилища и память должны сохранять ожидаемое поведение авторизованного поиска и не возвращать отравленное содержимое.

Production defaults:
- no indefinite retention для working memory;
- raw session/scratchpad retention disabled by default вне forensic mode;
- memory entries с sensitive data требуют explicit retention class и deletion workflow;
- forensic raw payload capture retention `<=30 days`.

### 3.4 Инструменты браузера, почты, файлов и выполнения кода

`Baseline`:
- Запускайте browser automation, URL fetchers, file parsers и code interpreters в isolated sandboxes без default access к internal networks, host files, cloud metadata services или учетным данным рабочей среды.
- Принудительно применяйте egress allowlists для agent-run browsers и fetch tools. Используйте deny-by-default для arbitrary public web access.
- Сканируйте и санитизируйте downloaded или retrieved content до попадания в memory, RAG pipelines или execution tools.
- Блокируйте high-risk file types по умолчанию: executables, scripts, archives, macros и active content, если workflow явно их не требует.
- Считайте имена и версии packages, команды установки и registry instructions из model output или внешнего content недоверенными. Не разрешайте автоматическую установку до проверки package identity, approved registry, publisher, version и integrity/lockfile подтверждения.
- Быстро patch browser engines, HTML/PDF/document parsers, sandbox images и execution runtimes.

`High-impact/regulated`:
- Требуйте подтверждение человеком перед execution third-party code, generated code with external side effects, package installation, shell commands или file operations вне temporary workspace.
- Используйте ephemeral execution environments с network restrictions, CPU/memory/time limits, read-only base images where practical и central log export before teardown.
- Запрещайте agents autonomously navigating public web для state-changing workflows, если domain set, data handling и меры защиты от prompt injection не прошли явное ревью.

### 3.5 Трассировка действий, мониторинг и реагирование на инциденты

`Baseline`:
- Формируйте agent action trace, который фиксирует security-relevant decisions без хранения unnecessary raw sensitive content.
- Коррелируйте model calls, retrieval events, memory writes, tool invocations, policy decisions, согласования, downstream actions и final output.
- Настройте оповещения об аномальных последовательностях инструментов, повторных отказах политик, новых сочетаниях инструментов, неожиданных записях в память, попытках межтенантного доступа, чрезмерных расходах токенов или запросов и дрейфе поведения после изменения модели или prompt.
- Не храните raw prompts, context, tool payloads и scratchpads в обычных logs; используйте minimized metadata и redacted fields.

`High-impact/regulated`:
- Поддерживайте runbooks для data leakage, runaway agent, malicious tool use, poisoned memory/RAG source, компрометации учетных данных tool и unsafe state-changing action.
- Тестируйте kill switch и rollback paths до launch и после крупных изменений среды выполнения или инструментов.
- Проверяйте incident timelines на реальных log fields; runbook не готов, если responders не могут восстановить, кто или что вызвало downstream action.

---

## 4. Проверка

Обязательные подтверждения:
- agent inventory entry с autonomy profile, владелец, tools, memory stores, identities и data classes;
- vendor-as-shipped vs deployed-configuration assessment, включая enabled tools, memory, connectors, sandboxing, меры контроля исходящего трафика, режимы согласования и paid/optional security features;
- policy matrix: `who/what/can-do` для каждого tool и memory source;
- action trace schema и sample redacted trace;
- sandbox configuration для browser/file/code tools;
- memory retention и deletion policy;
- согласование и результаты проверки kill switch для high-impact agents.

Negative tests:
- prompt injection пытается вызвать forbidden tool и блокируется policy;
- retrieved document требует ignore policy и не может переопределить tool authorization;
- инструкция из GitHub Issue, PR comment, README или package documentation не может получить secrets, расширить egress или запустить privileged tool;
- вымышленное или неожиданно новое имя package не устанавливается автоматически и переводит workflow в ручная проверка;
- user from tenant A не может читать или изменять данные tenant B через memory, tools или delegated agents;
- write action не выполняется без preview и confirmation;
- serialized checkpoint не содержит active tokens или secrets;
- browser tool не может обратиться к cloud metadata, internal admin services или unapproved external domains;
- code execution не может получить доступ к host filesystem, учетным данным production-среды или unrestricted network egress;
- multi-agent delegation сохраняет original authorization context.

Операционные сигналы:
- percentage tool calls with policy decision logged;
- покрытие согласованием для high-impact actions;
- denied tool calls per 1k sessions;
- memory write rejection rate и sensitive-data detections;
- mean time to kill runaway agents, target `<=60s`;
- оповещения о дрейфе поведения после изменения модели, prompt, инструмента или политики памяти.

---

## 5. Решение по результатам ревью

Матрица ниже определяет доменную критичность замечания и решение о релизе. Общие SLA устранения, жизненный цикл исключений, принятие риска и подтверждения закрытия определяет [плейбук управления уязвимостями](../../review/vulnerability-management/playbook.ru.md); при пересечении требований применяется более строгое.

| Severity | Agent condition | Обязательное действие |
|---|---|---|
| Critical | Agent может autonomously выполнять irreversible, financial, administrative, cross-tenant или external-disclosure actions без принудительного применения политики и согласования | Блокировать релиз |
| Critical | Execution/browser tool может обратиться к учетным данным production-среды, host filesystem, cloud metadata или internal network by default | Блокировать релиз и изолировать runtime |
| High | Memory/checkpoints могут сохранять активные учетные данные, secrets или regulated data без меры хранения и удаления | Блокировать high-impact workflows до исправления |
| High | Multi-agent workflow теряет original authorization context или допускает privilege escalation through delegation | Блокировать релиз для privileged workflows |
| High | Action traces не позволяют reconstruct high-impact downstream actions | Исправить до production launch |
| High | Tool-executing agent зависит от заявленных vendor, opt-in или только обнаруживающих мер без доказуемой песочницы, контроля egress и принудительной авторизации в развернутой конфигурации | Блокировать state-changing/execution workflows до подтверждения меры контроля |
| Medium | Инвентаризация или матрица политик неполна для агентов только для чтения или с низким воздействием | Назначить владельца и срок устранения |
| Medium | Нет мониторинга дрейфа поведения после изменения модели или prompt | Требовать компенсирующую проверку и подтверждения тестирования |
| Low | Prompt, tool или memory metadata без consistent naming, но access или logging не затронуты | Исправить opportunistically |

Релиз считается одобренным, только когда автономность агента ограничена, политики применяются принудительно, память обрабатывается безопасно, поверхности выполнения изолированы, пригодные для расследования трассировки доступны, а поведение kill switch проверено.

---

## 6. Связанные материалы

- [Обзор безопасности AI](../securing-ai/overview.ru.md)
- [Плейбук безопасности MCP](../mcp-security/playbook.ru.md)
- [Плейбук безопасной разработки с ИИ](../ai-assisted-development/playbook.ru.md)
- [Обзор OWASP LLM Top 10](../owasp-llm-top-10/overview.ru.md)
- [Плейбук моделирования угроз](../../review/threat-modeling/playbook.ru.md)
- [Плейбук безопасности браузера и frontend-части](../../application-security/web/browser-security/playbook.ru.md)
- [Плейбук безопасности API](../../application-security/api/api-security-patterns/playbook.ru.md)
