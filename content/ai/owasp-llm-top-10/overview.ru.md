# OWASP Top 10 для LLM-приложений (2025)

## 1. Область

Этот обзор стремится перевести OWASP Top 10 for LLM Applications (2025) в практические шаги.

Фокус этого обзора:
- как каждая угроза может выглядеть в реальности
- какие риски для бизнеса
- какие митигации использовать
- какие контроли можно внедрить и регулярно проверять

---

## 2. Контекст угроз (как инциденты с LLM происходят в реальности)

Большинство инцидентов — ошибка на границах доверия между элементами:
- пользовательский ввод -> модель
- внешний контент -> RAG/индексация -> модель
- вывод модели -> tools/API/БД
- runtime модели -> расходы/квоты/инфраструктура
- жизненный цикл модели -> датасеты/адаптеры/реестры/деплой

В review LLM-систем я бы не пропускал следующие контуры:
- IAM и авторизацию для tools и downstream-систем
- классификацию и обработку данных (ПДн, секреты и т.п.)
- безопасную обработку output до исполнения/рендера
- provenance и целостность моделей/адаптеров/датасетов

---

## 3. Практический разбор OWASP LLM Top 10

Обозначения приоритета:
- `Critical` — обязательно для production; блокер релиза при отсутствии
- `High` — внедрить в ближайший релизный цикл
- `Recommended` — повышает зрелость и устойчивость, плановое внедрение

## 3.1 LLM01: Prompt Injection

### Кратко (OWASP)
Уязвимость, при которой ввод (включая скрытый или внешний контент) меняет поведение LLM вопреки ожидаемым правилам и может привести к несанкционированным действиям.

### Как выглядит в production
- скрытые инструкции в документах, веб-страницах, письмах, изображениях
- prompts вида "ignore previous instructions"
- обфускация (кодировки, мультиязычность, split payload)

### Основные риски
- несанкционированный вызов tools
- эксфильтрация чувствительных данных
- манипуляция решениями в бизнес-процессах

### Приоритетные митигации и контроли
- `Critical`: policy enforcement между LLM и tools (жесткий allowlist действий + deny-by-default)
- `Critical`: запрет выполнять "сырой" output модели без детерминированной валидации и policy-check
- `Critical`: human approval для high-impact операций (платежи, удаление, отправка наружу)
- `High`: detection pipeline для прямых/непрямых инъекций на входе и RAG-контексте
- `High`: adversarial security tests (включая obfuscation/multilingual/multimodal кейсы) в CI
- `Recommended`: изоляция каналов контекста и trust-tiering prompt assembly (trusted/untrusted context separation)

---

## 3.2 LLM02: Sensitive Information Disclosure

### Кратко (OWASP)
Риск раскрытия чувствительной информации (ПДн, секретов, внутренних данных, интеллектуальной собственности) через ответы LLM, контекст, обучение или небезопасную обработку данных.

### Как выглядит в production
- утечки ПДн/секретов из chat history в ответах
- попадание конфиденциальных данных в training/fine-tuning
- выдача внутренних конфигов и диагностических деталей

### Основные риски
- privacy breach и регуляторные санкции
- компрометация учетных данных и lateral movement
- утечка интеллектуальной собственности и коммерческой тайны

### Приоритетные митигации и контроли
- `Critical`: DLP и redaction для prompts/context/output (до отправки в модель и до выдачи пользователю)
- `Critical`: запрет секретов в system prompts/knowledge base + автоматический secrets scanning
- `Critical`: tenant isolation + encryption in transit/at rest
- `High`: проверяемые retention/deletion policies + юридически согласованный opt-out по training data
- `High`: data minimization и sanitization pipeline до training/indexing
- `Recommended`: privacy-preserving техники (differential privacy, tokenization) для чувствительных сценариев

---

## 3.3 LLM03: Supply Chain

### Кратко (OWASP)
Риски цепочки поставки LLM: недоверенные модели, адаптеры, данные, зависимости и инфраструктура, которые могут быть подменены, уязвимы или юридически проблемны.

### Как выглядит в production
- уязвимые зависимости в ML/LLM пайплайне
- недоверенная базовая модель, LoRA-адаптер, конвертер артефактов
- компрометация аккаунтов model repository или фейковые модели

### Основные риски
- backdoor-поведение модели
- выполнение вредоносного кода в training/inference средах
- юридические и compliance-риски по лицензиям/T&C

### Приоритетные митигации и контроли
- `Critical`: обязательный security gate на внешние модели/адаптеры (источник, хэш, подпись, владелец)
- `Critical`: непрерывный CVE/dependency scanning ML toolchain и блокировка критичных уязвимостей
- `Critical`: artifact signing + hash pinning для моделей, адаптеров и контейнеров
- `High`: SBOM/AI-BOM как обязательный артефакт релиза
- `High`: license/T&C drift monitoring и юридический review для сторонних поставщиков
- `Recommended`: независимая red-team оценка моделей перед production adoption

---

## 3.4 LLM04: Data and Model Poisoning

### Кратко (OWASP)
Атаки отравления данных и моделей, при которых в training/fine-tuning/RAG внедряются триггеры и смещения, нарушающие целостность и безопасность поведения модели.

### Как выглядит в production
- отравленные training/fine-tuning датасеты
- триггеры/backdoors, активируемые конкретными фразами
- вредоносные embeddings/документы в RAG-корпусе

### Основные риски
- потеря целостности (bias, manipulation, toxic output)
- скрытое backdoor-поведение по триггеру
- мошенничество и небезопасная автоматизация downstream-процессов

### Приоритетные митигации и контроли
- `Critical`: data lineage + versioning + процесс согласования для всех наборов данных
- `Critical`: quality/safety gates перед ingestion (source authenticity, policy checks, toxic/outlier filtering)
- `High`: regression suites на known-trigger/backdoor-паттерны
- `High`: anomaly detection по сигналам тренировки/инференса (loss drift, behavior drift)
- `High`: rollback-ready model registry с подписанным процессом продвижения
- `Recommended`: регулярные red-team кампании по poisoning и tabletop exercises

---

## 3.5 LLM05: Improper Output Handling

### Кратко (OWASP)
Недостаточная валидация и санитизация output LLM перед передачей в системы-потребители (например: SQL/API/shell/template renderer/browser), из-за чего ответы модели становятся вектором инъекций и исполнения вредоносного кода.

Под downstream-системами здесь понимаются любые компоненты, которые получают ответ LLM и выполняют действие: БД, API, shell, движок шаблонов, браузерный рендерер, воркеры и automation-пайплайны.

### Как выглядит в production
- output модели напрямую уходит в shell/API/SQL/template renderer
- LLM-генерированные JS/Markdown рендерятся без санитизации
- сгенерированный код/пакеты используются без проверки

### Основные риски
- XSS, SQLi, SSRF, RCE через downstream-исполнение
- escalation через цепочки вызова tools
- компрометация supply chain через hallucinated packages

### Приоритетные митигации и контроли
- `Critical`: output всегда считать untrusted input + schema validation перед любым действием
- `Critical`: parameterized queries и запрет динамического исполнения команд из output
- `Critical`: context-aware encoding (HTML/JS/SQL/Markdown/email) и безопасные defaults
- `High`: sandbox execution для сгенерированного кода и команд
- `High`: CSP и жесткие browser-side политики для рендера LLM-контента
- `Recommended`: SAST/DAST/IAST профили, специально покрывающие LLM-интеграции

---

## 3.6 LLM06: Excessive Agency

### Кратко (OWASP)
Избыточная автономия LLM-агента (tools/plugins/functions и права), позволяющая выполнять опасные действия по неоднозначным, ошибочным или манипулятивным инструкциям.

### Как выглядит в production
- у агента есть лишние инструменты, не нужные для задачи
- plugins работают с правами шире пользовательского scope
- destructive actions исполняются автономно и без подтверждения

### Основные риски
- несанкционированные изменения/удаления/транзакции
- межтенантные утечки из-за over-privileged identity
- быстро растущий blast radius в agentic-архитектурах

### Приоритетные митигации и контроли
- `Critical`: минимизация tools/functions/permissions (agent capability hardening)
- `Critical`: выполнение действий строго в user context (RBAC/OAuth scopes per action)
- `Critical`: обязательное подтверждение пользователя для high-impact действий
- `High`: complete mediation во downstream-системах (не делегировать authz на LLM)
- `High`: rate limits, loop guards, kill switch для agent-процессов
- `Recommended`: формальная матрица "tool -> permission -> бизнес-владелец -> risk"

---

## 3.7 LLM07: System Prompt Leakage

### Кратко (OWASP)
Утечка system prompt и скрытых инструкций, которые не должны считаться секретом, но при раскрытии упрощают обход защит и развитие комбинированных атак.

### Как выглядит в production
- извлечение system prompt через probing
- раскрытие внутренней логики, ролей, ограничений
- ошибочное хранение секретов в prompt/config тексте

### Основные риски
- ускоренный обход guardrails
- компрометация архитектурных деталей и секретов
- комбинированные атаки: leakage + injection + privilege abuse

### Приоритетные митигации и контроли
- `Critical`: правило "system prompt не является секретом" в secure coding standard
- `Critical`: вынести секреты и auth-логику из prompt в внешние контролируемые сервисы
- `Critical`: запрет делегирования критичных security-решений модели (authn/authz/SoD)
- `High`: prompt linting и PR-gates на наличие секретов/рискованных инструкций
- `High`: versioning prompt'ов с security review и change approval
- `Recommended`: регулярные prompt-leak pentest сценарии и chaos exercises

---

## 3.8 LLM08: Vector and Embedding Weaknesses

### Кратко (OWASP)
Слабости в генерации, хранении и retrieval embeddings/vectors (особенно в RAG), приводящие к cross-tenant leakage, poisoned context и несанкционированному доступу.

### Как выглядит в production
- cross-tenant leakage в общей vector DB
- poisoned-документы в retrieval corpus
- embedding inversion и риски восстановления данных

### Основные риски
- утечка конфиденциальных данных через retrieval
- манипуляция ответами через отравленный контекст
- юридические и compliance-риски из-за источников данных

### Приоритетные митигации и контроли
- `Critical`: permission-aware retrieval (tenant/user/document-level ACL)
- `Critical`: логическая изоляция индексов/неймспейсов по арендаторам и классам данных
- `High`: ingestion pipeline с source validation, malware/policy scanning и content classification
- `High`: immutable audit logs по retrieval и alerts по аномалиям доступа
- `High`: регулярные re-index integrity проверки и purge процесс
- `Recommended`: privacy risk assessment на embedding inversion и leakage simulations

---

## 3.9 LLM09: Misinformation

### Кратко (OWASP)
Генерация правдоподобной, но ложной или вводящей в заблуждение информации (из-за hallucination, bias или неполного контекста), создающей операционные и юридические риски.

### Как выглядит в production
- уверенные, но ложные ответы в legal/medical/finance доменах
- вымышленные ссылки, невалидные утверждения, несуществующие пакеты
- избыточное доверие пользователей output модели

### Основные риски
- опасные бизнес-решения и вред пользователям
- репутационный и юридический ущерб
- security-риски из-за некорректных технических рекомендаций

### Приоритетные митигации и контроли
- `Critical`: обязательная привязка к источникам (citation + source validation)
- `Critical`: human sign-off для high-stakes доменов
- `High`: confidence thresholds + режим "не знаю/эскалация к эксперту"
- `High`: RAG на доверенных источниках с ограничением домена знаний
- `High`: UX-механики прозрачности (пометка AI-generated, ограничения применимости)
- `Recommended`: KPI-контроль hallucination rate и closed-loop процесс исправлений

---

## 3.10 LLM10: Unbounded Consumption

### Кратко (OWASP)
Неконтролируемое потребление ресурсов LLM (запросы, токены, inference), которое ведет к DoS, denial-of-wallet, деградации сервиса и рискам model extraction.

### Как выглядит в production
- prompt flooding, злоупотребление большим context, длинные сессии
- denial-of-wallet атаки на usage-based биллинг
- попытки model extraction через API probing

### Основные риски
- деградация сервиса и DoS
- неконтролируемый рост расходов
- кража модели и потеря IP

### Приоритетные митигации и контроли
- `Critical`: hard quotas/rate limits/budget caps per tenant/user/key
- `Critical`: лимиты на размер input/context и timeout/throttling для тяжелых запросов
- `Critical`: мониторинг стоимости в реальном времени + алерты и auto-cutoff
- `High`: request fingerprinting и detection extraction-паттернов
- `High`: graceful degradation + emergency traffic controls при пике нагрузки
- `Recommended`: watermarking/anti-extraction controls и adversarial robustness tuning

---

## 4. Краткое различие угроз

- `LLM01 Prompt Injection`: атака на инструкции выполнения; главное отличие — управление поведением модели через входной контент.
- `LLM02 Sensitive Information Disclosure`: утечка данных в ответах; отличие — фокус на конфиденциальности, а не на управлении действиями.
- `LLM03 Supply Chain`: компрометация внешних зависимостей LLM-стека; отличие — риск приходит через поставщиков и интеграции.
- `LLM04 Data and Model Poisoning`: отравление обучающих/индексируемых данных; отличие — подмена поведения модели через изменение ее knowledge base.
- `LLM05 Improper Output Handling`: небезопасное исполнение output в системах-потребителях; отличие — уязвимость в интеграционном слое после генерации.
- `LLM06 Excessive Agency`: у агента слишком много прав и инструментов; отличие — проблема в полномочиях и автономном действии.
- `LLM07 System Prompt Leakage`: раскрытие скрытых инструкций и внутренней логики; отличие — облегчает обход защит, но само по себе не равно исполнению кода.
- `LLM08 Vector and Embedding Weaknesses`: ошибки в retrieval/embeddings/RAG-хранилище; отличие — уязвимость в слое контекста и поиска.
- `LLM09 Misinformation`: правдоподобные, но ложные ответы; отличие — основной риск в качестве решений и доверии, а не в прямом exploitation.
- `LLM10 Unbounded Consumption`: неконтролируемое потребление токенов/ресурсов; отличие — фокус на доступности и стоимости (DoS/denial-of-wallet).