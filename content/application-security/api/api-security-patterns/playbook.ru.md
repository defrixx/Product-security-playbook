# Плейбук по безопасности API и типовым интеграциям

## 1. Область и цель

Этот плейбук описывает основные виды API, применимые угрозы, базовые меры защиты и типовые схемы интеграций для REST, SOAP/XML, GraphQL, Webhook и gRPC.

Базовый профиль согласован с OWASP API Security Top 10 2023. Это не пересказ списка: цель документа — превратить категории в проверяемые меры контроля для рабочих сред, рабочие настройки и подтверждения для ревью.

Используйте документ для:
- проектирования публичных, партнерских, внутренних и обращенных к фронтенду API;
- архитектурного ревью API до релиза;
- построения модели угроз, security checklist и negative test plan;
- выбора обязательных мер контроля для API gateway, BFF, service-to-service и webhook-интеграций.

Документ не заменяет специализированные материалы:
- для OIDC/OAuth используйте [руководство по безопасности OIDC + OAuth 2.0](../../identity/oidc-oauth/playbook.ru.md);
- для моделирования угроз используйте [плейбук по моделированию угроз](../../../review/threat-modeling/playbook.ru.md);
- для архитектурной gate-проверки используйте [чеклист ревью архитектуры безопасности](../../../review/architecture/checklist.ru.md).

---

## 2. Виды API и назначение

### 2.1 REST API

REST API обычно используют HTTP-методы, URI-ресурсы и представления данных в JSON. Клиент обращается к конкретному ресурсу или коллекции ресурсов, а операция выражается через метод вроде `GET`, `POST`, `PUT`, `PATCH` или `DELETE`.

Это основной выбор для публичных API, взаимодействия фронтенда и бэкенда, partner API и большинства CRUD/business-flow сценариев. В рабочих средах REST API часто находится за API gateway или BFF, но настоящая граница безопасности не должна заканчиваться на route: доменная логика все равно должна проверять права на объект, tenant, действие и поля.

Сильные стороны:
- широкая поддержка API gateways, OpenAPI, SDK generation, DAST и contract testing;
- понятная модель ресурсов и HTTP status codes;
- простая интеграция с OAuth 2.0, API keys, mTLS и rate limiting.

Типовые риски:
- Broken Object Level Authorization (BOLA): пользователь получает доступ к объекту по чужому ID, потому что API проверяет только факт входа, а не право на конкретный ресурс. Типовой признак — изменение `user_id`, `tenant_id`, `order_id` или другого object ID возвращает чужие данные или позволяет изменить чужой объект.
- Broken Function Level Authorization (BFLA): пользователь вызывает функцию, метод или route, которые не должны быть доступны его роли. Часто проявляется как доступ regular user к admin/support/export endpoints через прямой HTTP-запрос, даже если UI не показывает такую кнопку.
- Массовое присваивание и избыточное раскрытие полей: API принимает или возвращает больше полей, чем нужно для конкретной операции. При массовом присваивании клиент может передать `role`, `isAdmin`, `tenantId` или служебный флаг в write model; при избыточном раскрытии response показывает внутренние или чувствительные поля.
- Неконтролируемые параметры пагинации, фильтрации и сортировки: клиент управляет дорогостоящими запросами без лимитов и allowlist. Это может привести к resource exhaustion, обходу бизнес-ограничений, тайминг-утечкам или выборке данных вне ожидаемого scope.
- Слабая инвентаризация старых версий API: команда не знает, какие версии, routes и deprecated endpoints доступны в runtime. Старые версии часто обходят новые authz, validation и меры журналирования, потому что не проходят тот же release gate.

### 2.2 SOAP/XML API

SOAP API использует XML-сообщения с формальным envelope, WSDL-контрактами и часто с дополнительными WS-* механизмами для подписи, шифрования, routing и reliability. В отличие от обычного REST-over-HTTP, смысл операции обычно задается SOAP action, структурой XML body и контрактом сервиса.

SOAP применяется в legacy, enterprise, банковских, государственных и B2B-интеграциях, где важны формальные контракты, XML Schema, WS-* расширения и совместимость с существующими платформами. В рабочих средах такие API часто стоят перед критичными backend-системами, поэтому parser hardening, подписи, fault redaction и сегментация важны не меньше, чем сама аутентификация партнера.

Сильные стороны:
- строгие WSDL/XSD-контракты;
- зрелая поддержка enterprise middleware;
- возможность message-level security в WS-Security сценариях.

Типовые риски:
- XXE, XML entity expansion и XML bomb: XML parser обрабатывает external entities, DTD или чрезмерное расширение сущностей. Это может привести к чтению локальных файлов, SSRF, утечке сетевых metadata или отказу в обслуживании через рост памяти/CPU.
- Небезопасная XML canonicalization/signature validation: подпись проверяется не на том представлении XML или не на том элементе документа. Атакующий может использовать signature wrapping, чтобы сохранить валидную подпись на безопасной части сообщения и подставить вредоносный payload в исполняемую часть.
- Чрезмерно доверенная схема интеграции с бэкенд-системами: SOAP gateway передает валидный XML дальше как доверенный business command без повторной проверки контекста. В legacy-интеграциях это часто дает прямой путь к core banking, ERP, billing или другим системам с высоким воздействием.
- Сложная обработка ошибок и раскрытие внутренних деталей: SOAP faults и middleware errors могут раскрывать stack traces, имена backend-систем, SQL/XML fragments и routing details. Эти данные помогают атакующему подобрать следующий шаг и упрощают эксплуатацию parser/backend bugs.

### 2.3 GraphQL API

GraphQL API обычно предоставляет один endpoint, на который клиент отправляет query или mutation и сам выбирает нужные поля, вложенные связи и форму ответа. Schema описывает доступные типы, поля и операции, а resolvers получают данные из backend-сервисов, баз данных или других API.

GraphQL подходит для клиентских приложений, которым нужен гибкий выбор полей и агрегация данных из нескольких бэкенд-источников. Его нельзя рассматривать как “REST, только без большого количества endpoints”: основная модель безопасности переносится в resolvers, управление схемой и меры контроля стоимости запросов.

Сильные стороны:
- точный выбор полей клиентом;
- единая схема;
- удобная агрегация данных для фронтенда и mobile.

Типовые риски:
- Обход authorization на field/node/edge уровне: GraphQL resolver возвращает поле, node или связь без проверки прав на конкретный объект и tenant. Даже если top-level query защищен, вложенный resolver может раскрыть email, billing data, membership или admin-only атрибуты.
- Query depth/complexity DoS: клиент строит глубоко вложенный или дорогой query, который заставляет backend выполнять большое число resolver calls и downstream-запросов. Без лимитов depth, complexity, timeout и cancellation один запрос может создать нагрузку как множество REST-вызовов.
- Batching attacks и brute force внутри одного HTTP-запроса: клиент отправляет много operations или aliases в одном request и обходит per-request rate limit. Это удобно для перебора учетных данных, OTP, object IDs или проверки существования записей с меньшим числом видимых HTTP-событий.
- Утечки через introspection, GraphiQL и подробные ошибки: schema discovery и dev tooling раскрывают типы, поля, mutations, deprecated surfaces и внутренние naming conventions. Подробные ошибки могут дополнительно раскрывать resolver paths, backend messages и данные, полезные для атаки.

### 2.4 Webhook API

Webhook - это входящий вызов от внешнего провайдера или другой системы при наступлении события: платеж прошел, заказ изменился, пользователь создан, alert сработал. В отличие от обычного API, receiver обычно не инициирует запрос сам и должен принимать события асинхронно, с учетом retry, out-of-order delivery и повторной доставки.

Для принимающей стороны webhook является internet-facing точкой входа, даже если он не выглядит как пользовательский API. Его безопасность строится вокруг проверки подписи на raw body, меры защиты от replay с проверкой timestamp, идемпотентности, изоляции обработки через queue и строгой валидации payload до любых бизнес-действий.

Сильные стороны:
- асинхронная доставка событий;
- снижение polling;
- простая интеграция с SaaS и partner systems.

Типовые риски:
- Подмена провайдера: атакующий отправляет запрос, похожий на webhook от легитимного сервиса. Если подпись, timestamp, key ID и источник не проверяются до бизнес-обработки, система может принять поддельное событие как реальный платеж, refund, signup или alert.
- Повторная отправка старого события: ранее валидный webhook повторно отправляется после того, как состояние уже изменилось. Без freshness window и replay cache старое событие может повторно выполнить операцию или откатить состояние к нежелательному результату.
- Повторная обработка и нарушение идемпотентности: один и тот же event обрабатывается несколько раз из-за retry провайдера, сетевых ошибок или race condition. Если обработчик не привязан к event ID/idempotency key, возможны двойные списания, повторные уведомления, дубли заказов и неконсистентное состояние.
- SSRF-подобные цепочки, если payload запускает исходящие запросы: webhook payload содержит URL, domain, object reference или integration target, который receiver потом использует для outbound call. Без allowlist и меры контроля исходящего трафика это превращает webhook в непрямой SSRF или data exfiltration path.
- Переполнение очереди и poison messages: атакующий или неисправный provider отправляет много событий либо payload, который постоянно ломает worker. Это забивает очередь, задерживает легитимные события и может вызвать бесконечные retry loops без DLQ и лимитов.

### 2.5 gRPC API

gRPC API описывает сервисы и методы в `.proto`-контракте, использует Protocol Buffers для сериализации сообщений и обычно работает поверх HTTP/2. Вызов выглядит как RPC method call, а не как обращение к URI-ресурсу; API может быть unary, server/client streaming или bidirectional streaming.

gRPC часто применяется для внутреннего service-to-service взаимодействия, low-latency бэкенд-коммуникаций и streaming. В рабочих средах его нельзя считать безопасным только потому, что он “внутренний”: нужны TLS/mTLS, workload identity, method-level authorization, deadlines, message limits и контроль server reflection.

Сильные стороны:
- строгий protobuf-контракт;
- эффективная бинарная сериализация;
- поддержка unary и streaming RPC;
- удобные interceptors для authn/authz/logging.

Типовые риски:
- Отсутствие method-level authorization: сервис проверяет только mTLS/service identity, но не право вызывающего workload на конкретный RPC method и resource. После компрометации одного сервиса это упрощает lateral movement и вызов privileged методов.
- Незашифрованный plaintext gRPC во внутренних сетях: трафик передается без TLS/mTLS, потому что сеть считается доверенной. Это повышает риск перехвата, подмены и credential/session leakage при ошибках сегментации, sidecar bypass или компрометации node.
- Чрезмерно включенный server reflection: reflection раскрывает список services, methods и message types клиентам, которым это не нужно в рабочей среде. Для атакующего это ускоряет reconnaissance и помогает строить корректные payloads без доступа к proto-файлам.
- Message size/streaming DoS: большие сообщения, длинные streams или отсутствие deadlines удерживают память, connections и worker threads. Без лимитов на message size, stream duration и concurrency один клиент может деградировать весь backend pool.
- Слабый контроль backward compatibility protobuf-схем: изменения в proto ломают старых клиентов или меняют смысл default/unknown fields. Ошибки schema evolution могут привести к bypass authorization, неверной интерпретации business flags или silent data loss.

---

## 3. Форматы данных и security-impact

| Формат | Где используется | Security-impact | Обязательные меры |
|---|---|---|---|
| JSON | REST, GraphQL, webhooks | Mass assignment, type confusion, excessive data exposure, инъекции в downstream interpreters | JSON Schema/OpenAPI validation, allowlist полей, запрет unknown properties для write models, response filtering |
| XML | SOAP, legacy REST, SAML-like payloads | XXE, entity expansion, XPath/XSLT-инъекции, signature wrapping | Disable DTD/external entities, secure processing mode, schema limits, signature wrapping tests |
| Protocol Buffers | gRPC, event contracts | Неочевидные defaults, unknown fields, schema evolution ошибки | protobuf validation, max message size, compatibility checks, explicit authorization вне схемы |
| Multipart/form-data | загрузка файлов, смешанные payload | Malware, различия поведение парсера, oversized parts, подмена content-type | лимиты размера файлов/частей, content sniffing, malware scanning, изоляция storage |
| application/x-www-form-urlencoded | browser forms, OAuth endpoints | parameter pollution, неоднозначность encoding, CSRF exposure | строгий поведение парсера, политика duplicate parameters, меры защиты от CSRF для cookie-bound flows |
| Binary payloads | файловые API, streaming, media | parser exploits, decompression bombs, resource exhaustion | bounded parsing, sandboxed processing, decompression ratio limits, async scanning |

---

## 4. Модели экспозиции

Стиль API и модель экспозиции нужно разделять. REST может быть публичным, внутренним или обращенным к фронтенду; каждый вариант имеет разные границы доверия.

| Модель экспозиции | Граница доверия | Основные риски | Базовый профиль безопасности |
|---|---|---|---|
| Browser/frontend -> Backend API | Браузер и бэкенд разделены internet boundary; браузер недоверенный | CSRF, CORS ошибки, утечка токенов, BOLA, XSS-to-API abuse | BFF или HttpOnly session cookie, меры защиты от CSRF, strict CORS, object-level authz |
| Public API -> API Gateway -> Internal services | Internet client к public edge | API key theft, OAuth misuse, bot abuse, quota bypass, inventory drift | OAuth/client учетные данные или HMAC/request signing, gateway validation, per-client quotas, schema enforcement |
| Partner API | Договорной внешний клиент | credential sharing, слабые меры контроля партнера, excessive access | mTLS или OAuth client учетные данные, allowlisting где оправдано, scoped access, contract monitoring |
| Internal service-to-service API | Внутренняя сеть не считается доверенной | lateral movement, confused deputy, missing authz | workload identity, mTLS, method/resource authorization, network policy |
| Webhook receiver | Внешний провайдер вызывает вашу точку входа | spoofing, replay, duplicate delivery, payload abuse | проверка подписи, timestamp window, idempotency key, изоляция через async queue |
| Admin/privileged API | Пользователь или сервис выполняет опасные действия | privilege escalation, repudiation, массовое повреждение данных | step-up auth, JIT/JEA access, согласование для destructive actions, immutable audit |

---

## 5. Общая модель угроз API

Минимальная модель угроз для любого API должна покрывать:
- кто вызывает API: браузер, mobile app, партнер, бэкенд-сервис, SaaS provider, admin user;
- какие учетные данные используются: cookie session, OAuth token, API key, client certificate, webhook secret, workload identity;
- где проходит граница доверия;
- какие объекты и операции требуют object-level, property-level и function-level authorization;
- какие параметры влияют на downstream calls, database queries, файловые пути, URLs, queues и привилегированные действия;
- какие лимиты ограничивают cost, payload size, concurrency, streaming duration и поведение повторных попыток;
- какие события журналируются для расследования и обнаружения.

### 5.1 Базовая матрица угроз

Матрица покрывает категории OWASP API Security Top 10 2023: BOLA, Broken Authentication, BOPLA, Unrestricted Resource Consumption, BFLA, Unrestricted Access to Sensitive Business Flows, SSRF, Security Misconfiguration, Improper Inventory Management и Unsafe Consumption of APIs.

| Угроза | Где проявляется | Обязательные меры контроля | Проверка |
|---|---|---|---|
| BOLA | REST resources, GraphQL nodes, gRPC methods | Object-level authorization на каждый read/write, tenant boundary в policy | Негативные тесты: пользователь A не читает/меняет объект пользователя B |
| BOPLA / excessive data exposure | REST responses, GraphQL fields | Field/property-level authorization, response DTO allowlist | Тесты на отсутствие sensitive fields для ролей без доступа |
| BFLA | admin endpoints, mutations, service methods | Function-level policy, deny-by-default routing, admin separation | Тесты доступа regular user к privileged operation |
| Broken authentication | Public/partner/internal API | OAuth 2.0 flows, усиленные согласно RFC 9700; OIDC login по OpenID Connect Core; token validation; mTLS или DPoP sender-constrained tokens по RFC 8705/RFC 9449, где используются | Тесты invalid issuer/audience/expired token, OIDC nonce/login tests где применимо, mTLS/DPoP binding tests |
| Resource exhaustion | GraphQL, gRPC streaming, uploads, search/list endpoints | Rate limits, лимиты payload, query cost/depth limits, timeouts | Load/abuse tests, поведение 413/429, подтверждение срабатывания timeout |
| Business-flow abuse | signup, checkout, booking, search, export | Лимиты по риску, меры контроля частоты операций, обнаружение abuse, step-up | Abuse-case tests и мониторинг sensitive flows |
| SSRF через API | webhook payloads, URL fetchers, import/export | URL allowlist, egress policy, metadata IP block, DNS rebinding protection | SSRF canary tests, egress deny logs |
| Security misconfiguration | gateways, CORS, debug, reflection | Secure defaults, environment separation, config scanning | Config ревью, public endpoint inventory, debug endpoint checks |
| Improper inventory | legacy versions, shadow APIs | API catalog, владелец, lifecycle, deprecation policy | Сверка gateway routes, OpenAPI specs и runtime traffic |
| Небезопасное потребление API | Сторонние и партнёрские API | Внешние данные считаются недоверенными, проверка схемы ответа, circuit breaker | Контрактные тесты и тесты некорректных ответов вышестоящих систем |

---

## 6. Угрозы и меры по типам API

### 6.1 REST

Обязательные меры:
- OpenAPI 3.1 contract как минимум для всех релизных endpoints; OpenAPI 3.2 допустим там, где его поддерживают gateway validation, code generation, linting, scanners и contract-test tooling;
- authentication на gateway или service edge, но authorization внутри доменной логики;
- object-level authorization для каждого endpoint с object ID;
- separate DTO/schema для create/update/read, чтобы исключить mass assignment;
- explicit response allowlist, особенно для user, tenant, payment, admin и support объектов;
- pagination defaults и жесткие лимиты;
- consistent 401/403/404 strategy без утечки существования чужих объектов;
- rate limits по client, user, tenant, IP и sensitive business flow.

Рабочие настройки:
- максимальный размер тела запроса: `1-10 MB` для обычных JSON-эндпоинтов; больше — только после отдельного архитектурного ревью;
- default page size: `50-100`, hard max: `500-1000`;
- gateway timeout: `<=30s`, internal service timeout обычно `<=3-5s`;
- все write endpoints должны иметь idempotency key, если клиент может безопасно повторить запрос после network failure.

Проверка:
- OpenAPI linting и contract tests выполняются в CI для измененных endpoints.
- Есть покрытие request/response validation для gateway и service-level enforcement paths.
- Write DTOs отклоняют unknown properties или доказывают explicit field allowlist для защиты от mass assignment.
- Gateway routes, service routes и OpenAPI inventory сравниваются на drift перед релизом.

### 6.2 SOAP/XML

Обязательные меры:
- запрет DTD и external entities во всех XML parsers;
- отключение external DTD loading, XInclude и небезопасных resolver;
- secure processing mode и лимиты entity expansion, depth, attributes, total document size;
- XSD validation с контролем внешних schema imports;
- проверка XML signature wrapping, если используется WS-Security/XML Signature;
- redaction SOAP faults и correlation ID вместо stack traces;
- отдельный network segment или gateway для legacy SOAP backend.

Рабочие настройки:
- XML document size hard limit задается явно для каждого operation class;
- SOAP endpoint не должен иметь прямой доступ к internal metadata services, admin panels и cloud control plane;
- parser configuration должна проверяться unit/integration tests с XXE и XML bomb payloads.

### 6.3 GraphQL

Обязательные меры:
- authentication до выполнения query;
- authorization в resolvers на object, field и mutation уровне;
- лимиты query depth, query complexity и operation count;
- запрет или строгая авторизация introspection и GraphiQL в рабочей среде;
- persisted queries или allowlisted operations для high-impact, public abuse-prone GraphQL API, если это совместимо с продуктом;
- лимиты batching и отдельная защита от brute force внутри одного запроса;
- timeout и cancellation propagation в downstream calls;
- schema ревью для sensitive fields и deprecated fields;
- persisted-query или operation allowlists версионируются вместе со schema и ревьюятся при изменении auth-relevant fields, resolvers или directives.

Рабочие настройки:
- максимальная query depth: `5-10` для публичных API, выше только по обоснованию;
- max operations per request: `1` по умолчанию для public API; batching только с явным лимитом;
- timeout resolver: `<=2-5s`, общий request timeout: `<=10-15s`;
- introspection disabled для anonymous/public clients; для внутренних клиентов - только с authenticated developer role;
- dynamic GraphQL queries допустимы для public API только с более строгим cost budget, per-client abuse monitoring и утвержденный владельцем exception; persisted queries не заменяют resolver authorization и меры контроля стоимости запросов.

### 6.4 Webhooks

Обязательные меры:
- проверяйте provider signature до parsing бизнес-payload;
- ограничивайте request body size до чтения всего payload в память;
- сохраняйте и проверяйте точный raw request body, который использует signature scheme провайдера, до JSON/XML/form parsing, normalization, decompression, charset conversion или изменения со стороны middleware;
- запрещайте compression/decompression webhook body, если provider явно не требует это в контракте;
- если compression требуется, задавайте decompression ratio limit и фиксируйте, над чем считается signature: compressed bytes или decompressed payload;
- документируйте provider-specific canonical string, signed fields, timestamp field, разрешенные algorithms, key identifier rules и логику выбора secret/certificate;
- сравнивайте signatures в constant time и отклоняйте unsigned, duplicate-signature, unknown-algorithm, unknown-key и malformed-signature cases;
- timestamp freshness window и replay cache по event ID/signature nonce;
- idempotent processing по provider event ID;
- быстрая приемка события и асинхронная обработка через queue;
- валидация схемы payload и максимальный размер;
- строгий content type и отклонение неизвестных типов событий;
- секреты webhook ротационно обновляются и хранятся в secrets manager;
- исходящие вызовы, запускаемые webhook payload, проходят SSRF-меры контроля.

Рабочие настройки:
- окно свежести timestamp: `<=5m`, если provider поддерживает timestamp;
- допустимый clock skew: `<=60s`, если provider не требует более узкое значение;
- срок хранения replay cache: минимум `24h` или больше максимального retry window провайдера;
- rotation secret/key использует явное overlap window: старый и новый ключ принимаются только на период provider retry window, затем старый ключ удаляется;
- HTTP response для принятого события: `2xx` только после проверки signature, freshness и schema;
- повторные попытки обработки: bounded exponential backoff + DLQ, без бесконечных retry loops.

Проверка:
- негативные тесты покрывают raw-body mutation со стороны framework/proxy middleware, invalid canonicalization, stale/future timestamps, wrong algorithm, wrong key ID, duplicate replay и overlap при rotation ключа.

### 6.5 gRPC

Обязательные меры:
- TLS для всех релизных channels; mTLS для service-to-service;
- workload identity или OAuth token в metadata, не учетные данные внутри message body;
- method-level authorization через interceptor/policy layer;
- максимальный размер получаемого/отправляемого сообщения;
- deadline/timeout на стороне клиента и сервера;
- server reflection выключен или доступен только authenticated developer/admin clients;
- protobuf schema compatibility checks в CI;
- structured audit events для privileged methods.

Рабочие настройки:
- plaintext gRPC допустим только в local development или изолированном тестовом контуре;
- максимальный размер получаемого сообщения: `4-16 MB` по умолчанию, больше только для documented streaming/file scenarios;
- server deadline для unary methods: `<=5s` для обычных операций, отдельный budget для long-running jobs;
- certificate lifetime для service identity: `<=90d` при автоматической ротации.

---

## 7. Базовые меры безопасности для API

### 7.1 Аутентификация

Рекомендации:
- Потоки browser/frontend: предпочтительно BFF + HttpOnly/Secure/SameSite cookie; не храните refresh token в browser storage.
- Public/partner API: OAuth 2.0 client учетные данные, authorization code + PKCE для user-delegated access или HMAC/request signing с timestamp, nonce, canonical request, key ID, replay cache, rotation и scoped access. Подписанный request без canonicalization и replay semantics считается bearer secret, а не полноценной защитой от replay/подмены.
- Service-to-service: workload identity + mTLS; не полагайтесь только на внутреннюю сеть.
- Webhooks: provider-specific signature scheme + timestamp/replay checks.

Проверка:
- тесты expired/invalid issuer/invalid audience token;
- проверка token validation в каждом resource server;
- подтверждения ротации API keys/client secrets/certificates;
- mTLS handshake failure для неизвестного клиента.

### 7.2 Авторизация

Рекомендации:
- authorization выполняется на уровне domain object/action, а не только на gateway route;
- каждая операция имеет явную политику: actor, action, resource, tenant и контекст (`context`);
- privileged operations отделены от обычных user operations;
- deny-by-default для новых endpoints, methods, mutations и типов webhook-событий.

Проверка:
- негативные тесты BOLA/BFLA/BOPLA;
- отчет о покрытии политики;
- audit events для allow/deny решений по sensitive actions.

### 7.3 Валидация ввода и применение схем

Рекомендации:
- валидируйте request body, path, query, headers и metadata;
- запрещайте unknown fields для write operations, если backward compatibility не требует обратного;
- нормализуйте ввод до authorization только там, где это не меняет security meaning;
- не передавайте user-controlled values в SQL/NoSQL/LDAP/OS/XML/URL без безопасных API и allowlist.

Проверка:
- schema validation tests;
- fuzz/negative tests для boundary values;
- тесты на инъекции для downstream interpreters.

### 7.4 Rate limiting и защита от злоупотреблений

Рекомендации:
- применяйте лимиты на нескольких ключах: IP, пользователь, client, tenant, token, API key, endpoint, business flow;
- отделяйте technical rate limit от business меры противодействия злоупотреблениям;
- для expensive operations используйте quota/cost model;
- 429 responses не должны раскрывать лишнюю информацию о других tenants или внутренних лимитах.

Проверка:
- нагрузочный тест 429 поведение;
- алерты по burst, sustained abuse, quota exhaustion;
- dashboard per-client/per-tenant API consumption.

### 7.5 Транспортная и сетевая безопасность

Рекомендации:
- HTTPS обязателен для всех API вне local development;
- TLS 1.3 по умолчанию; TLS 1.2 только с современной конфигурацией;
- HSTS для browser-facing HTTPS, если нет legacy constraints;
- egress policy для API, которые делают outbound calls по входным данным.

Проверка:
- TLS scan;
- запрет plaintext endpoints в инвентаре;
- egress deny tests для metadata IP, localhost, private ranges и запрещенных доменов.

### 7.6 Журналирование, аудит и обнаружение

Минимальные события:
- authentication success/failure;
- authorization deny для sensitive actions;
- admin и privileged operation;
- API key/client credential usage;
- rate-limit/quota decisions;
- webhook signature/replay failures;
- schema validation failures на public boundary;
- доступ к sensitive data и bulk export.

Минимальные поля:
- timestamp, actor, client ID, tenant ID, source IP, user agent или workload identity;
- API name, version, endpoint/method, action, resource type, resource ID или stable hash;
- decision, reason, status code, correlation ID, request ID;
- не логируйте tokens, secrets, необработанные учетные данные и sensitive payload без redaction.

Проверка:
- проверка примеров логов;
- правила обнаружения для auth failures, BOLA probing, quota abuse и webhook replay;
- трассировка request ID через gateway, service и datastore.

---

## 8. Схемы типовых интеграций

### 8.1 Браузер и frontend -> Backend REST API

```mermaid
flowchart LR
    U[Browser / SPA] -->|HTTPS, cookie session| B[BFF or Backend API]
    B -->|token or service identity| A[Resource API]
    A --> D[(Database)]
```

Основные угрозы:
- XSS приводит к API abuse в сессии пользователя;
- CSRF на state-changing endpoints;
- CORS misconfiguration;
- BOLA/BFLA на backend API;
- утечка access/refresh tokens в browser storage.

Обязательные меры контроля:
- BFF-паттерн или server-side session cookie с `HttpOnly`, `Secure`, `SameSite`;
- CSRF protection для `POST/PUT/PATCH/DELETE`: synchronizer token или signed double-submit cookie, привязанный к authenticated session через HMAC и server-side secret; naive double-submit cookies недопустимы;
- строгий список разрешенных origin без wildcard при передаче учетных данных;
- object-level authorization на backend;
- access token не доступен JavaScript, если используется BFF.

Проверка:
- CSRF negative tests без token/Origin, с несовпадающим token и с cookie injection/subdomain cookie сценариями;
- CORS preflight tests для forbidden origins;
- BOLA tests по object IDs;
- проверка browser storage на отсутствие refresh tokens.

### 8.2 Public REST API -> API Gateway -> Internal Services

```mermaid
flowchart LR
    C[External Client] -->|HTTPS + OAuth/API key| G[API Gateway]
    G -->|validated request| S[Internal Service]
    S --> D[(Data Store)]
    G --> L[Rate limit / WAF / API logs]
```

Основные угрозы:
- credential theft и replay;
- quota bypass;
- route shadowing и stale versions;
- excessive data exposure;
- SSRF через URL/import endpoints.

Обязательные меры контроля:
- authentication на gateway и validation в resource service для критичных API;
- per-client, per-tenant и per-endpoint quotas;
- OpenAPI-based request validation;
- response filtering в service layer;
- API inventory с владельцем, версией, классификацией данных и датой вывода из эксплуатации.

Проверка:
- invalid token/API key tests;
- тесты поведения при ответе `429`;
- сверка gateway routes с API catalog;
- SSRF tests для URL-bearing endpoints.

### 8.3 SOAP/XML Partner Integration

```mermaid
flowchart LR
    P[Partner System] -->|HTTPS/mTLS + SOAP| X[SOAP Gateway]
    X -->|validated XML| M[Integration Middleware]
    M --> E[Enterprise Backend]
```

Основные угрозы:
- XXE и XML bomb;
- signature wrapping;
- partner credential compromise;
- утечки через SOAP faults;
- legacy backend exposure.

Обязательные меры контроля:
- mTLS или эквивалентная strong client authentication;
- hardened XML parser до передачи в middleware;
- WSDL/XSD allowlist и контролируемые schema imports;
- SOAP fault redaction;
- network segmentation между SOAP gateway и backend.

Проверка:
- XXE/XML bomb test suite;
- invalid certificate test;
- signature wrapping negative tests;
- проверка примеров SOAP fault.

### 8.4 GraphQL Gateway -> Backend Services

```mermaid
flowchart LR
    C[Client] -->|HTTPS + session/token| Q[GraphQL Gateway]
    Q --> R[Resolvers]
    R --> S1[Service A]
    R --> S2[Service B]
    R --> D[(Database)]
```

Основные угрозы:
- утечка данных на уровне fields;
- expensive nested queries;
- batching brute force;
- SSRF/инъекции на уровне resolver;
- утечки через introspection.

Обязательные меры контроля:
- authn до execution;
- resolver-level authorization;
- лимиты depth/complexity/cost;
- persisted queries или allowlisted operations для high-risk public API;
- controlled introspection и disabled GraphiQL для public API в рабочей среде;
- downstream timeouts и cancellation.

Проверка:
- unauthorized field/node tests;
- complex query DoS tests;
- introspection tests anonymous/public clients;
- resolver timeout tests.

### 8.5 Webhook Provider -> Receiver -> Queue -> Worker

```mermaid
flowchart LR
    P[Webhook Provider] -->|HTTPS + signature| R[Webhook Receiver]
    R -->|validated event| Q[(Queue)]
    Q --> W[Worker]
    W --> S[Domain Service]
    R --> C[(Replay Cache)]
```

Основные угрозы:
- поддельное событие provider;
- replay;
- повторная обработка события;
- poison message;
- SSRF через последующее действие, запускаемое событием.

Обязательные меры контроля:
- проверка подписи до бизнес-разбора;
- timestamp window и replay cache;
- идемпотентность по event ID;
- асинхронная обработка и DLQ;
- валидация схемы и allowlist типов событий;
- allowlist исходящих URL и egress-меры контроля для последующих действий.

Проверка:
- invalid signature test;
- replay same event ID test;
- duplicate delivery idempotency test;
- поведение DLQ для проблемных сообщений;
- SSRF canary test.

### 8.6 Internal gRPC Service-to-Service

```mermaid
flowchart LR
    A[Service A] -->|gRPC over mTLS| B[Service B]
    B -->|policy check| P[Policy Engine]
    B --> D[(Data Store)]
    A --> O[Tracing / Metrics]
```

Основные угрозы:
- lateral movement после компрометации workload;
- отсутствующая method-level authorization;
- plaintext-трафик внутри internal network;
- reflection раскрывает service surface;
- streaming/message-size DoS.

Обязательные меры контроля:
- mTLS с workload identity;
- method-level authorization в interceptors;
- максимальный размер сообщения и длительность stream;
- ограниченный server reflection;
- deadlines на клиенте и сервере;
- protobuf compatibility gates в CI.

Проверка:
- тест с неизвестным client certificate;
- тест unauthorized method;
- тест доступа к reflection;
- тесты oversized message и long stream;
- CI-подтверждения проверок несовместимых изменений в proto.

### 8.7 Kubernetes ServiceAccount Token для межсервисной аутентификации

Этот паттерн подходит для сервисов в Kubernetes, когда кластер является доверенным issuer workload identity, а отдельный OAuth-сервер для межсервисных вызовов не требуется. Вызывающий workload передает короткоживущий projected ServiceAccount token, а принимающий сервис проверяет его через Kubernetes TokenReview API. Это только аутентификация workload: прикладная авторизация, защита канала и сетевой контроль остаются отдельными мерами.

```mermaid
flowchart LR
    K[Kubelet] -->|rotate projected token| A[Service A]
    A -->|TLS/mTLS + Bearer token| B[Service B]
    B -->|TokenReview with expected audience| KAPI[Kubernetes API]
    KAPI -->|identity + accepted audience| B
    B -->|method/resource policy| D[(Protected resource)]
```

Обязательные меры контроля:
- назначайте отдельный ServiceAccount каждому workload; не принимайте shared или namespace `default` ServiceAccount как service identity;
- монтируйте отдельный projected token с `audience`, соответствующей стабильной security boundary принимающего сервиса, и с коротким `expirationSeconds`; допустимый Kubernetes минимум равен `600` секундам;
- задавайте `automountServiceAccountToken: false`, если workload не нужен автоматически смонтированный токен для Kubernetes API, и явно монтируйте только требуемые token projections;
- передавайте токен как `Authorization: Bearer <token>` через TLS/mTLS; запрещайте его запись в application, proxy, tracing и error logs;
- принимающий сервис отправляет ожидаемую аудиторию в `TokenReview.spec.audiences` и принимает результат только при `status.authenticated: true` и наличии ожидаемого значения в `status.audiences`;
- проверяйте точный principal `system:serviceaccount:<namespace>:<service-account>` по deny-by-default allowlist; совпадение только namespace или группы `system:serviceaccounts` недостаточно;
- применяйте authorization на уровне method/action/resource/tenant после аутентификации. Kubernetes RBAC вызывающего ServiceAccount не предоставляет автоматически право на прикладную операцию;
- выдавайте принимающему workload собственную ClusterRole только с `create` на `tokenreviews.authentication.k8s.io`. Не используйте `system:auth-delegator`, если сервису не требуется также создавать `subjectaccessreviews`;
- читайте projected token заново после ротации или используйте библиотеку, отслеживающую обновление файла; не удерживайте значение токена бессрочно в памяти;
- ограничивайте east-west reachability через NetworkPolicy или эквивалентную CNI policy. Audience-bound bearer token не заменяет mTLS и может быть повторно использован против той же аудитории до expiry, если его похитили.

Доступность и производительность:
- задавайте короткий timeout для TokenReview, ограниченные retry с jitter и явный отказ в доступе при ошибке проверки защищенных операций;
- мониторьте latency, error rate, throttling и объем TokenReview относительно лимитов и SLO control plane;
- positive cache не должен жить дольше оставшегося срока токена. Учитывайте, что cache откладывает эффект удаления Pod или ServiceAccount;
- offline JWT validation через OIDC discovery/JWKS допустима после отдельного threat-model решения: она снимает синхронную зависимость от kube-apiserver, но удаленный Pod или ServiceAccount не отзывает уже выданный токен до его `exp`.

Проверка:
- valid token от разрешенного ServiceAccount и с ожидаемой аудиторией принимается;
- wrong audience, expired token, invalid signature и токен другого cluster issuer отклоняются;
- валидный token от неразрешенного ServiceAccount аутентифицируется, но получает authorization deny;
- отсутствие ожидаемой аудитории в `TokenReview.status.audiences` приводит к deny даже при `status.authenticated: true`;
- удаление связанного Pod или ServiceAccount приводит к отказу TokenReview; отдельно проверяется максимальная задержка локального cache;
- отказ, timeout и throttling Kubernetes API не приводят к fail-open;
- ротация projected token не прерывает штатные межсервисные вызовы, а redaction tests подтверждают отсутствие токена в логах и traces.

---

## 9. Чеклист релизного ревью

| Проверка | Подтверждение |
|---|---|
| У API есть владелец, модель экспозиции, классификация данных и статус жизненного цикла | Запись в API catalog |
| Модель аутентификации явно описана и актуальна | Конфиг IdP/gateway/service, тесты валидации токенов |
| Авторизация покрывает уровень объекта, свойства и функции | Матрица политики, негативные тесты |
| Контракт существует и совпадает с runtime routes | OpenAPI/WSDL/proto/schema, diff маршрутов gateway |
| Валидация ввода покрывает body, path, query, headers и metadata | Schema tests, validator config |
| Лимиты ресурсов заданы явно | Конфиг payload/page/query/message/timeout/rate limit |
| Чувствительные бизнес-потоки имеют abuse-меры контроля | Velocity rules, quota dashboards, fraud/abuse alerts |
| Webhook endpoints проверяют подпись и replay | Тесты invalid signature/replay |
| XML parsers захарднены там, где принимается XML | Parser config, XXE tests |
| GraphQL имеет меры контроля depth/complexity/field authorization | GraphQL security tests |
| gRPC использует TLS/mTLS и method authz | mTLS config, interceptor tests |
| Kubernetes ServiceAccount authentication ограничена audience и явным allowlist вызывающих workload | Projected volume manifest, минимальный TokenReview RBAC, negative tests wrong audience/wrong ServiceAccount/control-plane failure |
| Логи помогают расследованию и не раскрывают секреты | Примеры логов, redaction tests |
| Deprecated versions заблокированы или отслеживаются | Deprecation policy, traffic report |

---

## 10. Матрица решения ревью

Используйте эту матрицу для API-замечаний перед релизом. Она дополняет release governance: если замечание здесь блокирует release, exception должен проходить через процесс release governance с владельцем, сроком действия, компенсирующими мерами и подтверждением проверки. Для общего SLA, lifecycle исключений и подтверждений закрытия по scanner замечания используйте [плейбук управления уязвимостями](../../../review/vulnerability-management/playbook.ru.md).

| Severity | Когда использовать | Обязательное действие |
|---|---|---|
| Critical | BOLA/BFLA или обход авторизации на уровне свойств раскрывает межтенантные данные, административные действия, состояние платежей или ledger, секреты либо массовый экспорт; подмена или повтор webhook может запустить финансовые операции, изменение учетной записи или привилегированного состояния; ошибка XML-парсера дает чтение файлов, SSRF к metadata/control plane или RCE; обход GraphQL resolver раскрывает чувствительные поля tenant или администратора; открытый текст или отсутствие аутентификации в gRPC раскрывает высокоценные межсервисные операции | Блокировать релиз до исправления; исключение требует согласования руководителя функции безопасности и владельца бизнеса |
| High | Public или partner API имеет reachable object/function authorization gap; меры проверки подписи webhook, timestamp, replay или идемпотентности неполны для sensitive events; GraphQL не имеет resolver-level authorization или cost limits на public/high-risk API; SOAP/XML parser hardening отсутствует, но impact bounded; gRPC не имеет mTLS или method authorization для sensitive internal methods | Владелец, срок, устранение или accepted risk и подтверждения negative tests |
| Medium | API inventory, schema validation, rate limits, меры контроля introspection/reflection, logging или lifecycle deprecated versions неполны при bounded exposure и компенсирующие меры | Отслеживать исправление и проверить закрытие |
| Low | Documentation, contract hygiene, non-sensitive logging improvement или hardening issue с ограниченным direct impact | Исправить при ближайшей возможности |

Обязательный результат ревью:
- affected API style, route/method/event/RPC, exposure model и data class;
- attacker preconditions и impact;
- required fix или compensating control;
- negative test или runtime подтверждения, доказывающие closure;
- владелец, срок и решение по остаточному риску.
---

## 11. Связанные материалы

- [Плейбук OIDC + OAuth 2.0](../../identity/oidc-oauth/playbook.ru.md)
- [Плейбук безопасности браузера и frontend-части](../../web/browser-security/playbook.ru.md)
- [Плейбук злоупотребления бизнес-логикой](../../business-logic/business-logic-abuse/playbook.ru.md)
- [Плейбук моделирования угроз](../../../review/threat-modeling/playbook.ru.md)
- [Плейбук безопасности MCP](../../../ai-security/mcp-security/playbook.ru.md)
- [Плейбук безопасности Agentic AI](../../../ai-security/agentic-ai/playbook.ru.md)
