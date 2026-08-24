---
title: "Плейбук безопасности MCP"
description: "Этот плейбук покрывает использование Model Context Protocol (MCP) в рабочих средах, где AI-приложения обнаруживают или вызывают tools, resources и reusable prompts через локальн..."
sidebar:
  order: 40
---
## 1. Область и цель

Этот плейбук покрывает использование Model Context Protocol (MCP) в рабочих средах, где AI-приложения обнаруживают или вызывают tools, resources и reusable prompts через локальные или удаленные MCP servers.

Используйте этот документ для:
- ревью архитектуры MCP перед использованием в рабочей среде;
- onboarding внутренних и third-party MCP servers;
- ревью MCP gateways, OAuth flows, tool wrappers, resource exposure и prompt templates;
- подготовки negative tests для tool execution, authorization, logging и capability drift.

Ответственность документа:
- Этот плейбук отвечает за MCP protocol схемы развертывания, registry для servers/tools/resources/prompts, capability baselines, transport choices, MCP-specific OAuth usage, gateway policy, protocol logging и меры контроля дрейфа capability.
- Tool abuse и data leakage рассматриваются здесь через границу MCP: процесс утверждения server, capability negotiation, resource exposure, token handling и контроль downstream destinations.
- Общий AI control baseline находится в [обзоре безопасности AI](/Product-security-playbook/ru/ai-security/securing-ai/overview/), а автономия agents, memory, action traces, согласования, rollback и kill switches — в [плейбуке безопасности Agentic AI](/Product-security-playbook/ru/ai-security/agentic-ai/playbook/).
- [Обзор OWASP LLM Top 10](/Product-security-playbook/ru/ai-security/owasp-llm-top-10/overview/) используется как таксономия угроз, а не как checklist развертывания.

Вне области:
- общее поведение моделей, prompt injection, RAG и AI release governance; используйте [обзор безопасности AI](/Product-security-playbook/ru/ai-security/securing-ai/overview/);
- основы OAuth/OIDC вне MCP-specific usage; используйте [плейбук OIDC + OAuth 2.0](/Product-security-playbook/ru/application-security/identity/oidc-oauth/playbook/);
- generic API hardening для downstream business APIs; используйте [плейбук безопасности API](/Product-security-playbook/ru/application-security/api/api-security-patterns/playbook/).

Цель:
- сделать каждую MCP capability явной, авторизованной, наблюдаемой и быстро отключаемой до того, как она сможет повлиять на production data или business state.

---

## 2. Границы доверия MCP

Минимальные компоненты для моделирования:
- host: AI-приложение или IDE/client, где встроен MCP client;
- client: protocol component, который подключается к MCP servers;
- server: локальный или удаленный процесс, который предоставляет tools, resources и prompts;
- gateway: optional, но recommended control point для рабочей среды;
- downstream systems: APIs, databases, filesystems, browsers, queues, SaaS и identity providers, к которым обращаются tools.

MCP primitives сами являются security surfaces:
- tools являются callable operations и должны рассматриваться как APIs;
- resources являются data access paths и наследуют classification исходных данных;
- prompts являются content supply-chain inputs и не должны считаться политикой или секретами;
- sampling позволяет server запрашивать model completions через client и должен быть отключен, если нет проверенного use case.

Сценарии с высоким воздействием:
- локальный `stdio` server, установленный разработчиком, открывает file или shell access агенту, который может работать с production;
- remote server незаметно добавляет write tool или широкий resource pattern после первоначального согласования;
- model-supplied parameter доходит до privileged backend, потому что tool handler доверяет schema hints вместо server-side validation;
- OAuth tokens утекают через logs, prompts, resource payloads или token passthrough в downstream APIs;
- third-party MCP server меняет поведение, dependencies или capability declarations без enterprise ревью.

---

## 3. Базовый профиль для рабочих сред

### 3.1 MCP Registry

`Baseline`:
- Ведите enterprise MCP registry как authoritative inventory для production-approved servers, tools, resources, prompts, transports, владельцы, environments, scopes, downstream destinations и срок пересмотра.
- Фиксируйте capability baseline для каждого server: tool names, descriptions, input schemas, resource URI patterns, prompt identifiers, transport, authentication mode, package/artifact identity и expected logging fields.
- Рассматривайте любой новый tool, resource, prompt, schema expansion, resource pattern expansion, transport change или authorization change как security-relevant change.
- Политика по умолчанию для unregistered или changed capabilities: `deny`.

`High-impact/regulated`:
- Требуйте signed artifacts или pinned digests для MCP servers и tool wrappers.
- Зеркалируйте approved third-party MCP artifacts во внутренний registry или package mirror; production hosts не должны устанавливать компоненты напрямую из community registries.
- Устанавливайте срок пересмотра не дольше `90 days` для servers, которые могут изменять данные, выполнять code, получать sensitive resources или использовать third-party infrastructure.

Проверка:
- сравнивайте runtime capability negotiation с registry baseline;
- настройте alerts на `listChanged` events, unknown servers, unknown tools, schema drift и resource pattern expansion;
- выборочно проверяйте production sessions и подтверждайте, что каждый tool call связан с approved registry entry.

### 3.2 Схемы развертывания

Предпочтительный production pattern:
- Используйте gateway-mediated развертывание для remote MCP там, где это возможно. Gateway должен принудительно применять список разрешенных MCP servers, user/workload authorization, capability filtering, redaction, журналирование аудита, egress policy, rate limits и emergency disablement.

Local `stdio` servers:
- Разрешайте только утвержденные server binaries/scripts через endpoint management или application allowlisting.
- Запускайте server с минимально привилегированной OS identity, достаточной для workflow.
- Явно ограничивайте filesystem roots; не выдавайте home-directory или repository-wide access по умолчанию.
- Ведите список разрешенных environment variables для каждого server и блокируйте переменные с учетными данными без явного согласования.
- Блокируйте outbound network access от local servers, если server не требует его и destination не утвержден.

Remote Streamable HTTP servers:
- Требуйте TLS для всего traffic.
- Используйте управляемую организацией авторизацию, согласованную с текущим профилем авторизации MCP: требования проекта OAuth 2.1, обязательные для MCP метаданные, параметр `resource` и проверки аудитории токена.
- Требуйте PKCE с `S256` для public clients.
- Публикуйте OAuth Protected Resource Metadata и возвращайте `WWW-Authenticate` на `401`, чтобы clients обнаруживали правильный authorization server от MCP server, а не из user-supplied configuration.
- Если поддерживается Dynamic Client Registration, ограничивайте его registration policy: утвержденные redirect URI patterns, client type, grant types, scopes, token lifetimes и владелец. Для high-impact или regulated MCP clients предпочитайте pre-registered enterprise clients; не разрешайте self-service registration выдавать broad scopes или refresh tokens без ревью.
- Требуйте, чтобы MCP clients передавали OAuth `resource` parameter и в authorization request, и в token request, используя canonical MCP server URI.
- Требуйте, чтобы MCP clients или gateway валидировали `iss` в authorization response, когда authorization server публикует `authorization_response_iss_parameter_supported=true`; если `iss` присутствует без объявления в metadata, отклоняйте response, кроме явно принятого local policy issuer, и все равно сравнивайте значение с issuer из проверенного authorization server metadata document.
- Проверяйте token issuer, expiry, audience/resource binding, resource indicator и scope на каждом request.
- Не передавайте client access tokens дальше в downstream APIs. Tool handlers должны получать отдельные учетные данные для downstream-систем или использовать controlled token exchange pattern, утвержденный владельцами identity/security.
- Не включайте `offline_access` или выдачу refresh token в базовый профиль MCP resource server. Если утвержденный клиент получает refresh token, токен должен быть sender-constrained либо ротироваться с обнаружением повторного использования; хранение и отзыв остаются отдельными мерами управления идентичностью. MCP-сервер не должен запрашивать или рекламировать `offline_access` через challenge `WWW-Authenticate` или `scopes_supported` в Protected Resource Metadata без явно утвержденного сценария использования.

Third-party MCP servers:
- Требуйте provider onboarding до использования: data handling, subprocessors, security contact, vulnerability disclosure, patch SLA, log access, retention, capability-change notification и exit process.
- Утверждайте server для конкретного environment и use case; согласование для development не означает согласование для production.

### 3.3 Меры контроля для Tools, Resources и Prompts

Tools:
- Принудительно применяйте server-side validation для всех tool parameters, включая type, size, enum, path, URL, identifier и business state constraints.
- Применяйте object-level, tenant-level и action-level authorization внутри tool handler или gateway; не выводите authorization из model intent или natural-language instructions.
- Разделяйте read и write operations на разные tools с отдельными scopes и политики согласования.
- Требуйте `preview -> explicit confirm -> execute` для state-changing tools, если исключение не утверждено с владельцем, expiry, rollback plan и abuse-case tests.

Resources:
- Ограничивайте resource URI patterns до минимально нужной области.
- Применяйте classification, RBAC/ABAC, tenant isolation, DLP/redaction и журналирование аудита до того, как resource content попадает в model context.
- Считайте externally sourced или user-controlled resource content недоверенным и проверяйте на indirect prompt injection перед использованием.

Prompts:
- Версионируйте MCP prompts и ревьюйте их как code/configuration.
- Не храните secrets, учетные данные, hidden policy assumptions, customer data или proprietary implementation details в prompt declarations.
- По умолчанию логируйте prompt identifier и version, а не raw prompt text.

Sampling:
- Держите sampling отключенным по умолчанию.
- Если sampling включен, ограничьте его утвержденными servers, утвержденными model endpoints, maximum prompt size и redacted/minimized logs.
- Настройте alerts на repeated near-duplicate sampling requests, необычный prompt size или sensitive data classes в sampling payloads.

### 3.4 Logging и Incident Readiness

Логируйте минимум:
- authenticated user или workload identity;
- host, client, server, gateway, transport и environment;
- tool/resource/prompt identifier и version;
- scopes и policy decision;
- request ID/session ID/correlation ID;
- downstream destination и result class;
- redaction status и denial reason, где применимо.

Не логируйте по умолчанию:
- raw access tokens или refresh tokens;
- full prompt/context/resource payloads;
- secrets, private keys, session cookies или full sensitive documents.

Raw payload capture допустим только в scoped forensic mode с согласование, case ID, encryption, restricted access, retention `<=30 days` и подтверждением удаления.

Incident response должен поддерживать:
- независимое отключение server, gateway route, tool, resource, prompt, OAuth client, OAuth grant и учетных данных downstream-систем;
- freeze MCP registry на время active investigation;
- ротацию учетных данных, которые используются affected tool handlers;
- восстановление action timeline по gateway, server, IdP и downstream logs;
- graceful failure для dependent workflows, когда tool или server отключен.

---

## 4. Проверка

Обязательные подтверждения:
- MCP registry entry для каждого production server и capability;
- capability baseline diff из развертывание или session initialization;
- OAuth Protected Resource Metadata, authorization server metadata, поведение `WWW-Authenticate`, обработка `resource` parameter и token validation tests для remote servers;
- Dynamic Client Registration policy или подтверждение, что production MCP clients pre-registered и self-service registration отключен/ограничен;
- подтверждение endpoint/application allowlisting для local `stdio` servers;
- gateway policy, redaction и logging configuration;
- provider onboarding record для third-party servers.

Negative tests:
- unregistered server блокируется;
- registered server с новым tool или более широким resource URI pattern блокируется до согласования;
- model-supplied parameter вне schema или business constraints отклоняется server-side;
- expired, wrong-audience, wrong-issuer или insufficient-scope token отклоняется;
- отсутствующий или неправильный OAuth `resource` parameter отклоняется либо не позволяет получить token, пригодный для MCP server;
- authorization response с missing/mismatched `iss` отклоняется MCP client или gateway в соответствии с metadata выбранного authorization server;
- выдача refresh token или `offline_access` не запрашивается, не требуется и не рекламируется без утвержденного use case;
- token в query string, log field, tool output или prompt payload обнаруживается и блокируется/редактируется;
- write tool не выполняется без required confirmation или согласование;
- malformed JSON-RPC messages fail closed и дают safe errors;
- local `stdio` server не может читать вне declared roots или наследовать unapproved environment variables.

Операционные сигналы:
- доля MCP servers с registry baseline;
- доля tool calls, evaluated by gateway или policy layer;
- alerts по capability drift, unknown servers, abnormal tool sequences и redaction failures;
- mean time to disable server/tool during drills, target `<=60s` для high-impact capabilities;
- provider log export latency и completeness для third-party servers.

---

## 5. Решение по результатам ревью

Матрица ниже определяет доменную критичность замечания и решение о релизе. Общие SLA устранения, жизненный цикл исключений, принятие риска и подтверждения закрытия определяет [плейбук управления уязвимостями](/Product-security-playbook/ru/review/vulnerability-management/playbook/); при пересечении требований применяется более строгое.

| Severity | MCP condition | Обязательное действие |
|---|---|---|
| Critical | Unapproved MCP server может выполнять code, менять production data, получать secrets или обращаться к sensitive internal systems | Блокировать релиз или немедленно отключить доступ |
| Critical | Remote MCP token validation принимает wrong issuer/audience/expiry или разрешает token passthrough в downstream APIs | Блокировать релиз до исправления и повторной проверки |
| High | Capability drift не обнаруживается или новые tools/resources становятся доступными без согласования | Блокировать high-impact workflows; разрешать только read-only low-risk use с compensating monitoring |
| High | Tool handler полагается на model/client-side validation для privileged parameters | Исправить до production для state-changing или sensitive-data tools |
| Medium | Реестр существует, но в нем нет владельца, срока пересмотра или метаданных downstream-направления | Назначить владельца и срок устранения |
| Medium | Logs поддерживают operations, но не позволяют восстановить identity-to-tool-to-downstream action chain | Улучшить до широкого rollout |
| Low | Naming, descriptions или prompt metadata inconsistent, но access не расширяется | Исправить opportunistically |

Релиз считается одобренным только когда каждая production MCP capability зарегистрирована, ограничена scope, авторизована, логируется и может быть отключена независимо от остальных capabilities.

---

## 6. Связанные материалы

- [Обзор безопасности AI](/Product-security-playbook/ru/ai-security/securing-ai/overview/)
- [Плейбук безопасности Agentic AI](/Product-security-playbook/ru/ai-security/agentic-ai/playbook/)
- [Плейбук моделирования угроз](/Product-security-playbook/ru/review/threat-modeling/playbook/)
- [Плейбук безопасности API](/Product-security-playbook/ru/application-security/api/api-security-patterns/playbook/)
- [Плейбук OIDC + OAuth 2.0](/Product-security-playbook/ru/application-security/identity/oidc-oauth/playbook/)
