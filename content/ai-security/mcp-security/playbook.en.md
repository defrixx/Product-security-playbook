# MCP Security Playbook

## 1. Scope and Objective

This playbook covers production use of Model Context Protocol (MCP) where AI applications discover or invoke tools, resources, or reusable prompts through local or remote MCP servers.

Use this document for:
- MCP architecture review before production use;
- onboarding internal and third-party MCP servers;
- reviewing MCP gateways, OAuth flows, tool wrappers, resource exposure, and prompt templates;
- building negative tests for tool execution, authorization, logging, and capability drift.

Document ownership:
- This playbook owns MCP protocol deployment patterns, server/tool/resource/prompt registry, capability baselines, transport choices, MCP-specific OAuth usage, gateway policy, protocol logging, and capability drift controls.
- It treats tool abuse and data leakage through the MCP boundary: server approval, capability negotiation, resource exposure, token handling, and downstream destination control.
- It relies on [Securing AI](../securing-ai/overview.en.md) for the general AI control baseline and on the [Agentic AI security playbook](../agentic-ai/playbook.en.md) for agent autonomy, memory, action traces, approvals, rollback, and kill switches.
- It uses the [OWASP LLM Top 10 overview](../owasp-llm-top-10/overview.en.md) for threat taxonomy, not as a deployment checklist.

Out of scope:
- general model behavior, prompt injection, RAG, and AI release governance; use the [Securing AI overview](../securing-ai/overview.en.md);
- OAuth/OIDC fundamentals outside MCP-specific usage; use the [OIDC + OAuth 2.0 security guide](../../application-security/identity/oidc-oauth/playbook.en.md);
- generic API hardening for downstream business APIs; use the [API security playbook](../../application-security/api/api-security-patterns/playbook.en.md).

Objective:
- make every MCP capability explicit, authorized, observable, and revocable before it can affect production data or business state.

---

## 2. MCP Trust Boundaries

Minimum components to model:
- host: AI application or IDE/client that embeds an MCP client;
- client: protocol component that connects to MCP servers;
- server: local or remote process exposing tools, resources, and prompts;
- gateway: optional but recommended control point for production;
- downstream systems: APIs, databases, filesystems, browsers, queues, SaaS, and identity providers reached by tools.

MCP primitives are security surfaces:
- tools are callable operations and must be treated as APIs;
- resources are data access paths and inherit the classification of the underlying data;
- prompts are content supply-chain inputs and must not be trusted as policy or secrets;
- sampling lets a server request model completions through a client and should be disabled unless there is a reviewed use case.

High-impact scenarios:
- a local `stdio` server installed by a developer exposes file or shell access to a production-capable agent;
- a remote server silently adds a write tool or broad resource pattern after initial approval;
- a model-supplied parameter reaches a privileged backend because the tool handler trusts schema hints instead of enforcing server-side validation;
- OAuth tokens leak through logs, prompts, resource payloads, or token passthrough to downstream APIs;
- a third-party MCP server changes behavior, dependencies, or capability declarations without enterprise review.

---

## 3. Production Baseline

### 3.1 MCP Registry

`Baseline`:
- Maintain an enterprise MCP registry as the authoritative inventory for production-approved servers, tools, resources, prompts, transports, owners, environments, scopes, downstream destinations, and review expiry.
- Record a capability baseline for every server: tool names, descriptions, input schemas, resource URI patterns, prompt identifiers, transport, authentication mode, package/artifact identity, and expected logging fields.
- Treat any new tool, resource, prompt, schema expansion, resource pattern expansion, transport change, or authorization change as a security-relevant change.
- Default policy for unregistered or changed capabilities is `deny`.

`High-impact/regulated`:
- Require signed artifacts or pinned digests for MCP servers and tool wrappers.
- Mirror approved third-party MCP artifacts into an internal registry or package mirror; production hosts should not install directly from community registries.
- Set review expiry no longer than `90 days` for servers that can modify data, execute code, access sensitive resources, or use third-party infrastructure.

Verification:
- compare runtime capability negotiation against the registry baseline;
- alert on `listChanged` events, unknown servers, unknown tools, schema drift, and resource pattern expansion;
- sample production sessions and confirm every tool call maps to an approved registry entry.

### 3.2 Deployment Patterns

Preferred production pattern:
- Use a gateway-mediated deployment for remote MCP wherever possible. The gateway should enforce server allowlists, user/workload authorization, capability filtering, redaction, audit logging, egress policy, rate limits, and emergency disablement.

Local `stdio` servers:
- Allow only approved server binaries/scripts through endpoint management or application allowlisting.
- Run with the least privileged OS identity available for the workflow.
- Restrict filesystem roots explicitly; do not grant home-directory or repository-wide access by default.
- Maintain an allowlist of environment variables exposed to each server and block credential-bearing variables unless explicitly approved.
- Block outbound network access from local servers unless the server requires it and the destination is approved.

Remote Streamable HTTP servers:
- Require TLS for all traffic.
- Use enterprise-managed authorization aligned with the current MCP authorization profile: OAuth 2.1 draft behavior plus the MCP-required metadata, `resource` parameter, and token audience checks.
- Require PKCE with `S256` for public clients.
- Publish OAuth Protected Resource Metadata and return `WWW-Authenticate` on `401` so clients discover the correct authorization server from the MCP server, not from user-supplied configuration.
- If Dynamic Client Registration is supported, constrain it with a registration policy: approved redirect URI patterns, client type, grant types, scopes, token lifetimes, and owner. For high-impact or regulated MCP clients, prefer pre-registered enterprise clients; do not allow self-service registration to issue broad scopes or refresh tokens without review.
- Require MCP clients to send the OAuth `resource` parameter in both authorization and token requests, using the canonical MCP server URI.
- Require MCP clients or the gateway to validate `iss` in authorization responses when the authorization server publishes `authorization_response_iss_parameter_supported=true`; if `iss` is present without metadata advertisement, reject it unless local policy explicitly accepts that issuer, and still compare it with the issuer from the validated authorization server metadata document.
- Validate token issuer, expiry, audience/resource binding, resource indicator, and scope on every request.
- Do not pass client access tokens through to downstream APIs. Tool handlers must obtain separate downstream credentials or use a controlled token exchange pattern approved by identity/security owners.
- Do not make `offline_access` or refresh-token issuance part of the MCP resource-server baseline. If an approved client receives a refresh token, it must be sender-constrained or rotated with reuse detection; storage and revocation are separate identity controls. The MCP server must not request or advertise `offline_access` through `WWW-Authenticate` challenges or Protected Resource Metadata `scopes_supported` without an explicitly approved use case.

Third-party MCP servers:
- Require provider onboarding before use: data handling, subprocessors, security contact, vulnerability disclosure, patch SLA, log access, retention, capability-change notification, and exit process.
- Approve the server for a specific environment and use case; approval for development does not imply production approval.

### 3.3 Tool, Resource, and Prompt Controls

Tools:
- Enforce server-side validation for all tool parameters, including type, size, enum, path, URL, identifier, and business state constraints.
- Apply object-level, tenant-level, and action-level authorization inside the tool handler or gateway; never infer authorization from model intent or natural-language instructions.
- Split read and write operations into separate tools with separate scopes and approval policies.
- Require `preview -> explicit confirm -> execute` for state-changing tools unless the exception is approved with owner, expiry, rollback plan, and abuse-case tests.

Resources:
- Restrict resource URI patterns to the narrowest required scope.
- Apply classification, RBAC/ABAC, tenant isolation, DLP/redaction, and audit logging before resource content enters model context.
- Treat externally sourced or user-controlled resource content as untrusted and scan for indirect prompt injection before use.

Prompts:
- Version MCP prompts and review them as code/configuration.
- Do not store secrets, credentials, hidden policy assumptions, customer data, or proprietary implementation details in prompt declarations.
- Log prompt identifier and version, not raw prompt text by default.

Sampling:
- Keep sampling disabled by default.
- If enabled, restrict it to approved servers, approved model endpoints, maximum prompt size, and redacted/minimized logs.
- Alert on repeated near-duplicate sampling requests, unusual prompt size, or sensitive data classes in sampling payloads.

### 3.4 Logging and Incident Readiness

Log at minimum:
- authenticated user or workload identity;
- host, client, server, gateway, transport, and environment;
- tool/resource/prompt identifier and version;
- scopes and policy decision;
- request ID/session ID/correlation ID;
- downstream destination and result class;
- redaction status and denial reason where applicable.

Do not log by default:
- raw access tokens or refresh tokens;
- full prompt/context/resource payloads;
- secrets, private keys, session cookies, or full sensitive documents.

Raw payload capture is allowed only in scoped forensic mode with approval, case ID, encryption, restricted access, retention `<=30 days`, and deletion evidence.

Incident response must support:
- disabling a server, gateway route, tool, resource, prompt, OAuth client, OAuth grant, and downstream credential independently;
- freezing the MCP registry during active investigation;
- rotating credentials used by affected tool handlers;
- reconstructing an action timeline from gateway, server, IdP, and downstream logs;
- failing dependent workflows gracefully when a tool or server is disabled.

---

## 4. Verification

Required evidence:
- MCP registry entry for every production server and capability;
- capability baseline diff from deployment or session initialization;
- OAuth Protected Resource Metadata, authorization server metadata, `WWW-Authenticate` behavior, `resource` parameter handling, and token validation tests for remote servers;
- Dynamic Client Registration policy or evidence that production MCP clients are pre-registered and self-service registration is disabled/constrained;
- endpoint/application allowlisting evidence for local `stdio` servers;
- gateway policy, redaction, and logging configuration;
- provider onboarding record for third-party servers.

Negative tests:
- unregistered server is blocked;
- registered server with a new tool or wider resource URI pattern is blocked until approved;
- model-supplied parameter outside schema or business constraints is rejected server-side;
- expired, wrong-audience, wrong-issuer, or insufficient-scope token is rejected;
- missing or wrong OAuth `resource` parameter is rejected or fails to obtain a token usable for the MCP server;
- authorization response with missing or mismatched `iss` is rejected by the MCP client or gateway according to authorization server metadata;
- refresh token issuance or `offline_access` is not requested, required, or advertised without an approved use case;
- token in query string, log field, tool output, or prompt payload is detected and blocked/redacted;
- write tool cannot execute without required confirmation or approval;
- malformed JSON-RPC messages fail closed and produce safe errors;
- local `stdio` server cannot read outside declared roots or inherit unapproved environment variables.

Operational signals:
- percentage of MCP servers covered by registry baseline;
- percentage of tool calls evaluated by gateway or policy layer;
- alerts for capability drift, unknown servers, abnormal tool sequences, and redaction failures;
- mean time to disable a server/tool during drills, target `<=60s` for high-impact capabilities;
- provider log export latency and completeness for third-party servers.

---

## 5. Review Decision

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](../../review/vulnerability-management/playbook.en.md) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | MCP condition | Required action |
|---|---|---|
| Critical | Unapproved MCP server can execute code, modify production data, access secrets, or reach sensitive internal systems | Block release or disable access immediately |
| Critical | Remote MCP token validation accepts wrong issuer/audience/expiry or permits token passthrough to downstream APIs | Block release until fixed and retested |
| High | Capability drift is not detected or new tools/resources become usable without approval | Block high-impact workflows; approve only read-only low-risk use with compensating monitoring |
| High | Tool handler relies on model/client-side validation for privileged parameters | Fix before production for state-changing or sensitive-data tools |
| Medium | Registry exists but lacks owner, review expiry, or downstream destination metadata | Track remediation with owner and due date |
| Medium | Logs support operations but cannot reconstruct identity-to-tool-to-downstream action chains | Improve before broad rollout |
| Low | Naming, descriptions, or prompt metadata are inconsistent but do not expand access | Fix opportunistically |

Release is approved only when every production MCP capability is registered, scoped, authorized, logged, and independently revocable.

---

## 6. Related Materials

- [Securing AI overview](../securing-ai/overview.en.md)
- [Agentic AI security playbook](../agentic-ai/playbook.en.md)
- [Threat modeling playbook](../../review/threat-modeling/playbook.en.md)
- [API security playbook](../../application-security/api/api-security-patterns/playbook.en.md)
- [OIDC + OAuth 2.0 security guide](../../application-security/identity/oidc-oauth/playbook.en.md)
