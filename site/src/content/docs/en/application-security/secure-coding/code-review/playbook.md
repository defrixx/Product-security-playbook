---
title: "Secure Coding and Code Review Playbook"
description: "This playbook covers code-level security review for application changes: input validation, output encoding, authentication/session implementation, access control, injection, fil..."
sidebar:
  order: 50
---
## 1. Scope and Objective

This playbook covers code-level security review for application changes: input validation, output encoding, authentication/session implementation, access control, injection, file handling, logging, cryptography use, dependency use, and review evidence.

This playbook is the canonical owner of the generic SAST, SCA, and secret-scanning baseline: required execution, result handling, post-fix reruns, and closure evidence. Domain playbooks refine applicability, additional analyzers, and thresholds for their system class without redefining this baseline.

Use it when reviewing:
- new endpoints, background jobs, parsers, integrations, and data-processing paths;
- changes to authentication, authorization, session, password, token, or identity logic;
- code that handles files, external URLs, templates, queries, shell commands, secrets, or cryptographic operations;
- fixes for SAST, DAST, SCA, pentest, bug bounty, or incident findings.

Out of scope:
- abuse of intended product behavior: use the [Business Logic Abuse playbook](/Product-security-playbook/en/application-security/business-logic/business-logic-abuse/playbook/);
- OAuth/OIDC protocol and token architecture: use the [OIDC + OAuth 2.0 security guide](/Product-security-playbook/en/application-security/identity/oidc-oauth/playbook/);
- browser-only controls such as CSP, CORS, cookies, and frontend supply chain: use the [browser and frontend security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/);
- API protocol patterns across REST, SOAP/XML, GraphQL, Webhooks, and gRPC: use the [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/).

Objective:
- make code review decisions concrete and testable;
- catch vulnerabilities before release without turning review into a generic checklist ritual;
- preserve enough evidence that a finding, fix, and residual risk can be reconstructed later.

---

## 2. Threat Model

Assets:
- user data, tenant data, credentials, sessions, tokens, secrets, business state, logs, files, configuration, and downstream systems reached by the application.

Attackers and entry points:
- unauthenticated users sending crafted HTTP/API requests;
- authenticated users changing object IDs, tenant IDs, workflow states, filters, sort keys, or role-sensitive inputs;
- partner systems, webhooks, message queues, file uploads, imported documents, and third-party APIs;
- compromised dependencies, malicious packages, leaked secrets, and build-time inputs.

High-impact scenarios:
- user-controlled input reaches an interpreter: SQL, NoSQL, LDAP, XML, template engine, OS shell, browser, deserializer, or expression evaluator;
- missing object authorization exposes another tenant's data;
- weak session or token handling allows replay, fixation, privilege escalation, or post-logout use;
- uploaded files become executable content, malware transport, SSRF helpers, or stored XSS payloads;
- logs, errors, traces, or analytics leak secrets and regulated data.

---

## 3. Release-Ready Baseline

### 3.1 Input Validation and Canonicalization

Release-ready defaults:
- Validate all untrusted input on the server side before business logic, persistence, query construction, or calls to downstream systems.
- Define expected type, length, format, charset, range, enum, and object ownership for each externally controlled field.
- Canonicalize encoded input before validation where multiple encodings or path formats are accepted.
- Prefer allowlists for identifiers, enum values, sort keys, fields, redirect targets, callback URLs, MIME types, and file extensions.
- Reject validation failures by default. Silent normalization is acceptable only when the product owner and security reviewer agree that ambiguity cannot change authorization, price, state, or data selection.

Verification:
- Negative tests cover overlong values, encoded bypasses, unexpected Unicode, duplicate parameters, nested JSON, array/object confusion, and unsupported enum values.
- Server-side validation cannot be bypassed by disabling frontend checks or calling the API directly.

### 3.2 Output Encoding and Interpreter Boundaries

Release-ready defaults:
- Encode output for the exact target context: HTML body, HTML attribute, JavaScript, CSS, URL, SQL, LDAP, XML, shell, template, log, or CSV.
- Treat output encoding as context-specific; do not use one generic escaping helper for all interpreters.
- Prefer safe APIs: parameterized queries, prepared statements, structured logging, shell-free process invocation, safe templating, and framework-native encoders.
- Disable dangerous sinks such as `eval`, dynamic template evaluation, unsafe deserialization, and shell concatenation unless a narrow, reviewed exception exists.

Verification:
- Tests prove that untrusted strings render as data, not executable code or query syntax.
- Code review traces user-controlled values from source to sink and identifies the encoding or safe API at the boundary.

### 3.3 Authentication, Sessions, and Access Control

Release-ready defaults:
- Authentication and session checks run on the server side and fail closed.
- Session identifiers are rotated after login, privilege change, recovery, and sensitive account changes.
- Authorization is enforced in service/domain logic for every object and state transition, not only in routing, UI, or gateway rules.
- Resource ownership, tenant membership, role, scope, and policy context are evaluated together. A valid token or session is not sufficient authorization.
- Privileged actions require step-up or explicit approval where impact is high: admin changes, payout/payment changes, bulk export, destructive action, support impersonation, and permission grant.

Verification:
- Tests cover horizontal access, vertical access, cross-tenant access, stale session, logout/revocation behavior, and direct calls to hidden routes.
- Batch, async job, GraphQL, webhook, and export paths enforce the same authorization model as single-object APIs.

### 3.4 Injection and Query Safety

Release-ready defaults:
- SQL, NoSQL, LDAP, XML, search, and analytics queries use parameterized or structured APIs.
- User-controlled identifiers such as column names, sort keys, index names, collection names, and query operators use explicit allowlists.
- Shell commands are avoided. If process execution is required, pass arguments as an array, avoid shell interpolation, constrain executable paths, and run with least privilege.
- XML parsing of untrusted input disables DTDs, external entities, external DTD loading, XInclude, and network access. Secure processing mode and entity/depth/size limits are enabled where the parser supports them.
- XML schema validation must not fetch external schemas or DTDs at runtime. Required schemas are pinned, reviewed, and loaded from trusted local or controlled sources.
- If SOAP/XML, SAML-like payloads, or partner XML require features that weaken the default parser profile, the exception records the parser/library version, enabled features, external fetch behavior, payload size limit, owner, expiry, and negative test evidence.

Verification:
- Tests include injection payloads for every interpreter used by the changed code.
- Review confirms that ORM, query builder, and serialization helpers do not reintroduce string-built query fragments.
- XML negative tests include DOCTYPE rejection, external entity/file read payloads, external DTD/network fetch attempts, entity expansion/XML bomb payloads, oversized documents, and schema import attempts.

### 3.5 File Handling and External Fetches

Release-ready defaults:
- File uploads enforce size limits, extension policy, MIME/content checks, malware scanning where applicable, random server-side names, and storage outside executable web roots.
- Upload limits are explicit per route: maximum file size, maximum multipart body size, maximum file count, accepted content types, storage class, retention, quarantine behavior, and asynchronous scan timeout.
- Uploaded content is served with safe `Content-Type`, `Content-Disposition: attachment` unless inline rendering is required, `X-Content-Type-Options: nosniff`, and a cache policy appropriate to the data class.
- Malware or content-policy scanning happens before trusted processing or broad availability. Scan failures, timeouts, and unknown verdicts fail closed for high-risk file classes and route to quarantine or manual review.
- Archive extraction protects against path traversal, absolute paths, symlinks/hardlinks, special files, zip bombs, nested compression, excessive file count, excessive path length, and overwrite of existing files. Extraction runs in an isolated working directory with output-size and decompression-ratio limits.
- Server-side URL fetches use allowlisted schemes and destinations, DNS resolution checks, IP range blocking, redirect limits, timeout limits, response size limits, and metadata-network blocking.
- SSRF defenses validate the resolved target before connect and after redirects; block localhost, loopback, link-local, cloud metadata, private, multicast, and otherwise non-routable ranges unless the destination is an explicitly approved internal integration.
- For DNS names, account for rebinding: resolve through trusted resolvers, enforce allowlists on the final resolved IPs, avoid using stale validation after connection target changes, and prefer an egress proxy or network policy for high-risk fetchers.
- Do not let fetched content drive a second-stage request, parser, archive extraction, or template rendering without repeating validation for that new sink. Webhook and import handlers should preserve raw bodies when signature verification depends on the exact bytes; parsing, decompression, charset conversion, or middleware mutation must happen only after signature verification.

Verification:
- Tests cover polyglot files, malware-test fixtures, path traversal, absolute paths, symlink archive entries, archive traversal, decompression bombs, excessive file count, oversized payloads, content-type confusion, scan timeout behavior, and unsafe inline rendering.
- SSRF tests cover link-local and cloud metadata ranges, localhost, private IPv4 and IPv6 ranges, IPv4-mapped IPv6, decimal/hex/octal IP encodings where parsers support them, redirects to blocked ranges, DNS rebinding, slow responses, oversized responses, and blocked egress logs.
- For deeper API-specific webhook, GraphQL, SOAP/XML, and gRPC controls, cross-check the [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/). For browser rendering of uploaded or generated content, cross-check the [browser and frontend security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/).

### 3.6 Logging, Error Handling, and Privacy

Release-ready defaults:
- Logs include correlation ID, actor, tenant, object, action, result, and reason where useful for investigation.
- Logs do not include passwords, session IDs, refresh tokens, access tokens, private keys, raw authorization headers, reset tokens, payment secrets, or unnecessary personal data.
- Error responses are actionable for legitimate clients but do not reveal stack traces, internal paths, SQL fragments, secret names, or account existence.
- Security-relevant failures produce observable events: denied authorization, validation rejection, suspicious upload, SSRF block, token validation failure, and policy bypass attempt.

Verification:
- Tests and code review inspect both success and failure paths for secret or PII leakage.
- Live-environment logging has retention, access control, and redaction appropriate to the data class.

### 3.7 Cryptography and Secrets

Release-ready defaults:
- Use vetted platform libraries and standard protocols. Do not implement custom encryption, signature, password hashing, random generation, or token formats without explicit cryptographic review.
- Passwords use a current password hashing scheme with a per-password unique salt and stored algorithm/cost metadata. Default for new systems: Argon2id with at least `19 MiB` memory, `2` iterations, and parallelism `1`; raise memory/time cost when login latency and capacity allow it.
- Use bcrypt only for compatibility or where Argon2id/scrypt is unavailable; configure cost `>=10`, benchmark toward the highest tolerable cost, and handle bcrypt's `72` byte input limit explicitly through library support or reviewed pre-hashing.
- Use PBKDF2 only when platform or FIPS constraints require it; use PBKDF2-HMAC-SHA-256 with at least `600,000` iterations unless a newer approved local standard requires more.
- Password verification must enforce an input length ceiling large enough for passphrases but bounded against hash-time DoS. Do not silently truncate passwords.
- Rehash on successful login when the stored algorithm or cost is below the current baseline. Legacy hash migration must keep old verifiers isolated, observable, and time-boxed.
- A pepper may be used as defense-in-depth only if it is stored separately in KMS/HSM or an equivalent secret store, has rotation and emergency revocation procedures, and is not treated as a substitute for strong hashing.
- Keys and secrets are loaded from a secrets manager or protected runtime environment, not from source code, images, client-side bundles, logs, or default config.
- Encryption decisions specify what is protected, from whom, where keys live, how rotation works, and what audit evidence proves access.

Verification:
- Review confirms secure random generation, authenticated encryption where encryption is used for integrity-sensitive data, key separation, rotation path, no secret material in code or tests, and password hash parameters that match the approved baseline.
- Tests cover password verification for long inputs, Unicode normalization policy, legacy hash upgrade, no truncation, wrong-password timing behavior, and rate limiting around expensive hash operations.
- Secrets scanning covers repository history, CI variables where accessible, build logs, container layers, and deployment manifests.

---

## 4. Business Logic Review Overlay

Secure code can still violate business invariants. For sensitive flows, add this overlay and cross-check the [Business Logic Abuse playbook](/Product-security-playbook/en/application-security/business-logic/business-logic-abuse/playbook/).

Review questions:
- Ownership checks: can a user act on an object they do not own by changing an ID, filter, export job, batch item, or async task reference?
- Tenant isolation: is tenant context derived from authenticated membership and policy rather than request fields alone?
- Workflow state transitions: are allowed transitions explicit, and are direct calls to later states rejected?
- Price, discount, promo, and credit abuse: can retries, ordering changes, refund paths, or coupon stacking create value outside intended budgets?
- Idempotency and replay: do duplicate requests, webhooks, queue messages, and retries produce at most one external effect?
- Race conditions: can concurrent requests bypass quotas, double spend, overbook, approve twice, or win a stale authorization decision?
- Approval bypass: can a lower-privileged actor call an internal endpoint, background job, or bulk operation that skips human approval?
- Quota and rate-limit abuse: are limits applied to the right actor dimensions: account, tenant, source, device/session signal, payment instrument, API client, and time window?
- Privilege escalation through legitimate features: can invite, support, impersonation, role change, export, or integration features create unintended authority?

Required evidence:
- negative tests for every critical invariant;
- log/audit events for denied attempts;
- owner-approved release decision when an invariant is intentionally relaxed.

---

## 5. Review Decision Matrix

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | Use when | Required action |
|---|---|---|
| Critical | Direct exploitable path to credential/session compromise, cross-tenant data access, remote code execution, secret exposure, payment manipulation, or unsafe release to a live environment | Block release until fixed; exception requires explicit authorized risk acceptance if policy allows it |
| High | Plausible live-environment exploitation of injection, authorization bypass, sensitive data leakage, unsafe file handling, SSRF, crypto misuse, or missing security evidence for a high-risk change | Owner, due date, fix or accepted risk, and verification evidence |
| Medium | Meaningful gap with bounded impact, lower likelihood, or strong compensating controls | Track remediation and verify closure |
| Low | Hardening, clarity, test coverage, or logging improvement with limited direct impact | Fix opportunistically |

Required review output:
- finding summary and affected code path;
- attacker preconditions and impact;
- required fix or compensating control;
- verification method;
- owner, due date, and residual risk decision.

---

## 6. Related Materials

- [Business Logic Abuse playbook](/Product-security-playbook/en/application-security/business-logic/business-logic-abuse/playbook/)
- [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/)
- [Browser and frontend security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/)
- [OIDC + OAuth 2.0 security guide](/Product-security-playbook/en/application-security/identity/oidc-oauth/playbook/)
- [Vulnerability management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/)
- [MCP security playbook](/Product-security-playbook/en/ai-security/mcp-security/playbook/)
- [Agentic AI security playbook](/Product-security-playbook/en/ai-security/agentic-ai/playbook/)
- [Secure AI-Assisted Development playbook](/Product-security-playbook/en/ai-security/ai-assisted-development/playbook/)
