---
title: "Web Application Defense Playbook for OWASP Top 10"
description: "This document keeps the detailed OWASP Top 10:2021 structure for stable review links and adds an explicit mapping to OWASP Top 10:2025, which is the current OWASP web applicatio..."
sidebar:
  order: 10
---
## 1. Scope

This document keeps the detailed OWASP Top 10:2021 structure for stable review links and adds an explicit mapping to OWASP Top 10:2025, which is the current OWASP web application Top 10 release. Use the category-specific sections as the control baseline; use the mapping below when reporting against 2025.

Document boundaries:
- This playbook defines web-level review decision, severity, and minimum negative tests for OWASP Top 10 categories.
- Detailed requirements for API authorization, GraphQL, webhooks, and gRPC are owned by the [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/).
- Browser-specific controls for CSP, CORS, cookies, embedded content, and frontend supply chain are owned by the [browser and frontend security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/).
- Secure coding details for validation, output encoding, injection, file handling, and crypto misuse are owned by the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/).
- SAST, SCA, and secret scanning in the category sections below are applicability overlays for web risks. The Secure Coding and Code Review playbook owns their generic configuration, required execution, result handling, and closure evidence.
- Supply-chain and container-image controls are owned by the dedicated supply-chain playbooks; this document uses them only as web release decision context.

OWASP Top 10:2025 mapping:

| OWASP Top 10:2025 category | Primary section in this playbook | Review note |
|---|---|---|
| A01 Broken Access Control | Section 2 | Same primary risk; API-specific BOLA/BFLA depth is in the API playbook. |
| A02 Security Misconfiguration | Section 3 | Includes headers, CORS, XML parser settings, cloud permissions, and environment separation. |
| A03 Software Supply Chain Failures | Section 4 and supply-chain playbooks | 2025 broadens the old vulnerable-components category to build, developer, artifact, registry, and vendor paths. |
| A04 Cryptographic Failures | Section 5 | Same control family; verify transport, key lifecycle, token validation, and storage. |
| A05 Injection | Section 6 | Includes SQL, shell, template, XSS, XXE, SSRF-style URL interpretation, and parser-mediated injection. |
| A06 Insecure Design | Section 7 | Includes business logic, state machines, abuse economics, and exceptional-condition failure behavior. |
| A07 Authentication Failures | Section 8 | Identity and session details are cross-referenced to the OIDC/OAuth playbook where applicable. |
| A08 Software or Data Integrity Failures | Section 9 | Includes tampered artifacts/configs, unsafe deserialization, and client-controlled object integrity. |
| A09 Security Logging and Alerting Failures | Section 10 | Same operational detection and response control family. |
| A10 Mishandling of Exceptional Conditions | Section 7 and Section 10 | Treat fail-open handling, partial transaction recovery, resource exhaustion, and sensitive error disclosure as release-review items even when no classic injection or auth bypass exists. |

---

## 2. A01:2021 Broken Access Control

### 2.1 Threat, description, and attacker objective

Broken access control appears when a user or service can read, modify, or delete data outside its role and ownership scope. The attacker objective is to move beyond assigned permissions, access other users' objects, and execute privileged actions.

### 2.2 Types and typical exploitation flow

Types:
- `IDOR` (Insecure Direct Object Reference): a user changes an object identifier and gets another user's data. Example: `GET /api/orders/1002` is changed to `GET /api/orders/1003`, and the API returns someone else's order.
- `BOLA` (Broken Object Level Authorization): API validates authentication but not object ownership. Example: in GraphQL query `invoice(id: "inv_778")`, attacker swaps the ID and gets another customer's invoice.
- Forced browsing (direct invocation of hidden endpoints): access to routes not exposed in UI. Example: standard user manually opens `/admin/export` and downloads sensitive export.
- Privilege escalation: user-level account executes admin-only action. Example: `PATCH /api/users/me` with `role=admin` is accepted without server-side policy check.
- Token/cookie tampering: attacker modifies authorization/session attributes. Example: claim `role:user -> role:admin` in weakly validated JWT.
- `CORS` abuse (Cross-Origin Resource Sharing policy misuse): browser allows hostile origin to read credentialed API responses. Example: server reflects arbitrary `Origin` and sets `Access-Control-Allow-Credentials: true`, enabling data theft from victim session.
- `SSRF` chain (Server-Side Request Forgery): server fetches attacker-controlled URL and reaches internal resources. Example: `image_url=http://169.254.169.254/latest/meta-data/` leaks cloud metadata.

Typical flow:
- Recon of API routes and object identifiers (`user_id`, `order_id`, `tenant_id`)
- Identifier or role tampering in request
- Validation of missing server-side authorization
- Mass object enumeration and data harvesting
- Escalation to write/delete operations

What gets impacted:
- Tenant/user data isolation
- Administrative functions
- Internal APIs and management services

Impact:
- Data exposure, unauthorized changes, and takeover of critical business operations

### 2.3 Practical defense

- `deny-by-default` and per-request/per-object authorization
- Centralized policy-engine (`RBAC`/`ABAC`/`ReBAC`)
- Mandatory ownership checks (`resource.owner_id == caller.subject_id`)
- Strict internal/external API segmentation and mTLS
- Strict `CORS` allowlists
- Step-up authentication for high-risk actions
- Verification:
  - negative integration tests for horizontal/vertical privilege abuse
  - forced browsing tests
  - `401/403` anomaly and ID probing monitoring

### 2.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` when access-control bypass affects admin functions, tenant isolation, payment state, bulk export, or secrets.

Release-ready defaults:
- Every user, tenant, support, admin, and service operation has an explicit policy entry: actor, action, resource, tenant, context.
- Authorization is enforced in the service/domain layer, not only in UI, gateway, route middleware, or GraphQL schema directives.
- New endpoints, methods, mutations, and bulk/export jobs are `deny-by-default` until a policy and negative tests exist.
- CORS for credentialed browser flows uses an exact origin allowlist; wildcard origins with credentials are rejected.

Required evidence:
- Policy matrix or equivalent policy-as-code for sensitive operations.
- Negative test results for object-level, property-level, and function-level authorization.
- Sample audit events for allow/deny decisions on sensitive actions.
- Route/API inventory showing owner, exposure model, and data classification.

Negative tests:
- User A cannot read, update, delete, export, or infer existence of User B's object.
- Low-privilege user cannot call admin endpoints directly.
- Cross-tenant object IDs, nested GraphQL nodes, batch endpoints, and bulk exports are denied.
- Untrusted origins cannot read credentialed responses.

False positives / false negatives:
- A `403` response alone is not enough evidence; verify the backend policy path, not only gateway behavior.
- Scanner route findings often miss business-object authorization and GraphQL resolver authorization.
- `404` masking can be acceptable, but tests must still prove no unauthorized data or timing signal is exposed.

---

## 3. A05:2021 Security Misconfiguration

### 3.1 Threat, description, and attacker objective

Security misconfiguration happens when app, server, container, or cloud settings are unsafe. The attacker objective is to exploit defaults and weak hardening for initial access, persistence, and lateral movement.

### 3.2 Types and typical exploitation flow

Types:
- Debug mode and stack traces in live environments: internal paths, versions, and env details are exposed. Example: traceback reveals `DB_HOST` and SQL query fragments.
- Default accounts/passwords: attacker logs in with factory credentials. Example: admin console accepts `admin/admin`.
- Excessive HTTP methods and exposed admin routes: attack surface grows unnecessarily. Example: endpoint allows `PUT`/`DELETE` though it should be read-only.
- Unsafe XML parser settings -> `XXE` (XML External Entity): parser resolves external entities. Example: payload with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` returns file content.
- Missing security headers (`CSP`, `HSTS`): browser has fewer safeguards for script and transport security. Example: without CSP, injected inline script executes successfully.
- Over-permissive service/storage permissions: minor bug becomes major compromise. Example: web service with `s3:*` reads all buckets after single SSRF primitive.

Typical flow:
- Scanning for exposed debug/admin/version endpoints
- Attempting default credential login
- XXE parser probing
- Policy/header/proxy misconfiguration abuse
- Moving to file access, lateral movement, and persistence

What gets impacted:
- Sensitive data and secrets
- Admin/control interfaces
- Service trust boundaries

Impact:
- Fast initial compromise and accelerated privilege expansion

### 3.3 Practical defense

- Hardened baseline profiles for each environment + drift detection
- Policy-as-code and mandatory config review
- Safe XML parser profile with DTD/External Entity restrictions
- Mandatory security response headers
- Regular configuration audits and external attack-surface review
- Verification:
  - IaC/runtime compliance checks
  - safe degradation tests
  - golden-config deviation tracking

### 3.4 Release review baseline

Priority:
- Default severity is `Medium`; raise to `High` when the misconfiguration exposes admin surfaces, secrets, cloud metadata, debug execution, or internet-facing unsafe defaults.

Release-ready defaults:
- Debug mode, verbose stack traces, sample apps, default credentials, public admin consoles, and directory listing are disabled in live environments.
- Security headers are defined per application class; browser-facing apps at minimum decide on HSTS, CSP, frame protection, content-type sniffing, referrer policy, and cookie attributes.
- XML parsers disable DTD, external entities, unsafe resolvers, and unbounded entity expansion unless a documented legacy exception exists.
- Configuration drift is checked at deploy time and at least every `24h` for internet-facing and high-value services.

Required evidence:
- IaC and runtime configuration scan results for the deployed environment.
- External attack-surface inventory with owner and exposure reason.
- Header and TLS scan output for browser-facing endpoints.
- Exception register for any debug, legacy parser, public admin, or weak header deviation.

Negative tests:
- Default credentials fail on all exposed management interfaces.
- Debug endpoints and stack traces are not reachable without approved admin access.
- XXE and XML bomb payloads fail safely where XML is accepted.
- Public endpoints do not expose internal version banners, environment variables, or sensitive metadata.

False positives / false negatives:
- Header scanners can overstate risk for non-browser APIs; classify by actual client and exposure.
- Passing IaC checks is not enough if runtime mutation, Helm values, or emergency changes drift after deploy.
- Some legacy integrations require weaker settings; treat them as exceptions with owner, compensating controls, and expiry.

---

## 4. A06:2021 Vulnerable and Outdated Components

### 4.1 Threat, description, and attacker objective

This category covers vulnerable, unsupported, or untrusted components in application code, runtime images, plugins, client packages, and build tooling. The attacker objective is to exploit a known weakness or introduce malicious code through a trusted dependency path.

### 4.2 Types and typical exploitation flow

Types:
- Known vulnerable dependency or framework: application ships a component with exploitable CVE or end-of-life support status. Example: a public RCE proof of concept works against the deployed parser or web framework.
- Dependency confusion: build system resolves package from public registry instead of private one. Example: internal `corp-utils` gets installed from npm/PyPI where attacker published the same package name.
- Typosquatting: package name looks legitimate but is malicious. Example: `reqeusts` is installed instead of `requests` and exfiltrates tokens.
- CI runner/plugin compromise: malicious build step executes in trusted pipeline. Example: poisoned CI plugin reads `CI_SECRET` and sends it to attacker endpoint.
- Artifact substitution between build and deploy: modified artifact is pushed under expected tag. Example: tag `v1.4.2` is overwritten with backdoored container image.
- Unmaintained base image or runtime: OS packages and language runtimes no longer receive security fixes. Example: a container image keeps an end-of-life runtime because the application still builds on it.

Typical flow:
- Finding exposed components with known vulnerabilities or unsupported versions
- Finding dependencies without strict source pinning
- Injecting malicious package or plugin update
- Compromising CI token/secret
- Publishing substituted artifact to trusted registry
- Releasing malicious code via legitimate pipeline

What gets impacted:
- Product code and release artifacts
- CI/CD secrets and trust credentials when component updates or build plugins are abused
- Release infrastructure and downstream services

Impact:
- Exploitation of known weaknesses, broad release compromise, and supply-chain persistence

### 4.3 Practical defense

- Maintain `SBOM` (Software Bill of Materials)
- Sign artifacts and verify signatures at deploy time
- Use internal trusted mirrors and block unapproved sources
- Use `SCA` (Software Composition Analysis) as a mandatory gate for known vulnerable, end-of-life, and policy-banned components
- Track component ownership, upgrade path, and exception expiry for dependencies, base images, and plugins
- Use short-lived CI credentials and runner isolation
- Verification:
  - provenance/attestation gates in CD
  - anomalous publish/install monitoring
  - supply-chain tabletop exercises

### 4.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` when a reachable component vulnerability enables RCE, auth bypass, tenant/data compromise, signed release artifact compromise, CI secret exposure, live deployment credential exposure, or compromise of widely consumed packages/images.

Release-ready defaults:
- Live deployments use supported components and immutable artifact references (`sha256` digest for images) and reject mutable tags such as `latest`.
- Release artifacts are signed or accompanied by verified provenance/attestation from a trusted builder.
- CI credentials are short-lived, scoped to the pipeline, and unavailable to untrusted pull-request or fork builds.
- Dependency sources are pinned to approved registries or mirrors; dependency confusion controls exist for private package names.
- End-of-life frameworks, runtimes, base images, and critical libraries require a migration owner, deadline, compensating controls, and explicit risk acceptance.

Required evidence:
- SBOM or dependency inventory for release artifacts, including runtime/base image components where available.
- SCA results with policy outcome, reachability/risk context, and exception handling.
- Provenance/signature verification result from deploy gate.
- CI/CD permissions review for runners, workflow files, release tokens, and artifact registry access.

Negative tests:
- Deploy by mutable tag or unsupported base image is rejected in live environments.
- Unsigned artifact, wrong builder identity, wrong repository, or wrong workflow identity fails the gate.
- Build from fork/untrusted branch cannot access live-environment signing or deploy credentials.
- Dependency from an unapproved source or private-name public package is blocked.

False positives / false negatives:
- An SBOM without a deploy-time policy gate is inventory, not enforcement.
- SCA can miss malicious packages with no CVE and can overstate unreachable findings; combine it with source pinning, provenance, reachability review, and behavior review.
- Signature validity alone is insufficient; verify signer identity, builder identity, source, parameters, and subject digest.

---

## 5. A02:2021 Cryptographic Failures

### 5.1 Threat, description, and attacker objective

Cryptographic failures allow attackers to read, tamper with, or replay protected data. The attacker objective is to break trust in transport, storage, keys, and tokens.

### 5.2 Types and typical exploitation flow

Types:
- Missing or downgraded `TLS` (Transport Layer Security): data travels without strong channel protection. Example: login credentials are sent over plain HTTP on public Wi-Fi.
- Weak/outdated algorithms and cipher modes: crypto exists but is not practically robust. Example: legacy cipher suite allows decrypting captured traffic.
- Unsafe password storage: plaintext or fast unsalted hashes. Example: after DB leak, hashes are cracked quickly with dictionary attacks.
- Key/secret leakage in code and CI: sensitive keys appear in Git, artifacts, or logs. Example: `AWS_SECRET_ACCESS_KEY` appears in public commit history.
- Reused `IV` (Initialization Vector) or nonce: symmetric encryption guarantees degrade. Example: nonce reuse enables analysis and token forgery patterns.

Typical flow:
- Network interception and downgrade probing
- Exploiting weak cryptographic configuration
- Obtaining DB dump/backup
- Offline credential cracking and credential reuse
- Service access with compromised token/key material

What gets impacted:
- Passwords, tokens, personal/payment data
- Key infrastructure
- Service trust relationships

Impact:
- Large-scale data breaches and long-lived key compromise

### 5.3 Practical defense

- Enforce TLS 1.2+ (preferably 1.3) and HSTS
- Store keys in `HSM`/`KMS`
- Use adaptive password hashing (Argon2id/scrypt/bcrypt/PBKDF2)
- Use scheduled + emergency key rotation
- Encrypt sensitive data at rest by classification
- Verification:
  - crypto inventory and key lifetime controls
  - TLS scanning
  - secret scanning in repos/images

### 5.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` for plaintext credentials, exploitable weak password storage, payment/PII exposure, signing-key compromise, or token-forgery impact.

Release-ready defaults:
- TLS 1.3 is preferred; TLS 1.2 is allowed only with modern cipher suites and no legacy protocol fallback.
- Browser-facing HTTPS uses HSTS after rollout safety is confirmed; preload is a separate risk decision.
- Passwords use Argon2id, scrypt, bcrypt, or PBKDF2 with parameters reviewed for current platform cost; plaintext, reversible encryption, and fast hashes are rejected.
- Keys live in KMS/HSM or an approved secret-management system; emergency revocation and rotation must be tested for high-value keys.
- Sensitive data encryption is tied to data classification, access control, backup handling, and key separation.

Required evidence:
- TLS scan and configuration for all public and internal high-value endpoints.
- Password hashing configuration and migration plan for legacy hashes.
- Key inventory with owner, storage location, rotation cadence, and emergency procedure.
- Secret scanning results for repositories, images, logs, and CI artifacts.

Negative tests:
- HTTP and TLS downgrade attempts do not expose sessions or credentials.
- Weak JWT algorithms, unknown `kid`/JWKS sources, and expired keys are rejected where tokens are used.
- Known leaked test secrets are detected in CI and image scanning.
- Backup restore does not bypass encryption or key-access policy.

False positives / false negatives:
- TLS scanner grades do not prove application-level token or key lifecycle safety.
- "Encrypted at rest" claims from a platform are incomplete without key ownership, access paths, and backup coverage.
- Password hash strength depends on parameters and hardware cost, not only algorithm name.

---

## 6. A03:2021 Injection

### 6.1 Threat, description, and attacker objective

Injection happens when untrusted input reaches SQL, shell, template engines, or browser execution context without safe handling. The attacker objective is data exfiltration/modification, control bypass, and arbitrary code execution.

### 6.2 Types and typical exploitation flow

Types:
- `SQLi` (SQL Injection): user input changes SQL query logic. Example: `id=1 OR 1=1` returns all records; blind/time-based variant uses `SLEEP(5)` for confirmation.
- Command Injection: user input is executed by shell command. Example: `filename=report.txt; cat /etc/passwd`.
- `SSTI` (Server-Side Template Injection): input is interpreted as template expression. Example: `{{7*7}}` returns `49`, proving template code execution.
- `XSS` (Cross-Site Scripting): malicious JavaScript executes in victim browser. Example: payload `<script>fetch('/api/me')</script>` in comment steals session data.
- `XXE` (XML External Entity): XML entity resolves local file or triggers SSRF. Example: entity referencing `file:///etc/hosts` returns local file content.

Typical flow:
- Discover input surface (parameter/header/cookie/body)
- Validate payload interpretation
- Confirm vulnerability via error/timing/out-of-band signal
- Exfiltrate data or execute commands
- Persist via session/account compromise

What gets impacted:
- Databases and business records
- Application server and OS
- Browser sessions and user actions

Impact:
- Full data compromise, RCE, and account takeover at scale

### 6.3 Practical defense

- Parameterized queries and ORM for SQL
- Ban string concatenation in SQL/command contexts
- Input filtering + allowlists
- Use CSP as defense-in-depth
- Avoid shell execution; use built-in language/runtime APIs instead
- Apply output-context encoding everywhere
- If OS command execution is unavoidable: use a fixed executable path, argv-style APIs without shell expansion, a small allowlist of operations, strict argument validation, and no user-controlled command names
- Shell metacharacter escaping is a last-resort compensating control, not the primary defense; test metacharacters and argument injection explicitly
- Isolate interpreter/template runtimes (sandbox/container)
- For SSTI: update template libraries, forbid user template upload/modification, sanitize template input, prefer logic-less templates
- For SSRF: allowlist trusted addresses, validate parameters, account for DNS rebinding behavior
- For XSS/PHP injection: htmlspecialchars, filtering/escaping, disable unnecessary functions
- Make `SAST`/`DAST`/fuzzing mandatory in CI
- Verification:
  - payload regression suite
  - blind/time-based scenario coverage
  - security review for every new input surface

### 6.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` for unauthenticated RCE, injection reaching live data stores, command execution, or cross-tenant data extraction.

Release-ready defaults:
- SQL, NoSQL, LDAP, OS command, template, XML, URL, and browser sinks have approved safe APIs and code-review rules.
- User-controlled input never selects executable names, template files, deserialization classes, SQL fragments, or outbound network targets without a strict allowlist.
- CSP is used as defense-in-depth for XSS; output encoding and sanitization remain the primary browser-side controls.
- URL fetchers use scheme/host/port allowlists, DNS rebinding defenses, metadata IP blocks, and egress policy.

Required evidence:
- Sink inventory for high-risk interpreters and downstream calls.
- Regression payload suite covering SQLi, command injection, SSTI, XSS, XXE, SSRF, and argument injection where relevant.
- SAST/DAST/fuzzing results with triage notes for reachable sinks.
- Code review evidence for any shell, template, deserialization, or URL-fetching feature.

Negative tests:
- SQL metacharacters and boolean/time-based payloads cannot alter query semantics.
- Shell metacharacters and argument injection cannot alter command behavior.
- Untrusted template input cannot evaluate server-side expressions.
- SSRF canaries, metadata IPs, localhost, private ranges, and DNS rebinding attempts are blocked.
- XSS payloads are encoded/sanitized in each output context.

False positives / false negatives:
- WAF blocks are not proof of remediation; verify the application sink is safe.
- SAST can overreport unreachable sinks and underreport framework-specific injection paths.
- Escaping alone is context-specific and fragile; prefer parameterization, safe APIs, and allowlists.

---

## 7. A04:2021 Insecure Design

### 7.1 Threat, description, and attacker objective

Insecure design means critical security controls were never built into architecture and business logic. The attacker objective is to exploit systemic design gaps that cannot be fixed with a local patch.

### 7.2 Types and typical exploitation flow

Types:
- Unsafe recovery/fallback logic: simplified mode bypasses critical checks. Example: when SMS provider fails, transaction confirmation is silently disabled.
- Mishandled exceptional conditions: missing input, partial dependency failure, timeout, duplicate callback, or privilege-check error leaves the system in an unknown or fail-open state. Example: a payment flow debits one ledger, fails on crediting the destination, and retries without a full rollback/idempotency guard.
- Missing controls for critical operations (limit/rate/approval): no anti-abuse guardrails. Example: user performs 1000 transfers in minutes without velocity limit.
- Weak tenant isolation: tenant boundaries exist only in UI logic. Example: changing `tenant_id` in API request exposes another tenant's objects.
- State-machine flaws: invalid transitions are accepted. Example: order moves from `draft` directly to `paid` without payment verification.
- Business logic race conditions: concurrent requests break invariants. Example: double-click on `withdraw` causes double balance deduction.

Typical flow:
- Analyze business process/state transitions
- Find uncontrolled state transition
- Trigger edge states (retry/race/partial failure)
- Force exception paths such as timeouts, malformed optional parameters, dependency errors, and interrupted transactions
- Bypass expected control flow
- Execute forbidden operation without exploiting low-level code bugs

What gets impacted:
- Payment and privilege-change operations
- Business state integrity
- Cross-tenant boundaries

Impact:
- Fraud/abuse and irreversible business errors

### 7.3 Practical defense

- Perform threat modeling before implementation
- Define abuse/misuse cases for critical workflows
- Encode security requirements directly into user stories
- Add anti-automation controls and out-of-band confirmation
- Require independent security design review
- Verification:
  - state-machine tests
  - negative business-flow tests
  - adversarial walkthroughs

### 7.4 Release review baseline

Priority:
- Default severity is `Medium`; raise to `High` or `Critical` when design gaps affect money movement, authorization, tenant isolation, safety, privacy, or irreversible operations.

Release-ready defaults:
- Critical flows have a documented state machine, allowed transitions, idempotency model, replay handling, and failure behavior.
- Abuse controls exist for signup, login, checkout, transfer, refund, export, invite, support, and privilege-change flows where applicable.
- High-impact operations require step-up, approval, rate/velocity limits, or dual control based on risk.
- Exceptional-condition handling is designed per critical flow: fail closed, roll back partial state, preserve idempotency, emit a security-relevant event, and return a safe user-facing error without internal details.
- Threat modeling is mandatory before release for new trust boundaries, sensitive data, external integrations, AI/agentic flows, and payment/security workflows.

Required evidence:
- Threat model or abuse-case table with residual risk and owner.
- State-transition tests and idempotency tests for critical business operations.
- Rate/velocity/approval configuration and monitoring for abuse-sensitive flows.
- Release decision showing accepted risks and compensating controls.

Negative tests:
- Invalid state transitions are rejected.
- Duplicate, replayed, out-of-order, delayed, and concurrent requests cannot create unauthorized business state.
- Dependency failure does not silently skip mandatory checks.
- Missing parameters, malformed optional fields, timeout, partial dependency failure, and retry storms do not create inconsistent state, privilege bypass, or sensitive error disclosure.
- Normal users cannot trigger high-risk support/admin/business operations without required controls.

False positives / false negatives:
- Generic STRIDE output can miss fraud and business-state abuse; test real workflows.
- Unit tests for individual services may miss distributed races and retries.
- Product-approved behavior can still be a security risk if abuse economics and monitoring are not assessed.

---

## 8. A07:2021 Identification and Authentication Failures

### 8.1 Threat, description, and attacker objective

Authentication and session failures let attackers act as legitimate users. The attacker objective is account takeover, MFA bypass, and long-lived session control.

### 8.2 Types and typical exploitation flow

Types:
- Credential stuffing and password spraying: automated login attempts with leaked credentials. Example: bot checks large `email:password` list against `/login`.
- Brute force: repeated guessing for a specific account. Example: 10,000 attempts against `admin@company.com` without strict lockout.
- Session fixation/hijacking: attacker forces or steals session identifier. Example: victim logs in using attacker-provided session ID.
- Weak password reset flow: recovery token process is predictable or reusable. Example: reset token does not expire and can be replayed.
- Missing/weak `MFA` (Multi-Factor Authentication): second factor is not required for high-risk operations. Example: money transfer is approved with password only.
- Broken logout/revocation: tokens stay valid after logout. Example: stolen refresh token keeps issuing new access tokens.

Typical flow:
- Attempt login using breached credentials at scale
- Abuse weak recovery process
- Capture or fix session token
- Reuse token after logout
- Escalate privileges inside hijacked session

What gets impacted:
- User/admin accounts
- Session token lifecycle
- Account recovery channels

Impact:
- Large-scale account takeover and fraudulent actions

### 8.3 Practical defense

- Mandatory MFA for high-risk roles/operations
- Breached-password checks and weak-password blocking
- Rotate session IDs after login/privilege changes
- Enforce idle and absolute session timeout
- Ensure reliable logout/token revocation
- Verification:
  - brute-force resilience tests
  - fixation/hijacking tests
  - login/reset anomaly monitoring

### 8.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` for admin account takeover, broken password reset, MFA bypass for high-impact actions, or reusable refresh/session token compromise.

Release-ready defaults:
- Browser applications use server-side sessions or BFF-style token handling; refresh tokens are not stored in browser storage.
- Session ID rotates after login, privilege elevation, and recovery completion.
- User sessions have idle and absolute timeouts; high-risk actions require recent authentication.
- Credential stuffing controls include breached-password checks, per-account and per-source throttling, bot signals, and anomaly alerts.
- Logout destroys local session and revokes or invalidates refresh/session material where the architecture supports it.

Required evidence:
- IdP/session configuration with TTLs, cookie attributes, MFA/step-up policy, and reset-token lifetime.
- Negative tests for invalid issuer/audience/expired token, fixation, reset-token replay, and logout/revocation.
- Monitoring for login failures, password spraying, reset abuse, MFA failures, and impossible travel/session anomalies.
- Privileged-role inventory with MFA and break-glass handling.

Negative tests:
- Stolen or fixed pre-login session ID cannot survive authentication.
- Reset token is single-use, expires quickly, and cannot be reused after password change.
- Refresh/session token cannot continue indefinitely after logout, Not Before update, or revocation event.
- Password spraying and credential stuffing produce throttling and alert signals.

False positives / false negatives:
- MFA presence does not prove protection if recovery or remembered-device flows bypass it.
- Lockout can become a DoS vector; evaluate adaptive throttling and step-up, not only hard account locks.
- JWT validation tests must include issuer, audience, time claims, algorithm allowlist, and key trust.

---

## 9. A08:2021 Software and Data Integrity Failures

### 9.1 Threat, description, and attacker objective

Risk appears when systems trust data/config/code without validating origin and integrity. The attacker objective is update/data tampering and unsafe deserialization exploitation.

### 9.2 Types and typical exploitation flow

Types:
- Unsigned updates/configs: system trusts files without origin validation. Example: service loads plugin ZIP without signature verification.
- Policy/artifact tampering in delivery path: content is altered between pipeline stages. Example: registry serves modified image under expected tag.
- Insecure deserialization: untrusted serialized object is treated as trusted. Example: crafted payload triggers unintended method execution.
- Trusting client-controlled objects/cookies without `MAC` (Message Authentication Code): attacker changes critical fields client-side. Example: cookie `{"role":"user"}` changed to `{"role":"admin"}` and accepted.

Typical flow:
- Find update/config/object ingestion point
- Craft tampered payload
- Bypass source/signature validation
- Execute altered logic or deserialization gadget chain
- Persist by repeatedly injecting modified trusted artifacts

What gets impacted:
- Update and configuration channels
- Internal application state models
- Business data integrity controls

Impact:
- Unauthorized logic changes, RCE, persistent compromise

### 9.3 Practical defense

- Sign and verify updates/artifacts/configurations
- Block unsafe deserialization of untrusted input
- Separate trusted control plane from user-controlled data plane
- Enforce integrity checks on critical objects
- Verification:
  - tampering tests
  - startup trust-chain checks
  - signature/hash mismatch alerts

### 9.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` when integrity failure enables RCE, release to a live environment compromise, payment/ledger tampering, or policy bypass.

Release-ready defaults:
- Updates, plugins, models, configs, rules, and release artifacts are verified before use.
- Deserialization of untrusted input is forbidden unless a narrow, reviewed format and allowlist exist.
- Client-controlled state is signed/MACed or stored server-side; authorization data is not trusted from client-modifiable fields.
- Deployment and startup perform trust-chain checks and fail closed on mismatch for high-value components.

Required evidence:
- Artifact/config signature verification results and policy configuration.
- Inventory of deserialization formats and trust boundaries.
- Tests proving tampered client objects, cookies, configs, and update artifacts are rejected.
- Audit/alert examples for signature, digest, or policy mismatch.

Negative tests:
- Modified artifact, wrong digest, wrong signer, or unsigned config fails before deploy/startup.
- Crafted serialized payload cannot instantiate unsafe types or trigger code paths.
- Modified cookie/client object cannot change role, tenant, balance, entitlement, or workflow state.
- Policy/rules update from unapproved source is rejected.

False positives / false negatives:
- Hash checks without trusted provenance or signature can detect corruption but not authorized origin.
- Deserialization scanners may miss framework-specific gadget chains and message broker payloads.
- Signed data can still be unsafe if signing keys, canonicalization, or trusted fields are poorly controlled.

---

## 10. A09:2021 Security Logging and Monitoring Failures

### 10.1 Threat, description, and attacker objective

If security events are not logged or alerted in time, incidents stay invisible. The attacker objective is to maximize dwell time and reduce probability of containment.

### 10.2 Types and typical exploitation flow

Types:
- Missing logs for critical security events: attack leaves no detection trail. Example: failed logins and role changes are not recorded.
- Local log tampering/deletion: attacker erases evidence after compromise. Example: `app.log` is deleted on host after initial foothold.
- No `SIEM` (Security Information and Event Management) correlation: separate signals never become incident alert. Example: 50 authorization failures and suspicious API access are not correlated.
- `PII` (Personally Identifiable Information) and secret leakage through logs: logs become a high-value breach source. Example: `Authorization: Bearer ...` is written in plain logs.
- `SOC` (Security Operations Center) overload from noise/false positives: real incidents are missed. Example: thousands of low-priority alerts hide a real takeover attempt.

Typical flow:
- Run low-noise attack path
- Validate no alert on failed logins/probing
- Remove/alter logs
- Re-exploit the same weakness without detection

What gets impacted:
- Detection and response
- Forensics and auditability
- Regulatory evidence and compliance posture

Impact:
- Delayed breach discovery and amplified business damage

### 10.3 Practical defense

- Filter and escape user input (also relevant for safe logging/display)
- Define mandatory security event catalog (auth/access/config/privilege/data changes)
- Standardize log schema and correlation IDs
- Use tamper-evident/append-only audit trails
- Centralize ingestion and define alert runbooks for high severity cases
- Keep secrets and sensitive personal data out of logs
- Verification:
  - DAST/pentest must trigger alerts
  - recurring MTTD/MTTR review
  - periodic detection-quality testing

### 10.4 Release review baseline

Priority:
- Default severity is `Medium`; raise to `High` when missing telemetry affects auth, authorization, admin actions, data export, payment/security events, or incident reconstruction.

Release-ready defaults:
- Security event catalog covers authentication, authorization decisions, admin actions, privilege changes, secret/key access, configuration changes, data export, rate limits, validation failures, and webhook/API abuse.
- Logs use a consistent schema with timestamp, actor, tenant, client, source, action, resource, decision, reason, correlation ID, and request ID where applicable.
- Tokens, credentials, secrets, full payment data, and sensitive payloads are redacted before storage.
- High-value audit logs are centralized, access-controlled, tamper-evident or append-only, and retained at least `90d` unless stricter requirements apply.
- Alerts have owner, severity, runbook, and target response SLO.

Required evidence:
- Sample logs for allowed and denied sensitive actions.
- Detection rules and runbooks for top abuse cases.
- Retention, immutability, and access-control settings for audit storage.
- MTTD/MTTR or exercise results for realistic attack paths.

Negative tests:
- Failed login burst, BOLA probing, invalid token, privilege change, bulk export, webhook replay, and schema validation failure produce expected events.
- Secrets and bearer tokens are not present in application, proxy, job, or CI logs.
- Local log deletion does not remove central audit evidence.
- Alert routing reaches the expected owner with enough context to investigate.

False positives / false negatives:
- High log volume is not detection quality; verify actionable alerts and runbooks.
- Redaction can remove investigation context; retain stable hashes/correlation IDs where useful.
- DAST-triggered alerts may not cover low-noise business abuse paths without custom tests.

---

## 11. A10:2021 Server-Side Request Forgery

### 11.1 Threat, description, and attacker objective

Server-Side Request Forgery appears when an application fetches attacker-controlled URLs or resolves attacker-controlled destinations from server-side infrastructure. The attacker objective is to make a trusted server reach cloud metadata, internal services, management planes, or sensitive network locations that the attacker cannot access directly.

### 11.2 Types and typical exploitation flow

Types:
- URL fetchers and importers: application retrieves a user-supplied URL for image preview, webhook validation, document import, or link unfurling. Example: `image_url=http://169.254.169.254/latest/meta-data/` reaches cloud metadata.
- Parser or converter callbacks: PDF, XML, SVG, office, or media processing resolves remote references. Example: a document conversion job follows an internal URL embedded in attacker-controlled content.
- Webhook and integration testing features: user configures a callback endpoint and the service probes it from a privileged network. Example: validation endpoint reaches an internal admin panel.
- DNS rebinding and redirect chains: initial URL looks allowed, then redirects or resolves to private ranges. Example: allowed public host redirects to `http://127.0.0.1:8080/admin`.
- Cloud metadata access: workload can reach provider metadata service and retrieve identity tokens or credentials when metadata protections and egress policy are missing.

Typical flow:
- Find server-side fetch, preview, webhook, import, or parser feature
- Supply URL or content that reaches private networks, loopback, link-local, metadata, or internal DNS names
- Bypass naive deny rules with redirects, DNS rebinding, alternate IP notation, IPv6, or parser behavior
- Use response timing, error messages, callbacks, or stored output to infer or exfiltrate internal data

What gets impacted:
- Cloud workload credentials and metadata services
- Internal admin panels, service APIs, and control planes
- Network segmentation and tenant/service boundaries

Impact:
- Internal reconnaissance, credential theft, unauthorized internal actions, and lateral movement through a trusted server

### 11.3 Practical defense

- Allowlist exact outbound destinations by business purpose; avoid generic "any URL" fetchers in live environments.
- Resolve and validate the final destination after redirects, canonicalization, DNS resolution, and IP normalization; block private, loopback, link-local, multicast, and cloud metadata ranges unless explicitly approved.
- Enforce network egress policy from the workload namespace/VPC/subnet so application validation is not the only control.
- Disable or tightly configure parser features that resolve remote references in XML, SVG, PDF, office, media, and archive processing.
- Use dedicated fetcher services with low privilege, no ambient cloud credentials, no access to internal admin networks, response size/time limits, and audited destination policy.
- For cloud metadata, require provider-specific protections such as IMDSv2/hop limits, workload identity scoping, metadata concealment, and egress deny rules.
- Verification:
  - redirect and DNS rebinding tests
  - private/link-local/metadata IP negative tests
  - egress policy and cloud metadata deny evidence

### 11.4 Release review baseline

Priority:
- Default severity is `High`; raise to `Critical` when SSRF can reach cloud metadata credentials, control-plane APIs, internal admin panels, tenant data services, signing/deploy credentials, or state-changing internal endpoints.

Release-ready defaults:
- User-controlled fetch destinations are either not supported or constrained to approved schemes, hosts, ports, content types, and response sizes.
- Final effective destination is validated after redirects and DNS resolution; private, loopback, link-local, multicast, and metadata destinations are blocked by both application policy and network egress control.
- Fetching runs under a dedicated identity with no broad cloud metadata, service-mesh admin, Kubernetes API, Vault, CI/CD, or internal admin access.
- Parser/converter features that can fetch remote content are disabled or routed through the same controlled fetcher.
- SSRF attempts produce security events with source actor, feature, requested URL class, resolved destination class, decision, and correlation ID.

Required evidence:
- Inventory of all URL fetch, webhook validation, import, preview, parser, and converter features with owner and destination policy.
- Egress policy, DNS, proxy, and cloud metadata protection evidence for the deployed environment.
- Negative test results for redirects, DNS rebinding, alternate IP formats, IPv6, private ranges, and metadata endpoints.
- Alert/audit samples for denied and allowed fetches.

Negative tests:
- `http://127.0.0.1`, `localhost`, RFC1918, link-local, IPv6 loopback, multicast, and cloud metadata endpoints are denied.
- Redirects to denied destinations are blocked even when the first URL is public and allowlisted.
- DNS rebinding from public to private address is denied after re-resolution.
- Parser-embedded remote references cannot reach internal networks.

False positives / false negatives:
- A URL regex or hostname denylist alone is not enough; validate normalized URLs, resolved addresses, redirects, and effective network path.
- A proxy can centralize policy, but only if direct egress from the workload is blocked.
- Blind SSRF may not return data directly; verify timing, callbacks, DNS logs, egress logs, and denied metadata access.

---

## 12. Related Materials

- [Browser and frontend security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/)
- [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/)
- [Secure coding and code review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/)
- [Threat modeling playbook](/Product-security-playbook/en/review/threat-modeling/playbook/)
