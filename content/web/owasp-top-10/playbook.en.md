# Web Application Defense Playbook for OWASP Top 10:2025

## 1. Scope

This document defines a practical baseline for protecting web applications against the key OWASP Top 10 risks.

---

## 2. A01:2025 Broken Access Control

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

### 2.4 Production review baseline

Priority:
- Default severity is `High`; raise to `Critical` when access-control bypass affects admin functions, tenant isolation, payment state, bulk export, or secrets.

Production defaults:
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

## 3. A02:2025 Security Misconfiguration

### 3.1 Threat, description, and attacker objective

Security misconfiguration happens when app, server, container, or cloud settings are unsafe. The attacker objective is to exploit defaults and weak hardening for initial access, persistence, and lateral movement.

### 3.2 Types and typical exploitation flow

Types:
- Debug mode and stack traces in production: internal paths, versions, and env details are exposed. Example: traceback reveals `DB_HOST` and SQL query fragments.
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

### 3.4 Production review baseline

Priority:
- Default severity is `Medium`; raise to `High` when the misconfiguration exposes admin surfaces, secrets, cloud metadata, debug execution, or internet-facing unsafe defaults.

Production defaults:
- Debug mode, verbose stack traces, sample apps, default credentials, public admin consoles, and directory listing are disabled in production.
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

## 4. A03:2025 Software Supply Chain Failures

### 4.1 Threat, description, and attacker objective

This category covers compromise of dependencies, CI/CD, artifact repositories, plugins, and build tools. The attacker objective is to inject malicious code into a trusted release path.

### 4.2 Types and typical exploitation flow

Types:
- Dependency confusion: build system resolves package from public registry instead of private one. Example: internal `corp-utils` gets installed from npm/PyPI where attacker published same package name.
- Typosquatting: package name looks legitimate but is malicious. Example: `reqeusts` is installed instead of `requests` and exfiltrates tokens.
- CI runner/plugin compromise: malicious build step executes in trusted pipeline. Example: poisoned CI plugin reads `CI_SECRET` and sends it to attacker endpoint.
- Artifact substitution between build and deploy: modified artifact is pushed under expected tag. Example: tag `v1.4.2` is overwritten with backdoored container image.
- Vulnerable/unmaintained dependencies with known `CVE` (Common Vulnerabilities and Exposures): known exploit path remains open in production. Example: outdated library is exploitable by public RCE PoC.

Typical flow:
- Finding dependencies without strict source pinning
- Injecting malicious package or plugin update
- Compromising CI token/secret
- Publishing substituted artifact to trusted registry
- Releasing malicious code via legitimate pipeline

What gets impacted:
- Product code and release artifacts
- CI/CD secrets and trust credentials
- Release infrastructure and downstream services

Impact:
- Broad release compromise and supply-chain persistence

### 4.3 Practical defense

- Maintain `SBOM` (Software Bill of Materials)
- Sign artifacts and verify signatures at deploy time
- Use internal trusted mirrors and block unapproved sources
- Use `SCA` (Software Composition Analysis) as mandatory gate
- Use short-lived CI credentials and runner isolation
- Verification:
  - provenance/attestation gates in CD
  - anomalous publish/install monitoring
  - supply-chain tabletop exercises

### 4.4 Production review baseline

Priority:
- Default severity is `High`; raise to `Critical` when compromise can affect signed release artifacts, CI secrets, production deploy credentials, or widely consumed packages/images.

Production defaults:
- Production deploys use immutable artifact references (`sha256` digest for images) and reject mutable tags such as `latest`.
- Release artifacts are signed or accompanied by verified provenance/attestation from a trusted builder.
- CI credentials are short-lived, scoped to the pipeline, and unavailable to untrusted pull-request or fork builds.
- Dependency sources are pinned to approved registries or mirrors; dependency confusion controls exist for private package names.

Required evidence:
- SBOM or dependency inventory for release artifacts.
- SCA results with policy outcome and exception handling.
- Provenance/signature verification result from deploy gate.
- CI/CD permissions review for runners, workflow files, release tokens, and artifact registry access.

Negative tests:
- Deploy by mutable tag is rejected in production.
- Unsigned artifact, wrong builder identity, wrong repository, or wrong workflow identity fails the gate.
- Build from fork/untrusted branch cannot access production signing or deploy credentials.
- Dependency from an unapproved source or private-name public package is blocked.

False positives / false negatives:
- An SBOM without a deploy-time policy gate is inventory, not enforcement.
- SCA can miss malicious packages with no CVE; combine it with source pinning, provenance, and behavior review.
- Signature validity alone is insufficient; verify signer identity, builder identity, source, parameters, and subject digest.

---

## 5. A04:2025 Cryptographic Failures

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

### 5.4 Production review baseline

Priority:
- Default severity is `High`; raise to `Critical` for plaintext credentials, exploitable weak password storage, payment/PII exposure, signing-key compromise, or token-forgery impact.

Production defaults:
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

## 6. A05:2025 Injection

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

### 6.4 Production review baseline

Priority:
- Default severity is `High`; raise to `Critical` for unauthenticated RCE, injection reaching production data stores, command execution, or cross-tenant data extraction.

Production defaults:
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

## 7. A06:2025 Insecure Design

### 7.1 Threat, description, and attacker objective

Insecure design means critical security controls were never built into architecture and business logic. The attacker objective is to exploit systemic design gaps that cannot be fixed with a local patch.

### 7.2 Types and typical exploitation flow

Types:
- Unsafe recovery/fallback logic: simplified mode bypasses critical checks. Example: when SMS provider fails, transaction confirmation is silently disabled.
- Missing controls for critical operations (limit/rate/approval): no anti-abuse guardrails. Example: user performs 1000 transfers in minutes without velocity limit.
- Weak tenant isolation: tenant boundaries exist only in UI logic. Example: changing `tenant_id` in API request exposes another tenant's objects.
- State-machine flaws: invalid transitions are accepted. Example: order moves from `draft` directly to `paid` without payment verification.
- Business logic race conditions: concurrent requests break invariants. Example: double-click on `withdraw` causes double balance deduction.

Typical flow:
- Analyze business process/state transitions
- Find uncontrolled state transition
- Trigger edge states (retry/race/partial failure)
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

### 7.4 Production review baseline

Priority:
- Default severity is `Medium`; raise to `High` or `Critical` when design gaps affect money movement, authorization, tenant isolation, safety, privacy, or irreversible operations.

Production defaults:
- Critical flows have a documented state machine, allowed transitions, idempotency model, replay handling, and failure behavior.
- Abuse controls exist for signup, login, checkout, transfer, refund, export, invite, support, and privilege-change flows where applicable.
- High-impact operations require step-up, approval, rate/velocity limits, or dual control based on risk.
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
- Normal users cannot trigger high-risk support/admin/business operations without required controls.

False positives / false negatives:
- Generic STRIDE output can miss fraud and business-state abuse; test real workflows.
- Unit tests for individual services may miss distributed races and retries.
- Product-approved behavior can still be a security risk if abuse economics and monitoring are not assessed.

---

## 8. A07:2025 Authentication Failures

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

### 8.4 Production review baseline

Priority:
- Default severity is `High`; raise to `Critical` for admin account takeover, broken password reset, MFA bypass for high-impact actions, or reusable refresh/session token compromise.

Production defaults:
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

## 9. A08:2025 Software or Data Integrity Failures

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

### 9.4 Production review baseline

Priority:
- Default severity is `High`; raise to `Critical` when integrity failure enables RCE, production release compromise, payment/ledger tampering, or policy bypass.

Production defaults:
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

## 10. A09:2025 Security Logging and Alerting Failures

### 10.1 Threat, description, and attacker objective

If security events are not logged or alerted in time, incidents stay invisible. The attacker objective is to maximize dwell time and reduce probability of containment.

### 10.2 Types and typical exploitation flow

Types:
- Missing logs for critical security events: attack leaves no detection trail. Example: failed logins and role changes are not recorded.
- Local log tampering/deletion: attacker erases evidence after compromise. Example: `app.log` is deleted on host after initial foothold.
- No `SIEM` (Security Information and Event Management) correlation: separate signals never become incident alert. Example: auth failures and suspicious API access are not correlated.
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

### 10.4 Production review baseline

Priority:
- Default severity is `Medium`; raise to `High` when missing telemetry affects auth, authorization, admin actions, data export, payment/security events, or incident reconstruction.

Production defaults:
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

## 11. A10:2025 Mishandling of Exceptional Conditions

### 11.1 Threat, description, and attacker objective

Unsafe handling of exceptional states (network/database/dependency/input errors) can move systems into fail-open mode and bypass security controls. The attacker objective is to trigger such states and execute blocked actions.

### 11.2 Types and typical exploitation flow

Types:
- Fail-open when authz/introspection is unavailable: access is incorrectly allowed on dependency error. Example: token validation fails upstream but API still returns `200 OK`.
- Unhandled exceptions in critical workflows: service crashes or skips controls after exception. Example: validation exception routes request into branch without authorization check.
- Internal detail leakage via error response: attacker gains implementation data for next step. Example: response reveals SQL fragment, file path, and framework version.
- Partially completed transactions without rollback: system state becomes inconsistent. Example: funds are debited but audit/event record is not created after second-step failure.

Typical flow:
- Trigger exception condition (timeout/malformed input/race)
- Observe system behavior under failure state
- Repeat requests until insecure fallback appears
- Abuse lifted control (for example, authorization bypass)

What gets impacted:
- Authorization and integrity controls
- Transaction reliability
- Service availability and predictability

Impact:
- Unauthorized operations without direct perimeter breach

### 11.3 Practical defense

- Secure-failure model: critical operations must fail-closed
- Local exception handling + global fallback handler
- Hide internal stack/implementation details from clients
- Mandatory rollback for partial failures
- Timeout/retry/circuit-breaker policies that preserve security invariants
- Verification:
  - dependency failure chaos tests
  - missing/invalid input tests
  - rollback correctness and error-path observability tests

### 11.4 Production review baseline

Priority:
- Default severity is `Medium`; raise to `High` or `Critical` when exceptional states bypass authorization, integrity, payment, safety, or audit controls.

Production defaults:
- AuthN/AuthZ, token introspection, policy, payment, and entitlement failures are fail-closed by default.
- Error responses are stable and do not expose stack traces, SQL fragments, secrets, filesystem paths, or internal topology.
- Timeouts, retries, circuit breakers, and fallback modes preserve security invariants.
- Critical multi-step operations have idempotency, transaction boundaries, rollback/compensation, and audit guarantees.
- Degraded mode has an explicit owner, max duration, visible alert, and release approval for high-value systems.

Required evidence:
- Failure-mode matrix for critical dependencies and operations.
- Chaos/fault-injection or integration tests for authz, database, queue, payment, IdP, and policy-engine failures.
- Rollback/compensation evidence for partial transactions.
- Alert and audit samples for fail-closed and degraded-mode events.

Negative tests:
- Unavailable policy, token introspection, or entitlement service does not grant access to protected operations.
- Malformed input and parser errors cannot skip validation or authorization.
- Retry storms cannot duplicate payment, order, export, or privilege-change effects.
- Error responses do not disclose internal details.

False positives / false negatives:
- Generic exception handlers can hide details from users but still skip audit or rollback.
- Chaos tests must assert security outcomes, not only availability.
- Fail-open may be acceptable for narrowly defined low-risk read paths, but only with documented exception and short degraded window.
