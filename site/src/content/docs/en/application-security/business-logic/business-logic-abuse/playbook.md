---
title: "Business Logic Abuse Playbook"
description: "This playbook covers abuse of valid product functionality: account takeover pressure, signup/trial/promo abuse, inventory and booking manipulation, tenant isolation abuse, workf..."
sidebar:
  order: 40
---
## 1. Scope and Objective

This playbook covers abuse of valid product functionality: account takeover pressure, signup/trial/promo abuse, inventory and booking manipulation, tenant isolation abuse, workflow/state-machine bypass, and automation against sensitive business flows.

Use this document for:
- product features where the attacker does not need a classic injection bug;
- API and web flows that can be automated, replayed, chained, or economically abused;
- pre-release review of signup, login, reset, checkout, referral, credits, admin/support, export, booking, and tenant-management flows.

Out of scope:
- low-level API authentication and authorization mechanics: use the [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/);
- OAuth/OIDC session and token controls: use the [OIDC + OAuth 2.0 security guide](/Product-security-playbook/en/application-security/identity/oidc-oauth/playbook/);
- browser-only controls: use the [browser and frontend security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/);
- code-level review of validation, encoding, auth/session implementation, injection, file handling, logging, and crypto misuse: use the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/).

Objective:
- identify sensitive business flows before launch;
- set explicit abuse limits, state-machine guards, ownership checks, and detection signals;
- make abuse resistance testable by product, engineering, AppSec, fraud, and operations teams.

---

## 2. Threat Model

Assets:
- account access, user identity, tenant isolation, balances/credits, inventory, coupons, referral rewards, payments, booking slots, exports, admin/support actions, and audit integrity.

Attackers and entry points:
- external users automating public flows;
- fraud actors using bots, proxies, disposable email, stolen credentials, or payment instruments;
- authenticated users abusing object IDs, tenant IDs, role transitions, or workflow order;
- partner or B2B clients exceeding intended machine-to-machine usage;
- insiders or support users misusing privileged product operations.

High-impact scenarios:
- Credential stuffing validates breached credentials and leads to account takeover.
- Trial/signup automation creates many accounts to harvest credits, abuse free usage, bypass quotas, or spam other users.
- Promo/referral abuse loops rewards through fake accounts or self-referrals.
- Inventory/booking abuse reserves scarce goods or slots without intent to purchase or attend.
- Tenant isolation abuse changes `tenant_id`, organization membership, invite state, or support context to access another tenant.
- Workflow abuse calls later state transitions directly: refund without capture, approve without review, export without ownership, downgrade after consuming credits.

---

## 3. Sensitive Flow Inventory

Every sensitive business flow must have an owner, abuse objective, limits, and verification method.

| Flow class | Typical abuse | Required controls |
|---|---|---|
| Login and reset | credential stuffing, account enumeration, reset flooding | adaptive rate limits, breached credential detection where available, MFA/step-up, enumeration-resistant responses, alerting |
| Signup and trial | fake accounts, quota farming, spam, disposable identity abuse | velocity limits, email/phone/domain policy, device/IP reputation where lawful, delayed trust, abuse review queue |
| Promo/referral/credits | self-referral, reward loops, coupon stacking | one-time redemption, graph checks, reward delay, refund/reversal coupling, ledger audit |
| Checkout/payment | scalping, card testing, duplicate capture, refund abuse | idempotency, state machine, payment risk controls, per-account/device/payment limits |
| Booking/inventory | denial of inventory, reservation hoarding | hold TTL, payment commitment, release jobs, per-actor quotas, anomaly detection |
| Tenant/admin/support | cross-tenant access, privileged action misuse | object/tenant authorization, JIT/JEA admin access, immutable audit, approval for destructive actions |
| Export/reporting | bulk data theft, scraping through valid UI/API | row/object authorization, export quotas, async approval for high-volume exports, watermarking/logging |

Recommended control:
- Classify new or changed flows as `normal`, `sensitive`, or `critical`.
- `Sensitive` flows require explicit abuse cases and monitoring before release.
- `Critical` flows require negative tests, runbook coverage, and an owner-approved release decision.

---

## 4. Release-Ready Baseline

### 4.1 Account Takeover and Credential Abuse

Release-ready defaults:
- Rate-limit by account, source network, device/session signal, and client/application where available. A single IP-only limit is not enough.
- Do not reveal whether username, email, phone, or reset token exists.
- Use MFA or step-up for risky login, password reset completion, new device, payment change, admin action, and bulk export.
- Notify users of password change, MFA change, new recovery method, and suspicious successful login.
- Log failed and successful authentication events with correlation IDs and risk context.

Verification:
- Credential stuffing simulation with known invalid and reused pairs does not create lockout DoS or account enumeration.
- Reset flow cannot be used to flood a victim or infer account existence.
- Successful takeover-like sequence produces alertable events.

### 4.2 Signup, Trial, Promo, and Referral Abuse

Release-ready defaults:
- Free-value flows have explicit budgets per account, tenant, payment instrument, device/browser signal, source network, and time window.
- Promo and referral rewards are delayed until the referred account reaches a real qualifying event.
- Reward ledgers are append-only or auditable; reversal is possible when abuse is confirmed.
- Disposable email, suspicious domain, proxy/Tor, and high-velocity patterns route to friction or review, not necessarily hard block.
- Abuse controls are evaluated for privacy and regional legal requirements before device fingerprinting or biometric/human-detection signals are used.

Verification:
- Automated creation of accounts cannot multiply credits, coupons, or trial capacity beyond the configured budget.
- Self-referral and circular referral graphs are detected or blocked.
- Coupon stacking and refund-after-reward scenarios fail safely.

### 4.3 Tenant Isolation and Object/Workflow Authorization

Release-ready defaults:
- Authorization is enforced on every object and state transition in the service/domain layer.
- Tenant context is derived from authenticated membership and policy, not from user-controlled request fields alone.
- Cross-tenant admin/support actions require explicit support context, reason, ticket, JIT/JEA access where applicable, and immutable audit.
- Bulk operations and exports re-check authorization per object or use a verified tenant-scoped query path.

Verification:
- User from tenant A cannot read, update, export, invite into, approve, or infer objects from tenant B.
- Support/admin impersonation cannot silently bypass tenant audit.
- Batch, GraphQL, async job, and export paths enforce the same policy as single-object APIs.

### 4.4 State Machines, Idempotency, and Replay

Release-ready defaults:
- Critical workflows use explicit state machines with allowed transitions.
- State-changing requests use idempotency keys where retries or duplicate events are expected.
- Webhook, payment, refund, booking, and fulfillment flows reject stale, duplicate, out-of-order, and already-consumed events.
- Business state changes and external side effects are transactionally coupled or compensated through a tested recovery process.

Verification:
- Direct calls to later workflow states are denied.
- Duplicate payment/webhook/booking messages do not duplicate external effects.
- Replay after the configured time window fails and creates an investigation signal.

### 4.5 Abuse Monitoring and Response

Release-ready defaults:
- Sensitive flows emit structured events with actor, tenant, object, action, result, reason, correlation ID, and relevant risk signals.
- Dashboards track flow conversion, rejection, velocity, duplicate attempts, reward issuance/reversal, account creation bursts, login failure clusters, and export volume.
- Abuse response has playbooks for throttling, temporary friction, account/tenant suspension, reward reversal, token/session revocation, and customer support communication.
- High-risk flows have an emergency control that can disable, throttle, or add friction to the risky action without redeploying application code.

Verification:
- A tabletop or simulation proves that the team can identify affected accounts/tenants, stop the flow, reverse unsafe credits where possible, and preserve evidence.

### 4.6 Abuse budgets and configuration governance

Release-ready defaults:
- Every sensitive flow has a versioned abuse budget: actor keys, counters, time windows, thresholds, friction path, owner, and expiry/review cadence.
- Starting budgets are explicit even when the final values are product-specific: signup/trial by account, tenant, payment instrument, device/browser signal, source network, and `24h`/`7d` windows; reset and OTP by account plus delivery destination; booking/inventory by actor plus scarce resource; export by actor, tenant, object count, byte volume, and time window.
- Limit configuration changes are treated as production policy changes. High-risk limit increases require owner approval, reason, rollout time, rollback path, and monitoring confirmation.
- Fail-open behavior is documented. If the limiter, risk engine, queue, or ledger is degraded, critical flows either fail closed or fall back to a bounded safe mode with an explicit maximum window.

Verification:
- Compare configured limits against the flow inventory and confirm each sensitive flow has owner-approved thresholds.
- Test that limit bypass through alternate identifiers, batch APIs, GraphQL aliases, async jobs, retries, and partner credentials is rejected or counted under the same abuse budget.
- Simulate risk-engine or limiter outage and confirm the flow follows the documented fail-closed or bounded safe-mode behavior.

---

## 5. Review Decision

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | Condition | Required action |
|---|---|---|
| Critical | Abuse enables cross-tenant action, account takeover at scale, payment/ledger manipulation, irreversible admin/support action, or bulk export of sensitive data | Block release until remediated; exception requires formal risk acceptance by security leadership and business owner |
| High | Bypass of a limit or state-machine guard in a critical flow, promo/referral economic abuse, export scraping, signup/trial quota farming, or privileged workflow abuse with bounded impact | Assign owner and due date, implement mitigation or compensating controls, and confirm negative tests and monitoring |
| High | High-risk flow has no versioned abuse budget, emergency throttle/friction control, or tested fail-closed/safe-mode behavior | Block broad rollout until limits, owner, monitoring, and fallback behavior are defined and tested |
| Medium | Sensitive flow lacks owner, abuse objective, limits, monitoring, runbook, or negative tests, but exploitation does not immediately enable high-impact business action | Create remediation with owner, due date, and release follow-up; do not expand the flow until baseline evidence exists |
| Low | Naming, dashboards, labels, or documentation are incomplete, but limits, authorization, and state guards work | Fix opportunistically and verify during the next review |

A high-risk product flow is release-ready only when it has explicit flow classification, abuse cases, limits, owner, negative tests, monitoring signal, and residual-risk decision.

---

## 6. Related Review Overlay

Use this playbook together with the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/). Secure coding review checks whether security primitives are implemented correctly; business-logic abuse review checks whether valid actions can still break product invariants. For high-risk product flows, both reviews are required before release.

---

## 7. Related Materials

- [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/)
- [Threat modeling playbook](/Product-security-playbook/en/review/threat-modeling/playbook/)
- [Secure coding and code review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/)
- [Vulnerability management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/)
