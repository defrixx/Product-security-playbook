# Security Architecture Review Checklist

## 1. Scope, Objective, and Context

This checklist is used to systematically assess how architecture changes affect security risk before release.

Review focus:
- identify new or amplified attack paths;
- verify that key security controls actually work for target scenarios;
- document residual risks, owners, and release decision conditions.

### Input Artifacts

- up-to-date architecture diagram;
- change set description (PR/ticket/ADR);
- data-flow and trust-boundary description;
- component ownership list;
- relevant policies/configurations and test/scan results.

### Review Outputs

- findings list in a standardized format (section 5);
- documented decisions/trade-offs and accepted risks (section 5);
- final security verdict based on gate rules (section 7).

Traceability is mandatory: each significant conclusion must reference a concrete input artifact (PR/config/diagram/log/test).

---

## 2. Threat Modeling and Abuse Cases

For the full process, use the [Threat Modeling Playbook](../threat-modeling/playbook.en.md). It covers methodology selection, input and output artifacts, the recommended path, attack scenarios, risk analysis, control mapping, and the lite path.

For architecture review, the minimum requirement is to:
- update the DFD/C4 or textual description of data flows and trust boundaries;
- produce threat scenarios for new/changed entry points, data flows, and privileged operations;
- map every scenario to an existing control, gap, or accepted risk;
- describe an attack path and verification method for `High`/`Critical` scenarios;
- use STRIDE-LM only as a lite taxonomy, not as a replacement for full threat modeling.

Evidence:
- link to the threat model or threat scenario table;
- links to security tests, control evidence, or exercise results.

---

## 3. Core Security Domains Review

Validate controls through threat scenarios and abuse cases from section 2: which scenario each control mitigates, where gaps remain, and what evidence confirms control effectiveness.

### 3.1 Authentication

| What to verify | Evidence |
|---|---|
| Mechanisms: OAuth 2.0, OpenID Connect, API keys, mTLS | IdP/provider configuration |
| Centralized authentication; no custom cryptography; token validation (`issuer`, `audience`, `expiration`) | Token validator examples; failure tests for invalid tokens |

### 3.2 Authorization

| What to verify | Evidence |
|---|---|
| Model: RBAC/ABAC | Policy/role matrix |
| Enforcement at every layer (API/service/data); no implicit trust between services; least-privilege principle | Enforcement examples in code/config; tests denying unauthorized actions |

### 3.3 Audit and Logging

| What to verify | Evidence |
|---|---|
| Authentication events, authorization decisions, data access, and critical actions are logged | Logging architecture/config; sample events |
| Tamper resistance; centralized collection; traceability with `correlation_id` | Retention/access validation; immutability/access settings |

---

## 4. Control Coverage

For each row, validate linkage to a threat scenario, abuse case, or explicitly recorded requirement from section 2. If linkage is unclear, record it as a gap or justified exception.

### 4.1 Data Security

| What to verify | Evidence |
|---|---|
| Data classification (Public/Internal/Confidential/Secret) | Data classification matrix |
| Encryption at rest; TLS in transit | Encryption/TLS configuration |
| Secrets management via Vault/KMS; token/key leakage risks | Secrets rotation/access policy; secret scanning results |

### 4.2 Integration Security

| What to verify | Evidence |
|---|---|
| Trust validation for external systems | API contracts; validation schemas; trust configuration |
| Input validation/sanitization | Validation rules; negative test cases |
| Outbound security (egress control) | Egress/policy configuration |
| Retry/fallback behavior without sensitive data leakage | Integration failure-handling tests |

### 4.3 Runtime Security

| What to verify | Evidence |
|---|---|
| Containers run as non-root | Cluster manifests/policies |
| Unnecessary capabilities are dropped | Policy/manifest checks; scan outputs |
| Runtime controls are enabled (for example seccomp/AppArmor) | Runtime configuration; runtime inspection |
| Secrets are not stored in plaintext env/files | Image/config scan outputs; secret scanning |

### 4.4 Compliance

| What to verify | Evidence |
|---|---|
| Requirement sources (business, security, regulatory) | Requirements register |
| Requirement fulfillment evidence | Control implementation artifacts; verification reports |
| Identified conflicts and resolution | Approval records; decision log |
| Traceability `requirement -> architecture decision -> control` | Traceability matrix; stakeholder approval records |

---

## 5. Decision Log, Findings, and Recommendations

### 5.1 Decision Log and Architecture Notes

Document:
- assumptions;
- trade-offs;
- decision rationale;
- rejected alternatives;
- accepted risks and technical debt with owner and tracking ticket.

Track control exceptions in a separate team security exception policy (if such a document exists, add the reference in ADR/decision log).

Evidence:
- ADR/decision log;
- links to approved exceptions.

### 5.2 Findings and Recommendations (mandatory format)

Each finding must use this template:
- ID:
- Observation:
- Risk/Impact:
- Severity: `Low|Medium|High|Critical`
- Likelihood: `Low|Medium|High`
- Recommendation (specific action):
- Owner:
- Due date:
- Verification method:
- Evidence references (PR/config/log/test/diagram):

Requirements:
- no ambiguous wording;
- owner and due date are mandatory for all `High`/`Critical` findings;
- verification method is mandatory before closure.

---

## 6. Low-Risk Fast Path (Lite Path)

Use the lite path from the [Threat Modeling Playbook](../threat-modeling/playbook.en.md#31-lite-path) as the baseline for minimum analysis.

Use Lite Path only if all are true:
- no new external integrations;
- no authentication/authorization/session changes;
- no new sensitive data processing;
- no new internet-facing entry points;
- no privilege expansion or trust-boundary change.

Minimum mandatory checks (6-8 items):
- verify authentication and authorization for changed components;
- verify input/output validation at integration points;
- verify secrets handling and TLS;
- verify logging of critical security events;
- verify runtime hardening (non-root, capabilities, baseline runtime controls);
- record findings in mandatory format;
- make final decision using gate rules.

Escalation to full review is mandatory if any appears:
- potential `High`/`Critical` risk;
- new entry point or trust boundary;
- uncertainty about evidence completeness.

---

## 7. Final Security Verdict (gate rules)

Statuses:
- `Rejected`
- `Approved with risks`
- `Approved`

Mandatory rules:
- `Rejected` if at least one `Critical` exists without confirmed mitigation;
- `Approved with risks` if accepted `High` risks exist with owner + due date + compensating controls;
- `Approved` only if open risks are not above the agreed threshold (typically not above `Medium`) and a closure plan exists.

Additionally:
- mandatory pre-release fixes must be tracked explicitly;
- residual risks must be explicitly accepted by an authorized owner.
