# Security Architecture Review Checklist

## 1. Scope and Context

Define the boundaries of the review:

- Change type:
  - New system / service
  - Modification of existing architecture
  - External integration
- Scope level:
  - Application / Service
  - Platform / Infrastructure
  - Data / Storage
- Trust boundaries:
  - Internal
  - External (third-party, internet-facing)

---

## 2. Baseline vs Change Analysis

Strict comparison: **before → after**

- Added components
- Modified components
- Removed components
- Data flow changes:
  - New data flows
  - Modified existing flows
- Trust boundary changes

---

## 3. Trigger-based Risk Identification

Identify risk triggers:

- New integrations:
  - External APIs
  - Partner systems
- Changes in access model:
  - New roles
  - Privilege expansion
- Changes in:
  - Authentication
  - Authorization
  - Session management
- Sensitive data handling:
  - PII / secrets / tokens introduced
- Deployment model changes:
  - Cloud / on-prem / hybrid

---

## 4. Attack Surface Analysis

Assess attack surface impact:

- New entry points:
  - API endpoints
  - UI
  - Background jobs
- Exposure:
  - Internet-facing
  - Internal only
- New protocols / interfaces:
  - HTTP, gRPC, messaging
- Changes in:
  - Network exposure
  - Service-to-service communication

---

## 5. Security Control Bypass Analysis

Identify bypass opportunities:

- Can authentication be bypassed?
- Can authorization be bypassed?
- Is privilege escalation possible?
- Trust boundary violations
- Direct backend access without controls
- Internal APIs exposed externally
- Shadow flows:
  - Undocumented data access paths

---

## 6. Core Security Domains Review

### 6.1 Authentication

- Mechanisms:
  - OAuth 2.0
  - OpenID Connect
  - API keys / mTLS
- Checks:
  - Centralized authentication
  - No custom cryptography
  - Token validation:
    - issuer
    - audience
    - expiration

---

### 6.2 Authorization

- Model:
  - RBAC / ABAC
- Checks:
  - Enforcement at every layer (API, service)
  - No implicit trust between services
  - Least privilege principle

---

### 6.3 Audit & Logging

- What is logged:
  - Authentication events
  - Authorization decisions
  - Data access
- Properties:
  - Tamper resistance
  - Centralized logging
- Traceability:
  - Correlation IDs

---

## 7. Data Security

- Data classification:
  - Public / Internal / Confidential / Secret
- Storage:
  - Encryption at rest
- Transmission:
  - TLS enforcement
- Secret management:
  - Vault / KMS
- Token leakage risks

---

## 8. Integration Security

- Trust validation of external systems
- Input validation / sanitization
- Outbound security:
  - Restrict external access
- Retry / fallback:
  - No sensitive data leakage

---

## 9. Infrastructure & Runtime Security

- Containers:
  - Non-root execution
  - Drop unnecessary capabilities
- Runtime controls:
  - seccomp / AppArmor
- Secret handling:
  - No plaintext storage (env/files)

---

## 10. Threat Modeling / Abuse Cases

Apply STRIDE:

- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

**How to apply:**

- Identify all **new or changed elements**:
  - entry points (API, UI, webhooks)
  - data flows (who → what → where)
  - integrations (internal/external)

- Apply STRIDE **to each element and interaction**, not globally:
  - where identity can be spoofed
  - where data can be tampered
  - where access control can be bypassed

- Convert findings into **explicit abuse cases**:
  - Abuse Case:
    <attack scenario>
  - Impact:
    <what is compromised>
  - Mitigation:
    <required control>

**Requirements:**

- At least one abuse case per new entry point or data flow
- Each abuse case must map to a concrete control or gap
- Absence of abuse cases indicates incomplete analysis

---

## 11. Compliance & Stakeholder Requirements

- Requirements sources:
  - Business
  - Security
  - Regulatory
- Validation:
  - Requirements satisfied
  - Conflicts identified
- Traceability:
  - Requirement → Architecture → Control

---

## 12. Findings & Recommendations

For each finding:

- Finding:
  - Description
  - Location
- Risk:
  - Impact
  - Likelihood
- Recommendation:
  - Concrete action (no ambiguity)

---

## 13. Decision Log / Architecture Notes

Document:

- Assumptions
- Trade-offs
- Decision rationale
- Rejected alternatives

**Requirements:**
- No ambiguity
- Full traceability of decisions
- Every accepted risk or technical debt MUST have a tracking ticket an assigned owner

---

## 14. Final Security Verdict

- Status:
  - Approved
  - Approved with risks
  - Rejected
- Conditions:
  - Required fixes before release
- Residual risks:
  - Explicitly accepted risks