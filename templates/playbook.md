# Playbook Title

## 1. Scope and Objective

Define what this playbook covers, who should use it, and which production decision it supports.

**In scope:**
- System, workflow, technology, or control area.
- Environments covered, for example production, staging, CI/CD, or developer workstations.
- Main assets and trust boundaries.

**Out of scope:**
- Adjacent topics covered by other playbooks.
- Known exclusions and assumptions.

**Objective:**
- Concrete security outcome.
- Release, review, or operational decision this playbook enables.

---

## 2. Version Assumptions and Sources

Security-sensitive guidance must state the authoritative sources and version assumptions used to write the document.

| Area | Assumption | Source | Last verified |
|---|---|---|---|
| Standard/framework | Version or publication status | Official URL | YYYY-MM-DD |
| Product/runtime | Supported versions or feature gates | Vendor docs | YYYY-MM-DD |

Rules:
- Prefer primary sources: RFCs, vendor docs, OWASP, NIST, CNCF/Kubernetes, CIS, cloud provider docs.
- If guidance depends on a version or feature gate, state the minimum version and fallback behavior.
- Do not write "recommended" for a security control unless the source and operational rationale are current.

---

## 3. Threat Model

Describe realistic production attack paths, not generic theory.

**Assets:**
- Critical data, identities, infrastructure, business state, or release artifacts.

**Attackers and entry points:**
- External user, compromised workload, malicious insider, CI identity, partner system, or supply-chain actor.
- Entry points and trust boundaries.

**High-impact scenarios:**
- Scenario 1: preconditions, abused weakness, impact.
- Scenario 2: preconditions, abused weakness, impact.

---

## 4. Production Baseline

State concrete defaults. Include numbers where they are operationally meaningful.

**Mandatory controls:**
- Control with exact requirement and applicability.
- Control with owner or enforcement point.

**Production defaults:**
- Numeric limit, timeout, TTL, cadence, retention period, or policy default.
- Exception rule with owner, justification, expiry, and compensating controls.

**Tradeoffs and applicability:**
- When the default can break production or cause false positives.
- When a stronger profile is required.

---

## 5. Verification

A recommendation is incomplete unless it can be verified.

**Required evidence:**
- Configuration, policy, log, test, scan, or runtime evidence.

**Negative tests:**
- Abuse case that must fail.
- Misconfiguration or bypass attempt that must be rejected.

**Operational signals:**
- Metrics, alerts, audit events, drift checks, or incident-response evidence.

**False positives / false negatives:**
- Common cases where tools overreport or miss the real risk.

---

## 6. Review Decision

Use the repository severity model consistently.

| Severity | Meaning | Required action |
|---|---|---|
| Critical | Direct path to severe compromise or unsafe release state | Block release until mitigated; exception requires explicit authorized risk acceptance if policy allows it |
| High | Material production risk with plausible exploitation | Owner, due date, mitigation or accepted risk |
| Medium | Meaningful gap with bounded impact or lower likelihood | Track remediation and verify closure |
| Low | Minor hardening or clarity issue with limited impact | Fix opportunistically |

Required output:
- Finding summary.
- Owner.
- Due date.
- Verification method.
- Residual risk decision.

---

## 7. Related Materials

- Link to related RU/EN playbooks.
- Link to standards, vendor docs, and internal policies.

---

## 8. RU/EN Synchronization Checklist

Before finalizing:
- Any material change in `*.ru.md` is mirrored in `*.en.md`, and the reverse.
- Structure, headings, tables, numeric defaults, severity rules, and source references are equivalent.
- Differences are intentional and documented, not accidental translation drift.

---

## Writing Rules

- Use clean Markdown and avoid decorative symbols.
- Keep guidance production-relevant, testable, and specific.
- Avoid vague phrases such as "secure properly", "use best practices", or "configure safely".
- Include operational context, tradeoffs, and verification signals where relevant.
- Keep recommendations aligned with current authoritative sources.
