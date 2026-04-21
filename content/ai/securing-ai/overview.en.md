# Securing AI: Overview

## 1. Scope and objective

This overview is aimed at securing production systems:
- AI/LLM assistants and agentic workflows
- RAG and knowledge retrieval
- decisioning models (including antifraud/scoring)
- MLOps/LLMOps and business-system integrations

Objective:
- cover all key security aspects starting from `Zero Trust`
- provide practical, verifiable controls for each aspect

---

## 2. Foundational principles

### 2.1 Zero Trust for AI

**Focus:**
- trust no input, output, integration, model, or data source by default

**Practical controls:**
- `Critical`: explicit trust boundaries for `user -> model -> tool -> downstream` flows
- `Critical`: `deny-by-default` for tool execution and data access
- `Critical`: continuous verification of user context (not just at session start)
- `High`: policy-as-code for authorization and data policies
- `Recommended`: regular threat modeling for agent-flow changes

**Verification signals:**
- percentage of tool calls blocked by policy engine
- trust-boundary test coverage

---

## 3. Security aspects and controls

### 3.1 Identity and access (AI IAM)

**Risks:**
- over-privileged agents
- service identity impersonation
- cross-tenant access

**OWASP LLM Top 10 coverage:**
- `LLM06: Excessive Agency`
- `LLM02: Sensitive Information Disclosure`

**Practical controls:**
- `Critical`: workload identity instead of static keys
- `Critical`: least privilege per tool and API
- `Critical`: tenant-aware authorization on every downstream step
- `High`: short-lived tokens, rotation, audience binding
- `Recommended`: SoD for high-impact operations

**Verification signals:**
- share of services without long-lived credentials
- number of cross-tenant policy denied attempts

### 3.2 Data security and privacy

**Risks:**
- PII/secret leakage via prompt/context/output
- unauthorized data use for training
- retention/regulatory violations

**OWASP LLM Top 10 coverage:**
- `LLM02: Sensitive Information Disclosure`
- `LLM07: System Prompt Leakage`

**Practical controls:**
- `Critical`: data classification + data handling matrix for AI use cases
- `Critical`: DLP/redaction before model call and before user response
- `Critical`: encryption in transit/at rest + tenant isolation
- `High`: strict data minimization for inference/training
- `High`: enforceable retention/deletion controls
- `Recommended`: privacy impact assessment for new AI features

**Verification signals:**
- number of DLP hits per 1k requests
- deletion SLA and on-time completion rate

### 3.3 Model and supply chain security

**Risks:**
- compromised models/adapters
- vulnerable ML dependencies
- legal exposure from licensing terms

**OWASP LLM Top 10 coverage:**
- `LLM03: Supply Chain`
- `LLM04: Data and Model Poisoning`

**Practical controls:**
- `Critical`: trusted registry + provenance checks (hash/signature/publisher)
- `Critical`: SBOM/AI-BOM for model artifacts and runtime
- `Critical`: CVE scanning + gating for critical vulnerabilities
- `High`: controlled promotion flow (dev -> staging -> prod) with approvals
- `High`: legal review for third-party model terms
- `Recommended`: independent red team before production adoption

**Verification signals:**
- release share with signed artifacts
- time-to-fix for critical CVEs in AI stack

### 3.4 Prompt, context, and RAG security

**Risks:**
- prompt injection (direct/indirect)
- poisoned knowledge base
- retrieval without ACL and cross-tenant leakage

**OWASP LLM Top 10 coverage:**
- `LLM01: Prompt Injection`
- `LLM08: Vector and Embedding Weaknesses`
- `LLM04: Data and Model Poisoning`

**Practical controls:**
- `Critical`: strict context separation (trusted vs untrusted)
- `Critical`: retrieval with document-level/tenant-level authorization
- `Critical`: ingestion security pipeline (malware/content/policy checks)
- `High`: detection for jailbreak/injection patterns
- `High`: prompt template versioning + mandatory security review
- `Recommended`: adversarial test suite in CI/CD

**Verification signals:**
- injection success rate in red-team tests
- share of RAG documents passing policy scan

### 3.5 Output and agent-action security

**Risks:**
- unsafe execution of model output
- unwanted transactions and destructive actions
- escalation through tool chains

**OWASP LLM Top 10 coverage:**
- `LLM05: Improper Output Handling`
- `LLM06: Excessive Agency`

**Practical controls:**
- `Critical`: always treat output as untrusted input
- `Critical`: schema validation + allowlisted commands/operations
- `Critical`: two-step execution for state-changing actions (`preview -> explicit confirm -> execute`)
- `Critical`: human-in-the-loop + four-eyes approval for high-impact/irreversible operations
- `High`: sandbox for code/command execution
- `High`: rate limits, loop guards, kill switch with defaults (`max tool-chain depth=3`, `max autonomous steps=5`, `request budget=60 req/min per user`, `token budget=20k tokens/request`)
- `Recommended`: transaction risk scoring before execution

**Verification signals:**
- number of blocked risky action attempts
- share of requests blocked by guardrail budget limits
- mean time to kill in runaway-agent scenarios (SLO: `<=60s`)

### 3.6 Infrastructure and runtime security

**Risks:**
- compromise of inference/training environments
- lateral movement inside platform
- uncontrolled egress

**OWASP LLM Top 10 coverage:**
- `LLM10: Unbounded Consumption`
- `LLM03: Supply Chain`

**Practical controls:**
- `Critical`: node/container hardening (seccomp, runtime policies)
- `Critical`: network segmentation and egress allowlisting
- `Critical`: centralized vault-based secrets management
- `High`: EDR/runtime detection for AI workloads
- `High`: immutable logs + centralized SIEM
- `Recommended`: confidential compute for sensitive scenarios

**Verification signals:**
- runtime policy coverage across AI workloads
- number of egress-deny events in AI namespaces

### 3.7 AppSec for AI applications

**Risks:**
- classic web/API vulnerabilities + AI-specific attack chains
- unsafe frontend rendering of model output
- SSRF/XSS/SQLi via LLM-mediated paths

**OWASP LLM Top 10 coverage:**
- `LLM05: Improper Output Handling`
- `LLM01: Prompt Injection` (in LLM-mediated flows)

**Practical controls:**
- `Critical`: secure coding baseline (OWASP ASVS + AI-specific checks)
- `Critical`: parameterized queries + context-aware output encoding
- `Critical`: CSP/HTML sanitization for LLM content
- `High`: SAST/DAST/IAST profiles for AI endpoints
- `Recommended`: security contract tests between AI gateway and downstream APIs

**Verification signals:**
- high-severity findings discovered before release
- AI endpoint coverage in automated security testing

### 3.8 Monitoring, detection, and incident response

**Risks:**
- late detection of abuse/prompt attacks/data leakage
- lack of AI-specific incident playbooks

**OWASP LLM Top 10 coverage:**
- cross-functional coverage of `LLM01`–`LLM10` through detection and response

**Practical controls:**
- `Critical`: audit trail for prompts, retrieval, tool calls, policy decisions with field-level data minimization
- `Critical`: secret/PII masking and redaction in logs before storage
- `Critical`: store raw payload only for forensics, encrypted, with strict access control and retention `<=30 days`
- `Critical`: detection rules for injection, privilege misuse, data exfiltration
- `High`: AI incident runbooks (containment, rollback, customer comms)
- `High`: tabletop exercises for realistic AI attack paths
- `Recommended`: continuous purple teaming

**Verification signals:**
- MTTD/MTTR for AI security events
- percentage of incidents handled with runbook compliance
- share of raw-payload logs deleted on time per retention policy

### 3.9 Governance, risk, and compliance

**Risks:**
- uncontrolled rollout of AI features
- non-compliance with internal policy and regulations

**OWASP LLM Top 10 coverage:**
- cross-functional coverage of `LLM01`–`LLM10` through release gates and risk ownership

**Practical controls:**
- `Critical`: AI risk register with owner and remediation due dates
- `Critical`: release gate for security/privacy/compliance criteria
- `High`: model cards + system cards for high-risk use cases
- `High`: third-party risk assessment for AI vendors
- `Recommended`: quarterly control effectiveness review

**Verification signals:**
- release share passing AI risk gate without exception
- number of overdue remediation actions

### 3.10 Safety and abuse resilience

**Risks:**
- harmful output, misuse, business-logic abuse
- in antifraud scenarios: adversarial adaptation and detector bypass

**OWASP LLM Top 10 coverage:**
- `LLM09: Misinformation`
- `LLM10: Unbounded Consumption` (abuse/automation loops)
- `LLM04: Data and Model Poisoning` (for model manipulation)

**Practical controls:**
- `Critical`: policy filters for harmful/disallowed intents
- `Critical`: safeguarded fallback to deterministic business logic
- `High`: abuse monitoring by user/device/session behavior
- `High`: regular threshold calibration for fraud/risk models
- `Recommended`: attacker-in-the-loop simulations

**Verification signals:**
- false negative/false positive rates in abuse/fraud cases
- model drift indicators and drift response time

---

## 4. Operating model for implementation

### 4.1 Minimum RACI

- Product: owner of AI feature business risk
- Security/AppSec: owner of security requirements and release gates
- ML/AI Engineering: owner of model lifecycle and technical controls
- Platform/SRE: owner of runtime hardening, observability, and IR readiness
- Legal/Privacy: owner of data-use terms and privacy controls

### 4.2 Mandatory release artifacts

- threat model for the AI feature
- policy matrix (`who/what/can-do`)
- data flow + data classification
- model/supply chain provenance package
- test evidence (security + abuse + resilience)