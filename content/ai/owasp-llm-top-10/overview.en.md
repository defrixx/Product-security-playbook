# OWASP Top 10 for LLM Applications (2025)

## 1. Scope

This overview aims to translate OWASP Top 10 for LLM Applications (2025) into practical steps.

This overview focuses on:
- how each threat can look in reality
- what the business risks are
- which mitigations to use
- which controls can be implemented and regularly verified

---

## 2. Threat context (how LLM incidents happen in reality)

Most incidents are failures at trust boundaries between components:
- user input -> model
- external content -> RAG/indexing -> model
- model output -> tools/API/DB
- model runtime -> cost/quotas/infrastructure
- model lifecycle -> datasets/adapters/registries/deployment

In real reviews, these areas are non-negotiable:
- IAM and authorization for tools and downstream systems
- data classification and handling (PII, secrets, etc.)
- secure output processing before execution/rendering
- provenance and integrity of models/adapters/datasets

---

## 3. Practical breakdown of OWASP LLM Top 10

Priority labels:
- `Critical` — mandatory for production; release blocker if absent
- `High` — implement in the nearest release cycle
- `Recommended` — improves maturity and resilience; planned implementation

## 3.1 LLM01: Prompt Injection

### Summary (OWASP)
A vulnerability where input (including hidden or external content) changes LLM behavior against expected rules and can lead to unauthorized actions.

### How it appears in production
- hidden instructions in documents, web pages, emails, images
- prompts like "ignore previous instructions"
- obfuscation (encodings, multilingual payloads, split payload)

### Main risks
- unauthorized tool invocation
- exfiltration of sensitive data
- manipulation of decisions in business processes

### Priority mitigations and controls
- `Critical`: policy enforcement between LLM and tools (strict action allowlist + deny-by-default)
- `Critical`: prohibit executing raw model output without deterministic validation and policy checks
- `Critical`: human approval for high-impact operations (payments, deletion, external sending)
- `High`: detection pipeline for direct/indirect injections in input and RAG context
- `High`: adversarial security tests (including obfuscation/multilingual/multimodal cases) in CI
- `Recommended`: context channel isolation and trust-tiered prompt assembly (trusted/untrusted context separation)

---

## 3.2 LLM02: Sensitive Information Disclosure

### Summary (OWASP)
Risk of exposing sensitive information (PII, secrets, internal data, intellectual property) via LLM responses, context, training, or insecure data handling.

### How it appears in production
- leakage of PII/secrets from chat history in responses
- confidential data entering training/fine-tuning
- disclosure of internal configs and diagnostic details

### Main risks
- privacy breach and regulatory penalties
- credential compromise and lateral movement
- intellectual property and trade secret leakage

### Priority mitigations and controls
- `Critical`: DLP and redaction for prompts/context/output (before sending to the model and before returning to the user)
- `Critical`: prohibit secrets in system prompts/knowledge base + automated secrets scanning
- `Critical`: tenant isolation + encryption in transit/at rest
- `High`: verifiable retention/deletion policies + legally aligned training-data opt-out
- `High`: data minimization and sanitization pipeline before training/indexing
- `Recommended`: privacy-preserving techniques (differential privacy, tokenization) for sensitive scenarios

---

## 3.3 LLM03: Supply Chain

### Summary (OWASP)
LLM supply chain risks: untrusted models, adapters, data, dependencies, and infrastructure that can be tampered with, vulnerable, or legally problematic.

### How it appears in production
- vulnerable dependencies in the ML/LLM pipeline
- untrusted base model, LoRA adapter, artifact converter
- compromised model repository accounts or fake models

### Main risks
- backdoor model behavior
- malicious code execution in training/inference environments
- legal and compliance risks related to licenses/T&C

### Priority mitigations and controls
- `Critical`: mandatory security gate for external models/adapters (source, hash, signature, owner)
- `Critical`: continuous CVE/dependency scanning of the ML toolchain and blocking critical vulnerabilities
- `Critical`: artifact signing + hash pinning for models, adapters, and containers
- `High`: SBOM/AI-BOM as a mandatory release artifact
- `High`: license/T&C drift monitoring and legal review for third-party providers
- `Recommended`: independent red-team evaluation of models before production adoption

---

## 3.4 LLM04: Data and Model Poisoning

### Summary (OWASP)
Data and model poisoning attacks where triggers and biases are introduced into training/fine-tuning/RAG, compromising model behavior integrity and safety.

### How it appears in production
- poisoned training/fine-tuning datasets
- trigger/backdoor behavior activated by specific phrases
- malicious embeddings/documents in the RAG corpus

### Main risks
- integrity loss (bias, manipulation, toxic output)
- hidden trigger-based backdoor behavior
- fraud and unsafe automation in downstream processes

### Priority mitigations and controls
- `Critical`: data lineage + versioning + approval workflow for all datasets
- `Critical`: quality/safety gates before ingestion (source authenticity, policy checks, toxic/outlier filtering)
- `High`: regression suites for known trigger/backdoor patterns
- `High`: anomaly detection on training/inference signals (loss drift, behavior drift)
- `High`: rollback-ready model registry with a signed promotion process
- `Recommended`: regular poisoning red-team campaigns and tabletop exercises

---

## 3.5 LLM05: Improper Output Handling

### Summary (OWASP)
Insufficient validation and sanitization of LLM output before passing it to consumer systems (for example: SQL/API/shell/template renderer/browser), making model responses an injection vector and enabling malicious code execution.

Here, downstream systems means any component that consumes LLM output and performs an action: databases, APIs, shell runners, template engines, browser renderers, workers, and automation pipelines.

### How it appears in production
- model output sent directly to shell/API/SQL/template renderer
- LLM-generated JS/Markdown rendered without sanitization
- generated code/packages used without verification

### Main risks
- XSS, SQLi, SSRF, RCE via downstream execution
- escalation through tool invocation chains
- supply-chain compromise via hallucinated packages

### Priority mitigations and controls
- `Critical`: always treat output as untrusted input + schema validation before any action
- `Critical`: parameterized queries and prohibition of dynamic command execution from output
- `Critical`: context-aware encoding (HTML/JS/SQL/Markdown/email) and secure defaults
- `High`: sandbox execution for generated code and commands
- `High`: CSP and strict browser-side policies for rendering LLM content
- `Recommended`: SAST/DAST/IAST profiles specifically covering LLM integrations

---

## 3.6 LLM06: Excessive Agency

### Summary (OWASP)
Excessive autonomy of an LLM agent (tools/plugins/functions and permissions), allowing dangerous actions from ambiguous, incorrect, or manipulated instructions.

### How it appears in production
- the agent has extra tools not needed for the task
- plugins operate with permissions broader than the user scope
- destructive actions execute autonomously and without confirmation

### Main risks
- unauthorized changes/deletions/transactions
- cross-tenant leakage due to over-privileged identity
- rapidly growing blast radius in agentic architectures

### Priority mitigations and controls
- `Critical`: minimize tools/functions/permissions (agent capability hardening)
- `Critical`: execute actions strictly in user context (RBAC/OAuth scopes per action)
- `Critical`: mandatory user confirmation for high-impact actions
- `High`: complete mediation in downstream systems (do not delegate authz to the LLM)
- `High`: rate limits, loop guards, kill switch for agent workflows
- `Recommended`: formal matrix "tool -> permission -> business owner -> risk"

---

## 3.7 LLM07: System Prompt Leakage

### Summary (OWASP)
Leakage of system prompts and hidden instructions, which should not be treated as secrets but, if disclosed, make it easier to bypass defenses and develop chained attacks.

### How it appears in production
- system prompt extraction via probing
- disclosure of internal logic, roles, constraints
- incorrect storage of secrets in prompt/config text

### Main risks
- accelerated guardrail bypass
- compromise of architectural details and secrets
- chained attacks: leakage + injection + privilege abuse

### Priority mitigations and controls
- `Critical`: "system prompt is not a secret" rule in secure coding standards
- `Critical`: move secrets and auth logic from prompts into external controlled services
- `Critical`: prohibit delegating critical security decisions to the model (authn/authz/SoD)
- `High`: prompt linting and PR gates for secrets/risky instructions
- `High`: prompt versioning with security review and change approval
- `Recommended`: regular prompt-leak pentest scenarios and chaos exercises

---

## 3.8 LLM08: Vector and Embedding Weaknesses

### Summary (OWASP)
Weaknesses in generating, storing, and retrieving embeddings/vectors (especially in RAG), leading to cross-tenant leakage, poisoned context, and unauthorized access.

### How it appears in production
- cross-tenant leakage in a shared vector DB
- poisoned documents in the retrieval corpus
- embedding inversion and data reconstruction risks

### Main risks
- confidential data leakage via retrieval
- response manipulation through poisoned context
- legal and compliance risks due to data sources

### Priority mitigations and controls
- `Critical`: permission-aware retrieval (tenant/user/document-level ACL)
- `Critical`: logical isolation of indexes/namespaces by tenant and data class
- `High`: ingestion pipeline with source validation, malware/policy scanning, and content classification
- `High`: immutable audit logs for retrieval and anomaly alerts on access patterns
- `High`: regular re-index integrity checks and purge workflow
- `Recommended`: privacy risk assessment for embedding inversion and leakage simulations

---

## 3.9 LLM09: Misinformation

### Summary (OWASP)
Generation of plausible but false or misleading information (due to hallucination, bias, or incomplete context), creating operational and legal risks.

### How it appears in production
- confident but false answers in legal/medical/finance domains
- fabricated references, invalid claims, non-existent packages
- excessive user trust in model output

### Main risks
- dangerous business decisions and user harm
- reputational and legal damage
- security risks from incorrect technical recommendations

### Priority mitigations and controls
- `Critical`: mandatory source grounding (citation + source validation)
- `Critical`: human sign-off for high-stakes domains
- `High`: confidence thresholds + fallback mode "I don't know/escalate to expert"
- `High`: RAG on trusted sources with knowledge-domain restriction
- `High`: UX transparency mechanisms (AI-generated labeling, applicability limits)
- `Recommended`: KPI control of hallucination rate and a closed-loop remediation process

---

## 3.10 LLM10: Unbounded Consumption

### Summary (OWASP)
Uncontrolled consumption of LLM resources (requests, tokens, inference), leading to DoS, denial-of-wallet, service degradation, and model extraction risks.

### How it appears in production
- prompt flooding, abuse of large context, long sessions
- denial-of-wallet attacks on usage-based billing
- model extraction attempts via API probing

### Main risks
- service degradation and DoS
- uncontrolled cost growth
- model theft and IP loss

### Priority mitigations and controls
- `Critical`: hard quotas/rate limits/budget caps per tenant/user/key
- `Critical`: limits on input/context size and timeout/throttling for heavy requests
- `Critical`: real-time cost monitoring + alerts and auto-cutoff
- `High`: request fingerprinting and detection of extraction patterns
- `High`: graceful degradation + emergency traffic controls during load spikes
- `Recommended`: watermarking/anti-extraction controls and adversarial robustness tuning

---

## 4. Threat Differentiation Summary

- `LLM01 Prompt Injection`: attacks execution instructions; key distinction is behavioral control of the model through input content.
- `LLM02 Sensitive Information Disclosure`: leaks sensitive data in outputs; distinction is confidentiality impact rather than action control.
- `LLM03 Supply Chain`: compromises external dependencies in the LLM stack; distinction is risk entering through vendors/integrations.
- `LLM04 Data and Model Poisoning`: poisons training/indexed data; distinction is behavior manipulation by altering the model knowledge base.
- `LLM05 Improper Output Handling`: unsafely executes model output in consumer systems; distinction is the integration layer after generation.
- `LLM06 Excessive Agency`: grants an agent excessive permissions/tools; distinction is over-privileged autonomous action.
- `LLM07 System Prompt Leakage`: exposes hidden instructions and internal logic; distinction is easier guardrail bypass, not direct code execution by itself.
- `LLM08 Vector and Embedding Weaknesses`: weaknesses in retrieval/embeddings/RAG storage; distinction is the context and retrieval layer.
- `LLM09 Misinformation`: produces plausible but false content; distinction is decision-quality and trust risk rather than direct exploitation.
- `LLM10 Unbounded Consumption`: allows uncontrolled token/resource usage; distinction is availability and cost impact (DoS/denial-of-wallet).