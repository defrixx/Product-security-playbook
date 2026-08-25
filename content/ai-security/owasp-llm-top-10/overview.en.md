# OWASP Top 10 for LLM Applications (2026): Overview

## 1. Scope

This overview is a threat-focused summary of OWASP Top 10 for LLM Applications (2026).

This overview focuses on:
- how each threat emerges in real systems
- what technical and business risks it creates
- what adjacent risks can amplify impact

Document ownership:
- This document owns the threat taxonomy and risk vocabulary for LLM application reviews.
- It explains prompt injection, data leakage, tool abuse, excessive agency, and related risks as categories and attack mechanics.
- It does not define the production control baseline; use [Securing AI](../securing-ai/overview.en.md) for controls, implementation priorities, and verification signals.
- It does not replace the specialized playbooks for agent autonomy or MCP protocol governance.

The 2026 taxonomy covers a model used as an application component. When the model acts through tools, retains memory, coordinates with other agents, or autonomously causes downstream effects, pair this taxonomy with the OWASP Top 10 for Agentic Applications.

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

## 3. Threat-focused breakdown of OWASP LLM Top 10

This document intentionally focuses on threats, attack mechanics, and risks.
For practical controls, implementation priorities, and verification signals, see [Securing AI](../securing-ai/overview.en.md). For agent autonomy, memory, tool execution, and action traces, use the [Agentic AI security playbook](../agentic-ai/playbook.en.md). For MCP server registry, protocol deployment, OAuth usage, and capability drift, use the [MCP security playbook](../mcp-security/playbook.en.md).

## 3.1 LLM01: Prompt Injection

### Summary (OWASP)
A vulnerability where input (including hidden or external content) changes LLM behavior against expected rules and can lead to unauthorized actions.

### How it appears in live environments
- hidden instructions in documents, web pages, emails, images
- prompts like "ignore previous instructions"
- obfuscation (encodings, multilingual payloads, split payload)

### Main risks
- unauthorized tool invocation
- exfiltration of sensitive data
- manipulation of decisions in business processes

---

## 3.2 LLM02: Sensitive Information Disclosure

### Summary (OWASP)
Risk of exposing sensitive information (PII, secrets, internal data, intellectual property) via LLM responses, context, training, or insecure data handling.

### How it appears in live environments
- leakage of PII/secrets from chat history in responses
- confidential data entering training/fine-tuning
- disclosure of internal configs and diagnostic details

### Main risks
- privacy breach and regulatory penalties
- credential compromise and lateral movement
- intellectual property and trade secret leakage

---

## 3.3 LLM03: Excessive Agency

### Summary (OWASP)
Excessive functionality, permissions, or autonomy allows model output to trigger damaging actions, especially when prompt injection or misinformation reaches tools and downstream systems.

### How it appears in live environments
- the application exposes tools that are not required for the task
- tool credentials or permissions exceed the initiating user's scope
- irreversible or externally visible actions execute without deterministic authorization or confirmation

### Main risks
- unauthorized changes, deletions, messages, or transactions
- cross-tenant access through an over-privileged execution identity
- prompt injection or false output acquiring a much larger blast radius

---

## 3.4 LLM04: Supply Chain

### Summary (OWASP)
Compromise or misrepresentation of models, adapters, datasets, dependencies, tools, and deployment artifacts across the LLM supply chain.

### How it appears in live environments
- vulnerable or malicious ML/LLM dependencies and serialized artifacts
- an untrusted base model, LoRA adapter, converter, or third-party tool package
- a promoted model artifact whose identity, provenance, or integrity was not verified

### Main risks
- backdoored behavior or malicious code execution in training/inference environments
- substitution between evaluated and deployed artifacts
- licensing, privacy, and compliance exposure from opaque sources

---

## 3.5 LLM05: Data and Model Poisoning

### Summary (OWASP)
Poisoning of pre-training, fine-tuning, feedback, or retrieval data, or direct manipulation of model artifacts, introduces triggers, biases, or unsafe behavior that persists into production.

### How it appears in live environments
- poisoned training, fine-tuning, or preference datasets
- fine-tuning subversion and trigger-based backdoors
- malicious documents or embeddings entering a RAG corpus

### Main risks
- integrity loss, targeted bias, manipulation, or toxic output
- persistent backdoor behavior activated by a trigger
- fraud and unsafe automation in downstream processes

---

## 3.6 LLM06: Unbounded Consumption

### Summary (OWASP)
Uncontrolled use of requests, context, tokens, inference, tools, or recursive workflows causes availability loss, denial of wallet, capacity exhaustion, or model extraction.

### How it appears in live environments
- prompt flooding, oversized context, long sessions, or expensive repeated inference
- parallel, recursive, or tool-mediated loops without budgets
- high-volume API probing intended to extract model behavior or weights

### Main risks
- service degradation and denial of service
- uncontrolled spend and shared-capacity starvation
- model theft and intellectual-property loss

---

## 3.7 LLM07: Misinformation

### Summary (OWASP)
Plausible but false, misleading, or unsupported output causes users or downstream systems to make incorrect decisions or perform unsafe actions.

### How it appears in live environments
- confident false claims in legal, medical, financial, or operational workflows
- fabricated evidence, citations, completion status, or nonexistent packages
- users or automation treating model output as authoritative without verification

### Main risks
- user harm and incorrect business or security decisions
- reputational, contractual, and legal damage
- supply-chain compromise through hallucinated dependencies

---

## 3.8 LLM08: Hidden Context Exposure

### Summary (OWASP)
Unauthorized extraction, inference, or reconstruction of non-user-facing instructions and operational context becomes security-relevant when it reveals secrets, policy logic, tool schemas, trust boundaries, workflow criteria, or proprietary behavior.

### How it appears in live environments
- extraction of system prompts, developer instructions, or retrieved policy text
- disclosure of tool/function schemas, refusal logic, roles, or workflow rules
- credentials or security-critical configuration embedded in model-visible context

### Main risks
- targeted bypass of guardrails and more effective prompt injection
- exposure and reuse of embedded credentials
- privilege escalation or unsafe output manipulation using disclosed policy and tool details

---

## 3.9 LLM09: Vector and Embedding Weaknesses

### Summary (OWASP)
Weaknesses in generating, storing, authorizing, and retrieving embeddings and vectors, especially in RAG, lead to cross-tenant leakage, poisoned context, unauthorized access, and reconstruction of source data.

### How it appears in live environments
- cross-tenant retrieval from a shared vector index
- authorization applied after retrieval instead of inside the index query
- embedding inversion, membership inference, and poisoned retrieval content

### Main risks
- confidential data leakage or source reconstruction
- response manipulation through poisoned context
- legal and compliance exposure from improperly governed data sources

---

## 3.10 LLM10: Improper Output Handling

### Summary (OWASP)
Insufficient validation, sanitization, and contextual encoding of LLM output before it reaches consumer systems turns model responses and generated code into injection or execution paths.

Here, downstream systems means any component that consumes LLM output and performs an action: databases, APIs, shell runners, template engines, browser renderers, workers, and automation pipelines.

### How it appears in live environments
- model output sent directly to shell, API, SQL, or a template renderer
- generated HTML, JavaScript, or Markdown rendered without contextual sanitization
- generated code or package recommendations accepted without security verification

### Main risks
- XSS, SQL injection, SSRF, command injection, or RCE in downstream components
- vulnerable generated code propagated at scale
- supply-chain compromise through hallucinated packages

---

## 4. Threat Differentiation Summary

- `LLM01 Prompt Injection`: attacks execution instructions; key distinction is behavioral control of the model through input content.
- `LLM02 Sensitive Information Disclosure`: leaks sensitive data in outputs; distinction is confidentiality impact rather than action control.
- `LLM03 Excessive Agency`: grants excessive functionality, permissions, or autonomy; distinction is that model output can reach privileged actions.
- `LLM04 Supply Chain`: compromises or misrepresents external artifacts and dependencies; distinction is risk entering through the delivery chain.
- `LLM05 Data and Model Poisoning`: poisons training, fine-tuning, feedback, or retrieval data; distinction is persistent behavior manipulation through model inputs or artifacts.
- `LLM06 Unbounded Consumption`: permits uncontrolled resource use; distinction is availability, capacity, cost, and extraction impact.
- `LLM07 Misinformation`: produces plausible but false or unsupported content; distinction is decision-quality and downstream trust.
- `LLM08 Hidden Context Exposure`: reveals or reconstructs non-user-facing control context; distinction is the attack advantage created by exposed instructions, policy, and schemas.
- `LLM09 Vector and Embedding Weaknesses`: exploits authorization, integrity, and confidentiality failures in retrieval and embedding storage.
- `LLM10 Improper Output Handling`: passes model output unsafely to a consumer; distinction is the integration boundary after generation.

---

## 5. Related Materials

- [Securing AI overview](../securing-ai/overview.en.md)
- [Agentic AI security playbook](../agentic-ai/playbook.en.md)
- [MCP security playbook](../mcp-security/playbook.en.md)
- [Threat modeling playbook](../../review/threat-modeling/playbook.en.md)
- [API security playbook](../../application-security/api/api-security-patterns/playbook.en.md)
