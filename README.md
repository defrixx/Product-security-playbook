# Product Security Playbook

This repository is a working collection of product security documents, including architecture review checklists, Kubernetes hardening playbooks, and security overviews.

## Repository Status

This repository is a working security knowledge base, not a finished reference.

The content evolves over time based on practical work:
- Existing documents are regularly reviewed and updated
- New materials are added incrementally
- Documents should be treated as work in progress

The guidance reflects accumulated engineering experience, not immutable standards.

## Authorship Note

Not every document here was written from scratch by one person.

Some sections compile and adapt existing practices, references, and public knowledge, with additional analysis, edits, and implementation context.

Treat this repository as curated working material rather than purely original standalone writing.

---

## Contents

### Review and Governance
- [`content/review/architecture/`](content/review/architecture/) - security architecture review checklist
- [`content/review/threat-modeling/`](content/review/threat-modeling/) - threat modeling methodology review and practical playbook
- [`content/review/release-governance/`](content/review/release-governance/) - release governance and security quality gates for protected environments, deployment approvals, release evidence, exceptions, and escalation
- [`content/review/vulnerability-management/`](content/review/vulnerability-management/) - vulnerability triage, exploitability, SLA, release blocking, exceptions, and closure evidence

### Application Security
- [`content/application-security/web/owasp-top-10/`](content/application-security/web/owasp-top-10/) - practical defense playbook for OWASP Top 10 (2025)
- [`content/application-security/web/browser-security/`](content/application-security/web/browser-security/) - browser and frontend controls for CSP, CORS, cookies, third-party scripts, embedded content, and frontend supply chain
- [`content/application-security/api/api-security-patterns/`](content/application-security/api/api-security-patterns/) - API security and integration patterns for REST, SOAP/XML, GraphQL, Webhooks, and gRPC
- [`content/application-security/business-logic/business-logic-abuse/`](content/application-security/business-logic/business-logic-abuse/) - business logic abuse playbook for ATO, signup/trial/promo abuse, tenant isolation, workflow abuse, and sensitive business flows
- [`content/application-security/secure-coding/code-review/`](content/application-security/secure-coding/code-review/) - secure coding and code review playbook for validation, encoding, auth/session, access control, injection, file handling, logging, crypto misuse, and review evidence
- [`content/application-security/identity/oidc-oauth/`](content/application-security/identity/oidc-oauth/) - OIDC + OAuth 2.0 security playbook

### DevSecOps
- [`content/platform-security/kubernetes/cluster-security-review/`](content/platform-security/kubernetes/cluster-security-review/) - Kubernetes cluster security review playbook
- [`content/platform-security/kubernetes/adversarial-validation/`](content/platform-security/kubernetes/adversarial-validation/) - Kubernetes adversarial validation and attack-path review playbook
- [`content/platform-security/kubernetes/pod-security/`](content/platform-security/kubernetes/pod-security/) - Kubernetes pod security hardening playbook
- [`content/platform-security/kubernetes/secrets/`](content/platform-security/kubernetes/secrets/) - Kubernetes Secrets security playbook
- [`content/platform-security/kubernetes/seccomp/`](content/platform-security/kubernetes/seccomp/) - Kubernetes seccomp review checklist
- [`content/platform-security/kubernetes/container-escape-capability-abuse/`](content/platform-security/kubernetes/container-escape-capability-abuse/) - container escape and Linux capability abuse overview
- [`content/platform-security/secrets/vault/`](content/platform-security/secrets/vault/) - Vault security playbook

### Supply Chain
- [`content/supply-chain/slsa-provenance/`](content/supply-chain/slsa-provenance/) - SLSA v1.2 provenance overview for container image CI/CD pipelines
- [`content/supply-chain/container-image-security/`](content/supply-chain/container-image-security/) - container image and OCI registry security playbook for Dockerfile baselines, digest pinning, multi-arch images, registry promotion, scanning, signing, and deploy-time verification

### AI Security
- [`content/ai-security/securing-ai/`](content/ai-security/securing-ai/) - Securing AI overview
- [`content/ai-security/owasp-llm-top-10/`](content/ai-security/owasp-llm-top-10/) - OWASP LLM Top 10 threat-focused overview (2026)
- [`content/ai-security/agentic-ai/`](content/ai-security/agentic-ai/) - Agentic AI security playbook for autonomy, tools, memory, action traces, sandboxing, and kill-switch controls
- [`content/ai-security/ai-assisted-development/`](content/ai-security/ai-assisted-development/) - secure AI-assisted development playbook for coding assistants, generated code review, dependency verification, SDLC gates, and coding-agent environments
- [`content/ai-security/mcp-security/`](content/ai-security/mcp-security/) - MCP security playbook for server/tool registry, deployment patterns, OAuth, capability drift, and protocol-layer logging

### Reference
- [`reference/infrastructure-technologies/`](reference/infrastructure-technologies/) - overview of infrastructure technologies and their production operating models
