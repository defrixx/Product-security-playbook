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

## Contributions

Feel free to use, adapt, and extend this repository.

PRs are welcome if you want to improve existing materials or add new ones.

## Author

Product Security Architect with experience in:
- Kubernetes and cloud-native platforms
- Security architecture and threat modeling
- Secure SDLC and platform security

---

## Contents (Current Structure)

- [`templates/playbook.md`](templates/playbook.md) - reusable template for new security playbook documents

### Architecture
- [`content/architecture/security-review/`](content/architecture/security-review/) - security architecture review checklist
- [`content/architecture/case-studies-security/`](content/architecture/case-studies-security/) - security lens for 16 architecture case studies (ByteByteGo)

### Web Application
- [`content/web/owasp-top-10/`](content/web/owasp-top-10/) - practical defense playbook for OWASP Top 10 (2025)

### AI
- [`content/ai/owasp-llm-top-10/`](content/ai/owasp-llm-top-10/) - OWASP LLM Top 10 threat-focused overview (2025)
- [`content/ai/securing-ai/`](content/ai/securing-ai/) - Securing AI overview

### Kubernetes
- [`content/kubernetes/cluster-security-review/`](content/kubernetes/cluster-security-review/) - Kubernetes cluster security review playbook
- [`content/kubernetes/pod-security/`](content/kubernetes/pod-security/) - Kubernetes pod security hardening playbook
- [`content/kubernetes/seccomp/`](content/kubernetes/seccomp/) - Kubernetes seccomp review checklist
- [`content/kubernetes/container-escape-capability-abuse/`](content/kubernetes/container-escape-capability-abuse/) - attack vectors overview

### Identity
- [`content/identity/oidc-oauth/`](content/identity/oidc-oauth/) - OIDC + OAuth 2.0 security playbook

### Secrets
- [`content/secrets/vault/`](content/secrets/vault/) - Vault security playbook

### Supply Chain
- [`content/supply-chain/slsa-provenance/`](content/supply-chain/slsa-provenance/) - SLSA v1.2 provenance overview for container image CI/CD pipelines