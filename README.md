# Product Security Playbook

This repository is a working collection of product security documents, including architecture review checklists, Kubernetes hardening playbooks, and security overviews.

## Contents (Current Structure)

- [`content/architecture/security-review/`](content/architecture/security-review/) - security architecture review checklist
- [`content/kubernetes/pod-security/`](content/kubernetes/pod-security/) - Kubernetes pod security hardening playbook
- [`content/kubernetes/seccomp/`](content/kubernetes/seccomp/) - Kubernetes seccomp review checklist
- [`content/kubernetes/container-escape-capability-abuse/`](content/kubernetes/container-escape-capability-abuse/) - attack vectors overview
- [`content/identity/oidc-oauth/`](content/identity/oidc-oauth/) - OIDC + OAuth 2.0 security playbook
- [`content/secrets/vault/`](content/secrets/vault/) - Vault security playbook

- [`templates/playbook.md`](templates/playbook.md) - reusable template for new security playbook documents

## Language Note

English files are the primary source.
Russian files are machine-translated drafts and may contain wording inaccuracies.
If you notice issues in Russian text, please suggest fixes via PR or issue.

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
