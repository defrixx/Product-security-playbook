---
title: "Secure AI-Assisted Development Playbook"
description: "This playbook covers the use of generative AI throughout the software development lifecycle: inline completion, chat-based code generation, AI code review, IDE agents, and codin..."
sidebar:
  order: 50
---
## 1. Scope and Objective

This playbook covers the use of generative AI throughout the software development lifecycle: inline completion, chat-based code generation, AI code review, IDE agents, and coding agents that create or modify application code, tests, dependencies, infrastructure as code, CI/CD workflows, and documentation.

Use it for:
- onboarding AI coding assistants and defining allowed operating modes;
- reviewing changes created wholly or partly by a model;
- release gates for AI-generated code and agent-authored pull requests;
- protecting source code, secrets, architecture context, and development environments;
- verifying dependencies, tests, and security evidence proposed or created by a model.

Document ownership boundaries:
- This playbook owns the secure use of AI when developing conventional software and the evidence required before merge or release.
- General code quality and security requirements are in the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/).
- Autonomy, tool authorization, memory, sandboxing, approval, rollback, and kill-switch controls are in the [Agentic AI Security playbook](/Product-security-playbook/en/ai-security/agentic-ai/playbook/).
- MCP server registry and protocol controls are in the [MCP Security playbook](/Product-security-playbook/en/ai-security/mcp-security/playbook/).

Out of scope:
- developing or training foundation models;
- selecting controls for AI features running inside a product; use the [Securing AI overview](/Product-security-playbook/en/ai-security/securing-ai/overview/);
- the general secure coding baseline independent of code origin.

Objective:
- prevent generation speed, persuasive model output, or coding-agent autonomy from bypassing security requirements, review ownership, and release controls.

---

## 2. Threat Model and Change Classification

Primary scenarios:
- a model creates functionally correct code with injection, broken access control, unsafe deserialization, weak cryptography, or a business-logic flaw;
- a large generated diff is accepted without understanding data flows, trust boundaries, and side effects;
- a coding assistant receives secrets, proprietary code, customer data, or incident artifacts through files, terminal output, logs, diagnostics, or tool responses;
- indirect prompt injection in an issue, README, dependency documentation, test fixture, or web page changes agent behavior;
- a model proposes a nonexistent, impersonated, abandoned, or vulnerable package;
- generated tests confirm the current implementation but do not test security requirements and abuse cases;
- an agent changes authentication, CI/CD, deployment, permissions, or dependencies beyond the intended task.

Classify the change by maximum impact:

| Class | Example | Minimum decision |
|---|---|---|
| Low | Documentation, comments, or local refactoring with no behavior change | Normal review and standard CI |
| Medium | Application logic, parser, API handler, dependency update, or test generation | Human review, security-relevant tests, and required scanners |
| High | Authentication, authorization, cryptography, secrets, tenant isolation, payments, file/upload processing, CI/CD, or IaC | Named domain-competent reviewer, threat/abuse cases, and independent security verification |
| Critical | Production credentials, signing/release policy, destructive migration, privileged automation, or changes without human review | Do not allow autonomous merge/release; require separate approval and environment controls |

Code origin does not change vulnerability severity. AI-generated and human-written changes pass the same product security gates; stronger control is needed where the generation method increases diff size, autonomy, or review uncertainty.

---

## 3. Production Baseline

### 3.1 Governance, Inventory, and Approved Use

`Baseline`:
- Maintain an inventory of approved coding assistants, models/providers, deployment modes, data-handling terms, retention settings, enabled tools, network access, and owners.
- Define the repositories, data classes, and environments allowed for each tool. Consumer accounts and unapproved extensions must not process proprietary or regulated material.
- Assign an accountable human to every change. A model, vendor, or agent identity cannot be the code owner or residual-risk owner.
- Apply branch protection, required reviews, and CI gates equally to human and agent-authored branches.
- Do not treat an AI-generated label as a control. Provenance supports triage and metrics but does not prove that a change is safe.

`High-impact/regulated`:
- Require security and data-owner approval before enabling a new provider, remote code index, repository-wide context, external connector, or autonomous write mode.
- Prohibit direct push and autonomous merge to protected branches.

### 3.2 Context, Data, and Secret Boundaries

`Baseline`:
- Send only the minimum context required for the task. Exclude production data, credentials, private keys, session tokens, and unrelated repository content.
- Treat prompts, chat history, code indexes, terminal output, compiler errors, stack traces, tool responses, screenshots, and uploaded files as separate data flows with classification, retention, and access rules.
- Use enterprise/provider settings that prohibit training on organization data and enforce an acceptable retention policy; verify effective configuration rather than relying on a marketing claim.
- Apply secret scanning before context submission where supported and on every commit/push. Revoke or rotate an exposed secret immediately; deleting it from the diff is insufficient.
- Do not treat `.gitignore`, `.env`, an instruction file, or a request not to read secrets as a security boundary. Technically restrict filesystem scope, environment injection, logs, and tool permissions.

`High-impact/regulated`:
- Use an organization-managed gateway/account, auditable access, and repository allowlist.
- Disable raw prompt/context retention unless an approved forensic or compliance need exists.

### 3.3 Task Definition and Security Context

`Baseline`:
- Before generation, define functional requirements, trust boundaries, data classifications, authorization expectations, prohibited operations, and failure behavior.
- For security-relevant changes, explicitly enumerate negative scenarios: cross-tenant access, privilege escalation, injection, replay, race conditions, unsafe retries, partial failure, and sensitive-data disclosure.
- Require a minimal scoped diff. Approve changes to public interfaces, schemas, authentication flows, dependencies, CI/CD, and infrastructure separately.
- Instruction files and prompt templates may encode workflow and secure defaults, but they are not authorization, sandbox, or release controls.
- Do not rely on a universal secure prompt, persona, threats to the model, or repeated generation as security evidence.

`High-impact/regulated`:
- Bind the task to a threat model, abuse cases, or security acceptance criteria before implementation starts.
- Require a plan/preview before file changes and renewed approval when scope expands.

### 3.4 Generated Code Review

`Baseline`:
- The reviewer must understand changed data flows, trust boundaries, authorization decisions, and external side effects. Verifying only successful execution or UI behavior is insufficient.
- Review generated diffs line by line. Do not merge large opaque changes when the reviewer cannot explain their purpose and consequences.
- Review removed validation, guards, tests, logging, timeouts, and error handling as well as added code.
- Compare implementation against security requirements independently of the model's explanation. Confident output or self-review is not evidence.
- Use the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/) for language- and framework-specific review.

`High-impact/regulated`:
- Require a reviewer who was not the sole author of the prompt and does not rely only on the same model/session for verification.
- Changes to authentication, cryptography, tenant isolation, CI/CD security controls, and signing paths require domain-owner review.

### 3.5 Dependencies and Generated Supply-Chain Changes

`Baseline`:
- Do not install a package solely because a model suggested it. Verify its exact name, namespace, registry, publisher/owner, release history, license, maintenance status, and an official link from a trusted project source.
- Treat nonexistent or unexpectedly new package names as potential slopsquatting/typosquatting signals. Stop the workflow pending human verification.
- Allow dependency changes only through manifests/lockfiles and approved registries; CI must detect unreviewed manifest, lockfile, registry, and install-script changes.
- Apply the generic SCA and secret-scanning baseline from the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/). For AI-generated dependency changes, additionally verify package reputation, transitive dependencies, and lifecycle/install scripts for high-impact packages.
- Do not accept a fabricated version. The resolver must confirm version and integrity; release builds use the reviewed lockfile and immutable integrity/digest where supported by the ecosystem.

`High-impact/regulated`:
- A coding agent must not autonomously install a package or expand registry/network allowlists.
- A new package for authentication, cryptography, serialization, build/release, or privileged runtime requires separate owner approval.

### 3.6 Testing and Independent Verification

`Baseline`:
- Run existing unit, integration, and regression tests after an AI-generated change. Do not weaken assertions or gates to make the pipeline pass.
- Derive tests from requirements and abuse cases, not only from the current implementation. Verify fail-closed behavior and unauthorized paths.
- Run SAST, SCA, and secret scanning under the generic baseline in the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/). For AI-generated changes, this playbook adds independent verification of generated tests and applicable domain scanners and targeted security tests for IaC, containers, and exposed paths.
- Review generated tests like production code. Confirm that they fail when the relevant defect is deliberately introduced.
- A model may assist with triage and remediation, but closing a finding requires a scanner/test rerun and review of the actual diff.

`High-impact/regulated`:
- Require independent security verification not performed solely by the same model/session that created the code.
- Use negative integration tests and manual/adversarial review for critical business rules.

### 3.7 Coding Agents and Development Environment

`Baseline`:
- Coding agents with shell, browser, file-write, or package-install capabilities also comply with the [Agentic AI Security playbook](/Product-security-playbook/en/ai-security/agentic-ai/playbook/).
- Run the agent in an ephemeral sandbox with a scoped repository checkout, non-production credentials, and deny-by-default access to the host filesystem, internal network, and cloud metadata.
- Separate reading untrusted external content from privileged execution. An issue, PR comment, README, web page, or package documentation cannot change tool authorization.
- Bound egress allowlists, commands, writable paths, runtime, and resource budget. Blocked egress must fail closed and leave an audit signal.
- Require preview/approval for package installation, workflow changes, secret access, network-allowlist changes, destructive commands, and any external side effects.

`High-impact/regulated`:
- Use a disposable environment per task and short-lived, task-specific credentials.
- An agent-authored change must not modify or disable the controls that verify that same change.

### 3.8 Release Evidence and Monitoring

`Baseline`:
- Retain the task/issue, human owner, changed files, review approvals, CI results, security scan results, and dependency decisions. Do not retain raw sensitive prompts without a defined need.
- Measure security outcomes rather than only accepted suggestions: escaped defects, reopened findings, vulnerable dependency introductions, and review churn.
- Monitor drift after model, provider, extension, tool-permission, or instruction-file changes.
- Incident response must be able to identify changes created during a particular agent/provider period, but do not assume perfect attribution of individual lines.

`High-impact/regulated`:
- Record model/tool configuration, agent permissions, and the approval trail needed to reconstruct the change path.
- Reassess the allowed autonomy mode after a security incident or repeated gate-bypass attempts.

---

## 4. Verification

Required evidence:
- approved-tool inventory and effective data-handling configuration;
- repository/data/environment access matrix;
- branch protection and required-review settings for agent-authored branches;
- sample AI-assisted change with task scope, human owner, reviewed diff, and CI evidence;
- dependency approval evidence for a new package;
- scanner configuration and SAST, SCA, and secret-scanning results;
- sandbox, egress, and approval configuration for coding agents.

Negative tests:
- a secret in a file, terminal output, or stack trace is blocked/redacted before model submission and detected on commit;
- an instruction in an issue or README cannot authorize a forbidden command or exfiltration;
- a hallucinated package name is not installed automatically;
- a manifest change without the expected lockfile or approved registry blocks the pipeline;
- generated authorization code rejects horizontal, vertical, and cross-tenant access;
- the test suite fails after deliberate removal of a security check;
- the agent cannot modify branch protection, a CI security job, or scanner suppression without separate approval;
- a high-impact diff cannot merge with model self-review as the only evidence.

Operational signals:
- percentage of AI-assisted changes that pass required human review and security gates;
- rate of secrets and unapproved dependencies detected before merge;
- escaped-vulnerability rate for AI-assisted and other changes with comparable risk profiles;
- average agent-authored diff size and percentage returned for uncontrolled scope;
- blocked tool, egress, and package-install attempts;
- findings reopened after AI-generated remediation.

---

## 5. Review Decision

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | Condition | Required action |
|---|---|---|
| Critical | An agent can merge/release to a protected environment without human approval and required CI gates | Block the mode and restore branch/release protection |
| Critical | A coding assistant/agent can access production secrets or customer data without an approved need and technical isolation | Revoke access, rotate exposed credentials, and perform incident assessment |
| High | High-impact code was accepted without a reviewer able to explain security behavior and side effects | Block merge pending independent review |
| High | An agent autonomously installs unknown packages or changes registry/egress policy | Block the workflow pending allowlist and approval controls |
| High | Security verification consists only of self-review by the same model/session with no independent tests/scanners | Require new independent verification |
| Medium | Inventory, provenance metadata, or AI-use evidence is incomplete while normal review and release gates remain effective | Assign a remediation owner and due date |
| Medium | Generated tests cover only the happy path | Add negative and abuse-case tests before a high-impact release |
| Low | AI-assisted labels or metrics are inconsistent without affecting access, review, or gates | Fix through process improvement |

A release is approved only when an accountable human understands the change, scope is bounded, dependencies are verified, secrets are protected, security controls have independent evidence, and AI cannot bypass branch, CI, or environment policy.

---

## 6. Related Materials

- [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/)
- [Agentic AI Security playbook](/Product-security-playbook/en/ai-security/agentic-ai/playbook/)
- [MCP Security playbook](/Product-security-playbook/en/ai-security/mcp-security/playbook/)
- [Securing AI overview](/Product-security-playbook/en/ai-security/securing-ai/overview/)
- [Threat Modeling playbook](/Product-security-playbook/en/review/threat-modeling/playbook/)
- [Release Governance playbook](/Product-security-playbook/en/review/release-governance/playbook/)
- [SLSA provenance overview](/Product-security-playbook/en/supply-chain/slsa-provenance/overview/)
