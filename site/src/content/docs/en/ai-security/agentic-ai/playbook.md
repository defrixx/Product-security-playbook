---
title: "Agentic AI Security Playbook"
description: "This playbook covers AI agents and multi-agent workflows that plan, call tools, use memory, retrieve context, execute code, browse the web, or change business state."
sidebar:
  order: 30
---
## 1. Scope and Objective

This playbook covers AI agents and multi-agent workflows that plan, call tools, use memory, retrieve context, execute code, browse the web, or change business state.

Use this document for:
- security review of autonomous and semi-autonomous workflows;
- release gates for agents with tools, memory, browser/email/file access, or code execution;
- defining policy enforcement, action tracing, approval, rollback, and kill-switch requirements;
- building negative tests for tool misuse, memory poisoning, delegation abuse, and runaway loops.

Document ownership:
- This playbook owns agent autonomy, tool use by agents, memory/scratchpad/checkpoint handling, action traces, approvals, rollback, and kill-switch behavior.
- It treats prompt injection, data leakage, and excessive agency through the lens of agent execution and business impact.
- It relies on [Securing AI](/Product-security-playbook/en/ai-security/securing-ai/overview/) for the general AI control baseline and on the [OWASP LLM Top 10 overview](/Product-security-playbook/en/ai-security/owasp-llm-top-10/overview/) for threat taxonomy.
- It does not define MCP protocol, server registry, or transport governance controls; use the [MCP security playbook](/Product-security-playbook/en/ai-security/mcp-security/playbook/).

Out of scope:
- MCP protocol-specific controls; use the [MCP security playbook](/Product-security-playbook/en/ai-security/mcp-security/playbook/);
- general LLM threat taxonomy; use the [OWASP LLM Top 10 overview](/Product-security-playbook/en/ai-security/owasp-llm-top-10/overview/);
- generic API, browser, Kubernetes, and supply-chain controls unless they are part of the agent runtime.

Objective:
- ensure agents cannot turn ambiguous, malicious, or mistaken instructions into unauthorized access, unsafe execution, data leakage, or uncontrolled business impact.

---

## 2. Agent Threat Model

Minimum components to model:
- model and prompt layer;
- orchestration loop, planner, router, policy engine, and tool selector;
- working memory, scratchpad, long-term memory, retrieval stores, and checkpoints;
- tools and downstream systems;
- user, workload, and tool identities;
- browser, URL fetcher, file parser, code interpreter, shell, or office/email integration;
- audit trail, approvals, rollback paths, and kill switch.

High-impact scenarios:
- prompt injection or poisoned retrieval content causes the agent to call a tool outside the intended task;
- an attacker hijacks an agent by changing its prompt, memory, runtime configuration, identity binding, tool manifest, or orchestration route, so the deployed agent no longer enforces the approved policy;
- a rogue or shadow agent, duplicate deployment, or unregistered automation reaches live data or tools outside the approved inventory and monitoring boundary;
- a long-running workflow accumulates secrets, PII, or tokens in scratchpad, memory, logs, or serialized checkpoints;
- a browser or code-execution tool downloads malicious content, executes generated code, or reaches internal network destinations;
- one agent delegates a task to a more privileged agent or shared tool without preserving the original authorization context;
- the agent performs technically valid actions that violate business intent, for example bulk deletion, duplicate transaction, or external disclosure.

A particularly dangerous combination is access to sensitive data, ingestion of untrusted content, and a channel for data transfer or action execution. Where one workflow needs all three, separate them across trust zones or agent roles and enforce a policy boundary between reading and privileged action. Treat GitHub Issues, pull-request comments, READMEs, web pages, email, package documentation, and repository content as untrusted input even when hosted by a trusted organization.

---

## 3. Production Baseline

### 3.1 Agent Inventory and Classification

`Baseline`:
- Maintain an inventory of production agents, owners, runtime location, model/provider, autonomy level, tools, memory stores, retrieval sources, identities, data classes, and business operations.
- Give each deployed agent a verifiable identity and bind it to an approved configuration or deployment record. Detect unknown identities, duplicate deployments, unregistered runtimes, configuration drift, and tool use by agents absent from the inventory; quarantine them from live tools and data pending review.
- Classify each agent by maximum impact, not by intended use. A read-only assistant with access to confidential data is still sensitive; an agent with a single write tool may be high-impact.
- Perform initial triage across three axes: attack surface, blast radius, and evidence for defense controls. The minimum fast question is whether the agent executes tools, and if so, whether execution is isolated from the host, internal network, credentials, and production data.
- Assess the agent in two states: vendor-as-shipped/default configuration and the actually deployed configuration. If the safe posture depends on opt-in settings, paid features, a customer-managed gateway, sandbox, or egress policy, that must be visible in the release decision.
- Do not count a vendor claim as a control without evidence that it is enforced. A detection-only guardrail that only logs or warns after an irreversible action is a forensic signal, not a preventive control.
- Assign an explicit autonomy profile:
  - `Assistive`: no tool execution or only user-visible draft output.
  - `Read-only tool user`: can retrieve data but cannot change business state.
  - `State-changing agent`: can create, update, submit, trigger, or delete.
  - `Execution agent`: can run code, browse, manipulate files, or interact with external content.

`High-impact/regulated`:
- Require a named product owner, security owner, SRE/operations owner, and data owner before launch.
- Review access and tool entitlements at least quarterly and after every material model/provider/tool change.

### 3.2 Policy Enforcement and Authorization

`Baseline`:
- Put a policy enforcement layer between model output and tool execution. The model may propose an action; policy decides whether it can run.
- Authorize every tool call using user/workload identity, tenant, role, data class, environment, action, and workflow state.
- Never treat model reasoning, natural-language instructions, prompt text, or tool descriptions as authorization evidence.
- Split tools by risk: separate read/write/admin/bulk/export/destructive operations into distinct capabilities with distinct scopes.
- Use short-lived, tool-specific credentials. Do not share one broad agent identity across unrelated tools.

`High-impact/regulated`:
- Require step-up authentication or human approval for high-impact, irreversible, cross-tenant, financial, security, privacy, or external-disclosure actions.
- Strip active tokens, secrets, and session cookies from checkpoints, scratchpads, persisted memory, tool outputs, and execution traces before storage.
- For multi-agent workflows, propagate original user/workload context and enforce delegation boundaries at every hop.

Starting defaults:
- `max autonomous steps=5` for read-only workflows;
- `max autonomous steps=3` before re-authorization for state-changing workflows;
- `max tool-chain depth=3`;
- default state-changing execution flow: `preview -> explicit confirm -> execute`;
- kill-switch SLO `<=60s` for state-changing or execution agents.

### 3.3 Memory, Retrieval, and State

`Baseline`:
- Treat working memory, scratchpads, long-term memory, vector stores, summaries, checkpoints, and tool outputs as data stores subject to classification, access control, retention, deletion, and audit requirements.
- Exclude secrets, tokens, credentials, raw regulated data, and unnecessary sensitive fields from memory by policy.
- Apply document-level and tenant-level authorization before retrieved content enters the agent context.
- Mark untrusted retrieved content as untrusted. It may inform the answer, but it must not override policy, identity, or tool authorization.
- Version prompts, memory rules, retrieval policies, embedding models, and dataset snapshots so incident response can roll back context, not only code.

`High-impact/regulated`:
- Use memory write policies that validate what the agent may persist, who can read it later, and when it expires.
- Quarantine or disable memory sources that show poisoning, unexpected sensitive data, or abnormal write patterns.
- Test recovery for semantic integrity: restored vector stores and memory must produce expected authorized retrieval behavior and must not reintroduce poisoned content.

Production defaults:
- no indefinite retention for working memory;
- raw session/scratchpad retention disabled by default outside forensic mode;
- memory entries containing sensitive data require explicit retention class and deletion workflow;
- forensic raw payload capture retention `<=30 days`.

### 3.4 Browser, Email, File, and Code Execution Tools

`Baseline`:
- Run browser automation, URL fetchers, file parsers, and code interpreters in isolated sandboxes with no default access to internal networks, host files, cloud metadata services, or production credentials.
- Enforce egress allowlists for agent-run browsers and fetch tools. Use deny-by-default for arbitrary public web access.
- Scan and sanitize downloaded or retrieved content before it enters memory, RAG pipelines, or execution tools.
- Block high-risk file types by default: executables, scripts, archives, macros, and active content unless the workflow explicitly requires them.
- Treat package names and versions, install commands, and registry instructions from model output or external content as untrusted. Do not allow automatic installation until package identity, approved registry, publisher, version, and integrity/lockfile evidence are verified.
- Patch browser engines, HTML/PDF/document parsers, sandbox images, and execution runtimes promptly.

`High-impact/regulated`:
- Require human approval before executing third-party code, generated code with external side effects, package installation, shell commands, or file operations outside a temporary workspace.
- Use ephemeral execution environments with network restrictions, CPU/memory/time limits, read-only base images where practical, and central log export before teardown.
- Prohibit agents from autonomously navigating the public web for state-changing workflows unless the domain set, data handling, and prompt-injection controls are explicitly reviewed.

### 3.5 Action Trace, Monitoring, and Incident Response

`Baseline`:
- Produce an agent action trace that records decisions relevant to security without storing unnecessary raw sensitive content.
- Correlate model calls, retrieval events, memory writes, tool invocations, policy decisions, approvals, downstream actions, and final output.
- Alert on abnormal tool sequences, repeated policy denials, new tool combinations, unexpected memory writes, cross-tenant attempts, high token/request spend, and behavior drift after model or prompt changes.
- Alert when an unknown agent identity, duplicate runtime, unapproved prompt/configuration digest, unexpected orchestration route, or inventory-to-runtime mismatch appears.
- Keep raw prompts, context, tool payloads, and scratchpads out of normal logs; use minimized metadata and redacted fields.

`High-impact/regulated`:
- Maintain runbooks for data leakage, runaway agent, malicious tool use, poisoned memory/RAG source, compromised tool credential, and unsafe state-changing action.
- Test kill switch and rollback paths before launch and after major runtime/tool changes.
- Exercise incident timelines using actual log fields; a runbook is not ready if responders cannot reconstruct who or what caused a downstream action.

---

## 4. Verification

Required evidence:
- agent inventory entry with autonomy profile, owner, tools, memory stores, identities, and data classes;
- deployed-agent identity/configuration attestation and reconciliation results showing no unknown, duplicate, or unregistered agent runtime;
- vendor-as-shipped vs deployed-configuration assessment, including enabled tools, memory, connectors, sandboxing, egress controls, approval modes, and paid/optional security features;
- policy matrix: `who/what/can-do` for each tool and memory source;
- action trace schema and sample redacted trace;
- sandbox configuration for browser/file/code tools;
- memory retention and deletion policy;
- approval and kill-switch drill results for high-impact agents.

Negative tests:
- prompt injection tries to call a forbidden tool and is blocked by policy;
- retrieved document instructs the agent to ignore policy and cannot override tool authorization;
- an instruction in a GitHub Issue, PR comment, README, or package documentation cannot obtain secrets, expand egress, or invoke a privileged tool;
- a fabricated or unexpectedly new package name is not installed automatically and routes the workflow to manual review;
- user from tenant A cannot retrieve or act on tenant B data through memory, tools, or delegated agents;
- write action cannot execute without preview and confirmation;
- serialized checkpoint contains no active tokens or secrets;
- browser tool cannot reach cloud metadata, internal admin services, or unapproved external domains;
- code execution cannot access host filesystem, production credentials, or unrestricted network egress;
- multi-agent delegation preserves the original authorization context.

Operational signals:
- percentage of tool calls with policy decision logged;
- approval coverage for high-impact actions;
- denied tool calls per 1k sessions;
- memory write rejection rate and sensitive-data detections;
- mean time to kill runaway agents, target `<=60s`;
- behavior drift alerts after model, prompt, tool, or memory-policy changes.

---

## 5. Review Decision

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | Agent condition | Required action |
|---|---|---|
| Critical | Agent can autonomously perform irreversible, financial, administrative, cross-tenant, or external-disclosure actions without policy enforcement and approval | Block release |
| Critical | Execution/browser tool can reach production credentials, host filesystem, cloud metadata, or internal network by default | Block release and isolate runtime |
| High | Memory/checkpoints can persist active credentials, secrets, or regulated data without retention and deletion controls | Block high-impact workflows until fixed |
| High | Multi-agent workflow loses original authorization context or allows privilege escalation through delegation | Block release for privileged workflows |
| High | Action traces cannot reconstruct high-impact downstream actions | Fix before production launch |
| High | Tool-executing agent depends on vendor-claimed, opt-in, or detection-only controls without proven sandboxing, egress control, and authorization enforcement in the deployed configuration | Block state-changing/execution workflows until controls are confirmed |
| Medium | Inventory or policy matrix is incomplete for read-only or low-impact agents | Track remediation with owner and due date |
| Medium | Behavior drift monitoring is missing after model/prompt changes | Require compensating review and test evidence |
| Low | Prompt, tool, or memory metadata lacks consistent naming but does not affect access or logging | Fix opportunistically |

Release is approved only when the agent has bounded autonomy, explicit policy enforcement, safe memory handling, isolated execution surfaces, usable forensic traces, and tested kill-switch behavior.

---

## 6. Related Materials

- [Securing AI overview](/Product-security-playbook/en/ai-security/securing-ai/overview/)
- [MCP security playbook](/Product-security-playbook/en/ai-security/mcp-security/playbook/)
- [Secure AI-Assisted Development playbook](/Product-security-playbook/en/ai-security/ai-assisted-development/playbook/)
- [OWASP LLM Top 10 overview](/Product-security-playbook/en/ai-security/owasp-llm-top-10/overview/)
- [Threat modeling playbook](/Product-security-playbook/en/review/threat-modeling/playbook/)
- [Browser security playbook](/Product-security-playbook/en/application-security/web/browser-security/playbook/)
- [API security playbook](/Product-security-playbook/en/application-security/api/api-security-patterns/playbook/)
