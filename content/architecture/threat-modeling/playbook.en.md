# Threat Modeling Playbook

## 1. Scope, Objective, and Outcome

Threat modeling is needed to understand in advance how a system can be attacked, which assets and business operations would be affected, which controls already reduce risk, where gaps remain, and which decisions must be made before release.

Use this playbook for:
- new systems and major architecture changes;
- reviews of internet-facing services, identity flows, payment flows, AI/ML functionality, supply chain, and platform components;
- preparing security findings, test plans, compensating controls, and accepted-risk decisions.

Minimum output of a threat modeling exercise:
- system model: components, data, flows, trust boundaries, external dependencies;
- list of realistic attack and abuse scenarios;
- mapping of scenarios to assets, vulnerabilities, weaknesses, and controls;
- risk assessment with explicit impact/likelihood and residual risk;
- action plan: mitigation, validation, owner, due date, and release decision.

Threat modeling should be iterative: early sketch during design, refinement before implementation, validation before release, and updates after significant changes, incidents, or new threat intelligence.

---

## 2. Input and Output Artifacts

### Input Artifacts

Mandatory inputs:
- short system description, business goals, and critical user journeys;
- architecture diagram or C4/DFD with trust boundaries;
- data description: data classes, storage locations, transmission, and processing;
- external dependencies: IdP, payment providers, SaaS, third-party APIs, package registries, CI/CD, cloud services;
- entry points and privileged operations;
- authentication/authorization/session model;
- current security controls: WAF/API gateway, mTLS, OAuth/OIDC, rate limiting, secrets management, audit logging, detection, runtime policy;
- SAST/DAST/SCA/IaC/container scan results, pentest results, incident history, and vulnerability management data;
- regulatory/compliance constraints where they affect requirements;
- component owners and acceptable risk appetite.

Useful additional inputs:
- sequence diagrams for critical operations;
- threat intelligence for the industry, product, stack, and similar incidents;
- crown-jewel register and business impact analysis;
- access-control matrix or policy model;
- current detection/response runbooks;
- known abuse patterns from support, fraud, SOC, and incident response.

### Output Artifacts

Minimum outputs:
- Threat model scope: included areas, exclusions, and assumptions;
- DFD/C4/architecture rendering with trust boundaries, data stores, external entities, and security controls;
- Threat scenario table;
- Attack path or attack tree for `High`/`Critical` risks;
- Risk register with inherent risk, existing controls, residual risk, and decision;
- Mitigation backlog with owner, due date, and verification method;
- Test plan: negative tests, abuse-case tests, control validation, logging/detection checks;
- Decision log: accepted risks, exceptions, trade-offs.

Example risk register row:

| ID | Scenario | Asset | Existing controls | Residual risk | Decision | Verification |
|---|---|---|---|---|---|---|
| TM-001 | Attacker replays stolen refresh token against BFF token endpoint | User session, API access | HttpOnly cookie, refresh rotation | Medium | Add reuse detection + revoke token family | Integration test + audit event check |

---

## 3. Practical Workflow

Choose a methodology only after the required outputs are clear. A review is useful when it produces attack scenarios, control evidence, residual risk, and a release decision; the methodology is a way to get there, not the deliverable.

### 3.1 Lite Path

Lite path is allowed only if all are true:
- no new trust boundaries;
- no new external integrations;
- no authentication/authorization/session/cryptography changes;
- no new sensitive data or regulated flows;
- no new internet-facing entry points;
- expected impact is not above `Medium`.

Minimum lite process:
1. Update DFD or textual data flow.
2. Run STRIDE-LM over changed components/flows.
3. Add at least one abuse case per new entry point.
4. Verify controls using the relevant playbook, standard, or vendor guidance.
5. Record residual risk and verification.

Escalation to the full path is mandatory if a potential `High|Critical` appears, a new trust boundary is introduced, privacy/safety/payment impact exists, or the team cannot prove control effectiveness.

### 3.2 Recommended Path

For most product teams, the optimal approach is a hybrid process: the lightweight baseline from Microsoft/OWASP, threat-driven depth from PASTA/IDDIL, privacy coverage from LINDDUN, and risk prioritization using OWASP/NIST/CVSS/EPSS/SSVC. Use STRIDE as a quick taxonomy, not as a standalone methodology.

Use this path by default for:
- new services and major feature changes;
- changes to authN/authZ/session/token flows;
- new external integrations and inbound webhooks;
- processing of `Confidential`, `Secret`, PII, payment, medical, or regulated data;
- CI/CD, artifact provenance, deployment, platform, and Kubernetes control plane changes;
- AI/agentic workflows where data leakage, prompt injection, tool abuse, and autonomous actions matter.

Recommended path steps:

1. Inventory and diagram.
- Gather components, data, entry points, dependencies, trust boundaries, owners.
- Artifact: DFD/C4 + component inventory.
- Example: for BFF/API/DB/IdP/queue/webhook gateway, record protocols, auth method, data classes, and environments.

2. Security and privacy objectives.
- Define CIA, privacy goals, compliance constraints, abuse-sensitive operations.
- Artifact: security requirements and risk criteria.
- Example: payment capture requires integrity and non-repudiation; profile export requires confidentiality and privacy transparency.

3. Threat generation.
- Walk through STRIDE-LM, LINDDUN, OWASP Top 10/API, CAPEC, ATT&CK, domain-specific libraries.
- Artifact: threat scenario table.
- Example: for a webhook, add spoofing, replay, idempotency bypass, event-order tampering, fraud abuse.

4. Attack scenario modeling.
- For top scenarios, describe attack path, preconditions, exploited weakness, affected asset, controls and gaps.
- Artifact: attack tree/path for each `High`/`Critical`.
- Example: replay webhook -> duplicate capture -> ledger inconsistency -> refund abuse.

5. Control mapping.
- Map attack steps to preventive, detective, and responsive controls.
- Use the relevant repository playbooks, MASVS, Kubernetes/NIST/CIS/CNCF guidance, D3FEND, vendor docs.
- Artifact: control coverage matrix.
- Example: signature verification prevents spoofing, idempotency/state machine reduces replay, duplicate-event alert detects abuse.

6. Risk analysis.
- Calculate inherent and residual risk. For CVEs, add CVSS v4.0, EPSS, KEV, and SSVC decision.
- Artifact: risk register.
- Example: inherent `High`, residual `Medium` after timestamp window `<=5m`, idempotency, and state guard; release allowed only with detection and rollback runbook.

7. Verification and release gate.
- Tie every mitigation to a test/evidence item.
- Artifact: test plan, findings, release verdict.
- Example: automated test rejects stale webhook, duplicate event, invalid signature, and out-of-order transition; audit event is visible in SIEM.

### 3.3 Unified Example: PSP Webhook Attack Modeling

Scope:
- `payment-bff`, `checkout-api`, `webhook-gateway`, PSP, `payments-db`, internal ledger topic.
- Critical assets: payment state, authorization/capture decision, customer PII, merchant balance.
- Trust boundaries: public internet to webhook gateway, gateway to internal API, API to database/topic.

Scenario:
- Attacker replays a valid PSP webhook to trigger duplicate capture or inconsistent payment state.

Attack path:
1. Attacker obtains old webhook payload and signature from leaked logs, compromised observability access, or partner-side exposure.
2. Attacker sends the old payload to `/webhooks/psp`.
3. Gateway accepts timestamp skew larger than the operational need.
4. Checkout API treats event as new because the idempotency key is missing or incorrectly scoped.
5. Payment state transitions from `authorized` to `captured` twice, or ledger emits a duplicate credit event.

Risk analysis:
- Impact: `High`, because payment integrity and merchant/customer balances can be affected.
- Likelihood: `Medium`, because valid payload exposure is plausible through logs/support tooling, but signature material is not trivially generated.
- Inherent risk: `High`.
- Existing controls: TLS, IP allowlist, HMAC signature validation.
- Gaps: no strict timestamp window, weak idempotency, insufficient state transition guard, no duplicate-event alert.
- Residual target: `Low|Medium`, depending on fraud exposure.

Recommended controls:
- HMAC signature validation with exact canonicalization and key rotation.
- Timestamp freshness window `<=5m`; reject future timestamps beyond clock skew `<=60s`.
- Single-use event id scoped to PSP account + environment + event type.
- State machine guard: `capture` only from `authorized`, never from terminal states.
- Store raw event hash and normalized event id for replay detection.
- Audit event for accepted/rejected webhook with reason code and correlation_id.
- Alert on duplicate event id, invalid signature spikes, out-of-order transition attempts.
- Negative tests for stale timestamp, duplicate event, modified amount, wrong merchant id, invalid signature, and out-of-order events.

Release gate:
- `Rejected` if duplicate capture is possible.
- `Approved with risks` only if duplicate capture is blocked but alert/runbook is incomplete, with owner and due date.
- `Approved` when controls and tests prove replay cannot cause financial state change and detection exists for attempted replay.

---

## 4. Methodology Reference

### 4.1 Microsoft Threat Modeling

Core steps:
- Define security requirements.
- Diagram the application.
- Identify threats.
- Mitigate threats.
- Validate mitigations.

Use when:
- a fast and understandable SDLC baseline is needed;
- teams already use Microsoft Threat Modeling Tool;
- a shared language for DFDs, trust boundaries, and STRIDE is needed.

Strengths:
- simple sequence;
- fits engineering workflows;
- produces clear artifacts for architecture review.

Limitations:
- STRIDE is not a full methodology and may produce shallow scenarios;
- without attack libraries and risk analysis, the output often becomes a generic checklist.

Example:
- For a new upload service, the team builds a DFD: browser, upload API, object storage, malware scanner, metadata DB. STRIDE identifies file tampering, information disclosure through public bucket, DoS through large uploads, and EoP through service role abuse. Controls and tests are added for each scenario.

### 4.2 STRIDE and STRIDE-LM

STRIDE is a threat taxonomy, not a full methodology.

Categories:
- Spoofing -> authenticity;
- Tampering -> integrity;
- Repudiation -> non-repudiation/accountability;
- Information Disclosure -> confidentiality;
- Denial of Service -> availability;
- Elevation of Privilege -> authorization;
- Lateral Movement in STRIDE-LM -> segmentation/least privilege.

Use when:
- doing a quick pass over DFD elements;
- applying a lightweight option for low-risk changes;
- helping teams start threat modeling.

Limitations:
- weak coverage for business logic abuse, fraud, privacy, and supply chain unless supplemented;
- does not provide risk scoring or control validation.

Example:
- For endpoint `POST /admin/users/{id}/role`, STRIDE prompts spoofing admin identity, tampering role payload, repudiation of role changes, disclosure of role lists, DoS through request floods, and EoP through missing authorization checks.

### 4.3 PASTA

PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric and threat-focused methodology with seven stages:
1. Define Objectives.
2. Define Technical Scope.
3. Application Decomposition.
4. Threat Analysis.
5. Vulnerability and Weakness Analysis.
6. Attack Modeling.
7. Risk and Impact Analysis.

Use when:
- reviewing high-risk systems, payments, identity, or regulated workloads;
- business impact, CTI, vulnerability data, and attack paths need to be connected;
- a serious risk register is needed for decision makers.

Strengths:
- strong linkage from business objectives to attack scenarios to risk treatment;
- supports CTI, vulnerability catalogs, and attack trees;
- pushes likelihood and impact decisions toward evidence.

Limitations:
- high effort if performed fully;
- requires facilitation and mature input data.

Example:
- For an internet banking transfer flow, PASTA starts with the business objective "prevent unauthorized transfer", decomposes mobile app, API, risk engine, and core banking, adds CTI for account takeover and malware, builds an attack tree for session hijack + mule transfer, estimates fraud-loss risk, and selects step-up auth, transaction signing, and velocity rules.

### 4.4 OCTAVE, OCTAVE-S, OCTAVE Allegro

OCTAVE is an organization-focused approach for identifying and managing information security risks. Classic OCTAVE includes an organizational view, a technological view, and protection strategy. OCTAVE-S simplifies the process for small organizations. OCTAVE Allegro focuses more strongly on information assets and risk measurement criteria.

Use when:
- the review must rise above a single application and assess organizational risks;
- there is no mature register of critical assets and risk criteria;
- threat modeling needs to connect to enterprise risk management.

Strengths:
- good at identifying high-priority assets and business impact categories;
- useful for building risk measurement criteria;
- fits program-level assessment, not only product-level assessment.

Limitations:
- heavy for feature-level threat modeling;
- weaker without external threat intelligence and security expertise.

Example:
- An organization chooses three critical information assets: customer PII, signing keys, and billing ledger. OCTAVE Allegro records containers: database, backups, support exports, analytics pipeline. Disclosure/tampering risks and protection priorities are assessed for each container.

### 4.5 Trike

Trike is built around a formal requirements model:
- Requirements Model: actors, assets, actions, rules through an actor-asset-action matrix;
- Implementation Model: DFD, technologies, protocols, trust boundaries, controls;
- Threat Model: threats as deviations from intended actions;
- Risk Model: quantitative impact and likelihood assessment.

Use when:
- authorization correctness is critical;
- the system maps well to actors/assets/actions/rules;
- repeatability and a formal access-control matrix are needed.

Strengths:
- strong defensive perspective;
- good at finding missing or incorrect authorization rules;
- deterministic when inputs are good.

Limitations:
- labor-intensive for large systems;
- tooling and ecosystem are less active than for more popular approaches;
- attack trees and DFDs still require manual work.

Example:
- For a SaaS CRM, build a matrix: tenant admin, support agent, end user x customer record, invoice, API token x CRUD. Any action outside the matrix becomes a threat. This quickly exposes a risk of support agents reading cross-tenant invoices.

### 4.6 LINDDUN

LINDDUN is a privacy threat modeling framework:
- model the system;
- elicit privacy threats;
- manage threats.

Categories:
- Linkability;
- Identifiability;
- Non-repudiation;
- Detectability;
- Disclosure of information;
- Unawareness;
- Non-compliance.

Use when:
- PII, telemetry, analytics, AI datasets, user tracking, consent, and retention are in scope;
- performing privacy-by-design reviews;
- products have GDPR/CCPA/HIPAA-like obligations.

Strengths:
- covers blind spots that STRIDE usually misses;
- provides privacy threat trees and mitigation strategies;
- works well with DFDs.

Limitations:
- does not replace security threat modeling;
- risk scoring must be selected separately.

Example:
- For a mobile analytics SDK, LINDDUN identifies linkability of device_id with email, detectability of a medical condition from API calls, unawareness due to incomplete consent text, and non-compliance due to indefinite retention.

### 4.7 VAST

VAST (Visual, Agile, Simple Threat) focuses on scaling threat modeling through visualization, automation, self-service, and Agile/DevOps integration. It commonly distinguishes application threat models and operational threat models.

Use when:
- many teams and services are involved;
- a repeatable pipeline-integrated practice is needed;
- the organization can support a tool-driven threat library.

Strengths:
- scalability;
- clear visualization for different roles;
- good fit for continuous threat modeling.

Limitations:
- quality depends strongly on tooling and threat library;
- depth may drop if the process becomes fully self-service without security review.

Example:
- A platform team adds template-driven threat models to service onboarding: the team selects "public REST API + PostgreSQL + Kafka", the tool generates baseline threats and required controls, and the security reviewer focuses on deviations and high-risk flows.

### 4.8 NIST SP 800-154 Data-Centric Threat Modeling

NIST SP 800-154 describes data-centric threat modeling as a form of risk assessment focused on protecting specific data in a system. As of April 30, 2026, NIST still marks the publication as an initial public draft, while stating that it plans to finalize it.

Steps:
1. Identify and characterize the system and data of interest.
2. Identify and select attack vectors.
3. Characterize controls for mitigating attack vectors.
4. Analyze the threat model.

Use when:
- the main risk is data: PII, secrets, financial records, training data, telemetry;
- the team needs to understand where data is stored, transmitted, processed, and output;
- negative control implications such as cost, usability, performance, and operational burden need to be considered.

Strengths:
- forces data lifecycle tracking;
- complements DFD and privacy review well;
- considers feasibility and side effects of controls.

Limitations:
- does not cover every system-level attack;
- final risk analysis is less practical than PASTA/FAIR/OWASP.

Example:
- For a secrets scanning platform, model secret values as data of interest: source repositories, CI logs, alert DB, ticket exports. Attack vectors include unauthorized analyst access, log disclosure, webhook exfiltration. Controls include field-level encryption, token redaction, RBAC, and retention limits.

### 4.9 OWASP Threat Modeling Process

OWASP TMP provides structured application threat modeling:
- scope/decompose the application;
- determine threats;
- determine countermeasures and mitigation;
- assess the work.

Use when:
- reviewing web/API applications;
- teams use OWASP Top 10, API Security Top 10, and the repository web/API playbooks;
- a practical middle ground between STRIDE and PASTA is needed.

Strengths:
- clear input artifacts: entry points, exit points, assets, trust levels, DFD;
- maps well to web/API control checklists and test evidence;
- fits application security review.

Limitations:
- output can become generic if limited to Top 10;
- DREAD, often mentioned near OWASP TMP, is outdated and subjective.

Example:
- For a GraphQL API, the team records entry points (`/graphql`, admin console), assets (PII, billing data), trust levels (anonymous, user, admin), generates threats such as introspection leakage, batching DoS, IDOR, overbroad resolver authorization, and maps API controls and tests.

### 4.10 TARA

In this overview, distinguish:
- MITRE TARA (Threat Assessment and Remediation Analysis): a countermeasure-selection method based on a managed attack-to-control catalog;
- Intel TARA (Threat Agent Risk Assessment): a threat-agent-driven risk assessment method.

MITRE TARA workflow:
- Cyber Threat Susceptibility Analysis;
- Cyber Risk Remediation Assessment;
- Knowledge Management.

Use when:
- mission assurance, acquisition, or complex systems are in scope;
- catalog-based countermeasure selection is needed;
- the team can maintain an up-to-date attack/control knowledge base.

Strengths:
- strong mapping of attack vectors to controls;
- considers utility/cost of countermeasures;
- knowledge management keeps the process adaptive.

Limitations:
- maintaining an internal threat-to-control catalog is expensive;
- may be too heavy for a normal product team.

Example:
- For a satellite ground segment, TARA links attack vector "compromise command uplink workstation" to controls: privileged access workstation, command signing, network segmentation, operator dual control, anomaly detection. The team then selects controls with the best utility/cost.

### 4.11 IDDIL/ATC

IDDIL/ATC is a threat-driven Lockheed Martin approach:
- Identify the assets;
- Define the attack surface;
- Decompose the system;
- Identify attack vectors;
- List threat actors and objectives;
- Analysis;
- Assessment and triage;
- Controls.

Use when:
- the goal is to shift from compliance checklist to real threats;
- threat actors, attack surface, and control effectiveness matter;
- an architectural rendering with threats and controls overlaid is useful.

Strengths:
- strong threat-driven framing;
- useful artifacts: threat profiles, functional controls hierarchy, controls scorecard, architectural rendering;
- STRIDE-LM adds lateral movement.

Limitations:
- many manual matrices and documents;
- may not scale well without automation.

Example:
- For a Kubernetes platform, IDDIL records assets (secrets, cluster-admin, workloads), attack surface (API server, CI deploy token, ingress), actors (external attacker, compromised developer, malicious workload), attack vectors (stolen kubeconfig, admission bypass, container escape), and maps controls onto an architectural rendering.

### 4.12 hTMM

Hybrid Threat Modeling Method combines STRIDE, Security Cards, and Persona non Grata:
- identify target system;
- brainstorm threats with Security Cards;
- filter scenarios using realistic personas;
- summarize threats with actor, purpose, target, action, result, impact, threat type;
- assess risk.

Use when:
- a facilitated workshop is needed;
- developers, product, users, and security should all participate;
- CTI is sparse, but the team needs broader threat imagination.

Strengths:
- helps non-security participants generate threat ideas;
- PnG makes scenarios more realistic;
- fits early design.

Limitations:
- does not explicitly require a DFD, so the system model may be weak;
- needs separate risk scoring and control mapping.

Example:
- For a collaboration platform, the team creates Persona non Grata "disgruntled contractor with workspace access" and uses Security Cards to generate scenarios: bulk export before offboarding, secret exfiltration from shared docs, reputational damage through malicious public link.

### 4.13 Security Cards

Security Cards is a threat brainstorming technique, not a standalone methodology. Cards cover:
- human impact;
- adversary motivations;
- adversary resources;
- adversary methods.

Use when:
- in early design;
- running a workshop with a mixed audience;
- searching for non-obvious abuse cases.

Example:
- In a workshop for a children-focused application, a human-impact card pushes the team to consider stalking, harassment, and parental consent abuse, which would not appear in a normal STRIDE pass.

### 4.14 Persona non Grata

Persona non Grata describes unwelcome or malicious personas as user archetypes with motives, resources, and goals.

Use when:
- insider threat is relevant;
- fraud/abuse is relevant;
- social features and marketplaces are in scope;
- reliable CTI is unavailable, but realistic actors can be described.

Example:
- Persona "merchant abusing refund workflow" helps identify a scenario: create an order, initiate a partial refund, exploit a race condition in webhook status update, and withdraw funds before reconciliation.

### 4.15 QTMM

Quantitative Threat Modeling Methodology uses attack trees and quantitative risk aggregation. The privacy-by-design variant combines DFDs, STRIDE, privacy protection goals, misuse cases, quantified attack trees, and security/privacy requirements.

Use when:
- alternative designs must be compared quantitatively;
- mature likelihood, impact, and control-effectiveness data is available;
- privacy/security risks need recalculation after controls.

Strengths:
- supports before/after scoring;
- attack trees show which control breaks which path;
- useful for justifying expensive controls.

Limitations:
- result quality depends on the quality of numerical estimates;
- DREAD should be replaced with a more mature scoring model.

Example:
- For a data sharing platform, the team builds a re-identification attack tree. After adding k-anonymity, aggregation thresholds, and access review, residual risk is recalculated and two export designs are compared.

### 4.16 ID Methodology

ID from the source overview is a practical hybrid:
1. Inventory System Components.
2. Diagram Architecture.
3. Identify Threats.
4. Decompose Application.
5. Illustrate Threats.
6. Document Risk.

Use when:
- a realistic, scalable, and non-academic path is needed;
- the team wants to combine PASTA, IDDIL/ATC, NIST data-centric, LINDDUN, and VAST;
- architectural visualizations with threats and controls are important.

Strengths:
- pragmatic mix;
- good starting point for an internal standard;
- keeps threat-driven focus without full PASTA overhead.

Limitations:
- not a formal standard or broadly validated methodology;
- organization-specific tailoring is mandatory.

Example:
- For a new AI assistant, the team inventories tools, memory, vector DB, model gateway, builds a DFD, generates threats through OWASP LLM Top 10 + LINDDUN, illustrates a prompt injection -> tool abuse attack path, and documents residual risk after tool allowlist, human approval, and audit.

### 4.17 Domain-Specific and Emerging Approaches

Additional approaches and libraries are useful as domain overlays:
- MAESTRO: layer-based threat library for agentic AI; better treated as an attack/control library than a full methodology.
- EMB3D: threat model for embedded devices.
- MITRE medical device playbook: practical principles for safety-critical medical devices.
- KTH TMM / PASTA+FAIR inspired approaches: useful where stronger risk quantification is needed.
- VerSprite OTM: organizational threat modeling approach with PASTA/FAIR influence.

Example:
- For an agentic AI workflow, the main process remains the recommended path, but threat generation is supplemented with OWASP LLM Top 10, MITRE ATLAS, and MAESTRO for prompt injection, tool misuse, memory poisoning, and agent privilege abuse scenarios.

---

## 5. Supporting Resources

### 5.1 Control Frameworks

Control frameworks provide requirements, safeguards, and countermeasures. Use them after scenario generation, not instead of it.

Recommended baseline:
- OWASP MASVS for mobile;
- OWASP API Security Top 10 for API abuse classes;
- NIST SSDF SP 800-218 for secure SDLC controls;
- NIST CSF 2.0 for enterprise cybersecurity risk management;
- NIST SP 800-53 Rev. 5 for organization/system controls;
- CIS Benchmarks for hardening;
- CNCF/Kubernetes guidance for cloud-native workloads;
- MITRE D3FEND for defensive technique vocabulary;
- LINDDUN mitigation strategies for privacy controls;
- vendor docs for technology-specific controls.

Example:
- Threat scenario "attacker steals access token from SPA localStorage" maps to OAuth BCP/OIDC controls, the BFF pattern from the identity playbook, the web/API playbooks, and D3FEND defensive techniques around credential protection/detection.

### 5.2 Attack Libraries

Attack libraries help avoid reinventing attack patterns.

Use:
- MITRE ATT&CK for real-world adversary tactics, techniques, and procedures;
- MITRE CAPEC for software attack patterns;
- OWASP Top 10, API Security Top 10, LLM Top 10 for domain-specific application risks;
- MITRE ATLAS for AI-enabled systems;
- OSC&R for software supply chain attack behaviors;
- cloud/provider threat libraries for AWS/Azure/GCP-specific paths;
- MAESTRO/PLOT4AI for AI/privacy overlays;
- Security Cards and PnG for brainstorming.

Example:
- For a CI/CD threat model, the team uses OSC&R for dependency confusion and malicious build script, ATT&CK for credential access/lateral movement, CAPEC for command injection, and OWASP Top 10 for insecure design.

### 5.3 Vulnerability Catalogs

Vulnerability catalogs connect the threat model to real weaknesses and exploited vulnerabilities.

Use:
- CVE/MITRE for public vulnerability identifiers;
- NVD/NIST for enrichment, CVSS, and SCAP data;
- CWE/MITRE for weakness classes and root cause mapping;
- CISA KEV for vulnerabilities exploited in the wild;
- OSV for open source dependency vulnerabilities;
- GitHub Advisory Database, Go Vulnerability Database, RustSec, Snyk DB as ecosystem-specific sources;
- cloud vulnerability databases for cloud provider/service issues.

Example:
- Attack path "RCE in exposed file converter" receives CWE mapping (deserialization or command injection), CVE if known, CVSS v4.0 technical severity, EPSS likelihood, KEV status, and asset criticality. The risk decision is not based on CVSS alone.

### 5.4 Risk Assessment Models

Risk models help prioritize remediation. Do not mix technical severity, exploitation likelihood, and business impact into one opaque score.

Practical set:
- OWASP Risk Rating: simple application-level likelihood x impact matrix;
- NIST SP 800-30: formal risk assessment context;
- CVSS v4.0: technical vulnerability severity, not business risk;
- EPSS: likelihood of CVE exploitation in the wild;
- CISA KEV: known exploitation signal;
- SSVC: decision-oriented vulnerability prioritization;
- FAIR: quantitative financial risk analysis for mature organizations;
- OCTAVE risk criteria: business impact categories;
- DREAD: historically known, but not recommended as the primary scoring model due to subjectivity and weak reproducibility.

Example:
- A CVE with CVSS 9.8 in a non-internet-facing dev tool may have lower release risk than CVSS 7.5 in an internet-facing auth proxy with KEV and high EPSS. The decision must account for exposure, asset criticality, exploit activity, and compensating controls.

### 5.5 CTI

Threat intelligence improves scenario realism. At minimum, consider:
- intent: why the actor would attack the system;
- opportunity: exposed attack surface and vulnerabilities;
- capability: tooling, infrastructure, TTPs, exploit maturity.

Analysis inputs:
- internal incidents, SOC alerts, fraud/support cases;
- CISA, vendor advisories, cloud provider advisories;
- MITRE ATT&CK groups/software/campaign mappings;
- ISAC/industry reports, DBIR-like reports;
- MISP/OpenCTI where a mature CTI process exists.

Example:
- After a series of credential stuffing incidents in the industry, likelihood for account takeover scenarios increases, and controls include bot detection, breached password checks, MFA step-up, and alerts for impossible travel/session anomalies.

---

## 6. Selection Matrix

| Approach | Best context | Do not use as | Example |
|---|---|---|---|
| STRIDE-LM | quick pass over DFD | full risk methodology | endpoint-level review |
| Microsoft TM | baseline SDLC process | deep attack simulation | new web service |
| OWASP TMP | web/API appsec review | enterprise risk program | GraphQL/API review |
| PASTA | high-risk, evidence-driven systems | lightweight checklist | banking/payment flow |
| LINDDUN | privacy/data processing | replacement for security TM | analytics SDK |
| NIST 800-154 | data-centric systems | full system TM | secrets/PII data lifecycle |
| OCTAVE/Allegro | enterprise/asset risk | feature-level review | crown jewels assessment |
| Trike | authorization-heavy systems | fast workshop | SaaS RBAC matrix |
| VAST | scale and automation | deep manual analysis | service onboarding at scale |
| TARA | mission assurance/control selection | low-effort product review | aerospace/defense system |
| IDDIL/ATC | threat-driven architecture | fully automated practice | Kubernetes platform |
| hTMM | brainstorming workshop | evidence-based risk analysis | early product concept |
| QTMM | quantitative comparison | subjective spreadsheet theater | privacy export design |
