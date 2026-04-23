# Security Lens for 16 Architecture Case Studies (ByteByteGo)

## 1. Scope and how to read this document

This playbook analyzes 16 ByteByteGo case studies through a practical security lens:
- which assets must be protected;
- which common threats and risks appear;
- which technical and process controls are typically used in production;
- which signals prove that controls are actually working.

Boundary:
- this is not a claim about each company’s complete internal implementation;
- this is a security decomposition of the architecture pattern implied by each case title.

Evidence model:
- `Confirmed`: supported by a public primary company source or official documentation;
- `Inferred`: practical control derived from threat modeling and industry practice.

Important for section 3:
- the `Confirmed` column contains only controls with direct links;
- if public evidence is limited for a case, this is explicitly reflected as `partially confirmed`.

---

## 2. Unified security lens for architecture case studies

For each case, review at least these 7 domains:

1. Identity and trust boundaries
- machine identity, user identity, and inter-service privileges;
- no implicit trust inside internal networks.

2. Data protection
- data classification, encryption in transit/at rest, secrets, keys, tokens;
- no sensitive data in logs or telemetry.

3. Abuse and business-logic attacks
- BOLA/BFLA/BOPLA, brute force, scraping, fraud, bot automation;
- rate limits, risk scoring, and step-up controls.

4. Platform/runtime hardening
- sandboxing, workload isolation, policy-as-code, least privilege;
- secure defaults for containers and execution environments.

5. Software supply chain
- provenance/attestations, artifact signing, dependency pinning;
- secured CI/CD and controlled release privileges.

6. Detection and response
- authn/authz events, data-access events, admin actions, policy denies;
- incident playbook with a testable path from alert to containment.

7. Verifiability
- every control must have either a test or a measurable indicator;
- controls without observability and negative tests are incomplete.

---

## 3. Consolidated table for 16 cases

| Case | Threats and risks | Controls definitely implemented by the company (`Confirmed`) | Controls with no public information but strongly suggested (`Inferred`) | Security evidence signals |
|---|---|---|---|---|
| Discord — How Discord Stores Messages | Horizontal access to other users’ messages; call/stream content leakage; voice-session hijacking | E2EE for audio/video and Go Live, plus call encryption/participant verification flows ([Discord E2EE](https://support.discord.com/hc/en-us/articles/25968222946071/)) | Object-level authz checks `tenant->channel->message`; short-lived webhook/bot creds; strict message log redaction | BOLA negative tests; anomalous read/export alerts; aged webhook token ratio |
| Netflix — How Netflix Streams Content | Playback token theft; credential abuse; TLS/certificate compromise | Centralized TLS certificate orchestration via Lemur ([Netflix Lemur](https://github.com/Netflix/lemur)); public responsible disclosure channel ([Netflix RVD](https://help.netflix.com/en/node/6657)) | Device-bound playback tokens; anti-replay nonces; adaptive login/playback limits | Replay/invalid-token rate at edge; account-takeover MTTD/MTTR; cert rotation SLA |
| Airbnb — How Airbnb Architecture Evolved | Insecure migration changes in distributed systems; phishing/account takeover; product vulnerabilities | Public security disclosure channel through HackerOne ([Airbnb Security](https://www.airbnb.com/info/security)); official account/phishing security guidance ([Help secure account](https://www.airbnb.com/help/article/501)) | Centralized policy decision point; mTLS/workload identity across services; PII-labeled data contracts | Centralized authz coverage; overdue policy exceptions; tenant-isolation e2e tests |
| Cursor — How Cursor Ships Code | Prompt injection through context; code/secret exfiltration; unsafe autonomous actions | SOC 2 Type II, annual pentests; Privacy Mode with zero-retention for providers in that mode; AES-256 at rest and TLS 1.2+ ([Cursor Security](https://cursor.com/en-US/security), [Cursor Data Use](https://cursor.com/en-US/data-use), [Cursor Enterprise](https://cursor.com/en-US/enterprise)) | Retrieval allowlist/secret denylist; mandatory security gates for AI-generated PRs; strict tool least privilege | Prompt-injection test pass rate; blocked secret exfil attempts; AI PR security-gate coverage |
| Tinder — How Tinder Matches Users | Fake/bot profiles; impersonation/catfishing; business-flow abuse | Photo Verification with liveness checks; ID + Photo Verification where available ([Photo Verification](https://www.help.tinder.com/hc/en-us/articles/360034941812-Photo-Verification), [ID + Photo Verification](https://www.help.tinder.com/hc/en-us/articles/19868368795917-ID-Photo-Verification), [How it works](https://www.help.tinder.com/hc/en-us/articles/4422771431309-How-Does-Photo-Verification-Work)) | Velocity/risk scoring for match/message flows; adaptive challenges; field-level profile protection | Fake-account precision/recall; bot containment time; abuse-to-ban latency |
| OpenAI — How OpenAI Codex Works | Unsafe command/code execution; agent data leakage; risky autonomy | Codex CLI approval modes and sandboxed network-disabled `Full Auto`; API data controls (no training by default, retention controls) ([Codex CLI](https://help.openai.com/en/articles/11096431-openai-codex-ci-getting-started), [OpenAI data controls](https://platform.openai.com/docs/guides/your-data)) | Tool-runtime egress policies; human approval for high-risk changes; retrieval source provenance checks | Share of high-risk actions with human approval; sandbox escape incidents; policy block rate |
| Reddit — How Reddit Sends Notifications | Account takeover; spoofed notifications; retry storm abuse | 2FA with authenticator app and backup codes ([Reddit 2FA](https://support.reddithelp.com/hc/en-us/articles/360043470031-What-is-two-factor-authentication-and-how-do-I-set-it-up), [backup codes](https://support.reddithelp.com/hc/en-us/articles/360058446411-What-are-two-factor-authentication-backup-codes-and-how-do-I-get-them-)) | Signed trusted notification events; idempotency + deduplication; bounded retries with jitter | Duplicate notification ratio; spoofing rejects; retry-storm MTTR |
| X — How X Ranks Posts | Ranking manipulation via coordinated behavior; API abuse; signal poisoning | Public API rate-limit/429 documentation ([X API rate limits](https://docs.x.com/x-api/fundamentals/rate-limits)); open recommendation-system repository ([the-algorithm](https://github.com/twitter/the-algorithm)) | Feature provenance checks; strict role separation for model/feature access; coordinated bot behavior controls | Time to suppress coordinated campaigns; unauthorized model/policy change count; anti-abuse false positives |
| Dropbox — How Dropbox AI Searches | Cross-tenant retrieval; sensitive data leakage in AI search/chat; connected-app integration risks | Dash answers/search over content users already have access to; platform encryption controls (AES-256 at rest, SSL/TLS in transit) ([Dash search](https://help.dropbox.com/view-edit/dropbox-dash-search-and-explore), [Dropbox security](https://help.dropbox.com/security/how-security-works)) | ACL enforcement on retrieval path; DLP label-aware indexing; connector sandbox + egress allowlist | Tenant-escape test results; DLP coverage on indexed corpus; connector policy violations |
| Uber — How Uber Controls Access | Privilege escalation; high-blast-radius superuser commands; lateral movement | Central ABAC model via `Charter` ([ABAC at Uber](https://www.uber.com/en-DE/blog/attribute-based-access-control-at-uber/)); SPIFFE/SPIRE zero-trust workload identity rollout ([SPIFFE/SPIRE at Uber](https://www.uber.com/en-SE/blog/our-journey-adopting-spiffe-spire/)); Superuser Gateway with peer review and no direct superuser access ([Superuser Gateway](https://www.uber.com/pe/en/blog/superuser-gateway-guardrails/)) | JIT/JEA over standing privileges; short-lived service credentials; strict domain segmentation | Median privileged-session lifetime; services without static secrets; lateral-movement block count |
| Google — How Google Spanner Scales | Data/control plane compromise; key lifecycle failures; excessive DB privileges | Spanner default encryption at rest + CMEK option; IAM at project/instance/database levels ([Spanner CMEK](https://docs.cloud.google.com/spanner/docs/cmek), [Spanner IAM overview](https://docs.cloud.google.com/spanner/docs/iam)) | Separation-of-duties IAM roles; mandatory DDL/admin audit trails; controlled key lifecycle | Key-rotation coverage; DDL/admin audit completeness; unauthorized data access attempts |
| Stripe — How Stripe Ships Fast | Duplicate effects on retries; payment data compromise; release risk | API idempotency keys for safe POST retries; PCI Service Provider Level 1 status ([Idempotent requests](https://docs.stripe.com/api/idempotent_requests), [Security at Stripe](https://docs.stripe.com/security/stripe)) | Signed artifacts + provenance checks at deploy; CI security gates as blockers; risk-based payment API limits | Unsiged artifact runtime ratio; duplicate-charge incidents; security-root-cause CFR |
| AMEX — How AMEX Processes Payments | Card-not-present fraud; PAN exposure; checkout account takeover | SafeKey built on EMV 3-D Secure; card-on-file tokenization replacing PAN with tokens and domain controls ([SafeKey](https://www.americanexpress.com/en-us/security/safekey/), [Tokenization](https://network.americanexpress.com/globalnetwork/tokenization/)) | Token lifecycle monitoring; adaptive fraud scoring per channel; strict CDE segmentation | Fraud/chargeback trends; tokenized transaction ratio; authentication challenge success rate |
| Anthropic — How Anthropic Built Agents | Unsafe agent command execution; prompt injection; data exfiltration | Claude Code security model: read-only by default + explicit approvals; fine-grained permission system; commercial data not used for training by default ([Claude Code security](https://code.claude.com/docs/en/security), [permissions](https://code.claude.com/docs/en/permissions), [data training policy](https://privacy.anthropic.com/en/articles/7996868-i-want-to-opt-out-of-my-prompts-and-results-being-used-for-training-models)) | Capability sandbox for high-risk tools; deny-by-default dangerous action classes; human-in-the-loop for destructive actions | High-impact actions requiring approval; sandbox policy violation rate; capability revoke time |
| Shopify — The Shopify Tech Stack | Excessive app permissions; webhook spoofing; API abuse/throttling pressure | Access-scopes model with minimum needed data access; HMAC verification guidance for webhook-like calls; documented API limits and 429 behavior ([Access scopes](https://shopify.dev/docs/admin-api/access-scopes), [HMAC verification](https://shopify.dev/docs/apps/build/flow/actions/endpoints), [API limits](https://shopify.dev/docs/api/usage/limits)) | Runtime scope governance; mandatory signature verification on all webhook endpoints; ecosystem anti-abuse controls | Excessive-scope app count; webhook signature failure ratio; rate-limit breach trend |
| Meta — How Meta Animates Images | AI/manipulated media abuse; platform vulnerabilities; content trust risks | Public AI-generated/manipulated-media labeling approach; large-scale bug bounty program with periodic reporting ([AI labeling approach](https://about.fb.com/news/2024/04/metas-approach-to-labeling-ai-generated-content-and-manipulated-media/), [Meta Bug Bounty](https://www.facebook.com/whitehat), [2024 recap](https://engineering.fb.com/2025/02/13/security/looking-back-at-our-bug-bounty-program-in-2024/)) | Media provenance checks in processing pipeline; sandboxed media processing; deepfake-specific abuse detection | Detected-vs-escaped manipulated media ratio; time-to-label/remove; bounty-to-fix cycle time |
