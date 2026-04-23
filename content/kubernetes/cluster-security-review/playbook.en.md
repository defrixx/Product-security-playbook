# Kubernetes Cluster Security Review Playbook

## 1. Scope and Objective

This playbook defines a **practical Kubernetes cluster security review** across:
- deployment subjects (human and machine identities);
- deployment and supply chain path;
- external and internal service boundaries;
- observability required for Incident Response;
- Admission / RBAC / ServiceAccount boundaries;
- secrets flow from source to runtime.

**Objective:**
- reduce unauthorized deployment and hidden privilege-escalation risk;
- reduce blast radius after workload or CI/CD compromise;
- ensure incident investigations are reproducible from cluster evidence.

---

## 2. Threat Model (Cluster Security Review)

**What is protected:**
- deployment rights and cluster-configuration change rights;
- `source -> build -> registry -> deploy` chain integrity;
- Kubernetes API access and admission/namespace policy integrity;
- ServiceAccount tokens, application secrets, and external secret-store access;
- audit trail quality for investigations.

**Typical attacker path:**
- compromise developer or CI identity;
- perform unauthorized deployment or policy mutation;
- establish persistence through RBAC/admission drift;
- extract secrets and move laterally.

---

## 3. Review Domains and Checks

### 3.1 Who can deploy

**What to verify:**
- subjects with `create/update/patch/delete` on workload resources (`deployments`, `statefulsets`, `daemonsets`, `jobs`, `cronjobs`, `pods`);
- subjects with rights over `pods/exec`, `pods/ephemeralcontainers`, `pods/attach`, `pods/portforward`;
- subjects who can change `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`;
- subjects with `nodes/proxy` access (Kubelet API exposure);
- machine identities that actually deploy to production (CD controllers, CI bots).

**Risk signals:**
- users or groups holding `cluster-admin` without break-glass ownership;
- wildcard privileges (`resources: ["*"]`, `verbs: ["*"]`) in production namespaces;
- direct production deploy from human identities, bypassing CD;
- `nodes/proxy`, `escalate`, `bind`, or `impersonate` granted without explicit security approval.

**Production recommendation:**
- production deploys are performed only by dedicated CI/CD ServiceAccounts;
- human users do not deploy directly except break-glass roles with owner + expiry;
- review all ClusterRole/ClusterRoleBinding objects every `30d`;
- enforce automatic policy fail for high-risk RBAC verbs outside an approved allowlist (`escalate`, `bind`, `impersonate`, `serviceaccounts/token`, `nodes/proxy`).

**Minimum evidence commands:**
```bash
kubectl get clusterrolebindings,rolebindings -A
kubectl get clusterroles,roles -A -o yaml
kubectl auth can-i create deployments --as=<subject> -n <ns>
kubectl auth can-i get nodes/proxy --as=<subject>
```

---

### 3.2 Deployment chain

**What to verify:**
- deployment intent source (PR merge, release tag, manual apply);
- where builds run and which identity signs artifacts;
- image selection strategy in manifests (`digest` vs mutable tag);
- who can modify pipeline definitions, CD projects, and environments;
- separation of duties between code authors and release approvers/executors.

**Risk signals:**
- production deploy from local `kubectl apply`;
- mutable tags (`:latest`) used in production;
- one subject can write code, edit pipeline, and release alone;
- no artifact provenance or pre-deploy verification.

**Production recommendation:**
- deploy only via CI/CD, with cluster changes audit-able and replay-able;
- production images pinned by `@sha256` digest only;
- branch protection + mandatory review for IaC/manifests and pipeline configuration;
- separate `author`, `approver`, and `releaser` roles.

---

### 3.3 External and internal services

**What to verify:**
- all cluster entry points: `Ingress`, `Gateway`, `LoadBalancer`, `NodePort`;
- workload egress dependencies (SaaS, cloud APIs, internal services);
- allowed namespace/service-to-service communication paths;
- existence of an actual production service/data-flow inventory.

**Risk signals:**
- unknown public endpoints;
- no default-deny network model;
- unrestricted egress for critical workloads;
- no ownership for external integrations.

**Production recommendation:**
- north-south and east-west flow inventory updated at least every `30d`;
- production namespaces use default deny + explicit allow rules;
- every public endpoint has owner, data classification, and vulnerability SLA.

---

### 3.4 Observability for Incident Response

**What to verify:**
- Kubernetes Audit Logging is enabled on `kube-apiserver`;
- centralized collection exists for audit logs, control-plane logs, and runtime events;
- event coverage includes RBAC/admission/namespace-label changes/deployments;
- CI/CD release events can be correlated with actual Kubernetes API activity.

**Risk signals:**
- audit logging is partial or only local on control-plane nodes;
- no critical operation events (`rolebindings`, `clusterrolebindings`, `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, `namespaces`);
- retention shorter than typical incident lifecycle.

**Production recommendation:**
- centralized immutable audit storage with at least `90d` retention (or stricter regulatory requirement);
- for high-risk API operations, log at `Request`/`RequestResponse` where appropriate while preventing sensitive-data leakage;
- alerting on RBAC changes, webhook config changes, namespace security label changes, and mass Secret reads;
- complement API audit with runtime/network behavioral telemetry (for example, CNI observability and eBPF tooling) to detect not only deploy events but anomalous runtime behavior;
- timeline reconstruction drill at least every `90d`.

---

### 3.5 Admission / RBAC / ServiceAccount boundaries

**What to verify:**
- critical security rules are enforced through admission (not documentation-only policy);
- RBAC controls sensitive read operations (admission does not block `get/list/watch`);
- namespace label mutation is restricted (to protect PSA/NetworkPolicy boundaries);
- `automountServiceAccountToken` is disabled by default for workloads without API needs;
- production workloads do not use the namespace `default` ServiceAccount.

**Risk signals:**
- reliance only on mutating webhook without validating policy;
- developer roles can modify `validatingwebhookconfigurations`/`mutatingwebhookconfigurations`;
- application identities can mutate namespace labels and weaken enforcement;
- one ServiceAccount is reused across unrelated workloads.

**Production recommendation:**
- separate responsibilities: RBAC controls "who can", admission controls "with which parameters";
- use `ValidatingAdmissionPolicy` (Kubernetes `v1.30+`) or webhook-based equivalent for policy enforcement;
- deny `escalate` / `bind` / `impersonate` / `serviceaccounts/token` by default;
- for control-plane hardening, evaluate `EventRateLimit` and `AlwaysPullImages` separately (with operational impact considered) where applicable;
- enforce one ServiceAccount per workload and quarterly permission recertification.

---

### 3.6 Secrets flow

**What to verify:**
- where each secret originates, how it reaches runtime, and how it rotates;
- whether plaintext/base64 secrets appear in Git manifests;
- etcd encryption at rest status for Secret data;
- who has `get/list/watch` on Secrets in production;
- token/secret TTL and revocation process quality.

**Risk signals:**
- secrets stored in repository or values files without external secret manager;
- long-lived ServiceAccount token secrets used as the primary mechanism;
- broad `list/watch` on Secrets for human or CI identities;
- no provable rotation and emergency revocation process.

**Production recommendation:**
- use pull model from external secret store (for example Vault) instead of storing values in manifests;
- enable etcd encryption at rest and verify status after control-plane changes;
- limit Secret ACL to minimum required workload identities;
- use short-lived tokens and regular secret rotation;
- if push model is used for operational reasons (for example `sops`/`helm-secrets`), require encrypted Git storage, controlled key management, and forbid decryption outside trusted CI/CD boundaries;
- periodically verify logging does not expose secret values.

---

## 4. Minimum Production Policy Gates

The minimum gatekeeping baseline should include:
- deny direct human deploy into production namespaces;
- deny mutable image tags in production (`:latest` and equivalents);
- block high-risk RBAC verbs outside explicit allowlist;
- block namespace `default` ServiceAccount usage for application workloads;
- require namespace-level pod security labels and monitor drift;
- allow exceptions only via explicit object containing `owner`, `justification`, and `expiry`.

---

## 5. Required Review Outputs

A review is complete only when it provides:
- full deploy-subject inventory with effective permissions;
- deployment-chain map with trust boundaries and control points;
- external/internal service interaction inventory;
- observability coverage map for IR (what is logged and where retained);
- Admission/RBAC/ServiceAccount responsibility matrix;
- secrets-flow map including TTL/rotation/revocation and owners.

---

## 6. Anti-patterns

- One shared `cluster-admin` account for the whole team.
- Production deploy via developer local kubeconfig.
- Admission controls without RBAC protection for sensitive reads.
- RBAC least privilege without protection of admission/webhook configs.
- One shared ServiceAccount for all namespace applications.
- Secrets in Git (including base64 YAML) as normal process.
- No reconstructable incident timeline from audit/logging data.

---

## 7. Related Repository Materials

- Pod runtime hardening: [kubernetes/pod-security/playbook.en.md](../pod-security/playbook.en.md)
- Seccomp review checklist: [kubernetes/seccomp/checklist.en.md](../seccomp/checklist.en.md)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.en.md](../container-escape-capability-abuse/overview.en.md)
- Vault and secrets: [secrets/vault/playbook.en.md](../../secrets/vault/playbook.en.md)
- OIDC/OAuth for machine/human access patterns: [identity/oidc-oauth/playbook.en.md](../../identity/oidc-oauth/playbook.en.md)
