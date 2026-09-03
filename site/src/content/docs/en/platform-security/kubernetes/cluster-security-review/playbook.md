---
title: "Kubernetes Cluster Security Review Playbook"
description: "This playbook defines a **practical Kubernetes cluster security review** across:"
sidebar:
  order: 10
---
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
- subjects with `nodes/proxy` access (broad node-level Kubelet API access);
- subjects with access to fine-grained Kubelet API subresources: `nodes/metrics`, `nodes/stats`, `nodes/log`, `nodes/spec`, `nodes/checkpoint`, `nodes/configz`, `nodes/healthz`, `nodes/pods`;
- machine identities that actually deploy to live environments (CD controllers, CI bots).

**Risk signals:**
- users or groups holding `cluster-admin` without break-glass ownership;
- wildcard privileges (`resources: ["*"]`, `verbs: ["*"]`) in protected namespaces;
- direct live deployment from human identities, bypassing CD;
- `nodes/proxy`, `escalate`, `bind`, or `impersonate` granted without explicit security approval;
- monitoring/logging agents granted `nodes/proxy` even though fine-grained Kubelet API subresources are sufficient for their function.

**Recommended control:**
- live deployments are performed only by dedicated CI/CD ServiceAccounts;
- human users do not deploy directly except break-glass roles with owner + expiry;
- review all ClusterRole/ClusterRoleBinding objects every `30d`;
- enforce automatic policy fail for high-risk RBAC verbs outside an approved allowlist (`escalate`, `bind`, `impersonate`, `serviceaccounts/token`, `nodes/proxy`);
- for Kubernetes `v1.36+`: `KubeletFineGrainedAuthz` is GA and the feature gate is locked/enabled, so observability workloads should use minimal subresources (`nodes/metrics`, `nodes/stats`, `nodes/pods`, and other required endpoints) instead of broad `nodes/proxy`;
- deny new RBAC bindings to `nodes/proxy` for observability workloads when their kubelet scraping/logging use case is covered by fine-grained permissions.
- primary evidence for reducing `nodes/proxy`: `kubectl auth can-i get nodes/metrics|nodes/stats|nodes/pods --as=<subject>` and equivalent checks for the actual kubelet endpoints required;
- secondary evidence: Kubernetes version, managed-provider documentation, kubelet authorization configuration, and vendor release notes for the exact cluster minor version;
- if fine-grained subresources are unavailable or blocked by the cluster distribution, `nodes/proxy` is allowed only as an exception with owner, expiry, minimal subject scope, and a separate blast-radius review.

**Minimum evidence commands:**
```bash
kubectl get clusterrolebindings,rolebindings -A
kubectl get clusterroles,roles -A -o yaml
kubectl get validatingadmissionpolicy,validatingadmissionpolicybinding -o yaml
kubectl auth can-i create deployments --as=<subject> -n <ns>
kubectl auth can-i get nodes/proxy --as=<subject>
kubectl auth can-i get nodes/metrics --as=<subject>
kubectl auth can-i get nodes/stats --as=<subject>
kubectl auth can-i get nodes/pods --as=<subject>
kubectl get clusterroles -o yaml | grep -n 'nodes/proxy'
# Secondary evidence is provider- and deployment-specific:
# collect Kubernetes minor version, kubelet authorization configuration, and managed-provider release notes
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
- live deployment from local `kubectl apply`;
- tag-only image references used in live environments, including version-like tags such as `:v1.2.3`;
- one subject can write code, edit pipeline, and release alone;
- no artifact provenance or pre-deploy verification.

**Recommended control:**
- deploy only via CI/CD, with cluster changes audit-able and replay-able;
- release images pinned by `@sha256` digest only;
- branch protection + mandatory review for IaC/manifests and pipeline configuration;
- separate `author`, `approver`, and `releaser` roles.

---

### 3.3 External and internal services

**What to verify:**
- all cluster entry points: `Ingress`, `Gateway`, `LoadBalancer`, `NodePort`;
- which ingress controllers and Gateway API implementations are installed, who owns their `IngressClass`/`GatewayClass`, and which namespaces may attach routes;
- Service objects with `spec.externalIPs` set;
- workload egress dependencies (SaaS, cloud APIs, internal services);
- allowed namespace/service-to-service communication paths;
- existence of an actual live service/data-flow inventory.

**Risk signals:**
- unknown public endpoints;
- new production exposure built on the community `ingress-nginx` controller without controller inventory, ownership, patch tracking, and a migration plan for any announced EOL/retirement;
- use of `Service.spec.externalIPs` in live or multi-tenant clusters;
- no default-deny network model;
- unrestricted egress for critical workloads;
- no ownership for external integrations.

**Recommended control:**
- north-south and east-west flow inventory updated at least every `30d`;
- protected namespaces use default deny + explicit allow rules;
- every public endpoint has owner, data classification, and vulnerability SLA;
- do not treat the Ingress API itself as deprecated: the Ingress resource remains supported, but its feature set is frozen. For new complex L7/L4 edge scenarios and long-term platform development, prefer Gateway API with an explicitly chosen implementation and security review.
- separate the `Ingress` resource from the concrete controller. CVEs and security fixes usually apply to the controller implementation, webhook, data plane, or admission path, not to the `Ingress` API object itself. For the community Kubernetes `ingress-nginx` controller, maintain an explicit lifecycle decision: inventory IngressClass/controller deployments, owned public endpoints, critical annotations, custom snippets, auth/TLS behavior, upstream support status, patch cadence, and replacement target. If EOL/retirement is announced or patch cadence no longer meets production SLA, remaining on it becomes an accepted exposure that needs owner, expiry, compensating controls, and a migration deadline. New production deployments on this controller are allowed only as an exception with owner, expiry, and patch/rollback plan.
- use the Gateway API security baseline below. A namespace must not be able to attach a route to a shared/public Gateway or reference another namespace's backend/TLS secret without explicit permission from the owner of the referenced resource.
- deny new `Service.spec.externalIPs` through admission policy: `DenyServiceExternalIPs`, `ValidatingAdmissionPolicy`, or a tested policy engine. In Kubernetes `v1.36+`, this field is deprecated; historically it has been insecure by default because a user who can create or modify a Service can intercept traffic to a chosen IP when the CVE-2020-8554 conditions are present.
- create a migration plan with owner and deadline for existing `externalIPs`. Preferred targets are managed `type: LoadBalancer`, Ingress/Gateway API for HTTP(S)/L4 entry, or `NodePort` only behind an external load balancer/firewall with explicit IP ownership and network ACLs.
- do not replace `externalIPs` with manual `status.loadBalancer.ingress` patching without a separate permission model: `services/status` must remain a privileged operation, unavailable to ordinary deploy identities.

**Gateway API security baseline:**
- `GatewayClass` is a platform-owned object. Permission to create or change `GatewayClass` and controller parameters must be limited to platform/security owners because it selects the controller implementation and trust boundary.
- A `Gateway` for shared/public edge should live in a platform-owned namespace. Application namespaces may attach `HTTPRoute`/`GRPCRoute`/`TCPRoute` only through explicitly configured `allowedRoutes` on the intended listener.
- `allowedRoutes` should be as narrow as possible: `Same` for a single-tenant Gateway, `Selector` only with managed labels and admission protection against unauthorized label changes, and `All` is not acceptable for shared/public Gateways without separate risk acceptance.
- Cross-namespace references require a `ReferenceGrant` in the namespace that owns the target resource. This applies to backend Services, TLS Secrets, and other referents; missing `ReferenceGrant` must produce an invalid route/reference, not silent fallback.
- TLS termination policy records where TLS terminates, which certificate sources are allowed, who may reference TLS Secrets, which protocols/ciphers/min TLS version the controller implementation enforces, and how rotation is performed.
- Hostname and listener scope must be constrained: a route from an application namespace must not capture a wildcard hostname, another domain, privileged path prefix, or another tenant's listener without Gateway owner approval.
- Route status conditions must be monitored as security signals: `Accepted=False`, `ResolvedRefs=False`, unexpected parentRefs/backendRefs/hostname changes require review before production traffic.
- Policy attachment (authn/authz, WAF, rate limits, header normalization, CORS, request size, timeout, retry) must have an owner and precedence model. Do not rely on controller-specific defaults without explicit evidence.
- During migration from `ingress-nginx`, do not copy annotations mechanically. For every critical annotation (`auth`, `rewrite`, `configuration-snippet`, body size, buffering, proxy headers, TLS, redirects), record the Gateway API equivalent, unsupported behavior, or compensating control.

**Minimum evidence commands:**
```bash
kubectl get services -A -o jsonpath='{range .items[?(@.spec.externalIPs)]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.spec.externalIPs}{"\n"}{end}'
kubectl auth can-i patch services/status --as=<subject> -n <ns>
kubectl get ingressclass,gatewayclass
kubectl get ingress -A
kubectl get gateway,httproute,tcproute,tlsroute,referencegrant -A
kubectl get gateway -A -o yaml
kubectl get httproute,grpcroutes,tcproutes,tlsroutes -A -o yaml
kubectl auth can-i create gatewayclass --as=<subject>
kubectl auth can-i create referencegrant --as=<subject> -n <target-ns>
```

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

**Recommended control:**
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
- live workloads do not use the namespace `default` ServiceAccount.
- projected ServiceAccount tokens used for service-to-service authentication or external trust integrations have an explicit application-specific `audience` and bounded lifetime;
- which workloads can create `tokenreviews` and `subjectaccessreviews`, and whether they actually need both permissions.

**Risk signals:**
- reliance only on mutating webhook without validating policy;
- developer roles can modify `validatingwebhookconfigurations`/`mutatingwebhookconfigurations`;
- application identities can mutate namespace labels and weaken enforcement;
- one ServiceAccount is reused across unrelated workloads.
- a destination service validates a ServiceAccount token without `TokenReview.spec.audiences` or trusts any authenticated ServiceAccount;
- an application workload is bound to `system:auth-delegator` when it needs only TokenReview.

**Recommended control:**
- separate responsibilities: RBAC controls "who can", admission controls "with which parameters";
- use `ValidatingAdmissionPolicy` (Kubernetes `v1.30+`) or webhook-based equivalent for policy enforcement;
- for protected namespaces, admission policy must enforce, not only audit/warn: `ValidatingAdmissionPolicyBinding.validationActions` includes `Deny`, `failurePolicy` remains `Fail`, and parameterized policies use `parameterNotFoundAction: Deny` when a missing parameter should block an unsafe default;
- deny `escalate` / `bind` / `impersonate` / `serviceaccounts/token` by default;
- for control-plane hardening, evaluate `AlwaysPullImages` separately with operational impact considered where applicable. It reduces reuse of locally cached images without repeat pull authorization, but increases dependence on registry availability and can break air-gapped or registry-outage scenarios. It does not replace digest pinning and signature/provenance verification: a fresh pull of a mutable tag can still fetch an unwanted artifact;
- treat `EventRateLimit` as version- and deployment-dependent: it is an alpha admission controller and is disabled by default in upstream Kubernetes; prefer provider-supported API/event throttling or a tested custom policy where alpha admission plugins are not acceptable;
- enforce one ServiceAccount per workload and quarterly permission recertification.
- for a TokenReview-only consumer, create a custom ClusterRole with only `create` on `tokenreviews.authentication.k8s.io`; the built-in `system:auth-delegator` also permits `subjectaccessreviews` and is not the minimum profile for this use case;
- admission policy for an approved service-to-service pattern should require an explicit `audience`, bounded `expirationSeconds`, a read-only mount, and no namespace `default` ServiceAccount; `expirationSeconds` must not be below the Kubernetes minimum of `600` seconds;
- verify fail-closed destination behavior during TokenReview timeout, throttling, and unavailability, and assess the pattern's control-plane load;
- when offline OIDC/JWKS validation replaces TokenReview, document acceptance of delayed revocation: deleting the bound Pod or ServiceAccount does not invalidate the token before `exp`.

---

### 3.6 Secrets flow

**What to verify:**
- where each secret originates, how it reaches runtime, and how it rotates;
- whether plaintext/base64 secrets appear in Git manifests;
- etcd encryption at rest status for Secret data;
- who has `get/list/watch` on Secrets in live environments;
- where registry pull credentials are stored, which ServiceAccounts attach `imagePullSecrets`, and whether the credentials are pull-only and scoped;
- token/secret TTL and revocation process quality.

**Risk signals:**
- plaintext/base64 secrets stored in repository, values files, rendered manifests, or CI artifacts;
- Kubernetes Secret used for high-value runtime secrets without confirmed etcd encryption at rest, strict RBAC, audit, and ownership;
- External Secrets Operator or another sync process creates a Kubernetes Secret without a real compatibility need;
- long-lived ServiceAccount token secrets used as the primary mechanism;
- broad `list/watch` on Secrets for human or CI identities;
- broad or push-capable registry credentials attached as `imagePullSecrets`, especially on shared or default ServiceAccounts;
- no provable rotation and emergency revocation process.

**Recommended control:**
- for high-value runtime secrets, prefer file-only delivery from an external secret store (for example Vault Agent Injector or Secrets Store CSI) so values are not synchronized into Kubernetes Secret objects;
- use native Kubernetes Secret for low/medium-value secrets only when etcd encryption at rest, strict RBAC, audit, and a safe delivery model are in place;
- if the application or platform requires a Kubernetes Secret object through External Secrets Operator or a similar sync mechanism, treat this as higher exposure and apply the same checks as for native Secret;
- enable etcd encryption at rest and verify status after control-plane changes;
- limit Secret ACL to minimum required workload identities;
- use short-lived tokens and regular secret rotation;
- scope registry pull credentials to the minimum repository and pull-only permission set; prefer provider-supported credential providers over long-lived `imagePullSecrets` where available;
- if an encrypted-at-source push model is used for operational reasons (for example `sops`/`helm-secrets`), require controlled keys, review, and no decryption outside trusted CI/CD boundaries;
- periodically verify logging does not expose secret values.

---

### 3.7 Adversarial validation

**What to verify:**
- key attack paths have been tested from a low-trust workload position: service discovery, east-west reachability, ServiceAccount permissions, `NodePort` exposure, `exec`/ephemeral containers;
- evidence exists before and after remediation, not only a list of YAML settings;
- detection/policy test cases are used to verify audit, runtime telemetry, and admission controls.

**Recommended control:**
- run adversarial validation for live-like environments after major RBAC, CNI, admission policy, runtime security tooling, and deployment-chain changes;
- destructive, DoS, and escape checks run only in an isolated environment or namespace with pre-approved scope;
- use the dedicated playbook for scenario-to-control mapping: [kubernetes/adversarial-validation/playbook.en.md](/Product-security-playbook/en/platform-security/kubernetes/adversarial-validation/playbook/).

---

## 4. Minimum Policy Gates for Live Environments

The minimum gatekeeping baseline should include:
- deny direct human deploy into protected namespaces;
- deny tag-only images in live environments and require an immutable digest reference (`@sha256:...`); `tag@sha256` may be allowed for readability, but the digest must be the value used for deployment;
- block high-risk RBAC verbs outside explicit allowlist;
- require protected namespaces to have ingress and egress default-deny NetworkPolicy, or a documented CNI-equivalent policy with tested enforcement;
- block new Service objects with `spec.externalIPs`; existing use is allowed only as a migration exception with `owner`, `expiry`, verified external IP ownership, and a transition plan to `LoadBalancer`, Gateway API/Ingress, or controlled `NodePort`;
- maintain ingress controller and Gateway API implementation inventory; for the community `ingress-nginx` controller, require a migration plan or exception with owner/expiry; for Gateway API, enforce policy gates for `allowedRoutes`, cross-namespace `ReferenceGrant`, TLS secret ownership, and route attachment to shared Gateways;
- require Kubernetes audit logging with policy coverage for RBAC changes, admission/webhook changes, namespace security label changes, Secret reads, `exec`, attach/port-forward, and ephemeral-container updates;
- restrict and periodically recertify `get/list/watch` access to Secrets in live environments;
- require `automountServiceAccountToken: false` by default unless the workload has a documented Kubernetes API access need;
- block namespace `default` ServiceAccount usage for application workloads;
- require protected namespaces to enforce Pod Security Standards `restricted` by default:
  - `pod-security.kubernetes.io/enforce: restricted`
  - `pod-security.kubernetes.io/enforce-version: <pinned Kubernetes minor version>`
  - `pod-security.kubernetes.io/audit: restricted`
  - `pod-security.kubernetes.io/audit-version: <same pinned version>`
  - `pod-security.kubernetes.io/warn: restricted`
  - `pod-security.kubernetes.io/warn-version: <same pinned version>`;
- require effective seccomp hardening evidence, not only namespace labels: enforced `restricted` admission must reject workloads without explicit `RuntimeDefault` or approved `Localhost`; namespaces using `baseline`, custom policy, or temporary exceptions must either require explicit seccomp fields or prove kubelet `--seccomp-default` / `seccompDefault` so unspecified profiles become `RuntimeDefault`;
- do not treat this list as the complete workload `securityContext` baseline; maintain detailed requirements for capabilities, AppArmor/SELinux, sysctls, groups, volumes, and user namespaces in the [Kubernetes Pod Security playbook](/Product-security-playbook/en/platform-security/kubernetes/pod-security/playbook/);
- use `warn`/`audit=restricted` without `enforce=restricted` only during a documented rollout or migration window with owner, expiry, and a blocking date for enforcement;
- monitor Pod Security label drift and block deployment if live-environment labels regress, are removed, or point to an unapproved version;
- verify through admission policy tests that live workloads without an image digest are rejected, including `:latest`, version-like tags, and image names with no explicit tag;
- verify etcd Secret encryption at rest where the team owns or can configure the control plane;
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
- Live deployment via developer local kubeconfig.
- Admission controls without RBAC protection for sensitive reads.
- RBAC least privilege without protection of admission/webhook configs.
- `Service.spec.externalIPs` as the standard way to publish a service externally.
- the community `ingress-nginx` controller as the new production default without migration plan and ownership.
- One shared ServiceAccount for all namespace applications.
- Secrets in Git (including base64 YAML) as normal process.
- No reconstructable incident timeline from audit/logging data.

---

## 7. Related Repository Materials

- Pod runtime hardening: [kubernetes/pod-security/playbook.en.md](/Product-security-playbook/en/platform-security/kubernetes/pod-security/playbook/)
- Kubernetes adversarial validation: [kubernetes/adversarial-validation/playbook.en.md](/Product-security-playbook/en/platform-security/kubernetes/adversarial-validation/playbook/)
- Seccomp review checklist: [kubernetes/seccomp/checklist.en.md](/Product-security-playbook/en/platform-security/kubernetes/seccomp/checklist/)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.en.md](/Product-security-playbook/en/platform-security/kubernetes/container-escape-capability-abuse/overview/)
- Kubernetes Secrets: [kubernetes/secrets/playbook.en.md](/Product-security-playbook/en/platform-security/kubernetes/secrets/playbook/)
- Vault and secrets: [secrets/vault/playbook.en.md](/Product-security-playbook/en/platform-security/secrets/vault/playbook/)
- OIDC/OAuth for machine/human access patterns: [identity/oidc-oauth/playbook.en.md](/Product-security-playbook/en/application-security/identity/oidc-oauth/playbook/)
