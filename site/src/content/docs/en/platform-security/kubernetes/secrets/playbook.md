---
title: "Kubernetes Secrets Security Playbook"
description: "This playbook covers protection of native Kubernetes `Secret` objects and the path that delivers secrets into workload runtime."
sidebar:
  order: 40
---
## 1. Scope and Objective

This playbook covers protection of native Kubernetes `Secret` objects and the path that delivers secrets into workload runtime.

**In scope:**
- `Secret` objects and their use through volumes and environment variables;
- Secret data stored in etcd and on worker nodes;
- RBAC, ServiceAccount, and indirect Secret access through Pod creation;
- registry credentials stored as `imagePullSecrets` and attached through Pod specs or ServiceAccounts;
- choosing between native Kubernetes Secrets and an external secret manager;
- verification for production review, CI/CD policy, and incident response.

**Out of scope:**
- full Kubernetes cluster hardening;
- general Pod Security baseline;
- detailed operation of Vault, KMS, or cloud secret managers;
- application-level credential lifecycle management outside Kubernetes.

**Objective:**
- prevent accidental exposure through Git, manifests, logs, debug tooling, and broad roles;
- limit blast radius after workload or namespace identity compromise;
- make Kubernetes Secret requirements verifiable through RBAC, admission, audit, and runtime evidence.

---

## 2. Threat Model

**Assets:**
- application credentials, API keys, database passwords, signing material, and private keys;
- ServiceAccount tokens and credentials obtained through external secret integration;
- container registry credentials used by `imagePullSecrets`;
- etcd snapshots, control-plane storage, worker node filesystem, and runtime memory;
- audit trail for Secret reads/changes and deployment intent.

**Typical attackers:**
- compromised application inside a Pod;
- user or CI identity with excessive RBAC in a namespace;
- operator with access to node filesystem or etcd backups;
- supply-chain or debug process that collects env, manifests, logs, or artifacts.

**High-impact scenarios:**
- a subject has `list` or `watch` on `secrets` and obtains the contents of all Secrets in a namespace, even though direct read of one object was not intended;
- a subject can create a Pod in a namespace and mounts any available Secret into that new Pod, bypassing the absence of direct `get secrets`;
- a Secret is stored as base64 in Git, Helm values, rendered manifests, or CI artifacts and is effectively plaintext to every reader of that path;
- a privileged Pod or arbitrary `hostPath` gains access to Secret volumes of other Pods on the same node;
- a broad `imagePullSecret` is attached to a shared ServiceAccount and lets unrelated workloads pull private images or enumerate registry content outside their release boundary;
- a Secret is delivered through environment variables and leaks through debug dumps, error reports, process inspection, or observability pipelines.

---

## 3. Production Baseline

### 3.1 Use Kubernetes Secret instead of ConfigMap

Secret values must be stored in `Secret`, not in `ConfigMap`, annotations, labels, command arguments, or arbitrary custom resources.

`Secret.data` uses base64 encoding only as a serialization format. It is not encryption and does not add protection. Any Secret manifest containing a real value is a sensitive artifact.

**Production defaults:**
- forbid plaintext/base64 Secret manifests in Git, Helm values, and CI artifacts;
- allow encrypted-at-source approaches (`sops`, sealed/encrypted manifests, provider-specific encryption) only with controlled keys, review, and no local decryption outside the trusted CI/CD path;
- do not use `ConfigMap` for passwords, tokens, certificates, private keys, OAuth client secrets, webhook secrets, or database credentials;
- if an existing `ConfigMap` contains a sensitive value, treat the value as compromised and rotate it after migration.

### 3.2 Pod delivery: files first, env only by exception

For production workloads, the preferred way to deliver a Secret to an application is a read-only file through a volume or external secret integration, not an environment variable.

Environment variables are acceptable only when the application does not support a file source and the service owner accepts the risk. Env is commonly captured by crash reports, debug output, process metadata, support bundles, and APM/logging pipelines.

**Production defaults:**
- mount the Secret only into containers that actually need it;
- set `readOnly: true` for Secret volume mounts;
- do not use `subPath` for a Secret if the application expects automatic value updates;
- do not pass Secrets in container args, command-line flags, or startup scripts that may be logged;
- for high-value secrets, forbid env delivery without owner, expiry, compensating controls, and migration plan.

### 3.3 RBAC and namespace boundary

Permissions on `secrets` are not ordinary read permissions. `get`, `list`, and `watch` expose Secret contents, not only metadata.

Pod creation in a namespace is also a sensitive permission: a subject that can create a Pod can often mount a Secret from that namespace and read it through the created workload. For that reason, `create pods`, `create deployments`, `update deployments`, `pods/exec`, and `pods/ephemeralcontainers` must be reviewed alongside direct Secret permissions.

**Production defaults:**
- do not grant `get/list/watch secrets` to human users and CI identities by default;
- use one ServiceAccount per workload, with no reuse across unrelated services;
- forbid the default ServiceAccount for application workloads;
- set `automountServiceAccountToken: false` by default for workloads that do not need Kubernetes API access;
- treat `kubernetes.io/service-account-token` Secret objects as legacy long-lived credentials; do not create them for application workloads by default;
- prefer TokenRequest API or projected ServiceAccount tokens with explicit `audience` and short expiration for workloads that need Kubernetes API or external auth integration;
- any manually created long-lived ServiceAccount token Secret requires an owner, expiry or review date, break-glass/migration justification, access review, and a tested rotation/revocation path;
- require separate approval for `pods/exec`, `pods/ephemeralcontainers`, `serviceaccounts/token`, `escalate`, `bind`, `impersonate`, and `get/list/watch secrets`;
- perform quarterly recertification for live-environment ServiceAccount permissions;
- a namespace holding high-value Secrets must not be a shared namespace for arbitrary workloads.

### 3.4 Storage in etcd and on worker nodes

Kubernetes stores Secrets as API objects in etcd. For production, enable encryption at rest for Secret data and verify that new and existing objects are actually encrypted after configuration changes.

Encryption at rest reduces the risk of reading etcd storage, disks, and backups, but it does not protect against a subject that can read Secrets through the Kubernetes API and does not solve node-level compromise after a Secret is delivered to a Pod.

**Production defaults:**
- enable at-rest encryption for `secrets` in every production cluster;
- use a KMS provider or managed control-plane encryption where it is supported and operationally reliable;
- restrict access to etcd endpoints, snapshots, backup storage, and control-plane node filesystem;
- regularly test restore/rotation for encryption configuration and KMS keys;
- set `immutable: true` for static Secrets that should change only through versioned rollout; do not use it for Secrets that are rotated in place or updated by a controller;
- forbid arbitrary `hostPath`, privileged workloads, and debug containers in namespaces running workloads with high-value Secrets.

### 3.5 Secret in transit and control-plane access

Secret transfer between API server, etcd, kubelet, and node must use protected channels with correct component authentication. In managed Kubernetes, some control-plane guarantees belong to the provider, but the team still owns RBAC, audit, and workload delivery model.

**Production defaults:**
- kubelet, API server, and etcd endpoints are not directly reachable from application namespaces;
- kubelet client credentials, API server etcd credentials, and control-plane certificates are protected as high-value secrets;
- node access is treated as potential access to workload Secrets on that node;
- multi-tenant workloads with different trust boundaries are separated with node pools, taints/tolerations, runtime policy, and NetworkPolicy.

### 3.6 External secret managers

An external secret manager is not an automatic replacement for Kubernetes Secret. It is useful when a stronger lifecycle is needed: dynamic credentials, centralized audit, short TTL, revocation, separation of duties, HSM/KMS-backed protection, or one model for Kubernetes and non-Kubernetes consumers.

**Decision model:**
- Native Kubernetes Secret is acceptable for low/medium-value secrets when encryption at rest, strict RBAC, audit, and a safe delivery model are in place.
- Vault Agent Injector or Secrets Store CSI file-only delivery is preferred for high-value runtime secrets because values do not need to be synchronized into Kubernetes Secret objects.
- External Secrets Operator is appropriate when the application or platform requires a Kubernetes Secret object; this increases exposure and requires etcd encryption, RBAC review, and audit.
- Dynamic credentials are preferred over long-lived static secrets when the downstream system supports TTL, lease, and revoke.

### 3.7 Registry credentials and imagePullSecrets

Registry pull credentials are Secrets with direct supply-chain impact. A subject that can read or reuse a broad `imagePullSecret` may pull private images, inspect layers for embedded secrets, or run unapproved images from a registry path outside the intended release boundary.

**Production defaults:**
- prefer node or workload credential providers that issue scoped, short-lived registry credentials where the platform supports them;
- scope `kubernetes.io/dockerconfigjson` credentials to the minimum registry, repository, and pull-only permission set; do not reuse organization-wide or push-capable tokens as `imagePullSecrets`;
- attach `imagePullSecrets` only to the ServiceAccounts and Pods that need them; do not put high-value registry credentials on the namespace `default` ServiceAccount;
- treat any broad `imagePullSecret` as high-value: owner, expiry or review date, rotation path, and evidence that it is not readable by human/CI identities outside the release path;
- admission policy should reject workloads that reference unapproved `imagePullSecrets`, use default ServiceAccount registry credentials in protected namespaces, or pull from registries outside the approved source list.

---

## 4. Verification

### 4.1 Inventory and policy checks

```bash
kubectl get secrets -A
kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" type="}{.type}{" immutable="}{.immutable}{"\n"}{end}'
kubectl get secrets -A -o jsonpath='{range .items[?(@.type=="kubernetes.io/service-account-token")]}{.metadata.namespace}/{.metadata.name}{" sa="}{.metadata.annotations.kubernetes\.io/service-account\.name}{"\n"}{end}'
kubectl get secrets -A -o jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" sa="}{.spec.serviceAccountName}{" automount="}{.spec.automountServiceAccountToken}{"\n"}{end}'
kubectl get serviceaccounts -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" imagePullSecrets="}{.imagePullSecrets[*].name}{"\n"}{end}'
kubectl get roles,clusterroles -A -o yaml | grep -n 'resources:.*secrets'
kubectl get rolebindings,clusterrolebindings -A
```

Check deployment rights as well as direct Secret grants:

```bash
kubectl auth can-i list secrets --as=<subject> -n <ns>
kubectl auth can-i watch secrets --as=<subject> -n <ns>
kubectl auth can-i create pods --as=<subject> -n <ns>
kubectl auth can-i create pods/exec --as=<subject> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=<subject> -n <ns>
```

### 4.2 Negative tests

Policy/admission must reject:
- `ConfigMap` with keys or values resembling passwords, tokens, private keys, or certificates;
- Pod that mounts a Secret without an explicit allowlist/owner for the workload;
- Pod that passes a Secret through env for high-value classes without an approved exception;
- workload with `serviceAccountName: default`;
- workload without `automountServiceAccountToken: false` when Kubernetes API access is not required;
- workload in a protected namespace that references an unapproved `imagePullSecret` or inherits broad registry credentials from the ServiceAccount;
- manually created `kubernetes.io/service-account-token` Secret without an approved legacy or break-glass exception;
- arbitrary `hostPath`, `privileged: true`, `pods/exec`, and ephemeral debug in protected namespaces.

### 4.3 Audit and detection

Minimum centralized audit events:
- `get/list/watch` on `secrets`;
- create/update/delete on `secrets`, especially `kubernetes.io/service-account-token` objects;
- creation/update of workloads that reference a Secret;
- changes to `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`;
- `pods/exec`, `pods/ephemeralcontainers`, `serviceaccounts/token`;
- encryption configuration changes, KMS provider health, and control-plane backup jobs.

Operational signals:
- spike in Secret reads after a release or RBAC change;
- human identity reads a Secret in a production namespace without a break-glass ticket;
- CI identity receives `list/watch secrets`;
- new workload mounts a Secret that does not belong to its service owner;
- new or changed `imagePullSecret` is attached to the default ServiceAccount, shared across unrelated workloads, or grants broader registry access than the workload owner needs;
- Secret values are detected in logs, traces, metric labels, crash dumps, or support bundles.

---

## 5. Review Decision

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | Condition | Required action |
|---|---|---|
| Critical | Secret value published in Git/public artifact or production identity can mass-read Secrets without need | Immediate rotation, exposure removal, audit timeline, release block until remediation |
| High | `list/watch secrets`, broad Pod creation, or `pods/exec` is available to human/CI identity in production without justification | Owner, due date, RBAC fix, recertification, and audit verification |
| High | A subject can create Pod/Deployment in a namespace with high-value Secrets without admission restrictions on Secret mount/env, ServiceAccount, and workload owner | Block release for that namespace until policy is enforced; verify indirect Secret read through a created Pod is impossible |
| Critical | Pod creation rights in a namespace with high-value Secrets allow mass extraction of production credentials, tenant secrets, signing material, or private keys | Block release, revoke/rotate affected Secrets, restrict deploy rights, and reconstruct audit timeline |
| High | Production Secret is stored in a ConfigMap, unencrypted manifest, or CI artifact | Migrate to Secret/external store, rotate value, prevent recurrence through policy |
| High | Manually created long-lived ServiceAccount token Secret exists in production without an approved exception | Revoke the token, migrate to TokenRequest/projected token flow, and audit all consumers |
| High | Broad or push-capable registry credential is used as `imagePullSecret` for unrelated workloads or the default ServiceAccount | Replace with scoped pull-only credentials or credential provider integration, rotate the registry token, and audit image pulls |
| Medium | Secret is delivered through env for a high-value workload without documented exception | Migration plan to file/external delivery or accepted risk with expiry |
| Medium | Etcd encryption at rest is not confirmed or does not cover existing Secret objects | Enable/reencrypt, attach evidence, record residual risk |
| Low | Missing owner labels/annotations, rotation metadata, or inventory for low-value Secret | Fix during planned work and add a drift check |

---

## 6. Related Materials

- [Kubernetes cluster security review](/Product-security-playbook/en/platform-security/kubernetes/cluster-security-review/playbook/)
- [Kubernetes pod security hardening](/Product-security-playbook/en/platform-security/kubernetes/pod-security/playbook/)
- [Kubernetes adversarial validation](/Product-security-playbook/en/platform-security/kubernetes/adversarial-validation/playbook/)
- [Vault security playbook](/Product-security-playbook/en/platform-security/secrets/vault/playbook/)
