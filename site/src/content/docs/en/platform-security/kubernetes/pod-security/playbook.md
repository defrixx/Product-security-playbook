---
title: "Kubernetes Pod Security Playbook"
description: "Focus strictly on **Pod / Container runtime security**:"
sidebar:
  order: 30
---
## 1. Scope and Objective

Focus strictly on **Pod / Container runtime security**:
- Covers only **workload-level controls**
- Excludes **networking, ingress, and cluster-wide policies**
- Objective: **minimize impact in case of container compromise**

---

## 2. Threat Model (Condensed)

Focus: **what is being protected and from whom**

**Assets:**
- Node (host OS)
- Kubernetes control plane (indirect exposure)
- Secrets / ServiceAccount tokens
- Other pods running on the same node

**Attacker:**
- Compromised application inside a container
- Malicious or vulnerable container image (supply chain)

---

## 3. Attack Vectors (Pod-Level)

### Privilege Escalation

- setuid/setgid binaries
- Dangerous Linux capabilities (e.g., `CAP_SYS_ADMIN`)
- Running containers as root
- Misuse of `privileged` mode

### Container Escape

- Access to host namespaces
- Exposure to `/proc`, `/sys`
- Exploitation of unsafe syscalls
- Host filesystem access through unsafe mounts

### Lateral Movement

- Abuse of ServiceAccount tokens
- Unauthorized access to Kubernetes API
- Access to shared or sensitive volumes
- Reuse of overly permissive default identities

---

## 4. Core Security Controls

Controls are grouped by security domain.

Where relevant, distinguish between:
- **Pod-level controls:** affect the entire Pod
- **Container-level controls:** must be enforced for each container

---

### 4.1 Process Identity and Privileges

**Container-level controls:**
- `runAsNonRoot: true`
- `runAsUser` (fixed, non-zero UID)
- `runAsGroup` (fixed, non-zero GID)
- `allowPrivilegeEscalation: false`
- `privileged: false`

**Pod-level controls:**
- `hostUsers: false`

**User namespaces in Kubernetes `v1.36+`:**
- User Namespaces are GA for Linux workloads; Pod-level enablement is done with `hostUsers: false`.
- In live environments, use `hostUsers: false` as the default workload-isolation recommendation where it is compatible with the container runtime, kernel, and storage stack.
- With a user namespace enabled, UID `0` inside the container is not UID `0` on the host: container root and container UID/GID values are mapped to an unprivileged range on the node.
- This reduces blast radius for container escapes, misconfigured mounts, and vulnerabilities that depend on host UID/GID identity, but it does not replace `runAsNonRoot`, `seccompProfile.type: RuntimeDefault`, `capabilities.drop: ["ALL"]`, or denying `privileged: true`.
- Capabilities become namespaced when `hostUsers: false` is set: for example, `CAP_NET_ADMIN` may grant administrative actions over container-local resources without granting host-level administrative power. Even then, grant capabilities only with explicit justification, owner, and expiry.

**Compatibility and failure modes for `hostUsers: false`:**
- Do not treat `hostUsers: false` as a drop-in YAML flag. Verify it on the same Kubernetes minor version, kernel, runtime, CSI/storage stack, and admission policy used in live environments.
- Minimum runtime evidence: Linux `6.3+` or a vendor-supported kernel with ID-mapped mount support for all filesystems used by the workload, containerd `2.0+` or CRI-O `1.25+`, an OCI runtime with user namespace support such as `runc` `1.2+` or `crun` `1.9+`, and kubelet events/metrics showing successful user-namespace Pod creation.
- Roll out in stages: first stateless workloads without `hostNetwork`, `hostPID`, `hostIPC`, raw block `volumeDevices`, or special storage assumptions; then stateful/storage-heavy workloads only after CSI/storage compatibility testing; then platform workloads through separate design review.
- For images that genuinely need root-like behavior inside the container, use a dedicated exception path: owner, expiry, incompatibility reason for `runAsNonRoot`, evidence that host UID/GID remain unprivileged, and compensating controls (`seccomp`, dropped capabilities, read-only root filesystem, restricted volumes).
- Pods with user namespaces cannot use host namespaces: `hostNetwork: true`, `hostPID: true`, and `hostIPC: true` are incompatible and should fail admission or deployment validation.
- Raw block `volumeDevices` are not compatible with Pods using user namespaces. Stateful or storage-heavy workloads need an explicit storage compatibility test before adopting this control.
- NFS volumes are not compatible with user-namespace Pods until the Linux NFS client supports idmapped mounts; treat NFS-backed workloads as incompatible unless the platform team has verified support on the exact kernel and storage path.
- Pod Security Standards relax `runAsNonRoot` and `runAsUser` checks for Pods with user namespaces because container UID `0` is mapped to an unprivileged host UID. This does not mean "root is safe by default"; keep `runAsNonRoot: true` for normal app workloads unless the workload has a documented reason to run as root inside the user namespace.
- Required verification: admission test for forbidden host namespace combinations, deploy test with the workload's real volumes, node/runtime compatibility evidence, kubelet `started_user_namespaced_pods_total` / `started_user_namespaced_pods_errors_total` monitoring, and a PSS test proving the namespace policy outcome is understood.

**Important `securityContext` semantics (Kubernetes):**
- If the same field is set at both Pod and Container levels, the value in `container.securityContext` overrides `pod.spec.securityContext`.
- `allowPrivilegeEscalation` directly controls the Linux `no_new_privs` flag for the container process.
- `allowPrivilegeEscalation: false` is not effective as expected when the container runs with `privileged: true` or has `CAP_SYS_ADMIN`.

**Purpose:**
- Prevent privilege escalation via setuid/setgid binaries
- Eliminate implicit root privileges
- Prevent near-host-level execution inside the container

---

### 4.2 Linux Capabilities

**Container-level controls:**
- `capabilities.drop: ["ALL"]`
- Add back only explicitly required capabilities

**Critical:**
- Avoid `CAP_SYS_ADMIN`
- Avoid `CAP_NET_ADMIN`
- Avoid granting capabilities without documented justification

**Purpose:**
- Minimize kernel-exposed privileged operations
- Reduce privilege escalation and breakout opportunities

For review, do not stop at YAML. `capabilities.drop/add` controls several Linux capability sets through the CRI/runtime, and the final state depends on the entrypoint, `execve`, file capabilities, and `allowPrivilegeEscalation`. For disputed workloads, verify `CapEff`, `CapPrm`, `CapBnd`, `CapAmb`, and `NoNewPrivs` at runtime; the detailed model is covered in the [container escape and capability abuse overview](/Product-security-playbook/en/platform-security/kubernetes/container-escape-capability-abuse/overview/).

---

### 4.3 Filesystem Hardening

**Container-level controls:**
- `readOnlyRootFilesystem: true`

**Why this matters:**
- `readOnlyRootFilesystem: false` leaves the container root filesystem writable. After process compromise, an attacker can write runtime payloads, modify application files or configuration, place droppers and web shells, and complicate investigation through local changes inside the container.
- Writable paths should be explicit and constrained: move `/tmp`, cache, or log directories to dedicated mounts with a clear purpose, lifecycle, and limits instead of leaving the entire root filesystem writable.

**Additional guidance:**
- Provide explicit writable mounts only where required by the application
- For workloads with `readOnlyRootFilesystem: true`, use dedicated `emptyDir` mounts for required writable paths (for example `/tmp` and application log directories)
- Use `emptyDir` only when necessary
- Avoid storing persistent or sensitive data in writable container paths

---

### 4.4 Volume Controls

**Restrictions:**
- Avoid `hostPath` unless strictly necessary
- Use `readOnly: true` where possible
- Minimize the number of mounted volumes
- Mount only the paths required by the application
- Avoid sharing sensitive volumes across unrelated workloads

**High-risk mounts:**
- `/var/run/docker.sock`
- `/proc`
- `/sys`
- Any host-mounted path
- Runtime sockets or device paths exposed from the host

**Purpose:**
- Prevent direct host interaction
- Reduce node compromise and credential exposure risk

**Adversarial validation checks:**
- verify application workloads do not mount `docker.sock`, `containerd.sock`, CRI sockets, `/proc`, `/sys`, or sensitive host paths;
- deny runtime socket mounts through admission policy; allow exceptions only for trusted platform/build workloads with owner, expiry, and compensating controls;
- after remediation, repeat the same query or policy test to confirm the unsafe mount no longer deploys.

---

### 4.5 Kernel-Level Isolation

**Container-level controls:**
- `seccompProfile.type: RuntimeDefault`
- `appArmorProfile.type: RuntimeDefault` on Linux nodes with AppArmor
- `procMount: Default`
- For custom profiles: allow only justified syscalls, and review high-risk syscalls and bypass combinations separately

**Important seccomp evidence:**
- Current Pod Security Standards `restricted` requires `seccompProfile.type` to be explicitly set to `RuntimeDefault` or `Localhost` at Pod or container level; `baseline` only blocks explicit `Unconfined`.
- Workloads outside enforced `restricted`, legacy namespaces, and exception paths can still run with an unspecified seccomp profile. If kubelet `--seccomp-default` / `seccompDefault` is not enabled on the node, that unspecified profile can run as `Unconfined`.
- Live-environment evidence must show either enforced `restricted` admission with explicit seccomp fields, an equivalent custom admission policy, or node-level seccomp defaulting to `RuntimeDefault`, plus effective runtime verification where possible.

**AppArmor and SELinux:**
- If nodes support AppArmor, explicitly set `appArmorProfile.type: RuntimeDefault` for application workloads. Do not rely only on the implicit default: if AppArmor is disabled on the node, an unspecified profile may provide no runtime restriction.
- Deny `appArmorProfile.type: Unconfined` through admission policy. Allow `Localhost` only for profiles preloaded on all eligible nodes, with an owner, rollout process, and regression test.
- Use `seLinuxOptions` only in SELinux-enabled clusters where labels, storage behavior, and runtime policy are owned by the platform team. Custom SELinux labels without an ownership model often break volume compatibility and make investigations harder.
- When using `SELinuxChangePolicy` or `SELinuxMount` behavior in SELinux-enabled clusters, check Pod events and platform metrics for volume label conflicts before rollout, especially for shared volumes and different SELinux labels.

**Sysctls:**
- By default, deny workloads that set `spec.securityContext.sysctls`, except for an explicitly allowed safe subset from Pod Security Standards for your Kubernetes minor version.
- Allow unsafe sysctls only for special performance or real-time scenarios: dedicated node pool, taints/tolerations, owner, expiry, load test, and rollback plan. Do not run normal application workloads on nodes with expanded `allowed-unsafe-sysctls`.

Detailed seccomp review (dangerous syscalls, `io_uring`/`bpf`, combo checks, CI governance): [kubernetes/seccomp/checklist.en.md](/Product-security-playbook/en/platform-security/kubernetes/seccomp/checklist/)

---

### 4.6 Service Account and API Access

**Pod-level controls:**
- `automountServiceAccountToken: false` by default
- Use a dedicated ServiceAccount only when Kubernetes API access is required
- Apply least-privilege RBAC
- Do not use the namespace `default` ServiceAccount for application workloads

**Risk addressed:**
- Lateral movement via Kubernetes API
- Token abuse after container compromise
- Uncontrolled privilege reuse across workloads

**Mandatory admission/policy gates (prevent namespace-level bypass):**
- Reject pods that do not set `automountServiceAccountToken: false` unless explicitly annotated as API-calling workloads.
- Reject pods that use `serviceAccountName: default`.
- Require an explicitly named ServiceAccount for every workload.
- Enforce these checks via admission policy (Kyverno/Gatekeeper/ValidatingAdmissionPolicy), not documentation-only review.
- Require exception objects with owner/expiry for any policy bypass.

---

### 4.7 Host and Namespace Isolation

**Pod-level controls:**
- `hostNetwork: false`
- `hostPID: false`
- `hostIPC: false`
- `shareProcessNamespace: false`

**Critical `shareProcessNamespace` semantics:**
- If `shareProcessNamespace: true`, processes become visible across containers in the Pod, including data exposed via `/proc`.
- Containers can send signals to processes in sibling containers.
- `/proc/<pid>/root` can expose another container's filesystem.
- For live workloads, deny `shareProcessNamespace: true` by default; allow only explicit break-glass exceptions with owner and expiry.

**Mandatory admission/policy gate:**
- Reject Pods with `shareProcessNamespace: true` via admission policy (Kyverno/Gatekeeper/ValidatingAdmissionPolicy), except explicitly registered exceptions.

**Purpose:**
- Prevent access to host processes
- Prevent access to host network namespace
- Preserve workload isolation boundaries

---

### 4.8 Resource Constraints

**Pod / container runtime controls:**
- Define `resources.requests` for CPU and memory so scheduling decisions reflect real workload needs.
- Define memory limits for live workloads to bound node-level DoS and noisy-neighbor impact.
- Define `ephemeral-storage` requests and limits for workloads that write temporary files, caches, logs, uploads, or generated artifacts.
- Treat CPU limits as workload-specific, not a blanket security default. CPU limits can introduce throttling and latency regressions for services with bursty or latency-sensitive behavior; use them when the DoS/noisy-neighbor risk is higher than the throttling risk, or when required by platform policy.
- For internet-facing, multi-tenant, batch, build, AI/inference, and untrusted-code workloads, document the resource abuse model and choose CPU, memory, and ephemeral-storage guardrails explicitly.
- For critical services, validate limits through load testing rather than copying generic values.

**Namespace-level controls:**
- apply `ResourceQuota` and, where needed, `LimitRange` for shared protected namespaces;
- deny BestEffort pods in protected namespaces unless an exception is explicitly accepted;
- require namespace quotas to cover CPU, memory, pods, and ephemeral storage where supported by the platform;
- run DoS/`stress-ng` checks only in isolated load/staging environments, not live protected namespaces.

---

### 4.9 Debug surfaces

**What to control:**
- `pods/exec`
- `pods/attach`
- `pods/portforward`
- `pods/ephemeralcontainers`
- node-level debug flows

**Recommended control:**
- restrict `exec` and ephemeral containers in sensitive namespaces to dedicated support/SRE roles;
- log and alert on `exec`, attach/port-forward, and ephemeral-container additions;
- use admission policy to deny debug surfaces in high-value namespaces where operationally acceptable.

---

### 4.10 Process Groups and Volume Ownership

**Pod-level controls:**
- `runAsGroup` sets the primary GID for container processes; use a fixed non-zero GID instead of implicit values from the image.
- Use `fsGroup` only when the workload genuinely needs group-based access to a volume. Do not use it as a generic way to "fix permissions" without understanding storage behavior.
- Grant `supplementalGroups` minimally: each additional GID expands process access to files and mounted storage.
- For Kubernetes `v1.33+`, use `supplementalGroupsPolicy: Strict` for sensitive workloads so groups from `/etc/group` inside the image are not implicitly added to the container process.
- For large PVCs and stateful workloads, use `fsGroupChangePolicy: OnRootMismatch` when the storage driver and permission model support it; this reduces startup delays from recursive ownership changes.

**Operational caveats:**
- `fsGroup` and `fsGroupChangePolicy` work only for volume types and CSI drivers that support ownership/permission management. For CSI volumes, the driver may handle permission changes itself; verify the effective owner/group inside the running Pod.
- Do not assign one broad GID to unrelated workloads for convenient shared-storage access. That turns the storage group into an implicit boundary bypassing namespace/RBAC separation.
- If `supplementalGroupsPolicy: Strict` is unavailable on part of the nodes, Kubernetes `v1.33+` should have the kubelet reject that Pod; in the `v1.31-v1.32` alpha behavior, it could silently fall back to `Merge`. Verify feature support on the node pool and runtime evidence through `id` inside the container or `.status.containerStatuses[].user.linux` where the field is available.
- For a multi-container Pod with shared `emptyDir` or PVC, document the ownership contract: which container writes, which reads, which paths are writable, which GID is required, and who owns the exception.

**Checks:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" runAsGroup="}{.spec.securityContext.runAsGroup}{" fsGroup="}{.spec.securityContext.fsGroup}{" supplementalGroups="}{.spec.securityContext.supplementalGroups}{" supplementalGroupsPolicy="}{.spec.securityContext.supplementalGroupsPolicy}{"\n"}{end}'
kubectl exec -n <ns> <pod> -- id
kubectl exec -n <ns> <pod> -- stat -c '%u:%g %a %n' <mounted-path>
```

---

## 5. Pod Security Standards (PSS)

Baseline alignment:
- Target: **Restricted profile**

**Purpose:**
- Reuse the upstream Kubernetes pod hardening baseline
- Avoid ad hoc or inconsistent workload security rules
- Enforce a minimum acceptable Pod security posture

**Important limitation:**

Pod Security Standards help enforce secure Pod specification defaults, but they do **not** replace:
- Image trust and supply chain controls
- RBAC design and identity architecture
- Runtime threat detection
- Network isolation
- Cluster-wide hardening
- Effective seccomp verification outside enforced `restricted`: namespaces using `baseline`, legacy exceptions, or custom policies must still prove explicit `RuntimeDefault`/approved `Localhost` or node-level seccomp defaulting.

### 5.1 Enforcement Baseline

- `pod-security.kubernetes.io/enforce: restricted` on all protected namespaces.
- Pin the policy version for all modes to the approved Kubernetes minor version:
  - `pod-security.kubernetes.io/enforce-version: v<minor>`
  - `pod-security.kubernetes.io/audit-version: v<minor>`
  - `pod-security.kubernetes.io/warn-version: v<minor>`
- Use `latest` only in explicitly owned canary or non-protected namespaces where policy drift is intentionally tested before cluster-wide adoption.
- Separate `warn`/`audit` from `enforce`; live environments must not rely on warn-only mode.
- Treat seccomp as a separate runtime evidence requirement: `restricted` admission must reject workloads without explicit `RuntimeDefault` or approved `Localhost`, equivalent custom policies must do the same, or node configuration must prove kubelet `--seccomp-default` / `seccompDefault` is enabled for namespaces where unspecified profiles are temporarily tolerated.
- Namespace policy drift check every `24h`.
- Block deployment if namespace labels regress or are removed.
- During Kubernetes upgrades, run a dry-run evaluation of the next PSS version before changing namespace labels, record violations by workload owner, remediate or approve time-boxed exceptions, then update `enforce-version`, `audit-version`, and `warn-version` together.
- Treat a PSS version change as a policy change: it needs owner approval, rollout window, rollback plan, and post-change evidence that protected namespaces still enforce `restricted`.

---

## 6. Anti-patterns

Each anti-pattern directly increases risk from the threat model:

- Running containers as root
  -> Enables privilege escalation and increases escape impact

- `privileged: true`
  -> Grants near-host-level access and breaks isolation assumptions

- Adding broad Linux capabilities without strict need
  -> Expands the kernel attack surface and privilege boundary

- Uncontrolled `hostPath` usage
  -> Enables direct access to the host filesystem and possible node compromise

- Mounting sensitive host interfaces such as container runtime sockets
  -> Can enable host takeover or control over other containers

- Missing seccomp profile
  -> Exposes a broader syscall surface and increases kernel exploitability

- Non-default `procMount` usage
  -> Weakens process information isolation

- Use of `shareProcessNamespace: true`
  -> Breaks process-isolation boundaries between containers in the same Pod and simplifies in-Pod lateral movement

- Implicit supplementary groups from the container image
  -> Can grant process access to shared storage or files that is not visible in the manifest without runtime verification

- Broad `fsGroup`/`supplementalGroups` without an ownership model
  -> Turns group-based volume access into a side channel between workloads

- `appArmorProfile.type: Unconfined` or missing AppArmor evidence on supported nodes
  -> Removes the expected LSM protection layer and makes PSS/audit output incomplete

- Unsafe sysctls in normal application namespaces
  -> Can affect the node or neighboring workloads and should remain an exception for isolated node pools

- Writable root filesystem (`readOnlyRootFilesystem: false`)
  -> Enables persistence, runtime payload storage, and modification of application files or configuration inside the container

- Automatic mounting of ServiceAccount tokens by default
  -> Increases Kubernetes API abuse risk after compromise

- Use of the namespace `default` ServiceAccount
  -> Encourages privilege reuse and weak identity separation between workloads

---

## 7. Related Materials

- Adversarial validation for pod-level abuse paths: [kubernetes/adversarial-validation/playbook.en.md](/Product-security-playbook/en/platform-security/kubernetes/adversarial-validation/playbook/)
- Kubernetes Secrets for Secret volumes, env delivery, and ServiceAccount/RBAC boundaries: [kubernetes/secrets/playbook.en.md](/Product-security-playbook/en/platform-security/kubernetes/secrets/playbook/)
