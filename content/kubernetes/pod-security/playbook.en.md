# Kubernetes Pod Security Hardening

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
- **Pod-level controls**  -  affect the entire Pod
- **Container-level controls**  -  must be enforced for each container

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
- In production, use `hostUsers: false` as the default workload-isolation recommendation where it is compatible with the container runtime, kernel, and storage stack.
- With a user namespace enabled, UID `0` inside the container is not UID `0` on the host: container root and container UID/GID values are mapped to an unprivileged range on the node.
- This reduces blast radius for container escapes, misconfigured mounts, and vulnerabilities that depend on host UID/GID identity, but it does not replace `runAsNonRoot`, `seccompProfile.type: RuntimeDefault`, `capabilities.drop: ["ALL"]`, or denying `privileged: true`.
- Capabilities become namespaced when `hostUsers: false` is set: for example, `CAP_NET_ADMIN` may grant administrative actions over container-local resources without granting host-level administrative power. Even then, grant capabilities only with explicit justification, owner, and expiry.

**Compatibility and failure modes for `hostUsers: false`:**
- Do not treat `hostUsers: false` as a drop-in YAML flag. Verify it on the same Kubernetes minor version, kernel, runtime, CSI/storage stack, and admission policy used in production.
- Pods with user namespaces cannot use host namespaces: `hostNetwork: true`, `hostPID: true`, and `hostIPC: true` are incompatible and should fail admission or deployment validation.
- Raw block `volumeDevices` are not compatible with Pods using user namespaces. Stateful or storage-heavy workloads need an explicit storage compatibility test before adopting this control.
- Pod Security Standards relax `runAsNonRoot` and `runAsUser` checks for Pods with user namespaces because container UID `0` is mapped to an unprivileged host UID. This does not mean "root is safe by default"; keep `runAsNonRoot: true` for normal app workloads unless the workload has a documented reason to run as root inside the user namespace.
- Required verification: admission test for forbidden host namespace combinations, deploy test with the workload's real volumes, node/runtime compatibility evidence, and a PSS test proving the namespace policy outcome is understood.

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
- `procMount: Default`
- For custom profiles: allow only justified syscalls, and review high-risk syscalls and bypass combinations separately

Detailed seccomp review (dangerous syscalls, `io_uring`/`bpf`, combo checks, CI governance): [kubernetes/seccomp/checklist.en.md](../seccomp/checklist.en.md)

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
- For production workloads, deny `shareProcessNamespace: true` by default; allow only explicit break-glass exceptions with owner and expiry.

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
- Define memory limits for production workloads to bound node-level DoS and noisy-neighbor impact.
- Define `ephemeral-storage` requests and limits for workloads that write temporary files, caches, logs, uploads, or generated artifacts.
- Treat CPU limits as workload-specific, not a blanket security default. CPU limits can introduce throttling and latency regressions for services with bursty or latency-sensitive behavior; use them when the DoS/noisy-neighbor risk is higher than the throttling risk, or when required by platform policy.
- For internet-facing, multi-tenant, batch, build, AI/inference, and untrusted-code workloads, document the resource abuse model and choose CPU, memory, and ephemeral-storage guardrails explicitly.
- For critical services, validate limits through load testing rather than copying generic values.

**Namespace-level controls:**
- apply `ResourceQuota` and, where needed, `LimitRange` for shared production namespaces;
- deny BestEffort pods in production namespaces unless an exception is explicitly accepted;
- require namespace quotas to cover CPU, memory, pods, and ephemeral storage where supported by the platform;
- run DoS/`stress-ng` checks only in isolated load/staging environments, not live production namespaces.

---

### 4.9 Debug surfaces

**What to control:**
- `pods/exec`
- `pods/attach`
- `pods/portforward`
- `pods/ephemeralcontainers`
- node-level debug flows

**Production recommendation:**
- restrict `exec` and ephemeral containers in sensitive namespaces to dedicated support/SRE roles;
- log and alert on `exec`, attach/port-forward, and ephemeral-container additions;
- use admission policy to deny debug surfaces in high-value namespaces where operationally acceptable.

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

### 5.1 Enforcement baseline

- `pod-security.kubernetes.io/enforce: restricted` on all production namespaces.
- Pin the policy version for all modes to the approved Kubernetes minor version:
  - `pod-security.kubernetes.io/enforce-version: v<minor>`
  - `pod-security.kubernetes.io/audit-version: v<minor>`
  - `pod-security.kubernetes.io/warn-version: v<minor>`
- Use `latest` only in explicitly owned canary or non-production namespaces where policy drift is intentionally tested before cluster-wide adoption.
- Separate `warn`/`audit` from `enforce`; production must not rely on warn-only mode.
- Namespace policy drift check every `24h`.
- Block deployment if namespace labels regress or are removed.
- During Kubernetes upgrades, run a dry-run evaluation of the next PSS version before changing namespace labels, record violations by workload owner, remediate or approve time-boxed exceptions, then update `enforce-version`, `audit-version`, and `warn-version` together.
- Treat a PSS version change as a policy change: it needs owner approval, rollout window, rollback plan, and post-change evidence that production namespaces still enforce `restricted`.

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

- Writable root filesystem (`readOnlyRootFilesystem: false`)  
  -> Enables persistence, runtime payload storage, and modification of application files or configuration inside the container

- Automatic mounting of ServiceAccount tokens by default  
  -> Increases Kubernetes API abuse risk after compromise

- Use of the namespace `default` ServiceAccount  
  -> Encourages privilege reuse and weak identity separation between workloads

---

## 7. Related Materials

- Adversarial validation for pod-level abuse paths: [kubernetes/adversarial-validation/playbook.en.md](../adversarial-validation/playbook.en.md)
