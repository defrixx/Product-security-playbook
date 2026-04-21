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

**Purpose:**
- Prevent access to host processes
- Prevent access to host network namespace
- Preserve workload isolation boundaries

---

### 4.8 Resource Constraints

**Pod / container runtime controls:**
- Define `resources.requests`
- Define `resources.limits`

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
- Separate `warn`/`audit` from `enforce`; production must not rely on warn-only mode.
- Namespace policy drift check every `24h`.
- Block deployment if namespace labels regress or are removed.

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

- Writable root filesystem  
  -> Enables persistence and runtime payload storage inside the container

- Automatic mounting of ServiceAccount tokens by default  
  -> Increases Kubernetes API abuse risk after compromise

- Use of the namespace `default` ServiceAccount  
  -> Encourages privilege reuse and weak identity separation between workloads
