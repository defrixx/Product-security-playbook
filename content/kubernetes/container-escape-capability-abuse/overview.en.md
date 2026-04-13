# Container Escape and Capability Abuse: Attack Vectors Overview

## 1. Scope

This note explains two related but distinct risk areas in container security:
- **Container escape**  -  an attacker crosses an isolation boundary and gains access to host resources, host namespaces, or host execution paths.
- **Capability abuse**  -  an attacker stays inside the container's namespaces but abuses excessive Linux privileges to access sensitive host data, host devices, or dangerous kernel functionality.

---

## 2. Why Containers Are Exposed

Containers are not separate kernels or full security boundaries. They are Linux processes isolated by kernel primitives such as:
- namespaces
- cgroups
- Linux capabilities
- seccomp / LSMs
- filesystem and runtime restrictions
An attack succeeds when one or more of these controls are misconfigured, bypassed, over-permissive, or broken by a kernel/runtime flaw.

---

## 3. What Counts as a Container Escape

A container escape is any attacker action that crosses isolation boundaries and reaches host context. Common examples include:
- joining host namespaces
- accessing host filesystems through privileged mounts
- using container runtime control paths to create host-level execution
- abusing cgroup control files so the host kernel executes attacker-controlled code
- exploiting kernel vulnerabilities to gain host-equivalent privileges

---

## 4. Main Container Escape Attack Vectors

## 4.1 Namespace transition into host context

An attacker can join host namespaces directly or indirectly, typically through `setns`, `unshare`, `clone`, or tools like `nsenter`.

### Typical preconditions
- privileged container
- access to host namespace file descriptors
- dangerous runtime flags such as `--pid=host`
- kernel/runtime weakness that enables namespace transition

### Typical impact
- host process visibility
- host filesystem visibility
- host network visibility
- easier follow-on privilege escalation and persistence

---

## 4.2 Cgroup release_agent abuse

A classic misconfiguration-based escape is abuse of the cgroup v1 `release_agent` mechanism.

### Attack pattern
The attacker mounts cgroup v1, creates a child cgroup, writes to control files such as:
- `notify_on_release`
- `release_agent`
- `cgroup.procs`
The host kernel then executes attacker-controlled code when the cgroup is released.

### Typical preconditions
- cgroup v1 present
- ability to mount or manipulate cgroup files
- usually excessive privileges such as `CAP_SYS_ADMIN`
- sometimes kernel-specific variants

### Typical impact
- host command execution
- full host compromise path

---

## 4.3 Docker socket / runtime API abuse

If a container can access `docker.sock` or an exposed container runtime API, it can often ask the runtime to create a new privileged container or mount the host filesystem.

### Attack pattern
The attacker uses the runtime API to launch a child container with:
- elevated privileges
- host root mounted into the container
- broad device access
- relaxed security controls

### Typical preconditions
- mounted `docker.sock`
- exposed Docker API
- similar runtime control channel exposure

### Typical impact
- rapid escalation to host filesystem access
- creation of privileged follow-on containers
- persistence through runtime-managed workloads

---

## 4.4 Host `/proc` access from privileged containers

A privileged or over-permitted container may read host information through `/proc`, including:
- `/proc/1/root/*`
- `/proc/1/environ`
- `/proc/1/maps`
- kernel tunables such as `core_pattern`

### Typical preconditions
- `--privileged`
- `--pid=host`
- `CAP_SYS_PTRACE`
- host `/proc` visibility
- weak runtime isolation

### Typical impact
- credential harvesting
- token discovery
- host process reconnaissance
- preparation for persistence or lateral movement

---

## 4.5 Vulnerable kernel subsystem exploitation

An attacker may exploit kernel bugs reachable from a container, for example through:
- `splice`
- `fsopen` / `fsconfig`
- netfilter / netlink paths
- symlink race paths
- runtime overwrite attempts such as `/proc/self/exe`

### Typical preconditions
- vulnerable kernel or runtime
- reachable syscall surface
- often additional privilege or namespace conditions depending on the CVE

### Typical impact
- privilege escalation
- namespace escape
- credential corruption
- host-level execution

---

## 5. What Capability Abuse Is

Capability abuse is different from full escape:
- The attacker may remain inside container namespaces but still perform dangerous actions because the container has been granted excessive Linux capabilities or broad runtime privileges.
This is often more realistic than a "clean" escape because many environments intentionally over-grant privileges for operational convenience.

---

## 6. Main Capability Abuse Attack Vectors

## 6.1 Excessive `CAP_SYS_ADMIN`

### What it enables
Depending on context, it may allow:
- mounting filesystems
- manipulating namespaces
- interacting with sensitive kernel interfaces
- broad administrative actions that should never be normal for most workloads

### Abuse examples
- mounting host-related filesystems
- manipulating cgroup structures
- enabling access paths into sensitive kernel or host resources

### Impact
Even without crossing namespaces, this can provide host data exposure or direct paths to further escalation.

---

## 6.2 `CAP_SYS_PTRACE` with host PID visibility

### Abuse examples
- reading `/proc/1/environ`
- reading `/proc/1/maps`
- inspecting process state and memory layout

### Why this matters
Environment variables often contain:
- cloud credentials
- API tokens
- service secrets
- internal endpoints

### Impact
This is a high-value credential theft vector and a strong enabler for lateral movement.

---

## 6.3 `CAP_NET_RAW` and raw socket access

### Abuse examples
- packet capture
- ARP and interface reconnaissance
- low-level network interaction not expected for ordinary application containers

### Impact
- network reconnaissance
- credential capture opportunities
- support for lateral movement or spoofing-related abuse

---

## 6.4 `--privileged` containers

### Typical properties
- all capabilities
- broad device access
- weaker seccomp restrictions
- weaker AppArmor/LSM isolation depending on configuration

### Abuse examples
- mounting host block devices such as `/dev/sda1`
- reading `/dev/kmsg`
- using `keyctl`
- interacting with BPF-related paths
- attempting module load flows

### Impact
A privileged container often does not need a classic escape. It may already have enough power to compromise the node operationally.

---

## 6.5 Host device and sensitive kernel interface access

### Abuse targets
- block devices
- `/dev/kmsg`
- kernel keyrings
- BPF interfaces
- module-loading paths

### Impact
- host reconnaissance
- persistence preparation
- tampering opportunities
- deeper post-exploitation

---

## 7. Difference Between Escape and Capability Abuse

## Container escape
The attacker crosses isolation boundaries.

Examples:
- joining host namespaces
- using runtime APIs to create host-mounted privileged containers
- exploiting kernel bugs to reach host context

## Capability abuse
The attacker stays within the assigned container context but that context is already too powerful.

Examples:
- reading `/proc/1/environ`
- mounting sensitive filesystems
- using raw sockets
- accessing `/dev/kmsg`
- abusing keyrings or BPF paths

## Why the distinction matters
A security review that looks only for "escape" can miss the more common operational reality: the container never technically broke out, but it still exposed host secrets or enabled node compromise.

---

## 8. Typical Root Causes

Most of these attack vectors depend on one or more of the following failures:
- running containers as `--privileged`
- mounting `docker.sock`
- using `hostPID`, `hostNetwork`, or host filesystem mounts without strict justification
- granting dangerous capabilities such as `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_RAW`
- weak seccomp / AppArmor / SELinux posture
- vulnerable kernel or runtime versions
- poor control of daemonset/pod creation in Kubernetes
- assuming containers are a hard security boundary

---

## 9. Security Review Questions

When reviewing a workload, ask:
- Can the container reach host namespaces?
- Can it access the runtime control plane such as `docker.sock`?
- Can it read host `/proc` paths?
- Does it have dangerous capabilities?
- Is it privileged?
- Can it mount filesystems or access block devices?
- Can it create raw sockets?
- Can it access kernel-facing interfaces such as keyrings, BPF, or module-load paths?
- Is the node/kernel/runtime version exposed to known breakout paths?
- Would compromise of this container expose host credentials or enable privileged follow-on actions?