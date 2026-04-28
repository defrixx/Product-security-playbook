# Kubernetes Seccomp Review Checklist

## 1. Scope and Security Objective

Use this checklist to verify whether seccomp is applied **correctly, realistically, and safely** for Kubernetes workloads.

### Objective

Seccomp is used to:
- reduce reachable kernel attack surface;
- block clearly dangerous syscalls;
- constrain syscall surface per workload where operationally justified.

### Non-objectives

Seccomp is **not**:
- a complete sandbox;
- a substitute for runtime isolation;
- a substitute for dropping excessive Linux capabilities;
- proof of security just because a profile exists in YAML.

Note: seccomp is one layer. User namespaces do not replace seccomp; review syscall surface and capabilities independently. Validate other hardening layers using the dedicated pod security and container escape/capability abuse checklists:
- [kubernetes/pod-security/playbook.en.md](../pod-security/playbook.en.md)
- [kubernetes/container-escape-capability-abuse/overview.en.md](../container-escape-capability-abuse/overview.en.md)

---

## 2. Baseline Questions Before Review

Before reviewing a profile, confirm:
- seccomp is enabled for the workload;
- profile scope is correct (Pod or Container);
- profile source is runtime default, custom, or auto-generated;
- runtime in use (`Docker/Moby`, `containerd/runc`, other);
- target architectures (`x86_64`, `x86`, `x32`, `arm64`, others);
- granted Linux capabilities;
- whether the workload truly needs advanced kernel interaction.

The real security effect depends on runtime behavior, architecture coverage, and capabilities, not only static JSON/YAML.

---

## 3. Design Principles

### 3.1 Block dangerous first

Review priority should be:
- remove known high-risk syscalls first;
- then reduce additional syscall surface where justified;
- avoid replacing threat modeling with mechanical "block everything not seen in trace".

### 3.2 Design per workload

The team should explicitly define:
- why this workload needs seccomp;
- which attack classes are reduced;
- which operational tradeoffs are accepted.

---

## 4. Profile Source and Generation Quality

### 4.1 Auto-generated profiles require manual curation

If a profile came from tracing/tooling (SPO, eBPF tracers, ptrace/strace-like, OCI/runtime tracing), manual syscall review is mandatory before approval.

### 4.2 Do not assume trace completeness

Account for:
- different tracing layers producing different syscall sets;
- runtime setup syscalls contaminating traces;
- identical code generating different traces across libc, kernel, build, and runtime conditions.

### 4.3 Separate app signal from platform noise

Check whether syscall entries came from:
- `containerd` / `containerd-shim` / `runc`;
- init containers / sidecars;
- CNI and secret injection workflows;
- storage mount paths;
- the profiling tool itself.

---

## 5. Scope of Application: Pod vs Container

### 5.1 Verify actual attachment scope

Confirm where the profile is applied:
- Pod security context;
- Container security context.

### 5.2 Prefer container-specific profiles when behavior differs

Pod-wide profiles are often over-broad when a Pod includes init/sidecar containers or mixed responsibilities.

---

## 6. High-Risk Syscalls and Bypass Combos

Review allowed syscalls and combinations as one risk surface, not line by line.

### 6.1 Tier 1 (default fail without exceptional justification)

These should be disallowed by default:
- `bpf`
- `ptrace`
- `kexec_load`
- `init_module`
- `finit_module`

If any are allowed, require explicit justification, security sign-off, compensating controls, owner, and review expiry.

### 6.2 Tier 2 (significant risk, strong justification required)

Carefully justify:
- `io_uring_setup`, `io_uring_enter`, `io_uring_register`
- `perf_event_open`
- `mount`
- `clone`, `clone3`
- `unshare`
- `add_key`, `keyctl`
- `userfaultfd`
- `chroot`

### 6.3 Why risky syscalls exist and why they are restricted

Use this table during review to distinguish real technical need from "the application starts this way". If a syscall is allowed, the exception should state which component calls it, which operation is impossible without it, why a less privileged path is not viable, which capabilities are granted to the container, and how expanded use is detected.

| Syscall / group | Common use | What it gives the process | Why restrict it or require justification |
| --- | --- | --- | --- |
| `bpf` | Creating and managing eBPF maps/programs, loading eBPF programs into the kernel, attaching to tracing/network/control-plane events. | Ability to run verified but still kernel-resident code and store state in kernel-managed structures. | This is direct interaction with kernel subsystems. Normal app workloads almost never need it; it often appears as observability/CNI/tracing noise. Allow only for explicitly scoped eBPF/observability components with separate security review and minimal capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` in older models). |
| `ptrace` | Debugging, tracing, inspecting, and modifying another process. | Reading/changing tracee registers and memory, intercepting syscalls and signals. | In a container, this risks secret disclosure and interference with neighboring processes in the same PID namespace; with a flawed namespace/capability model, risk can cross workload boundaries. It should normally be blocked for production app containers except tightly isolated debug/profiling cases. |
| `kexec_load`, `kexec_file_load` | Loading a new kernel image for later transition without a full firmware boot. | Preparing the system to reboot into another kernel. | A container workload should not have a path to control the kernel boot chain. Presence in a profile almost always indicates profiling error or excessive privileges; it is also tied to `CAP_SYS_BOOT`. |
| `init_module`, `finit_module`, `delete_module` | Loading and removing kernel modules. | Changing code that runs in kernel space. | This is a host-level operation and incompatible with the normal container isolation model. It is acceptable only for very specialized node-level agents, in which case the design is a separate privileged security model, not a regular workload profile. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Creating rings and executing asynchronous I/O through io_uring. | A high-performance I/O interface where one syscall family can initiate different file/network-like operations. | This is a bypass risk for profiles that block "classic" file/network syscalls while leaving io_uring open. Allow only with proven performance need, documented fallback, and validation that the profile does not rely on restrictions bypassed through io_uring. |
| `perf_event_open` | Performance counters, profiling, tracing, CPU/kernel/user-space events. | Access to counters and sample/ring-buffer data; some modes require `CAP_PERFMON` or `CAP_SYS_ADMIN` or depend on `perf_event_paranoid`. | It can expose process and host/kernel activity and interacts with BPF/perf infrastructure. App containers usually do not need it; move profiling into controlled jobs or node agents. |
| `mount`, `umount`, `umount2`, `pivot_root` | Mounting, unmounting, and changing the root filesystem. | Changing the mount namespace and filesystem visibility. | With `CAP_SYS_ADMIN`, this is one of the broadest container escape and host filesystem exposure surfaces. Regular workloads should not mount at runtime; use Kubernetes volumes/CSI/init-time preparation instead of allowing the syscall. |
| `clone`, `clone3`, `unshare`, `setns` | Creating processes/threads and namespaces, entering existing namespaces. | Control over process namespace/topology, including user/mount/network/PID namespace scenarios. | Not every `clone` is dangerous: most applications need processes and threads. Risk appears with namespace flags, `setns`, and `unshare`, especially alongside capabilities and user namespaces. In custom profiles, check arguments, not only the syscall name. |
| `add_key`, `keyctl`, `request_key` | Using the kernel keyring. | Creating, finding, and using keys in kernel-managed keyrings. | The keyring has historically not been a simple per-container resource and can create unwanted cross-boundary effects. Applications should use standard secret stores, tmpfs volumes, or KMS integrations instead of the kernel keyring. |
| `userfaultfd` | User-space page-fault handling, live migration, checkpoint/restore, memory-management runtimes. | Delegating page-fault handling to user space for selected memory regions. | Useful for specialized runtime/CRIU/migration cases, but rarely needed by a normal service. It expands the kernel memory-management attack surface; require an owner, kernel-version assumptions, and confirmation that a simpler mechanism cannot replace it. |
| `chroot` | Changing the process root directory. | Restricting path resolution relative to a new root. | `chroot` is not container isolation by itself and can create false sandboxing assumptions. In Kubernetes, the root filesystem should be controlled by the runtime/volume model; runtime `chroot` inside an app container requires explanation and review of `CAP_SYS_CHROOT`, mounts, and writable paths. |
| `open_by_handle_at`, `name_to_handle_at` | Opening a file by persistent file handle and obtaining such a handle. | Bypassing ordinary path-based name resolution when the process has a suitable mount fd and rights. | This can break assumptions behind path-based controls and has appeared in historical container breakout classes. Block in app profiles unless there is a very specific storage-agent scenario. |
| `process_vm_readv`, `process_vm_writev`, `kcmp` | Cross-process memory read/write and comparison of kernel resources used by processes. | Inspecting or modifying another process without a ptrace-style workflow. | This is process-inspection surface close to debug/tracing risk. Block for normal app containers; for profilers, require a separate scope, PID namespace boundaries, and capability restrictions. |
| Time syscalls: `clock_settime`, `clock_adjtime`, `settimeofday`, `stime` | Changing system time. | Influence over host/global timekeeping where time is not namespaced. | Can break TLS, audit, scheduling, and distributed-systems assumptions. Containers normally should not change time; this is tied to `CAP_SYS_TIME`. |
| Low-level I/O syscalls: `iopl`, `ioperm` | Managing I/O privilege level and access to I/O ports. | Low-level access to hardware/architecture interfaces. | Normal workloads do not need it and it carries host-level risk; it should generally stay outside containers together with `CAP_SYS_RAWIO`. |

### 6.4 Mandatory `io_uring` checks

Treat `io_uring` as a syscall-multiplexing risk. Check the anti-pattern:
- classic network/file syscalls blocked;
- `io_uring_setup` + `io_uring_enter` allowed.

Always document:
- business need for `io_uring`;
- fallback without `io_uring`;
- accepted residual risk.

### 6.5 Mandatory `bpf` checks

If `bpf` is allowed, treat the profile as presumptively unsafe until proven otherwise.
Check whether `bpf` was included accidentally via tracing/runtime/CNI/capability noise.

### 6.6 Mandatory bypass combo checks

Check combinations:
- `io_uring_setup` + `io_uring_enter` while network syscalls are blocked;
- `io_uring_setup` + `io_uring_enter` while file/filesystem-path syscalls are blocked;
- `io_uring_setup` + `io_uring_enter` while `splice`/`tee`/`vmsplice` are blocked;
- `io_uring_setup` + `io_uring_enter` with futex/process-wait restrictions;
- `io_uring_setup` + `io_uring_enter` while `ioctl` or xattr syscalls are blocked.

---

## 7. Runtime, Capabilities, Architecture

### 7.1 Do not review seccomp separately from capabilities

Assess effective policy together with capabilities, especially `CAP_SYS_ADMIN`, `CAP_BPF`, and other kernel-facing capabilities.

### 7.2 Account for runtime implementation of effective profile

Confirm:
- profile is static or runtime-generated;
- capability-sensitive mutations happen at startup.

### 7.3 Architecture and ABI coverage

Verify explicit coverage for target architectures. In relevant environments, check x32 ABI blind spots (`SCMP_ARCH_X32`).

---

## 8. Operational Correctness and Lifecycle

### 8.1 Functional correctness

A profile must not break production, but adding high-risk syscalls just to make startup succeed is not acceptable.

### 8.2 Realistic validation

Profiling/validation should include:
- real startup path;
- real dependency initialization;
- sidecar/init behavior when present;
- production-like kernel/runtime;
- relevant architectures and libc.

### 8.3 CI/CD policy gates

Minimum controls:
- fail build on forbidden syscalls;
- fail build on dangerous combo patterns;
- require manual security review for high-risk deltas;
- enforce exception tracking (owner + expiry).

### 8.4 Drift and effective-profile verification on nodes

Do not rely only on Git YAML. Store approved profile hash and compare it with runtime effective profile via runtime inspection (`crictl inspect` / runtime API) at least every `24h` and after kernel/runtime/capability changes.

---

## 9. Reviewer Decision Matrix

### 9.1 Canonical anti-patterns (single list)

- Auto-generated profile approved without manual curation.
- Quality judged by "number of blocked syscalls".
- Classic syscalls blocked while `io_uring` remains open.
- Static YAML/JSON reviewed without runtime context.
- App syscalls mixed with runtime/init/CNI noise.
- Dangerous syscalls kept because "the workload runs with them".
- Powerful capabilities granted without seccomp re-review.

### 9.2 Fail immediately if

- `bpf`, `ptrace`, `kexec_load`, `init_module`, or `finit_module` are allowed without exceptional justification;
- `io_uring` is allowed but bypass implications were not reviewed;
- effective runtime policy is unknown;
- capabilities and seccomp were reviewed independently.

### 9.3 Escalate to manual security review if

- `io_uring_*`, `mount`, `unshare`, `clone/clone3`, `perf_event_open`, `userfaultfd`, `keyctl`, or `add_key` are present;
- profile is Pod-wide for a multi-container Pod;
- runtime mutates effective policy dynamically;
- workload needs stronger isolation than seccomp can realistically provide.

### 9.4 Accept with conditions if

- high-risk syscalls are removed or tightly justified;
- scope is correct;
- architecture/ABI coverage is verified;
- bypass combinations and residual risk are documented;
- CI/CD enforces continuous validation.

---

## 10. Final Review Statement

A good seccomp profile:
- reduces real attack surface;
- excludes or tightly controls high-risk syscalls;
- accounts for bypass combinations, runtime, and capabilities;
- is maintained as a continuous process, not a one-time setup.

A profile that is merely "strict" or present in YAML is not sufficient by itself.