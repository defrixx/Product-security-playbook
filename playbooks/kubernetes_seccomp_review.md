# Kubernetes Seccomp Review Checklist

## 1. Scope and Security Objective

Use this checklist to review whether seccomp is being applied **correctly, realistically, and safely** for Kubernetes workloads.

### Objective

Seccomp should be used to:

- Reduce the reachable kernel attack surface
- Block clearly dangerous syscalls that enable breakout, escalation, stealth, or policy bypass
- Enforce a workload-specific syscall baseline where operationally feasible
- Complement, not replace, stronger isolation and other workload hardening controls

### Non-objectives

Seccomp should **not** be treated as:

- A complete sandbox
- A substitute for runtime isolation
- A substitute for dropping Linux capabilities
- A substitute for Pod Security controls, user separation, AppArmor/SELinux, or network policy
- Proof that a workload is "secure" just because a profile exists

---

## 2. Baseline Questions Before Review

Confirm the following first:

- Is seccomp enabled for the workload at all?
- Is the profile applied at the correct scope:
  - Pod-level
  - Container-level
- Is the profile custom, runtime default, or auto-generated?
- Which runtime is in use:
  - Docker/Moby
  - containerd/runc
  - Other
- Which architecture(s) must be covered:
  - x86_64
  - x86
  - x32
  - arm64
  - others
- Which Linux capabilities are granted to the container?
- Is the workload expected to need advanced kernel interaction, or is it a normal application process?

This matters because the actual security effect of a seccomp profile depends on runtime behavior, architecture coverage, and capability context, not just the static JSON/YAML you review.

---

## 3. Correct Design Principles

### 3.1 Prefer "block dangerous first" over "blindly block everything not observed"

The seccomp design should be based on:

- Blocking **known-dangerous** syscalls first
- Then reducing additional syscall surface where justified
- Avoiding a naive assumption that "unused" automatically means "security-relevant"

A key point: **unnecessary syscalls** and **dangerous syscalls** are not the same. Blocking dangerous syscalls clearly reduces risk. Blocking arbitrary unused syscalls may only add fragility if there is no clear threat reduction.

### 3.2 Apply per workload, not as a cargo-cult exercise

The team should explicitly define:

- Why seccomp is used for this workload
- Which attack classes are being reduced
- What operational tradeoffs are acceptable
- Whether seccomp is the right tool at all for this workload

### 3.3 Treat seccomp as one layer in defense in depth

Use seccomp alongside:

- Non-root execution
- Dropped capabilities
- `allowPrivilegeEscalation: false`
- Read-only filesystem where possible
- AppArmor/SELinux where available
- Runtime default protections
- Admission policy
- Network controls
- Stronger isolation for high-risk workloads

---

## 4. Profile Source and Generation Review

## 4.1 If the profile was auto-generated, require manual review

Identify whether the profile came from:

- Tracing-based generation tools
- Security Profiles Operator workflows
- eBPF tracers
- ptrace/strace-like tooling
- OCI/runtime tracing

If yes, verify there was a **manual syscall review** before approval.

## 4.2 Do not assume tracing tools agree or are complete

Reviewers should account for the following:

- Different tracing layers see different syscall sets
- Runtime setup syscalls can be captured and mistaken for application syscalls
- Identical code can yield different syscall traces across libc, kernel, build, and runtime conditions

## 4.3 Confirm the trace captured the application, not surrounding platform noise

Look for contamination from:

- `containerd`
- `containerd-shim`
- `runc`
- init containers
- sidecars
- CNI components
- secret injection workflows
- storage mounts
- tracing tools themselves

---

## 5. Scope of Application: Pod vs Container

### 5.1 Verify the profile is attached at the intended scope

Verify where the profile is applied:

- Pod security context
- Container security context

Then confirm this is intentional.

### 5.2 Prefer container-specific review when behavior differs inside the Pod

Be careful when:

- There are init containers
- There are sidecars
- Containers have different responsibilities
- One container is more privileged than another

A Pod-wide profile can be too broad and may mix startup/runtime behavior from multiple containers.

---

## 6. Dangerous Syscall Review

The following syscalls should be treated as high-risk review items.

## 6.1 Tier 1: Default fail unless there is an exceptional, documented reason

These should be **disallowed by default**:

- `bpf`
- `ptrace`
- `kexec_load`
- `init_module`
- `finit_module`

### Review note

If any of the above are allowed, require:

- Explicit justification
- Security sign-off
- Compensating controls
- Review of whether the workload should instead run in stronger isolation

## 6.2 Tier 2: Significant risk, strong justification required

Review carefully if the profile allows:

- `io_uring_setup`
- `io_uring_enter`
- `io_uring_register`
- `perf_event_open`
- `mount`
- `clone`
- `unshare`

## 6.3 Additional sensitive syscalls explicitly highlighted in the series

Explicitly review:

- `add_key`
- `keyctl`
- `userfaultfd`
- `clone3`
- `chroot`

---

## 7. io_uring Review: Mandatory Section

If `io_uring_*` is allowed, treat this as a major review event.

### 7.1 Reviewer understanding of bypass risk

Ensure the team understands that `io_uring` is not just an I/O optimization. It can act as a **syscall multiplexer**, allowing operations that would otherwise be blocked at the syscall layer.

`io_uring_enter()` can submit operations corresponding to network, file, filesystem, polling, splice, futex/wait, ioctl, and xattr behavior without directly invoking the blocked syscalls.

### 7.2 Check for the specific anti-pattern

Treat the following as a serious anti-pattern:

- Blocking `socket`, `connect`, `send`, `recv`
- But allowing `io_uring_setup` + `io_uring_enter`

This creates a false sense of security. Network restrictions can be bypassed this way because the blocked network syscalls are never directly called.

### 7.3 Check for optional feature leakage

Verify that `io_uring` was not included only because the application opportunistically tested for it.

### 7.4 If `io_uring` is kept, document why

Require documentation of:

- Why it is needed
- Whether fallback exists
- Which attack surface is accepted
- Which compensating controls exist

---

## 8. eBPF / bpf Review: Mandatory Section

If `bpf` is allowed, treat the profile as presumptively unsafe until proven otherwise.

### 8.1 Confirm whether `bpf` is truly required

`bpf` is one of the first syscalls an attacker would look for because it enables powerful kernel interaction and has been tied to escalation and stealth use cases.

### 8.2 Check for hidden origin of `bpf` in the profile

Verify whether `bpf` entered the profile because of:

- eBPF-based tracing tools
- runtime/CNI behavior
- Pod-level noisy profiling
- granted capabilities
- unrelated infrastructure components

### 8.3 Treat `bpf` as incompatible with most ordinary application workloads

For normal business workloads, `bpf` allowance should usually be treated as a design failure unless there is a very strong and explicit platform-level justification.

---

## 9. Capabilities and Seccomp Must Be Reviewed Together

### 9.1 Do not review seccomp in isolation

Review the container's granted capabilities.
Capabilities can materially affect the effective seccomp policy. In Docker/Moby and containerd flows, capability-sensitive handling can change what is allowed, including syscall behavior around `bpf` and other sensitive functions.

### 9.2 Flag dangerous capability combinations

Require review when seccomp is paired with capabilities such as:

- `CAP_SYS_ADMIN`
- `CAP_BPF`
- other powerful kernel-facing capabilities

### 9.3 Anti-pattern

Treat this as an anti-pattern:

- "We have seccomp, so extra capabilities are acceptable"

This is incorrect reasoning. Capabilities can drastically reduce the value of seccomp.

---

## 10. Architecture and ABI Coverage

### 10.1 Confirm architecture coverage is explicit

Verify that the profile covers the architectures relevant to deployment.

### 10.2 Check for x32 ABI blind spots where relevant

If `SCMP_ARCH_X32` is not declared, blocked syscall numbers may be reachable through x32 ABI paths in some conditions.

### 10.3 Do not assume one profile behaves identically across all environments

Different kernel versions, libc variants, toolchains, and runtimes can change which syscalls are actually used or observed. The same code can legitimately produce different syscall lists on different systems.

---

## 11. Combo and Bypass Review

A good seccomp review must check **combinations**, not just single syscall lines.

### 11.1 Mandatory combo checks

Review for these patterns:

- `io_uring_setup` + `io_uring_enter` while network syscalls are blocked
- `io_uring_setup` + `io_uring_enter` while file I/O syscalls are blocked
- `io_uring_setup` + `io_uring_enter` while filesystem-path syscalls are blocked
- `io_uring_setup` + `io_uring_enter` while polling syscalls are blocked
- `io_uring_setup` + `io_uring_enter` while `splice`/`tee`/`vmsplice` are blocked
- `io_uring_setup` + `io_uring_enter` with process-wait/futex restrictions
- `io_uring_setup` + `io_uring_enter` where `ioctl` is blocked
- `io_uring_setup` + `io_uring_enter` where xattr syscalls are blocked

These combination classes illustrate why line-by-line syscall review can miss real bypass paths.

### 11.2 Anti-pattern

Treat this as an anti-pattern:

- "We blocked the classic syscall names, therefore the function is blocked"

This is not sufficient when multiplexing mechanisms exist.

---

## 12. Operational Correctness Review

### 12.1 Verify required syscalls remain available

A profile that breaks production is not a good profile.

Missing necessary syscalls leads to crashes and failed deployments, which is the most immediate operational failure mode.

### 12.2 Avoid adding dangerous syscalls just to start the workload

This is often worse than a startup failure because it creates a functioning but less secure workload.
A profile can pass CI and deploy successfully while still weakening security by allowing dangerous syscalls.

### 12.3 Require test coverage under realistic runtime behavior

Confirm that profiling and validation were performed with:

- Real startup path
- Real dependency initialization
- Real sidecars/init containers present if applicable
- Production-like kernel/runtime behavior
- Relevant architecture and libc conditions

---

## 13. Runtime and Implementation Awareness

### 13.1 Confirm how the effective profile is produced by the runtime

For example:

- Is the profile loaded as static JSON?
- Is it generated dynamically?
- Are capability-based variations applied at startup?

Containerd may generate the effective seccomp configuration dynamically depending on process capabilities, which makes the real enforced policy harder to audit from static files alone.

### 13.2 Anti-pattern

Treat this as an anti-pattern:

- "The YAML looks safe, therefore the runtime behavior is safe"

The actual filter applied at runtime may differ in effect depending on implementation details, capabilities, and platform context.

---

## 14. CI/CD and Lifecycle Management

### 14.1 Seccomp review must not be a one-time activity

Re-evaluate seccomp whenever any of the following change:

- Application code
- Dependencies
- Base image
- libc
- Kernel
- Node type
- Container runtime
- Capabilities
- Sidecars/init containers
- Workload behavior

Seccomp is not a one-time exercise and should be integrated into CI because even normal changes can invalidate previous assumptions.

### 14.2 Add policy gates to CI

Recommended controls:

- Fail build if forbidden syscalls are present
- Fail build if dangerous combinations are present
- Compare custom profile against runtime default
- Require manual security review for high-risk deltas
- Maintain exceptions with expiry and owner

### 14.3 Track profile drift

The team should be able to answer:

- Which version of the profile is deployed
- Which image/workload version it matches
- When it was last profiled
- What changed since last approval

---

## 15. Recommended Review Heuristics

Use these practical review heuristics.

### 15.1 Good signs

- Profile purpose is documented
- Dangerous syscalls are explicitly reviewed
- Capabilities are minimized
- Profile is container-specific where needed
- Architecture coverage is explicit
- Auto-generated output was manually curated
- `io_uring` and `bpf` receive special scrutiny
- CI validates the profile continuously
- Team compares against runtime defaults
- Team understands that seccomp is only one layer

### 15.2 Bad signs

- Profile exists only because "best practice says so"
- Profile was auto-generated and never manually reviewed
- Review focused only on "number of syscalls blocked"
- Pod-level profiling captured unrelated components
- Dangerous syscalls were included because "the app started with them"
- `io_uring` is allowed while network/file syscalls are blocked
- `bpf` is present in an ordinary app profile
- Capabilities were granted without re-reviewing seccomp
- Architecture/ABI coverage was ignored
- No retesting is done after changes

---

## 16. Common Anti-Patterns

### Anti-pattern 1: Auto-generated profile = approved profile

Auto-generation is only an input, not a security decision.

### Anti-pattern 2: Counting blocked syscalls as the main success metric

A stricter profile is not automatically safer if dangerous syscalls are still allowed.

### Anti-pattern 3: Blocking classic network syscalls while leaving `io_uring` open

This can leave the network path effectively reachable.

### Anti-pattern 4: Reviewing static YAML/JSON without runtime context

Runtime behavior, capabilities, and implementation details still matter.

### Anti-pattern 5: Mixing application syscalls with runtime/init/CNI syscalls

This can broaden the profile and introduce dangerous allowances.

### Anti-pattern 6: Keeping dangerous syscalls because "the workload works with them"

A workload starting successfully does not mean the profile is acceptably secure.

---

## 17. Minimal Reviewer Decision Framework

Use this simplified decision flow.

### Fail immediately if:

- `bpf` is allowed without exceptional justification
- `ptrace` is allowed without exceptional justification
- `kexec_load`, `init_module`, or `finit_module` are allowed without exceptional justification
- `io_uring` is allowed but bypass implications were not reviewed
- Capabilities and seccomp were reviewed separately
- The profile source is auto-generated and uncurated
- The effective runtime behavior is unknown

### Escalate for manual security review if:

- `io_uring_*` is present
- `mount`, `unshare`, `clone`, `clone3`, `perf_event_open`, `userfaultfd`, `keyctl`, or `add_key` are present
- The profile is Pod-wide with multiple containers
- The workload has elevated capabilities
- The runtime dynamically mutates effective policy
- The workload needs stronger isolation guarantees than seccomp can realistically provide

### Accept with conditions if:

- Dangerous syscalls are removed or tightly justified
- Scope is correct
- Architecture coverage is explicit
- Capabilities are minimized
- Bypass combinations were assessed
- CI continuously validates the profile
- The team understands and documents the residual risk

---

## 18. Final Review Statement

A seccomp profile should be considered **good** only when it:

- Reduces real attack surface
- Excludes known-dangerous syscalls unless explicitly justified
- Avoids obvious bypass combinations
- Matches the actual workload rather than runtime noise
- Is reviewed together with capabilities, runtime, and architecture context
- Is maintained continuously, not created once and forgotten

A profile that is merely restrictive, auto-generated, or present in YAML is not enough.
