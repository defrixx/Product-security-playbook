---
title: "Container Image Security and OCI Registry Playbook"
description: "This playbook covers the security review of container images and OCI registries: image structure, Dockerfile baseline, secrets leakage, digest pinning, multi-platform images, re..."
sidebar:
  order: 20
---
## 1. Scope and Objective

This playbook covers the security review of container images and OCI registries: image structure, Dockerfile baseline, secrets leakage, digest pinning, multi-platform images, registry promotion, vulnerability scanning, signing, provenance, and deploy-time verification.

Use it for:
- services deployed from container images to Kubernetes or another orchestrator;
- base images, shared runtime images, build images, and release images;
- registry design, artifact promotion, retention, and image admission policies;
- release reviews where image identity, signature, SBOM, or provenance is part of the evidence.

Out of scope:
- the generic SAST, SCA, and secret-scanning baseline for source code and dependencies: use the [Secure Coding and Code Review playbook](/Product-security-playbook/en/application-security/secure-coding/code-review/playbook/); this document owns only scanning specifics for built images, their layers, and OCI artifacts;
- Kubernetes workload runtime hardening: use the [Pod Security playbook](/Product-security-playbook/en/platform-security/kubernetes/pod-security/playbook/);
- container escape and Linux capability abuse: use the [container escape overview](/Product-security-playbook/en/platform-security/kubernetes/container-escape-capability-abuse/overview/);
- SLSA Build provenance policy details: use the [SLSA provenance overview](/Product-security-playbook/en/supply-chain/slsa-provenance/overview/).

Objective:
- ensure live deployments reference the exact image that was reviewed and approved;
- reduce image-level attack surface and secrets exposure;
- make registry promotion, signature, SBOM, provenance, and vulnerability decisions auditable.

---

## 2. OCI Image Model

Reviewers must distinguish these objects:

| Object | Meaning | Review concern |
|---|---|---|
| Image config | JSON object with runtime defaults and rootfs metadata: user, environment, entrypoint, command, labels, volumes, exposed ports, and layer DiffIDs | Secrets in environment/defaults, unsafe user, unexpected entrypoint, metadata drift |
| Filesystem layers | Ordered filesystem changesets used to construct the root filesystem | Secrets in layers, excessive tools, vulnerable packages, unexpected binaries |
| Manifest | Platform-specific object that references one config and ordered layer descriptors | The digest actually pulled for a platform |
| Image index / manifest list | Higher-level object pointing to platform-specific manifests | Multi-arch ambiguity and platform coverage |
| Tag | Human-readable registry reference to an index or manifest | Mutable unless registry policy enforces immutability |
| Digest | Content-addressed identifier for registry content such as index, manifest, config, or layer | Live-environment trust anchor |
| Image ID | Local identifier derived from image config | Useful locally, but not the registry reference Kubernetes should trust |
| Registry repository | Namespace grouping related artifacts, tags, manifests, indexes, signatures, SBOMs, and attestations | Access control, retention, audit, promotion |

Rule for live environments:
- Treat tags as discovery labels or release channels, not as approval evidence.
- Treat digests as the deployable artifact identity.
- For multi-arch images, decide whether policy verifies the index digest, each platform-specific manifest digest, or both. Critical images should verify both.

---

## 3. Dockerfile Release-Ready Baseline

Mandatory controls:
- Use a minimal, supported base image. Prefer distroless, slim, or purpose-built runtime images when operationally practical.
- Pin the base image by digest for live-environment builds or record the exact base digest in provenance/SBOM evidence.
- Use multi-stage builds to keep compilers, package managers, test tools, and build caches out of the runtime image.
- Run as a non-root user by default. The image user must be compatible with the Kubernetes `securityContext`.
- Do not require privileged mode, host namespaces, broad Linux capabilities, writable host paths, or Docker socket access.
- Keep secrets out of `ARG`, `ENV`, copied files, package manager config, build cache, image labels, and layer history.
- Avoid package managers and shells in runtime images where they are not needed for operations or support.
- Make the startup command explicit and avoid shell wrappers that hide unexpected behavior.

Recommended controls:
- Use reproducible build inputs where practical: pinned dependencies, locked package indexes, deterministic build steps, and stable timestamps where tooling supports them.
- Label images with source repository, revision, build time, license, and maintainer metadata, but do not put sensitive internal URLs or secrets in labels.
- Keep debug tooling in a separate debug image or controlled ephemeral debug workflow, not in the live runtime image.

Verification:
- Inspect Dockerfile, image config, user, entrypoint, environment, exposed ports, labels, and history.
- Scan the final runtime image, not only the build stage.
- Confirm the runtime image can start with non-root, read-only root filesystem where practical, dropped capabilities, and expected mounted paths.

---

## 4. Runtime Assumptions

Image hardening does not replace Kubernetes hardening.

Release-ready defaults:
- The image should not need root. If root is required, document the system call, filesystem, port, or ownership reason and prefer a narrower fix.
- The Kubernetes `securityContext` must enforce the intended image assumptions: `runAsNonRoot`, `allowPrivilegeEscalation: false`, dropped capabilities, seccomp profile, and read-only root filesystem where practical.
- Runtime-writable paths should be explicit: mounted volume, `emptyDir`, or application data directory. Do not depend on writing across the whole image filesystem.
- Health checks and startup probes must not require privileged tools, shell access, or secrets printed to output.

Verification:
- Run the workload with the intended Pod Security profile before release.
- Confirm the container fails safely if filesystem writes, root execution, or extra capabilities are denied.

---

## 5. Secrets Leakage

Common leakage paths:
- copied `.env`, `.npmrc`, `.pypirc`, Maven/Gradle settings, cloud credentials, kubeconfigs, SSH keys, certificates, or package tokens;
- secrets passed through build args or environment variables and preserved in image metadata or layer history;
- private repository URLs with embedded credentials;
- test fixtures, logs, crash dumps, debug bundles, and generated config;
- build cache exported to shared runners or registries.

Release-ready controls:
- Use BuildKit secret mounts or equivalent ephemeral secret mechanisms for build-time access.
- Do not copy developer home directories, whole repositories, or broad glob patterns into images without `.dockerignore` review.
- Rotate credentials immediately if a secret is found in an image, even if a later layer deletes the file. Deleted files may remain recoverable from earlier layers.
- Keep scanning evidence for the final image digest and for base/shared images consumed by many services.

Verification:
- Inspect image history, layer contents, config environment, labels, and build logs.
- Run secrets scanning against the built image and repository history.
- Confirm remediation includes credential rotation, registry cleanup where possible, and updated build controls.

---

## 6. Tags, Digests, and Multi-Arch Images

Release-ready defaults:
- Deploy to live environments by digest: `registry.example.com/team/app@sha256:...`.
- Use immutable release tags only as convenience references. Tag overwrite for release channels must be blocked or treated as a release incident.
- Preserve the approved digest in manifests, Helm values, Kustomize overlays, GitOps state, and deployment evidence.
- Resolve tag-to-digest before approval, not during live deployment.
- For multi-arch images, verify the index and the platform-specific manifests allowed for the target cluster.

Review guidance:
- A logical image reference such as `app:1.2.3` can resolve to different platform manifests on different nodes.
- If the cluster includes mixed architectures, admission policy must account for every allowed platform.
- If only a platform manifest is approved, deployment should not use an unapproved index that could select a different platform object.

Verification:
- Evidence includes image reference, index digest if present, platform manifest digest, OS/architecture, signature status, SBOM/provenance subject, and deploy gate result.

---

## 7. Registry Promotion and Retention

Release-ready defaults:
- Promote the same artifact from development to staging to live environments by digest. Do not rebuild between approval and live deployment.
- If copying between registries is required, record source digest, destination digest, media type, platform set, copy tool, actor, and timestamp.
- Separate write permissions from read/deploy permissions. CI that builds images should not automatically have broad delete or tag-mutation rights in release repositories.
- Use repository-level or environment-level boundaries for high-value images, base images, and signing/provenance artifacts.
- Retention and garbage collection must preserve images and linked artifacts required for rollback, incident response, vulnerability investigation, customer evidence, and audit.

Registry access controls:
- restrict push/delete/tag mutation to trusted release automation and a small operations group;
- require MFA or strong identity controls for human registry admins;
- log push, delete, tag mutation, permission changes, anomalous pull spikes, and failed authentication;
- protect referrers such as signatures, SBOMs, and provenance from deletion before the corresponding image evidence retention expires.

Verification:
- A rollback drill can pull the approved digest and its linked SBOM/provenance/signature after retention policy runs.
- A tag overwrite attempt is blocked or produces an alert.

---

## 8. Scanning, Signing, SBOM, and Provenance

Baseline for live environments:
- Scan the final image digest for OS packages, language packages, and known vulnerable components.
- Generate an SBOM for release images and shared base images.
- Sign release images and verify signatures before deployment. The verification policy must pin the expected signer identity, not only check that "some valid signature exists".
- Generate provenance for release builds and bind it to the artifact digest. The verification policy must check `subject` digest, trusted builder identity, expected source repository/ref, `buildType`, and approved build parameters.
- Run deploy-time verification through admission, release orchestration, or an equivalent gate; do not rely only on CI success.

Minimum trust policy:
- For keyless signing, pin OIDC issuer and certificate identity/SAN to the release workflow identity. Use exact matches or tightly scoped patterns for one repository/workflow/ref class.
- For key-based signing, pin the public key or KMS/HSM key identity, owner, rotation process, and emergency revocation path.
- For SLSA provenance, pin trusted `builder.id`, expected `predicateType`, expected source identity, and the `externalParameters` schema allowed for the build type.
- Do not mix SLSA predicate versions in one policy. `predicateType`, `builder.id`, `buildType`, source/material fields, and parameter schema must match a real attestation sample from the specific builder; v0.2 and v1 need separate checks or an explicit migration mapping.
- For SBOMs and attestations, verify the attestation signature and that the attestation subject matches the exact image digest being deployed, including index and platform manifest policy for multi-arch images.
- For OCI referrers or sidecar artifacts, retention must preserve the image, signature, SBOM, and provenance together. Deleting a referrer before evidence expiry is a release-evidence failure.
- Deploy gates must fail closed for high-value and internet-facing live services when required signature/provenance/SBOM evidence is missing, unverifiable, or bound to a different digest. Temporary fail-open behavior requires explicit break-glass approval, expiry, alerting, and post-release review.

Example policy fields:
```yaml
image: registry.example.com/team/app@sha256:...
allowed_signers:
  - oidc_issuer: https://token.actions.githubusercontent.com
    certificate_identity: repo:ORG/REPO:ref:refs/tags/v*
trusted_builders:
  - builder_id: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v*
    build_type: https://github.com/slsa-framework/slsa-github-generator/container@v1
expected_source:
  repository: github.com/ORG/REPO
  ref_pattern: refs/tags/v*
required_attestations:
  - type: slsa-provenance
    predicate_type: https://slsa.dev/provenance/v1
  - type: sbom
    format: spdx-json
multi_arch_policy: verify-index-and-platform-manifests
admission_failure_mode: fail-closed
```

Vulnerability policy:
- Critical/high vulnerabilities with plausible reachability or exposed attack surface should block deployment to live environments unless an exception has owner, justification, expiry, compensating controls, and verification evidence.
- Unfixed vulnerabilities are not automatically acceptable. Review exploitability, package reachability, runtime exposure, mitigations, and vendor status.
- Base image vulnerabilities need an owner. Shared base images should have a faster rebuild path because many services inherit their risk.

Verification:
- Evidence includes scanner version/config, vulnerability result, ignored findings with justification, signature identity, provenance predicate, builder identity, SBOM location, and deploy gate decision.
- Signature verification evidence includes the verified image digest, certificate identity or key identity, OIDC issuer where applicable, transparency log or bundle verification status where used, and the policy rule that matched.
- Provenance/SBOM evidence includes attestation digest/location, subject digest, predicate type, builder identity, source repository/ref, build parameters decision, and whether the deployed object was an index digest, a platform manifest digest, or both.
- Admission evidence includes the policy version, namespace/environment scope, failure mode, result for tag-only images, result for unsigned images, and result for signed-but-wrong-identity images.

---

## 9. Review Decision Matrix

The matrix below defines domain severity and the release decision. The [Vulnerability Management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/) owns generic remediation SLAs, the exception lifecycle, risk acceptance, and closure evidence; where requirements overlap, apply the stricter one.

| Severity | Use when | Required action |
|---|---|---|
| Critical | Secret in image, unsigned release image where signing is required, mutable unverified tag in live environments, image requires privileged/root-only execution without approved exception, or deploy digest cannot be tied to approved evidence | Block release until fixed; exception requires authorized risk acceptance if policy allows it |
| High | Critical/high reachable vulnerability, stale unsupported base image, broad registry write/delete/tag rights, missing deploy-time verification for high-value service, or multi-arch image with unverified target platform | Owner, due date, remediation or accepted risk, and verification evidence |
| Medium | Missing SBOM for non-critical service, weak retention, inconsistent labels, incomplete platform metadata, or scanner coverage gap with bounded impact | Track remediation and verify closure |
| Low | Documentation, metadata, cleanup, or hardening improvement with limited direct impact | Fix opportunistically |

Required review output:
- image reference, digest, registry, platform, and release context;
- finding summary and impact;
- required remediation or compensating control;
- verification method;
- owner, due date, and residual risk decision.

---

## 10. Related Materials

- [SLSA provenance overview](/Product-security-playbook/en/supply-chain/slsa-provenance/overview/)
- [Infrastructure technologies reference](/Product-security-playbook/en/reference/infrastructure-technologies/infrastructure-technologies/)
- [Vulnerability management playbook](/Product-security-playbook/en/review/vulnerability-management/playbook/)
- [Kubernetes Pod Security playbook](/Product-security-playbook/en/platform-security/kubernetes/pod-security/playbook/)
- [Container escape and capability abuse overview](/Product-security-playbook/en/platform-security/kubernetes/container-escape-capability-abuse/overview/)
