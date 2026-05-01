# Kubernetes Adversarial Validation

## 1. Scope and Objective

This playbook describes how to translate Kubernetes attack paths into safe production validation. The focus is a verifiable cycle:
- confirm the access path and trust boundary;
- enumerate reachable surface;
- prove one controlled abuse path;
- explain the root cause;
- apply the control and repeat the same test.

**Objective:**
- verify that Kubernetes controls close real attack paths, not only look correct in YAML;
- produce evidence for security review, remediation, and re-test;
- connect offensive lab scenarios to production guardrails: RBAC, admission, NetworkPolicy, runtime hardening, supply chain, and observability.

---

## 2. Review Method

### 2.1 Minimum validation loop

Each scenario should follow the same cycle:
- **Verify:** confirm the target workload, service, identity, or policy exists.
- **Enumerate:** collect low-noise context: pods, services, routes, mounts, env, ServiceAccount, RBAC, image metadata.
- **Prove:** perform the smallest action that proves the risk without expanding impact.
- **Explain:** record the root cause in terms of the broken trust boundary.
- **Fix and re-test:** apply the control and repeat the same test case to prove closure.

A successful validation outcome is not "something looks suspicious", but a concrete proof artifact: reachable `NodePort`, excessive ServiceAccount permission, internal service reachable through SSRF, runtime socket mount, Secret read through the API, runtime detection alert, or admission-policy denial.

### 2.2 Safety constraints

For production and shared staging:
- run destructive, DoS, or runtime escape checks only in an isolated namespace or clone environment;
- define scope in advance: namespaces, workloads, identities, IP ranges, time window;
- do not read real secret values without separate approval; proving `get/list/watch` or token exposure is usually enough;
- do not run mass scanning across pod CIDRs without rate/concurrency limits;
- prove remediation with the same minimal test case, not a stronger technique.

Evidence commands are classified as:
- `safe in prod`: read-only metadata or policy checks that do not reveal secret values;
- `staging only`: commands that inspect artifacts or run active probes and should use a clone, canary, or isolated namespace;
- `requires approval`: commands that may expose sensitive data, scan infrastructure, or touch real workloads.

---

## 3. Scenario-to-Control Matrix

### 3.1 Exposed source and secrets

**What to verify:**
- the web application does not expose `.git`, `.svn`, backup files, build metadata, or local env files;
- container image layers do not contain deleted secrets, `.env`, cloud credentials, or internal config;
- Git and registry scanning run before merge/release;
- previously exposed secrets are rotated, not only removed from the current branch.

**Production recommendation:**
- block VCS/build service paths at the web tier and in artifact packaging;
- forbid plaintext/base64 secrets in Git and image layers;
- enable pre-merge and pre-release secret scanning;
- any secret that reached Git or an image layer is treated as compromised and rotated.

**Evidence:**
Classification: `safe in prod` for header checks and scan status review; `staging only` for image export or layer inspection; `requires approval` before exporting production images.

```bash
curl -I https://<app>/.git/config
docker history --no-trunc <image>
# Staging/approved only: may export sensitive layers for offline scanning.
docker save <image> -o image.tar
trufflehog git file://<repo>
```

### 3.2 Runtime socket and host access

**What to verify:**
- workloads do not mount `docker.sock`, `containerd.sock`, CRI sockets, host `/proc`, `/sys`, or broad `hostPath`;
- build/CI workloads are not given the host runtime control plane for convenience;
- `privileged: true`, `hostPID`, `hostNetwork`, `hostIPC`, and dangerous capabilities have owner, justification, and expiry.

**Production recommendation:**
- deny runtime socket mounts through admission policy;
- use rootless/isolated builders or dedicated build nodes instead of host socket sharing;
- for exceptions, require a separate namespace, tight RBAC, NetworkPolicy, runtime detection, and review period no longer than `30d`.

**Evidence:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{.spec.volumes}{"\n"}{end}' | grep -E 'docker.sock|containerd.sock|hostPath'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" privileged="}{.spec.containers[*].securityContext.privileged}{" hostPID="}{.spec.hostPID}{" hostNetwork="}{.spec.hostNetwork}{"\n"}{end}'
```

### 3.3 SSRF and internal service discovery

**What to verify:**
- server-side URL fetchers cannot reach arbitrary internal URLs;
- sensitive internal services require authentication instead of trusting "inside the cluster";
- cloud metadata endpoints are protected with provider-specific controls;
- egress from frontend/workload namespaces is restricted to an explicit allowlist.

**Production recommendation:**
- URL fetchers use allowlists for schemes, domains, and ports;
- deny access to metadata IP ranges and cluster-internal sensitive services for workloads that do not need it;
- never request cloud metadata credential paths during validation; prove protection through deny evidence, non-sensitive canaries, or provider-specific metadata controls;
- monitor unexpected HTTP requests from frontend pods to internal service DNS and metadata endpoints.

**Evidence:**
Classification: `safe in prod` for policy deny logs and non-sensitive canaries; `staging only` for active service reachability probes; `requires approval` before probing production metadata endpoints.

```bash
kubectl run -n <ns> --rm -it netcheck --image=curlimages/curl -- sh
curl -m 2 http://<sensitive-service>.<namespace>.svc.cluster.local
# Safe metadata validation: prefer deny logs or a non-sensitive canary.
curl -m 2 -I http://169.254.169.254/
# AWS IMDSv2 should reject tokenless metadata calls; do not request /latest/meta-data/iam/security-credentials/.
curl -m 2 -s -o /dev/null -w "%{http_code}\n" http://169.254.169.254/latest/meta-data/
# GCP/Azure: verify egress deny or provider-specific metadata protections without requesting token/credential paths.
kubectl logs -n <network-policy-or-runtime-security-ns> <policy-or-sensor-pod>
```

### 3.4 NodePort and service exposure

**What to verify:**
- every `NodePort`, `LoadBalancer`, `Ingress`, and `Gateway` has an owner, purpose, and expected audience;
- node security groups/firewalls do not expose the NodePort range externally without need;
- internet exposure is verified with actual connectivity, not only Service YAML review.

**Production recommendation:**
- use `ClusterIP` or internal load balancers for internal services;
- alert on new `NodePort` services in production namespaces;
- public entry point inventory is updated at least every `30d`.

**Evidence:**
Classification: `safe in prod` for service inventory; `requires approval` for external connectivity scans against node IPs.

```bash
kubectl get svc -A -o wide
kubectl get svc -A --field-selector spec.type=NodePort
# Requires an approved scope, isolated window, target list, rate limits, and owner approval.
nmap -Pn -p 30000-32767 <node-external-ip>
```

### 3.5 Namespace bypass and network boundaries

**What to verify:**
- namespaces are not treated as a network boundary without NetworkPolicy or equivalent CNI enforcement;
- sensitive namespaces have default-deny ingress and egress;
- allowed east-west flows are documented and tested from a low-trust pod.

**Production recommendation:**
- enable default deny for production and high-value namespaces;
- explicitly allow only required service-to-service paths;
- re-test NetworkPolicy after CNI changes, namespace label changes, and service selector changes.

**Evidence:**
```bash
kubectl get networkpolicy -A
kubectl run -n <low-trust-ns> --rm -it netcheck --image=curlimages/curl -- sh
curl -m 2 http://<target-service>.<target-ns>.svc.cluster.local
```

### 3.6 ServiceAccount and RBAC abuse

**What to verify:**
- the workload identity cannot read Secrets, modify workloads, create pods, run `exec`, add ephemeral containers, or change RBAC without need;
- `automountServiceAccountToken` is disabled for workloads that do not require Kubernetes API access;
- the default ServiceAccount is not used by application workloads.

**Production recommendation:**
- one ServiceAccount per workload, with permissions granted by function rather than namespace convenience;
- `get/list/watch secrets`, `pods/exec`, `pods/ephemeralcontainers`, `escalate`, `bind`, `impersonate`, and `serviceaccounts/token` require separate approval;
- quarterly recertification for production ServiceAccount permissions.

**Evidence:**
```bash
kubectl auth can-i list secrets --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i create pods/exec --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl get rolebindings,clusterrolebindings -A
```

### 3.7 Resource exhaustion

**What to verify:**
- every production container has `resources.requests` and `resources.limits`;
- namespaces have `ResourceQuota` and, where needed, `LimitRange`;
- alerting covers CPU/memory spikes, OOMKilled, throttling, and restart loops.

**Production recommendation:**
- deny BestEffort pods in production namespaces;
- define namespace-level quotas for shared clusters;
- run DoS checks only in isolated load/staging environments.

**Evidence:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{.spec.containers[*].resources}{"\n"}{end}'
kubectl get resourcequota,limitrange -A
kubectl top pods -A
```

### 3.8 Image registry and supply chain

**What to verify:**
- the private registry requires authentication, authorization, and network restriction;
- the registry API does not expose catalog/manifests broadly;
- production deploy uses image digest and passes provenance/signature policy;
- image history does not contain suspicious fetch-and-execute patterns;
- batch/utility jobs do not run images from unapproved registries without an owner and provenance.

**Production recommendation:**
- registry endpoints must not be reachable from general-purpose networks;
- registry audit logging is mandatory for production artifacts;
- the deploy gate verifies digest, trusted builder identity, provenance/signature, and policy outcome;
- block images that download and execute remote content during build/startup without separate review.

**Evidence:**
```bash
curl -I https://<registry>/v2/
curl https://<registry>/v2/_catalog
cosign verify <image>@sha256:<digest>
docker history --no-trunc <image>
kubectl get jobs -A -o wide
```

### 3.9 Debug surfaces: exec and ephemeral containers

**What to verify:**
- who can use `pods/exec`, `pods/attach`, `pods/portforward`, `pods/ephemeralcontainers`;
- debug containers do not bypass Pod Security/RBAC expectations;
- node-level `kubectl debug node/...` is allowed only for break-glass roles.

**Production recommendation:**
- `exec` in sensitive namespaces should be restricted and audit-able;
- allow ephemeral containers only to support/SRE roles with short duration and separate logging;
- use admission policy to deny debug surfaces in high-value namespaces where operationally acceptable.

**Evidence:**
```bash
kubectl auth can-i create pods/exec --as=<subject> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=<subject> -n <ns>
kubectl get events -A --field-selector reason=Started
```

### 3.10 Detection and policy validation

**What to verify:**
- audit logs cover RBAC changes, Secret reads, `exec`, ephemeral containers, admission denials, and namespace label drift;
- runtime telemetry sees sensitive path reads, shell spawns, suspicious network tooling, `nsenter`, and host path access;
- admission policy blocks known unsafe patterns before deploy.

**Production recommendation:**
- use offensive lab behaviors as detection test cases, but adapt them to a safe staging environment;
- Falco/Tetragon or equivalent runtime sensors should have a tuned signal-to-noise baseline;
- Kyverno/Gatekeeper/ValidatingAdmissionPolicy policies should have owners, test cases, and exception lifecycle.

**Evidence:**
```bash
kubectl get validatingadmissionpolicies,validatingadmissionpolicybindings
kubectl get clusterpolicies -A
kubectl logs -n <runtime-security-ns> -l app.kubernetes.io/name=<sensor>
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout
kubectl --namespace <sensitive-ns> exec -it <pod> -- sh
```

### 3.11 Runtime and environment discovery

**What to verify:**
- the workload does not expose high-value secrets through environment variables, debug endpoints, shell access, or verbose error output;
- the container does not have unexpected mounts, writable sensitive paths, broad `/proc` visibility, or a service account token where Kubernetes API access is not needed;
- general-purpose helper images and security toolboxes do not appear in production namespaces without a change record and owner.

**Production recommendation:**
- do not put long-lived secrets in env vars for application workloads; use a secret manager, workload identity, or short-lived mounted credentials;
- disable `automountServiceAccountToken` and debug shells where they are not required by the runtime function;
- alert on multi-tool images, unexpected shells, package managers, and network scanners in production namespaces.

**Evidence:**
Classification: `safe in prod` for Kubernetes API metadata inventory; `staging only` for shell-based inspection; `requires approval` before executing commands in production pods.

```bash
# Do not print environment variable values. Check only names/classes through an approved debug path.
kubectl exec -n <ns> <pod> -- sh -c 'env | cut -d= -f1 | grep -Ei "TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AWS_|GOOGLE_|AZURE_"'
# Staging/approved only: shell-based runtime inspection touches the workload.
kubectl exec -n <ns> <pod> -- mount
kubectl exec -n <ns> <pod> -- cat /proc/self/cgroup
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" sa="}{.spec.serviceAccountName}{" automount="}{.spec.automountServiceAccountToken}{" image="}{.spec.containers[*].image}{"\n"}{end}'
```

### 3.12 Benchmark and posture review

**What to verify:**
- Docker/container runtime, kubelet, API server, RBAC, audit, and node hardening are checked with benchmark tooling, not only manual YAML review;
- the kube-bench/CIS profile matches the actual Kubernetes version and provider flavor; managed-service constraints are recorded as exceptions or not applicable;
- kubeaudit/Popeye or equivalent scanners find privileged pods, missing limits, weak security context, stale references, and hygiene debt;
- benchmark findings are translated into a remediation backlog with owner, severity, and re-test evidence.

**Production recommendation:**
- run posture scans regularly and after platform upgrades;
- separate exploitable misconfigurations from hygiene findings so remediation does not turn into noise;
- do not treat clean scanner output as sufficient security assurance: confirm critical controls with targeted validation tests from this playbook.

**Evidence:**
```bash
kubectl logs -n <audit-ns> job/<kube-bench-job>
kubeaudit all
popeye
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" privileged="}{.spec.containers[*].securityContext.privileged}{" limits="}{.spec.containers[*].resources.limits}{"\n"}{end}'
```

### 3.13 Legacy management-plane services

**What to verify:**
- the cluster has no Helm v2 Tiller, old dashboard/admin services, abandoned operators, or package-management components with broad RBAC;
- management-plane services are not reachable from application namespaces and low-trust pods;
- service accounts for deployment tooling do not have cluster-admin by default and cannot read Secrets without need.

**Production recommendation:**
- Helm v2/Tiller should be retired; for Helm v3, store release state and deploy credentials with least privilege;
- any in-cluster admin service requires an explicit owner, network isolation, authentication, audit logging, and expiry for the exception;
- check for legacy components after migrations, incident cleanup, and cluster upgrades.

**Evidence:**
```bash
kubectl get svc,deploy,sa,rolebinding,clusterrolebinding -A | grep -Ei 'tiller|dashboard|admin|operator'
kubectl auth can-i '*' '*' --as=system:serviceaccount:<ns>:<deploy-sa>
kubectl get clusterrolebinding -A -o wide
```

---

## 4. Review Outputs

Adversarial validation is complete only when it provides:
- scenario-to-control matrix for tested attack paths;
- evidence for every proof target before and after remediation;
- residual risk and exception list with owners/expiry;
- mapping between findings and dedicated playbooks: Cluster Review, Pod Security, Container Escape, Seccomp, SLSA, Vault;
- re-test log showing that the remediation closed the original abuse path.

---

## 5. Related Repository Materials

- Kubernetes cluster security review: [kubernetes/cluster-security-review/playbook.en.md](../cluster-security-review/playbook.en.md)
- Pod runtime hardening: [kubernetes/pod-security/playbook.en.md](../pod-security/playbook.en.md)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.en.md](../container-escape-capability-abuse/overview.en.md)
- Seccomp review checklist: [kubernetes/seccomp/checklist.en.md](../seccomp/checklist.en.md)
- SLSA provenance for container images: [supply-chain/slsa-provenance/overview.en.md](../../supply-chain/slsa-provenance/overview.en.md)
- Vault and secrets: [secrets/vault/playbook.en.md](../../secrets/vault/playbook.en.md)
