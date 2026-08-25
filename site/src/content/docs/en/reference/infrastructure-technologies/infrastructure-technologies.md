---
title: "Infrastructure Technologies Reference"
description: "This document explains how key technologies commonly seen in live infrastructure and security reviews work. It does not replace playbooks: the focus here is purpose, operating m..."
sidebar:
  order: 10
---
This document explains how key technologies commonly seen in live infrastructure and security reviews work. It does not replace playbooks: the focus here is purpose, operating model, responsibility boundaries, and common live patterns.

Sections are grouped by the role a technology plays in a live system: build and supply chain, container platform, identity/secrets, automation, data stores, and messaging.

## Table of Contents

- [Build, Delivery, and Supply Chain](#build-delivery-and-supply-chain)
  - [CI/CD Platforms](#cicd-platforms)
  - [Docker](#docker)
  - [OCI Registry / Artifact Registry](#oci-registry--artifact-registry)
  - [Helm](#helm)
- [Container Platform and Kubernetes Runtime](#container-platform-and-kubernetes-runtime)
  - [Container Runtimes](#container-runtimes)
  - [Kubernetes](#kubernetes)
  - [CNI / Kubernetes Networking](#cni--kubernetes-networking)
  - [Ingress / Gateway / API Gateway](#ingress--gateway--api-gateway)
  - [Istio](#istio)
  - [Policy Engines](#policy-engines)
- [Identity, Secrets, and Access](#identity-secrets-and-access)
  - [Cloud IAM / Workload Identity](#cloud-iam--workload-identity)
  - [Vault](#vault)
- [Automation and Configuration Management](#automation-and-configuration-management)
  - [Ansible](#ansible)
  - [Terraform / OpenTofu](#terraform--opentofu)
- [Data Stores, Search, and Messaging](#data-stores-search-and-messaging)
  - [Object Storage](#object-storage)
  - [PostgreSQL / Relational Databases](#postgresql--relational-databases)
  - [Redis](#redis)
  - [Vector Database / Vector DB](#vector-database--vector-db)
  - [Elasticsearch / OpenSearch](#elasticsearch--opensearch)
  - [Kafka](#kafka)
  - [RabbitMQ](#rabbitmq)
- [Related Materials](#related-materials)

## Build, Delivery, and Supply Chain

### CI/CD Platforms

#### What It Is Used For
CI/CD platforms are used to build, test, package, publish, and deploy software artifacts. Common examples include GitHub Actions, GitLab CI, Jenkins, Buildkite, and TeamCity. In live environments this is a central part of the software supply chain: the pipeline gets access to source code, secrets, package registries, cloud accounts, artifact registries, and deployment environments.

#### Operating Model
A pipeline or workflow describes a sequence of jobs. A job runs on a runner/agent and usually consists of steps: source checkout, dependency installation, tests, security scans, build, artifact upload, image push, and deployment. A runner can be hosted, where the CI/CD vendor provides the execution infrastructure, or self-hosted, where the team runs agents in its own network, cloud account, or Kubernetes cluster.

Artifacts are used to pass build outputs between jobs and later stages. Cache speeds up repeated builds by storing dependencies or intermediate outputs. An environment defines a deployment target such as `staging` or `prod`, and can have protection rules: required reviewers, wait timers, branch/tag restrictions, and environment-scoped secrets. A secret store holds tokens, passwords, certificates, and signing keys available to the pipeline during job execution.

A modern live pattern is to use OIDC federation instead of long-lived static secrets. The CI/CD platform issues a short-lived OIDC token for a specific job/workflow with claims about the repository, branch/tag, pipeline, environment, and actor. A cloud provider or Vault verifies the issuer, audience, subject, and additional claims, then issues temporary credentials with a limited policy.

The deploy pipeline should not be the only trust point. The pipeline builds and publishes an artifact, while a deploy/admission gate separately verifies the digest, signature, provenance, policy result, environment approval, and release eligibility. The boundary usually sits where the pipeline hands an immutable artifact and deployment intent to Kubernetes, a GitOps controller, a release orchestrator, or a cloud deploy service.

Untrusted workflow input is a separate boundary. Pull request titles and bodies, issue comments, branch names, tag names, release notes, commit messages, and forked code must be treated as attacker-controlled when they reach shell scripts, deployment commands, release notes, AI-assisted workflow steps, or policy inputs.

#### Interaction Diagram
```mermaid
flowchart LR
  Repo["Source repository"] --> Pipeline["Workflow / pipeline"]
  Pipeline --> Job["Job"]
  Job --> Runner["Runner / agent"]
  Runner --> Cache["Cache"]
  Runner --> Artifacts["Artifacts"]
  Runner --> OIDC["OIDC token"]
  OIDC --> Cloud["Cloud IAM / Vault"]
  Cloud --> TempCreds["Short-lived credentials"]
  TempCreds --> Publish["Publish image / artifact"]
  Publish --> Registry["Artifact registry"]
  Pipeline --> Env["Protected environment"]
  Env --> Approval["Approval / protection rules"]
  Approval --> DeployGate["Deploy or admission gate"]
  Registry --> DeployGate
  DeployGate --> Runtime["Kubernetes / cloud runtime"]
```

#### Responsibility Boundaries
A CI/CD platform runs automation and provides primitives for secrets, runners, artifacts, approvals, and identity federation, but it does not make a pipeline secure automatically. The team owns minimal workflow permissions, trusted actions/plugins, self-hosted runner isolation, protected branches/tags/environments, secrets, cache poisoning controls, artifact integrity, and separation between build and deploy roles.

Hosted runners reduce operational burden and usually provide a clean ephemeral environment. Self-hosted runners are needed for private networks, specialized hardware, or compliance, but require hardening, cleanup, egress control, patching, and protection against persistence between jobs.

#### Common Live Patterns
- Protected branches and tags for release refs.
- Environment approvals for live deployment.
- OIDC federation into a cloud provider or Vault instead of static deploy secrets.
- OIDC trust bound to issuer, audience, protected ref/environment, workflow identity, and repository identity; broad organization-wide trust is not a live-deploy default.
- Separate runners for trusted and untrusted workloads.
- Ephemeral self-hosted runners for pull request builds from untrusted code.
- No production secrets, signing material, or deploy credentials on runners that execute untrusted fork or branch code.
- Artifact upload by digest and publication of SBOM/provenance/signatures.
- Read-only source token by default; write permissions only for selected jobs.
- A deploy gate that does not trust pipeline success alone.

#### Related Project Files
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — trusted builders, provenance, and verification policy.
- `content/review/release-governance/playbook.ru.md` / `playbook.en.md` — protected environments, release evidence, and approvals.
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — short-lived secrets and credentials issued to pipelines.
- There is no dedicated CI/CD security playbook yet.

### Docker

#### What It Is Used For
Docker is used to build, package, and run applications in containers. In live environments it most often appears as an image build tool, a local development tool, a CI/CD pipeline component, and part of the container supply chain, even when Kubernetes runs containers through containerd or CRI-O rather than Docker Engine.

#### Operating Model
`Dockerfile` describes what an image is built from: the base image, package installation, copied files, environment variables, user, working directory, and startup command. During a build, Docker turns instructions into a set of layers. Each layer records a filesystem change, and the final image becomes a portable artifact that can be pushed to a registry and run in different environments.

At the OCI level, a runnable image is not a single opaque file. A platform-specific image manifest points to one image config object and an ordered set of filesystem layer descriptors. The config records runtime defaults such as entrypoint, command, environment, user, exposed ports, volumes, labels, and root filesystem metadata. Layers record filesystem changes; they do not carry the runtime configuration by themselves. An image index, also called a manifest list in Docker terminology, points to one or more platform-specific manifests.

A registry stores and serves images. Docker CLI is the client used by developers or CI jobs to send build, publish, and run commands. Docker daemon executes those commands on the host: it builds images, creates containers, attaches volumes and networks, assigns constraints, and delegates low-level execution to the runtime.

A container is a running process with an isolated view of the filesystem, processes, network, and resources. A volume is used for data that must survive container recreation. A network defines how a container communicates with other containers, the host, and external systems.

A typical flow looks like this: a developer or CI job builds an image from a `Dockerfile`, publishes it to a registry, then a runtime pulls the image and starts a container from an immutable set of layers with configured namespaces, cgroups, capabilities, mounts, and networking. When used with Kubernetes, Docker usually remains in the build/package stage, while node-level execution is handled by a container runtime.

The terms `tag`, `digest`, and image ID are easy to mix up in reviews. A tag is a mutable registry reference unless registry policy prevents mutation. A digest identifies registry content such as an index, manifest, config, or layer. The image ID is derived from the image config and is useful locally, but live deployment policy should bind to the registry digest that Kubernetes and the container runtime pull.

#### Interaction Diagram
```mermaid
flowchart LR
  Dev["Developer / CI"] --> Dockerfile["Dockerfile"]
  Dockerfile --> Build["docker build"]
  Build --> Layers["Image layers"]
  Layers --> Image["Container image"]
  Image --> Registry["Image registry"]

  Registry --> Pull["Pull image"]
  Pull --> Runtime["Container runtime"]
  Runtime --> Container["Running container"]

  subgraph Host["Container host"]
    Runtime --> Namespaces["Linux namespaces"]
    Runtime --> Cgroups["cgroups"]
    Runtime --> Caps["Capabilities"]
    Container --> Volumes["Volumes"]
    Container --> Networks["Container networks"]
  end

  Container --> App["Application process"]
```

#### Responsibility Boundaries
Docker helps package an application and define runtime parameters, but it does not make an image secure automatically. The team is responsible for minimizing the base image, keeping secrets out of layers, pinning versions, scanning dependencies, running without root, limiting capabilities, and publishing images correctly to a registry.

The application still owns its own authentication, authorization, input handling, and safe use of secrets.

#### Common Live Patterns
- Building images in CI.
- Storing images in a private registry.
- Multi-stage builds.
- Minimal base images.
- Image scanning before publication or deployment.
- Image signing and provenance for critical services.
- Digest-pinned live deployments; tags are used for discovery or channels, not as the release trust anchor.
- Running containers in Kubernetes through containerd or CRI-O rather than directly through Docker Engine.

#### Related Project Files
- `content/supply-chain/container-image-security/playbook.ru.md` / `playbook.en.md` — OCI image model, Dockerfile baseline, registry promotion, digest pinning, scanning, and signing.
- `content/platform-security/kubernetes/container-escape-capability-abuse/overview.ru.md` / `overview.en.md` — container escape risks through capabilities and dangerous container settings.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — secure workload settings that apply to containers in Kubernetes.
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — artifact origin, supply chain, and build trust.

### OCI Registry / Artifact Registry

#### What It Is Used For
An OCI registry stores and serves container images and related supply-chain artifacts: SBOMs, signatures, provenance attestations, scan results, Helm charts, and other OCI-compatible objects. In live environments, the registry is usually the central point between the build pipeline, the deployment platform, and runtime: CI publishes artifacts, the admission/deploy gate verifies them, and Kubernetes nodes pull digests to run workloads.

#### Operating Model
The OCI Distribution Specification defines the API for pushing and pulling content through a registry. The core objects are blobs, manifests, image indexes, digests, and tags. A blob stores an image layer or config. A manifest describes one image or artifact and references blobs by digest. An image index connects several platform-specific manifests, such as `linux/amd64` and `linux/arm64`. A digest is a content-addressed identifier for specific registry content; a tag is a human-readable reference to a manifest or index and may be mutable unless registry policy prevents it.

A repository inside a registry groups related artifacts, for example `prod/payments/api`. A client pushes blobs and a manifest, then may assign a tag. During pull, the client asks for a manifest or index by tag or digest, receives descriptors for the selected content, and downloads the referenced blobs. For a multi-platform image, the client may first receive an index and then select the platform-specific manifest for its OS and architecture. Kubernetes deployments to live environments should reference images by digest because a tag is not a reliable immutable reference without a separate tag immutability policy.

Registry promotion must preserve what was reviewed. Copying an image from one registry to another can change the repository reference and may produce a different top-level digest when the copied object, media type, or index shape changes. Review evidence therefore needs the source and destination references, the exact digest deployed, the platform manifest set, and the signature/provenance subject that was accepted by policy.

Modern artifact registries often store not only images, but also referrers: signatures, SBOMs, and provenance linked to a subject digest. For example, image `sha256:...` can have a cosign signature, SLSA provenance, and SBOM as separate OCI artifacts. A deploy gate or admission policy first extracts the image digest, then looks for linked attestations/referrers and verifies the signature, builder identity, provenance predicate, and policy outcome.

The registry also handles authorization, retention, replication, vulnerability scanning, pull-through cache, and audit logs. In a cloud registry this is often a managed service with IAM policies; in self-hosted deployments such as Harbor or distribution-based registries, the team owns storage, TLS, auth, replication, and cleanup.

#### Interaction Diagram
```mermaid
flowchart LR
  Source["Source repo"] --> CI["CI build pipeline"]
  CI --> Build["Build image"]
  Build --> Image["OCI image manifest"]
  Build --> SBOM["SBOM"]
  Build --> Prov["SLSA provenance"]
  Build --> Sig["Signature"]

  Image --> Push["Push by digest"]
  SBOM --> Push
  Prov --> Push
  Sig --> Push
  Push --> Registry["OCI / Artifact registry"]

  subgraph RegistryBox["Registry repository"]
    Registry --> Manifests["Manifests / image indexes"]
    Registry --> Blobs["Layer and config blobs"]
    Registry --> Tags["Tags"]
    Registry --> Referrers["Referrers: signatures, SBOM, attestations"]
    Registry --> Policy["AuthZ, retention, immutability, audit"]
  end

  DeployGate["Deploy / admission gate"] --> Registry
  DeployGate --> Verify["Verify digest, signature, provenance, policy"]
  Verify --> Kubernetes["Kubernetes deploy"]
  Kubernetes --> Node["Node kubelet / runtime"]
  Node --> Registry
  Registry --> Pull["Pull image blobs"]
  Pull --> Workload["Running workload"]
```

#### Responsibility Boundaries
A registry stores and serves artifacts through an API, but it does not automatically prove that an image is safe, signed by the right subject, or built from an approved source. The team owns authentication and authorization, immutable digest-based deployment, tag immutability for release tags, signatures, provenance, retention, vulnerability management, and audit trail.

The artifact registry should not be the only control point. Even if the registry blocks some unsafe images, the deploy gate should independently verify digest, signature, builder identity, provenance, and policy decision before a workload reaches a live environment.

#### Common Live Patterns
- Private registry with IAM/RBAC and separate repositories by environment or domain.
- Deployment only by digest (`image@sha256:...`); tags are used for discovery, not as the trust anchor.
- Tag immutability for release tags and no overwrites for live-environment tags.
- Image signing and SBOM/provenance publication as OCI artifacts/referrers.
- Admission/deploy gate that verifies signature, trusted builder identity, SLSA provenance, and vulnerability policy.
- Retention policy for old images while keeping artifacts required for rollback, incident response, and audit.
- Pull-through cache with a separate trust policy for upstream images.
- Audit logging for push/delete/tag mutation/anomalous pull patterns.

#### Related Project Files
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — provenance, verification policy, and trusted builders.
- `content/supply-chain/container-image-security/playbook.ru.md` / `playbook.en.md` — container image and OCI registry security baseline.
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — registry as part of the deployment chain and release gate.
- `content/platform-security/kubernetes/adversarial-validation/playbook.ru.md` / `playbook.en.md` — private registry exposure, image history, and supply-chain abuse path checks.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — runtime impact of running an untrusted image.

### Helm

#### What It Is Used For
Helm is used as a package manager for Kubernetes: manifest templating, release management, and application distribution through charts. In live environments it is often used to install platform components, ingress controllers, monitoring stacks, policy engines, and internal applications.

#### Operating Model
A chart is a package of Kubernetes manifests and templates for one application or platform component. A template contains Kubernetes YAML with Go templating. `values.yaml` and environment-specific values provide render parameters: image tag, replicas, resources, ingress, service account, RBAC, security context, and other settings.

A release is an installed instance of a chart in a specific namespace with a specific set of values. A repository stores charts and chart versions. A dependency allows a chart to include other charts, such as a database or sidecar component. A hook runs Kubernetes resources at specific lifecycle points, such as before install, after upgrade, or before deletion.

Helm renders manifests from templates and values, then sends the resulting Kubernetes objects to the cluster API. Release state is stored in Kubernetes, and updates are performed with `helm upgrade`: Helm compares the new chart/values with the current release and applies changes.

When used with GitOps, Helm is often not run manually by an operator. A GitOps controller takes a chart and values from Git or a registry, renders them or delegates rendering to Helm, then synchronizes the resulting objects with Kubernetes.

#### Interaction Diagram
```mermaid
flowchart LR
  ChartRepo["Chart repository"] --> Chart["Helm chart"]
  ValuesRepo["Git values per environment"] --> Values["values.yaml"]
  Chart --> Render["helm template / helm upgrade"]
  Values --> Render
  Render --> Manifests["Rendered Kubernetes manifests"]

  subgraph Objects["Rendered objects"]
    Manifests --> Deploy["Deployment / StatefulSet / DaemonSet"]
    Manifests --> Service["Service / Ingress / Gateway"]
    Manifests --> RBAC["ServiceAccount / Role / Binding"]
    Manifests --> Config["ConfigMap / Secret"]
    Manifests --> Hooks["Helm hooks / Jobs"]
  end

  Render --> API["Kubernetes API Server"]
  API --> Release["Helm release state in cluster"]
  API --> Cluster["Kubernetes cluster"]

  GitOps["GitOps controller"] --> Chart
  GitOps --> Values
  GitOps --> API
```

#### Responsibility Boundaries
Helm does not determine whether the resulting configuration is secure. A chart can create privileged workloads, wildcard RBAC, unsafe ingress, or secrets with sensitive values.

The team is responsible for reviewing rendered manifests, controlling values, verifying chart provenance, pinning versions, limiting hooks, and checking the permissions that the chart creates in the cluster.

#### Common Live Patterns
- Internal chart repository.
- Pinning chart/app versions.
- Separate values per environment.
- Rendering manifests in CI with policy checks.
- A GitOps controller applies the chart instead of manual `helm install`.
- Signature/provenance checks for third-party charts.
- Minimizing post-install hooks and privileged jobs.

#### Related Project Files
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — Helm is often a source of RBAC, workload, and ingress configuration for review.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — review of final pod specs after chart rendering.
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — trust in artifacts, including charts and deployment packages.

## Container Platform and Kubernetes Runtime

### Container Runtimes

#### What It Is Used For
A container runtime starts containers on a node: it pulls images, prepares the filesystem, namespaces, and cgroups, and hands execution to a lower-level runtime. In Kubernetes, the runtime usually works through CRI and is part of every worker node.

#### Operating Model
CRI is the interface between kubelet and the runtime. Because of CRI, kubelet is not tied to a specific implementation and can work with containerd, CRI-O, or another compatible runtime. The runtime receives kubelet requests to create a pod sandbox, pull an image, start a container, stop a container, and report status.

The OCI image spec defines the image format, while the OCI runtime spec defines how to start a container from that image with the required namespaces, cgroups, mounts, capabilities, and entrypoint process. The image store keeps pulled images locally on the node. The snapshotter prepares filesystem layers so a container gets its working filesystem view without copying the whole image.

A pod sandbox represents the infrastructure shell of a pod: networking, namespaces, and base resources inside which application containers run. A shim process maintains the connection to a running container and lets the runtime avoid keeping the entire lifecycle inside one process.

A typical chain looks like this: kubelet receives a pod assignment, calls the CRI runtime, the runtime pulls the image from a registry, prepares snapshots/layers, creates a sandbox, and then invokes an OCI runtime such as `runc` or Kata Containers. The low-level runtime creates Linux isolation and starts the application process.

#### Interaction Diagram
```mermaid
flowchart LR
  Kubelet["kubelet"] --> CRI["CRI API"]
  CRI --> Runtime["containerd / CRI-O"]
  Runtime --> ImageStore["Image store"]
  Registry["Image registry"] --> ImageStore
  Runtime --> Snapshotter["Snapshotter"]
  Snapshotter --> FS["Container filesystem"]
  Runtime --> Sandbox["Pod sandbox"]
  Runtime --> Shim["Shim process"]
  Runtime --> OCI["OCI runtime"]
  OCI --> Kernel["Linux kernel"]

  subgraph KernelFeatures["Kernel isolation"]
    Kernel --> NS["Namespaces"]
    Kernel --> CG["cgroups"]
    Kernel --> Mounts["Mounts"]
    Kernel --> Caps["Capabilities"]
    Kernel --> Seccomp["seccomp / LSM"]
  end

  OCI --> Process["Application process"]
  Sandbox --> Process
  FS --> Process
```

#### Responsibility Boundaries
The runtime executes a container with the requested constraints, but it does not decide which permissions are safe. If a Kubernetes workload requests privileged mode, dangerous capabilities, `hostPath`, `hostPID`, or `hostNetwork`, the runtime will technically apply that configuration.

Policy, admission control, and baselines belong to the platform.

#### Common Live Patterns
- containerd as the runtime in managed Kubernetes.
- CRI-O in clusters oriented around a Kubernetes-native runtime stack.
- RuntimeClass for isolating selected workloads.
- gVisor or Kata Containers for workloads with stronger isolation requirements.
- Centralized runtime configuration in node images.
- Runtime event monitoring and node-level audit.

#### Related Project Files
- `content/platform-security/kubernetes/container-escape-capability-abuse/overview.ru.md` / `overview.en.md` — the connection between runtime isolation, capabilities, and escape scenarios.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — workload settings that the runtime applies on the node.
- `content/platform-security/kubernetes/seccomp/checklist.ru.md` / `checklist.en.md` — syscall filtering as part of runtime hardening.

### Kubernetes

#### What It Is Used For
Kubernetes is used to orchestrate containerized applications: scheduling, service discovery, rollouts, autoscaling, configuration, secrets, networking, and workload lifecycle management. In live environments it often acts as the base platform for microservices, batch jobs, internal platforms, and cloud-native infrastructure.

#### Operating Model
The API Server is the central management point: user commands, controller activity, kubelet communication, and external integrations go through it. It validates requests, applies authentication, authorization, and admission, then stores desired state in etcd. etcd stores cluster state: workload objects, services, secrets, bindings, configuration, and metadata.

The scheduler selects a node for a pod based on resources, constraints, affinity, taints/tolerations, and other placement rules. The controller-manager runs controllers that continuously compare desired state with actual state: for example, creating new pods for a Deployment, replacing failed pods, or synchronizing endpoints for a Service. Admission controllers run at the API boundary and can mutate or reject objects before they are persisted.

On each worker node, kubelet receives assigned pods through the API Server and asks the container runtime to start the required containers. The container runtime pulls images and creates containers. The CNI plugin configures pod networking, while kube-proxy or an eBPF/CNI replacement provides service networking.

A pod is the smallest executable Kubernetes unit: one or more containers with shared network identity and volumes. A Deployment manages stateless replicas and rollouts, a StatefulSet manages stateful workloads with stable identity, and a DaemonSet runs an agent on every suitable node. A Service provides a stable network access point to a dynamic set of pods, while Ingress or Gateway publishes HTTP/TCP entry into the cluster. ConfigMap stores non-secret configuration, Secret stores sensitive values, and ServiceAccount defines workload identity. RBAC connects roles/clusterroles to subjects through rolebindings/clusterrolebindings. NetworkPolicy describes allowed network flows between pods and external addresses.

In a normal flow, a user applies a manifest through the API Server, the object is stored in etcd, a controller creates or updates child objects, the scheduler assigns a pod to a node, kubelet starts containers through the runtime, and networking components make the workload reachable by other services.

#### Interaction Diagram
```mermaid
flowchart TB
  User["User / CI / GitOps"] --> API["API Server"]
  API --> Auth["AuthN / AuthZ / Admission"]
  Auth --> ETCD["etcd"]

  Controller["Controller Manager"] <--> API
  Scheduler["Scheduler"] <--> API
  Controller --> Desired["Desired state reconciliation"]
  Scheduler --> Placement["Pod placement decision"]

  API --> Kubelet["kubelet on worker node"]
  Kubelet --> Runtime["Container runtime"]
  Runtime --> Pod["Pod"]

  subgraph PodBox["Pod"]
    Pod --> C1["Container A"]
    Pod --> C2["Container B / sidecar"]
    Pod --> SA["ServiceAccount identity"]
    Pod --> Vol["Volumes"]
  end

  CNI["CNI plugin"] --> PodNet["Pod network"]
  KubeProxy["kube-proxy / eBPF datapath"] --> Service["Service"]
  Ingress["Ingress / Gateway"] --> Service
  Service --> PodNet

  ConfigMap["ConfigMap"] --> Pod
  Secret["Secret"] --> Pod
  RBAC["RBAC roles and bindings"] --> API
  NetworkPolicy["NetworkPolicy"] --> CNI
```

#### Responsibility Boundaries
Kubernetes provides APIs and workload management mechanisms, but it does not guarantee secure cluster or application configuration by itself. The platform team owns RBAC, isolation, admission policies, network policies, audit logs, node hardening, upgrade lifecycle, and integration with IAM, secrets, and registries.

Application teams own secure pod specs, health checks, resource limits, secrets, ingress configuration, and application behavior.

#### Common Live Patterns
- Managed Kubernetes: EKS, GKE, AKS, or an equivalent platform.
- GitOps through Argo CD or Flux.
- Namespace separation by environment, team, or blast radius.
- Separate node pools for trusted/untrusted, stateful, GPU, or privileged workloads.
- Ingress controller or Gateway API.
- External Secrets Operator or CSI driver for secrets.
- Policy engine: Kyverno or OPA Gatekeeper.
- Private control plane and restricted access to the Kubernetes API.

#### Related Project Files
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — comprehensive Kubernetes cluster security review.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — requirements for secure pod/workload configuration.
- `content/platform-security/kubernetes/seccomp/checklist.ru.md` / `checklist.en.md` — seccomp profile review.
- `content/platform-security/kubernetes/container-escape-capability-abuse/overview.ru.md` / `overview.en.md` — container escape and Linux capability misuse.

### CNI / Kubernetes Networking

#### What It Is Used For
CNI and Kubernetes networking provide pod connectivity, service discovery, Service load balancing, egress/ingress paths, and network policy enforcement. In live environments this is one of the main blast-radius control layers: the CNI decides whether a workload in one namespace can reach another workload, a metadata endpoint, a control-plane endpoint, or an external system.

Common implementations include Cilium, Calico, cloud-provider CNIs, Flannel, and other plugins. Cilium focuses on an eBPF datapath, observability, and kube-proxy replacement. Calico is widely used for Kubernetes NetworkPolicy and extended policy models, including GlobalNetworkPolicy in the Calico stack. Some managed clusters use cloud-native CNI where pod IPs integrate directly with the VPC/VNet.

#### Operating Model
Kubernetes defines the general network model: a pod gets an IP, pods can communicate with each other, a Service provides a stable virtual IP or DNS name for a set of endpoints, and NetworkPolicy describes allowed ingress/egress flows. The Kubernetes API stores objects, but it does not enforce NetworkPolicy on the datapath. Enforcement is performed by the CNI plugin or an associated policy engine.

The CNI plugin is called by kubelet/container runtime when a pod sandbox is created. It allocates an IP, connects the pod network interface, programs routes, rules, eBPF maps, or iptables/nftables, and then maintains state as pods, nodes, services, and policies change. DNS is usually provided by CoreDNS, while Service traffic is implemented by kube-proxy through iptables/IPVS or by the CNI datapath when kube-proxy replacement is used.

NetworkPolicy is a namespace-scoped Kubernetes resource. It selects pods through labels and defines which ingress and egress traffic is allowed. The important semantic detail: a pod without a matching policy is usually non-isolated for that direction. Once a pod is selected by an ingress or egress policy, only explicitly described flows are allowed for that direction. This means default deny requires a dedicated policy, not just the presence of a CNI.

Cilium can replace kube-proxy and implement Service load balancing through eBPF. In that model, Cilium agents program the eBPF datapath on nodes, use maps for service/backend lookup, collect flow visibility through Hubble, and enforce L3/L4/L7 policies. Calico can enforce Kubernetes NetworkPolicy and its own extended policies, including ordered rules, tiers, and host endpoints depending on edition/configuration. The practical review point: check not only policy YAML, but also the actual CNI, datapath mode, egress support, namespace selectors, DNS/FQDN policies, and observability.

#### Interaction Diagram
```mermaid
flowchart TB
  API["Kubernetes API"] --> Pods["Pods / Services / Endpoints"]
  API --> NP["NetworkPolicy objects"]
  API --> CNIController["CNI controller / agent"]

  Kubelet["kubelet"] --> Runtime["container runtime"]
  Runtime --> Sandbox["Pod sandbox"]
  Sandbox --> CNIPlugin["CNI plugin ADD/DEL"]
  CNIPlugin --> PodIF["Pod network interface + IP"]

  CNIController --> Datapath["Datapath: eBPF / iptables / routes"]
  NP --> CNIController
  Pods --> CNIController
  Datapath --> Policy["Policy enforcement"]
  Datapath --> ServiceLB["Service load balancing"]
  CoreDNS["CoreDNS"] --> ServiceDNS["Service DNS"]

  subgraph Node["Worker node"]
    PodA["Pod A"] --> PodIF
    PodIF --> Datapath
    Datapath --> PodB["Pod B"]
    Datapath --> Egress["External egress"]
  end

  ServiceLB --> PodB
  Policy --> FlowLogs["Flow logs / Hubble / Calico logs"]
```

#### Responsibility Boundaries
CNI provides the datapath and may enforce NetworkPolicy, but it does not know service business semantics. The platform owns CNI selection, policy enforcement enablement, default-deny baseline, egress strategy, observability, upgrade compatibility, and validation that policy is actually active.

Application teams own correct labels, required service-to-service flow definitions, avoiding implicit "namespace isolation" assumptions, and connectivity testing after changes.

#### Common Live Patterns
- Default-deny ingress and egress for live and high-value namespaces.
- Explicit allow rules for service-to-service flows, DNS, and required egress.
- Separate node pools or clusters for workloads with different trust levels.
- Cilium/Hubble or Calico flow logs for network event investigation.
- Kube-proxy replacement only after compatibility checks with cloud load balancers, service mesh, NodePort/LoadBalancer behavior, and observability.
- Egress gateway/NAT strategy for stable outbound traffic identity.
- NetworkPolicy re-test after changes to namespace labels, pod labels, CNI version, and service selectors.
- Separate controls for metadata endpoints and cloud control-plane endpoints.

#### Related Project Files
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — service boundary review, egress, and NetworkPolicy baseline.
- `content/platform-security/kubernetes/adversarial-validation/playbook.ru.md` / `playbook.en.md` — namespace bypass, SSRF, NodePort exposure, and actual reachability checks.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — pod-level controls complement, but do not replace, network isolation.
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — trust boundary and data flow analysis.

### Ingress / Gateway / API Gateway

#### What It Is Used For
Ingress, Gateway, and API Gateway publish services outside the cluster or between network zones. They accept client traffic, terminate TLS or pass TLS through, route requests to Kubernetes Services, apply authentication/authorization integrations, rate limits, WAF/API security policies, header normalization, and observability.

Common live-environment implementations include NGINX Ingress Controller, cloud load balancer controllers, Envoy Gateway, Kong Gateway/Kong Ingress Controller, HAProxy/Contour/Traefik, and service mesh gateway components. Kubernetes Ingress remains a stable API for HTTP/HTTPS routing, but its development is frozen; new Kubernetes networking capabilities are primarily developed in Gateway API. If the controller is implemented by Istio, this section describes the north-south entry point, while Istio mesh semantics (`VirtualService`, `DestinationRule`, `PeerAuthentication`, `AuthorizationPolicy`, sidecar/ambient) are covered separately in the Istio section.

#### Operating Model
An Ingress resource describes host/path routing to a backend Service. By itself, Ingress does not work without an Ingress Controller. The controller watches the Kubernetes API, selects Ingress objects by `ingressClassName`, generates proxy/load balancer configuration, and exposes an external endpoint through a `LoadBalancer` Service, NodePort, cloud load balancer, or edge appliance.

Gateway API separates roles more explicitly. `GatewayClass` describes the controller type. `Gateway` describes listeners, addresses, ports, TLS, and rules for which Routes may attach to it. `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `TLSRoute`, and other route resources describe application-level routing. `allowedRoutes` and the cross-namespace attachment model form a trust boundary between the platform team that owns the Gateway and application teams that own Routes. Do not confuse Kubernetes Gateway API `Gateway` with Istio `networking.istio.io/Gateway`: the names are similar, but ownership, deployment model, and route resources differ.

An API Gateway adds API-management functions: plugins/policies for auth, JWT/OIDC validation, API keys, rate limiting, request/response transformation, WAF, bot protection, schema validation, developer portals, or analytics. In Kubernetes this can be the same controller that reads Ingress/Gateway API resources and generates gateway data plane configuration.

Critical security review points: where TLS terminates, whether `X-Forwarded-*` is trusted, who can create routes for public hostnames, how wildcard hosts are protected, whether upstream mTLS exists, how authentication is enforced, how WAF/rate limiting works, who can change annotations/plugins, and whether they bypass the baseline.

#### Interaction Diagram
```mermaid
flowchart TB
  Client["External client"] --> DNS["DNS"]
  DNS --> LB["Cloud LB / edge load balancer"]
  LB --> GatewayDP["Ingress / Gateway data plane"]

  subgraph K8s["Kubernetes cluster"]
    API["Kubernetes API"] --> Ingress["Ingress"]
    API --> Gateway["Gateway"]
    API --> Route["HTTPRoute / Ingress rules"]
    API --> Secret["TLS Secret / certificate"]
    API --> Policy["Gateway plugins / auth / WAF policy"]

    Controller["Ingress/Gateway controller"] --> GatewayDP
    Ingress --> Controller
    Gateway --> Controller
    Route --> Controller
    Secret --> Controller
    Policy --> Controller

    GatewayDP --> TLS["TLS termination or passthrough"]
    TLS --> Auth["AuthN/AuthZ, WAF, rate limits, header policy"]
    Auth --> Service["Kubernetes Service"]
    Service --> Pod["Backend Pods"]
  end

  GatewayDP --> Logs["Access logs / metrics / traces"]
```

#### Responsibility Boundaries
The Ingress/Gateway layer controls the network entry point, but it does not replace application authorization. If the gateway only checks token presence, the application still needs to enforce business authorization and tenant boundaries. If TLS terminates at the gateway, decide explicitly whether mTLS or encryption is required to the upstream service.

The platform owns controller hardening, class ownership, public exposure, certificate lifecycle, baseline annotations/plugins, default security headers, logging, and guardrails for cross-namespace routes. Application teams own route ownership, backend readiness, correct host/path rules, and application compatibility with proxy headers/timeouts.

#### Common Live Patterns
- Gateway API for new deployments, Ingress for existing workloads where migration is not complete.
- Separate ingress/gateway classes for public, internal, and admin traffic.
- TLS termination at the gateway with managed certificate lifecycle; upstream mTLS for sensitive backends.
- Strict policy for `X-Forwarded-*`, `Forwarded`, `Host`, and client IP headers; applications trust only headers from approved proxies.
- WAF/API security and rate limiting on public routes.
- Wildcard hosts denied or separately approved.
- Cross-namespace route attachment only through explicit `allowedRoutes`/ReferenceGrant and ownership rules.
- Access logs with correlation ID, request outcome, upstream service, and policy decision.
- Controller service account protection: it can often read Secrets and change gateway/proxy configuration.

#### Related Project Files
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — entry point inventory, service exposure, and ownership.
- `content/platform-security/kubernetes/adversarial-validation/playbook.ru.md` / `playbook.en.md` — NodePort/Ingress/Gateway reachability and SSRF/internal exposure checks.
- `content/application-security/web/owasp-top-10/playbook.ru.md` / `playbook.en.md` — application-layer risks behind the gateway.
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — trust boundaries, external integrations, and architectural review evidence.

### Istio

#### What It Is Used For
Istio is used as a service mesh for service-to-service traffic management: mTLS, traffic routing, retries, telemetry, authorization policies, and progressive delivery. In live environments it most often appears in Kubernetes clusters with many internal services and strict service-to-service security requirements.

#### Operating Model
Istiod is the mesh control plane. It consumes Kubernetes/Istio configuration, generates and distributes data plane configuration, manages service discovery, and participates in certificate distribution for mTLS. The data plane is represented by an Envoy proxy next to the application in the sidecar model, or by ambient mesh components when ambient mode is used. In ambient mode, the base L4 secure overlay is provided by per-node `ztunnel`, while L7 features are added through waypoint proxies.

Envoy proxy intercepts inbound and outbound workload traffic, establishes mTLS, applies routing rules, retry/timeout policy, authorization policy, and collects telemetry. An ingress gateway accepts external traffic into the mesh, while an egress gateway centralizes controlled outbound traffic from the mesh to external systems.

Key CRDs define mesh behavior. In the Istio API, `VirtualService` describes routing and traffic shifting. `DestinationRule` defines subsets, load balancing, and connection policy for an upstream. `Gateway` controls ingress/egress points into the mesh. `PeerAuthentication` defines the mTLS mode, and `AuthorizationPolicy` defines which workload may call which other workload. Separately, Istio supports Kubernetes Gateway API; in that model, `Gateway`, `HTTPRoute`, and other route resources come from `gateway.networking.k8s.io`, not from the Istio API.

When combined with Kubernetes, the application remains a regular Deployment/Pod, but its traffic passes through the data plane. Istiod watches services and policies in the Kubernetes API, recalculates configuration, and sends it to proxies. Proxies on the traffic path then enforce mTLS, routing, policy, and telemetry without changing application business code.

#### Interaction Diagram
```mermaid
flowchart TB
  K8sAPI["Kubernetes API"] --> Istiod["Istiod control plane"]
  IstioCRD["Istio CRD: VirtualService, DestinationRule, Gateway, PeerAuthentication, AuthorizationPolicy"] --> Istiod
  Istiod --> ConfigA["Proxy config"]
  Istiod --> ConfigB["Proxy config"]
  Istiod --> Certs["Workload certificates"]

  subgraph Mesh["Service mesh data plane"]
    ServiceA["Service A app"] --> EnvoyA["Envoy sidecar / ambient proxy"]
    EnvoyA --> MTLS["mTLS + routing + policy"]
    MTLS --> EnvoyB["Envoy sidecar / ambient proxy"]
    EnvoyB --> ServiceB["Service B app"]
  end

  ConfigA --> EnvoyA
  ConfigB --> EnvoyB
  Certs --> EnvoyA
  Certs --> EnvoyB

  External["External client"] --> IngressGW["Ingress gateway"]
  IngressGW --> EnvoyA
  EnvoyB --> EgressGW["Egress gateway"]
  EgressGW --> ExternalAPI["External service"]

  EnvoyA --> Telemetry["Telemetry: metrics, logs, traces"]
  EnvoyB --> Telemetry
```

#### Responsibility Boundaries
Istio can provide mTLS between workloads and centralized mesh policy, but it does not fix weak application authentication and does not replace Kubernetes RBAC, NetworkPolicy, CNI datapath policy, or API security. NetworkPolicy is still needed for L3/L4 blast-radius control and for limiting traffic that should not rely only on mesh enrollment.

The platform owns correct mesh onboarding, certificate lifecycle, policy model, gateway exposure, and compatibility with applications.

#### Common Live Patterns
- Mesh enabled only for selected namespaces instead of the whole cluster at once.
- Strict mTLS for internal services.
- AuthorizationPolicy for service-to-service access.
- Separate ingress and egress gateways when north-south or outbound traffic must pass through controlled mesh edge points.
- Explicit decision on which API owns routing: Istio `VirtualService`/`Gateway`, Kubernetes Gateway API, or both during a transition.
- Canary/blue-green routing through VirtualService and DestinationRule.
- Telemetry integration with Prometheus, Grafana, or OpenTelemetry.
- Gradual migration from sidecar to ambient mesh where justified.

#### Related Project Files
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — applies to mesh as part of the Kubernetes control/data plane.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — sidecar/mesh workloads remain Kubernetes workloads and inherit pod security requirements.
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — useful for analyzing trust boundaries and service-to-service communication.
- There is no dedicated Istio playbook yet.

### Policy Engines

#### What It Is Used For
Policy engines are used for automated checking and enforcement of technical rules: Kubernetes admission policies, IaC checks, CI quality gates, image verification, configuration validation, and governance. Common tools include OPA, Gatekeeper, Kyverno, and Conftest.

#### Operating Model
OPA is a general-purpose policy engine: an application or tool passes structured input, policy code makes a decision, and the enforcement point applies the result. Conftest uses OPA/Rego to check structured files in CI or locally: Kubernetes manifests, Terraform plans, Helm outputs, and YAML/JSON configs.

In Kubernetes, a policy engine usually runs as a dynamic admission controller. After authentication and authorization, the API Server sends an AdmissionReview to a validating or mutating webhook. The policy engine checks the object, userInfo, namespace, labels, image references, and external context where supported, then allows, denies, or mutates the request before it is persisted in etcd.

Gatekeeper is built around constraint templates and constraints, and supports admission validation and audit of existing resources. Kyverno uses Kubernetes-native policy resources and supports validate, mutate, generate, cleanup/delete, and image verification patterns. During policy rollout, teams usually use audit/dry-run/warn modes before enforce; otherwise an untested rule can block deployment of critical workloads.

CI policy and runtime admission policy solve different problems. CI policy checks proposed configuration before merge/deploy and gives developers fast feedback. Runtime admission policy protects the cluster from CI bypass, manual changes, compromised deploy credentials, and drift, but must be highly available, observable, and carefully configured for failure policy.

#### Interaction Diagram
```mermaid
flowchart LR
  Developer["Developer / CI"] --> Config["Manifest / Terraform / Helm output"]
  Config --> CIPolicy["CI policy: Conftest / OPA / Kyverno CLI"]
  CIPolicy --> Merge["Merge / deploy intent"]
  Merge --> APIServer["Kubernetes API Server"]
  APIServer --> Admission["AdmissionReview"]
  Admission --> Engine["Gatekeeper / Kyverno"]
  Engine --> Decision["Allow / deny / mutate / audit"]
  Decision --> APIServer
  APIServer --> ETCD["etcd"]
  Engine --> Audit["Audit existing resources"]
```

#### Responsibility Boundaries
A policy engine makes decisions according to configured rules, but it does not define the right security policy by itself. The team owns rule ownership, tests, rollout mode, exceptions, failure behavior, versioning, observability, performance impact, and alignment between rules and real risk scenarios.

#### Common Live Patterns
- CI checks for pull requests and Terraform/Kubernetes changes.
- Admission enforcement for critical Kubernetes controls.
- Audit mode before enforce for new or risky policies.
- Explicit exception model with owner, reason, expiry, and review.
- Policy unit tests and fixtures for known-good/known-bad manifests.
- Separate policy bundles by environment or risk tier.
- Monitoring webhook latency, denial rates, audit violations, and policy engine availability.
- Image verification policies for digest, signature, and attestations on live workloads.

#### Related Project Files
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — admission control and cluster policy gates.
- `content/platform-security/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — workload controls that can be enforced through a policy engine.
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — image/provenance verification before deployment.
- There is no dedicated policy engines playbook yet.

## Identity, Secrets, and Access

### Cloud IAM / Workload Identity

#### What It Is Used For
Cloud IAM manages access to cloud resources: compute, storage, databases, queues, KMS, secrets, networking, and managed services. Workload identity binds a workload identity from a runtime, such as a Kubernetes ServiceAccount or CI job identity, to a cloud identity without storing long-lived access keys inside an application or pipeline.

#### Operating Model
IAM usually consists of principals and policies. A principal can be a user, group, service account, managed identity, role, or federated subject. A policy defines allowed actions on resources and conditions such as account, project, region, tag, resource name, or token claims. In AWS, the key objects are IAM users, groups, roles, policies, and STS. In Google Cloud, they are principals/service accounts, IAM roles, and allow policies. In Azure, they are Microsoft Entra identities, managed identities, app registrations, and Azure RBAC role assignments.

Short-lived credentials are issued through federation. A workload receives a signed token from a trusted issuer, such as the Kubernetes API server or CI/CD platform. Cloud IAM verifies the OIDC issuer, audience, subject, and conditions, then issues a temporary access token or role session. In Kubernetes this is implemented through cloud-specific integrations: AWS IAM Roles for Service Accounts, GCP Workload Identity Federation for GKE, and Microsoft Entra Workload ID for AKS.

The metadata service is a separate important boundary. On a cloud VM/node, the metadata endpoint can issue credentials for the instance/node identity. If a pod can reach the metadata service and the node role is too broad, workload compromise becomes lateral movement from Kubernetes into the cloud control plane. Workload identity reduces this risk, but only when node metadata access is restricted, service accounts are separated, trust policies are narrow, and cloud permissions are minimal.

Trust policies must bind to stable workload attributes, not only to a human-readable name. For Kubernetes, bind to issuer, audience, namespace, service account, and where the provider supports it, cluster/project/account identity. For CI/CD, bind to issuer, audience, repository or immutable repository ID where available, protected ref or environment, workflow identity, and expected trigger. A wildcard subject that lets any workload in a namespace, repository, or organization assume a live cloud role is a production finding.

Kubernetes RBAC and cloud IAM solve different problems. Kubernetes RBAC controls access to Kubernetes API objects. Cloud IAM controls cloud resources outside Kubernetes. A ServiceAccount with minimal Kubernetes RBAC can still have dangerously broad cloud permissions, and the reverse is also true.

#### Interaction Diagram
```mermaid
flowchart LR
  Pod["Pod / workload"] --> KSA["Kubernetes ServiceAccount"]
  KSA --> Token["Projected OIDC token"]
  Token --> Trust["Cloud trust policy"]
  Trust --> STS["STS / token exchange"]
  STS --> Creds["Short-lived cloud credentials"]
  Creds --> Resource["Cloud resource"]

  Pod --> Metadata["Node metadata service"]
  Metadata --> NodeRole["Node / VM identity"]
  NodeRole --> Resource
```

#### Responsibility Boundaries
The cloud provider owns IAM primitives, token exchange, and enforcement on cloud APIs. The platform team owns identity mapping, trust policies, node metadata restrictions, least privilege, audit logs, credential lifetime, break-glass access, and separation between environments. Application teams own the correct workload identity selection, absence of embedded keys, and correct token refresh handling.

#### Common Live Patterns
- Separate cloud identity per service or bounded workload group.
- Federation through OIDC instead of static cloud access keys.
- Trust policy bound to issuer, audience, namespace, service account, repository, branch/tag, or environment.
- Short credential lifetime for federated sessions; live deploy and runtime sessions should normally be measured in minutes to a few hours, not days.
- Deny wildcard assume-role or token-exchange subjects for production identities.
- Workload access to the node metadata service blocked unless required.
- Narrow permissions on data-plane actions, without wildcard admin policies.
- Separate identities for build, deploy, and runtime.
- Auditing for AssumeRole/token exchange, key creation, policy changes, and anomalous API calls.

#### Related Project Files
- `content/application-security/identity/oidc-oauth/playbook.ru.md` / `playbook.en.md` — OIDC concepts, token validation, and trust boundaries.
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — Kubernetes-to-cloud attack paths and cluster identity.
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — dynamic credentials and secrets delivery.
- There is no dedicated Cloud IAM / workload identity playbook yet.

### Vault

#### What It Is Used For
HashiCorp Vault is used for centralized secret management, dynamic credentials, encryption-as-a-service, and access to sensitive material. In live environments it often sits between applications, CI/CD, Kubernetes, and external systems such as databases, cloud IAM, PKI, SSH, and message brokers.

#### Operating Model
Vault server receives API requests, performs authentication, checks policy, calls secret engines, and writes audit events. The storage backend stores encrypted Vault state: configuration, metadata, policies, and secret engine data. Seal/unseal protects master key material: while Vault is sealed, it cannot decrypt storage or serve normal requests.

Auth methods connect an external identity to a Vault identity: Kubernetes service account, OIDC subject, AppRole, cloud IAM principal, or another source. A policy defines which paths and operations are available. A token is the result of authentication and carries a set of policies. A lease defines the lifetime of an issued secret or credential and lets Vault renew or revoke it.

Secret engines perform the actual work. KV stores static secrets. The database engine issues dynamic database credentials. The PKI engine issues certificates. The Transit engine performs cryptographic operations without exposing key material to the client. Audit devices record requests and responses in audit logs with sensitive values masked.

A normal flow is: a workload authenticates through an auth method, receives a token with a limited policy, calls a secret engine path, and Vault returns a secret, dynamic credential, or cryptographic result. If the secret is leased, Vault tracks its lifetime and can renew or revoke it.

#### Interaction Diagram
```mermaid
flowchart LR
  Workload["App / CI / Kubernetes workload"] --> AuthMethod["Auth method"]
  AuthMethod --> Identity["Vault identity"]
  Identity --> Token["Token"]
  Token --> Policy["Policy check"]
  Policy --> Path["Vault path"]

  subgraph VaultServer["Vault server"]
    Path --> KV["KV secrets engine"]
    Path --> DB["Database secrets engine"]
    Path --> PKI["PKI secrets engine"]
    Path --> Transit["Transit engine"]
    KV --> StaticSecret["Static secret"]
    DB --> DynamicCred["Dynamic credential + lease"]
    PKI --> Certificate["Certificate + lease"]
    Transit --> CryptoResult["Encrypt / decrypt / sign result"]
  end

  VaultServer --> Audit["Audit device"]
  VaultServer --> Storage["Encrypted storage backend"]
  Storage --> Seal["Seal / unseal boundary"]

  StaticSecret --> Workload
  DynamicCred --> Workload
  Certificate --> Workload
  CryptoResult --> Workload
```

#### Responsibility Boundaries
Vault protects secret issuance and lifecycle, but it does not make every application that receives those secrets safe. Teams are responsible for minimal policies, short TTLs, audit logs, rotation, safe secret delivery into runtime, protection of root/admin tokens, and avoiding long-lived static secrets where dynamic ones are possible.

#### Common Live Patterns
- HA Vault cluster.
- Auto-unseal through cloud KMS or HSM.
- Kubernetes auth method for workloads.
- Dynamic database credentials.
- PKI engine for internal certificates.
- External Secrets Operator or Vault Agent Injector.
- Centralized audit devices.
- Separation of namespace, mount, and policy by team and environment.

#### Related Project Files
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — the main Vault playbook covering policies, auth methods, audit, and operational hardening.
- `content/platform-security/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — relevant when Vault is integrated with Kubernetes auth or secret delivery.
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — useful for analyzing trust boundaries around secrets.

## Automation and Configuration Management

### Ansible

#### What It Is Used For
Ansible is used for configuration management, provisioning, infrastructure automation, and orchestration of changes across servers, network devices, and platforms. In live environments it often appears in bootstrap processes, hardening, patch management, middleware configuration, and operational runbooks.

#### Operating Model
Inventory describes managed nodes and groups them by environment, role, or other attributes. A playbook defines a sequence of plays: which hosts to target, which variables to use, which tasks to run, and which privilege escalation settings apply. A task calls a module, and a module performs a concrete action: installing a package, changing a file, managing a service, creating a user, or calling an API.

A role packages reusable tasks, handlers, templates, defaults, and files. Variables parameterize playbook and role behavior for different environments. Facts are data collected from the managed node, such as OS, network interfaces, mounts, and package state. Collections provide modules, plugins, and roles as distributable packages. Ansible Vault encrypts sensitive variables or files when secrets are stored near playbooks.

A control node runs a playbook against managed nodes, usually over SSH or WinRM. Ansible copies or invokes a module on the target system, collects the result, and moves to the next task. Handlers run when changes occur, for example restarting a service after configuration changes.

In infrastructure workflows, Ansible often prepares hosts before they join Kubernetes, Kafka, RabbitMQ, or Vault: it installs packages, lays down configuration, manages service units, and applies baseline hardening.

#### Interaction Diagram
```mermaid
flowchart LR
  Operator["Operator / CI"] --> Control["Ansible control node"]
  Git["Git repository"] --> Control
  Inventory["Inventory"] --> Control
  Vars["Variables / group_vars / host_vars"] --> Control
  VaultVars["Ansible Vault / external secrets"] --> Control

  Control --> Playbook["Playbook"]
  Playbook --> Role["Role"]
  Role --> Tasks["Tasks"]
  Tasks --> Modules["Modules"]
  Modules --> SSH["SSH / WinRM"]

  SSH --> HostA["Managed node A"]
  SSH --> HostB["Managed node B"]
  SSH --> HostC["Managed node C"]

  HostA --> Facts["Facts"]
  HostB --> Facts
  HostC --> Facts
  Facts --> Control

  Tasks --> Handlers["Handlers"]
  Handlers --> Restart["Restart / reload services"]
```

#### Responsibility Boundaries
Ansible applies the described changes, but it does not guarantee that a playbook is safe. The team owns access control to the control node, secrets in inventory/vars, change review, idempotency, blast radius limits, safe privilege escalation settings, and reproducible runs.

A mistake in a playbook can propagate insecure configuration at scale.

#### Common Live Patterns
- Git-hosted playbooks with review.
- Inventory separation by environment.
- Ansible Vault or an external secrets manager for sensitive variables.
- Execution through AWX/Automation Controller or CI with an audit trail.
- Restricted `become` and SSH access.
- Dry-run/check mode for risky changes.
- Roles for baseline hardening and patch management.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — applies to change management, privileged automation, and trust boundaries.
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — relevant when Ansible retrieves secrets from Vault or stores sensitive variables.
- There is no dedicated Ansible playbook yet.

### Terraform / OpenTofu

#### What It Is Used For
Terraform and OpenTofu are used for Infrastructure as Code: describing, creating, and changing cloud resources, Kubernetes objects, IAM policies, DNS records, managed databases, network components, and SaaS configuration through declarative code. In live environments they are often the main mechanism for changing production infrastructure, so they should be treated as privileged automation rather than an ordinary configuration repository.

#### Operating Model
Configuration describes desired state through resources, data sources, variables, outputs, providers, and modules. A provider knows the API of a specific platform: cloud, Kubernetes, Vault, DNS, monitoring, or SaaS. The CLI builds a dependency graph, reads current state from the state file, creates a plan, and then apply calls provider operations to bring infrastructure to the desired state.

State maps configuration to real remote objects and contains attributes of created resources. It is a critical artifact: state often includes internal identifiers, connection strings, generated passwords, private endpoints, IAM bindings, and other sensitive values even when variables are marked sensitive. A remote backend is needed not only for collaboration, but also for access control, audit, encryption, and locking. Locking protects against concurrent apply operations that can corrupt state or create conflicting changes.

Modules provide reuse, but create a supply-chain boundary. Public modules, provider versions, and transitive module sources should be pinned and reviewed like application dependencies. A plan is an important review artifact, but not an absolute guarantee: drift, out-of-band changes, provider behavior, and data sources can change the final apply.

In live environments Terraform/OpenTofu usually runs from CI/CD or a dedicated IaC platform, not from an operator laptop. The pipeline obtains short-lived credentials through OIDC/workload identity, builds a plan, stores it as evidence, passes approval, and applies changes with a limited role. Manual apply should be a break-glass process with an audit trail and later state reconciliation.

#### Interaction Diagram
```mermaid
flowchart LR
  Repo["IaC repository"] --> CI["CI / IaC runner"]
  CI --> Init["init providers / modules"]
  Init --> Plan["plan"]
  Plan --> Approval["Review / approval"]
  Approval --> Apply["apply"]

  State["Remote state backend"] --> Plan
  Apply --> State
  Lock["State lock"] --> Plan
  Lock --> Apply

  OIDC["OIDC / workload identity"] --> Creds["Short-lived credentials"]
  Creds --> Apply
  Apply --> Providers["Providers"]
  Providers --> Cloud["Cloud / Kubernetes / SaaS APIs"]
  Cloud --> Resources["Managed resources"]
```

#### Responsibility Boundaries
Terraform/OpenTofu applies infrastructure changes, but it does not decide whether the architecture itself is secure. The team owns module review, provider pinning, remote state security, separation of duties, least-privilege credentials, drift detection, plan/apply approvals, policy-as-code gates, and state recoverability.

The state backend should be treated as high-value storage. Access to it is often equivalent to access to infrastructure topology, IAM bindings, and secrets.

#### Common Live Patterns
- Remote state backend with encryption, access control, audit logs, backup/versioning, and locking.
- Separate state/workspaces or backends by environment, account, blast-radius zone, and ownership domain.
- Plan in a pull request or change request; apply only after approval.
- Short-lived cloud credentials through OIDC/workload identity instead of long-lived access keys.
- Provider and module versions pinned; external module sources reviewed.
- Policy-as-code to block public exposure, broad IAM, unencrypted storage, and unsafe Kubernetes resources.
- Drift detection and import workflow for resources changed outside IaC.
- No plaintext secrets in variables, outputs, state-sharing outputs, or CI logs.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — applies to trust boundaries, data flows, and architecture changes through IaC.
- `content/review/release-governance/playbook.ru.md` / `playbook.en.md` — approvals, release evidence, and separation of duties for infrastructure changes.
- `content/application-security/identity/oidc-oauth/playbook.ru.md` / `playbook.en.md` — OIDC federation for CI/CD and workload identity.
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — relevant when Terraform/OpenTofu retrieves credentials or secrets from Vault.
- There is no dedicated Terraform/OpenTofu playbook yet.

## Data Stores, Search, and Messaging

### Object Storage

#### What It Is Used For
Object storage is used to store files and blobs: user uploads, backups, logs, artifacts, data lake objects, static assets, ML datasets, and exports. Common implementations include Amazon S3, Google Cloud Storage, Azure Blob Storage, and S3-compatible systems such as MinIO.

#### Operating Model
A bucket or container is the top-level storage container. An object stores content, metadata, key/name, and versions if versioning is enabled. A prefix is not a real directory in most object storage systems, but is used as a namespace convention for grouping objects, lifecycle policies, and IAM conditions.

Access is controlled through a combination of IAM policies, bucket/container policies, ACLs, or legacy access models. In live environments, a centralized IAM/policy model with public access blocked by default is preferred; ACLs should be used only where they are truly needed and understood. Signed URLs, presigned URLs, and SAS tokens provide time-limited upload/download access without giving users cloud credentials. Such a URL itself becomes a bearer credential until it expires or the signing credential is revoked.

Encryption can be provider-managed, customer-managed through KMS, or client-side. Versioning, retention, soft delete, and object lock/immutability help protect against accidental deletion, ransomware, and destructive insider actions, but increase cost and require lifecycle management. Access logs and cloud audit logs are needed for investigations: who read, wrote, deleted, or changed policy.

#### Interaction Diagram
```mermaid
flowchart LR
  App["Application"] --> IAM["IAM / bucket policy"]
  IAM --> Bucket["Bucket / container"]
  User["User / client"] --> SignedURL["Signed URL / SAS / presigned URL"]
  SignedURL --> Object["Object"]
  Bucket --> Object
  Object --> Versioning["Versioning / retention"]
  Bucket --> Logs["Access logs / audit logs"]
  KMS["KMS key"] --> Bucket
```

#### Responsibility Boundaries
Object storage reliably stores objects and enforces access policy, but it does not understand the business semantics of the data. The team owns bucket ownership, public exposure, object naming, signed URL scope/lifetime, malware scanning for uploads, encryption/KMS policy, lifecycle, retention, backup restore tests, and protection of sensitive data in logs/artifacts.

#### Common Live Patterns
- Private buckets/containers by default and an explicit public access exception process.
- Separate buckets by environment, data sensitivity, or ownership domain.
- Presigned upload/download with short TTL and a restricted method/object key.
- Server-side encryption with KMS for sensitive data.
- Versioning/soft delete/retention for backups and critical artifacts.
- Object lock or immutable retention for compliance archives and ransomware-resistant backups.
- Access logs/audit logs with a separate write-only destination.
- Lifecycle policies for old versions, incomplete uploads, and temporary exports.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — data flows, trust boundaries, and storage exposure.
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — artifact, SBOM, and provenance storage.
- There is no dedicated object storage playbook yet.

### PostgreSQL / Relational Databases

#### What It Is Used For
PostgreSQL and other relational databases are used for transactional state, accounts, orders, billing, authorization data, audit records, and other data where consistency, relational integrity, and query flexibility matter.

#### Operating Model
A database contains schemas, tables, indexes, views, functions, and roles. A schema groups database objects and is often used to separate domains or tenants, although it does not replace access control by itself. A role can be a login role for connections or a group role for granting privileges. Privileges define who can connect, read, write, change schema, execute functions, or manage objects.

Connection pooling reduces database load and controls the number of active connections. Live deployments often use PgBouncer or managed poolers; the pooling mode matters because transaction/session pooling affects prepared statements, temp tables, session variables, and role switching. Migrations change schema and should be versioned, reviewed, reversible where practical, and compatible with rolling deployment.

Row-level security can restrict rows at the database policy layer and is useful for tenant isolation, but it requires a strict ownership model, bypass scenario tests, and control over privileged roles. Backups and point-in-time recovery rely on base backups and WAL/archive logs. Read replicas offload reads and help recovery, but create separate access risks to the same data and lag-sensitive logic.

Extensions, superuser-like privileges, and procedural languages expand database capability, but increase blast radius. Audit should cover privileged actions, DDL, authentication failures, and access to sensitive tables where required.

#### Responsibility Boundaries
The database engine provides storage, transactions, privileges, and replication primitives. The team owns schema ownership, least-privilege roles, secret rotation, migration safety, backup restore tests, encryption, network exposure, audit, tenant isolation, and protection of sensitive data in queries, dumps, and replicas.

#### Common Live Patterns
- Managed PostgreSQL with private networking.
- Separate app roles for read/write, migrations, and admin operations.
- Connection pooling with an explicitly selected mode.
- Backups with regular restore drills and measured RPO/RTO.
- PITR for critical transactional systems.
- Read replicas with separate access policies.
- RLS for high-risk multi-tenant tables after a dedicated threat model.
- Audit logging for privileged operations and sensitive data access.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — data classification, tenant isolation, and trust boundaries.
- `content/application-security/business-logic/business-logic-abuse/playbook.ru.md` / `playbook.en.md` — integrity-sensitive flows and abuse cases.
- There is no dedicated database security playbook yet.

### Redis

#### What It Is Used For
Redis is used as a cache, session store, rate-limit store, lightweight queue, distributed lock backend, and fast key-value database. In live environments Redis often sits on the critical path for authentication, authorization decisions, shopping carts, background jobs, and anti-abuse controls.

#### Operating Model
Redis stores keys of different types: strings, hashes, lists, sets, sorted sets, streams, and other structures. Data usually lives in memory, while persistence is configured through RDB snapshots, AOF, or both. Replication and clustering are used for availability and scale, but require understanding consistency, failover, and key distribution.

AUTH and ACL restrict client access to commands and key patterns. TLS protects network traffic. Dangerous commands such as administrative, persistence-changing, scripting, or bulk key operations can cause data loss, credential exposure, DoS, or tenant boundary bypass if available to the application without need.

The eviction policy defines which keys are removed under memory pressure. For cache this is normal behavior; for session store or queue usage it can become an incident. Multi-tenant Redis requires especially strict key namespace, ACLs, memory quotas, and operational separation; using separate instances for different trust domains is often more reliable.

#### Responsibility Boundaries
Redis provides a fast in-memory data store and primitives for persistence/replication, but it does not guarantee safe cache, session, or lock semantics. The team owns network isolation, AUTH/ACL/TLS, command restrictions, key namespace, memory limits, eviction behavior, backups where needed, monitoring, and protection of secrets/PII in values.

#### Common Live Patterns
- Managed Redis or isolated private deployment.
- TLS and ACLs with separate users for applications and operations.
- Dangerous commands disabled for app users.
- Separate instances for cache, sessions, queues, and rate limiting.
- Explicit TTL for cache/session keys.
- Memory limits and eviction policy aligned with the use case.
- Monitoring memory, evictions, blocked clients, replication lag, and command latency.

#### Related Project Files
- `content/application-security/business-logic/business-logic-abuse/playbook.ru.md` / `playbook.en.md` — rate limits, sessions, and abuse controls.
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — state management and data flow review.
- There is no dedicated Redis playbook yet.

### Vector Database / Vector DB

#### What It Is Used For
A vector database stores embeddings and performs similarity search over vectors. In live environments it is most often used for RAG, semantic search, recommendations, deduplication, anomaly detection, and other scenarios where the system needs to search by semantic or feature proximity rather than exact match.

#### Operating Model
An embedding model converts text, an image, an event, or another object into a vector embedding: a fixed-dimensional numeric representation. The vector database stores the embedding, object ID, metadata, and, in some architectures, a reference to the source document or chunk. At query time, the application builds an embedding for the query and searches for nearest neighbors using a similarity metric such as cosine similarity, dot product, or Euclidean distance.

An index speeds up search, often with approximate nearest neighbor algorithms. This creates an important tradeoff: latency and cost improve by accepting approximation, so retrieval quality must be measured separately instead of treated as a default database property. Metadata filters limit results by tenant, document class, source, ACL, or other attributes; in RAG they must be part of the authorization model, not just a convenient search filter.

A vector database usually does not replace source-of-truth storage. Source documents, permissions, lifecycle, and deletion workflow often live in object storage, a database, or a document store, while the vector index is a derived representation. When a source document is updated or deleted, embeddings, metadata, and the search index must be updated as well; otherwise stale retrieval can return data that is no longer accessible or has been deleted by policy.

#### Responsibility Boundaries
A vector database provides embedding storage and similarity-based retrieval, but it does not guarantee correct authorization semantics, source data quality, or safe retrieved context. The team owns tenant isolation, document-level authorization, metadata integrity, ingestion validation, deletion propagation, encryption, backups, audit logs, monitoring, and protection against poisoned corpora, embedding leakage, and unbounded retrieval.

#### Common Live Patterns
- Separate indexes or namespaces by tenant, environment, and sensitivity where a shared index complicates isolation.
- Permission-aware retrieval: access filters are applied before context is returned to the model.
- Metadata schema with owner, source, classification, tenant, document version, and deletion state.
- Ingestion pipeline with validation, malware/content checks, provenance, and deduplication.
- Retrieval limits: `top_k`, score threshold, payload size limit, and rate limits.
- Evaluation set for retrieval quality and leakage tests before live-environment changes.
- Audit logging for queries, retrieved document IDs, metadata filters, and administrative changes.
- Regular index rebuild/cleanup after document deletion, permission changes, and embedding model upgrades.

#### Related Project Files
- `content/ai-security/securing-ai/overview.ru.md` / `overview.en.md` — LLMSecOps lifecycle, RAG data pipeline, and vector database controls.
- `content/ai-security/owasp-llm-top-10/overview.ru.md` / `overview.en.md` — LLM09 Vector and Embedding Weaknesses.
- There is no dedicated vector database security playbook yet.

### Elasticsearch / OpenSearch

#### What It Is Used For
Elasticsearch and OpenSearch are used for search, log analytics, observability, security analytics, and document indexing. In live environments they often store application logs, audit events, customer-visible search indexes, and operational telemetry.

#### Operating Model
A cluster consists of nodes and stores indexes. An index contains documents and a mapping that describes fields and types. Shards divide an index for scale and replication. An ingest pipeline can transform documents before write: parse logs, add fields, normalize events, or remove some data.

Access can be defined at the cluster, index, document, and field level depending on distribution, edition, and configuration. Dashboards/OpenSearch Dashboards/Kibana provide UI for search and visualization, but when exposed incorrectly they become a direct window into logs, PII, tokens, and internal infrastructure data.

Snapshot repositories are used for backup/restore and migration. They often live in object storage, so their IAM and retention are as important as permissions on the cluster itself. Logs and traces should be treated as sensitive data: they can contain authorization headers, session IDs, emails, payload fragments, stack traces, and internal hostnames.

#### Responsibility Boundaries
A search cluster indexes and searches documents, but it does not decide which data is safe to log or who should see it. The team owns network exposure, authentication, authorization, tenant/index isolation, field masking, ingest redaction, dashboard access, snapshot security, retention, and cost/cardinality controls.

#### Common Live Patterns
- Managed or dedicated cluster in a private network.
- Separate indexes or clusters for environments and sensitivity levels.
- Index lifecycle management for retention and cost control.
- Ingest redaction for secrets, tokens, and PII.
- Least-privilege dashboard roles.
- Snapshot repository with restricted IAM and restore drills.
- Alerting on authentication failures, public exposure, disk watermarks, and ingestion spikes.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — sensitive data flows and observability surfaces.
- `content/application-security/web/browser-security/playbook.ru.md` / `playbook.en.md` — relevant when frontend logs/telemetry contain browser-side data.
- There is no dedicated Elasticsearch/OpenSearch playbook yet.

### Kafka

#### What It Is Used For
Apache Kafka is used as a distributed event streaming platform: event bus, ingestion pipeline, audit/event log, integration backbone, stream processing source, and buffer between services. In live environments Kafka is often a critical shared platform that carries business events, telemetry, and integrations.

#### Operating Model
A broker stores topic partition data and serves producers/consumers. A topic is a logical category of events, such as `orders.created`. A partition is an ordered append-only log inside a topic; partitions provide scaling and parallelism. A replica is a copy of a partition on another broker for fault tolerance. The controller manages cluster metadata, partition leader election, and state changes.

A producer publishes records to a topic, selecting a partition explicitly or through a partitioner. A consumer reads records from partitions and advances an offset, which is the read position. A consumer group lets several instances of the same application divide partitions among themselves: one partition within a group is read by only one consumer instance at a time. This provides horizontal scaling for processing.

Schema Registry stores event schemas and helps control compatibility between producer and consumer contracts. Kafka Connect runs connectors that integrate Kafka with databases, object storage, search engines, and other systems. ACLs define who may read, write, create, or administer topics, groups, and cluster resources.

Current Kafka `4.x` clusters run in KRaft mode without ZooKeeper; older `3.x` clusters may still have ZooKeeper during migration. In a working flow, a producer sends an event to the broker leader for a partition, the broker writes it to the log and replicates it to followers, a consumer group reads events and commits offsets, and downstream services use those events for processing, integration, or analytics.

#### Interaction Diagram
```mermaid
flowchart LR
  Producer["Producer"] --> Topic["Topic"]
  Topic --> P0["Partition 0 leader"]
  Topic --> P1["Partition 1 leader"]

  subgraph KafkaCluster["Kafka cluster"]
    Broker1["Broker 1"] --> P0
    Broker2["Broker 2"] --> P1
    P0 --> R0["Partition 0 replicas"]
    P1 --> R1["Partition 1 replicas"]
    Controller["Controller / KRaft quorum"] --> Broker1
    Controller --> Broker2
  end

  P0 --> CG["Consumer group"]
  P1 --> CG
  CG --> C1["Consumer instance A"]
  CG --> C2["Consumer instance B"]
  C1 --> Offsets["Committed offsets"]
  C2 --> Offsets

  Schema["Schema Registry"] --> Producer
  Schema --> CG
  Connect["Kafka Connect"] --> Topic
  ACL["ACL / authentication"] --> KafkaCluster
```

#### Responsibility Boundaries
Kafka provides event delivery, storage, and replication, but it does not define data access semantics for the application. Teams are responsible for topic ownership, ACLs, tenant isolation, encryption in transit, retention, schema governance, protecting PII/secrets in events, and handling redelivery correctly.

Kafka does not guarantee that a consumer interprets a message safely.

#### Common Live Patterns
- Managed Kafka or a dedicated platform cluster; for self-managed Kafka `4.x`, operate KRaft quorum explicitly and treat any remaining ZooKeeper dependency as legacy migration scope.
- TLS for client-broker and inter-broker traffic.
- SASL, OAuth, or mTLS for authentication.
- ACLs by topic and group.
- Schema Registry for contracts.
- Separate clusters or prefixes for environments and domains.
- Kafka Connect with a separate secret model.
- Monitoring lag, under-replicated partitions, auth failures, and retention pressure.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — applies to event-driven architecture, trust boundaries, and data flow review.
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — relevant when credentials, certificates, or connector secrets are issued through Vault.
- There is no dedicated Kafka playbook yet.

### RabbitMQ

#### What It Is Used For
RabbitMQ is used as a message broker for queues, routing, asynchronous processing, task distribution, and service integration. In live environments it often appears in background jobs, transactional messaging, integration queues, and systems where routing semantics, acknowledgements, and backpressure matter.

#### Operating Model
A broker accepts messages, stores queues, and delivers messages to consumers. A virtual host separates a logical RabbitMQ space: exchanges, queues, bindings, user permissions, and policies live inside a vhost. An exchange accepts publications from producers and decides which queues should receive a message. A queue stores messages until a consumer reads them. A binding connects an exchange and a queue with a routing rule.

A routing key is used by an exchange to select matching bindings. A direct exchange routes by exact routing key, a topic exchange by patterns, a fanout exchange to all bound queues, and a headers exchange by message headers. A consumer reads a message from a queue and sends an acknowledgement after successful processing. If an acknowledgement is not received, the broker can return the message to the queue or send it through a dead-letter topology, depending on configuration.

A policy defines queue and exchange behavior: TTL, max length, dead-letter exchange, quorum settings, and other parameters. Operator policy acts as a guardrail above client-provided arguments and ordinary policies, especially for resource limits. User/permission defines which operations are allowed inside a vhost: configure, write, and read.

The working flow is: a producer publishes a message to an exchange, the exchange uses routing key and bindings to select a queue, the broker stores the message, a consumer takes it and acknowledges processing. If processing fails or the message expires, DLX/retry topology decides whether it is retried, delayed, or sent to a dead-letter queue.

#### Interaction Diagram
```mermaid
flowchart LR
  Producer["Producer"] --> Exchange["Exchange"]
  Producer --> RoutingKey["Routing key"]
  RoutingKey --> Exchange

  subgraph VHost["Virtual host"]
    Exchange --> BindingA["Binding: route A"]
    Exchange --> BindingB["Binding: route B"]
    BindingA --> QueueA["Queue A"]
    BindingB --> QueueB["Queue B"]
    QueueA --> ConsumerA["Consumer A"]
    QueueB --> ConsumerB["Consumer B"]
    ConsumerA --> AckA["Ack / nack"]
    ConsumerB --> AckB["Ack / nack"]
    QueueA --> DLX["Dead-letter exchange"]
    QueueB --> DLX
    DLX --> DLQ["Dead-letter queue"]
    Policy["Policy: TTL, max length, quorum, DLX"] --> QueueA
    Policy --> QueueB
  end

  Permissions["User permissions: configure / write / read"] --> VHost
  AckA --> QueueA
  AckB --> QueueB
```

#### Responsibility Boundaries
RabbitMQ owns broker delivery and routing, but not message content security or business processing semantics. The team owns TLS, users/permissions, vhost isolation, queue policies, DLQ, TTL, management UI exposure, credential protection, and payload control, especially when messages contain personal data or commands for internal systems.

#### Common Live Patterns
- Clustered RabbitMQ with quorum queues for critical queues; do not design new HA paths around classic mirrored queues, which are removed in RabbitMQ `4.x`.
- Durable queues for live messages; transient non-exclusive classic queues are deprecated in RabbitMQ `4.3+` and should not be a new production model. For temporary state, use exclusive/server-named queues or durable queues with TTL.
- Separate vhosts for domains, environments, or teams.
- TLS for client connections.
- Least-privilege permissions on exchanges and queues.
- DLQ and retry topology.
- Policies and operator policies for TTL, max length, quorum settings, and upper resource limits.
- Restricted access to the management UI.
- Monitoring queue depth, consumer count, unacked messages, and publish/ack rates.

#### Related Project Files
- `content/review/architecture/checklist.ru.md` / `checklist.en.md` — applies to asynchronous flows, trust boundaries, and message processing.
- `content/platform-security/secrets/vault/playbook.ru.md` / `playbook.en.md` — relevant when broker credentials or TLS materials are managed through Vault.
- There is no dedicated RabbitMQ playbook yet.
---

## Related Materials

- [Container image security playbook](/Product-security-playbook/en/supply-chain/container-image-security/playbook/)
- [Kubernetes cluster security review playbook](/Product-security-playbook/en/platform-security/kubernetes/cluster-security-review/playbook/)
- [Vault playbook](/Product-security-playbook/en/platform-security/secrets/vault/playbook/)
- [Securing AI overview](/Product-security-playbook/en/ai-security/securing-ai/overview/)
