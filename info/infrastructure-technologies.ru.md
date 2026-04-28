# Infrastructure Technologies

Этот документ описывает, как работают ключевые технологии, которые часто встречаются в production-инфраструктуре и security review. Он не заменяет плейбуки: здесь фокус на назначении, модели работы, границах ответственности и типовых эксплуатационных паттернах.

## Docker

### Для чего используется
Docker используется для сборки, упаковки и запуска приложений в контейнерах. В production он чаще всего встречается как инструмент сборки образов, локальной разработки, CI/CD pipeline и часть контейнерной supply chain, даже если в Kubernetes контейнеры запускает уже containerd или CRI-O.

### Модель работы
`Dockerfile` описывает, из чего собирается образ: базовый image, установку пакетов, копирование файлов, переменные окружения, пользователя, рабочую директорию и команду запуска. При сборке Docker превращает инструкции в набор слоев. Каждый layer фиксирует изменение filesystem, а итоговый image становится переносимым артефактом, который можно положить в registry и запускать в разных окружениях.

Registry хранит и раздает images. Docker CLI является клиентом, через который разработчик или CI отправляет команды сборки, публикации и запуска. Docker daemon выполняет эти команды на host: собирает image, создает container, подключает volumes и networks, назначает ограничения и передает низкоуровневый запуск runtime.

Container — это запущенный процесс с изолированным представлением filesystem, процессов, сети и ресурсов. Volume нужен для данных, которые должны пережить пересоздание container. Network определяет, как container общается с другими container, host и внешними системами.

Обычный поток выглядит так: разработчик или CI собирает image из `Dockerfile`, публикует его в registry, затем runtime скачивает image и запускает container из неизменяемого набора слоев с заданными namespace, cgroups, capabilities, mounts и сетевой конфигурацией. В связке с Kubernetes Docker чаще остается на этапе build/package, а запуском на node занимается container runtime.

### Схема взаимодействия
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

### Границы ответственности
Docker помогает упаковать приложение и задать параметры запуска, но не делает образ безопасным автоматически. Команда отвечает за минимизацию базового образа, отсутствие секретов в слоях, pinning версий, сканирование зависимостей, запуск без root, ограничение capabilities и корректную публикацию в registry.

Приложение по-прежнему отвечает за собственную аутентификацию, авторизацию, обработку входных данных и безопасную работу с секретами.

### Типовые production-паттерны
- Сборка образов в CI.
- Хранение образов в private registry.
- Multi-stage builds.
- Минимальные base images.
- Image scanning перед публикацией или deployment.
- Подписание образов и provenance для критичных сервисов.
- Запуск контейнеров в Kubernetes через containerd или CRI-O, а не напрямую через Docker Engine.

### Связанные файлы из проекта
- `content/kubernetes/container-escape-capability-abuse/overview.ru.md` / `overview.en.md` — риски container escape через capabilities и опасные параметры контейнера.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — безопасные настройки workload, применимые к контейнерам в Kubernetes.
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — происхождение артефактов, supply chain и доверие к сборкам.

## OCI Registry / Artifact Registry

### Для чего используется
OCI registry хранит и раздает container images и связанные артефакты supply chain: SBOM, signatures, provenance attestations, scan results, Helm charts и другие OCI-compatible objects. В production registry обычно является центральной точкой между build pipeline, deployment platform и runtime: CI публикует артефакты, admission/deploy gate проверяет их, Kubernetes nodes скачивают digest'ы для запуска workload'ов.

### Модель работы
OCI Distribution Specification описывает API для push/pull контента через registry. Основные объекты: blob, manifest, image index, digest и tag. Blob хранит слой image или конфигурацию. Manifest описывает один image или artifact и ссылается на blobs по digest. Image index связывает несколько platform-specific manifests, например `linux/amd64` и `linux/arm64`. Digest является content-addressed идентификатором; tag — человекочитаемая ссылка на manifest, которая может быть изменяемой, если registry policy это разрешает.

Repository внутри registry группирует related artifacts, например `prod/payments/api`. Клиент делает push blobs и manifest, затем может присвоить tag. При pull клиент запрашивает manifest по tag или digest, получает digest'ы blobs и скачивает их. Kubernetes в production должен ссылаться на image по digest, потому что tag не является надежной immutable-ссылкой без отдельной tag immutability policy.

Современный artifact registry часто хранит не только image, но и referrers: подписи, SBOM и provenance, связанные с subject digest. Например, image `sha256:...` может иметь cosign signature, SLSA provenance и SBOM как отдельные OCI artifacts. Deploy gate или admission policy сначала извлекает image digest, затем ищет связанные attestations/referrers, проверяет подпись, builder identity, provenance predicate и policy outcome.

Registry также управляет authorization, retention, replication, vulnerability scanning, pull-through cache и audit logs. В cloud registry это часто отдельный managed service с IAM policies; в self-hosted вариантах, например Harbor или distribution-based registry, команда сама отвечает за storage, TLS, auth, replication и cleanup.

### Схема взаимодействия
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

### Границы ответственности
Registry гарантирует хранение и выдачу артефактов по API, но не доказывает автоматически, что image безопасен, подписан правильным субъектом или собран из допустимого source. Команда отвечает за authn/authz, immutable digest-based deployment, tag immutability для release tags, подписи, provenance, retention, vulnerability management и audit trail.

Artifact registry не должен быть единственным control point. Даже если registry блокирует часть unsafe images, deploy gate должен независимо проверять digest, подпись, builder identity, provenance и policy decision перед попаданием workload в production.

### Типовые production-паттерны
- Private registry с IAM/RBAC и отдельными repositories по средам или доменам.
- Deployment только по digest (`image@sha256:...`), tags используются для удобства discovery, а не как trust anchor.
- Tag immutability для release tags и запрет перезаписи production tags.
- Подпись images и публикация SBOM/provenance как OCI artifacts/referrers.
- Admission/deploy gate, который проверяет signature, trusted builder identity, SLSA provenance и vulnerability policy.
- Retention policy для старых images, но с сохранением артефактов, нужных для rollback, incident response и audit.
- Pull-through cache с отдельной trust policy для upstream images.
- Audit logging для push/delete/tag mutation/pull anomalous patterns.

### Связанные файлы из проекта
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — provenance, verification policy и trusted builders.
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — registry как часть deployment chain и production gate.
- `content/kubernetes/adversarial-validation/playbook.ru.md` / `playbook.en.md` — проверки private registry exposure, image history и supply-chain abuse paths.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — runtime последствия запуска недоверенного image.

## Kubernetes

### Для чего используется
Kubernetes используется для оркестрации контейнеризированных приложений: scheduling, service discovery, rollout, autoscaling, конфигурация, секреты, сетевое взаимодействие и управление жизненным циклом workload. В production он часто является базовой платформой для микросервисов, batch-задач, internal platforms и cloud-native инфраструктуры.

### Модель работы
API Server является центральной точкой управления: через него проходят команды пользователей, контроллеров, kubelet и внешних интеграций. Он валидирует запросы, применяет authentication/authorization/admission и сохраняет желаемое состояние в etcd. etcd хранит состояние кластера: объекты workload, services, secrets, bindings, конфигурацию и метаданные.

Scheduler выбирает node для pod на основе ресурсов, constraints, affinity, taints/tolerations и других правил размещения. Controller-manager запускает контроллеры, которые постоянно сравнивают желаемое состояние с фактическим: например, создают новые pods для Deployment, заменяют упавшие pods или синхронизируют endpoints для Service. Admission controllers работают на входе в API и могут изменять или отклонять объекты до сохранения.

На каждой worker node kubelet получает назначенные pods через API Server и просит container runtime запустить нужные containers. Container runtime скачивает images и создает containers. CNI plugin настраивает сетевую связность pod, а kube-proxy или eBPF/CNI-замена обеспечивает service networking.

Pod — минимальная исполняемая единица Kubernetes: один или несколько containers с общей сетевой identity и volumes. Deployment управляет stateless replicas и rollout, StatefulSet — stateful workload со стабильной identity, DaemonSet — agent на каждой подходящей node. Service дает стабильную сетевую точку доступа к динамическому набору pods, Ingress или Gateway публикует HTTP/TCP-вход в кластер. ConfigMap хранит несекретную конфигурацию, Secret — чувствительные значения, ServiceAccount задает identity workload. RBAC связывает roles/clusterroles с subjects через rolebindings/clusterrolebindings. NetworkPolicy описывает разрешенные сетевые потоки между pods и внешними адресами.

В рабочем потоке пользователь применяет manifest через API Server, объект сохраняется в etcd, контроллер создает или обновляет дочерние объекты, scheduler назначает pod на node, kubelet запускает containers через runtime, а сетевые компоненты делают workload доступным другим сервисам.

### Схема взаимодействия
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

### Границы ответственности
Kubernetes предоставляет API и механизмы управления workload, но не гарантирует безопасную конфигурацию кластера и приложений сам по себе. Платформенная команда отвечает за RBAC, isolation, admission policies, сетевые политики, audit logs, node hardening, upgrade lifecycle и интеграцию с IAM, secrets и registry.

Команды приложений отвечают за безопасные pod specs, health checks, resource limits, секреты, конфигурацию ingress и поведение приложения.

### Типовые production-паттерны
- Managed Kubernetes: EKS, GKE, AKS или аналог.
- GitOps через Argo CD или Flux.
- Разделение namespace по средам, командам или blast radius.
- Отдельные node pools для trusted/untrusted, stateful, GPU или privileged workload.
- Ingress controller или Gateway API.
- External Secrets Operator или CSI driver для секретов.
- Policy engine: Kyverno или OPA Gatekeeper.
- Private control plane и ограниченный доступ к Kubernetes API.

### Связанные файлы из проекта
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — комплексный security review Kubernetes-кластера.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — требования к безопасной конфигурации pod/workload.
- `content/kubernetes/seccomp/checklist.ru.md` / `checklist.en.md` — проверка seccomp-профилей.
- `content/kubernetes/container-escape-capability-abuse/overview.ru.md` / `overview.en.md` — container escape и misuse Linux capabilities.

## CNI / Kubernetes networking

### Для чего используется
CNI и Kubernetes networking обеспечивают сетевую связность pod'ов, service discovery, Service load balancing, egress/ingress paths и enforcement сетевых политик. В production это один из главных слоев blast-radius control: именно CNI решает, может ли workload из одного namespace достучаться до другого workload, metadata endpoint, control-plane endpoint или внешней системы.

Типичные реализации: Cilium, Calico, cloud-provider CNI, Flannel и другие plugins. Cilium делает акцент на eBPF datapath, observability и kube-proxy replacement. Calico широко используется для Kubernetes NetworkPolicy и расширенных policy-моделей, включая GlobalNetworkPolicy в Calico-стеке. Некоторые managed clusters используют cloud-native CNI, где pod IPs интегрированы напрямую с VPC/VNet.

### Модель работы
Kubernetes задает общую сетевую модель: pod получает IP, pod'ы могут обращаться друг к другу, Service дает стабильный virtual IP или DNS name для набора endpoints, а NetworkPolicy описывает разрешенные ingress/egress потоки. Kubernetes API хранит объекты, но сам не применяет NetworkPolicy на datapath. Enforcement делает CNI plugin или связанный policy engine.

CNI plugin вызывается kubelet/container runtime при создании pod sandbox. Он выделяет IP, подключает network interface pod'а, программирует routes, rules, eBPF maps или iptables/nftables, а затем поддерживает состояние при изменении pods, nodes, services и policies. DNS обычно обеспечивается CoreDNS, а Service traffic реализуется kube-proxy через iptables/IPVS или CNI datapath, если используется kube-proxy replacement.

NetworkPolicy является namespace-scoped Kubernetes resource. Она выбирает pods через labels и задает, какой ingress и egress разрешен. Важная семантика: pod без подходящей policy обычно остается non-isolated для соответствующего направления. Как только pod выбран ingress или egress policy, разрешены только явно описанные потоки для этого направления. Поэтому default-deny требует отдельной policy, а не просто наличия CNI.

Cilium может заменить kube-proxy и реализовать Service load balancing через eBPF. В такой модели Cilium agents программируют eBPF datapath на nodes, используют maps для service/backend lookup, могут собирать flow visibility через Hubble и применять L3/L4/L7 policies. Calico может применять Kubernetes NetworkPolicy и собственные расширенные политики, включая ordered rules, tiers и host endpoints в зависимости от edition/configuration. Практический вывод для review: нужно проверять не только YAML policy, но и фактический CNI, режим datapath, поддержку egress, namespace selectors, DNS/FQDN policies и observability.

### Схема взаимодействия
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

### Границы ответственности
CNI обеспечивает datapath и может применять NetworkPolicy, но не знает бизнес-семантику сервисов. Платформа отвечает за выбор CNI, включение policy enforcement, default-deny baseline, egress strategy, observability, upgrade compatibility и проверку того, что policy действительно действует.

Команды приложений отвечают за корректные labels, описание нужных service-to-service потоков, отказ от неявной "namespace isolation" модели и тестирование connectivity после изменений.

### Типовые production-паттерны
- Default-deny ingress и egress для production/high-value namespaces.
- Явные allow rules для service-to-service потоков, DNS и нужного egress.
- Разделение node pools или clusters для workload'ов с разным trust level.
- Cilium/Hubble или Calico flow logs для расследования сетевых событий.
- kube-proxy replacement только после проверки совместимости с cloud load balancers, service mesh, NodePort/LoadBalancer behavior и observability.
- Egress gateway/NAT strategy для стабильной идентификации исходящего трафика.
- NetworkPolicy re-test после изменений namespace labels, pod labels, CNI version и service selectors.
- Отдельные controls для metadata endpoints и cloud control-plane endpoints.

### Связанные файлы из проекта
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — review service boundaries, egress и NetworkPolicy baseline.
- `content/kubernetes/adversarial-validation/playbook.ru.md` / `playbook.en.md` — проверки namespace bypass, SSRF, NodePort exposure и фактической reachability.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — pod-level controls дополняют, но не заменяют network isolation.
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — анализ trust boundaries и data flows.

## Ingress / Gateway / API Gateway

### Для чего используется
Ingress, Gateway и API Gateway публикуют сервисы за пределы кластера или между сетевыми зонами. Они принимают client traffic, завершают TLS или передают TLS дальше, маршрутизируют запросы к Kubernetes Services, применяют authentication/authorization integrations, rate limits, WAF/API security policies, header normalization и observability.

В production встречаются разные реализации: NGINX Ingress Controller, cloud load balancer controllers, Envoy Gateway, Kong Gateway/Kong Ingress Controller, HAProxy/Contour/Traefik и gateway-компоненты service mesh. Kubernetes Ingress остается stable API для HTTP/HTTPS routing, но его развитие заморожено; новые возможности Kubernetes networking в основном развиваются в Gateway API. Если controller реализован Istio, этот раздел описывает north-south entry point, а mesh-семантика Istio (`VirtualService`, `DestinationRule`, `PeerAuthentication`, `AuthorizationPolicy`, sidecar/ambient) рассматривается отдельно в разделе Istio.

### Модель работы
Ingress resource описывает host/path routing к backend Service. Сам по себе Ingress не работает без Ingress Controller. Controller наблюдает Kubernetes API, выбирает Ingress objects по `ingressClassName`, генерирует конфигурацию proxy/load balancer и обеспечивает внешний endpoint через Service type `LoadBalancer`, NodePort, cloud load balancer или edge appliance.

Gateway API разделяет роли явнее. `GatewayClass` описывает тип controller. `Gateway` описывает listener'ы, addresses, ports, TLS и правила, какие Routes могут к нему подключаться. `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `TLSRoute` и другие route resources описывают application-level routing. `allowedRoutes` и cross-namespace attachment model формируют trust boundary между platform team, которая владеет Gateway, и application teams, которые владеют Routes. Не путайте Kubernetes Gateway API `Gateway` с Istio `networking.istio.io/Gateway`: названия похожи, но ownership, deployment model и набор route resources отличаются.

API Gateway добавляет слой API-management: plugins/policies для auth, JWT/OIDC validation, API keys, rate limiting, request/response transformation, WAF, bot protection, schema validation, developer portals или analytics. В Kubernetes это может быть тот же controller, который читает Ingress/Gateway API resources и генерирует конфигурацию gateway data plane.

Критичные точки security review: где завершается TLS, доверяется ли `X-Forwarded-*`, кто может создавать routes для публичных hostnames, как защищены wildcard hosts, есть ли upstream mTLS, как enforced authentication, как работает WAF/rate limiting, кто может менять annotations/plugins и не обходят ли они baseline.

### Схема взаимодействия
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

### Границы ответственности
Ingress/Gateway слой контролирует network entry point, но не заменяет application authorization. Если gateway проверяет только наличие токена, приложение все равно должно проверять business authorization и tenant boundaries. Если TLS завершается на gateway, нужно явно решить, нужен ли mTLS или шифрование до upstream service.

Платформа отвечает за controller hardening, class ownership, public exposure, certificate lifecycle, baseline annotations/plugins, default security headers, logging и guardrails для cross-namespace routes. Application teams отвечают за route ownership, backend readiness, корректные host/path rules и совместимость приложения с proxy headers/timeouts.

### Типовые production-паттерны
- Gateway API для новых deployments, Ingress для existing workloads там, где migration еще не завершен.
- Отдельные ingress/gateway classes для public, internal и admin traffic.
- TLS termination на gateway с управляемым certificate lifecycle; upstream mTLS для sensitive backends.
- Strict policy на `X-Forwarded-*`, `Forwarded`, `Host` и client IP headers; приложение доверяет только заголовкам от approved proxy.
- WAF/API security и rate limiting на public routes.
- Запрет wildcard hosts или отдельный approval для wildcard routing.
- Cross-namespace route attachment только через явные `allowedRoutes`/ReferenceGrant и ownership rules.
- Access logs с correlation ID, request outcome, upstream service и policy decision.
- Защита controller service account: он часто может читать Secrets и менять gateway/proxy configuration.

### Связанные файлы из проекта
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — inventory entry points, service exposure и ownership.
- `content/kubernetes/adversarial-validation/playbook.ru.md` / `playbook.en.md` — проверки NodePort/Ingress/Gateway reachability и SSRF/internal exposure.
- `content/web/owasp-top-10/playbook.ru.md` / `playbook.en.md` — application-layer risks за gateway.
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — trust boundaries, external integrations и evidence для архитектурного review.

## Среды выполнения контейнеров (container runtimes)

### Для чего используется
Container runtime запускает контейнеры на node: скачивает образы, подготавливает filesystem, namespace, cgroups и передает запуск низкоуровневому runtime. В Kubernetes runtime обычно работает через CRI и является частью каждой worker node.

### Модель работы
CRI — интерфейс между kubelet и runtime. Благодаря CRI kubelet не зависит от конкретной реализации и может работать с containerd, CRI-O или другим совместимым runtime. Runtime получает от kubelet запросы на создание pod sandbox, pull image, запуск container, остановку container и сбор статуса.

OCI image spec описывает формат image, а OCI runtime spec — как из этого image запустить container с нужными namespace, cgroups, mounts, capabilities и процессом entrypoint. Image store хранит скачанные images локально на node. Snapshotter подготавливает filesystem layers так, чтобы container получил свое рабочее представление filesystem без полного копирования образа.

Pod sandbox представляет инфраструктурную оболочку pod: сеть, namespace и базовые ресурсы, внутри которых запускаются application containers. Shim process удерживает связь с запущенным container и позволяет runtime не держать весь lifecycle в одном процессе.

Типовая цепочка выглядит так: kubelet получает pod assignment, вызывает CRI runtime, runtime скачивает image из registry, подготавливает snapshot/layers, создает sandbox, затем вызывает OCI runtime, например `runc` или Kata Containers. Низкоуровневый runtime создает Linux-изоляцию и запускает процесс приложения.

### Схема взаимодействия
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

### Границы ответственности
Runtime исполняет контейнер с заданными ограничениями, но не решает сам, какие permissions безопасны. Если Kubernetes workload запрошен как privileged, с опасными capabilities, `hostPath`, `hostPID` или `hostNetwork`, runtime технически выполнит эту конфигурацию.

За policy, admission control и baseline отвечает платформа.

### Типовые production-паттерны
- containerd как runtime в managed Kubernetes.
- CRI-O в кластерах, ориентированных на Kubernetes-native runtime stack.
- RuntimeClass для изоляции отдельных workload.
- gVisor или Kata Containers для workload с повышенными требованиями к изоляции.
- Централизованная настройка runtime на node images.
- Monitoring runtime events и audit на уровне node.

### Связанные файлы из проекта
- `content/kubernetes/container-escape-capability-abuse/overview.ru.md` / `overview.en.md` — связь runtime-изоляции, capabilities и escape-сценариев.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — workload-настройки, которые runtime применяет на node.
- `content/kubernetes/seccomp/checklist.ru.md` / `checklist.en.md` — syscall filtering как часть runtime hardening.

## Istio

### Для чего используется
Istio используется как service mesh для управления сетевым взаимодействием между сервисами: mTLS, traffic routing, retries, telemetry, authorization policies и постепенные релизы. В production он чаще всего встречается в Kubernetes-кластерах с большим количеством внутренних сервисов и строгими требованиями к service-to-service security.

### Модель работы
Istiod является control plane mesh. Он принимает Kubernetes/Istio configuration, выпускает и распространяет конфигурацию для data plane, управляет service discovery и участвует в certificate distribution для mTLS. Data plane представлен Envoy proxy рядом с приложением в sidecar-модели или компонентами ambient mesh, если используется ambient-режим. В ambient mode базовый L4 secure overlay обеспечивает `ztunnel` на node, а L7-функции добавляются через waypoint proxies.

Envoy proxy перехватывает входящий и исходящий трафик workload, устанавливает mTLS, применяет routing rules, retry/timeout policy, authorization policy и собирает telemetry. Ingress gateway принимает внешний трафик в mesh, egress gateway централизует контролируемый выход из mesh во внешние системы.

Ключевые CRD задают поведение mesh. В Istio API `VirtualService` описывает маршрутизацию и traffic shifting. `DestinationRule` задает subsets, load balancing и connection policy для upstream. `Gateway` управляет точками входа/выхода в mesh. `PeerAuthentication` определяет mTLS-режим, а `AuthorizationPolicy` — кто к кому может обращаться. Отдельно Istio поддерживает Kubernetes Gateway API; в этой модели `Gateway`, `HTTPRoute` и другие route resources приходят из `gateway.networking.k8s.io`, а не из Istio API.

В связке с Kubernetes приложение остается обычным Deployment/Pod, но его трафик проходит через data plane. Istiod наблюдает за сервисами и политиками в Kubernetes API, пересчитывает конфигурацию и отправляет ее proxy. Proxy уже на пути трафика применяет mTLS, routing, policy и telemetry без изменения бизнес-кода приложения.

### Схема взаимодействия
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

### Границы ответственности
Istio может обеспечить mTLS между workload и централизованную mesh-policy, но не исправляет слабую аутентификацию внутри приложения и не заменяет Kubernetes RBAC, NetworkPolicy, CNI datapath policy или API security. NetworkPolicy по-прежнему нужен для L3/L4 blast-radius control и для ограничения traffic, который не должен полагаться только на mesh enrollment.

Платформа отвечает за корректный mesh onboarding, certificate lifecycle, policy model, gateway exposure и совместимость с приложениями.

### Типовые production-паттерны
- Mesh только для selected namespaces, а не сразу для всего кластера.
- Strict mTLS для внутренних сервисов.
- AuthorizationPolicy для service-to-service доступа.
- Отдельные ingress/egress gateways, если north-south или outbound traffic должен проходить через контролируемые mesh edge points.
- Явное решение, какой API используется для routing: Istio `VirtualService`/`Gateway`, Kubernetes Gateway API или оба в переходный период.
- Canary/blue-green routing через VirtualService и DestinationRule.
- Интеграция telemetry с Prometheus, Grafana или OpenTelemetry.
- Постепенная миграция с sidecar на ambient mesh там, где это оправдано.

### Связанные файлы из проекта
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — применимо к mesh как части Kubernetes control/data plane.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — sidecar/mesh workload остаются Kubernetes workload и наследуют pod security требования.
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — полезно для анализа trust boundaries и service-to-service взаимодействия.
- Прямого отдельного playbook по Istio пока нет.

## Vault

### Для чего используется
HashiCorp Vault используется для централизованного управления секретами, динамическими учетными данными, encryption-as-a-service и доступом к чувствительным материалам. В production он часто стоит между приложениями, CI/CD, Kubernetes и внешними системами: базами данных, cloud IAM, PKI, SSH и message brokers.

### Модель работы
Vault server принимает API-запросы, выполняет аутентификацию, проверяет policy, обращается к secret engines и пишет audit events. Storage backend хранит зашифрованное состояние Vault: конфигурацию, metadata, policies и данные secret engines. Seal/unseal защищает master key material: пока Vault sealed, он не может расшифровать хранилище и обслуживать обычные запросы.

Auth methods связывают внешнюю identity с Vault identity: Kubernetes service account, OIDC subject, AppRole, cloud IAM principal или другой источник. Policy определяет, какие paths и operations доступны. Token является результатом аутентификации и несет набор policy. Lease задает срок жизни выданного секрета или credential и позволяет Vault отзывать или обновлять его.

Secret engines выполняют конкретную работу. KV хранит статические secrets. Database engine выдает динамические database credentials. PKI engine выпускает сертификаты. Transit engine выполняет криптографические операции без раскрытия ключевого материала клиенту. Audit devices записывают запросы и ответы в audit log с маскированием чувствительных значений.

Обычный поток такой: workload аутентифицируется через auth method, получает token с ограниченной policy, обращается к path secret engine, а Vault возвращает секрет, динамический credential или результат криптографической операции. Если секрет leased, Vault отслеживает срок жизни и может выполнить renew или revoke.

### Схема взаимодействия
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

### Границы ответственности
Vault защищает выдачу и lifecycle секретов, но не делает безопасным любое приложение, которое эти секреты получает. Команды отвечают за минимальные policies, короткие TTL, audit logs, ротацию, безопасную доставку секретов в runtime, защиту root/admin tokens и отказ от долгоживущих статических секретов там, где возможны динамические.

### Типовые production-паттерны
- HA Vault cluster.
- Auto-unseal через cloud KMS или HSM.
- Kubernetes auth method для workload.
- Dynamic database credentials.
- PKI engine для internal certificates.
- External Secrets Operator или Vault Agent Injector.
- Централизованные audit devices.
- Разделение namespace, mount и policy по командам и средам.

### Связанные файлы из проекта
- `content/secrets/vault/playbook.ru.md` / `playbook.en.md` — основной playbook по Vault, policies, auth methods, audit и operational hardening.
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — если Vault интегрирован с Kubernetes auth или secret delivery.
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — полезно для анализа trust boundaries вокруг секретов.

## Ansible

### Для чего используется
Ansible используется для configuration management, provisioning, автоматизации инфраструктурных операций и оркестрации изменений на серверах, сетевых устройствах и платформах. В production он часто встречается в bootstrap-процессах, hardening, patch management, настройке middleware и операционных runbook.

### Модель работы
Inventory описывает managed nodes и группирует их по средам, ролям или другим признакам. Playbook задает последовательность plays: на какие hosts идти, с какими variables, какие tasks выполнить и с какими privilege escalation настройками. Task вызывает module, а module выполняет конкретное действие: устанавливает пакет, меняет файл, управляет service, создает пользователя или обращается к API.

Role упаковывает повторно используемые tasks, handlers, templates, defaults и files. Variables параметризуют поведение playbook и role для разных окружений. Facts — данные, собранные с managed node, например OS, network interfaces, mounts и package state. Collections поставляют модули, plugins и роли как распространяемые пакеты. Ansible Vault шифрует чувствительные переменные или файлы, если секреты хранятся рядом с playbooks.

Control node выполняет playbook против managed nodes, обычно через SSH или WinRM. Ansible копирует или вызывает module на целевой системе, получает результат и переходит к следующему task. Handlers выполняются при изменениях, например перезапускают service после изменения конфигурации.

В связке с инфраструктурой Ansible часто подготавливает hosts до подключения к Kubernetes, Kafka, RabbitMQ или Vault: ставит пакеты, раскладывает конфигурацию, управляет service units и применяет baseline hardening.

### Схема взаимодействия
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

### Границы ответственности
Ansible применяет описанные изменения, но не гарантирует, что playbook безопасен. Команда отвечает за контроль доступа к control node, секреты в inventory/vars, review изменений, idempotency, ограничение blast radius, безопасные privilege escalation настройки и воспроизводимость запусков.

Ошибка в playbook может массово распространить небезопасную конфигурацию.

### Типовые production-паттерны
- Git-hosted playbooks с review.
- Разделение inventory по средам.
- Ansible Vault или внешний secrets manager для чувствительных переменных.
- Запуск через AWX/Automation Controller или CI с audit trail.
- Ограничение `become` и SSH-доступа.
- Dry-run/check mode для рискованных изменений.
- Роли для baseline hardening и patch management.

### Связанные файлы из проекта
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — применимо к change management, privileged automation и trust boundaries.
- `content/secrets/vault/playbook.ru.md` / `playbook.en.md` — если Ansible получает секреты из Vault или хранит чувствительные переменные.
- Прямого отдельного playbook по Ansible пока нет.

## Helm

### Для чего используется
Helm используется как package manager для Kubernetes: шаблонизация манифестов, управление релизами и распространение приложений через charts. В production он часто применяется для установки платформенных компонентов, ingress controllers, monitoring stack, policy engines и внутренних приложений.

### Модель работы
Chart — пакет Kubernetes-манифестов и шаблонов для одного приложения или компонента платформы. Template содержит Kubernetes YAML с Go templating. `values.yaml` и environment-specific values задают параметры рендера: image tag, replicas, resources, ingress, service account, RBAC, security context и другие настройки.

Release — установленный экземпляр chart в конкретном namespace с конкретным набором values. Repository хранит charts и версии charts. Dependency позволяет chart включать другие charts, например базу данных или sidecar-компонент. Hook запускает Kubernetes resources в определенные моменты lifecycle, например до установки, после upgrade или перед удалением.

Helm рендерит manifests из templates и values, затем отправляет итоговые Kubernetes objects в cluster API. Состояние release хранится в Kubernetes, а обновления выполняются через `helm upgrade`: Helm сравнивает новую версию chart/values с текущим release и применяет изменения.

В связке с GitOps Helm часто не запускается вручную оператором. GitOps controller берет chart и values из Git или registry, рендерит их или делегирует рендер Helm, затем синхронизирует итоговые objects с Kubernetes.

### Схема взаимодействия
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

### Границы ответственности
Helm не определяет безопасность итоговой конфигурации. Chart может создать privileged workload, wildcard RBAC, небезопасный ingress или secret с чувствительными значениями.

Команда отвечает за review rendered manifests, контроль values, provenance chart, pinning версий, ограничения на hooks и проверку прав, которые chart создает в кластере.

### Типовые production-паттерны
- Internal chart repository.
- Pinning chart/app versions.
- Separate values per environment.
- Rendering manifests в CI с policy checks.
- GitOps-controller применяет chart вместо ручного `helm install`.
- Подпись/provenance для third-party charts.
- Минимизация post-install hooks и privileged jobs.

### Связанные файлы из проекта
- `content/kubernetes/cluster-security-review/playbook.ru.md` / `playbook.en.md` — Helm часто является источником RBAC, workload и ingress-конфигураций для review.
- `content/kubernetes/pod-security/playbook.ru.md` / `playbook.en.md` — проверка итоговых pod specs после рендера chart.
- `content/supply-chain/slsa-provenance/overview.ru.md` / `overview.en.md` — доверие к артефактам, включая charts и deployment packages.

## Kafka

### Для чего используется
Apache Kafka используется как distributed event streaming platform: event bus, ingestion pipeline, audit/event log, integration backbone, stream processing source и буфер между сервисами. В production Kafka часто является критичной shared-платформой, через которую проходят бизнес-события, telemetry и интеграции.

### Модель работы
Broker хранит данные topic partitions и обслуживает producers/consumers. Topic — логическая категория событий, например `orders.created`. Partition — упорядоченный append-only log внутри topic; именно partition дает масштабирование и параллелизм. Replica — копия partition на другом broker для отказоустойчивости. Controller управляет metadata кластера, leader election для partitions и изменениями состояния.

Producer публикует records в topic, выбирая partition явно или через partitioner. Consumer читает records из partitions и продвигает offset — позицию чтения. Consumer group позволяет нескольким экземплярам одного приложения разделить partitions между собой: одна partition в рамках group читается только одним consumer instance в момент времени. Это дает горизонтальное масштабирование обработки.

Schema Registry хранит схемы событий и помогает контролировать совместимость producer и consumer контрактов. Kafka Connect запускает connectors для интеграции Kafka с базами данных, object storage, search engines и другими системами. ACL описывают, кто может читать, писать, создавать или администрировать topics, groups и cluster resources.

Современные кластеры могут работать в KRaft-режиме без ZooKeeper. В рабочем потоке producer отправляет событие broker leader для partition, broker записывает его в log и реплицирует followers, consumer group читает события и фиксирует offsets, а downstream-сервисы используют эти события для обработки, интеграции или аналитики.

### Схема взаимодействия
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

### Границы ответственности
Kafka обеспечивает доставку, хранение и репликацию событий, но не решает семантику доступа к данным за приложение. Команды отвечают за topic ownership, ACL, tenant isolation, encryption in transit, retention, schema governance, защиту PII/secrets в событиях и корректную обработку повторной доставки.

Kafka не гарантирует, что consumer безопасно интерпретирует сообщение.

### Типовые production-паттерны
- Managed Kafka или выделенный platform cluster.
- TLS для client-broker и inter-broker traffic.
- SASL, OAuth или mTLS для аутентификации.
- ACL по topic и group.
- Schema Registry для контрактов.
- Separate clusters или prefixes для сред и доменов.
- Kafka Connect с отдельной моделью секретов.
- Monitoring lag, under-replicated partitions, auth failures и retention pressure.

### Связанные файлы из проекта
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — применимо к event-driven архитектуре, trust boundaries и data flow review.
- `content/secrets/vault/playbook.ru.md` / `playbook.en.md` — если credentials, certificates или connector secrets выдаются через Vault.
- Прямого отдельного playbook по Kafka пока нет.

## RabbitMQ

### Для чего используется
RabbitMQ используется как message broker для очередей, routing, asynchronous processing, task distribution и интеграции сервисов. В production он часто встречается в background jobs, transactional messaging, integration queues и системах, где важны routing semantics, acknowledgements и backpressure.

### Модель работы
Broker принимает сообщения, хранит очереди и доставляет сообщения consumers. Virtual host разделяет логическое пространство RabbitMQ: exchanges, queues, bindings, users permissions и policies живут внутри vhost. Exchange принимает публикации от producers и решает, в какие queues направить message. Queue хранит сообщения до чтения consumer. Binding связывает exchange и queue с routing rule.

Routing key используется exchange для выбора подходящих bindings. Direct exchange маршрутизирует по точному routing key, topic exchange — по шаблонам, fanout — во все связанные queues, headers — по headers сообщения. Consumer читает message из queue и отправляет acknowledgement после успешной обработки. Если ack не получен, broker может вернуть сообщение в очередь или отправить его по dead-letter topology в зависимости от настроек.

Policy задает поведение queues и exchanges: TTL, max length, dead-letter exchange, quorum settings и другие параметры. User/permission определяет, какие operations разрешены внутри vhost: configure, write и read.

Рабочий поток выглядит так: producer публикует message в exchange, exchange по routing key и bindings выбирает queue, broker хранит message, consumer забирает его и подтверждает обработку. Если обработка неуспешна или сообщение просрочено, DLX/retry topology решает, будет ли оно повторено, отложено или отправлено в dead-letter queue.

### Схема взаимодействия
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

### Границы ответственности
RabbitMQ отвечает за брокерскую доставку и routing, но не за безопасность содержимого сообщений и бизнес-семантику обработки. Команда отвечает за TLS, users/permissions, vhost isolation, queue policies, DLQ, TTL, ограничение management UI, защиту credentials и контроль payload, особенно если сообщения содержат персональные данные или команды для внутренних систем.

### Типовые production-паттерны
- Clustered RabbitMQ с quorum queues для критичных очередей.
- Отдельные vhosts для доменов, сред или команд.
- TLS для client connections.
- Least-privilege permissions на exchanges и queues.
- DLQ и retry topology.
- Policies для TTL, max length и quorum settings.
- Ограниченный доступ к management UI.
- Monitoring queue depth, consumer count, unacked messages и publish/ack rates.

### Связанные файлы из проекта
- `content/architecture/security-review/checklist.ru.md` / `checklist.en.md` — применимо к asynchronous flows, trust boundaries и обработке сообщений.
- `content/secrets/vault/playbook.ru.md` / `playbook.en.md` — если broker credentials или TLS materials управляются через Vault.
- Прямого отдельного playbook по RabbitMQ пока нет.
