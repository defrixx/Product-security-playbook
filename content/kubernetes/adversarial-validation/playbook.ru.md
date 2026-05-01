# Adversarial validation Kubernetes-кластера

## 1. Область и цель

Этот плейбук описывает, как переводить Kubernetes attack paths в безопасные production-проверки. Фокус на проверяемом цикле:
- подтвердить доступ и границу доверия;
- перечислить reachable surface;
- доказать один контролируемый путь злоупотребления;
- объяснить root cause;
- применить контроль и повторить тот же тест.

**Цель:**
- проверить, что Kubernetes-контроли закрывают реальные пути атаки, а не только выглядят корректно в YAML;
- получить подтверждения для security review, remediation и повторной проверки;
- связать offensive lab-сценарии с production guardrails: RBAC, admission, NetworkPolicy, runtime hardening, supply chain и observability.

---

## 2. Метод ревью

### 2.1 Минимальный цикл проверки

Каждый сценарий должен проходить один и тот же цикл:
- **Проверить:** подтвердить, что целевой workload, сервис, identity или policy действительно существуют.
- **Перечислить:** собрать низкошумный контекст: pods, services, routes, mounts, env, ServiceAccount, RBAC, image metadata.
- **Доказать:** выполнить минимальное действие, которое доказывает риск, без расширения воздействия.
- **Объяснить:** зафиксировать root cause в терминах нарушенной границы доверия.
- **Исправить и перепроверить:** применить контроль и повторить тот же test case, чтобы доказать закрытие пути.

Успешный результат проверки - не "нашли что-то подозрительное", а конкретный артефакт подтверждения: доступный `NodePort`, избыточное право ServiceAccount, достижимый internal service через SSRF, runtime socket mount, чтение Secret через API, alert от runtime detection или denial от admission policy.

### 2.2 Безопасные ограничения

Для production и shared staging:
- выполняйте destructive/DoS/runtime escape проверки только в изолированном namespace или clone-среде;
- заранее фиксируйте область: namespaces, workloads, identities, IP ranges, временное окно;
- не читайте реальные секретные значения без отдельного approval; достаточно доказать наличие права `get/list/watch` или факт выдачи токена;
- не запускайте mass scanning по pod CIDR без лимитов rate/concurrency;
- для доказательства исправления используйте тот же минимальный test case, а не более сильную технику.

Команды подтверждения классифицируются так:
- `safe in prod`: read-only проверки metadata или policy, которые не раскрывают значения секретов;
- `staging only`: команды, которые инспектируют artifacts или запускают активные probes и должны использовать clone, canary или изолированный namespace;
- `requires approval`: команды, которые могут раскрыть sensitive data, сканировать инфраструктуру или затронуть реальные workloads.

---

## 3. Матрица сценариев и контролей

### 3.1 Раскрытый исходный код и секреты

**Что проверять:**
- веб-приложение не отдает `.git`, `.svn`, backup-файлы, build metadata и локальные env-файлы;
- container image layers не содержат удаленные секреты, `.env`, cloud credentials или внутренние конфиги;
- Git и registry scanning срабатывают до merge/release;
- найденные ранее секреты ротируются, а не только удаляются из текущей ветки.

**Рекомендация для production:**
- блокируйте служебные VCS/build paths на web tier и при упаковке артефактов;
- запрещайте plaintext/base64 secrets в Git и image layers;
- включите pre-merge и pre-release secret scanning;
- любой секрет, попавший в Git или image layer, считается скомпрометированным и должен быть ротирован.

**Подтверждение:**
Классификация: `safe in prod` для header checks и проверки статуса сканирования; `staging only` для image export или layer inspection; `requires approval` перед экспортом production images.

```bash
curl -I https://<app>/.git/config
docker history --no-trunc <image>
# Только staging/approved: команда может экспортировать sensitive layers для offline scanning.
docker save <image> -o image.tar
trufflehog git file://<repo>
```

### 3.2 Runtime socket и доступ к host

**Что проверять:**
- workloads не монтируют `docker.sock`, `containerd.sock`, CRI sockets, host `/proc`, `/sys` и широкие `hostPath`;
- build/CI workloads не получают host runtime control plane ради удобства;
- `privileged: true`, `hostPID`, `hostNetwork`, `hostIPC` и dangerous capabilities имеют владельца, обоснование и expiry.

**Рекомендация для production:**
- deny runtime socket mounts через admission policy;
- используйте rootless/isolated builders или выделенные build nodes вместо host socket sharing;
- для исключений требуйте отдельный namespace, tight RBAC, NetworkPolicy, runtime detection и срок пересмотра не более `30d`.

**Подтверждение:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{.spec.volumes}{"\n"}{end}' | grep -E 'docker.sock|containerd.sock|hostPath'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" privileged="}{.spec.containers[*].securityContext.privileged}{" hostPID="}{.spec.hostPID}{" hostNetwork="}{.spec.hostNetwork}{"\n"}{end}'
```

### 3.3 SSRF и обнаружение внутренних сервисов

**Что проверять:**
- server-side URL fetchers не могут обращаться к arbitrary internal URLs;
- sensitive internal services требуют authentication, а не доверяют "внутрикластерности";
- cloud metadata endpoints защищены provider-specific controls;
- egress из frontend/workload namespaces ограничен явным allowlist.

**Рекомендация для production:**
- URL fetchers используют allowlist схем, доменов и портов;
- запретите доступ к metadata IP ranges и cluster-internal sensitive services для workload'ов, которым он не нужен;
- никогда не запрашивайте credential paths cloud metadata во время validation; доказывайте защиту через deny evidence, non-sensitive canaries или provider-specific metadata controls;
- мониторьте неожиданные HTTP-запросы из frontend pods к internal service DNS и metadata endpoints.

**Подтверждение:**
Классификация: `safe in prod` для policy deny logs и non-sensitive canaries; `staging only` для активных service reachability probes; `requires approval` перед проверкой production metadata endpoints.

```bash
kubectl run -n <ns> --rm -it netcheck --image=curlimages/curl -- sh
curl -m 2 http://<sensitive-service>.<namespace>.svc.cluster.local
# Safe metadata validation: предпочтительны deny logs или non-sensitive canary.
curl -m 2 -I http://169.254.169.254/
# AWS IMDSv2 должен отклонять tokenless metadata calls; не запрашивайте /latest/meta-data/iam/security-credentials/.
curl -m 2 -s -o /dev/null -w "%{http_code}\n" http://169.254.169.254/latest/meta-data/
# GCP/Azure: проверяйте egress deny или provider-specific metadata protections без запроса token/credential paths.
kubectl logs -n <network-policy-or-runtime-security-ns> <policy-or-sensor-pod>
```

### 3.4 NodePort и экспозиция сервисов

**Что проверять:**
- все `NodePort`, `LoadBalancer`, `Ingress` и `Gateway` имеют владельца, назначение и expected audience;
- node security groups/firewalls не открывают NodePort range наружу без необходимости;
- internet exposure проверяется фактическим подключением, а не только чтением Service YAML.

**Рекомендация для production:**
- для internal сервисов используйте `ClusterIP` или internal load balancer;
- alert на новый `NodePort` в production namespace;
- инвентарь public entry points обновляется минимум каждые `30d`.

**Подтверждение:**
Классификация: `safe in prod` для inventory сервисов; `requires approval` для внешних connectivity scans по node IP.

```bash
kubectl get svc -A -o wide
kubectl get svc -A --field-selector spec.type=NodePort
# Требуется approved scope, isolated window, target list, rate limits и owner approval.
nmap -Pn -p 30000-32767 <node-external-ip>
```

### 3.5 Обход namespace и сетевые границы

**Что проверять:**
- namespaces не воспринимаются как сетевой boundary без NetworkPolicy или эквивалентного CNI enforcement;
- sensitive namespaces имеют default-deny ingress и egress;
- разрешенные east-west потоки документированы и тестируются из low-trust pod.

**Рекомендация для production:**
- включите default deny для production и high-value namespaces;
- явно разрешайте только необходимые service-to-service пути;
- re-test NetworkPolicy после изменений CNI, namespace labels и service selectors.

**Подтверждение:**
```bash
kubectl get networkpolicy -A
kubectl run -n <low-trust-ns> --rm -it netcheck --image=curlimages/curl -- sh
curl -m 2 http://<target-service>.<target-ns>.svc.cluster.local
```

### 3.6 Злоупотребление ServiceAccount и RBAC

**Что проверять:**
- workload identity не может читать Secrets, менять workloads, создавать pods, выполнять `exec`, добавлять ephemeral containers или изменять RBAC без необходимости;
- `automountServiceAccountToken` выключен для workload'ов без Kubernetes API access;
- default ServiceAccount не используется application workload'ами.

**Рекомендация для production:**
- один ServiceAccount на workload, права выдаются по функции, а не по namespace convenience;
- `get/list/watch secrets`, `pods/exec`, `pods/ephemeralcontainers`, `escalate`, `bind`, `impersonate`, `serviceaccounts/token` требуют отдельного approval;
- quarterly recertification прав production ServiceAccounts.

**Подтверждение:**
```bash
kubectl auth can-i list secrets --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i create pods/exec --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl get rolebindings,clusterrolebindings -A
```

### 3.7 Исчерпание ресурсов

**Что проверять:**
- каждый production container имеет `resources.requests` и `resources.limits`;
- namespaces имеют `ResourceQuota` и, где нужно, `LimitRange`;
- alerting покрывает CPU/memory spikes, OOMKilled, throttling и restart loops.

**Рекомендация для production:**
- запретить BestEffort pods в production namespaces;
- задавать namespace-level quotas для shared clusters;
- DoS-проверки выполнять только в isolated load/staging среде.

**Подтверждение:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{.spec.containers[*].resources}{"\n"}{end}'
kubectl get resourcequota,limitrange -A
kubectl top pods -A
```

### 3.8 Registry образов и цепочка поставки

**Что проверять:**
- private registry требует authentication, authorization и network restriction;
- registry API не раскрывает catalog/manifests широкой аудитории;
- production-развертывание идет по digest и проходит provenance/signature policy;
- image history не содержит suspicious fetch-and-execute pattern;
- batch/utility jobs не запускают image'и из неутвержденных registry без владельца и provenance.

**Рекомендация для production:**
- registry endpoints не должны быть доступны из general-purpose networks;
- audit logging registry events обязателен для production artifacts;
- deploy gate должен проверять digest, trusted builder identity, provenance/signature и policy outcome;
- блокируйте image'и, которые скачивают и выполняют remote content во время build/startup без отдельного ревью.

**Подтверждение:**
```bash
curl -I https://<registry>/v2/
curl https://<registry>/v2/_catalog
cosign verify <image>@sha256:<digest>
docker history --no-trunc <image>
kubectl get jobs -A -o wide
```

### 3.9 Поверхности отладки: exec и ephemeral containers

**Что проверять:**
- кто может выполнять `pods/exec`, `pods/attach`, `pods/portforward`, `pods/ephemeralcontainers`;
- debug containers не обходят Pod Security/RBAC ожидания;
- node-level `kubectl debug node/...` разрешен только break-glass ролям.

**Рекомендация для production:**
- `exec` в sensitive namespaces должен быть ограничен и audit-able;
- ephemeral containers разрешайте только support/SRE ролям с коротким сроком и отдельным логированием;
- применяйте admission policy для запрета debug surfaces в high-value namespaces, где это операционно допустимо.

**Подтверждение:**
```bash
kubectl auth can-i create pods/exec --as=<subject> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=<subject> -n <ns>
kubectl get events -A --field-selector reason=Started
```

### 3.10 Детектирование и проверка policy

**Что проверять:**
- audit logs покрывают RBAC changes, Secret reads, `exec`, ephemeral containers, admission denials и namespace label drift;
- runtime telemetry видит чтение sensitive paths, shell spawn, suspicious network tools, `nsenter`, host path access;
- admission policy блокирует известные unsafe patterns до развертывания.

**Рекомендация для production:**
- используйте offensive lab behaviors как detection test cases, но адаптируйте их под безопасную staging-среду;
- Falco/Tetragon или эквивалентные runtime sensors должны иметь настроенный signal-to-noise baseline;
- Kyverno/Gatekeeper/ValidatingAdmissionPolicy policies должны иметь владельца, test cases и жизненный цикл исключений.

**Подтверждение:**
```bash
kubectl get validatingadmissionpolicies,validatingadmissionpolicybindings
kubectl get clusterpolicies -A
kubectl logs -n <runtime-security-ns> -l app.kubernetes.io/name=<sensor>
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout
kubectl --namespace <sensitive-ns> exec -it <pod> -- sh
```

### 3.11 Обнаружение runtime-контекста и окружения

**Что проверять:**
- workload не раскрывает high-value secrets через environment variables, debug endpoints, shell-доступ или verbose error output;
- в контейнере нет неожиданных mounts, writable sensitive paths, broad `/proc` visibility и service account token там, где Kubernetes API не нужен;
- general-purpose helper images и security toolboxes не появляются в production namespace без change record и владельца.

**Рекомендация для production:**
- не помещайте долгоживущие секреты в env vars для application workload'ов; используйте secret manager, workload identity или short-lived mounted credentials;
- выключайте `automountServiceAccountToken` и debug shell там, где они не нужны для runtime-функции;
- alert на запуск multi-tool images, unexpected shells, package managers и network scanners в production namespaces.

**Подтверждение:**
Классификация: `safe in prod` для Kubernetes API metadata inventory; `staging only` для shell-based inspection; `requires approval` перед выполнением команд в production pods.

```bash
# Не выводите значения environment variables. Проверяйте только имена/классы через approved debug path.
kubectl exec -n <ns> <pod> -- sh -c 'env | cut -d= -f1 | grep -Ei "TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AWS_|GOOGLE_|AZURE_"'
# Только staging/approved: shell-based runtime inspection затрагивает workload.
kubectl exec -n <ns> <pod> -- mount
kubectl exec -n <ns> <pod> -- cat /proc/self/cgroup
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" sa="}{.spec.serviceAccountName}{" automount="}{.spec.automountServiceAccountToken}{" image="}{.spec.containers[*].image}{"\n"}{end}'
```

### 3.12 Benchmark и ревью posture

**Что проверять:**
- Docker/container runtime, kubelet, API server, RBAC, audit и node hardening проверяются benchmark tooling, а не только ручным чтением YAML;
- kube-bench/CIS profile выбран под фактическую Kubernetes version и provider flavor; managed-service ограничения отмечены как exception или not applicable;
- kubeaudit/Popeye или эквивалентные scanners находят privileged pods, missing limits, weak security context, stale references и hygiene debt;
- benchmark findings переводятся в remediation backlog с владельцем, severity и re-test evidence.

**Рекомендация для production:**
- запускайте posture scans регулярно и после platform upgrades;
- отделяйте exploitable misconfigurations от hygiene findings, чтобы remediation не превращался в шум;
- не считайте чистый scanner output достаточным security assurance: подтверждайте critical controls targeted validation-тестами из этого playbook.

**Подтверждение:**
```bash
kubectl logs -n <audit-ns> job/<kube-bench-job>
kubeaudit all
popeye
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" privileged="}{.spec.containers[*].securityContext.privileged}{" limits="}{.spec.containers[*].resources.limits}{"\n"}{end}'
```

### 3.13 Legacy-сервисы management plane

**Что проверять:**
- в кластере нет Helm v2 Tiller, старых dashboard/admin services, abandoned operators или package-management components с broad RBAC;
- management-plane services не доступны из application namespaces и low-trust pods;
- service accounts для tooling развертывания не имеют cluster-admin по умолчанию и не могут читать Secrets без необходимости.

**Рекомендация для production:**
- Helm v2/Tiller должен быть выведен из эксплуатации; для Helm v3 храните release state и deploy credentials с минимально необходимыми правами;
- любые in-cluster admin services требуют explicit owner, network isolation, authentication, audit logging и expiry для exception;
- проверяйте legacy components после migration, incident cleanup и cluster upgrades.

**Подтверждение:**
```bash
kubectl get svc,deploy,sa,rolebinding,clusterrolebinding -A | grep -Ei 'tiller|dashboard|admin|operator'
kubectl auth can-i '*' '*' --as=system:serviceaccount:<ns>:<deploy-sa>
kubectl get clusterrolebinding -A -o wide
```

---

## 4. Выходные артефакты ревью

Adversarial validation считается завершенной, когда есть:
- матрица сценариев и контролей для проверенных путей атаки;
- подтверждение для каждого proof target до и после remediation;
- список residual risks и исключений с владельцами/expiry;
- mapping между findings и профильными плейбуками: Cluster Review, Pod Security, Container Escape, Seccomp, SLSA, Vault;
- re-test log, показывающий, что исправление закрыло исходный abuse path.

---

## 5. Связанные материалы в репозитории

- Ревью безопасности Kubernetes-кластера: [kubernetes/cluster-security-review/playbook.ru.md](../cluster-security-review/playbook.ru.md)
- Усиление безопасности Pod runtime: [kubernetes/pod-security/playbook.ru.md](../pod-security/playbook.ru.md)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.ru.md](../container-escape-capability-abuse/overview.ru.md)
- Чеклист ревью seccomp: [kubernetes/seccomp/checklist.ru.md](../seccomp/checklist.ru.md)
- SLSA provenance для container images: [supply-chain/slsa-provenance/overview.ru.md](../../supply-chain/slsa-provenance/overview.ru.md)
- Vault и секреты: [secrets/vault/playbook.ru.md](../../secrets/vault/playbook.ru.md)
