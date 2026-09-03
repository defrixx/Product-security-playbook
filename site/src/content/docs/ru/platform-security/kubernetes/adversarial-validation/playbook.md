---
title: "Плейбук проверки защищенности Kubernetes-кластера"
description: "Этот плейбук описывает, как переводить Kubernetes attack paths в безопасные проверки для рабочих сред. Фокус на проверяемом цикле:"
sidebar:
  order: 20
---
## 1. Область и цель

Этот плейбук описывает, как переводить Kubernetes attack paths в безопасные проверки для рабочих сред. Фокус на проверяемом цикле:
- подтвердить доступ и границу доверия;
- перечислить reachable surface;
- доказать один контролируемый путь злоупотребления;
- объяснить root cause;
- применить контроль и повторить тот же тест.

**Цель:**
- проверить, что Kubernetes-меры контроля закрывают реальные пути атаки, а не только выглядят корректно в YAML;
- получить подтверждения для проверка безопасности, устранения проблем и повторной проверки;
- связать offensive lab-сценарии с защитными мерами рабочих сред: RBAC, admission, NetworkPolicy, усиление защиты runtime, supply chain и observability.

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

Для рабочих сред и shared staging:
- выполняйте destructive/DoS/runtime escape проверки только в изолированном namespace или clone-среде;
- заранее фиксируйте область: namespaces, workloads, identities, IP ranges, временное окно;
- не читайте реальные секретные значения без отдельного согласования; достаточно доказать наличие права `get/list/watch` или факт выдачи токена;
- не запускайте mass scanning по pod CIDR без лимитов rate/concurrency;
- для доказательства исправления используйте тот же минимальный test case, а не более сильную технику.

Команды подтверждения классифицируются так:
- `безопасно в рабочей среде`: read-only проверки metadata или policy, которые не раскрывают значения секретов;
- `только staging`: команды, которые инспектируют артефакты или запускают активные probes и должны использовать clone, canary или изолированный namespace;
- `требует согласования`: команды, которые могут раскрыть sensitive data, сканировать инфраструктуру или затронуть реальные workloads.

---

## 3. Матрица сценариев и мер контроля

### 3.1 Раскрытый исходный код и секреты

**Что проверять:**
- веб-приложение не отдает `.git`, `.svn`, backup-файлы, build metadata и локальные env-файлы;
- container image layers не содержат удаленные секреты, `.env`, облачные учетные данные или внутренние конфиги;
- Git и registry scanning срабатывают до merge/release;
- для найденных ранее секретов выполняется ротация, а не только удаление из текущей ветки.

**Рекомендация для рабочих сред:**
- блокируйте служебные VCS/build paths на web tier и при упаковке артефактов;
- запрещайте plaintext/base64 secrets в Git и image layers;
- включите pre-merge и pre-release secret scanning;
- любой секрет, попавший в Git или image layer, считается скомпрометированным и требует ротации.

**Подтверждение:**
Классификация: `безопасно в рабочей среде` для header checks и проверки статуса сканирования; `только staging` для image export или layer inspection; `требует согласования` перед экспортом release images.

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

**Рекомендация для рабочих сред:**
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
- cloud metadata endpoints защищены мерами, специфичными для provider;
- egress из frontend/workload namespaces ограничен явным allowlist.

**Рекомендация для рабочих сред:**
- URL fetchers используют allowlist схем, доменов и портов;
- запретите доступ к metadata IP ranges и cluster-internal sensitive services для рабочих нагрузок, которым он не нужен;
- никогда не запрашивайте пути с учетными данными в cloud metadata во время validation; доказывайте защиту через подтверждения блокировки, non-sensitive canary или специфичные для provider меры защиты metadata;
- мониторьте неожиданные HTTP-запросы из frontend pods к internal service DNS и metadata endpoints.

**Подтверждение:**
Классификация: `безопасно в рабочей среде` для policy deny logs и non-sensitive canaries; `только staging` для активных service reachability probes; `требует согласования` перед проверкой metadata endpoints рабочей среды.

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
- все `NodePort`, `LoadBalancer`, `Ingress` и `Gateway` имеют владельца, назначение и ожидаемую аудиторию;
- node security groups/firewalls не открывают NodePort range наружу без необходимости;
- internet exposure проверяется фактическим подключением, а не только чтением Service YAML.

**Рекомендация для рабочих сред:**
- для internal сервисов используйте `ClusterIP` или internal load balancer;
- alert на новый `NodePort` в защищенном namespace;
- инвентарь public entry points обновляется минимум каждые `30d`.

**Подтверждение:**
Классификация: `безопасно в рабочей среде` для inventory сервисов; `требует согласования` для внешних connectivity scans по node IP.

```bash
kubectl get svc -A -o wide
kubectl get svc -A --field-selector spec.type=NodePort
# Требуется approved scope, isolated window, target list, rate limits и согласование владельца.
nmap -Pn -p 30000-32767 <node-external-ip>
```

### 3.5 Обход namespace и сетевые границы

**Что проверять:**
- namespaces не воспринимаются как сетевой boundary без NetworkPolicy или эквивалентного CNI enforcement;
- sensitive namespaces имеют default-deny ingress и egress;
- разрешенные east-west потоки документированы и тестируются из low-trust pod.

**Рекомендация для рабочих сред:**
- включите default deny для рабочих сред и high-value namespaces;
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
- `automountServiceAccountToken` выключен для рабочих нагрузок без Kubernetes API access;
- default ServiceAccount не используется application рабочими нагрузками.

**Рекомендация для рабочих сред:**
- один ServiceAccount на workload, права выдаются по функции, а не по namespace convenience;
- `get/list/watch secrets`, `pods/exec`, `pods/ephemeralcontainers`, `escalate`, `bind`, `impersonate`, `serviceaccounts/token` требуют отдельного согласования;
- ежеквартальный пересмотр прав ServiceAccount в рабочей среде.

**Подтверждение:**
```bash
kubectl auth can-i list secrets --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i create pods/exec --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl get rolebindings,clusterrolebindings -A
```

### 3.7 Исчерпание ресурсов

**Что проверять:**
- каждый контейнер в рабочей среде имеет CPU и memory `resources.requests`, чтобы scheduling отражал реальные потребности workload;
- каждый контейнер в рабочей среде имеет memory limit, чтобы ограничить node-level DoS и noisy-neighbor impact;
- CPU limits являются risk-based, а не blanket requirement; требуйте их, когда DoS/noisy-neighbor risk выше throttling/latency risk или когда этого требует platform policy;
- рабочие нагрузки, которые пишут temporary files, caches, logs, uploads, generated artifacts или batch output, имеют `ephemeral-storage` requests и limits;
- namespaces имеют `ResourceQuota` и, где нужно, `LimitRange`;
- alerting покрывает CPU/memory spikes, OOMKilled, throttling и restart loops.

**Рекомендация для рабочих сред:**
- используйте Pod Security playbook как canonical source для resource-constraint policy и исключений;
- запретить BestEffort pods в защищенных namespace;
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
- релизное развертывание идет по digest и проходит provenance/signature policy;
- история образа не содержит подозрительной последовательности загрузки и выполнения;
- batch/utility jobs не запускают образы из неутвержденных registry без владельца и provenance.

**Рекомендация для рабочих сред:**
- registry endpoints не должны быть доступны из general-purpose networks;
- audit logging registry events обязателен для релизных артефактов;
- deploy gate должен проверять digest, trusted builder identity, provenance/signature и policy outcome;
- блокируйте образы, которые скачивают и выполняют remote content во время build/startup без отдельного ревью.

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

**Рекомендация для рабочих сред:**
- `exec` в sensitive namespaces должен быть ограничен и audit-able;
- ephemeral containers разрешайте только support/SRE ролям с коротким сроком и отдельным журналированием;
- применяйте admission policy для запрета debug surfaces в high-value namespaces, где это операционно допустимо.

**Подтверждение:**
```bash
kubectl auth can-i create pods/exec --as=<subject> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=<subject> -n <ns>
# Kubernetes Events не являются надежным подтверждением exec. Проверяйте audit logs/SIEM:
# verb=create resource=pods subresource=exec|attach|portforward
# verb=update resource=pods subresource=ephemeralcontainers
kubectl get events -A --field-selector involvedObject.kind=Pod | grep -Ei 'ephemeral|debug'
```

### 3.10 Обнаружение и проверка политик

**Что проверять:**
- audit logs покрывают изменения RBAC, Secret reads, `exec`, ephemeral containers, admission denials и namespace label drift;
- runtime telemetry видит чтение sensitive paths, shell spawn, suspicious network tools, `nsenter`, host path access;
- admission policy блокирует известные unsafe patterns до развертывания.

**Рекомендация для рабочих сред:**
- используйте сценарии из offensive lab как тестовые случаи обнаружения, адаптируя их для безопасной staging-среды;
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
- general-purpose helper images и security toolboxes не появляются в защищенном namespace без change record и владельца.

**Рекомендация для рабочих сред:**
- не помещайте долгоживущие секреты в env vars для application рабочих нагрузок; используйте secret manager, workload identity или short-lived mounted учетные данные;
- выключайте `automountServiceAccountToken` и debug shell там, где они не нужны для runtime-функции;
- alert на запуск multi-tool images, неожиданных shell-процессов, package managers и network scanners в защищенных namespace.

**Подтверждение:**
Классификация: `безопасно в рабочей среде` для Kubernetes API metadata inventory; `только staging` для shell-based inspection; `требует согласования` перед выполнением команд в pods в рабочей среде.

```bash
# Не выводите значения environment variables. Проверяйте только имена/классы через approved debug path.
kubectl exec -n <ns> <pod> -- sh -c 'env | cut -d= -f1 | grep -Ei "TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AWS_|GOOGLE_|AZURE_"'
# Только staging/approved: shell-based runtime inspection затрагивает workload.
kubectl exec -n <ns> <pod> -- mount
kubectl exec -n <ns> <pod> -- cat /proc/self/cgroup
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" sa="}{.spec.serviceAccountName}{" automount="}{.spec.automountServiceAccountToken}{" image="}{.spec.containers[*].image}{"\n"}{end}'
```

### 3.12 Benchmark и ревью профиля защищенности

**Что проверять:**
- Docker/container runtime, kubelet, API server, RBAC, audit и усиление защиты node проверяются benchmark tooling, а не только ручным чтением YAML;
- kube-bench/CIS profile выбран под фактическую Kubernetes version и provider flavor; managed-service ограничения отмечены как исключение или not applicable;
- kubeaudit/Popeye или эквивалентные scanners находят privileged pods, missing limits, weak security context, stale references и hygiene debt;
- benchmark-замечания переводятся в backlog устранения с владельцем, severity и re-test подтверждением.

**Рекомендация для рабочих сред:**
- запускайте сканирование профиля защищенности регулярно и после platform upgrades;
- отделяйте exploitable misconfigurations от hygiene-замечаний, чтобы устранение не превращалось в шум;
- не считайте необработанный вывод scanner достаточной гарантией безопасности: подтверждайте критичные меры контроля целевыми validation-тестами из этого плейбука.

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

**Рекомендация для рабочих сред:**
- Helm v2/Tiller должен быть выведен из эксплуатации; для Helm v3 храните release state и учетные данные развертывания с минимально необходимыми правами;
- любые административные сервисы внутри кластера требуют явно назначенного владельца, сетевой изоляции, аутентификации, журналирования аудита и срока действия исключения;
- проверяйте legacy components после migration, incident cleanup и cluster upgrades.

**Подтверждение:**
```bash
kubectl get svc,deploy,sa,rolebinding,clusterrolebinding -A | grep -Ei 'tiller|dashboard|admin|operator'
kubectl auth can-i '*' '*' --as=system:serviceaccount:<ns>:<deploy-sa>
kubectl get clusterrolebinding -A -o wide
```

### 3.14 Дрейф `securityContext` рабочих нагрузок

**Что проверять:**
- application рабочие нагрузки на Linux nodes с AppArmor не запускаются с `appArmorProfile.type: Unconfined` и имеют подтверждение для `RuntimeDefault` или утвержденного `Localhost` profile;
- рабочие нагрузки не задают unsafe `spec.securityContext.sysctls` в обычных namespace приложений;
- `fsGroup`, `supplementalGroups` и `supplementalGroupsPolicy` не выдают широкое членство в группах без модели владения shared storage;
- sensitive рабочие нагрузки на Kubernetes `v1.33+` используют `supplementalGroupsPolicy: Strict`, если им нужна строгая модель групп.

**Рекомендация для рабочих сред:**
- проверяйте эти поля admission policy тестами, а не только ручным YAML ревью;
- запрещайте AppArmor `Unconfined` и unsafe sysctls по умолчанию; исключения оформляйте с владельцем, expiry, выделенным node pool там, где это нужно, и rollback plan;
- для group-based volume access фиксируйте контракт: какой GID нужен, какие paths доступны на запись, какие рабочие нагрузки разделяют storage и почему это допустимо.

**Подтверждение:**
Классификация: `безопасно в рабочей среде` для inventory и admission dry-run; `только staging` для runtime-проверок через `exec` в чувствительных рабочих нагрузках.

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" appArmorPod="}{.spec.securityContext.appArmorProfile.type}{" sysctls="}{.spec.securityContext.sysctls}{"\n"}{end}'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" appArmorContainers="}{.spec.containers[*].securityContext.appArmorProfile.type}{"\n"}{end}'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" appArmorInit="}{.spec.initContainers[*].securityContext.appArmorProfile.type}{" appArmorEphemeral="}{.spec.ephemeralContainers[*].securityContext.appArmorProfile.type}{"\n"}{end}'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" fsGroup="}{.spec.securityContext.fsGroup}{" supplementalGroups="}{.spec.securityContext.supplementalGroups}{" supplementalGroupsPolicy="}{.spec.securityContext.supplementalGroupsPolicy}{"\n"}{end}'
kubectl exec -n <ns> <pod> -- id
kubectl exec -n <ns> <pod> -- stat -c '%u:%g %a %n' <mounted-path>
```

---

## 4. Выходные артефакты ревью

Adversarial validation считается завершенной, когда есть:
- матрица сценариев и мер контроля для проверенных путей атаки;
- подтверждение для каждого proof target до и после устранения;
- список residual risks и исключений с владельцами/expiry;
- mapping между замечаниями и профильными плейбуками: Cluster Review, Pod Security, Container Escape, Seccomp, SLSA, Vault;
- re-test log, показывающий, что исправление закрыло исходный abuse path.

---

## 5. Связанные материалы в репозитории

- Ревью безопасности Kubernetes-кластера: [kubernetes/cluster-security-review/playbook.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/cluster-security-review/playbook/)
- Усиление безопасности Pod runtime: [kubernetes/pod-security/playbook.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/pod-security/playbook/)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/container-escape-capability-abuse/overview/)
- Чеклист ревью seccomp: [kubernetes/seccomp/checklist.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/seccomp/checklist/)
- SLSA provenance для container images: [supply-chain/slsa-provenance/overview.ru.md](/Product-security-playbook/ru/supply-chain/slsa-provenance/overview/)
- Kubernetes Secrets: [kubernetes/secrets/playbook.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/secrets/playbook/)
- Vault и секреты: [secrets/vault/playbook.ru.md](/Product-security-playbook/ru/platform-security/secrets/vault/playbook/)
