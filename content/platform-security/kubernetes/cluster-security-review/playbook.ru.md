# Плейбук ревью безопасности Kubernetes-кластера

## 1. Область и цель

Этот плейбук описывает **практическое ревью безопасности Kubernetes-кластера** на уровне:
- субъектов деплоя (human и machine identities);
- цепочки поставки и деплоя;
- внешних и внутренних сервисных границ;
- observability для Incident Response;
- границ Admission / RBAC / ServiceAccount;
- потока секретов от источника до runtime.

**Цель:**
- сократить вероятность несанкционированного деплоя и скрытого privilege escalation;
- уменьшить blast radius при компрометации workload или CI/CD;
- обеспечить воспроизводимое расследование инцидентов по данным кластера.

---

## 2. Модель угроз для ревью безопасности кластера

**Что защищаем:**
- права деплоя и изменения конфигурации кластера;
- цепочку `source -> build -> registry -> deploy`;
- доступ к Kubernetes API, admission-конфигурациям и namespace policy;
- токены ServiceAccount, application secrets, доступ к external secret store;
- audit trail для расследований.

**Типовой путь атакующего:**
- компрометация developer/CI identity;
- несанкционированное развертывание или изменение политики;
- закрепление через RBAC/admission drift;
- извлечение секретов и lateral movement.

---

## 3. Домены ревью и проверки

### 3.1 Кто может деплоить

**Что проверять:**
- кто имеет `create/update/patch/delete` на workload-ресурсы (`deployments`, `statefulsets`, `daemonsets`, `jobs`, `cronjobs`, `pods`);
- кто имеет права на `pods/exec`, `pods/ephemeralcontainers`, `pods/attach`, `pods/portforward`;
- кто может менять `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`;
- кто имеет доступ к `nodes/proxy` (широкий node-level доступ к Kubelet API);
- кто имеет доступ к fine-grained Kubelet API subresources: `nodes/metrics`, `nodes/stats`, `nodes/log`, `nodes/spec`, `nodes/checkpoint`, `nodes/configz`, `nodes/healthz`, `nodes/pods`;
- какие machine identities реально деплоят в рабочую среду (CD controllers, CI bots).

**Сигналы риска:**
- пользователи или группы с `cluster-admin` без break-glass назначения;
- wildcard-права (`resources: ["*"]`, `verbs: ["*"]`) в защищенных namespace;
- возможность деплоя в рабочую среду напрямую из human identity, минуя CD-процесс;
- доступ к `nodes/proxy`, `escalate`, `bind`, `impersonate` без отдельного согласования безопасности;
- monitoring/logging agents, которым выдан `nodes/proxy`, хотя для их функции достаточно fine-grained Kubelet API subresources.

**Рекомендация для рабочих сред:**
- развертывание в рабочую среду только через выделенные CI/CD ServiceAccounts;
- human users не деплоят напрямую, кроме break-glass ролей с владельцем + expiry;
- ревью всех ClusterRole/ClusterRoleBinding каждые `30d`;
- автоматический fail policy для опасных RBAC-глаголов вне allowlist (`escalate`, `bind`, `impersonate`, `serviceaccounts/token`, `nodes/proxy`);
- для Kubernetes `v1.36+`: `KubeletFineGrainedAuthz` находится в GA, feature gate locked/enabled, поэтому observability рабочие нагрузки должны использовать минимальные subresources (`nodes/metrics`, `nodes/stats`, `nodes/pods` и другие нужные эндпоинты), а не общий `nodes/proxy`;
- запрещайте новые RBAC bindings на `nodes/proxy` для observability рабочих нагрузок, если их kubelet scraping/logging сценарий покрывается fine-grained правами.
- primary подтверждения для сокращения `nodes/proxy`: `kubectl auth can-i get nodes/metrics|nodes/stats|nodes/pods --as=<subject>` и аналогичные проверки фактически нужных kubelet endpoints;
- secondary подтверждения: версия Kubernetes, документация managed-provider, конфигурация авторизации kubelet и vendor release notes для точной minor-версии кластера;
- если fine-grained subresources недоступны или заблокированы конкретной поставкой кластера, `nodes/proxy` допустим только как exception с владельцем, expiry, минимальным subject scope и отдельным blast-radius ревью.

**Минимальные команды для подтверждения:**
```bash
kubectl get clusterrolebindings,rolebindings -A
kubectl get clusterroles,roles -A -o yaml
kubectl get validatingadmissionpolicy,validatingadmissionpolicybinding -o yaml
kubectl auth can-i create deployments --as=<subject> -n <ns>
kubectl auth can-i get nodes/proxy --as=<subject>
kubectl auth can-i get nodes/metrics --as=<subject>
kubectl auth can-i get nodes/stats --as=<subject>
kubectl auth can-i get nodes/pods --as=<subject>
kubectl get clusterroles -o yaml | grep -n 'nodes/proxy'
# Вторичные подтверждения зависят от provider и способа развертывания:
# соберите Kubernetes minor version, kubelet authorization configuration и managed-provider release notes
```

---

### 3.2 Цепочка деплоя

**Что проверять:**
- откуда приходит намерение развертывания (PR merge, release tag, manual apply);
- где выполняется build и кто подписывает артефакты;
- как выбирается image в манифесте (`digest` vs mutable tag);
- кто имеет право менять pipeline definition, CD projects и окружения;
- есть ли разделение обязанностей между автором кода и субъектом approve/release.

**Сигналы риска:**
- развертывание из локального `kubectl apply` в рабочей среде;
- использование tag-only ссылок на image в рабочей среде, включая version-like tags вроде `:v1.2.3`;
- один и тот же субъект одновременно пишет код, меняет pipeline и проводит релиз;
- отсутствие артефактного provenance и верификации перед развертыванием.

**Рекомендация для рабочих сред:**
- развертывание только из CI/CD, изменение кластера из pipeline audit-able и replay-able;
- образы для рабочей среды только по `@sha256` digest;
- branch protection + mandatory ревью для IaC/manifests и pipeline конфигураций;
- отдельные роли для `author`, `approver`, `releaser`.

---

### 3.3 Внешние и внутренние сервисы

**Что проверять:**
- все entry points в кластер: `Ingress`, `Gateway`, `LoadBalancer`, `NodePort`;
- какие ingress controllers и Gateway API implementations установлены, кто владеет их `IngressClass`/`GatewayClass`, и какие namespace могут прикреплять routes;
- Service objects с заполненным `spec.externalIPs`;
- список egress-зависимостей рабочих нагрузок (SaaS, cloud APIs, internal services);
- какие namespace/service могут общаться между собой по сети;
- есть ли фактический inventory сервисов и data-flows для рабочих сред.

**Сигналы риска:**
- неизвестные публичные endpoints;
- новый production exposure строится на community `ingress-nginx` controller без инвентаря controller, ownership, отслеживания patch и migration plan на случай объявленного EOL/retirement;
- использование `Service.spec.externalIPs` в рабочих или multi-tenant кластерах;
- отсутствие default-deny модели NetworkPolicy;
- критичные workloads с unrestricted egress;
- отсутствие владельца у внешних интеграций.

**Рекомендация для рабочих сред:**
- инвентарь north-south и east-west потоков обновляется не реже `30d`;
- для защищенных namespace: default deny + explicit allow rules;
- каждый публичный endpoint имеет владельца, data-classification и SLA по уязвимостям;
- не считайте Ingress API deprecated: ресурс Ingress остается поддерживаемым, но его feature set заморожен. Для новых сложных L7/L4 edge-сценариев и долгосрочного развития предпочитайте Gateway API с явно выбранной реализацией и проверка безопасности.
- разделяйте `Ingress` resource и конкретный controller. CVE и security fixes обычно относятся к controller implementation, webhook, data plane или admission path, а не к самому API object `Ingress`. Для community Kubernetes `ingress-nginx` фиксируйте явное lifecycle decision: inventory IngressClass/controller развертывания, owned public endpoints, critical annotations, custom snippets, поведение аутентификации и TLS, upstream support status, patch cadence и replacement target. Если объявлен EOL/retirement или patch cadence больше не соответствует production SLA, оставаться на нем означает accepted exposure и требует владельца, expiry, компенсирующие меры и migration deadline. Новые production развертывания на этом controller допустимы только как exception с владельцем, expiry и patch/rollback plan.
- для Gateway API используйте отдельный security baseline ниже. Namespace не должен иметь возможность прикрепить route к shared/public Gateway или сослаться на backend/TLS secret другого namespace без явного разрешения владельца соответствующего ресурса.
- запрещайте новые `Service.spec.externalIPs` через admission policy: `DenyServiceExternalIPs`, `ValidatingAdmissionPolicy` или проверенный policy engine. В Kubernetes `v1.36+` это поле deprecated; исторически оно небезопасно по умолчанию, потому что пользователь с правом создавать или менять Service может перехватывать трафик к выбранному IP при выполнении условий CVE-2020-8554.
- для существующих `externalIPs` заведите migration plan с владельцем и сроком. Предпочтительные целевые варианты: управляемый `type: LoadBalancer`, ingress/Gateway API для HTTP(S)/L4-входа, либо `NodePort` только за внешним балансировщиком/фаерволом с явным ownership IP-адресов и сетевых ACL.
- не заменяйте `externalIPs` ручным patch `status.loadBalancer.ingress` без отдельной модели прав: `services/status` должен оставаться privileged operation, недоступной обычным deploy identities.

**Gateway API security baseline:**
- `GatewayClass` считается platform-owned объектом. Право создавать или менять `GatewayClass` и controller parameters должно быть доступно только platform/security владельцы, потому что оно выбирает controller implementation и trust boundary.
- `Gateway` для shared/public edge должен находиться в platform-owned namespace. Application namespaces получают право прикреплять `HTTPRoute`/`GRPCRoute`/`TCPRoute` только через явно настроенный `allowedRoutes` на нужном listener.
- `allowedRoutes` должен быть максимально узким: `Same` для single-tenant Gateway, `Selector` только с управляемыми labels и admission-защитой от самовольной смены labels, `All` недопустим для shared/public Gateway без отдельного risk acceptance.
- Ссылки между namespace требуют `ReferenceGrant` в namespace владельца целевого ресурса. Это относится к backend-сервисам, TLS-секретам и другим целевым ресурсам; отсутствие `ReferenceGrant` должно делать маршрут или ссылку недействительными, а не приводить к неявному резервному поведению.
- TLS termination policy фиксирует, где завершается TLS, какие certificate sources разрешены, кто может ссылаться на TLS Secret, какие protocols/ciphers/min TLS version применяются в controller implementation и как выполняется rotation.
- Hostname и listener scope должны быть ограничены: route из application namespace не должен захватывать wildcard hostname, чужой domain, privileged path prefix или listener другого tenant без согласования владельца Gateway.
- Route status conditions должны мониториться как security signal: `Accepted=False`, `ResolvedRefs=False`, неожиданная смена parentRefs, backendRefs или hostnames требует ревью до production traffic.
- Policy attachment (authn/authz, WAF, rate limits, header normalization, CORS, request size, timeout, retry) должен иметь владелец и precedence model. Не полагайтесь на controller-specific defaults без явного подтверждения.
- При миграции с `ingress-nginx` не переносите annotations механически. Для каждой критичной annotation (`auth`, `rewrite`, `configuration-snippet`, body size, buffering, proxy headers, TLS, redirects) фиксируйте Gateway API equivalent, неподдерживаемое поведение или compensating control.

**Минимальные команды для подтверждения:**
```bash
kubectl get services -A -o jsonpath='{range .items[?(@.spec.externalIPs)]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.spec.externalIPs}{"\n"}{end}'
kubectl auth can-i patch services/status --as=<subject> -n <ns>
kubectl get ingressclass,gatewayclass
kubectl get ingress -A
kubectl get gateway,httproute,tcproute,tlsroute,referencegrant -A
kubectl get gateway -A -o yaml
kubectl get httproute,grpcroutes,tcproutes,tlsroutes -A -o yaml
kubectl auth can-i create gatewayclass --as=<subject>
kubectl auth can-i create referencegrant --as=<subject> -n <target-ns>
```

---

### 3.4 Наблюдаемость для реагирования на инциденты

**Что проверять:**
- включен ли Kubernetes Audit Logging на уровне `kube-apiserver`;
- есть ли централизованный сбор audit logs, control-plane logs и runtime событий;
- охватываются ли события изменения RBAC, admission, меток namespace и развертываний;
- есть ли корреляция между CI/CD release event и фактическим API activity.

**Сигналы риска:**
- audit включен частично или хранится только локально на control-plane node;
- нет событий для критичных операций (`rolebindings`, `clusterrolebindings`, `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, `namespaces`);
- retention меньше длительности вашего typical incident lifecycle.

**Рекомендация для рабочих сред:**
- централизованный immutable аудит с retention минимум `90d` (или выше по требованиям регулятора);
- для высокорисковых API-операций логируйте не ниже `Request`/`RequestResponse` уровня с учетом утечки чувствительных данных;
- детекция на события: изменение RBAC, webhook-конфигов, namespace security labels, массовое чтение Secret-объектов;
- дополняйте API audit поведенческой телеметрией runtime/сети (например, CNI observability и eBPF-инструменты), чтобы видеть не только факт deploy, но и аномальное runtime-поведение;
- drill по восстановлению timeline инцидента минимум раз в `90d`.

---

### 3.5 Границы Admission / RBAC / ServiceAccount

**Что проверять:**
- что критичные правила безопасности принудительно применяются через admission, а не существуют только в документации;
- что RBAC покрывает read-операции на чувствительные ресурсы (admission не блокирует `get/list/watch`);
- что namespace label mutation ограничен (чтобы не ослабить PSA/NetworkPolicy boundaries);
- что `automountServiceAccountToken` отключен по умолчанию для рабочих нагрузок без доступа к API;
- что в рабочей среде не используется namespace `default` ServiceAccount.

**Сигналы риска:**
- reliance только на mutating webhook без validating policy;
- developer роли могут менять `validatingwebhookconfigurations`/`mutatingwebhookconfigurations`;
- приложение может менять namespace labels и ослаблять enforce policy;
- ServiceAccount переиспользуется между несвязанными рабочими нагрузками.

**Рекомендация для рабочих сред:**
- разделяйте ответственность: RBAC отвечает за "кто может", admission отвечает за "с какими параметрами";
- для policy enforcement используйте `ValidatingAdmissionPolicy` (Kubernetes `v1.30+`) или webhook-based equivalent;
- для защищенных namespace admission policy должна реально enforce, а не только audit/warn: `ValidatingAdmissionPolicyBinding.validationActions` включает `Deny`, `failurePolicy` остается `Fail`, а parameterized policies используют `parameterNotFoundAction: Deny`, если отсутствие параметра должно блокировать небезопасный default;
- запретите доступ к `escalate` / `bind` / `impersonate` / `serviceaccounts/token` по умолчанию;
- для усиления защиты control plane отдельно оцените `AlwaysPullImages` с учетом операционного влияния, если он релевантен вашему окружению. Он снижает reuse локально закешированного image без повторной проверки pull authorization, но усиливает зависимость от registry availability и может ломать air-gapped или registry-outage сценарии. Он не заменяет digest pinning и signature/provenance verification: свежий pull mutable tag все равно может подтянуть нежелательный artifact;
- рассматривайте `EventRateLimit` как зависящий от версии и способа поставки кластера: в upstream Kubernetes это alpha admission controller, отключенный по умолчанию; если alpha admission plugins неприемлемы, предпочитайте throttling API/events, поддерживаемый провайдером, или проверенную custom policy;
- требуйте по одному ServiceAccount на workload и quarterly recertification прав.

---

### 3.6 Поток секретов

**Что проверять:**
- где рождается секрет (source of truth), как он попадает в runtime, где выполняется его ротация;
- есть ли в Git plaintext/base64 секреты в манифестах;
- включено ли encryption at rest для Secret-данных в etcd;
- кто имеет `get/list/watch` к Secret в рабочей среде;
- где хранятся registry pull учетные данные, какие ServiceAccounts подключают `imagePullSecrets` и являются ли учетные данные pull-only и scoped;
- какой TTL у токенов/секретов и как проходит их отзыв (revocation).

**Сигналы риска:**
- plaintext/base64 секреты хранятся в репозитории, values-файлах, rendered manifests или CI artifacts;
- Kubernetes Secret используется для high-value runtime secrets без подтвержденного etcd encryption at rest, строгого RBAC, audit и владельца;
- External Secrets Operator или другой sync-процесс создает Kubernetes Secret без реальной необходимости совместимости;
- long-lived ServiceAccount token secrets используются как основной механизм;
- широкое `list/watch` на Secret для человеческих или CI identity;
- broad или push-capable учетные данные реестра подключены как `imagePullSecrets`, особенно на shared или default ServiceAccounts;
- нет подтверждаемого процесса ротации и аварийного отзыва.

**Рекомендация для рабочих сред:**
- для high-value runtime secrets предпочитайте доставку только файлами из внешнего secret store (например, Vault Agent Injector или Secrets Store CSI), чтобы не синхронизировать значения в Kubernetes Secret objects;
- используйте встроенный Kubernetes Secret для секретов low/medium-value только при включенных etcd encryption at rest, строгом RBAC, audit и безопасной модели доставки;
- если приложение или платформа требуют Kubernetes Secret object через External Secrets Operator или похожий sync-механизм, считайте это более высоким уровнем раскрытия и применяйте те же проверки, что для встроенного Secret;
- включите etcd encryption at rest и проверяйте статус после изменений control plane;
- ограничьте Secret ACL до минимально нужного набора workload identities;
- применяйте short-lived токены и регулярную ротацию секретов;
- ограничивайте registry pull учетные данные минимальным repository и pull-only permission set; где возможно, предпочитайте provider-supported credential providers вместо long-lived `imagePullSecrets`;
- если по операционным причинам используется encrypted-at-source push-модель (например, `sops`/`helm-secrets`), требуйте контролируемые ключи, ревью и запрет расшифровки вне доверенного CI/CD-контура;
- периодически проверяйте, что журналирование не раскрывает чувствительные значения.

---

### 3.7 Проверка атакующих сценариев

**Что проверять:**
- проверены ли ключевые attack paths из позиции low-trust workload: service discovery, east-west reachability, ServiceAccount permissions, `NodePort` exposure, `exec`/ephemeral containers;
- есть ли подтверждения до и после устранения, а не только список YAML-настроек;
- используются ли тестовые сценарии обнаружения и политик для проверки audit, runtime telemetry и меры admission-контроля.

**Рекомендация для рабочих сред:**
- проводите adversarial validation для похожих на рабочие окружений после крупных изменений RBAC, CNI, admission policy, runtime security tooling и цепочка развертывания;
- destructive, DoS и escape-проверки выполняйте только в изолированной среде или namespace с заранее утвержденной областью;
- используйте отдельный playbook для scenario-to-control mapping: [kubernetes/adversarial-validation/playbook.ru.md](../adversarial-validation/playbook.ru.md).

---

## 4. Минимальные policy gates для рабочих сред

Минимальный набор, который должен быть включен в gatekeeping:
- запрет direct human deploy в защищенных namespace;
- запрет tag-only images в рабочей среде и требование immutable digest reference (`@sha256:...`); формат `tag@sha256` допустим для читаемости, но развертывание должен использовать именно digest;
- блокировка опасных RBAC-глаголов вне явного allowlist;
- обязательный ingress и egress default-deny NetworkPolicy для защищенных namespace либо документированная CNI-equivalent policy с проверенным enforcement;
- блокировка новых Service objects с `spec.externalIPs`; существующие использования допускаются только как миграционное исключение с `owner`, `expiry`, подтвержденным ownership внешнего IP и планом перехода на `LoadBalancer`, Gateway API/Ingress или контролируемый `NodePort`;
- инвентарь ingress controllers и Gateway API implementations; для community `ingress-nginx` controller - migration plan или exception с владельцем/expiry; для Gateway API - policy gate на `allowedRoutes`, cross-namespace `ReferenceGrant`, TLS secret ownership и route attachment к shared Gateway;
- обязательный Kubernetes audit logging с покрытием изменения RBAC, изменения admission/webhook, изменений namespace security labels, Secret reads, `exec`, attach/port-forward и обновлений ephemeral containers;
- ограничение и периодическая recertification доступа `get/list/watch` к Secrets в рабочей среде;
- `automountServiceAccountToken: false` по умолчанию, если у workload нет документированной необходимости обращаться к Kubernetes API;
- блокировка использования namespace `default` ServiceAccount для application рабочих нагрузок;
- для защищенных namespace по умолчанию enforce Pod Security Standards `restricted`:
  - `pod-security.kubernetes.io/enforce: restricted`
  - `pod-security.kubernetes.io/enforce-version: <pinned Kubernetes minor version>`
  - `pod-security.kubernetes.io/audit: restricted`
  - `pod-security.kubernetes.io/audit-version: <same pinned version>`
  - `pod-security.kubernetes.io/warn: restricted`
  - `pod-security.kubernetes.io/warn-version: <same pinned version>`;
- требуйте подтверждение effective seccomp-профиля, а не только namespace labels: enforced `restricted` admission должен отклонять рабочие нагрузки без явного `RuntimeDefault` или утвержденного `Localhost`; namespace с `baseline`, custom policy или временными исключениями должны либо требовать явные seccomp fields, либо доказывать kubelet `--seccomp-default` / `seccompDefault`, чтобы unspecified profiles становились `RuntimeDefault`;
- не считайте этот список полным baseline для workload `securityContext`; детальные требования к capabilities, AppArmor/SELinux, sysctls, группам, volumes и user namespaces ведите по [Kubernetes Pod Security playbook](../pod-security/playbook.ru.md);
- используйте `warn`/`audit=restricted` без `enforce=restricted` только во время документированного rollout или migration window с владельцем, expiry и blocking date для включения enforcement;
- мониторьте drift Pod Security labels и блокируйте развертывание, если labels рабочей среды ослаблены, удалены или указывают на неутвержденную версию;
- проверяйте admission policy тестами, что рабочие нагрузки без image digest отклоняются, включая `:latest`, version-like tags и image names без явного tag;
- проверка etcd Secret encryption at rest там, где команда владеет control plane или может его конфигурировать;
- исключения только через оформленный объект с `owner`, `justification`, `expiry`.

---

## 5. Выходные артефакты ревью

Ревью считается завершенным, когда есть:
- список всех субъектов деплоя и их фактических прав;
- схема цепочки развертывания с trust boundaries и control points;
- инвентарь внешних/внутренних сервисных взаимодействий;
- карта observability coverage для IR (что логируется и где хранится);
- матрица Admission/RBAC/ServiceAccount responsibilities;
- карта secrets flow с TTL/rotation/revocation и владельцами.

---

## 6. Антипаттерны

- Один shared `cluster-admin` аккаунт для команды.
- Релизное развертывание через локальный kubeconfig разработчика.
- Admission rules без контроля RBAC read-доступа к чувствительным ресурсам.
- RBAC least privilege без защиты admission/webhook конфигов.
- `Service.spec.externalIPs` как штатный способ публикации сервиса наружу.
- community `ingress-nginx` controller как новый production default без migration plan и ownership.
- Общий ServiceAccount на все приложения namespace.
- Секреты в Git (включая base64 в YAML) как штатный процесс.
- Отсутствие проверяемого incident timeline по данным audit/logging.

---

## 7. Связанные материалы в репозитории

- Усиление защиты Pod runtime: [kubernetes/pod-security/playbook.ru.md](../pod-security/playbook.ru.md)
- Kubernetes adversarial validation: [kubernetes/adversarial-validation/playbook.ru.md](../adversarial-validation/playbook.ru.md)
- Seccomp ревью checklist: [kubernetes/seccomp/checklist.ru.md](../seccomp/checklist.ru.md)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.ru.md](../container-escape-capability-abuse/overview.ru.md)
- Kubernetes Secrets: [kubernetes/secrets/playbook.ru.md](../secrets/playbook.ru.md)
- Vault и секреты: [secrets/vault/playbook.ru.md](../../secrets/vault/playbook.ru.md)
- OIDC/OAuth для machine/human access patterns: [identity/oidc-oauth/playbook.ru.md](../../../application-security/identity/oidc-oauth/playbook.ru.md)
