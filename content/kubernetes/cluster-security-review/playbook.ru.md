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
- доступ к Kubernetes API, admission-конфигах и namespace policy;
- токены ServiceAccount, application secrets, access к external secret store;
- audit trail для расследований.

**Типовой путь атакующего:**
- компрометация developer/CI identity;
- несанкционированный деплой или изменение policy;
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
- какие machine identities реально деплоят в production (CD controllers, CI bots).

**Сигналы риска:**
- пользователи или группы с `cluster-admin` без break-glass назначения;
- wildcard-права (`resources: ["*"]`, `verbs: ["*"]`) в production namespaces;
- возможность деплоя в production напрямую из human identity, минуя CD-процесс;
- доступ к `nodes/proxy`, `escalate`, `bind`, `impersonate` без отдельного security approval;
- monitoring/logging agents, которым выдан `nodes/proxy`, хотя для их функции достаточно fine-grained Kubelet API subresources.

**Рекомендация для production:**
- деплой в production только через выделенные CI/CD ServiceAccounts;
- human users не деплоят напрямую, кроме break-glass ролей с owner + expiry;
- ревью всех ClusterRole/ClusterRoleBinding каждые `30d`;
- автоматический fail policy для опасных RBAC-verb'ов вне allowlist (`escalate`, `bind`, `impersonate`, `serviceaccounts/token`, `nodes/proxy`);
- для Kubernetes `v1.36+`: `KubeletFineGrainedAuthz` находится в GA, feature gate locked/enabled, поэтому observability workload'ы должны использовать минимальные subresources (`nodes/metrics`, `nodes/stats`, `nodes/pods` и другие нужные endpoint'ы), а не общий `nodes/proxy`;
- запрещайте новые RBAC bindings на `nodes/proxy` для observability workload'ов, если их kubelet scraping/logging сценарий покрывается fine-grained правами.

**Минимальные команды для evidence:**
```bash
kubectl get clusterrolebindings,rolebindings -A
kubectl get clusterroles,roles -A -o yaml
kubectl auth can-i create deployments --as=<subject> -n <ns>
kubectl auth can-i get nodes/proxy --as=<subject>
kubectl auth can-i get nodes/metrics --as=<subject>
kubectl get clusterroles -o yaml | grep -n 'nodes/proxy'
curl -sk --header "Authorization: Bearer $TOKEN" https://$NODE_IP:10250/metrics \
  | grep 'kubernetes_feature_enabled{name="KubeletFineGrainedAuthz",stage="GA"} 1'
```

---

### 3.2 Цепочка деплоя

**Что проверять:**
- откуда приходит deployment intent (PR merge, release tag, manual apply);
- где выполняется build и кто подписывает артефакты;
- как выбирается image в манифесте (`digest` vs mutable tag);
- кто имеет право менять pipeline definition, CD projects и окружения;
- есть ли разделение обязанностей между автором кода и субъектом approve/release.

**Сигналы риска:**
- деплой из локального `kubectl apply` в production;
- использование mutable tags (`:latest`) в production;
- один и тот же субъект одновременно пишет код, меняет pipeline и проводит release;
- отсутствие артефактного provenance и верификации перед deploy.

**Рекомендация для production:**
- deploy только из CI/CD, изменение кластера из pipeline audit-able и replay-able;
- образы в production только по `@sha256` digest;
- branch protection + mandatory review для IaC/manifests и pipeline конфигураций;
- отдельные роли для `author`, `approver`, `releaser`.

---

### 3.3 Внешние и внутренние сервисы

**Что проверять:**
- все entry points в кластер: `Ingress`, `Gateway`, `LoadBalancer`, `NodePort`;
- список egress-зависимостей workload'ов (SaaS, cloud APIs, internal services);
- какие namespace/service могут общаться между собой по сети;
- есть ли фактический inventory сервисов и data-flows для production.

**Сигналы риска:**
- неизвестные публичные endpoints;
- отсутствие default-deny модели NetworkPolicy;
- критичные workloads с unrestricted egress;
- отсутствие owner у внешних интеграций.

**Рекомендация для production:**
- инвентарь north-south и east-west потоков обновляется не реже `30d`;
- для production namespaces: default deny + explicit allow rules;
- каждый публичный endpoint имеет owner, data-classification и SLA по уязвимостям.

---

### 3.4 Наблюдаемость для реагирования на инциденты

**Что проверять:**
- включен ли Kubernetes Audit Logging на уровне `kube-apiserver`;
- есть ли централизованный сбор audit logs, control-plane logs и runtime событий;
- покрываются ли события по RBAC/admission/namespace label changes/deployments;
- есть ли корреляция между CI/CD release event и фактическим API activity.

**Сигналы риска:**
- audit включен частично или хранится только локально на control-plane node;
- нет событий для критичных операций (`rolebindings`, `clusterrolebindings`, `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, `namespaces`);
- retention меньше длительности вашего typical incident lifecycle.

**Рекомендация для production:**
- централизованный immutable аудит с retention минимум `90d` (или выше по требованиям регулятора);
- для высокорисковых API-операций логируйте не ниже `Request`/`RequestResponse` уровня с учетом утечки чувствительных данных;
- детекция на события: изменение RBAC, webhook-конфигов, namespace security labels, массовое чтение Secret-объектов;
- дополняйте API audit поведенческой телеметрией runtime/сети (например, CNI observability и eBPF-инструменты), чтобы видеть не только факт deploy, но и аномальное runtime-поведение;
- drill по восстановлению timeline инцидента минимум раз в `90d`.

---

### 3.5 Границы Admission / RBAC / ServiceAccount

**Что проверять:**
- что критичные security rules enforced через admission (не через documentation-only требования);
- что RBAC покрывает read-операции на чувствительные ресурсы (admission не блокирует `get/list/watch`);
- что namespace label mutation ограничен (чтобы не ослабить PSA/NetworkPolicy boundaries);
- что `automountServiceAccountToken` отключен по умолчанию для workload'ов без доступа к API;
- что в production не используется namespace `default` ServiceAccount.

**Сигналы риска:**
- reliance только на mutating webhook без validating policy;
- developer роли могут менять `validatingwebhookconfigurations`/`mutatingwebhookconfigurations`;
- приложение может менять namespace labels и ослаблять enforce policy;
- ServiceAccount переиспользуется между несвязанными workload'ами.

**Рекомендация для production:**
- разделяйте ответственность: RBAC отвечает за "кто может", admission отвечает за "с какими параметрами";
- для policy enforcement используйте `ValidatingAdmissionPolicy` (Kubernetes `v1.30+`) или webhook-based equivalent;
- запретите доступ к `escalate` / `bind` / `impersonate` / `serviceaccounts/token` по умолчанию;
- для control-plane hardening отдельно оцените `AlwaysPullImages` с учетом операционного влияния, если он релевантен вашему окружению;
- рассматривайте `EventRateLimit` как зависящий от версии и способа поставки кластера: в upstream Kubernetes это alpha admission controller, отключенный по умолчанию; если alpha admission plugins неприемлемы, предпочитайте throttling API/events, поддерживаемый провайдером, или проверенную custom policy;
- требуйте по одному ServiceAccount на workload и quarterly recertification прав.

---

### 3.6 Поток секретов

**Что проверять:**
- где рождается секрет (source of truth), как он попадает в runtime, где ротируется;
- есть ли в Git plaintext/base64 секреты в манифестах;
- включено ли encryption at rest для Secret-данных в etcd;
- кто имеет `get/list/watch` к Secret в production;
- какой TTL у токенов/секретов и как проходит их отзыв (revocation).

**Сигналы риска:**
- секреты хранятся в repo или в values-файлах без внешнего secret manager;
- long-lived ServiceAccount token secrets используются как основной механизм;
- широкое `list/watch` на Secret для человеческих или CI identity;
- нет подтверждаемого процесса ротации и аварийного отзыва.

**Рекомендация для production:**
- используйте pull-модель из внешнего secret store (например, Vault) вместо хранения значений в манифестах;
- включите etcd encryption at rest и проверяйте статус после изменений control plane;
- ограничьте Secret ACL до минимально нужного набора workload identities;
- применяйте short-lived токены и регулярную ротацию секретов;
- если по операционным причинам используется push-модель (например, `sops`/`helm-secrets`), требуйте шифрование в Git, контролируемые ключи и запрет расшифровки вне доверенного CI/CD-контура;
- периодически проверяйте, что логирование не раскрывает чувствительные значения.

---

### 3.7 Проверка атакующих сценариев

**Что проверять:**
- проверены ли ключевые attack paths из позиции low-trust workload: service discovery, east-west reachability, ServiceAccount permissions, `NodePort` exposure, `exec`/ephemeral containers;
- есть ли evidence до и после remediation, а не только список YAML-настроек;
- используются ли detection/policy test cases для проверки audit, runtime telemetry и admission controls.

**Рекомендация для production:**
- проводите adversarial validation для production-like окружений после крупных изменений RBAC, CNI, admission policy, runtime security tooling и deployment chain;
- destructive, DoS и escape-проверки выполняйте только в изолированной среде или namespace с заранее утвержденным scope;
- используйте отдельный playbook для scenario-to-control mapping: [kubernetes/adversarial-validation/playbook.ru.md](../adversarial-validation/playbook.ru.md).

---

## 4. Минимальные policy gates для production

Минимальный набор, который должен быть включен в gatekeeping:
- запрет direct human deploy в production namespaces;
- запрет mutable image tags в production (`:latest` и эквиваленты);
- блокировка опасных RBAC-verb'ов вне явного allowlist;
- блокировка использования namespace `default` ServiceAccount для application workload'ов;
- обязательные namespace-level pod security labels и мониторинг их drift;
- исключения только через оформленный объект с `owner`, `justification`, `expiry`.

---

## 5. Выходные артефакты ревью

Ревью считается завершенным, когда есть:
- список всех субъектов деплоя и их фактических прав;
- схема цепочки деплоя с trust boundaries и control points;
- инвентарь внешних/внутренних сервисных взаимодействий;
- карта observability coverage для IR (что логируется и где хранится);
- матрица Admission/RBAC/ServiceAccount responsibilities;
- карта secrets flow с TTL/rotation/revocation и владельцами.

---

## 6. Антипаттерны

- Один shared `cluster-admin` аккаунт для команды.
- Production deploy через локальный kubeconfig разработчика.
- Admission rules без контроля RBAC read-доступа к чувствительным ресурсам.
- RBAC least privilege без защиты admission/webhook конфигов.
- Общий ServiceAccount на все приложения namespace.
- Секреты в Git (включая base64 в YAML) как штатный процесс.
- Отсутствие проверяемого incident timeline по данным audit/logging.

---

## 7. Связанные материалы в репозитории

- Pod runtime hardening: [kubernetes/pod-security/playbook.ru.md](../pod-security/playbook.ru.md)
- Kubernetes adversarial validation: [kubernetes/adversarial-validation/playbook.ru.md](../adversarial-validation/playbook.ru.md)
- Seccomp review checklist: [kubernetes/seccomp/checklist.ru.md](../seccomp/checklist.ru.md)
- Container escape / capabilities: [kubernetes/container-escape-capability-abuse/overview.ru.md](../container-escape-capability-abuse/overview.ru.md)
- Vault и секреты: [secrets/vault/playbook.ru.md](../../secrets/vault/playbook.ru.md)
- OIDC/OAuth для machine/human access patterns: [identity/oidc-oauth/playbook.ru.md](../../identity/oidc-oauth/playbook.ru.md)
