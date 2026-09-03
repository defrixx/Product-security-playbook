# Плейбук безопасности Kubernetes Secrets

## 1. Область и цель

Этот плейбук описывает защиту встроенных Kubernetes-объектов `Secret` и путь доставки секретов в runtime для рабочих нагрузок.

**В области:**
- объекты `Secret`, их использование через volumes и переменные окружения;
- хранение Secret-данных в etcd и на worker nodes;
- RBAC, ServiceAccount и косвенный доступ к Secret через создание Pod;
- учетные данные реестра, хранящиеся как `imagePullSecrets` и подключаемые через Pod specs или ServiceAccounts;
- выбор между встроенными Kubernetes Secrets и внешним secret manager;
- проверки для production ревью, CI/CD policy и реагирования на инциденты.

**Вне области:**
- полный hardening Kubernetes-кластера;
- общий Pod Security baseline;
- детальная эксплуатация Vault, KMS или облачного secret manager;
- управление жизненным циклом учетных данных на уровне приложения вне Kubernetes.

**Цель:**
- не допустить случайного раскрытия секретов через Git, манифесты, логи, debug tooling и широкие роли;
- ограничить blast radius при компрометации workload или namespace identity;
- сделать требования к Kubernetes Secrets проверяемыми через RBAC, admission, audit и runtime-подтверждения.

---

## 2. Модель угроз

**Что защищаем:**
- учетные данные приложений, API-ключи, пароли баз данных, signing material и private keys;
- ServiceAccount tokens и учетные данные, полученные через интеграцию с внешним secret manager;
- container учетные данные реестра, используемые через `imagePullSecrets`;
- snapshots etcd, control-plane storage, файловую систему worker nodes и runtime memory;
- audit trail чтения и изменения Secret-объектов, а также намерение развертывания.

**Типовые атакующие:**
- скомпрометированное приложение внутри Pod;
- пользователь или CI identity с избыточным RBAC в namespace;
- оператор с доступом к файловой системе node или backups etcd;
- supply-chain или debug-процесс, который собирает env, manifests, logs или artifacts.

**Сценарии с высоким влиянием:**
- субъект имеет `list` или `watch` на `secrets` и получает содержимое всех Secret в namespace, хотя прямое чтение одного объекта не было задумано;
- субъект может создавать Pod в namespace, монтирует любой доступный Secret в новый Pod и обходит отсутствие прямого `get secrets`;
- Secret хранится как base64 в Git, Helm values, rendered manifests или CI artifacts и фактически становится plaintext для всех читателей этого контура;
- privileged Pod или произвольный `hostPath` получает доступ к Secret volumes других Pod на той же node;
- широкий `imagePullSecret` подключен к shared ServiceAccount и позволяет несвязанным рабочим нагрузкам pull private images или enumerate registry content вне их release boundary;
- Secret попадает в переменные окружения и утекает через debug dumps, error reports, инспекцию процессов или observability pipeline.

---

## 3. Базовые требования для production

### 3.1 Использование Kubernetes Secret вместо ConfigMap

Значения секретов должны храниться в `Secret`, а не в `ConfigMap`, annotations, labels, command arguments или произвольных custom resources.

`Secret.data` использует base64 encoding только как формат сериализации. Это не шифрование и не дополнительная защита. Любой Secret manifest с реальным значением считается чувствительным артефактом.

**Базовые требования:**
- запрещайте plaintext/base64 Secret manifests в Git, Helm values и CI artifacts;
- допускайте encrypted-at-source подходы (`sops`, sealed/encrypted manifests, provider-specific encryption) только с контролируемыми ключами, ревью и запретом локальной расшифровки вне доверенного CI/CD;
- не используйте `ConfigMap` для passwords, tokens, certificates, private keys, OAuth client secrets, webhook secrets или учетных данных database;
- если существующий `ConfigMap` содержит sensitive value, считайте значение скомпрометированным и ротируйте его после миграции.

### 3.2 Доставка в Pod: сначала файлы, env только по исключению

Для production рабочих нагрузок предпочтительный способ доставки Secret в приложение - read-only файл через volume или интеграцию с внешним secret manager, а не переменная окружения.

Переменные окружения допустимы только тогда, когда приложение не поддерживает файловый источник и владелец сервиса принял риск. Env часто попадает в crash reports, debug output, process metadata, support bundles и APM/logging pipelines.

**Базовые требования:**
- монтируйте Secret только в контейнеры, которым он реально нужен;
- задавайте `readOnly: true` для Secret volume mounts;
- не используйте `subPath` для Secret, если приложение ожидает автоматическое обновление значения;
- не передавайте Secret в container args, command line flags или startup scripts, которые логируются;
- для high-value секретов запрещайте env-доставку без владельца, expiry, компенсирующих контролей и migration plan.

### 3.3 RBAC и граница namespace

Права на `secrets` не являются обычными правами чтения. `get`, `list` и `watch` раскрывают содержимое Secret, а не только metadata.

Создание Pod в namespace тоже является чувствительным правом: субъект, который может создать Pod, часто может смонтировать Secret этого namespace и прочитать его через созданный workload. Поэтому `create pods`, `create deployments`, `update deployments`, `pods/exec` и `pods/ephemeralcontainers` нужно рассматривать вместе с прямыми Secret permissions.

**Базовые требования:**
- не выдавайте `get/list/watch secrets` human users и CI identities по умолчанию;
- выделяйте отдельный ServiceAccount на workload и не переиспользуйте его между несвязанными сервисами;
- запрещайте default ServiceAccount для application рабочих нагрузок;
- `automountServiceAccountToken: false` по умолчанию для рабочих нагрузок без Kubernetes API access;
- считайте объекты `kubernetes.io/service-account-token` legacy долгоживущие учетные данные; не создавайте их для application рабочих нагрузок по умолчанию;
- предпочитайте TokenRequest API или projected ServiceAccount tokens с явным `audience` и коротким expiration для рабочих нагрузок, которым нужен Kubernetes API или интеграция с внешней аутентификацией;
- любой вручную созданный long-lived ServiceAccount token Secret требует владельца, expiry или дата пересмотра, break-glass/migration justification, access ревью и проверенного пути rotation/revocation;
- `pods/exec`, `pods/ephemeralcontainers`, `serviceaccounts/token`, `escalate`, `bind`, `impersonate`, `get/list/watch secrets` требуют отдельного согласования;
- ежеквартально пересматривайте права ServiceAccount в рабочих средах;
- namespace с высокоценными Secret не должен быть shared namespace для произвольных рабочих нагрузок.

### 3.4 Хранение в etcd и на worker nodes

Kubernetes хранит Secret как API objects в etcd. Для production включайте encryption at rest для Secret data и проверяйте после изменения конфигурации, что новые и существующие объекты действительно зашифрованы.

Encryption at rest снижает риск чтения etcd storage, disks и backups, но не защищает от субъекта, который может читать Secret через Kubernetes API, и не решает проблему node-level компрометации после доставки Secret в Pod.

**Базовые требования:**
- включайте at-rest encryption для `secrets` во всех production кластерах;
- используйте KMS provider или managed control-plane encryption там, где это поддерживается и операционно устойчиво;
- ограничивайте доступ к etcd endpoints, snapshots, backup storage и control-plane node filesystem;
- регулярно тестируйте restore/rotation для encryption configuration и KMS keys;
- задавайте `immutable: true` для static Secrets, которые должны меняться только через versioned rollout; не используйте это для Secrets, которые ротируются in place или обновляются контроллером;
- запрещайте arbitrary `hostPath`, privileged workloads и debug containers в namespaces, где работают workloads с высокоценными Secret.

### 3.5 Secret при передаче и доступ к control plane

Передача Secret между API server, etcd, kubelet и node должна идти по защищенным каналам с корректной аутентификацией компонентов. В managed Kubernetes часть control-plane гарантий обеспечивает провайдер, но команда всё равно отвечает за RBAC, audit и модель доставки секретов в workload.

**Базовые требования:**
- kubelet, API server и etcd endpoints не доступны из application namespaces напрямую;
- клиентские учетные данные kubelet, учетные данные etcd API server и сертификаты control plane защищены как high-value secrets;
- node access считается потенциальным доступом к Secret рабочих нагрузок на этой node;
- multi-tenant workloads с разными trust boundaries разделяются node pools, taints/tolerations, runtime policy и NetworkPolicy.

### 3.6 Внешние secret managers

Внешний secret manager не является автоматической заменой Kubernetes Secret. Он полезен, когда нужен более сильный lifecycle: динамические учетные данные, централизованный audit, short TTL, revocation, separation of duties, HSM/KMS-backed protection или единая модель для Kubernetes и не-Kubernetes потребителей.

**Модель выбора:**
- Встроенный Kubernetes Secret подходит для секретов low/medium-value, если включены encryption at rest, строгий RBAC, audit и безопасная delivery model.
- Vault Agent Injector или доставка Secrets Store CSI только файлами предпочтительны для high-value runtime secrets, потому что значения можно не синхронизировать в Kubernetes Secret objects.
- External Secrets Operator подходит, когда приложение или платформа требуют Kubernetes Secret object; это повышает риск раскрытия и требует etcd encryption, RBAC ревью и audit.
- Dynamic учетные данные предпочтительнее long-lived static secrets, если downstream system поддерживает TTL, lease и revoke.

### 3.7 Учетные данные реестра и imagePullSecrets

Registry pull учетные данные - это Secret с прямым влиянием на software supply chain. Субъект, который может читать или переиспользовать широкий `imagePullSecret`, может pull private images, инспектировать layers на embedded secrets или запускать unapproved images из registry path вне разрешенной release boundary.

**Базовые требования:**
- предпочитайте node или workload credential providers, которые выдают scoped, short-lived учетные данные реестра, если platform это поддерживает;
- ограничивайте `kubernetes.io/dockerconfigjson` учетные данные минимальным registry, repository и pull-only permission set; не используйте organization-wide или push-capable tokens как `imagePullSecrets`;
- подключайте `imagePullSecrets` только к ServiceAccounts и Pods, которым они нужны; не размещайте high-value учетные данные реестра на namespace `default` ServiceAccount;
- считайте любой широкий `imagePullSecret` high-value: владелец, expiry или дата пересмотра, rotation path и подтверждение, что его не читают human/CI identities вне release path;
- admission policy должна отклонять workloads, которые ссылаются на unapproved `imagePullSecrets`, наследуют default ServiceAccount учетные данные реестра в protected namespaces или pull images из registries вне approved source list.

---

## 4. Проверка

### 4.1 Инвентаризация и policy-проверки

```bash
kubectl get secrets -A
kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" type="}{.type}{" immutable="}{.immutable}{"\n"}{end}'
kubectl get secrets -A -o jsonpath='{range .items[?(@.type=="kubernetes.io/service-account-token")]}{.metadata.namespace}/{.metadata.name}{" sa="}{.metadata.annotations.kubernetes\.io/service-account\.name}{"\n"}{end}'
kubectl get secrets -A -o jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" sa="}{.spec.serviceAccountName}{" automount="}{.spec.automountServiceAccountToken}{"\n"}{end}'
kubectl get serviceaccounts -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" imagePullSecrets="}{.imagePullSecrets[*].name}{"\n"}{end}'
kubectl get roles,clusterroles -A -o yaml | grep -n 'resources:.*secrets'
kubectl get rolebindings,clusterrolebindings -A
```

Проверяйте не только прямые права на Secret, но и deploy-права:

```bash
kubectl auth can-i list secrets --as=<subject> -n <ns>
kubectl auth can-i watch secrets --as=<subject> -n <ns>
kubectl auth can-i create pods --as=<subject> -n <ns>
kubectl auth can-i create pods/exec --as=<subject> -n <ns>
kubectl auth can-i update pods/ephemeralcontainers --as=<subject> -n <ns>
```

### 4.2 Негативные проверки

Policy/admission должны отклонять:
- `ConfigMap` с ключами или значениями, похожими на passwords, tokens, private keys или certificates;
- Pod, который монтирует Secret без явного списка разрешенных рабочих нагрузок и их владельцев;
- Pod, который передает Secret в env для high-value classes без approved exception;
- workload с `serviceAccountName: default`;
- workload без `automountServiceAccountToken: false`, если Kubernetes API access не требуется;
- workload в protected namespace, который ссылается на unapproved `imagePullSecret` или наследует широкие учетные данные реестра от ServiceAccount;
- вручную созданный `kubernetes.io/service-account-token` Secret без approved legacy или break-glass exception;
- arbitrary `hostPath`, `privileged: true`, `pods/exec` и ephemeral debug в protected namespaces.

### 4.3 Аудит и обнаружение

Минимальный набор событий для централизованного audit:
- `get/list/watch` на `secrets`;
- create/update/delete на `secrets`, особенно для объектов `kubernetes.io/service-account-token`;
- creation/update workloads, которые ссылаются на Secret;
- изменения `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`;
- `pods/exec`, `pods/ephemeralcontainers`, `serviceaccounts/token`;
- изменения encryption configuration, KMS provider health и control-plane backup jobs.

Операционные сигналы:
- spike чтения Secret после релиза или изменения RBAC;
- human identity читает Secret в production namespace без break-glass ticket;
- CI identity получает `list/watch secrets`;
- новый workload монтирует Secret, который не принадлежит его владельцу сервиса;
- новый или измененный `imagePullSecret` подключен к default ServiceAccount, shared между несвязанными рабочими нагрузками или дает более широкий registry access, чем нужен владельца рабочей нагрузки;
- значения Secret обнаружены в logs, traces, metrics labels, crash dumps или support bundles.

---

## 5. Решение по ревью

Матрица ниже определяет доменную критичность замечания и решение о релизе. Общие SLA устранения, жизненный цикл исключений, принятие риска и подтверждения закрытия определяет [плейбук управления уязвимостями](../../../review/vulnerability-management/playbook.ru.md); при пересечении требований применяется более строгое.

| Критичность | Условие | Требуемое действие |
|---|---|---|
| Critical | Значение Secret опубликовано в Git или публичном артефакте, либо identity production-среды может массово читать Secret без необходимости | Немедленная ротация, закрытие канала раскрытия, audit timeline, блокировка релиза до устранения |
| High | `list/watch secrets`, широкое право создания Pod или `pods/exec` доступны human/CI identity в production без обоснования | Назначить владельца и срок, исправить RBAC, провести recertification и проверить audit |
| High | Субъект может создавать Pod/Deployment в namespace с high-value Secret без admission-ограничений на mount/env Secret, ServiceAccount и владельца рабочей нагрузки | Блокировать релиз для этого namespace до введения policy; проверить, что indirect Secret read через созданный Pod невозможен |
| Critical | Право создания Pod в namespace с high-value Secret позволяет массово извлечь учетные данные рабочей среды, tenant secrets, signing material или private keys | Блокировать релиз, отозвать/ротировать затронутые Secret, ограничить deploy-права и восстановить audit timeline |
| High | Production Secret хранится в ConfigMap, незашифрованном manifest или CI artifact | Миграция в Secret/external store, ротация значения, запрет повторения через policy |
| High | В production есть вручную созданный long-lived ServiceAccount token Secret без approved exception | Отозвать token, мигрировать на TokenRequest/projected token flow и проверить всех потребителей по audit |
| High | Широкий или push-capable registry credential используется как `imagePullSecret` для несвязанных рабочих нагрузок или default ServiceAccount | Заменить на scoped pull-only учетные данные или credential provider integration, ротировать registry token и проверить image pulls по audit |
| Medium | Secret доставляется через env для high-value workload без задокументированного исключения | План миграции на файловую или внешнюю доставку либо принятый риск со сроком пересмотра |
| Medium | etcd encryption at rest не подтверждена или не покрывает существующие объекты Secret | Включить или повторно применить шифрование, приложить подтверждение, зафиксировать residual risk |
| Low | Нет меток или аннотаций владельца, rotation metadata или inventory для low-value Secret | Исправить в плановом порядке и добавить проверку drift |

---

## 6. Связанные материалы

- [Ревью безопасности Kubernetes-кластера](../cluster-security-review/playbook.ru.md)
- [Усиление безопасности Pod runtime](../pod-security/playbook.ru.md)
- [Kubernetes adversarial validation](../adversarial-validation/playbook.ru.md)
- [Плейбук безопасности Vault](../../secrets/vault/playbook.ru.md)
