---
title: "Плейбук безопасности Pod в Kubernetes"
description: "Фокус строго на **безопасности runtime Pod / Container**:"
sidebar:
  order: 30
---
## 1. Область и цель

Фокус строго на **безопасности runtime Pod / Container**:
- Охватывает только **меры уровня workload**
- Исключает **networking, ingress и cluster-wide policies**
- Цель: **минимизировать влияние в случае компрометации контейнера**

---

## 2. Модель угроз (кратко)

Фокус: **что защищается и от кого**

**Активы:**
- Node (host OS)
- Kubernetes control plane (косвенная экспозиция)
- Secrets / ServiceAccount tokens
- Другие pods, работающие на том же node

**Атакующий:**
- Компрометированное приложение внутри контейнера
- Вредоносный или уязвимый container image (supply chain)

---

## 3. Векторы атак (Pod-level)

### Повышение привилегий

- setuid/setgid binaries
- Опасные Linux capabilities (например, `CAP_SYS_ADMIN`)
- Запуск контейнеров от root
- Неправильное использование режима `privileged`

### Выход из контейнера

- Доступ к host namespaces
- Экспозиция `/proc`, `/sys`
- Эксплуатация небезопасных syscalls
- Доступ к host filesystem через небезопасные mounts

### Латеральное перемещение

- Злоупотребление ServiceAccount tokens
- Неавторизованный доступ к Kubernetes API
- Доступ к общим или чувствительным volumes
- Повторное использование избыточно разрешительных идентификаторов по умолчанию

---

## 4. Базовые меры безопасности

Меры контроля сгруппированы по доменам безопасности.

Где релевантно, различайте:
- **Меры уровня Pod:** влияют на весь Pod
- **Меры уровня Container:** должны применяться к каждому контейнеру

---

### 4.1 Идентичность процесса и привилегии

**Меры уровня Container:**
- `runAsNonRoot: true`
- `runAsUser` (фиксированный, ненулевой UID)
- `runAsGroup` (фиксированный, ненулевой GID)
- `allowPrivilegeEscalation: false`
- `privileged: false`

**Меры уровня Pod:**
- `hostUsers: false`

**User namespaces в Kubernetes `v1.36+`:**
- User Namespaces переведены в GA для Linux рабочих нагрузок; включение на уровне Pod выполняется через `hostUsers: false`.
- Для рабочих сред используйте `hostUsers: false` как стандартную рекомендацию изоляции рабочих нагрузок там, где это совместимо с container runtime, kernel и storage stack.
- При включенном user namespace UID `0` внутри контейнера не является UID `0` на host: root и GID/UID контейнера мапятся в непривилегированный диапазон на node.
- Это снижает blast radius при container escape, ошибочных mounts и уязвимостях, зависящих от host UID/GID, но не заменяет `runAsNonRoot`, `seccompProfile.type: RuntimeDefault`, `capabilities.drop: ["ALL"]` и запрет `privileged: true`.
- Capabilities при `hostUsers: false` становятся namespaced: например, `CAP_NET_ADMIN` может давать административные действия над локальными ресурсами контейнера, но не над host. Даже в таком режиме capabilities выдавайте только по явному обоснованию, с владельцем и expiry.

**Совместимость и failure modes для `hostUsers: false`:**
- Не считайте `hostUsers: false` простым YAML-флагом. Проверяйте его на той же minor-версии Kubernetes, kernel, runtime, CSI/storage stack и admission policy, которые используются в рабочей среде.
- Минимальное подтверждение среды выполнения: Linux `6.3+` или поддерживаемое поставщиком ядро с ID-mapped mounts для всех файловых систем рабочей нагрузки, containerd `2.0+` или CRI-O `1.25+`, среда выполнения OCI с поддержкой пользовательских namespaces, например `runc` `1.2+` или `crun` `1.9+`, и события или метрики kubelet, подтверждающие успешное создание Pod с пользовательским namespace.
- Развёртывание выполняйте поэтапно: сначала рабочие нагрузки без состояния, `hostNetwork`, `hostPID`, `hostIPC`, блочных `volumeDevices` и специальных требований к хранилищу; затем нагрузки с состоянием и интенсивным использованием хранилища — только после проверки совместимости CSI и хранилища; платформенные нагрузки — после отдельного архитектурного ревью.
- Для образов, которым действительно требуется поведение, аналогичное root внутри контейнера, используйте отдельный процесс исключения: укажите владельца, срок действия, причину несовместимости с `runAsNonRoot`, подтверждение того, что UID/GID на хосте остаются непривилегированными, и компенсирующие меры (`seccomp`, удаление capabilities, корневая файловая система только для чтения, ограниченные тома).
- Pods с user namespaces не могут использовать host namespaces: `hostNetwork: true`, `hostPID: true` и `hostIPC: true` несовместимы и должны падать на admission или deploy validation.
- Raw block `volumeDevices` несовместимы с Pods, использующими user namespaces. Stateful или storage-heavy рабочие нагрузки требуют отдельного storage compatibility test перед внедрением этого контроля.
- NFS volumes несовместимы с user-namespace Pods, пока Linux NFS client не поддерживает idmapped mounts; считайте рабочие нагрузки на NFS несовместимыми, если platform team не подтвердила поддержку на точном kernel и storage path.
- Pod Security Standards ослабляют проверки `runAsNonRoot` и `runAsUser` для Pods с user namespaces, потому что UID `0` контейнера мапится в непривилегированный host UID. Это не означает, что "root безопасен по умолчанию"; для обычных app рабочих нагрузок сохраняйте `runAsNonRoot: true`, если нет документированной причины запускаться root внутри user namespace.
- Обязательная проверка: admission test для запрещенных host namespace комбинаций, deploy test с реальными volumes рабочей нагрузки, подтверждения совместимости node/runtime, мониторинг kubelet `started_user_namespaced_pods_total` / `started_user_namespaced_pods_errors_total` и PSS test, показывающий, что результат namespace policy понятен команде.

**Важная семантика `securityContext` (Kubernetes):**
- Если одно и то же поле задано и на уровне Pod, и на уровне Container, значение из `container.securityContext` перекрывает значение из `pod.spec.securityContext`.
- `allowPrivilegeEscalation` напрямую управляет флагом Linux `no_new_privs` для процесса контейнера.
- `allowPrivilegeEscalation: false` фактически не дает ожидаемого эффекта, если контейнер запускается как `privileged: true` или имеет `CAP_SYS_ADMIN`.

**Назначение:**
- Предотвратить повышение привилегий через setuid/setgid binaries
- Убрать неявные root-привилегии
- Предотвратить выполнение в контейнере почти на уровне хоста

---

### 4.2 Linux Capabilities

**Меры уровня Container:**
- `capabilities.drop: ["ALL"]`
- Возвращайте только явно необходимые capabilities

**Критично:**
- Избегайте `CAP_SYS_ADMIN`
- Избегайте `CAP_NET_ADMIN`
- Избегайте выдачи capabilities без документированного обоснования

**Назначение:**
- Минимизировать привилегированные операции, экспонируемые ядром
- Снизить возможности повышения привилегий и breakout

Для ревью не ограничивайтесь YAML. `capabilities.drop/add` управляет несколькими Linux capability sets через CRI/runtime, а итоговое состояние зависит от entrypoint, `execve`, file capabilities и `allowPrivilegeEscalation`. Для спорных рабочих нагрузок проверяйте `CapEff`, `CapPrm`, `CapBnd`, `CapAmb` и `NoNewPrivs` в runtime; подробная модель описана в [обзоре container escape и capability abuse](/Product-security-playbook/ru/platform-security/kubernetes/container-escape-capability-abuse/overview/).

---

### 4.3 Усиление защиты файловой системы

**Меры уровня Container:**
- `readOnlyRootFilesystem: true`

**Почему это важно:**
- `readOnlyRootFilesystem: false` оставляет корневую файловую систему контейнера доступной для записи. После компрометации процесса атакующий может записывать полезную нагрузку, менять файлы приложения или конфигурацию, размещать загрузчики и web-shell, а также усложнять расследование за счет локальных изменений внутри контейнера.
- Writable paths должны быть явными и ограниченными: `/tmp`, cache или каталоги логов выносите в отдельные mounts с понятным назначением, жизненным циклом и лимитами, а не оставляйте весь root filesystem доступным для записи.

**Дополнительные рекомендации:**
- Предоставляйте явные writable mounts только там, где они нужны приложению
- Для рабочих нагрузок с `readOnlyRootFilesystem: true` используйте выделенные mounts `emptyDir` для необходимых writable путей (например, `/tmp` и каталогов логов приложения)
- Используйте `emptyDir` только когда это необходимо
- Избегайте хранения persistent или чувствительных данных в writable путях контейнера

---

### 4.4 Меры контроля volumes

**Ограничения:**
- Избегайте `hostPath`, если это не строго необходимо
- Используйте `readOnly: true`, где возможно
- Минимизируйте количество примонтированных volumes
- Монтируйте только пути, необходимые приложению
- Избегайте совместного использования чувствительных volumes между несвязанными рабочими нагрузками

**Mounts высокого риска:**
- `/var/run/docker.sock`
- `/proc`
- `/sys`
- Любой путь, примонтированный с host
- Runtime sockets или пути устройств, экспонированные с host

**Назначение:**
- Предотвратить прямое взаимодействие с host
- Снизить риск компрометации node и раскрытия учетных данных

**Проверки атакующих сценариев:**
- проверьте, что application рабочие нагрузки не монтируют `docker.sock`, `containerd.sock`, CRI sockets, `/proc`, `/sys` и sensitive host paths;
- запрещайте runtime socket mounts через admission policy; исключения допускайте только для доверенных platform/build рабочих нагрузок с владельцем, expiry и компенсирующими мерами;
- после устранения повторите тот же query или policy test, чтобы подтвердить, что unsafe mount больше не проходит развертывание.

---

### 4.5 Изоляция на уровне ядра

**Меры уровня Container:**
- `seccompProfile.type: RuntimeDefault`
- `appArmorProfile.type: RuntimeDefault` на Linux nodes с AppArmor
- `procMount: Default`
- Для custom profile: разрешайте только обоснованные syscalls, high-risk syscalls и bypass-комбинации ревьюьте отдельно

**Важное подтверждение seccomp:**
- Актуальный Pod Security Standards `restricted` требует явно заданный `seccompProfile.type: RuntimeDefault` или `Localhost` на уровне Pod или container; `baseline` только блокирует явный `Unconfined`.
- рабочие нагрузки вне enforced `restricted`, legacy namespaces и exception paths все еще могут запускаться с unspecified seccomp profile. Если на node не включен kubelet `--seccomp-default` / `seccompDefault`, такой unspecified profile может фактически выполняться как `Unconfined`.
- Подтверждение для рабочей среды должно показывать enforced `restricted` admission с явными seccomp fields, эквивалентную custom admission policy либо node-level seccomp defaulting в `RuntimeDefault`, плюс effective runtime verification там, где это возможно.

**AppArmor и SELinux:**
- Если nodes поддерживают AppArmor, явно задавайте `appArmorProfile.type: RuntimeDefault` для application рабочих нагрузок. Не полагайтесь только на implicit default: если AppArmor выключен на node, unspecified profile может не дать runtime-ограничений.
- `appArmorProfile.type: Unconfined` запрещайте через admission policy. `Localhost` допускайте только для заранее загруженных profiles на всех eligible nodes, с владельцем, rollout-процессом и regression test.
- `seLinuxOptions` используйте только в SELinux-enabled кластерах, где labels, поведение хранилища и runtime policy управляются платформенной командой. Custom SELinux labels без ownership модели часто ломают совместимость volumes и затрудняют расследование.
- При использовании поведения `SELinuxChangePolicy` или `SELinuxMount` в SELinux-enabled кластерах перед rollout проверяйте события Pod и платформенные метрики на конфликты volume labels, особенно для shared volumes и разных SELinux labels.

**Sysctls:**
- По умолчанию запрещайте рабочим нагрузкам задавать `spec.securityContext.sysctls`, кроме явно разрешенного safe subset из Pod Security Standards для вашей Kubernetes minor version.
- Unsafe sysctls допускайте только для специальных performance/real-time сценариев: отдельный node pool, taints/tolerations, владелец, expiry, load test и rollback plan. Не размещайте обычные application рабочие нагрузки на nodes с расширенным `allowed-unsafe-sysctls`.

Подробное ревью seccomp (dangerous syscalls, `io_uring`/`bpf`, combo-checks, CI governance): [kubernetes/seccomp/checklist.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/seccomp/checklist/)

---

### 4.6 Service Account и доступ к API

**Меры уровня Pod:**
- `automountServiceAccountToken: false` по умолчанию
- Используйте выделенный ServiceAccount только когда требуется доступ к Kubernetes API
- Применяйте RBAC по принципу минимально необходимых привилегий
- Не используйте namespace `default` ServiceAccount для application рабочих нагрузок

**Закрываемый риск:**
- Lateral movement через Kubernetes API
- Злоупотребление токенами после компрометации контейнера
- Неконтролируемое повторное использование привилегий между рабочими нагрузками

**Обязательные admission/policy gates (предотвращение обхода на уровне namespace):**
- Отклоняйте pods, которые не задают `automountServiceAccountToken: false`, если они явно не аннотированы как рабочие нагрузки, вызывающие API.
- Отклоняйте pods, использующие `serviceAccountName: default`.
- Требуйте явно именованный ServiceAccount для каждого workload.
- Применяйте эти проверки через admission policy (Kyverno/Gatekeeper/ValidatingAdmissionPolicy), а не через ревью только документации.
- Требуйте объекты исключений с владельцем/expiry для любого обхода политики.

---

### 4.7 Изоляция host и namespaces

**Меры уровня Pod:**
- `hostNetwork: false`
- `hostPID: false`
- `hostIPC: false`
- `shareProcessNamespace: false`

**Критично для `shareProcessNamespace`:**
- Если `shareProcessNamespace: true`, процессы становятся видимыми между контейнерами Pod, включая данные из `/proc`.
- Контейнеры могут посылать сигналы процессам в соседних контейнерах.
- Через `/proc/<pid>/root` может открываться доступ к файловой системе соседнего контейнера.
- Для рабочих нагрузок запрещайте `shareProcessNamespace: true` по умолчанию; исключения допускайте только по явно оформленному break-glass с владельцем и сроком действия.

**Обязательный admission/policy gate:**
- Отклоняйте Pod с `shareProcessNamespace: true` через admission policy (Kyverno/Gatekeeper/ValidatingAdmissionPolicy), кроме явно зарегистрированных исключений.

**Назначение:**
- Предотвратить доступ к процессам хоста
- Предотвратить доступ к network namespace хоста
- Сохранить границы изоляции рабочих нагрузок

---

### 4.8 Ограничения ресурсов

**Меры runtime-уровня Pod/container:**
- Определяйте `resources.requests` для CPU и memory, чтобы scheduler принимал решения на основе реальных потребностей рабочей нагрузки.
- Определяйте memory limits для рабочих нагрузок, чтобы ограничивать node-level DoS и noisy-neighbor impact.
- Определяйте `ephemeral-storage` requests и limits для рабочих нагрузок, которые пишут временные файлы, cache, logs, uploads или сгенерированные артефакты.
- Рассматривайте CPU limits как workload-specific решение, а не blanket security default. CPU limits могут вызывать throttling и ухудшать latency у bursty или latency-sensitive сервисов; применяйте их, когда риск DoS/noisy-neighbor выше риска throttling или когда этого требует политика платформы.
- Для internet-facing, multi-tenant, batch, build, AI/inference и untrusted-code рабочих нагрузок явно документируйте resource abuse model и выбирайте CPU, memory и ephemeral-storage guardrails.
- Для критичных сервисов подтверждайте лимиты load testing, а не копируйте generic values.

**Меры уровня namespace:**
- применяйте `ResourceQuota` и, где нужно, `LimitRange` для shared защищенных namespace;
- запрещайте BestEffort pods в защищенных namespace, если нет явно принятого исключения;
- требуйте, чтобы namespace quotas покрывали CPU, memory, pods и ephemeral storage там, где это поддерживается платформой;
- DoS/`stress-ng`-проверки выполняйте только в изолированной load/staging среде, не в живом защищенном namespace.

---

### 4.9 Поверхности отладки

**Что контролировать:**
- `pods/exec`
- `pods/attach`
- `pods/portforward`
- `pods/ephemeralcontainers`
- node-level debug flows

**Рекомендация для рабочих сред:**
- ограничьте `exec` и ephemeral containers в sensitive namespaces отдельными support/SRE ролями;
- логируйте и алертите `exec`, attach/port-forward и добавление ephemeral containers;
- используйте admission policy для запрета debug surfaces в high-value namespaces, где это операционно допустимо.

---

### 4.10 Группы процессов и владение volumes

**Меры уровня Pod:**
- `runAsGroup` задает primary GID процессов контейнера; используйте фиксированный ненулевой GID вместо неявных значений из image.
- `fsGroup` применяйте только когда рабочей нагрузке действительно нужен group-based доступ к volume. Не используйте его как универсальный способ "починить permissions" без понимания поведение хранилища.
- `supplementalGroups` выдавайте минимально: каждый дополнительный GID расширяет доступ процесса к файлам и mounted storage.
- Для Kubernetes `v1.33+` используйте `supplementalGroupsPolicy: Strict` в sensitive рабочих нагрузках, чтобы группы из `/etc/group` внутри image не добавлялись неявно к процессу контейнера.
- Для больших PVC и stateful рабочих нагрузок используйте `fsGroupChangePolicy: OnRootMismatch`, если storage driver и модель прав это поддерживают; это снижает задержки старта из-за рекурсивного изменения ownership.

**Операционные оговорки:**
- `fsGroup` и `fsGroupChangePolicy` работают только для типов томов и CSI-драйверов, которые поддерживают управление владельцем и правами. Для CSI-томов драйвер может брать изменение прав на себя; проверяйте фактические UID/GID владельца и группы внутри запущенного Pod.
- Не назначайте один широкий GID на несвязанные рабочие нагрузки ради удобного доступа к shared storage. Это превращает storage group в неявную boundary обхода namespace/RBAC.
- Если `supplementalGroupsPolicy: Strict` недоступен на части nodes, в Kubernetes `v1.33+` такой Pod должен быть отклонен kubelet; в `v1.31-v1.32` alpha-поведение могло silently перейти на резервный режим в `Merge`. Проверяйте поддержку feature на node pool и runtime подтверждения через `id` внутри контейнера или `.status.containerStatuses[].user.linux`, где поле доступно.
- Для multi-container Pod с общим `emptyDir` или PVC фиксируйте ownership contract: какой контейнер пишет, какой читает, какие paths доступны на запись, какой GID нужен и кто владеет исключением.

**Проверки:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" runAsGroup="}{.spec.securityContext.runAsGroup}{" fsGroup="}{.spec.securityContext.fsGroup}{" supplementalGroups="}{.spec.securityContext.supplementalGroups}{" supplementalGroupsPolicy="}{.spec.securityContext.supplementalGroupsPolicy}{"\n"}{end}'
kubectl exec -n <ns> <pod> -- id
kubectl exec -n <ns> <pod> -- stat -c '%u:%g %a %n' <mounted-path>
```

---

## 5. Pod Security Standards (PSS)

Выравнивание базового уровня:
- Целевой уровень: **Restricted profile**

**Назначение:**
- Переиспользовать upstream baseline для усиления защиты pod в Kubernetes
- Избежать ad hoc или несогласованных правил безопасности рабочих нагрузок
- Обеспечить минимально приемлемый уровень безопасности Pod

**Важное ограничение:**

Pod Security Standards помогают обеспечивать безопасные значения по умолчанию для спецификаций Pod, но **не** заменяют:
- Доверие к image и меры контроля supply chain
- Дизайн RBAC и архитектуру идентичности
- Runtime threat detection
- Сетевую изоляцию
- Усиление защиты на уровне кластера
- Проверку effective seccomp вне enforced `restricted`: namespace с `baseline`, legacy exceptions или custom policies все равно должны доказывать явный `RuntimeDefault`/утвержденный `Localhost` либо node-level seccomp defaulting.

### 5.1 Базовое применение

- `pod-security.kubernetes.io/enforce: restricted` во всех защищенных namespace.
- Закрепляйте версию policy для всех режимов на утвержденный Kubernetes minor:
  - `pod-security.kubernetes.io/enforce-version: v<minor>`
  - `pod-security.kubernetes.io/audit-version: v<minor>`
  - `pod-security.kubernetes.io/warn-version: v<minor>`
- Используйте `latest` только в явно назначенных canary или non-защищенных namespace, где policy drift намеренно проверяется перед распространением на весь кластер.
- Разделяйте `warn`/`audit` и `enforce`; рабочая среда не должна опираться только на режим warn.
- Считайте seccomp отдельным требованием к подтверждениям среды выполнения: `restricted` admission должен отклонять workload без явного `RuntimeDefault` или утвержденного `Localhost`, эквивалентные custom policy должны делать то же самое, либо конфигурация node должна доказывать, что kubelet `--seccomp-default` / `seccompDefault` включен для namespace, где профили без явного указания временно допускаются.
- Проверка дрейфа namespace policy каждые `24h`.
- Блокируйте развертывание, если labels namespace деградировали или были удалены.
- При upgrade Kubernetes выполняйте dry-run оценку следующей PSS version до изменения namespace labels, фиксируйте нарушения по владельцам рабочих нагрузок, устраняйте их или утверждайте ограниченные по сроку исключения, затем обновляйте `enforce-version`, `audit-version` и `warn-version` вместе.
- Считайте изменение PSS version изменением политики: нужны согласование владельца, rollout window, rollback plan и post-change подтверждение, что защищенных namespace по-прежнему enforce `restricted`.

---

## 6. Антипаттерны

Каждый антипаттерн напрямую увеличивает риск из threat model:

- Запуск контейнеров от root
  -> Позволяет повышение привилегий и увеличивает влияние выхода из контейнера

- `privileged: true`
  -> Дает доступ почти на уровне хоста и ломает допущения изоляции

- Добавление широких Linux capabilities без строгой необходимости
  -> Расширяет поверхность атаки ядра и границу привилегий

- Неконтролируемое использование `hostPath`
  -> Позволяет прямой доступ к файловой системе хоста и возможную компрометацию node

- Монтирование чувствительных host interfaces, таких как sockets container runtime
  -> Может привести к захвату хоста или контролю над другими контейнерами

- Отсутствие seccomp profile
  -> Экспонирует более широкую поверхность syscalls и повышает эксплуатируемость ядра

- Использование `procMount`, отличного от default
  -> Ослабляет изоляцию информации о процессах

- Использование `shareProcessNamespace: true`
  -> Ломает границы изоляции между контейнерами одного Pod и упрощает lateral movement внутри рабочей нагрузки

- Неявные supplementary groups из container image
  -> Могут дать процессу доступ к shared storage или файлам, который не виден в manifest без runtime-проверки

- Широкие `fsGroup`/`supplementalGroups` без ownership модели
  -> Превращают group-based доступ к volumes в обходной канал между рабочими нагрузками

- `appArmorProfile.type: Unconfined` или отсутствие подтверждений работы AppArmor на поддерживаемых node
  -> Убирает ожидаемый слой LSM-защиты и делает PSS/audit вывод неполным

- Unsafe sysctls в обычных application namespace
  -> Могут влиять на node или соседние рабочие нагрузки и должны оставаться исключением для изолированных node pools

- Writable root filesystem (`readOnlyRootFilesystem: false`)
  -> Позволяет persistence, хранение runtime payload и изменение файлов приложения или конфигурации внутри контейнера

- Автоматическое монтирование ServiceAccount tokens по умолчанию
  -> Повышает риск злоупотребления Kubernetes API после компрометации

- Использование namespace `default` ServiceAccount
  -> Поощряет повторное использование привилегий и слабое разделение identities между рабочими нагрузками

---

## 7. Связанные материалы

- Adversarial validation для проверки pod-level путей злоупотребления: [kubernetes/adversarial-validation/playbook.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/adversarial-validation/playbook/)
- Kubernetes Secrets для Secret volumes, env-доставки и ServiceAccount/RBAC границ: [kubernetes/secrets/playbook.ru.md](/Product-security-playbook/ru/platform-security/kubernetes/secrets/playbook/)
