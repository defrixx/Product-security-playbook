# Усиление безопасности Pod в Kubernetes

## 1. Область и цель

Фокус строго на **безопасности runtime Pod / Container**:
- Охватывает только **контроли уровня workload**
- Исключает **networking, ingress и cluster-wide policies**
- Цель: **минимизировать влияние в случае компрометации контейнера**

---

## 2. Модель угроз (кратко)

Фокус: **что защищается и от кого**

**Активы:**
- Node (host OS)
- Kubernetes control plane
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

## 4. Базовые контроли безопасности

Контроли сгруппированы по доменам безопасности.

Где релевантно, различайте:
- **Контроли уровня Pod**  -  влияют на весь Pod
- **Контроли уровня Container**  -  должны применяться к каждому контейнеру

---

### 4.1 Идентичность процесса и привилегии

**Контроли уровня Container:**
- `runAsNonRoot: true`
- `runAsUser` (фиксированный, ненулевой UID)
- `runAsGroup` (фиксированный, ненулевой GID)
- `allowPrivilegeEscalation: false`
- `privileged: false`

**Контроли уровня Pod:**
- `hostUsers: false`

**User namespaces в Kubernetes `v1.36+`:**
- User Namespaces переведены в GA для Linux workload'ов; включение на уровне Pod выполняется через `hostUsers: false`.
- Для production используйте `hostUsers: false` как стандартную рекомендацию изоляции workload'ов там, где это совместимо с container runtime, kernel и storage stack.
- При включенном user namespace UID `0` внутри контейнера не является UID `0` на host: root и GID/UID контейнера мапятся в непривилегированный диапазон на node.
- Это снижает blast radius при container escape, ошибочных mounts и уязвимостях, зависящих от host UID/GID, но не заменяет `runAsNonRoot`, `seccompProfile.type: RuntimeDefault`, `capabilities.drop: ["ALL"]` и запрет `privileged: true`.
- Capabilities при `hostUsers: false` становятся namespaced: например, `CAP_NET_ADMIN` может давать административные действия над локальными ресурсами контейнера, но не над host. Даже в таком режиме capabilities выдавайте только по явному обоснованию, с владельцем и expiry.

**Совместимость и failure modes для `hostUsers: false`:**
- Не считайте `hostUsers: false` простым YAML-флагом. Проверяйте его на той же minor-версии Kubernetes, kernel, runtime, CSI/storage stack и admission policy, которые используются в production.
- Pods с user namespaces не могут использовать host namespaces: `hostNetwork: true`, `hostPID: true` и `hostIPC: true` несовместимы и должны падать на admission или deploy validation.
- Raw block `volumeDevices` несовместимы с Pods, использующими user namespaces. Stateful или storage-heavy workload'ы требуют отдельного storage compatibility test перед внедрением этого контроля.
- Pod Security Standards ослабляют проверки `runAsNonRoot` и `runAsUser` для Pods с user namespaces, потому что UID `0` контейнера мапится в непривилегированный host UID. Это не означает, что "root безопасен по умолчанию"; для обычных app workload'ов сохраняйте `runAsNonRoot: true`, если нет документированной причины запускаться root внутри user namespace.
- Обязательная проверка: admission test для запрещенных host namespace комбинаций, deploy test с реальными volumes workload'а, evidence совместимости node/runtime и PSS test, показывающий, что результат namespace policy понятен команде.

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

**Контроли уровня Container:**
- `capabilities.drop: ["ALL"]`
- Возвращайте только явно необходимые capabilities

**Критично:**
- Избегайте `CAP_SYS_ADMIN`
- Избегайте `CAP_NET_ADMIN`
- Избегайте выдачи capabilities без документированного обоснования

**Назначение:**
- Минимизировать привилегированные операции, экспонируемые ядром
- Снизить возможности повышения привилегий и breakout

---

### 4.3 Харденинг файловой системы

**Контроли уровня Container:**
- `readOnlyRootFilesystem: true`

**Почему это важно:**
- `readOnlyRootFilesystem: false` оставляет root filesystem контейнера writable. После компрометации процесса атакующий может записывать runtime payload, менять файлы приложения или конфигурацию, размещать dropper'ы и web shell'ы, а также усложнять расследование за счет локальных изменений внутри контейнера.
- Writable paths должны быть явными и ограниченными: `/tmp`, cache или каталоги логов выносите в отдельные mounts с понятным назначением, жизненным циклом и лимитами, а не оставляйте весь root filesystem доступным для записи.

**Дополнительные рекомендации:**
- Предоставляйте явные writable mounts только там, где они нужны приложению
- Для workload'ов с `readOnlyRootFilesystem: true` используйте выделенные mounts `emptyDir` для необходимых writable путей (например, `/tmp` и каталогов логов приложения)
- Используйте `emptyDir` только когда это необходимо
- Избегайте хранения persistent или чувствительных данных в writable путях контейнера

---

### 4.4 Контроли volumes

**Ограничения:**
- Избегайте `hostPath`, если это не строго необходимо
- Используйте `readOnly: true`, где возможно
- Минимизируйте количество примонтированных volumes
- Монтируйте только пути, необходимые приложению
- Избегайте совместного использования чувствительных volumes между несвязанными workload'ами

**Mounts высокого риска:**
- `/var/run/docker.sock`
- `/proc`
- `/sys`
- Любой путь, примонтированный с host
- Runtime sockets или пути устройств, экспонированные с host

**Назначение:**
- Предотвратить прямое взаимодействие с host
- Снизить риск компрометации node и экспозиции учетных данных

**Проверки атакующих сценариев:**
- проверьте, что application workload'ы не монтируют `docker.sock`, `containerd.sock`, CRI sockets, `/proc`, `/sys` и sensitive host paths;
- запрещайте runtime socket mounts через admission policy; исключения допускайте только для доверенных platform/build workload'ов с владельцем, expiry и компенсирующими контролями;
- после remediation повторите тот же query или policy test, чтобы подтвердить, что unsafe mount больше не проходит развертывание.

---

### 4.5 Изоляция на уровне ядра

**Контроли уровня Container:**
- `seccompProfile.type: RuntimeDefault`
- `procMount: Default`
- Для custom profile: разрешайте только обоснованные syscalls, high-risk syscalls и bypass-комбинации ревьюьте отдельно

Подробное ревью seccomp (dangerous syscalls, `io_uring`/`bpf`, combo-checks, CI governance): [kubernetes/seccomp/checklist.ru.md](../seccomp/checklist.ru.md)

---

### 4.6 Service Account и доступ к API

**Контроли уровня Pod:**
- `automountServiceAccountToken: false` по умолчанию
- Используйте выделенный ServiceAccount только когда требуется доступ к Kubernetes API
- Применяйте RBAC по принципу наименьших привилегий
- Не используйте namespace `default` ServiceAccount для application workload'ов

**Закрываемый риск:**
- Lateral movement через Kubernetes API
- Злоупотребление токенами после компрометации контейнера
- Неконтролируемое повторное использование привилегий между workload'ами

**Обязательные admission/policy gates (предотвращение обхода на уровне namespace):**
- Отклоняйте pods, которые не задают `automountServiceAccountToken: false`, если они явно не аннотированы как workload'ы, вызывающие API.
- Отклоняйте pods, использующие `serviceAccountName: default`.
- Требуйте явно именованный ServiceAccount для каждого workload.
- Применяйте эти проверки через admission policy (Kyverno/Gatekeeper/ValidatingAdmissionPolicy), а не через ревью только документации.
- Требуйте объекты исключений с владельцем/expiry для любого обхода policy.

---

### 4.7 Изоляция host и namespaces

**Контроли уровня Pod:**
- `hostNetwork: false`
- `hostPID: false`
- `hostIPC: false`
- `shareProcessNamespace: false`

**Критично для `shareProcessNamespace`:**
- Если `shareProcessNamespace: true`, процессы становятся видимыми между контейнерами Pod, включая данные из `/proc`.
- Контейнеры могут посылать сигналы процессам в соседних контейнерах.
- Через `/proc/<pid>/root` может открываться доступ к файловой системе соседнего контейнера.
- Для production workload'ов запрещайте `shareProcessNamespace: true` по умолчанию; исключения допускайте только по явно оформленному break-glass с владельцем и сроком действия.

**Обязательный admission/policy gate:**
- Отклоняйте Pod'ы с `shareProcessNamespace: true` через admission policy (Kyverno/Gatekeeper/ValidatingAdmissionPolicy), кроме явно зарегистрированных исключений.

**Назначение:**
- Предотвратить доступ к процессам хоста
- Предотвратить доступ к network namespace хоста
- Сохранить границы изоляции workload'ов

---

### 4.8 Ограничения ресурсов

**Контроли runtime уровня Pod/container:**
- Определяйте `resources.requests` для CPU и memory, чтобы scheduler принимал решения на основе реальных потребностей workload'а.
- Определяйте memory limits для production workload'ов, чтобы ограничивать node-level DoS и noisy-neighbor impact.
- Определяйте `ephemeral-storage` requests и limits для workload'ов, которые пишут временные файлы, cache, logs, uploads или generated artifacts.
- Рассматривайте CPU limits как workload-specific решение, а не blanket security default. CPU limits могут вызывать throttling и ухудшать latency у bursty или latency-sensitive сервисов; применяйте их, когда риск DoS/noisy-neighbor выше риска throttling или когда этого требует platform policy.
- Для internet-facing, multi-tenant, batch, build, AI/inference и untrusted-code workload'ов явно документируйте resource abuse model и выбирайте CPU, memory и ephemeral-storage guardrails.
- Для критичных сервисов подтверждайте limits load testing, а не копируйте generic values.

**Контроли уровня namespace:**
- применяйте `ResourceQuota` и, где нужно, `LimitRange` для shared production namespaces;
- запрещайте BestEffort pods в production namespaces, если нет явно принятого исключения;
- требуйте, чтобы namespace quotas покрывали CPU, memory, pods и ephemeral storage там, где это поддерживается платформой;
- DoS/`stress-ng`-проверки выполняйте только в изолированной load/staging среде, не в живом production namespace.

---

### 4.9 Поверхности отладки

**Что контролировать:**
- `pods/exec`
- `pods/attach`
- `pods/portforward`
- `pods/ephemeralcontainers`
- node-level debug flows

**Рекомендация для production:**
- ограничьте `exec` и ephemeral containers в sensitive namespaces отдельными support/SRE ролями;
- логируйте и алертите `exec`, attach/port-forward и добавление ephemeral containers;
- используйте admission policy для запрета debug surfaces в high-value namespaces, где это операционно допустимо.

---

## 5. Pod Security Standards (PSS)

Выравнивание базового уровня:
- Целевой уровень: **Restricted profile**

**Назначение:**
- Переиспользовать upstream baseline для hardening pod в Kubernetes
- Избежать ad hoc или несогласованных правил безопасности workload'ов
- Обеспечить минимально приемлемый уровень безопасности Pod

**Важное ограничение:**

Pod Security Standards помогают обеспечивать безопасные значения по умолчанию для спецификаций Pod, но **не** заменяют:
- Доверие к image и контроли supply chain
- Дизайн RBAC и архитектуру идентичности
- Runtime threat detection
- Сетевую изоляцию
- Cluster-wide hardening

### 5.1 Базовое применение

- `pod-security.kubernetes.io/enforce: restricted` во всех production namespaces.
- Закрепляйте версию policy для всех режимов на утвержденный Kubernetes minor:
  - `pod-security.kubernetes.io/enforce-version: v<minor>`
  - `pod-security.kubernetes.io/audit-version: v<minor>`
  - `pod-security.kubernetes.io/warn-version: v<minor>`
- Используйте `latest` только в явно назначенных canary или non-production namespaces, где policy drift намеренно проверяется перед распространением на весь кластер.
- Разделяйте `warn`/`audit` и `enforce`; production не должен опираться на режим только warn.
- Проверка дрейфа namespace policy каждые `24h`.
- Блокируйте развертывание, если labels namespace деградировали или были удалены.
- При upgrade Kubernetes выполняйте dry-run оценку следующей PSS version до изменения namespace labels, фиксируйте нарушения по workload owner, устраняйте их или утверждайте time-boxed exceptions, затем обновляйте `enforce-version`, `audit-version` и `warn-version` вместе.
- Считайте изменение PSS version изменением policy: нужны approval владельца, rollout window, rollback plan и post-change evidence, что production namespaces по-прежнему enforce `restricted`.

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
  -> Ломает границы изоляции между контейнерами одного Pod и упрощает lateral movement внутри workload'а

- Writable root filesystem (`readOnlyRootFilesystem: false`)  
  -> Позволяет persistence, хранение runtime payload и изменение файлов приложения или конфигурации внутри контейнера

- Автоматическое монтирование ServiceAccount tokens по умолчанию  
  -> Повышает риск злоупотребления Kubernetes API после компрометации

- Использование namespace `default` ServiceAccount  
  -> Поощряет повторное использование привилегий и слабое разделение identities между workload'ами

---

## 7. Связанные материалы

- Adversarial validation для проверки pod-level путей злоупотребления: [kubernetes/adversarial-validation/playbook.ru.md](../adversarial-validation/playbook.ru.md)
