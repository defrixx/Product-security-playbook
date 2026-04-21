# Усиление безопасности Pod в Kubernetes

## 1. Область и цель

Фокус строго на **безопасности runtime Pod / Container**:
- Охватывает только **контроли уровня workload**
- Исключает **networking, ingress и cluster-wide policies**
- Цель: **минимизировать влияние в случае компрометации контейнера**

---

## 2. Threat Model (кратко)

Фокус: **что защищается и от кого**

**Assets:**
- Node (host OS)
- Kubernetes control plane
- Secrets / ServiceAccount tokens
- Другие pods, работающие на том же node

**Attacker:**
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

### Lateral Movement

- Злоупотребление ServiceAccount tokens
- Неавторизованный доступ к Kubernetes API
- Доступ к общим или чувствительным volumes
- Повторное использование избыточно разрешительных идентификаторов по умолчанию

---

## 4. Базовые контроли безопасности

Контроли сгруппированы по доменам безопасности.

Где релевантно, различайте:
- **Pod-level controls**  -  влияют на весь Pod
- **Container-level controls**  -  должны применяться к каждому контейнеру

---

### 4.1 Идентичность процесса и привилегии

**Container-level controls:**
- `runAsNonRoot: true`
- `runAsUser` (фиксированный, ненулевой UID)
- `runAsGroup` (фиксированный, ненулевой GID)
- `allowPrivilegeEscalation: false`
- `privileged: false`

**Pod-level controls:**
- `hostUsers: false`

**Назначение:**
- Предотвратить повышение привилегий через setuid/setgid binaries
- Убрать неявные root-привилегии
- Предотвратить выполнение в контейнере почти на уровне хоста

---

### 4.2 Linux Capabilities

**Container-level controls:**
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

**Container-level controls:**
- `readOnlyRootFilesystem: true`

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
- Любой path, примонтированный с host
- Runtime sockets или device paths, экспонированные с host

**Назначение:**
- Предотвратить прямое взаимодействие с host
- Снизить риск компрометации node и экспозиции учетных данных

---

### 4.5 Изоляция на уровне ядра

**Container-level controls:**
- `seccompProfile.type: RuntimeDefault`
- `procMount: Default`
- Используйте AppArmor profiles, где поддерживается:
  - `appArmorProfile.type: RuntimeDefault` или `Localhost`
- Используйте SELinux labels, где платформа поддерживает enforcement SELinux

**Назначение:**
- Фильтровать ненужные или опасные syscalls
- Снижать поверхность атаки ядра
- Предотвращать ослабление default-защит `/proc`
- Применять mandatory access control там, где доступно

---

### 4.6 Service Account и доступ к API

**Pod-level controls:**
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

**Pod-level controls:**
- `hostNetwork: false`
- `hostPID: false`
- `hostIPC: false`

**Назначение:**
- Предотвратить доступ к процессам хоста
- Предотвратить доступ к network namespace хоста
- Сохранить границы изоляции workload'ов

---

### 4.8 Ограничения ресурсов

**Pod / container runtime controls:**
- Определите `resources.requests`
- Определите `resources.limits`

---

## 5. Pod Security Standards (PSS)

Выравнивание baseline:
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
- Разделяйте `warn`/`audit` и `enforce`; production не должен опираться на режим только warn.
- Проверка дрейфа namespace policy каждые `24h`.
- Блокируйте deployment, если labels namespace деградировали или были удалены.

### 5.2 Управление исключениями

Любой workload, который не может соответствовать restricted controls, должен иметь:
- владелец
- тикет
- причина
- компенсирующие контроли
- expiry (по умолчанию `14d`, жесткий максимум `45d`)
- явные критерии закрытия

Истекшие исключения должны блокировать релиз.

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

- Writable root filesystem  
  -> Позволяет persistence и хранение runtime payload внутри контейнера

- Автоматическое монтирование ServiceAccount tokens по умолчанию  
  -> Повышает риск злоупотребления Kubernetes API после компрометации

- Использование namespace `default` ServiceAccount  
  -> Поощряет повторное использование привилегий и слабое разделение identities между workload'ами
