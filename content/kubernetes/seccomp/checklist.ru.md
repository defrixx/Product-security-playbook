# Чеклист ревью seccomp в Kubernetes

## 1. Область и цель безопасности

Используйте этот чеклист, чтобы проверить, применяется ли seccomp для Kubernetes workload'ов **корректно, реалистично и безопасно**.

### Цель

Seccomp используется для:
- снижения достижимой поверхности атаки ядра;
- блокировки явно опасных syscalls;
- ограничения syscall-surface под конкретный workload там, где это операционно оправдано.

### Не-цели

Seccomp **не** является:
- полноценным sandbox;
- заменой runtime isolation;
- заменой удаления избыточных Linux capabilities;
- доказательством безопасности только из-за наличия profile в YAML.

Примечание: seccomp — один слой защиты. User namespaces не заменяют seccomp; syscall surface и capabilities нужно ревьюить независимо. Остальные уровни hardening проверяйте по профильным чеклистам pod security и container escape/capability abuse:
- [kubernetes/pod-security/playbook.ru.md](../pod-security/playbook.ru.md)
- [kubernetes/container-escape-capability-abuse/overview.ru.md](../container-escape-capability-abuse/overview.ru.md)

---

## 2. Базовые вопросы перед ревью

Перед анализом profile подтвердите:
- seccomp вообще включен для workload;
- profile привязан на корректном уровне (Pod или Container);
- источник profile: runtime default, custom или auto-generated;
- используемый runtime (`Docker/Moby`, `containerd/runc`, другой);
- целевые архитектуры (`x86_64`, `x86`, `x32`, `arm64`, другие);
- выданные Linux capabilities;
- действительно ли workload нуждается в углубленном взаимодействии с ядром.

Фактический security-эффект seccomp зависит от runtime-поведения, архитектур и capabilities, а не только от статического JSON/YAML.

---

## 3. Принципы дизайна

### 3.1 Блокируйте опасное в первую очередь

Приоритет ревью:
- сначала убрать известные high-risk syscalls;
- затем сужать дополнительную поверхность syscalls там, где это обосновано;
- не подменять риск-модель механическим "блокируем все, чего нет в trace".

### 3.2 Делайте design per-workload

Команда должна явно зафиксировать:
- зачем seccomp нужен именно этому workload;
- какие классы атак снижаются;
- какие операционные компромиссы принимаются.

---

## 4. Источник profile и качество генерации

### 4.1 Auto-generated profile требует ручной курации

Если profile получен через tracing/tooling (SPO, eBPF tracers, ptrace/strace-like, OCI/runtime tracing), до approve обязателен manual review syscalls.

### 4.2 Не предполагайте полноту трассировки

Учитывайте, что:
- разные tracing layers дают разные наборы syscalls;
- runtime setup/syscalls могут загрязнять trace;
- одинаковый код может давать разные traces при изменениях libc, kernel, build, runtime.

### 4.3 Отделяйте app-сигнал от platform noise

Проверяйте, не попали ли в profile syscall-следы от:
- `containerd` / `containerd-shim` / `runc`;
- init containers / sidecars;
- CNI и secret-injection процессов;
- storage mount path;
- самого инструмента профилирования.

---

## 5. Область применения: Pod vs Container

### 5.1 Проверьте корректную область привязки

Подтвердите, где profile применен фактически:
- Pod security context;
- Container security context.

### 5.2 Предпочитайте container-specific profile при разном поведении контейнеров

Pod-wide profile часто расширяет разрешения, если в Pod есть init/sidecar или контейнеры с разными ролями.

---

## 6. Высокорисковые syscalls и bypass-комбинации

Проверяйте разрешения и комбинации как единую поверхность риска, а не построчно.

### 6.1 Уровень 1 (fail by default без исключительного обоснования)

По умолчанию должны быть запрещены:
- `bpf`
- `ptrace`
- `kexec_load`
- `init_module`
- `finit_module`

Если любой из них разрешен, требуйте: явное обоснование, security sign-off, компенсирующие контроли, ответственного и срок пересмотра.

### 6.2 Уровень 2 (существенный риск, требуется сильное обоснование)

Тщательно обосновывайте:
- `io_uring_setup`, `io_uring_enter`, `io_uring_register`
- `perf_event_open`
- `mount`
- `clone`, `clone3`
- `unshare`
- `add_key`, `keyctl`
- `userfaultfd`
- `chroot`

### 6.3 Зачем нужны рискованные syscalls и почему их ограничивают

Используйте эту таблицу при review, чтобы отличать реальную техническую необходимость от "приложение так стартует". Если syscall разрешен, в исключении должно быть указано: какой компонент его вызывает, какая операция без него невозможна, почему нельзя использовать менее привилегированный путь, какие capabilities выданы контейнеру и как проверяется отсутствие расширения сценариев использования.

| Syscall / группа | Для чего обычно используется | Что дает процессу | Почему ограничиваем или требуем обоснования |
| --- | --- | --- | --- |
| `bpf` | Создание и управление eBPF maps/programs, загрузка eBPF-программ в ядро, attach к tracing/network/control-plane событиям. | Возможность выполнять проверенный, но все равно kernel-resident код и хранить состояние в kernel-managed структурах. | Это прямое взаимодействие с подсистемами ядра. Для обычного app workload почти никогда не нужно; часто появляется из-за observability/CNI/tracing noise. Разрешайте только для явно выделенных eBPF/observability компонентов с отдельным security review и минимальными capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` в старых моделях). |
| `ptrace` | Отладка, трассировка, инспекция и изменение состояния другого процесса. | Чтение/изменение регистров и памяти tracee, перехват syscalls и сигналов. | В контейнере это риск утечки секретов и вмешательства в соседние процессы того же PID namespace; при ошибочной namespace/capability модели риск выходит за границы workload. Для production app контейнеров обычно должен быть запрещен, кроме специально изолированных debug/profiling сценариев. |
| `kexec_load`, `kexec_file_load` | Загрузка нового kernel image для последующего перехода без полного firmware boot. | Подготовка перезапуска системы в другой kernel. | Контейнерный workload не должен иметь путь к управлению kernel boot chain. Наличие такого syscall в профиле почти всегда означает ошибку профилирования или чрезмерные privileges; дополнительно связан с `CAP_SYS_BOOT`. |
| `init_module`, `finit_module`, `delete_module` | Загрузка и удаление kernel modules. | Изменение кода, работающего в kernel space. | Это host-level операция, несовместимая с обычной моделью изоляции контейнеров. Разрешение допустимо только для очень специальных node-level агентов, и тогда это уже отдельная privileged security-модель, а не обычный workload profile. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Создание rings и выполнение асинхронных I/O операций через io_uring. | Высокопроизводительный I/O интерфейс, где один набор syscalls может инициировать разные file/network-like операции. | Это bypass-риск для профилей, которые блокируют "классические" file/network syscalls, но оставляют io_uring. Допускайте только при доказанной performance необходимости, зафиксированном fallback и проверке, что профиль не полагается на блокировки, обходящиеся через io_uring. |
| `perf_event_open` | Performance counters, profiling, tracing, события CPU/kernel/user-space. | Доступ к счетчикам и sample/ring-buffer данным; в ряде режимов требует `CAP_PERFMON` или `CAP_SYS_ADMIN` либо зависит от `perf_event_paranoid`. | Может раскрывать поведение процессов и host/kernel activity, а также взаимодействует с BPF/perf инфраструктурой. В app контейнерах обычно не нужен; переносите profiling в отдельные controlled jobs или node agents. |
| `mount`, `umount`, `umount2`, `pivot_root` | Монтирование, размонтирование, изменение root filesystem. | Изменение mount namespace и видимости файловых систем. | При `CAP_SYS_ADMIN` это одна из самых широких поверхностей container escape и host filesystem exposure. Обычным workload не нужен runtime mount; используйте Kubernetes volumes/CSI/init-time подготовку вместо разрешения syscall. |
| `clone`, `clone3`, `unshare`, `setns` | Создание процессов/потоков и namespaces, вход в существующие namespaces. | Управление namespace/topology процесса, включая user/mount/network/PID namespace сценарии. | Не каждый `clone` опасен: процессы и потоки нужны почти всем. Риск возникает при namespace flags, `setns` и `unshare`, особенно вместе с capabilities и user namespaces. В custom профилях проверяйте аргументы, а не только имя syscall. |
| `add_key`, `keyctl`, `request_key` | Работа с kernel keyring. | Создание, поиск и использование ключей в kernel-managed keyrings. | Исторически keyring не является простым per-container ресурсом и может создавать нежелательные cross-boundary эффекты. Для приложений хранение секретов должно идти через штатные secret stores, tmpfs volumes или KMS-интеграции, а не через kernel keyring. |
| `userfaultfd` | User-space обработка page faults, live migration, checkpoint/restore, memory-management runtimes. | Передача обработки page faults в user space для выбранных memory regions. | Полезно для специализированных runtime/CRIU/migration сценариев, но редко нужно обычному сервису. Увеличивает поверхность memory-management ядра; требуйте owner, kernel-version assumptions и подтверждение, что feature нельзя заменить более простым механизмом. |
| `chroot` | Изменение root directory процесса. | Ограничение path resolution относительно нового root. | Сам по себе `chroot` не является контейнерной изоляцией и может давать ложное чувство sandboxing. В Kubernetes rootfs должен задаваться runtime/volume моделью; runtime `chroot` внутри app контейнера требует объяснения и проверки сочетания с `CAP_SYS_CHROOT`, mounts и writable paths. |
| `open_by_handle_at`, `name_to_handle_at` | Открытие файла по persistent file handle и получение такого handle. | Обход обычного path-based разрешения имени при наличии подходящего mount fd и прав. | Может ломать ожидания path-based controls и исторически фигурировал в container breakout классах. В app профилях обычно запрещайте, если нет очень конкретного storage-agent сценария. |
| `process_vm_readv`, `process_vm_writev`, `kcmp` | Межпроцессное чтение/запись памяти и сравнение kernel resources процессов. | Инспекция или модификация состояния другого процесса без ptrace-style workflow. | Это process-inspection поверхность, близкая по риску к debug/tracing. Запрещайте для обычных app контейнеров; для профилировщиков требуйте отдельный scope, PID namespace boundaries и ограничения capabilities. |
| Time syscalls: `clock_settime`, `clock_adjtime`, `settimeofday`, `stime` | Изменение системного времени. | Влияние на host/global timekeeping там, где время не namespaced. | Может ломать TLS, audit, scheduling и distributed systems assumptions. В контейнерах время обычно не должно изменяться; связано с `CAP_SYS_TIME`. |
| Low-level I/O syscalls: `iopl`, `ioperm` | Управление I/O privilege level и доступом к портам ввода-вывода. | Низкоуровневый доступ к аппаратным/архитектурным интерфейсам. | Не нужен обычному workload и связан с host-level риском; обычно должен оставаться за пределами контейнеров вместе с `CAP_SYS_RAWIO`. |

### 6.4 Обязательные проверки `io_uring`

Рассматривайте `io_uring` как syscall-multiplexing риск. Проверяйте anti-pattern:
- классические network/file/syscalls заблокированы;
- `io_uring_setup` + `io_uring_enter` разрешены.

Обязательно фиксируйте:
- зачем `io_uring` нужен бизнес-функции;
- есть ли fallback без `io_uring`;
- какой residual risk принимается.

### 6.5 Обязательные проверки `bpf`

Если `bpf` разрешен, profile считается presumptively unsafe, пока не доказано обратное.
Проверьте, не попал ли `bpf` в profile случайно из-за tracing/runtime/CNI/capabilities noise.

### 6.6 Обязательные combo-checks обхода

Проверьте комбинации:
- `io_uring_setup` + `io_uring_enter` при блокировке network syscalls;
- `io_uring_setup` + `io_uring_enter` при блокировке file/filesystem-path syscalls;
- `io_uring_setup` + `io_uring_enter` при блокировке `splice`/`tee`/`vmsplice`;
- `io_uring_setup` + `io_uring_enter` при ограничениях futex/process-wait;
- `io_uring_setup` + `io_uring_enter` при блокировке `ioctl` или xattr syscalls.

---

## 7. Runtime, capabilities и архитектура

### 7.1 Не ревьюйте seccomp в изоляции от capabilities

Проверяйте effective policy вместе с capabilities. Особенно при наличии `CAP_SYS_ADMIN`, `CAP_BPF` и других kernel-facing capabilities.

### 7.2 Учитывайте runtime-реализацию effective profile

Подтвердите:
- profile статический или runtime-генерируемый;
- есть ли capability-sensitive изменения на старте.

### 7.3 Покрытие архитектур и ABI

Проверьте явное покрытие целевых архитектур. Для релевантных окружений отдельно проверьте x32 ABI blind spots (`SCMP_ARCH_X32`).

---

## 8. Операционная корректность и lifecycle

### 8.1 Функциональная корректность

Profile не должен ломать production, но и нельзя добавлять high-risk syscalls просто чтобы workload стартовал.

### 8.2 Реалистичная валидация

Профилирование/валидация должны включать:
- реальный startup path;
- реальную инициализацию зависимостей;
- sidecar/init поведение (если есть);
- production-like kernel/runtime;
- релевантные архитектуры и libc.

### 8.3 Policy gates в CI/CD

Минимум:
- fail build при forbidden syscalls;
- fail build при опасных combo-patterns;
- ручной security review для high-risk delta;
- контроль исключений (owner + expiry).

### 8.4 Drift и проверка effective profile на nodes

Не ограничивайтесь Git YAML. Храните hash одобренного profile и сверяйте с runtime effective profile через runtime inspection (`crictl inspect` / runtime API) минимум раз в `24h` и после изменений kernel/runtime/capabilities.

---

## 9. Матрица решения ревьюера

### 9.1 Канонические антипаттерны (единый список)

- Auto-generated profile принят без ручной курации.
- Оценка качества по "количеству заблокированных syscalls".
- Блокировка classic syscalls при открытом `io_uring`.
- Ревью только статического YAML/JSON без runtime-контекста.
- Смешивание app syscalls с runtime/init/CNI noise.
- Сохранение опасных syscalls по аргументу "workload с ними работает".
- Выдача мощных capabilities без пересмотра seccomp.

### 9.2 Немедленно отклоняйте, если

- разрешены `bpf`, `ptrace`, `kexec_load`, `init_module`, `finit_module` без исключительного обоснования;
- разрешен `io_uring`, но bypass-риски не оценены;
- effective runtime policy неизвестна;
- capabilities и seccomp ревьюились раздельно.

### 9.3 Эскалируйте на ручное security review, если

- присутствуют `io_uring_*`, `mount`, `unshare`, `clone/clone3`, `perf_event_open`, `userfaultfd`, `keyctl`, `add_key`;
- profile Pod-wide для multi-container Pod;
- runtime динамически мутирует policy;
- workload требует stronger isolation, чем seccomp может реалистично обеспечить.

### 9.4 Принимайте с условиями, если

- high-risk syscalls удалены или строго обоснованы;
- scope применения корректен;
- architecture/ABI coverage подтверждено;
- bypass-комбинации и residual risk документированы;
- CI/CD обеспечивает непрерывную проверку.

---

## 10. Финальное заявление ревью

Хороший seccomp profile:
- снижает реальную поверхность атаки;
- исключает или строго контролирует high-risk syscalls;
- учитывает комбинации обхода, runtime и capabilities;
- поддерживается как непрерывный процесс, а не разовая настройка.

Профиль, который просто "строгий" или присутствует в YAML, сам по себе недостаточен.