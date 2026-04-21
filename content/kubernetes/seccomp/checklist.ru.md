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

Примечание: seccomp — один слой защиты. Остальные уровни hardening проверяйте по профильным чеклистам platform/pod security.

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

## 5. Scope применения: Pod vs Container

### 5.1 Проверьте корректный scope привязки

Подтвердите, где profile применен фактически:
- Pod security context;
- Container security context.

### 5.2 Предпочитайте container-specific profile при разном поведении контейнеров

Pod-wide profile часто расширяет разрешения, если в Pod есть init/sidecar или контейнеры с разными ролями.

---

## 6. High-risk syscalls и bypass-комбинации

Проверяйте разрешения и комбинации как единую поверхность риска, а не построчно.

### 6.1 Tier 1 (default fail без исключительного обоснования)

По умолчанию должны быть запрещены:
- `bpf`
- `ptrace`
- `kexec_load`
- `init_module`
- `finit_module`

Если любой из них разрешен, требуйте: явное обоснование, security sign-off, компенсирующие контроли, ответственного и срок пересмотра.

### 6.2 Tier 2 (существенный риск, strong justification)

Тщательно обосновывайте:
- `io_uring_setup`, `io_uring_enter`, `io_uring_register`
- `perf_event_open`
- `mount`
- `clone`, `clone3`
- `unshare`
- `add_key`, `keyctl`
- `userfaultfd`
- `chroot`

### 6.3 Обязательные проверки `io_uring`

Рассматривайте `io_uring` как syscall-multiplexing риск. Проверяйте anti-pattern:
- классические network/file/syscalls заблокированы;
- `io_uring_setup` + `io_uring_enter` разрешены.

Обязательно фиксируйте:
- зачем `io_uring` нужен бизнес-функции;
- есть ли fallback без `io_uring`;
- какой residual risk принимается.

### 6.4 Обязательные проверки `bpf`

Если `bpf` разрешен, profile считается presumptively unsafe, пока не доказано обратное.
Проверьте, не попал ли `bpf` в profile случайно из-за tracing/runtime/CNI/capabilities noise.

### 6.5 Обязательные combo-checks обхода

Проверьте комбинации:
- `io_uring_setup` + `io_uring_enter` при блокировке network syscalls;
- `io_uring_setup` + `io_uring_enter` при блокировке file/filesystem-path syscalls;
- `io_uring_setup` + `io_uring_enter` при блокировке `splice`/`tee`/`vmsplice`;
- `io_uring_setup` + `io_uring_enter` при ограничениях futex/process-wait;
- `io_uring_setup` + `io_uring_enter` при блокировке `ioctl` или xattr syscalls.

---

## 7. Runtime, capabilities, architecture

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

### 8.3 CI/CD policy gates

Минимум:
- fail build при forbidden syscalls;
- fail build при опасных combo-patterns;
- ручной security review для high-risk delta;
- контроль исключений (owner + expiry).

### 8.4 Drift и проверка effective profile на nodes

Не ограничивайтесь Git YAML. Храните hash одобренного profile и сверяйте с runtime effective profile через runtime inspection (`crictl inspect` / runtime API) минимум раз в `24h` и после изменений kernel/runtime/capabilities.

---

## 9. Reviewer decision matrix

### 9.1 Канонические anti-patterns (единый список)

- Auto-generated profile принят без ручной курации.
- Оценка качества по "количеству заблокированных syscalls".
- Блокировка classic syscalls при открытом `io_uring`.
- Ревью только статического YAML/JSON без runtime-контекста.
- Смешивание app syscalls с runtime/init/CNI noise.
- Сохранение опасных syscalls по аргументу "workload с ними работает".
- Выдача мощных capabilities без пересмотра seccomp.

### 9.2 Fail immediately if

- разрешены `bpf`, `ptrace`, `kexec_load`, `init_module`, `finit_module` без исключительного обоснования;
- разрешен `io_uring`, но bypass-риски не оценены;
- effective runtime policy неизвестна;
- capabilities и seccomp ревьюились раздельно.

### 9.3 Escalate to manual security review if

- присутствуют `io_uring_*`, `mount`, `unshare`, `clone/clone3`, `perf_event_open`, `userfaultfd`, `keyctl`, `add_key`;
- profile Pod-wide для multi-container Pod;
- runtime динамически мутирует policy;
- workload требует stronger isolation, чем seccomp может реалистично обеспечить.

### 9.4 Accept with conditions if

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
