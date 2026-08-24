---
title: "Плейбук безопасности образов контейнеров и OCI-реестра"
description: "Этот плейбук описывает ревью безопасности container images и OCI registries: структуру image, базовый профиль Dockerfile, утечки секретов, привязку к digest, multi-platform imag..."
sidebar:
  order: 20
---
## 1. Область и цель

Этот плейбук описывает ревью безопасности container images и OCI registries: структуру image, базовый профиль Dockerfile, утечки секретов, привязку к digest, multi-platform images, продвижение artifacts между registries, vulnerability scanning, signing, provenance и проверку перед развертыванием.

Используйте его для:
- сервисов, которые развертываются из container images в Kubernetes или другой orchestrator;
- base images, shared runtime images, build images и release images;
- registry design, artifact promotion, retention и image admission policies;
- релизных проверок, где image identity, signature, SBOM или provenance являются частью подтверждений.

Вне области:
- общая база SAST, SCA и поиска секретов для исходного кода и зависимостей: используйте [плейбук безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/); этот документ определяет только специфику сканирования собранных образов, их слоев и OCI-артефактов;
- усиление защиты Kubernetes workload в runtime: используйте [плейбук Pod Security](/Product-security-playbook/ru/platform-security/kubernetes/pod-security/playbook/);
- container escape и Linux capability abuse: используйте [обзор container escape](/Product-security-playbook/ru/platform-security/kubernetes/container-escape-capability-abuse/overview/);
- детали политики SLSA Build provenance: используйте [обзор SLSA provenance](/Product-security-playbook/ru/supply-chain/slsa-provenance/overview/).

Цель:
- гарантировать, что релизное развертывание ссылается ровно на тот image, который прошел ревью и согласование;
- снизить image-level attack surface и риск утечки секретов;
- сделать registry promotion, signature, SBOM, provenance и vulnerability decisions проверяемыми по audit trail.

---

## 2. OCI image model

Проверяющий должен различать эти объекты:

| Объект | Значение | Что проверять |
|---|---|---|
| Image config | JSON object с runtime defaults и rootfs metadata: user, environment, entrypoint, command, labels, volumes, exposed ports и layer DiffIDs | Секреты в environment/defaults, небезопасный user, неожиданный entrypoint, metadata drift |
| Слои файловой системы | Упорядоченные наборы изменений, из которых строится корневая файловая система | Секреты в слоях, лишние инструменты, уязвимые пакеты, неожиданные бинарные файлы |
| Manifest | Platform-specific object, который ссылается на один config и ordered layer descriptors | Digest, который фактически скачивается для platform |
| Image index / manifest list | Higher-level object, указывающий на platform-specific manifests | Multi-arch ambiguity и platform coverage |
| Tag | Human-readable registry reference на index или manifest | Mutable, если registry policy не включает immutability |
| Digest | Content-addressed identifier для registry content: index, manifest, config или layer | Якорь доверия для рабочей среды |
| Image ID | Local identifier, выводимый из image config | Полезен локально, но это не registry reference, которому должен доверять Kubernetes |
| Registry repository | Namespace, группирующий related artifacts, tags, manifests, indexes, signatures, SBOMs и attestations | Access control, retention, audit, promotion |

Правило для рабочих сред:
- Tags используйте как discovery labels или release channels, а не как подтверждение согласование.
- Digests считайте identity deployable artifact.
- Для multi-arch images заранее решайте, что проверяет policy: index digest, каждый platform-specific manifest digest или оба уровня. Для critical images проверяйте оба.

---

## 3. Dockerfile baseline для рабочих сред

Обязательные меры контроля:
- Используйте minimal supported base image. Предпочитайте distroless, slim или purpose-built runtime images, когда это operationally practical.
- Закрепляйте базовый образ по digest для релизных сборок или фиксируйте точный digest базового образа в подтверждениях provenance/SBOM.
- Используйте multi-stage builds, чтобы compilers, package managers, test tools и build caches не попадали в runtime image.
- Запускайте приложение от non-root user по умолчанию. Image user должен быть совместим с Kubernetes `securityContext`.
- Image не должен требовать privileged mode, host namespaces, broad Linux capabilities, writable host paths или доступа к Docker socket.
- Не допускайте секреты в `ARG`, `ENV`, copied files, package manager config, build cache, image labels и layer history.
- Избегайте package managers и shells в runtime images, если они не нужны для operations или support.
- Задавайте команду запуска явно и избегайте shell-оберток, скрывающих неожиданное поведение.

Рабочие рекомендации:
- Используйте reproducible build inputs там, где это практично: pinned dependencies, locked package indexes, deterministic build steps и stable timestamps, если tooling это поддерживает.
- Добавляйте labels с source repository, revision, build time, license и maintainer metadata, но не помещайте sensitive internal URLs или secrets в labels.
- Держите debug tooling в отдельном debug image или controlled ephemeral debug workflow, а не в релизном runtime image.

Верификация:
- Проверяйте Dockerfile, image config, user, entrypoint, environment, exposed ports, labels и history.
- Сканируйте final runtime image, а не только build stage.
- Подтвердите, что runtime image стартует с non-root, read-only root filesystem там, где это practical, dropped capabilities и ожидаемыми mounted paths.

---

## 4. Runtime assumptions

Image hardening не заменяет Kubernetes hardening.

Рабочие настройки:
- Image не должен требовать root. Если root необходим, документируйте причину на уровне system call, filesystem, port или ownership и предпочитайте более узкий fix.
- Kubernetes `securityContext` должен enforce assumptions image: `runAsNonRoot`, `allowPrivilegeEscalation: false`, dropped capabilities, seccomp profile и read-only root filesystem там, где это practical.
- Runtime-writable paths должны быть явными: mounted volume, `emptyDir` или application data directory. Не полагайтесь на запись по всему image filesystem.
- Health checks и startup probes не должны требовать privileged tools, shell access или вывода секретов в stdout/stderr.

Верификация:
- Запустите workload с intended Pod Security profile до release.
- Подтвердите, что container fails safely, если filesystem writes, root execution или extra capabilities запрещены.

---

## 5. Утечки секретов

Типовые пути утечки:
- copied `.env`, `.npmrc`, `.pypirc`, Maven/Gradle settings, облачные учетные данные, kubeconfigs, SSH keys, certificates или package tokens;
- секреты, переданные через build args или environment variables и сохраненные в image metadata или layer history;
- private repository URLs со встроенными учетными данными;
- test fixtures, logs, crash dumps, debug bundles и generated config;
- build cache, exported to shared runners или registries.

Рабочие меры контроля:
- Используйте BuildKit secret mounts или equivalent ephemeral secret mechanisms для build-time access.
- Не копируйте developer home directories, whole repositories или broad glob patterns в images без `.dockerignore` ревью.
- Немедленно выполняйте ротацию учетных данных, если secret найден в image, даже если later layer удаляет файл. Deleted files могут оставаться recoverable from earlier layers.
- Сохраняйте подтверждения сканирования для final image digest и для base/shared images, которые потребляет много сервисов.

Верификация:
- Проверяйте image history, layer contents, config environment, labels и build logs.
- Запустите secrets scanning against built image и repository history.
- Подтвердите, что устранение включает ротацию учетных данных, registry cleanup where possible и updated меры сборки.

---

## 6. Tags, digests и multi-arch images

Рабочие настройки:
- Релизное развертывание выполняется по digest: `registry.example.com/team/app@sha256:...`.
- Immutable release tags используйте только как convenience references. Tag overwrite для релизных channels должен блокироваться или считаться release incident.
- Сохраняйте approved digest в manifests, Helm values, Kustomize overlays, GitOps state и подтверждениях развертывания.
- Resolve tag-to-digest выполняется до согласования, а не во время релизного развертывания.
- Для multi-arch images проверяйте index и platform-specific manifests, разрешенные для target cluster.

Ориентиры для ревью:
- Logical image reference вроде `app:1.2.3` может resolve в разные platform manifests на разных nodes.
- Если cluster содержит mixed architectures, admission policy должна учитывать каждую allowed platform.
- Если approved только platform manifest, развертывание не должен использовать unapproved index, который может выбрать другой platform object.

Верификация:
- Подтверждения включают image reference, index digest if present, platform manifest digest, OS/architecture, signature status, SBOM/provenance subject и deploy gate result.

---

## 7. Registry promotion и retention

Рабочие настройки:
- Promote тот же artifact из development в staging и рабочую среду по digest. Не rebuild между согласование и релизным развертыванием.
- Если copy между registries необходим, фиксируйте source digest, destination digest, media type, platform set, copy tool, actor и timestamp.
- Разделяйте write permissions и read/deploy permissions. CI, который собирает images, не должен автоматически иметь broad delete или tag-mutation rights в релизных repositories.
- Используйте repository-level или environment-level boundaries для high-value images, base images и signing/provenance artifacts.
- Retention и garbage collection должны сохранять images и linked artifacts, нужные для rollback, incident response, vulnerability investigation, customer подтверждения и audit.

Меры контроля доступа к registry:
- restrict push/delete/tag mutation to trusted release automation и small operations group;
- требуйте MFA или равноценные строгие меры аутентификации для администраторов реестра;
- log push, delete, tag mutation, изменения разрешений, anomalous pull spikes и failed authentication;
- защищайте referrers: signatures, SBOMs и provenance от удаления до истечения подтверждения retention для соответствующего image.

Верификация:
- Rollback drill может pull approved digest и linked SBOM/provenance/signature после применения retention policy.
- Tag overwrite attempt блокируется или создает alert.

---

## 8. Scanning, signing, SBOM и provenance

Базовый профиль:
- Scan final image digest на OS packages, language packages и known vulnerable components.
- Формируйте SBOM для релизных и общих базовых образов.
- Подписывайте релизные образы и проверяйте подписи перед развертыванием. Политика проверки должна закреплять ожидаемую идентичность подписанта, а не только наличие любой действительной подписи.
- Формируйте provenance для релизных сборок и привязывайте его к digest артефакта. Политика проверки должна проверять digest в `subject`, идентичность доверенной системы сборки, ожидаемый репозиторий и ref исходного кода, `buildType` и утвержденные параметры сборки.
- Выполняйте проверку при развертывании через admission, оркестрацию релиза или равноценную контрольную точку; не полагайтесь только на успешное выполнение CI.

Минимальная trust policy:
- Для keyless signing закрепляйте OIDC issuer и certificate identity/SAN за release workflow identity. Используйте exact matches или строго ограниченные patterns для одного repository/workflow/ref class.
- Для key-based signing закрепляйте public key или KMS/HSM key identity, владельца, rotation process и emergency revocation path.
- Для SLSA provenance закрепляйте trusted `builder.id`, expected `predicateType`, expected source identity и schema `externalParameters`, разрешенную для build type.
- Не смешивайте SLSA predicate versions в одной policy. `predicateType`, `builder.id`, `buildType`, source/materials fields и parameters schema должны соответствовать реальному attestation sample конкретного builder; для v0.2 и v1 нужны разные проверки или явный migration mapping.
- Для SBOMs и attestations проверяйте attestation signature и то, что attestation subject совпадает с exact image digest, который разворачивается, включая index и platform manifest policy для multi-arch images.
- Для OCI referrers или sidecar-артефактов политика хранения должна сохранять образ, подпись, SBOM и provenance вместе. Удаление referrer до окончания срока хранения является нарушением требований к подтверждениям релиза.
- Контрольные точки развертывания должны завершаться запретом для высокоценных и доступных из интернета сервисов в рабочих средах, если обязательные подпись, provenance или SBOM отсутствуют, не проходят проверку либо относятся к другому digest. Временное разрешение при ошибке требует явного break-glass-согласования, срока действия, оповещений и послерелизного ревью.

Пример policy fields:
```yaml
image: registry.example.com/team/app@sha256:...
allowed_signers:
  - oidc_issuer: https://token.actions.githubusercontent.com
    certificate_identity: repo:ORG/REPO:ref:refs/tags/v*
trusted_builders:
  - builder_id: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v*
    build_type: https://github.com/slsa-framework/slsa-github-generator/container@v1
expected_source:
  repository: github.com/ORG/REPO
  ref_pattern: refs/tags/v*
required_attestations:
  - type: slsa-provenance
    predicate_type: https://slsa.dev/provenance/v1
  - type: sbom
    format: spdx-json
multi_arch_policy: verify-index-and-platform-manifests
admission_failure_mode: fail-closed
```

Политика по уязвимостям:
- Critical/high vulnerabilities с plausible reachability или exposed attack surface должны блокировать развертывание в рабочую среду, если нет exception с владельцем, обоснованием, сроком действия, компенсирующие меры и подтверждения проверки.
- Unfixed vulnerabilities не являются automatically acceptable. Проверьте эксплуатационность, package reachability, runtime exposure, mitigations и vendor status.
- Base image vulnerabilities требуют владельца. Shared base images должны иметь faster rebuild path, потому что множество сервисов наследует их risk.

Верификация:
- Подтверждения включают scanner version/config, vulnerability result, ignored замечания with justification, signature identity, provenance predicate, builder identity, SBOM location и deploy gate decision.
- Signature подтверждения проверки включает verified image digest, certificate identity или key identity, OIDC issuer where applicable, transparency log или bundle verification status where used и policy rule, который matched.
- Подтверждения provenance/SBOM включают digest и расположение attestation, subject digest, predicate type, identity системы сборки, repository/ref исходного кода, решение по параметрам сборки и указание, был ли развернут index digest, digest platform manifest или оба уровня.
- Подтверждения admission-политики включают версию политики, область namespace/environment, режим отказа и результаты для образов только с tag, неподписанных образов и образов с подписью неверного субъекта.

---

## 9. Матрица решения ревью

Матрица ниже определяет доменную критичность замечания и решение о релизе. Общие SLA устранения, жизненный цикл исключений, принятие риска и подтверждения закрытия определяет [плейбук управления уязвимостями](/Product-security-playbook/ru/review/vulnerability-management/playbook/); при пересечении требований применяется более строгое.

| Severity | Когда использовать | Обязательное действие |
|---|---|---|
| Critical | Секрет в образе, неподписанный релизный образ там, где подпись обязательна, изменяемый непроверенный tag в рабочей среде, требование privileged/root-only execution без утвержденного исключения или невозможность связать deploy digest с утвержденными подтверждениями | Блокировать релиз до исправления; исключение требует уполномоченного принятия риска, если политика это допускает |
| High | Critical/high reachable vulnerability, stale unsupported base image, широкие registry write/delete/tag права, отсутствующая deploy-time verification для high-value service или multi-arch image с unverified target platform | Владелец, срок, устранение или accepted risk и подтверждения проверки |
| Medium | Отсутствует SBOM для non-critical service, weak retention, inconsistent labels, incomplete platform metadata или scanner coverage gap с bounded impact | Отслеживать исправление и проверить закрытие |
| Low | Documentation, metadata, cleanup или hardening improvement с ограниченным direct impact | Исправить при ближайшей возможности |

Обязательный результат ревью:
- image reference, digest, registry, platform и release context;
- краткое описание замечания и impact;
- required устранение или компенсирующая мера;
- verification method;
- владелец, срок и решение по остаточному риску.

---

## 10. Связанные материалы

- [Обзор SLSA provenance](/Product-security-playbook/ru/supply-chain/slsa-provenance/overview/)
- [Справочник infrastructure technologies](/Product-security-playbook/ru/reference/infrastructure-technologies/infrastructure-technologies/)
- [Плейбук управления уязвимостями](/Product-security-playbook/ru/review/vulnerability-management/playbook/)
- [Плейбук Pod Security](/Product-security-playbook/ru/platform-security/kubernetes/pod-security/playbook/)
- [Обзор container escape и capability abuse](/Product-security-playbook/ru/platform-security/kubernetes/container-escape-capability-abuse/overview/)
