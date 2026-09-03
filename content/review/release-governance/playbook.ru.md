# Плейбук управления релизами и контрольных проверок безопасности

## 1. Область и цель

Этот плейбук задает слой контроля релизов вокруг CI/CD: security quality gates, protected environments, подтверждения развертывания, подтверждения релиза, обработку исключений и эскалацию.

Используйте документ для:
- релизов в рабочую среду и high-risk staging-релизов;
- GitLab, GitHub Actions, Argo CD, Jenkins или похожих delivery systems;
- сервисы, container images, изменения инфраструктуры, Kubernetes manifests и security-sensitive configuration.

Вне области:
- детальный разбор уязвимостей, exploitability, SLA и lifecycle исключений: используйте [плейбук управления уязвимостями](../vulnerability-management/playbook.ru.md);
- детальная реализация SLSA provenance: используйте [SLSA provenance overview](../../supply-chain/slsa-provenance/overview.ru.md);
- проверка допуска и RBAC в Kubernetes-кластере: используйте [плейбук ревью безопасности Kubernetes-кластера](../../platform-security/kubernetes/cluster-security-review/playbook.ru.md);
- architecture threat modeling: используйте [Threat Modeling Playbook](../threat-modeling/playbook.ru.md).

Цель:
- отделить право merge code от права развертывать риск;
- сделать решения по релизам основанными на подтверждениях и повторяемыми;
- не допускать незаметное развертывание в рабочую среду при замечаниях с высоким риском, непроверенных артефактах, неутвержденных исключениях и несанкционированных путях развертывания.

---

## 2. Модель угроз

Активы:
- право развертывания в рабочую среду, релизные артефакты, provenance/attestations, environment secrets, CI/CD runners, записи согласований, решения по исключениям, audit logs и customer-impacting состояние рабочей среды.

Атакующие и точки входа:
- compromised developer или maintainer account;
- malicious или compromised CI job, runner, reusable workflow, plugin или build dependency;
- insider, обходящий security checks через manual развертывание или environment permission drift;
- атакующий, подменяющий артефакты между build и deploy;
- delivery pressure, превращающий исключения в undocumented release debt.

High-impact сценарии:
- Один человек может писать код, менять pipeline, approve развертывание и deploy в рабочую среду без независимое ревью.
- Развёртывание в рабочую среду использует изменяемый тег или артефакт, который не был создан доверенным процессом релиза.
- Critical-замечание сканера подавлено без владельца, expiry, compensating control или подтверждений.
- Untrusted fork или branch получает доступ к signing, развертывание или environment secrets.
- Untrusted pull request, issue, comment, branch name, tag name или release note text интерполируется в privileged workflow step и приводит к command/script injection.
- Emergency release обходит normal gates и не оставляет следов послерелизного ревью.

---

## 3. Модель контроля релизов

### 3.1 Классы релизов

| Класс релиза | Примеры | Минимальный набор gate |
|---|---|---|
| Low-risk internal | Internal tool, no sensitive data, bounded blast radius | CI checks pass, согласование владельца, подтверждения сохранены |
| Standard live release | Customer-facing service, normal API или UI release | Security gates, protected environment, подтверждение развертывания, неизменяемость артефакта |
| High-risk live release | Auth, payment, tenant isolation, admin, secrets, platform, CI/CD, Kubernetes control plane | Независимое согласование безопасности, stricter gates, rollback plan, пакет релизных подтверждений |
| Emergency | Incident fix, срочное восстановление рабочей среды, patch для KEV/public exploit, response при broken embargo | Ускоренное согласование, narrow scope, с сохранением подтверждений, mandatory послерелизного ревью within `2 business days` |

Recommended control:
- Для каждого repository или deployable service задается default-класс релиза.
- Change может повысить класс конкретного релиза, если затрагивает auth, tenant isolation, payment, secrets, CI/CD, IaC, Kubernetes policy или privileged admin paths.

### 3.2 Разделение обязанностей

Рабочие настройки:
- Развёртывать в защищённые рабочие среды могут только выделенные идентичности CD или явно авторизованные релизные роли.
- Direct human развертывание допускается только как break-glass.
- Один человек не должен быть sole author, sole approver и sole deploy approver для high-risk релиза в рабочую среду.
- Изменения pipeline definitions, reusable workflows, manifests развертывания, IaC modules, конфигурации подписи и environment protection rules требуют ревью владельцами из CODEOWNERS или эквивалентной политики.
- Build, sign, publish и deploy jobs используют отдельные identities и permissions. Build job может публиковать unsigned candidate artifact, но не должен одновременно иметь unrestricted production deploy или signing authority, если workflow явно не прошел ревью как trusted release builder.

Верификация:
- Получите список users/groups/service accounts, которым разрешен deploy в рабочую среду.
- Подтвердите, что секреты среды доступны только заданиям, которые обращаются к защищённой среде после выполнения обязательных правил.
- Проверьте события аудита для изменений правил protected environment и подтверждений развертывания.

### 3.3 Hardening CI/CD execution plane

Рабочие настройки:
- Базовые права workflow token — read-only; права записи, `id-token: write`, публикация пакетов, подпись и права развертывания выдаются только jobs, которым они нужны.
- OIDC federation для CI/CD привязывает trust policy к issuer, audience, repository или immutable repository ID там, где это доступно, protected ref или environment, workflow identity и ожидаемому trigger. Wildcard trust на organization, project или branch prefix недопустим для развертывания в рабочую среду.
- Недоверенные forks, внешние pull requests, issues, comments, имена веток и tags, release notes и сообщения commit считаются вводом, контролируемым атакующим. Их нельзя напрямую интерполировать в shell, manifests развертывания, prompts или команды релиза.
- Third-party actions, reusable workflows, plugins и pipeline images закреплены на immutable versions или digests для release workflows; широкие floating tags допустимы только в non-release experimentation.
- Self-hosted runners разделяются по trust tier. Untrusted code не должен выполняться на persistent runners с network access к live environments, artifact signing, production secrets или учетным данным развертывания.
- Release runners должны быть ephemeral или очищаться по задокументированному standard; caches должны быть scoped по trust boundary и считаться untrusted build input.

Верификация:
- Проверьте workflow definitions на минимальные `permissions`, pinned dependencies, использование protected environments и прямую shell interpolation для untrusted context.
- Запустите workflow для fork/feature branch и подтвердите, что он не получает секреты environment, облачные роли OIDC, материалы подписи или jobs развертывания.
- Подтвердите, что runner groups/labels не позволяют untrusted jobs попадать на release или production-connected self-hosted runners.

---

## 4. Контрольные точки качества и безопасности

### 4.1 Gate types

| Gate | Назначение | Блокирующее поведение по умолчанию |
|---|---|---|
| Source governance | Protected branch/tag, обязательное ревью, CODEOWNERS for high-risk paths | Block direct релизных изменений исходного кода |
| SAST/поиск секретов | Выявление очевидных проблем в коде и секретов до релиза | Блокировать новые подтверждённые проблемы Critical/High и действующие секреты |
| SCA/SBOM | Выявление уязвимых зависимостей и ведение состава релиза | Блокировать эксплуатируемые проблемы Critical/High без исключения |
| Сканирование IaC/контейнеров | Выявление небезопасных настроек инфраструктуры, образов и среды выполнения | Блокировать Critical/High в пути релизного развертывания |
| Artifact signing/provenance | Prove artifact came from expected builder/source/workflow | Block unsigned/unverified артефакты там, где проверка обязательна |
| Тесты DAST/API | Проверить развернутую тестовую поверхность и поведение аутентификации и сессий | Блокировать подтвержденные Critical/High-проблемы, достижимые в целевом окружении |
| Ручное согласование | Зафиксировать готовность релиза и принятие риска | Обязательно для стандартных релизов и релизов с высоким риском в рабочую среду |

Рабочие настройки:
- Gates применяются к изменениям, а не только ко всему repository. Не блокируйте релиз только из-за unrelated legacy debt, если политика не говорит, что legacy debt превысил порог релиза.
- Новые Critical-замечания блокируют релиз, если нет действительного Critical-исключения.
- Новые High-замечания по умолчанию блокируют high-risk релизы в защищенные среды; standard live release может идти дальше только с владельцем, срок устранения, компенсирующими мерами и explicit acceptance.
- KEV, достоверный публичный эксплойт, активная эксплуатация, нарушение эмбарго или срочное исправление безопасности поставщика могут быть основанием для экстренного согласования узкого исправляющего релиза. Даже для такого релиза нужны идентичность артефакта, согласующий, ссылка на откат или снижение риска и подтверждения послерелизного ревью.
- Замечания по live secret блокируют релиз до revoke/rotation секрета и оценки exposure.
- Scanner output должен быть разобран как confirmed issue, false positive, accepted risk или backlog debt. Raw unreviewed reports сами по себе не считаются релизным подтверждением.

### 4.2 Gate aggregation

Рабочие настройки:
- Решение по релизу использует один aggregated status, а не набор разрозненных scanner dashboards.
- Aggregated status фиксирует: gate name, tool/source, commit/artifact digest, result, ID замечаний, ID исключений, approver, timestamp и ссылку на подтверждения.
- Failed non-security quality gate может блокировать развертывание, но security-исключения должны оставаться видимыми и отдельно утвержденными.

Верификация:
- Восстановите решение по релизу из logs и артефактов после развертывание.
- Подтвердите, что digest развернутого артефакта совпадает с digest артефакта, прошедшего gate.

---

## 5. Protected environments и подтверждения развертывания

Рабочие настройки:
- `prod` должен быть protected environment.
- `staging` protected, если содержит похожих на рабочие data, secrets, network reachability или роль release-signoff.
- Deployment authority должна быть уже, чем merge authority.
- Правила согласования зависят от environment: `prod`, regulated, platform и break-glass environments могут требовать разные группы согласующих.
- Self-согласования со стороныключен для high-risk релиза в рабочую среду, если он явно не обоснован organization policy и не компенсирован post-deploy ревью.
- Согласования развёртывания включают краткое обоснование или ссылку на релиз, а не только нажатие кнопки.

GitLab-specific notes:
- Protected environments ограничивают, кто может deploy в named environments.
- Deployment согласования могут блокировать развертывания до получения required согласования.
- Перед тем как полагаться на функции подтверждения развертывания, проверяйте их поведение для используемых tier/version.

GitHub-specific notes:
- Environments могут требовать protection rules до запуска job или доступа к environment secrets.
- Обязательные проверяющие, ограничения веток, таймеры ожидания и дополнительные правила защиты могут выражать релизную политику.
- Проверяйте plan и repository visibility, потому что feature availability отличается.

Верификация:
- Попробуйте развертывание от unauthorized user/branch и подтвердите отказ.
- Подтвердите, что environment secrets недоступны до прохождения protection rules.
- Проверьте журналы аудита для согласований, отклонений и изменений правил окружения.

---

## 6. Релизные подтверждения

Минимальный пакет подтверждений для standard live release:
- release ID, service, владелец, environment, класс релиза;
- source repository, protected ref, commit SHA и reviewed PR/MR;
- имя артефакта и immutable digest;
- CI/CD pipeline ID и runner/build identity;
- результаты gate и scanner versions/configs там, где это релевантно;
- SBOM или dependency inventory там, где это требуется;
- provenance/signature verification result там, где это требуется;
- запись о подтверждении развертывания;
- открытые замечания и утвержденные исключения;
- rollback или ссылка на задачу устранения для изменения с высоким риском.

Дополнительные подтверждения для high-risk релиза в рабочую среду:
- threat model или abuse-case update;
- negative tests для auth, tenant isolation, payment/ledger, admin или secrets path, touched by the change;
- для AI/agentic workflows: запись AI asset inventory, матрица политик, подтверждение action trace, подтверждения tool/MCP registry и kill-switch/rollback drill там, где это применимо;
- rollback/kill-switch plan;
- monitoring и alert confirmation для changed sensitive flow;
- явное согласование ответственного за безопасность.

Retention:
- Храните релизные подтверждения минимум `1 year` для рабочих сред или дольше, если это требуют regulatory, customer, audit или incident-response requirements.

---

## 7. Exceptions и escalation

Exception record должен включать:
- ID замечания или gate;
- affected service/release;
- risk statement и business reason;
- компенсирующие меры;
- владелец и approver;
- expiry date;
- условие проверки для закрытия.

Рабочие настройки:
- Critical-замечания по умолчанию отклоняются. Critical-исключение действительно только при согласовании руководителя функции безопасности и владельца бизнеса или продукта, явном TTL, компенсирующих мерах и обязательном послерелизном ревью.
- High-исключения требуют согласование владельца сервиса и ответственного за безопасность.
- Exceptions без expiry недействительны.
- Истекшие исключения автоматически проваливают следующий release gate, если не продлены через ревью.
- Emergency bypass требует послерелизного ревью в течение `2 business days`: что обошли, причина, impact, deployed artifact, residual замечания и план устранения.

Escalation triggers:
- релиз заблокирован из-за замечания уровня Critical без принятого риска;
- disputed severity или business impact;
- повторное продление исключения;
- отсутствует владелец замечания для рабочей среды;
- подтверждения не доказывают, какой артефакт был развернут.

---

## 8. Связанные материалы

- [Плейбук управления уязвимостями](../vulnerability-management/playbook.ru.md)
- [Чеклист ревью архитектуры безопасности](../architecture/checklist.ru.md)
- [Обзор безопасности AI](../../ai-security/securing-ai/overview.ru.md)
- [Плейбук безопасности Agentic AI](../../ai-security/agentic-ai/playbook.ru.md)
- [Плейбук безопасности MCP](../../ai-security/mcp-security/playbook.ru.md)
- [Плейбук безопасности container images](../../supply-chain/container-image-security/playbook.ru.md)
- [Плейбук ревью безопасности Kubernetes-кластера](../../platform-security/kubernetes/cluster-security-review/playbook.ru.md)
