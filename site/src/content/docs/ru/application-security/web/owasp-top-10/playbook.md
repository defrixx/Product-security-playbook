---
title: "Плейбук защиты веб-приложений по OWASP Top 10"
description: "Документ сохраняет детальную структуру OWASP Top 10:2021 ради стабильных ревью links и добавляет явное соответствие OWASP Top 10:2025, актуальному релизу OWASP для web applicati..."
sidebar:
  order: 10
---
## 1. Область

Документ сохраняет детальную структуру OWASP Top 10:2021 ради стабильных ревью links и добавляет явное соответствие OWASP Top 10:2025, актуальному релизу OWASP для web application risks. Используйте тематические разделы как базовый профиль мер контроля; для отчетности по 2025 используйте mapping ниже.

Границы документа:
- Этот плейбук задает решение по результатам web-ревью, severity и минимальные negative tests по категориям OWASP Top 10.
- Детальные требования по API authorization, GraphQL, webhooks и gRPC находятся в [плейбуке безопасности API](/Product-security-playbook/ru/application-security/api/api-security-patterns/playbook/).
- Специфичные для браузера меры контроля для CSP, CORS, cookies, embedded content и frontend supply chain находятся в [плейбуке безопасности браузера и frontend-части](/Product-security-playbook/ru/application-security/web/browser-security/playbook/).
- Secure coding details по validation, output encoding, injection, file handling и crypto misuse находятся в [плейбуке безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/).
- SAST, SCA и поиск секретов в тематических разделах ниже являются слоем применимости для web-рисков. Их общую конфигурацию, обязательные запуски, обработку результатов и подтверждение закрытия определяет плейбук безопасной разработки и ревью кода.
- Меры цепочки поставки ПО и безопасности образов контейнеров находятся в профильных supply-chain плейбуках; здесь они используются только как web release decision context.

Mapping к OWASP Top 10:2025:

| Категория OWASP Top 10:2025 | Основной раздел в этом playbook | Примечание для ревью |
|---|---|---|
| A01 Broken Access Control | Раздел 2 | Тот же основной риск; глубина по API-specific BOLA/BFLA находится в API playbook. |
| A02 Security Misconfiguration | Раздел 3 | Включает headers, CORS, XML parser settings, cloud permissions и разделение окружений. |
| A03 Software Supply Chain Failures | Раздел 4 и supply-chain playbooks | В 2025 старая категория vulnerable components расширена на build, developer, artifact, registry и vendor paths. |
| A04 Cryptographic Failures | Раздел 5 | Та же группа мер контроля; проверяйте transport, key lifecycle, token validation и storage. |
| A05 Injection | Раздел 6 | Включает SQL, shell, template, XSS, XXE, SSRF-style URL interpretation и parser-mediated injection. |
| A06 Insecure Design | Раздел 7 | Включает business logic, state machines, abuse economics и поведение при отказе при exceptional conditions. |
| A07 Authentication Failures | Раздел 8 | Детали identity/session при необходимости ведут в OIDC/OAuth playbook. |
| A08 Software or Data Integrity Failures | Раздел 9 | Включает tampered artifacts/configs, unsafe deserialization и целостность объектов, управляемых клиентом. |
| A09 Security Logging and Alerting Failures | Раздел 10 | Та же операционная группа обнаружения и реагирования. |
| A10 Mishandling of Exceptional Conditions | Разделы 7 и 10 | Fail-open handling, partial transaction recovery, resource exhaustion и sensitive error disclosure считаются release-ревью items, даже если нет классической injection или auth bypass. |

---

## 2. A01:2021 Broken Access Control

### 2.1 Угроза, описание и цель атаки

Нарушение контроля доступа возникает, когда пользователь или сервис может читать, менять или удалять данные вне своей роли и области владения. Цель атакующего: выйти за пределы разрешений, получить доступ к чужим объектам и выполнить привилегированные операции.

### 2.2 Виды и типовой ход эксплуатации

Типы:
- `IDOR` (Insecure Direct Object Reference, небезопасная прямая ссылка на объект): пользователь меняет идентификатор ресурса и получает чужие данные. Пример: `GET /api/orders/1002` заменяется на `GET /api/orders/1003`, и сервер отдает заказ другого клиента.
- `BOLA` (Broken Object Level Authorization, отсутствие проверки прав на уровне объекта): API проверяет факт логина, но не проверяет владение объектом. Пример: в GraphQL-запросе `invoice(id: "inv_778")` атакующий подставляет чужой `id` и видит чужой инвойс.
- Forced browsing (прямой вызов скрытых endpoint): доступ к роуту не из UI, а вручную по URL. Пример: обычный пользователь открывает `/admin/export` напрямую и получает выгрузку.
- Privilege escalation (эскалация привилегий): выполнение действий уровня администратора при роли пользователя. Пример: `PATCH /api/users/me` с полем `role=admin` принимается без server-side проверки.
- Token/cookie tampering (подмена сессионных/авторизационных атрибутов): изменение роли/идентификатора в токене или cookie. Пример: подмена claim `role:user -> role:admin` в неверно валидируемом JWT.
- `CORS` abuse (Cross-Origin Resource Sharing, небезопасная междоменная политика): браузер разрешает чужому origin читать ответы API с credential. Пример: сервер отражает любой `Origin` и ставит `Access-Control-Allow-Credentials: true`, из-за чего вредоносный сайт читает данные пользователя.
- `SSRF` chain (Server-Side Request Forgery, использование сервера как прокси к внутренним ресурсам): приложение по пользовательскому URL обращается во внутреннюю сеть. Пример: параметр `image_url=http://169.254.169.254/latest/meta-data/` позволяет читать cloud metadata.

Типовой ход:
- Разведка API и параметров (`user_id`, `order_id`, `tenant_id`)
- Подмена идентификатора или роли в запросе
- Проверка отсутствия server-side authorization-check
- Массовый перебор объектов и сбор данных
- Переход к операциям изменения/удаления

Что задевается:
- Изоляция данных между пользователями и tenant
- Административные функции и служебные панели
- Внутренние сервисы и management API

Последствия:
- Утечка данных, несанкционированные изменения, полный захват бизнес-функций

### 2.3 Практическая защита

- `deny-by-default` и проверка прав на каждый запрос и объект
- Централизованный policy-engine (`RBAC`/`ABAC`/`ReBAC`)
- Обязательный ownership-check (`resource.owner_id == caller.subject_id`)
- Жесткая сегментация external/internal API, mTLS между сервисами
- Ограничение `CORS` до строго согласованных origin/method/header
- Step-up auth на high-risk операциях
- Верификация:
  - негативные интеграционные тесты на горизонтальный и вертикальный обход
  - тесты forced browsing
  - мониторинг аномалий `401/403` и перебора идентификаторов

### 2.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если обход контроля доступа затрагивает admin-функции, tenant isolation, платежное состояние, bulk export или секреты.

Рабочие настройки:
- Каждая user, tenant, support, admin и service operation имеет явную запись политики: actor, action, resource, tenant и контекст (`context`).
- Authorization enforced в service/domain layer, а не только в UI, gateway, route middleware или GraphQL schema directives.
- Новые endpoints, methods, mutations и bulk/export jobs остаются `deny-by-default`, пока нет политики и negative tests.
- CORS для браузерных потоков с учетными данными использует точный список разрешенных origin; wildcard-origin при передаче учетных данных отклоняется.

Подтверждения:
- Матрица политик или эквивалентный policy-as-code для sensitive operations.
- Результаты negative tests для object-level, property-level и function-level authorization.
- Примеры audit events для allow/deny решений по sensitive actions.
- Route/API inventory с владельцем, exposure model и data classification.

Негативные тесты:
- Пользователь A не может читать, менять, удалять, экспортировать или определять существование объекта пользователя B.
- Пользователь с низкими привилегиями не может вызывать admin endpoints напрямую.
- Межтенантные object IDs, nested GraphQL nodes, batch endpoints и bulk exports отклоняются.
- Недоверенные origins не могут читать credentialed responses.

Ложные срабатывания / пропуски:
- Ответ `403` сам по себе не является достаточным подтверждением; проверяйте backend policy path, а не только поведение шлюза.
- Замечания сканера по routes часто пропускают business-object authorization и GraphQL resolver authorization.
- `404` masking допустим, но tests должны доказать отсутствие unauthorized data и timing signal.

---

## 3. A05:2021 Security Misconfiguration

### 3.1 Угроза, описание и цель атаки

Ошибки конфигурации появляются, когда приложение, сервер, контейнер или облачный сервис развернуты с небезопасными настройками. Цель атакующего: использовать дефолтные и избыточные настройки для входа, закрепления и расширения доступа.

### 3.2 Виды и типовой ход эксплуатации

Типы:
- Включенный debug/stack trace в рабочей среде: раскрываются внутренние пути, версии и переменные окружения. Пример: при ошибке сервер показывает traceback с `DB_HOST` и именем таблицы.
- Дефолтные учетные записи и пароли: вход с заводскими credential. Пример: панель администратора принимает `admin/admin`.
- Лишние HTTP-методы и открытые админ-роуты: расширяется поверхность атаки. Пример: endpoint принимает `PUT`/`DELETE`, хотя должен быть только `GET`.
- Небезопасный XML parser -> `XXE` (XML External Entity): parser разрешает внешние сущности. Пример: XML с `<!ENTITY xxe SYSTEM "file:///etc/passwd">` возвращает содержимое файла.
- Отсутствие критичных security headers (`CSP`, `HSTS`): браузер не получает ограничения на скрипты и транспорт. Пример: без CSP инъецированный inline-script успешно выполняется.
- Избыточные права сервисных аккаунтов, bucket/pvc/secret storage: локальная уязвимость быстро эскалирует. Пример: веб-сервис с правами `s3:*` читает все bucket по одному SSRF-запросу.

Типовой ход:
- Сканирование открытых панелей, debug-endpoint, версий компонентов
- Проверка дефолтных credential
- Тесты XML parser на внешние сущности
- Поиск misconfigured proxy/CORS/header policy
- Переход к чтению файлов, lateral movement, закреплению

Что задевается:
- Конфиденциальные данные и секреты
- Плоскость администрирования
- Межсервисные trust-boundary

Последствия:
- Быстрый initial access, ускоренная эскалация, устойчивое присутствие

### 3.3 Практическая защита

- Hardened baseline для всех окружений + автоматическая проверка drift
- Контроль конфигурации через policy-as-code и обязательное ревью
- Безопасный профиль XML parser с запретом DTD/External Entity где возможно
- Обязательный набор HTTP security headers
- Регулярный configuration audit и внешнее attack-surface ревью
- Верификация:
  - IaC/runtime compliance checks
  - тесты на безопасную деградацию конфигов
  - контроль отклонений от golden config

### 3.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High`, если misconfiguration раскрывает admin surfaces, secrets, cloud metadata, debug execution или internet-facing unsafe defaults.

Рабочие настройки:
- Debug mode, verbose stack traces, sample apps, default учетные данные, public admin consoles и directory listing отключены в рабочей среде.
- Security headers заданы по классу приложения; для browser-facing apps минимум принимается решение по HSTS, CSP, frame protection, content-type sniffing, referrer policy и cookie attributes.
- XML parsers отключают DTD, external entities, unsafe resolvers и unbounded entity expansion, если нет документированного legacy-исключения.
- Configuration drift проверяется на deploy и не реже чем каждые `24h` для internet-facing и high-value services.

Подтверждения:
- Результаты IaC и runtime configuration scan для deployed environment.
- External attack-surface inventory с владельцем и причиной exposure.
- Результаты проверки headers и TLS scan для browser-facing endpoints.
- Exception register для любых debug, legacy parser, public admin или weak header deviations.

Негативные тесты:
- Дефолтные учетные данные не работают на всех exposed management interfaces.
- Debug endpoints и stack traces недоступны без утвержденного admin access.
- XXE и XML bomb payloads завершаются безопасным отказом там, где принимается XML.
- Публичные endpoints не раскрывают internal version banners, environment variables или sensitive metadata.

Ложные срабатывания / пропуски:
- Header scanners могут завышать риск для non-browser API; классифицируйте по реальному client и exposure.
- Успешные IaC checks недостаточны, если runtime mutation, Helm values или экстренные изменения создают drift после deploy.
- Некоторым legacy integrations нужны более слабые настройки; оформляйте их как исключения с владельцем, компенсирующими мерами и expiry.

---

## 4. A06:2021 Vulnerable and Outdated Components

### 4.1 Угроза, описание и цель атаки

Эта категория охватывает уязвимые, неподдерживаемые или недоверенные components в application code, runtime images, plugins, client packages и build tooling. Цель атакующего: использовать известную слабость или внедрить вредоносный код через доверенный dependency path.

### 4.2 Виды и типовой ход эксплуатации

Типы:
- Известно уязвимая dependency или framework: приложение поставляет component с exploitable CVE или end-of-life support status. Пример: публичный RCE proof of concept работает против развернутого parser или web framework.
- Dependency confusion: система сборки берет пакет из публичного registry вместо внутреннего. Пример: внутренний `corp-utils` подтягивается из npm/PyPI, где атакующий опубликовал одноименный пакет.
- Typosquatting: установка пакета с похожим именем, но вредоносным содержимым. Пример: вместо `requests` устанавливается `reqeusts`, который отправляет токены наружу.
- Компрометация CI runner/plugin: вредоносный шаг выполняется в доверенной сборке. Пример: зараженный plugin CI читает `CI_SECRET` и отправляет его на внешний URL.
- Подмена артефакта между build и deploy: в registry попадает измененный image/package. Пример: тег `v1.4.2` переписывается образом с backdoor.
- Неподдерживаемый base image или runtime: OS packages и language runtimes больше не получают security fixes. Пример: container image сохраняет end-of-life runtime, потому что приложение все еще на нем собирается.

Типовой ход:
- Поиск exposed components с известными vulnerabilities или unsupported versions
- Поиск зависимости без pinning и проверки источника
- Внедрение malicious package или plugin update
- Захват CI token/secret
- Публикация подмененного артефакта в registry
- Доставка вредоносного кода в рабочую среду через легитимный pipeline

Что задевается:
- Код продукта и артефакты сборки
- CI/CD секреты и доверенные учетные данные, когда component updates или build plugins используются для abuse
- Релизный контур и downstream-сервисы

Последствия:
- Эксплуатация известных слабостей, массовая компрометация релизов и persistence на уровне цепочки поставки

### 4.3 Практическая защита

- `SBOM` (Software Bill of Materials) и инвентаризация транзитивных зависимостей
- Подпись артефактов и проверка подписи при deploy
- Internal trusted mirrors и запрет неутвержденных источников
- `SCA` (Software Composition Analysis) как обязательный gate для известных vulnerable, end-of-life и policy-banned components
- Отслеживание ownership, upgrade path и exception expiry для dependencies, base images и plugins
- Short-lived учетные данные для CI, изоляция runner, запрет shared secrets
- Верификация:
  - provenance/attestation в CD
  - мониторинг аномального publish/install
  - tabletop-упражнения по supply-chain инцидентам

### 4.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если reachable component vulnerability дает RCE, auth bypass, tenant/data compromise, компрометацию signed release artifact, раскрытие секрета CI, раскрытие учетных данных развертывания в рабочей среде или компрометацию широко используемых packages/images.

Рабочие настройки:
- Релизное развертывание использует поддерживаемые components и immutable artifact references (`sha256` digest для images), а также отклоняет mutable tags вроде `latest`.
- Релизные артефакты подписаны или сопровождаются verified provenance/attestation от trusted builder.
- CI учетные данные short-lived, scoped to pipeline и недоступны untrusted pull-request или fork builds.
- Dependency sources закреплены за approved registries или mirrors; для private package names есть меры защиты от dependency confusion.
- Фреймворки, среды выполнения, базовые образы и критичные библиотеки с завершенным сроком поддержки требуют владельца миграции, срока, компенсирующих мер и явного принятия риска.

Подтверждения:
- SBOM или dependency inventory для релизных артефактов, включая runtime/base image components там, где это доступно.
- результаты SCA с policy outcome, reachability/risk context и обработкой исключений.
- Результат provenance/signature verification из deploy gate.
- CI/CD permissions ревью для runners, workflow files, release tokens и artifact registry access.

Негативные тесты:
- Развертывание по изменяемому тегу или из неподдерживаемого базового образа отклоняется в рабочей среде.
- Неподписанный artifact, неверная builder identity, неверный repository или неверная workflow identity проваливает gate.
- Сборка из fork или недоверенной ветки не имеет доступа к подписи для рабочей среды или учетным данным развертывания.
- Dependency из unapproved source или private-name public package блокируется.

Ложные срабатывания / пропуски:
- SBOM без deploy-time policy gate — это inventory, а не enforcement.
- SCA может пропустить malicious packages без CVE и может завышать unreachable замечания; комбинируйте его с source pinning, provenance, reachability ревью и поведение ревью.
- Валидная подпись сама по себе недостаточна; проверяйте signer identity, builder identity, source, parameters и subject digest.

---

## 5. A02:2021 Cryptographic Failures

### 5.1 Угроза, описание и цель атаки

Криптографические ошибки позволяют атакующему читать, подменять или повторно использовать защищенные данные. Цель: компрометация каналов связи, хранилищ, ключей и токенов.

### 5.2 Виды и типовой ход эксплуатации

Типы:
- Отсутствие или ослабленный `TLS` (Transport Layer Security): данные передаются без надежной защиты канала. Пример: логин и пароль уходят по HTTP в открытом Wi-Fi.
- Слабые/устаревшие алгоритмы и режимы шифрования: криптозащита формально есть, но практической стойкости нет. Пример: использование устаревшего шифра позволяет дешифровать перехваченный трафик.
- Неправильное хранение паролей: пароли хранятся в plaintext или fast-hash без salt. Пример: после утечки БД хэши быстро восстанавливаются словарем.
- Утечки ключей/секретов из кода и CI: ключи попадают в Git, артефакты или логи сборки. Пример: `AWS_SECRET_ACCESS_KEY` найден в публичном commit.
- Повторный `IV` (Initialization Vector) или nonce: нарушается безопасность симметричного шифрования. Пример: повторный nonce в токенах позволяет анализировать и подделывать данные.

Типовой ход:
- Перехват трафика/поиск downgrade-пути
- Эксплуатация слабой криптоконфигурации
- Получение дампа БД/бэкапа
- Offline cracking credential и reuse
- Доступ к сервисам через скомпрометированные токены

Что задевается:
- Пароли, токены, персональные и платежные данные
- Ключевая инфраструктура
- Доверие между сервисами

Последствия:
- Массовая утечка, перехват сессий, долгосрочный компромат ключей

### 5.3 Практическая защита

- TLS 1.2+ (предпочтительно 1.3), HSTS
- Хранение ключей в `HSM`/`KMS`
- Пароли только через adaptive hash (Argon2id/scrypt/bcrypt/PBKDF2)
- Ротация ключей и секретов (плановая + аварийная)
- Шифрование данных at-rest по классификации
- Верификация:
  - крипто-инвентаризация и контроль сроков ключей
  - TLS-сканирование
  - secret scanning в репозиториях/контейнерах

### 5.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical` для учетных данных в открытом виде, эксплуатируемого слабого хранения паролей, раскрытия платежных/персональных данных, компрометации ключа подписи или возможности подделывать токены.

Рабочие настройки:
- TLS 1.3 preferred; TLS 1.2 разрешен только с modern cipher suites и без legacy protocol fallback.
- Browser-facing HTTPS использует HSTS после проверки rollout safety; preload — отдельное risk decision.
- Пароли хэшируются через Argon2id, scrypt, bcrypt или PBKDF2 с параметрами, проверенными под текущую platform cost; plaintext, reversible encryption и fast hashes отклоняются.
- Ключи находятся в KMS/HSM или утвержденной secret-management системе; emergency revocation и rotation тестируются для high-value keys.
- Шифрование sensitive data привязано к data classification, access control, backup handling и key separation.

Подтверждения:
- TLS scan и конфигурация для всех public и internal high-value endpoints.
- Конфигурация password hashing и migration plan для legacy hashes.
- Key inventory с владельцем, storage location, rotation cadence и emergency procedure.
- результаты поиска секретов для repositories, images, logs и CI artifacts.

Негативные тесты:
- HTTP и TLS downgrade attempts не раскрывают sessions или учетные данные.
- Weak JWT algorithms, unknown `kid`/JWKS sources и expired keys отклоняются там, где используются tokens.
- Известные leaked test secrets обнаруживаются в CI и image scanning.
- Восстановление из backup не обходит encryption или key-access policy.

Ложные срабатывания / пропуски:
- Оценка TLS scanner не доказывает безопасность application-level token или key lifecycle.
- Заявления "encrypted at rest" неполны без key ownership, access paths и backup coverage.
- Стойкость password hash зависит от parameters и hardware cost, а не только от названия algorithm.

---

## 6. A03:2021 Injection

### 6.1 Угроза, описание и цель атаки

Инъекции возникают, когда пользовательский ввод попадает в интерпретатор (SQL/shell/template/browser context, то есть контекст выполнения или вывода) без безопасной обработки. Цель атакующего: извлечение данных, обход авторизации и выполнение произвольного кода.

### 6.2 Виды и типовой ход эксплуатации

Типы:
- `SQLi` (SQL Injection): пользовательский ввод меняет SQL-логику запроса. Пример: `id=1 OR 1=1` возвращает все записи; в blind/time-based варианте используется `SLEEP(5)` для подтверждения.
- Command Injection: пользовательский ввод попадает в shell-команду. Пример: в параметр `filename` подставляется `report.txt; cat /etc/passwd`.
- `SSTI` (Server-Side Template Injection): ввод интерпретируется как выражение шаблонизатора. Пример: `{{7*7}}` возвращает `49`, что подтверждает выполнение кода шаблона.
- `XSS` (Cross-Site Scripting): вредоносный JavaScript выполняется в браузере жертвы. Пример: payload `<script>fetch('/api/me')</script>` в комментарии крадет данные сессии.
- `XXE` (XML External Entity): внешняя сущность в XML читает локальный файл или инициирует SSRF. Пример: XML-поле с сущностью на `file:///etc/hosts` возвращает содержимое файла.

Типовой ход:
- Поиск входной точки (параметр/заголовок/cookie/тело)
- Валидация интерпретации полезной нагрузки
- Подтверждение через ошибки/тайминг/out-of-band реакцию
- Извлечение данных или выполнение команд
- Закрепление через кражу сессии/учетных данных

Что задевается:
- Базы данных и бизнес-данные
- Сервер приложений и ОС
- Браузерные сессии пользователей

Последствия:
- Полный контроль над данными, RCE, массовая компрометация аккаунтов

### 6.3 Практическая защита

- Parameterized queries и ORM для SQL
- Запрет string-concatenation для SQL и команд
- Фильтрация входных данных + allowlist
- CSP как defense-in-depth
- Избегайте запуска shell; используйте встроенные API языка/runtime вместо shell-команд
- Контекстное экранирование на выводе
- Если выполнение OS command неизбежно: используйте фиксированный путь к executable, argv-style API без shell expansion, небольшой allowlist операций, строгую валидацию аргументов и запрет user-controlled command names
- Экранирование shell metacharacters — только last-resort compensating control, а не основная защита; отдельно тестируйте metacharacters и инъекцию аргументов.
- Изоляция процесса рендера/интерпретации (sandbox/container)
- Для SSTI: обновление шаблонизаторов, запрет пользовательских шаблонов, санитизация, logic-less templates
- Для SSRF: allowlist доверенных адресов, фильтрация параметров, учет DNS rebinding
- Для XSS/PHP-инъекций: htmlspecialchars, фильтрация/экранирование, отключение лишних функций
- `SAST`/`DAST`/fuzzing обязательны в CI
- Верификация:
  - набор regression payload-тестов
  - проверки blind/time-based сценариев
  - аудит всех новых точек ввода

### 6.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical` для unauthenticated RCE, инъекции в хранилища данных рабочих сред, command execution или cross-tenant data extraction.

Рабочие настройки:
- SQL, NoSQL, LDAP, OS command, template, XML, URL и browser sinks имеют approved safe APIs и code-review rules.
- User-controlled input никогда не выбирает executable names, template files, deserialization classes, SQL fragments или outbound network targets без strict allowlist.
- CSP используется как defense-in-depth для XSS; output encoding и санитизация остаются основными мерами контроля на стороне браузера.
- URL fetchers используют scheme/host/port allowlists, DNS rebinding defenses, metadata IP blocks и egress policy.

Подтверждения:
- Sink inventory для high-risk interpreters и downstream calls.
- Набор регрессионных payload для SQLi, command injection, SSTI, XSS, XXE, SSRF и инъекции аргументов, где применимо.
- результаты SAST, DAST и фаззинга с triage notes по reachable sinks.
- Подтверждения ревью кода для любого shell, template, deserialization или URL-fetching feature.

Негативные тесты:
- SQL metacharacters и boolean/time-based payloads не меняют query semantics.
- Метасимволы shell и инъекция аргументов не меняют поведение команды.
- Недоверенный template input не может выполнять server-side expressions.
- SSRF canaries, metadata IPs, localhost, private ranges и DNS rebinding attempts блокируются.
- XSS payloads encode/sanitize в каждом контексте вывода.

Ложные срабатывания / пропуски:
- WAF blocks не доказывают устранение проблемы; проверяйте безопасность application sink.
- SAST может завышать unreachable sinks и пропускать framework-specific пути инъекции.
- Escaping зависит от контекста и хрупок; предпочитайте parameterization, safe APIs и allowlists.

---

## 7. A04:2021 Insecure Design

### 7.1 Угроза, описание и цель атаки

Insecure design означает, что критичные защитные механизмы не предусмотрены в архитектуре и бизнес-логике. Цель атакующего: эксплуатировать системные gaps, которые невозможно быстро закрыть патчем в одном месте.

### 7.2 Виды и типовой ход эксплуатации

Типы:
- Небезопасные recovery/fallback сценарии: в упрощенном режиме система пропускает лишние проверки. Пример: при сбое SMS-сервиса подтверждение операции автоматически отключается.
- Неправильная обработка exceptional conditions: отсутствующий input, частичный сбой зависимости, timeout, duplicate callback или ошибка privilege-check оставляет систему в неизвестном или fail-open состоянии. Пример: payment flow списывает один ledger, падает при зачислении получателю и повторяется без полного rollback/idempotency guard.
- Отсутствие ограничений на критичные действия (лимит, скорость, подтверждение): нет anti-abuse барьеров. Пример: пользователь может сделать 1000 переводов подряд без rate-limit.
- Слабая tenant isolation: данные арендаторов разделены только логикой UI. Пример: подмена `tenant_id` в API показывает объекты другого клиента.
- Ошибки state machine: разрешены недопустимые переходы состояния. Пример: заказ переводится в `paid` напрямую из `draft`, минуя проверку оплаты.
- Логические race conditions: конкурирующие запросы обходят бизнес-инвариант. Пример: двойной клик по `withdraw` списывает баланс дважды.

Типовой ход:
- Анализ бизнес-процесса и пользовательских переходов
- Поиск неконтролируемого перехода состояния
- Провоцирование крайних состояний (повтор, гонка, отмена, частичный отказ)
- Принудительный переход в exception paths: timeouts, malformed optional parameters, dependency errors и interrupted transactions
- Обход ожидаемого control flow
- Выполнение запрещенной операции без формального взлома кода

Что задевается:
- Денежные операции и операции смены прав
- Целостность бизнес-состояний
- Межтенантные границы

Последствия:
- Fraud/abuse, необратимые бизнес-ошибки, системные инциденты

### 7.3 Практическая защита

- Threat modeling до разработки
- Abuse/misuse cases для всех критичных процессов
- Явные security requirements в user story
- Лимиты, анти-автоматизация, out-of-band подтверждение
- Независимое security архитектурное ревью
- Верификация:
  - тесты state machine
  - негативные бизнес-сценарии
  - adversarial walkthrough

### 7.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High` или `Critical`, когда design gaps затрагивают money movement, authorization, tenant isolation, safety, privacy или irreversible operations.

Рабочие настройки:
- Критичные flows имеют documented state machine, allowed transitions, idempotency model, replay handling и поведение при отказе.
- Меры противодействия злоупотреблениям есть для signup, login, checkout, transfer, refund, export, invite, support и privilege-change flows, где применимо.
- Операции с высоким воздействием требуют step-up, согласование, лимитов rate/velocity или dual control с учетом риска.
- Обработка exceptional conditions спроектирована для каждого critical flow: fail closed, rollback частичного состояния, сохранение idempotency, security-relevant event и безопасная user-facing error без внутренних деталей.
- Моделирование угроз обязательно до релиза для новых trust boundaries, sensitive data, external integrations, AI/agentic flows и payment/security workflows.

Подтверждения:
- Threat model или abuse-case table с residual risk и владелец.
- State-transition tests и idempotency tests для critical business operations.
- Rate/velocity/конфигурация согласований и monitoring для abuse-sensitive flows.
- Решение по релизу с accepted risks и компенсирующими мерами.

Негативные тесты:
- Invalid state transitions отклоняются.
- Duplicate, replayed, out-of-order, delayed и concurrent requests не создают unauthorized business state.
- Dependency failure не пропускает mandatory checks.
- Missing parameters, malformed optional fields, timeout, partial dependency failure и retry storms не создают inconsistent state, privilege bypass или sensitive error disclosure.
- Обычные пользователи не могут запускать high-risk support/admin/business operations без обязательных мер контроля.

Ложные срабатывания / пропуски:
- Generic STRIDE output может пропустить fraud и business-state abuse; тестируйте реальные workflows.
- Unit tests отдельных сервисов могут пропустить distributed races и retries.
- Утвержденное продуктовой командой поведение может оставаться риском безопасности, если abuse economics и monitoring не оценены.

---

## 8. A07:2021 Identification and Authentication Failures

### 8.1 Угроза, описание и цель атаки

Сбои аутентификации и управления сессией позволяют атакующему действовать от имени легитимного пользователя. Цель: захват учетной записи, обход MFA и длительное удержание сессии.

### 8.2 Виды и типовой ход эксплуатации

Типы:
- Credential stuffing и password spraying: массовые попытки входа с утекшими паролями. Пример: бот проверяет список `email:password` на `/login`.
- Brute force: перебор пароля для конкретного аккаунта. Пример: 10 000 попыток для `admin@company.com` без жесткого lockout.
- Session fixation/hijacking: фиксация или кража идентификатора сессии. Пример: жертва логинится с заранее выданным session ID атакующего.
- Слабый password reset flow: восстановление аккаунта по легко угадываемым данным. Пример: reset-token не истекает и может использоваться повторно.
- Отсутствующая/слабая `MFA` (Multi-Factor Authentication): второй фактор не обязателен для рисковых действий. Пример: перевод средств подтверждается только паролем.
- Невалидный logout/revocation: токены остаются активными после выхода. Пример: украденный refresh token продолжает выпускать новые access token.

Типовой ход:
- Использование утекших credential и автоматизированных попыток входа
- Поиск слабого recovery процесса
- Захват или фиксация session token
- Повторное использование токена после logout
- Эскалация привилегий внутри захваченной сессии

Что задевается:
- Аккаунты пользователей и админов
- Сессионные токены
- Каналы восстановления доступа

Последствия:
- Массовый захват учетных записей, мошеннические операции, потеря доверия к учетной системе

### 8.3 Практическая защита

- MFA обязательна для high-risk ролей и действий
- Проверка паролей на компрометацию
- Ротация session ID после login и privilege change
- Idle timeout + absolute timeout
- Надежный logout/revocation
- Верификация:
  - тесты устойчивости к brute-force
  - тесты фиксации/угона сессии
  - мониторинг аномалий login/reset

### 8.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical` для захвата admin-учетной записи, broken password reset, MFA bypass для действий с высоким воздействием или reusable refresh/session token compromise.

Рабочие настройки:
- Browser applications используют server-side sessions или BFF-style token handling; refresh tokens не хранятся в browser storage.
- Ротация Session ID выполняется после login, privilege elevation и recovery completion.
- User sessions имеют idle и absolute timeouts; high-risk actions требуют recent authentication.
- Меры защиты от credential stuffing включают breached-password checks, per-account и per-source throttling, bot signals и anomaly alerts.
- Logout уничтожает local session и отзывает или инвалидирует refresh/session material там, где architecture это поддерживает.

Подтверждения:
- IdP/session configuration с TTL, cookie attributes, MFA/step-up policy и reset-token lifetime.
- Негативные тесты для invalid issuer/audience/expired token, fixation, reset-token replay и logout/revocation.
- Monitoring для login failures, password spraying, reset abuse, MFA failures и impossible travel/session anomalies.
- Privileged-role inventory с MFA и break-glass handling.

Негативные тесты:
- Stolen или fixed pre-login session ID не переживает authentication.
- Reset token single-use, быстро истекает и не используется повторно после password change.
- Refresh/session token не продолжает работать бесконечно после logout, Not Before update или revocation event.
- Password spraying и credential stuffing вызывают throttling и alert signals.

Ложные срабатывания / пропуски:
- Наличие MFA не доказывает защиту, если recovery или remembered-device flows обходят второй фактор.
- Lockout может стать DoS-вектором; оценивайте adaptive throttling и step-up, а не только hard account locks.
- JWT validation tests должны включать issuer, audience, time claims, algorithm allowlist и key trust.

---

## 9. A08:2021 Software and Data Integrity Failures

### 9.1 Угроза, описание и цель атаки

Риск появляется, когда система доверяет данным, конфигам или коду без проверки происхождения и целостности. Цель атакующего: подмена обновлений/данных и внедрение опасных объектов через десериализацию.

### 9.2 Виды и типовой ход эксплуатации

Типы:
- Применение неподписанных обновлений и конфигов: система доверяет файлам без проверки происхождения. Пример: service загружает plugin ZIP без проверки подписи.
- Подмена policy/artifact в канале доставки: атакующий меняет содержимое между этапами pipeline. Пример: в registry под тем же тегом публикуется измененный container image.
- Insecure deserialization: объект из недоверенного источника десериализуется как доверенный. Пример: сериализованный payload вызывает выполнение нежелательного метода.
- Доверие к пользовательским cookie/object без `MAC` (Message Authentication Code): клиент может менять критичные поля. Пример: cookie `{"role":"user"}` меняется на `{"role":"admin"}` и принимается сервером.

Типовой ход:
- Поиск точки загрузки обновления/конфига/объекта
- Подготовка подмененного payload
- Обход проверки источника/подписи
- Выполнение измененной логики или запуск gadget chain
- Закрепление через персистентную подмену данных

Что задевается:
- Канал обновлений и конфигурация
- Внутренние модели состояния приложения
- Меры контроля целостности бизнес-данных

Последствия:
- Неавторизованное изменение логики, RCE, долговременная компрометация

### 9.3 Практическая защита

- Подписывать и верифицировать обновления, артефакты, конфиги
- Запрет unsafe deserialization для недоверенного ввода
- Отделять trusted control plane от user-controlled data plane
- Проверять integrity всех критичных объектов
- Верификация:
  - tampering-тесты
  - trust-chain checks при старте сервиса
  - алерты на signature/hash mismatch

### 9.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если integrity failure приводит к RCE, компрометации релиза в рабочую среду, payment/ledger tampering или policy bypass.

Рабочие настройки:
- Updates, plugins, models, configs, rules и релизные артефакты проверяются перед использованием.
- Deserialization недоверенного ввода запрещена, если нет узкого reviewed format и allowlist.
- Client-controlled state подписывается/MACed или хранится server-side; authorization data не доверяется из client-modifiable fields.
- Deployment и startup выполняют trust-chain checks и fail closed при mismatch для high-value components.

Подтверждения:
- Результаты проверки подписи artifact/config и конфигурация политики.
- Inventory deserialization formats и trust boundaries.
- Tests, доказывающие отклонение tampered client objects, cookies, configs и update artifacts.
- Audit/alert examples для signature, digest или policy mismatch.

Негативные тесты:
- Измененный artifact, неверный digest, неверный signer или неподписанный config отклоняются до deploy/startup.
- Сформированный serialized payload не может instantiate unsafe types или запускать dangerous code paths.
- Modified cookie/client object не может изменить role, tenant, balance, entitlement или workflow state.
- Обновление policy/rules из unapproved source отклоняется.

Ложные срабатывания / пропуски:
- Hash checks без trusted provenance или signature обнаруживают corruption, но не подтверждают authorized origin.
- Deserialization scanners могут пропустить framework-specific gadget chains и message broker payloads.
- Signed data все равно может быть unsafe при слабом контроле signing keys, canonicalization или trusted fields.

---

## 10. A09:2021 Security Logging and Monitoring Failures

### 10.1 Угроза, описание и цель атаки

Если security-события не журналируются или по ним нет своевременных алертов, инцидент остается незамеченным. Цель атакующего: увеличить dwell time и снизить вероятность блокировки.

### 10.2 Виды и типовой ход эксплуатации

Типы:
- Отсутствие журналов по критичным security-событиям: атака не оставляет сигналов для обнаружения. Пример: не журналируются неуспешные логины и смена ролей.
- Подмена/удаление локальных логов: злоумышленник стирает следы. Пример: после компрометации удаляется файл `app.log` на хосте.
- Нет корреляции в `SIEM` (Security Information and Event Management): отдельные события не складываются в инцидент. Пример: 50 ошибок авторизации и странный API-доступ не объединяются в алерт.
- Утечка ПДн и секретов через логи: логи становятся источником компромата. Пример: в log записывается `Authorization: Bearer ...`.
- Перегрузка `SOC` (Security Operations Center) шумом и false positive: критичные сигналы теряются. Пример: тысячи низкоприоритетных алертов маскируют реальную атаку.

Типовой ход:
- Выполнение скрытой атаки с минимальным шумом
- Проверка отсутствия алерта на неуспешные логины/сканирование
- Подавление следов (log tampering)
- Повторная эксплуатация без срабатывания обнаружения

Что задевается:
- Обнаружение и реагирование
- Форензика и аудит
- Регуляторная отчетность

Последствия:
- Позднее обнаружение компрометации и значительное увеличение ущерба

### 10.3 Практическая защита

- Фильтрация и экранирование пользовательского ввода (в т.ч. для безопасной записи/отображения)
- Обязательный каталог событий безопасности: аутентификация, доступ, конфигурация, привилегии и изменения данных
- Стандартизованный формат логов + correlation ID
- Tamper-evident/append-only audit trail
- Централизованный ingest, алертинг и runbook на каждый high-severity use case
- Исключение секретов и чувствительных данных из логов
- Верификация:
  - DAST/pentest должны вызывать алерты
  - регулярная проверка MTTD/MTTR
  - тесты качества обнаружения и эскалации

### 10.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High`, если отсутствие telemetry влияет на auth, authorization, admin actions, data export, платежные события/события безопасности или incident reconstruction.

Рабочие настройки:
- Security event catalog покрывает authentication, authorization decisions, admin actions, изменения привилегий, secret/key access, изменения конфигурации, data export, rate limits, validation failures и webhook/API abuse.
- Logs используют consistent schema с timestamp, actor, tenant, client, source, action, resource, decision, reason, correlation ID и request ID, где применимо.
- Tokens, учетные данные, secrets, full payment data и sensitive payloads редактируются перед сохранением.
- High-value audit logs centralized, access-controlled, tamper-evident или append-only и хранятся минимум `90d`, если нет более строгих требований.
- Оповещения имеют владельца, уровень критичности, runbook и целевой SLO реагирования.

Подтверждения:
- Sample logs для allowed и denied sensitive actions.
- Правила обнаружения и runbooks для top abuse cases.
- Retention, immutability и access-control settings для audit storage.
- MTTD/MTTR или результаты учений для realistic attack paths.

Негативные тесты:
- Всплеск неуспешных login attempts, BOLA probing, invalid token, privilege change, bulk export, webhook replay и schema validation failure создает ожидаемые events.
- Secrets и bearer tokens отсутствуют в application, proxy, job и CI logs.
- Local log deletion не удаляет central аудиторские подтверждения.
- Маршрутизация alert доходит до ожидаемого владельца с достаточным контекстом для investigation.

Ложные срабатывания / пропуски:
- Большой log volume не равен качеству обнаружения; проверяйте actionable alerts и runbooks.
- Redaction может удалить контекст расследования; где полезно, сохраняйте stable hashes/correlation IDs.
- DAST-triggered alerts могут не покрывать low-noise business abuse paths без custom tests.

---

## 11. A10:2021 Server-Side Request Forgery

### 11.1 Угроза, описание и цель атаки

Server-Side Request Forgery возникает, когда приложение делает server-side запросы к attacker-controlled URL или вычисляет attacker-controlled destinations из привилегированной инфраструктуры. Цель атакующего: заставить доверенный сервер обратиться к cloud metadata, internal services, management planes или sensitive network locations, куда атакующий не имеет прямого доступа.

### 11.2 Виды и типовой ход эксплуатации

Типы:
- URL fetchers и importers: приложение получает user-supplied URL для image preview, webhook validation, document import или link unfurling. Пример: `image_url=http://169.254.169.254/latest/meta-data/` обращается к cloud metadata.
- Parser или converter callbacks: PDF, XML, SVG, office или media processing разрешает remote references. Пример: document conversion job следует по internal URL внутри attacker-controlled content.
- Webhook и integration testing features: пользователь настраивает callback endpoint, а сервис проверяет его из privileged network. Пример: validation endpoint обращается к internal admin panel.
- DNS rebinding и redirect chains: исходный URL выглядит разрешенным, а затем redirect или DNS resolution ведет в private ranges. Пример: разрешенный public host перенаправляет на `http://127.0.0.1:8080/admin`.
- Доступ к cloud metadata: workload может обращаться к provider metadata service и получать identity tokens или учетные данные, если metadata protections и egress policy отсутствуют.

Типовой ход:
- Поиск server-side fetch, preview, webhook, import или parser feature
- Передача URL или content, который достигает private networks, loopback, link-local, metadata или internal DNS names
- Обход naive deny rules через redirects, DNS rebinding, alternate IP notation, IPv6 или поведение парсера
- Использование response timing, error messages, callbacks или stored output для inference или exfiltration internal data

Что задевается:
- Учетные данные cloud workload и metadata services
- Internal admin panels, service APIs и control planes
- Network segmentation и tenant/service boundaries

Последствия:
- Internal reconnaissance, credential theft, unauthorized internal actions и lateral movement через доверенный server

### 11.3 Практическая защита

- Allowlist exact outbound destinations по business purpose; избегайте generic "any URL" fetchers в рабочих средах.
- Проверяйте final destination после redirects, canonicalization, DNS resolution и IP normalization; блокируйте private, loopback, link-local, multicast и cloud metadata ranges, если нет явно утвержденного исключения.
- Применяйте network egress policy из workload namespace/VPC/subnet, чтобы application validation не была единственной мерой контроля.
- Отключайте или жестко настраивайте parser features, которые разрешают remote references в XML, SVG, PDF, office, media и archive processing.
- Используйте выделенные fetcher-сервисы с минимальными привилегиями, без неявно доступных облачных учетных данных и доступа к внутренним административным сетям, с ограничениями размера/времени ответа и проверяемой политикой назначения.
- Для cloud metadata требуйте provider-specific protections: IMDSv2/hop limits, workload identity scoping, metadata concealment и egress deny rules.
- Верификация:
  - redirect и DNS rebinding tests
  - private/link-local/metadata IP negative tests
  - egress policy и cloud metadata deny подтверждения

### 11.4 Базовый профиль ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если SSRF может достичь cloud metadata учетные данные, control-plane APIs, internal admin panels, tenant data services, signing/учетные данные развертывания или state-changing internal endpoints.

Рабочие настройки:
- User-controlled fetch destinations либо не поддерживаются, либо ограничены approved schemes, hosts, ports, content types и response sizes.
- Final effective destination валидируется после redirects и DNS resolution; private, loopback, link-local, multicast и metadata destinations блокируются application policy и network egress control.
- Fetching выполняется под dedicated identity без broad cloud metadata, service-mesh admin, Kubernetes API, Vault, CI/CD или internal admin access.
- Parser/converter features, способные получать remote content, отключены или routed через тот же controlled fetcher.
- SSRF attempts создают security events с source actor, feature, requested URL class, resolved destination class, decision и correlation ID.

Подтверждения:
- Inventory всех URL fetch, webhook validation, import, preview, parser и converter features с владельцем и destination policy.
- Egress policy, DNS, proxy и cloud metadata protection подтверждения для deployed environment.
- Результаты negative tests для redirects, DNS rebinding, alternate IP formats, IPv6, private ranges и metadata endpoints.
- Alert/audit samples для denied и allowed fetches.

Негативные тесты:
- `http://127.0.0.1`, `localhost`, RFC1918, link-local, IPv6 loopback, multicast и cloud metadata endpoints отклоняются.
- Redirects к denied destinations блокируются, даже если первый URL public и allowlisted.
- DNS rebinding с public на private address отклоняется после повторного resolution.
- Parser-embedded remote references не могут обращаться к internal networks.

Ложные срабатывания / пропуски:
- URL regex или hostname denylist сами по себе недостаточны; валидируйте normalized URLs, resolved addresses, redirects и effective network path.
- Proxy может централизовать policy, но только если direct egress из workload заблокирован.
- Blind SSRF может не возвращать data напрямую; проверяйте timing, callbacks, DNS logs, egress logs и denied metadata access.

---

## 12. Связанные материалы

- [Плейбук безопасности браузера и frontend-части](/Product-security-playbook/ru/application-security/web/browser-security/playbook/)
- [Плейбук безопасности API](/Product-security-playbook/ru/application-security/api/api-security-patterns/playbook/)
- [Плейбук безопасной разработки и ревью кода](/Product-security-playbook/ru/application-security/secure-coding/code-review/playbook/)
- [Плейбук моделирования угроз](/Product-security-playbook/ru/review/threat-modeling/playbook/)
