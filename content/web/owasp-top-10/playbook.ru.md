# Плейбук защиты Web Application по OWASP Top 10:2025

## 1. Область

Этот документ задает практический базовый уровень защиты веб-приложений от ключевых рисков OWASP Top 10.

---

## 2. A01:2025 Broken Access Control

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

### 2.4 Production-база для ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если обход контроля доступа затрагивает admin-функции, tenant isolation, платежное состояние, bulk export или секреты.

Production-настройки:
- Каждая user, tenant, support, admin и service operation имеет явную policy entry: actor, action, resource, tenant, context.
- Authorization enforced в service/domain layer, а не только в UI, gateway, route middleware или GraphQL schema directives.
- Новые endpoints, methods, mutations и bulk/export jobs остаются `deny-by-default`, пока нет policy и negative tests.
- CORS для credentialed browser flows использует exact origin allowlist; wildcard origins вместе с credentials отклоняются.

Подтверждения:
- Policy matrix или эквивалентный policy-as-code для sensitive operations.
- Результаты negative tests для object-level, property-level и function-level authorization.
- Примеры audit events для allow/deny решений по sensitive actions.
- Route/API inventory с owner, exposure model и data classification.

Негативные тесты:
- Пользователь A не может читать, менять, удалять, экспортировать или определять существование объекта пользователя B.
- Пользователь с низкими привилегиями не может вызывать admin endpoints напрямую.
- Межтенантные object IDs, nested GraphQL nodes, batch endpoints и bulk exports отклоняются.
- Недоверенные origins не могут читать credentialed responses.

Ложные срабатывания / пропуски:
- Ответ `403` сам по себе не является достаточным evidence; проверяйте backend policy path, а не только gateway behavior.
- Scanner findings по routes часто пропускают business-object authorization и GraphQL resolver authorization.
- `404` masking допустим, но tests должны доказать отсутствие unauthorized data и timing signal.

---

## 3. A02:2025 Security Misconfiguration

### 3.1 Угроза, описание и цель атаки

Ошибки конфигурации появляются, когда приложение, сервер, контейнер или облачный сервис развернуты с небезопасными настройками. Цель атакующего: использовать дефолтные и избыточные настройки для входа, закрепления и расширения доступа.

### 3.2 Виды и типовой ход эксплуатации

Типы:
- Включенный debug/stack trace в production: раскрываются внутренние пути, версии и переменные окружения. Пример: при ошибке сервер показывает traceback с `DB_HOST` и именем таблицы.
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
- Регулярный configuration audit и внешнее attack-surface review
- Верификация:
  - IaC/runtime compliance checks
  - тесты на безопасную деградацию конфигов
  - контроль отклонений от golden config

### 3.4 Production-база для ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High`, если misconfiguration раскрывает admin surfaces, secrets, cloud metadata, debug execution или internet-facing unsafe defaults.

Production-настройки:
- Debug mode, verbose stack traces, sample apps, default credentials, public admin consoles и directory listing отключены в production.
- Security headers заданы по классу приложения; для browser-facing apps минимум принимается решение по HSTS, CSP, frame protection, content-type sniffing, referrer policy и cookie attributes.
- XML parsers отключают DTD, external entities, unsafe resolvers и unbounded entity expansion, если нет документированного legacy exception.
- Configuration drift проверяется на deploy и не реже чем каждые `24h` для internet-facing и high-value services.

Подтверждения:
- Результаты IaC и runtime configuration scan для deployed environment.
- External attack-surface inventory с owner и причиной exposure.
- Результаты проверки headers и TLS scan для browser-facing endpoints.
- Exception register для любых debug, legacy parser, public admin или weak header deviations.

Негативные тесты:
- Дефолтные учетные данные не работают на всех exposed management interfaces.
- Debug endpoints и stack traces недоступны без утвержденного admin access.
- XXE и XML bomb payloads fail safely там, где принимается XML.
- Публичные endpoints не раскрывают internal version banners, environment variables или sensitive metadata.

Ложные срабатывания / пропуски:
- Header scanners могут завышать риск для non-browser API; классифицируйте по реальному client и exposure.
- Успешные IaC checks недостаточны, если runtime mutation, Helm values или emergency changes создают drift после deploy.
- Некоторым legacy integrations нужны более слабые настройки; оформляйте их как exceptions с owner, compensating controls и expiry.

---

## 4. A03:2025 Software Supply Chain Failures

### 4.1 Угроза, описание и цель атаки

Это риск компрометации цепочки поставки ПО: зависимости, CI/CD, репозитории артефактов, плагины и build-инструменты. Цель атакующего: внедрить вредоносный код в доверенный релизный поток.

### 4.2 Виды и типовой ход эксплуатации

Типы:
- Dependency confusion: система сборки берет пакет из публичного registry вместо внутреннего. Пример: внутренний `corp-utils` подтягивается из npm/PyPI, где атакующий опубликовал одноименный пакет.
- Typosquatting: установка пакета с похожим именем, но вредоносным содержимым. Пример: вместо `requests` устанавливается `reqeusts`, который отправляет токены наружу.
- Компрометация CI runner/plugin: вредоносный шаг выполняется в доверенной сборке. Пример: зараженный plugin CI читает `CI_SECRET` и отправляет его на внешний URL.
- Подмена артефакта между build и deploy: в registry попадает измененный image/package. Пример: тег `v1.4.2` переписывается образом с backdoor.
- Использование уязвимых/неподдерживаемых зависимостей с `CVE` (Common Vulnerabilities and Exposures): известная дыра остается доступной в production. Пример: старая библиотека логирования позволяет RCE по публичному exploit.

Типовой ход:
- Поиск зависимости без pinning и проверки источника
- Внедрение malicious package или plugin update
- Захват CI token/secret
- Публикация подмененного артефакта в registry
- Доставка вредоносного кода в production через легитимный pipeline

Что задевается:
- Код продукта и артефакты сборки
- CI/CD секреты и доверенные учетные данные
- Релизный контур и downstream-сервисы

Последствия:
- Массовая компрометация релизов, persistence на уровне цепочки поставки

### 4.3 Практическая защита

- `SBOM` (Software Bill of Materials) и инвентаризация транзитивных зависимостей
- Подпись артефактов и проверка подписи при deploy
- Internal trusted mirrors и запрет неутвержденных источников
- `SCA` (Software Composition Analysis) как обязательный gate
- Short-lived credentials для CI, изоляция runner, запрет shared secrets
- Верификация:
  - provenance/attestation в CD
  - мониторинг аномального publish/install
  - tabletop-упражнения по supply-chain инцидентам

### 4.4 Production-база для ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если компрометация может затронуть signed release artifacts, CI secrets, production deploy credentials или широко используемые packages/images.

Production-настройки:
- Production-deploy использует immutable artifact references (`sha256` digest для images) и отклоняет mutable tags вроде `latest`.
- Release artifacts подписаны или сопровождаются verified provenance/attestation от trusted builder.
- CI credentials short-lived, scoped to pipeline и недоступны untrusted pull-request или fork builds.
- Dependency sources закреплены за approved registries или mirrors; для private package names есть dependency confusion controls.

Подтверждения:
- SBOM или dependency inventory для release artifacts.
- SCA results с policy outcome и exception handling.
- Результат provenance/signature verification из deploy gate.
- CI/CD permissions review для runners, workflow files, release tokens и artifact registry access.

Негативные тесты:
- Deploy по mutable tag отклоняется в production.
- Неподписанный artifact, неверная builder identity, неверный repository или неверная workflow identity проваливает gate.
- Build из fork/untrusted branch не имеет доступа к production signing или deploy credentials.
- Dependency из unapproved source или private-name public package блокируется.

Ложные срабатывания / пропуски:
- SBOM без deploy-time policy gate — это inventory, а не enforcement.
- SCA может пропустить malicious packages без CVE; комбинируйте его с source pinning, provenance и behavior review.
- Валидная подпись сама по себе недостаточна; проверяйте signer identity, builder identity, source, parameters и subject digest.

---

## 5. A04:2025 Cryptographic Failures

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

### 5.4 Production-база для ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical` для plaintext credentials, exploitable weak password storage, exposure платежных/персональных данных, signing-key compromise или token-forgery impact.

Production-настройки:
- TLS 1.3 preferred; TLS 1.2 разрешен только с modern cipher suites и без legacy protocol fallback.
- Browser-facing HTTPS использует HSTS после проверки rollout safety; preload — отдельное risk decision.
- Пароли хэшируются через Argon2id, scrypt, bcrypt или PBKDF2 с параметрами, проверенными под текущую platform cost; plaintext, reversible encryption и fast hashes отклоняются.
- Ключи находятся в KMS/HSM или утвержденной secret-management системе; emergency revocation и rotation тестируются для high-value keys.
- Шифрование sensitive data привязано к data classification, access control, backup handling и key separation.

Подтверждения:
- TLS scan и конфигурация для всех public и internal high-value endpoints.
- Конфигурация password hashing и migration plan для legacy hashes.
- Key inventory с owner, storage location, rotation cadence и emergency procedure.
- Secret scanning results для repositories, images, logs и CI artifacts.

Негативные тесты:
- HTTP и TLS downgrade attempts не раскрывают sessions или credentials.
- Weak JWT algorithms, unknown `kid`/JWKS sources и expired keys отклоняются там, где используются tokens.
- Известные leaked test secrets обнаруживаются в CI и image scanning.
- Восстановление из backup не обходит encryption или key-access policy.

Ложные срабатывания / пропуски:
- Оценка TLS scanner не доказывает безопасность application-level token или key lifecycle.
- Заявления "encrypted at rest" неполны без key ownership, access paths и backup coverage.
- Стойкость password hash зависит от parameters и hardware cost, а не только от названия algorithm.

---

## 6. A05:2025 Injection

### 6.1 Угроза, описание и цель атаки

Инъекции возникают, когда пользовательский ввод попадает в интерпретатор (SQL/shell/template/browser context) без безопасной обработки. Цель атакующего: извлечение данных, обход авторизации и выполнение произвольного кода.

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
- Экранирование shell metacharacters — только last-resort compensating control, а не основная защита; отдельно тестируйте metacharacters и argument injection
- Изоляция процесса рендера/интерпретации (sandbox/container)
- Для SSTI: обновление шаблонизаторов, запрет пользовательских шаблонов, санитизация, logic-less templates
- Для SSRF: whitelist доверенных адресов, фильтрация параметров, учет DNS rebinding
- Для XSS/PHP-инъекций: htmlspecialchars, фильтрация/экранирование, отключение лишних функций
- `SAST`/`DAST`/fuzzing обязательны в CI
- Верификация:
  - набор regression payload-тестов
  - проверки blind/time-based сценариев
  - аудит всех новых точек ввода

### 6.4 Production-база для ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical` для unauthenticated RCE, injection в production data stores, command execution или cross-tenant data extraction.

Production-настройки:
- SQL, NoSQL, LDAP, OS command, template, XML, URL и browser sinks имеют approved safe APIs и code-review rules.
- User-controlled input никогда не выбирает executable names, template files, deserialization classes, SQL fragments или outbound network targets без strict allowlist.
- CSP используется как defense-in-depth для XSS; output encoding и sanitization остаются primary browser-side controls.
- URL fetchers используют scheme/host/port allowlists, DNS rebinding defenses, metadata IP blocks и egress policy.

Подтверждения:
- Sink inventory для high-risk interpreters и downstream calls.
- Regression payload suite для SQLi, command injection, SSTI, XSS, XXE, SSRF и argument injection, где применимо.
- SAST/DAST/fuzzing results с triage notes по reachable sinks.
- Code review evidence для любого shell, template, deserialization или URL-fetching feature.

Негативные тесты:
- SQL metacharacters и boolean/time-based payloads не меняют query semantics.
- Метасимволы shell и argument injection не меняют command behavior.
- Недоверенный template input не может выполнять server-side expressions.
- SSRF canaries, metadata IPs, localhost, private ranges и DNS rebinding attempts блокируются.
- XSS payloads encode/sanitize в каждом output context.

Ложные срабатывания / пропуски:
- WAF blocks не доказывают remediation; проверяйте безопасность application sink.
- SAST может завышать unreachable sinks и пропускать framework-specific injection paths.
- Escaping context-specific и хрупкий; предпочитайте parameterization, safe APIs и allowlists.

---

## 7. A06:2025 Insecure Design

### 7.1 Угроза, описание и цель атаки

Insecure design означает, что критичные защитные механизмы не предусмотрены в архитектуре и бизнес-логике. Цель атакующего: эксплуатировать системные gaps, которые невозможно быстро закрыть патчем в одном месте.

### 7.2 Виды и типовой ход эксплуатации

Типы:
- Небезопасные recovery/fallback сценарии: в упрощенном режиме система пропускает лишние проверки. Пример: при сбое SMS-сервиса подтверждение операции автоматически отключается.
- Отсутствие ограничений на критичные действия (лимит, скорость, подтверждение): нет anti-abuse барьеров. Пример: пользователь может сделать 1000 переводов подряд без rate-limit.
- Слабая tenant isolation: данные арендаторов разделены только логикой UI. Пример: подмена `tenant_id` в API показывает объекты другого клиента.
- Ошибки state machine: разрешены недопустимые переходы состояния. Пример: заказ переводится в `paid` напрямую из `draft`, минуя проверку оплаты.
- Логические race conditions: конкурирующие запросы обходят бизнес-инвариант. Пример: двойной клик по `withdraw` списывает баланс дважды.

Типовой ход:
- Анализ бизнес-процесса и пользовательских переходов
- Поиск неконтролируемого перехода состояния
- Провоцирование крайних состояний (повтор, гонка, отмена, частичный отказ)
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
- Независимое security design review
- Верификация:
  - тесты state machine
  - негативные бизнес-сценарии
  - adversarial walkthrough

### 7.4 Production-база для ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High` или `Critical`, когда design gaps затрагивают money movement, authorization, tenant isolation, safety, privacy или irreversible operations.

Production-настройки:
- Критичные flows имеют documented state machine, allowed transitions, idempotency model, replay handling и failure behavior.
- Abuse controls есть для signup, login, checkout, transfer, refund, export, invite, support и privilege-change flows, где применимо.
- High-impact operations требуют step-up, approval, rate/velocity limits или dual control с учетом риска.
- Threat modeling обязателен до release для новых trust boundaries, sensitive data, external integrations, AI/agentic flows и payment/security workflows.

Подтверждения:
- Threat model или abuse-case table с residual risk и owner.
- State-transition tests и idempotency tests для critical business operations.
- Rate/velocity/approval configuration и monitoring для abuse-sensitive flows.
- Release decision с accepted risks и compensating controls.

Негативные тесты:
- Invalid state transitions отклоняются.
- Duplicate, replayed, out-of-order, delayed и concurrent requests не создают unauthorized business state.
- Dependency failure не пропускает mandatory checks.
- Normal users не могут запускать high-risk support/admin/business operations без required controls.

Ложные срабатывания / пропуски:
- Generic STRIDE output может пропустить fraud и business-state abuse; тестируйте реальные workflows.
- Unit tests отдельных сервисов могут пропустить distributed races и retries.
- Product-approved behavior может оставаться security risk, если abuse economics и monitoring не оценены.

---

## 8. A07:2025 Authentication Failures

### 8.1 Угроза, описание и цель атаки

Сбои аутентификации и управления сессией позволяют атакующему действовать от имени легитимного пользователя. Цель: account takeover, обход MFA и длительное удержание сессии.

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
- Массовый takeover, мошеннические операции, потеря доверия к учетной системе

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

### 8.4 Production-база для ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical` для admin account takeover, broken password reset, MFA bypass для high-impact actions или reusable refresh/session token compromise.

Production-настройки:
- Browser applications используют server-side sessions или BFF-style token handling; refresh tokens не хранятся в browser storage.
- Session ID ротируется после login, privilege elevation и recovery completion.
- User sessions имеют idle и absolute timeouts; high-risk actions требуют recent authentication.
- Credential stuffing controls включают breached-password checks, per-account и per-source throttling, bot signals и anomaly alerts.
- Logout уничтожает local session и отзывает или инвалидирует refresh/session material там, где architecture это поддерживает.

Подтверждения:
- IdP/session configuration с TTL, cookie attributes, MFA/step-up policy и reset-token lifetime.
- Негативные тесты для invalid issuer/audience/expired token, fixation, reset-token replay и logout/revocation.
- Monitoring для login failures, password spraying, reset abuse, MFA failures и impossible travel/session anomalies.
- Privileged-role inventory с MFA и break-glass handling.

Негативные тесты:
- Stolen или fixed pre-login session ID не переживает authentication.
- Reset token single-use, quickly expires и не используется повторно после password change.
- Refresh/session token не продолжает работать бесконечно после logout, Not Before update или revocation event.
- Password spraying и credential stuffing вызывают throttling и alert signals.

Ложные срабатывания / пропуски:
- Наличие MFA не доказывает защиту, если recovery или remembered-device flows обходят второй фактор.
- Lockout может стать DoS-вектором; оценивайте adaptive throttling и step-up, а не только hard account locks.
- JWT validation tests должны включать issuer, audience, time claims, algorithm allowlist и key trust.

---

## 9. A08:2025 Software or Data Integrity Failures

### 9.1 Угроза, описание и цель атаки

Риск появляется, когда система доверяет данным, конфигам или коду без проверки происхождения и целостности. Цель атакующего: подмена обновлений/данных и внедрение опасных объектов через десериализацию.

### 9.2 Виды и типовой ход эксплуатации

Типы:
- Применение неподписанных обновлений и конфигов: система доверяет файлам без проверки происхождения. Пример: service загружает plugin ZIP без проверки подписи.
- Подмена policy/artefact в канале доставки: атакующий меняет содержимое между этапами pipeline. Пример: в registry под тем же тегом публикуется измененный container image.
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
- Контроли целостности бизнес-данных

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

### 9.4 Production-база для ревью

Приоритет:
- Базовая severity: `High`; повышайте до `Critical`, если integrity failure приводит к RCE, production release compromise, payment/ledger tampering или policy bypass.

Production-настройки:
- Updates, plugins, models, configs, rules и release artifacts проверяются перед использованием.
- Deserialization недоверенного ввода запрещена, если нет узкого reviewed format и allowlist.
- Client-controlled state подписывается/MACed или хранится server-side; authorization data не доверяется из client-modifiable fields.
- Deployment и startup выполняют trust-chain checks и fail closed on mismatch для high-value components.

Подтверждения:
- Artifact/config signature verification results и policy configuration.
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

## 10. A09:2025 Security Logging and Alerting Failures

### 10.1 Угроза, описание и цель атаки

Если security-события не логируются или по ним нет своевременных алертов, инцидент остается незамеченным. Цель атакующего: увеличить dwell time и снизить вероятность блокировки.

### 10.2 Виды и типовой ход эксплуатации

Типы:
- Отсутствие журналов по критичным security-событиям: атака не оставляет сигналов для детекта. Пример: не логируются неуспешные логины и смена ролей.
- Подмена/удаление локальных логов: злоумышленник стирает следы. Пример: после компрометации удаляется файл `app.log` на хосте.
- Нет корреляции в `SIEM` (Security Information and Event Management): отдельные события не складываются в инцидент. Пример: 50 ошибок авторизации и странный API-доступ не объединяются в алерт.
- Утечка ПДн и секретов через логи: логи становятся источником компромата. Пример: в log записывается `Authorization: Bearer ...`.
- Перегрузка `SOC` (Security Operations Center) шумом и false positive: критичные сигналы теряются. Пример: тысячи низкоприоритетных алертов маскируют реальную атаку.

Типовой ход:
- Выполнение скрытой атаки с минимальным шумом
- Проверка отсутствия алерта на неуспешные логины/сканирование
- Подавление следов (log tampering)
- Повторная эксплуатация без срабатывания детекта

Что задевается:
- Обнаружение и реагирование
- Форензика и аудит
- Регуляторная отчетность

Последствия:
- Позднее обнаружение компрометации и значительное увеличение ущерба

### 10.3 Практическая защита

- Фильтрация и экранирование пользовательского ввода (в т.ч. для безопасной записи/отображения)
- Обязательный каталог security-событий (auth/access/config/privilege/data changes)
- Стандартизованный формат логов + correlation ID
- Tamper-evident/append-only audit trail
- Централизованный ingest, алертинг и runbook на каждый high-severity use case
- Исключение секретов и чувствительных данных из логов
- Верификация:
  - DAST/pentest должны вызывать алерты
  - регулярная проверка MTTD/MTTR
  - тесты качества детектов и эскалации

### 10.4 Production-база для ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High`, если отсутствие telemetry влияет на auth, authorization, admin actions, data export, payment/security events или incident reconstruction.

Production-настройки:
- Security event catalog покрывает authentication, authorization decisions, admin actions, privilege changes, secret/key access, configuration changes, data export, rate limits, validation failures и webhook/API abuse.
- Logs используют consistent schema с timestamp, actor, tenant, client, source, action, resource, decision, reason, correlation ID и request ID, где применимо.
- Tokens, credentials, secrets, full payment data и sensitive payloads redacted before storage.
- High-value audit logs centralized, access-controlled, tamper-evident или append-only и хранятся минимум `90d`, если нет более строгих требований.
- Alerts имеют owner, severity, runbook и target response SLO.

Подтверждения:
- Sample logs для allowed и denied sensitive actions.
- Detection rules и runbooks для top abuse cases.
- Retention, immutability и access-control settings для audit storage.
- MTTD/MTTR или exercise results для realistic attack paths.

Негативные тесты:
- Всплеск неуспешных login attempts, BOLA probing, invalid token, privilege change, bulk export, webhook replay и schema validation failure создают expected events.
- Secrets и bearer tokens отсутствуют в application, proxy, job и CI logs.
- Local log deletion не удаляет central audit evidence.
- Маршрутизация alert доходит до expected owner с достаточным контекстом для investigation.

Ложные срабатывания / пропуски:
- Большой log volume не равен detection quality; проверяйте actionable alerts и runbooks.
- Redaction может удалить investigation context; где полезно, сохраняйте stable hashes/correlation IDs.
- DAST-triggered alerts могут не покрывать low-noise business abuse paths без custom tests.

---

## 11. A10:2025 Mishandling of Exceptional Conditions

### 11.1 Угроза, описание и цель атаки

Некорректная обработка исключительных состояний (ошибки сети, БД, внешних сервисов, невалидный ввод) может перевести систему в fail-open и снять security-контроль. Цель атакующего: спровоцировать такое состояние и выполнить запрещенную операцию.

### 11.2 Виды и типовой ход эксплуатации

Типы:
- Fail-open при недоступности authz/introspection: при ошибке внешнего сервиса доступ ошибочно разрешается. Пример: API не смог проверить токен и все равно возвращает `200 OK`.
- Необработанные исключения в критичных процессах: сервис падает или пропускает проверку после exception. Пример: ошибка валидации переводит процесс в ветку без authorization-check.
- Утечка внутренних деталей через error response: атакующий получает информацию для следующего шага. Пример: ответ содержит SQL-текст, путь к файлу и версию фреймворка.
- Частично завершенные транзакции без rollback: данные остаются в неконсистентном состоянии. Пример: деньги списаны, но операция в журнале не создана из-за ошибки второго шага.

Типовой ход:
- Провоцирование исключения (таймаут, некорректный формат, race)
- Наблюдение поведения системы в ошибочном состоянии
- Повтор запросов до перехода в небезопасный режим
- Эксплуатация снятого ограничения (например, обход авторизации)

Что задевается:
- Authorization/integrity контроли
- Надежность бизнес-транзакций
- Доступность и предсказуемость сервиса

Последствия:
- Несанкционированные действия без явного взлома периметра

### 11.3 Практическая защита

- Secure-failure: критичные операции только fail-closed
- Локальная обработка исключений + глобальный fallback handler
- Скрывать внутренние детали ошибок от клиента
- Обязательный rollback для частично неуспешных транзакций
- Timeout/retry/circuit breaker без нарушения security-инвариантов
- Верификация:
  - chaos-тесты отказов зависимостей
  - тесты на missing/invalid input
  - проверки корректности rollback и error-path мониторинга

### 11.4 Production-база для ревью

Приоритет:
- Базовая severity: `Medium`; повышайте до `High` или `Critical`, когда exceptional states обходят authorization, integrity, payment, safety или audit controls.

Production-настройки:
- AuthN/AuthZ, token introspection, policy, payment и entitlement failures fail-closed by default.
- Ответы об ошибках стабильны и не раскрывают stack traces, SQL fragments, secrets, filesystem paths или internal topology.
- Timeouts, retries, circuit breakers и fallback modes сохраняют security invariants.
- Critical multi-step operations имеют idempotency, transaction boundaries, rollback/compensation и audit guarantees.
- Degraded mode имеет explicit owner, max duration, visible alert и release approval для high-value systems.

Подтверждения:
- Failure-mode matrix для critical dependencies и operations.
- Chaos/fault-injection или integration tests для authz, database, queue, payment, IdP и policy-engine failures.
- Rollback/compensation evidence для partial transactions.
- Alert и audit samples для fail-closed и degraded-mode events.

Негативные тесты:
- Недоступные policy, token introspection или entitlement service не дает доступ к protected operations.
- Некорректный input и parser errors не пропускают validation или authorization.
- Retry storms не дублируют payment, order, export или privilege-change effects.
- Ответы об ошибках не раскрывают internal details.

Ложные срабатывания / пропуски:
- Generic exception handlers могут скрыть детали от users, но все еще пропустить audit или rollback.
- Chaos tests должны проверять security outcomes, а не только availability.
- Fail-open может быть допустим для узко определенных low-risk read paths, но только с documented exception и коротким degraded window.
