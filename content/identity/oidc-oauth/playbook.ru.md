# Руководство по безопасности OIDC + OAuth 2.0

## 1. Область и цель

Этот документ описывает безопасную интеграцию OIDC (аутентификация) и OAuth 2.0 (авторизация) с Keycloak.

---

## 2. OIDC и OAuth 2.0: как они работают вместе

- **OIDC** обрабатывает пользовательский вход и выдает `id_token` (кто аутентифицирован, как и когда)
- **OAuth 2.0** выдает `access_token` и `refresh_token` для доступа к API
- В потоке Authorization Code OIDC и OAuth обычно используются вместе

Базовое правило:
- Используйте `id_token` для контекста входа/сессии в клиенте (RP), а не как bearer-токен для API
- Используйте `access_token` для авторизации в API

---

## 3. Рекомендуемые архитектурные шаблоны

### 3.1 Веб-бэкенд (серверный рендеринг)

- Конфиденциальный клиент
- Поток Authorization Code
- PKCE включен (рекомендуется даже для конфиденциальных клиентов)
- Токены хранятся на сервере
- Браузер получает только cookie сессии

### 3.2 SPA + BFF (рекомендуется для браузера)

- SPA не хранит refresh token
- BFF выполняет обмен authorization code на токены и хранит refresh token на стороне сервера
- SPA взаимодействует с BFF через защищенную сессию на основе cookie
- BFF вызывает API от имени пользователя

### 3.3 Мобильные клиенты

- Публичный клиент
- Authorization Code + PKCE (`S256`)
- Только системный браузер (ASWebAuthenticationSession / Custom Tabs)
- Refresh token хранится только в защищенном хранилище ОС

### 3.4 Взаимодействие сервис-сервис

- OAuth Client Credentials
- Отдельные машинные клиенты и scopes/roles
- Не смешивайте пользовательские токены и сервисные токены

---

## 4. Наборы токенов и назначение токенов

### 4.1 Наборы токенов по потокам

1. `authorization_code` (со scope OIDC):
- `id_token` + `access_token` + часто `refresh_token`

2. `authorization_code` (без scope OIDC):
- `access_token` + часто `refresh_token`, без `id_token`

3. `client_credentials`:
- только `access_token` (обычно без refresh token)

4. `token exchange` (RFC 8693, Keycloak V2):
- входной токен -> новый `access_token` (другой audience/scope)

5. `offline_access` (scope, а не отдельный поток):
- `offline_access` — это OAuth scope, который меняет семантику refresh token
- при запросе и разрешении выдается offline token с долгим временем жизни или без привязки к пользовательской сессии
- это не отдельный grant flow, а модификация поведения токенов в существующих потоках (например, authorization_code)

### 4.2 Назначение каждого токена

- `id_token`: результат аутентификации пользователя для контекста сессии клиента
- `access_token`: bearer-токен, предъявляемый resource server для авторизации
- `refresh_token`: получение новых access token без полного повторного входа
- `offline token`: получение новых токенов без активной браузерной сессии
- ответ `userinfo`: опциональный источник дополнительных profile claims, не замена валидации `id_token`

Правило идентичности:
- Используйте `sub` как первичный стабильный идентификатор пользователя в приложении
- Не используйте `email` как первичный ключ идентичности

### 4.3 Критичные правила безопасности

- Никогда не используйте `id_token` как API bearer
- Держите `aud` и `scope` узкими
- Используйте явные численные ограничения времени для token/session (см. раздел 6), а не формулировки «короткий/длинный»
- PKCE обязателен для публичных клиентов

---

## 5. Матрица профилей защиты (Recommended и Maximum)

Maximum-профиль задается как **delta** к Recommended: в колонке Maximum перечислены только дополнительные или ужесточенные требования.
Маркировка по профилям в тексте ниже:
- Если пункт без тега, он относится к обоим профилям (`R+M`)
- Усиления Maximum-профиля вынесены в отдельные блоки `Усиления для профиля Maximum`

| Контроль | Recommended (R) | Maximum (M) | Обоснование / Угроза |
|---|---|---|---|
| Потоки и базовая модель клиентов | Authorization Code + PKCE (`S256`), SPA+BFF/server-side web app, mobile public + system browser, service confidential + client_credentials | Дополнительно к R: обязательные строгие client policies на уровне IdP | Снижение риска перехвата кода, злоупотребления токенами и дрейфа конфигурации |
| Sender-constrained токены | Не обязательно по умолчанию | Дополнительно к R: DPoP и/или mTLS, минимум binding refresh token для public clients | Уменьшение ущерба от кражи bearer-токена и повторного использования |
| PAR/JAR | Не обязательно по умолчанию | Дополнительно к R: PAR (RFC 9126) + JAR (RFC 9101) для критичных клиентов | Защита параметров авторизации от подмены и mix-up, снижение рисков front-channel |
| MFA/step-up | По риск-ориентированной бизнес-политике | Дополнительно к R: обязательный MFA/step-up для критичных операций | Защита от захвата аккаунта и несанкционированной эскалации |
| TTL/rotation токенов | Короткие TTL, refresh token rotation, явные численные лимиты из раздела 6 | Дополнительно к R: более жесткие TTL и окна деградации для контуров повышенного риска | Снижение окна эксплуатации компрометированных токенов |
| Валидация токенов | `iss/aud/exp/nbf/iat/signature`, `alg` allowlist, `nonce`, `azp`, policy checks | Дополнительно к R: обязательная holder-of-key validation для sender-constrained токенов | Защита от поддельных/ошибочно выданных токенов, mix-up и key-confusion |
| Сессии/cookie | HttpOnly/Secure/SameSite, узкие Domain/Path, rotation session ID, CSRF controls | Дополнительно к R: запрет cross-origin для session-bound endpoints без исключений | Защита от XSS-кражи cookie, CSRF, fixation и злоупотребления областью cookie |
| Выход/отзыв | RP-initiated logout + local logout + refresh revocation | Дополнительно к R: обязательная introspection для чувствительных API в окнах после logout/инцидента | Снижение replay после logout и ускорение эффекта revocation |
| Управление ключами | Плановая rotation signing keys, trusted JWKS/issuer pinning | Дополнительно к R: ускоренная cadence rotation и более жесткий emergency cutover SLA | Снижение зоны поражения при компрометации ключей |
| Эксплуатация/мониторинг | Базовые rate limits, lockout signals, мониторинг auth/token аномалий | Дополнительно к R: усиленные anti-automation controls, более строгие алерты и SLO | Снижение brute-force/abuse и MTTR при инцидентах |

---

## 6. Единая числовая база (единый источник значений)

Все численные лимиты для token/session/replay/rate-limiting задаются здесь. В остальных разделах ссылайтесь на этот baseline, а не дублируйте значения.

### 6.1 Временные параметры токенов и сессий

- Access token TTL: `5-15m` (по умолчанию: `10m`)
- ID token TTL: `<=5m`
- Browser/BFF refresh token absolute max lifetime: `<=24h`
- Mobile refresh token absolute max lifetime: `<=30d` только при secure enclave/keystore и device trust controls
- Refresh token reuse grace window (retry races): `<=30s`
- User session idle timeout (browser): `15m`
- User session max age (browser): `8h`
- Fresh auth (`max_age`) для high-risk операций: `<=15m`
- JWT/client clock skew tolerance: `<=60s` (hard limit: `<=120s`)

### 6.2 База для replay и rate-limiting

- Token endpoint rate limit (per client + source IP): `60 req/min` sustained
- Burst budget: `120 req/min` в пределах `<=1m`
- Brute-force lockout signal: `10` неудачных попыток за `5m`
- Callback state/nonce TTL: `<=10m`, single-use
- Introspection timeout budget: connect `<=100ms`, response `<=300ms`, total `<=500ms`
- Introspection cache TTL: positive `<=30s` (не больше token `exp`/`Not Before`), negative `<=5s`
- Допустимое degraded `fail-open` окно только для low-risk class C и только по исключению: `<=120s`

### 6.3 Усиления для профиля Maximum

- Для контуров повышенного риска или регулируемых сред: ужесточайте TTL и максимальные окна деградации относительно базовых значений
- Для контуров повышенного риска или регулируемых сред: применяйте более строгие лимиты rate-limiting/burst/cache и окон деградации

---

## 7. Домены контроля

### 7.1 Поток идентификации

- Используйте Authorization Code + PKCE (`S256`) для входа пользователей в браузерных и мобильных клиентах
- Выполняйте строгие проверки целостности callback: `state` обязателен и должен точно совпадать в связке request->callback
- `nonce` обязателен для OIDC login и должен совпадать с исходным authorization request
- Redirect/logout URI: только exact match и отдельные списки для каждого окружения
- Блокируйте устаревшие grants (`implicit`, `password`), если нет утвержденного исключения

Усиления для профиля Maximum:
- Включайте PAR/JAR для критичных клиентов и потоков с повышенным риском

### 7.2 Безопасность токенов

- Валидируйте `iss`, `aud`, `exp`, `nbf`, `iat`, signature (`kid`/JWKS)
- Применяйте JWT `alg` allowlist и отклоняйте неожиданные алгоритмы
- Валидируйте `azp`, когда присутствует (особенно при нескольких audiences)
- Валидируйте authorization scopes + roles + policy (deny-by-default)
- Никогда не используйте `id_token` как API bearer
- Используйте короткие TTL/rotation и явный audience (см. раздел 6)
- `Revoke Refresh Token` включен (rotation)
- Introspection обязательна для high-risk операций, подозрительных токенов и post-incident периодов

Усиления для профиля Maximum:
- Включайте sender-constrained tokens (DPoP и/или mTLS)
- Для public clients: минимум bind refresh token, предпочтительно refresh + access
- Проверяйте holder-of-key validation в adapters/runtime для DPoP/mTLS

### 7.3 Сессии и cookie

- Browser хранит только session cookie; refresh/offline tokens в browser storage запрещены
- Application server хранит состояние сессии (Redis/DB/in-memory с репликацией)
- Session ID rotation после login callback и после повышения привилегий
- Cookie `HttpOnly`: запрещает JS-доступ и снижает риск кражи cookie при XSS
- Cookie `Secure`: отправка только по HTTPS, снижает риск перехвата в канале
- Cookie `SameSite=Lax` (или `None; Secure` для cross-site SSO): снижает CSRF/login CSRF риск
- Узкие `Domain`/`Path`: уменьшают cross-app leakage и риск cookie tossing/subdomain takeover impact
- CSRF-защита обязательна для state-changing BFF endpoints (`POST/PUT/PATCH/DELETE`): synchronizer token или double-submit cookie
- Валидируйте `Origin` (основной) и `Referer` (запасной) для браузерных state-changing запросов
- Используйте same-origin policy для session-bound endpoints и проверки `Sec-Fetch-Site`

Усиления для профиля Maximum:
- Для session-bound endpoints не допускайте cross-origin CORS без явно утвержденного исключения

### 7.4 Выход и отзыв

- Реализуйте безопасный logout flow: local session destroy -> RP-initiated logout -> strict `post_logout_redirect_uri`
- Отзывайте refresh token на logout через `/protocol/openid-connect/revoke` (RFC 7009)
- Для multi-RP экосистем настройте back-channel/front-channel logout и запасной сценарий
- При глобальном инциденте используйте `Sign out all active sessions` + realm/client `Not Before`
- Учитывайте, что sign-out сам по себе не отменяет мгновенно уже выданные access token до `exp` (см. раздел 6)
- Для чувствительных API introspection обязательна в окне `<=15m` после logout/revocation/обновления `Not Before`
- Отклоняйте токены, которые неактивны, выданы до `Not Before`, или нарушают binding context

Усиления для профиля Maximum:
- Расширяйте область обязательной introspection для дополнительных endpoint классов

### 7.5 Управление ключами

- JWT signature проверяйте только по trusted JWKS (`/protocol/openid-connect/certs`) ожидаемого issuer
- `kid` должен резолвиться в активный ключ JWKS; недоверенные/user-controlled JWKS URL запрещены
- Плановая rotation realm signing keys обязательна
- Rotation: ввод нового ключа заранее (active/passive), удаление старого только после compatibility window
- Emergency compromise: немедленный выпуск нового ключа и инвалидация sessions/tokens
- Baseline cadence: signing key rotation каждые `90d`, overlap `24-72h`, emergency cutover `<=1h`
- HTTPS only; mTLS для доверенных внутренних каналов по threat model
- Для confidential clients предпочитайте `private_key_jwt` или mTLS; `client_secret` только при обязательной rotation

Усиления для профиля Maximum:
- Ужесточайте rotation cadence и emergency SLA для regulated/high-risk сред

### 7.6 Эксплуатация и мониторинг

- Централизуйте JWT/introspection validation в middleware и сохраняйте deny-by-default authorization
- Включите аудит admin/user events в IdP и корреляцию auth/API событий в SIEM
- Мониторьте: token endpoint errors, refresh failures, invalid signature, invalid audience, token-exchange/DPoP failures
- Накапливайте и алертите replay сигналы (`state`/`nonce` reuse, повторные callback correlation IDs)
- Для introspection используйте circuit breaker + backoff + автоматическое восстановление policy после подтвержденного восстановления
- Для классов endpoint зафиксируйте policy:
  - Class A (money movement/admin/privilege change/PII export): `fail-closed`
  - Class B (state-changing business operations): `fail-closed`
  - Class C (low-risk read-only): явное решение; `fail-open` только по утвержденному исключению

Усиления для профиля Maximum:
- Усиливайте anti-automation controls и алерты (более низкие пороги и более быстрый SLA реакции)

---

## 8. Пошаговая интеграция с Keycloak

### Шаг 1. Базовая настройка realm и криптографии

- Настройте ключи realm и план rotation (см. домен Key Management)
- Включите аудит admin/user events
- Проверьте HTTPS и корректную обработку proxy headers

### Шаг 2. Создайте типы клиентов

- `web-bff` (confidential)
- `spa-frontend` (если нужен отдельный public client)
- `mobile-app` (public + PKCE)
- `service-api-client` (confidential + `client_credentials`)

### Шаг 3. Зафиксируйте redirect/logout URI

- Только exact match
- Отдельный набор URI для каждого окружения
- Настройте `Valid Post Logout Redirect URIs`

### Шаг 4. Включите безопасные возможности

- Standard Flow: ON
- Implicit: OFF
- Direct Access Grants: OFF (если нет утвержденной бизнес-необходимости)
- PKCE method: `S256`
- Revoke Refresh Token: ON (обычно)

Усиления для профиля Maximum:
- Включите PAR/JAR и sender-constrained tokens для выбранных клиентов повышенного риска

### Шаг 5. Настройте scopes/roles/audience

- Минимальные client scopes
- Отдельные API client roles
- Audience mapping на точные resource servers

### Шаг 6. Интегрируйте приложение

- Используйте `.well-known/openid-configuration` как источник эндпоинтов
- Закрепляйте доверие к ожидаемому `issuer` и используйте только `jwks_uri` этого издателя
- Храните browser session cookie, а не bearer tokens в browser storage
- В callback строго валидируйте `state` и `nonce` до создания локальной сессии

### Шаг 7. Постройте middleware resource server

- Централизуйте JWT/introspection validation
- Применяйте проверки `iss/aud/exp/nbf` и scope/role
- Сохраняйте deny-by-default authorization

### Шаг 8. Реализуйте logout/revocation/invalidation

- Реализуйте RP-initiated logout
- Реализуйте revocation refresh token path
- Подготовьте сценарий реагирования на инцидент для массового `Not Before`

### Шаг 9. Мониторинг и обнаружение

- Введите набор метрик и алертов по домену Operations/Monitoring
- Зафиксируйте сценарий реагирования для replay/brute-force/token-abuse сигналов

---

## 9. Проверки по модели угроз (обязательны в ревью)

- Перехват authorization code -> PKCE + exact redirect URI
- Кража bearer token -> короткий TTL + sender-constrained tokens там, где это требуется риск-профилем
- Повторное использование refresh token -> rotation + reuse detection
- Open redirect -> строгий allowlist
- Mix-up attacks -> валидация `iss` + строгая конфигурация client/issuer
- Повышение привилегий -> строгое разделение audience/scope/role
- Session fixation -> rotation session ID после login
- Утечка токенов в логах -> redaction и явная политика no-token logging

---

## 10. Антипаттерны

- Использование `id_token` как API bearer
- PKCE `plain` вместо `S256`
- Wildcard redirect URI
- Хранение refresh token в browser storage
- Длинный TTL access token (часы/дни)
- Один client для user login и machine-to-machine трафика без сегрегации
- Отсутствие rotation ключей и процедуры реагирования на компрометацию ключей

---

## 11. Управление исключениями (обязательно)

Любое исключение из этого профиля (TTL, rotation, лимиты сессий, introspection scope, строгость redirect, хранение токенов) должно включать:
- Конкретного владельца (команда + ответственное лицо)
- Трекер-задачу
- Явное обоснование
- Компенсирующие контроли
- Дату истечения (по умолчанию максимум `30d`, жесткий максимум `90d`)
- Критерии закрытия (что должно быть изменено, чтобы убрать исключение)

Правило release gate:
- Истекшие исключения блокируют релиз до продления с одобрением члена команды безопасности или закрытия.
