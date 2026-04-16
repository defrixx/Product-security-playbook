# Security Playbook для OIDC + OAuth 2.0

## 1. Область и цель

Этот playbook описывает безопасную интеграцию OIDC (аутентификация) и OAuth 2.0 (авторизация) с Keycloak.

---

## 2. OIDC и OAuth 2.0: как они работают вместе

- **OIDC** обрабатывает пользовательский вход и выдает `id_token` (кто аутентифицирован, как и когда)
- **OAuth 2.0** выдает `access_token` и `refresh_token` для доступа к API
- В Authorization Code flow OIDC и OAuth обычно используются вместе

Базовое правило:
- Используйте `id_token` для контекста входа/сессии в клиенте (RP), а не как API bearer
- Используйте `access_token` для авторизации в API

---

## 3. Рекомендуемые архитектурные паттерны

### 3.1 Web Backend (server-rendered)

- Confidential client
- Authorization Code flow
- PKCE включен (рекомендуется даже для confidential clients)
- Токены хранятся на backend
- Браузер получает только session cookie

### 3.2 SPA + BFF (рекомендуется для браузера)

- SPA не хранит refresh token
- BFF выполняет code exchange и хранит refresh token на стороне сервера
- SPA взаимодействует с BFF через защищенную сессию на основе cookie
- BFF вызывает API от имени пользователя

### 3.3 Mobile

- Public client
- Authorization Code + PKCE (S256)
- Только system browser (ASWebAuthenticationSession / Custom Tabs)
- Refresh token хранится только в OS secure storage

### 3.4 Service-to-service

- OAuth Client Credentials
- Отдельные machine clients и scopes/roles
- Не смешивайте пользовательские токены и сервисные токены

---

## 4. Наборы токенов и назначение токенов

### 4.1 Наборы токенов по flow

1. `authorization_code` (со scope OIDC):
- `id_token` + `access_token` + часто `refresh_token`

2. `authorization_code` (без scope OIDC):
- `access_token` + часто `refresh_token`, без `id_token`

3. `client_credentials`:
- только `access_token` (обычно без refresh token)

4. `token exchange` (RFC 8693, Keycloak V2):
- входной токен -> новый `access_token` (другой audience/scope)

5. `offline_access` (scope, а не flow):
- `offline_access` — это OAuth scope, который меняет семантику refresh token
- при запросе и разрешении выдается offline token с long-lived или non-session-bound поведением
- это не отдельный grant flow, а модификация поведения токенов в существующих flow (например, authorization_code)

### 4.2 Назначение каждого токена

- `id_token`: результат аутентификации пользователя для контекста сессии клиента
- `access_token`: bearer, предъявляемый resource server для авторизации
- `refresh_token`: получение новых access token без полного повторного входа
- `offline token`: получение новых токенов без активной browser session
- ответ `userinfo`: опциональный источник дополнительных profile claims, не замена валидации `id_token`

Правило идентичности:
- Используйте `sub` как первичный стабильный идентификатор пользователя в приложении
- Не используйте `email` как первичный ключ идентичности

### 4.3 Критичные правила безопасности

- Никогда не используйте `id_token` как API bearer
- Держите `aud` и `scope` узкими
- Используйте явные численные ограничения времени для token/session (см. числовой baseline ниже), а не формулировки "короткий/длинный"
- PKCE обязателен для public clients

---

## 5. Baseline Secure Profile (Recommended)

Используйте как default для большинства систем.

1. Flow:
- Authorization Code + PKCE (`S256`)

2. Client model:
- Browser: SPA + BFF или server-side web
- Mobile: public client + PKCE + system browser
- Service: confidential + client credentials

3. Token controls:
- Access token TTL: `5-15m` (рекомендация по умолчанию: `10m`)
- ID token TTL: `<=5m`
- Browser/BFF refresh token absolute max lifetime: `<=24h`
- Mobile refresh token absolute max lifetime: `<=30d` только при хранении в secure enclave/keystore и контролях доверия к устройству
- Refresh token reuse grace window для retry races: `<=30s` (отклонять использование старого токена вне этого окна)
- `Revoke Refresh Token` включен (rotation)
- Ограниченные scopes
- Явный audience

4. Token validation:
- Валидируйте `iss`, `aud`, `exp`, `nbf`, `iat`, signature (`kid`/JWKS)
- Применяйте allowlist JWT `alg` и отклоняйте неожиданные алгоритмы
- Валидируйте `nonce` для front-channel user login flows
- Валидируйте `azp`, когда присутствует (особенно при нескольких audiences)
- Валидируйте `auth_time`/`acr`/`amr`, когда политика требует конкретной силы аутентификации
- Валидируйте authorization scopes + roles + policy

5. Проверки целостности callback:
- `state` обязателен и должен точно соответствовать request->callback
- `nonce` обязателен для OIDC login и должен совпадать с исходным значением authorization request

6. Logout:
- RP-Initiated Logout
- Local application session logout
- Back-channel/logout notifications там, где необходимо

7. Cookies:
- `HttpOnly`, `Secure`, `SameSite=Lax` (или `None; Secure` для cross-site SSO)
- Узкие `Domain` и `Path`
- Rotation Session ID после логина

8. Baseline timing и replay controls:
- User session idle timeout (browser): `15m`
- User session max age (browser): `8h`
- Для high-risk операций требуется свежее событие аутентификации в пределах `<=15m` (`max_age`)
- Допустимый clock skew при JWT validation: `<=60s` (жесткий предел: `<=120s`)
- Baseline rate limit для token endpoint:
  - Per client + source IP: `60 req/min` sustained
  - Burst: `120 req/min` в течение `<=1m`
  - Сигнал lockout от brute-force login/token после `10` неудачных попыток за `5m`

---

## 6. Maximum Security Profile

Используйте для high-risk и регулируемых сред.

1. Все из Recommended profile плюс:
- Sender-constrained tokens (DPoP и/или mTLS)
- PAR (RFC 9126)
- JAR (RFC 9101)
- Строгие client policies в Keycloak
- Обязательный MFA/step-up для критичных операций

2. DPoP в Keycloak 26.4+:
- Включайте `Require DPoP bound tokens` для выбранных clients
- Для public clients как минимум привязывайте refresh token (предпочтительно refresh + access)
- Проверяйте совместимость adapter/runtime для валидации holder-of-key

3. mTLS (где применимо):
- Аутентификация клиента на основе сертификата
- Certificate-bound tokens (RFC 8705), когда требуется

4. Дополнительные контроли:
- Строгий CORS
- Блокируйте устаревшие grants (implicit, password)
- Anti-automation и rate limiting на auth/token endpoints

---

## 7. Certificates, Keys, JWKS и Signatures

### 7.1 Что resource server обязан валидировать

- JWT signature по ключам JWKS (`/protocol/openid-connect/certs`)
- `kid` в JWT header должен резолвиться в активный ключ JWKS
- Доверяйте только ожидаемому issuer и его JWKS location из доверенных discovery metadata
- Никогда не принимайте JWKS с недоверенных или user-controlled URL

### 7.2 Rotation ключей в Keycloak (realm keys)

- Плановая rotation обязательна
- Вводите новый ключ заранее (подход active/passive)
- Удаляйте старый ключ только после окна совместимости
- При компрометации: немедленно выпустите новый ключ и инвалидируйте sessions/tokens
- Baseline cadence:
  - Rotation signing key каждые `90d` (или чаще для регулируемых профилей)
  - Окно overlap совместимости: `24-72h`
  - Цель emergency rotation при компрометации: полное переключение ключа за `<=1h`

### 7.3 TLS certificates

- Только HTTPS
- mTLS для доверенных внутренних каналов, где это требуется threat model
- Контролируйте набор доверенных CA и срок жизни сертификатов

### 7.4 Client auth на token endpoint

- Для confidential clients предпочитайте `private_key_jwt` или mTLS
- `client_secret` допустим только при обязательной rotation
- Применяйте policy ротации client secret в Keycloak

---

## 8. Sessions и хранение сессий

### 8.1 Где хранить

- Browser: только session cookie
- Application server: session state (Redis/DB/in-memory с репликацией)
- Refresh/offline tokens: server-side storage или OS secure storage на mobile

### 8.2 Что нельзя хранить в браузере

- Refresh token в `localStorage`/`sessionStorage` запрещен
- Access token в JS runtime только когда это неизбежно и с коротким TTL

### 8.3 Модель session timeout

Выравнивайте настройки Keycloak и приложения:
- SSO Session Idle
- SSO Session Max
- Client Session Idle/Max
- Access Token Lifespan
- Refresh token rotation policy
Иначе app session и валидность upstream token могут рассинхронизироваться.

Baseline defaults:
- SSO Session Idle: `15m`
- SSO Session Max: `8h`
- Client Session Idle: `15m`
- Client Session Max: `8h`
- Access Token Lifespan: `10m`
- Допуск client clock skew: `<=60s`

### 8.4 BFF session security controls (обязательно)

- CSRF-защита обязательна для всех state-changing BFF endpoints (`POST/PUT/PATCH/DELETE`):
  - Паттерн synchronizer token или double-submit cookie
  - Валидируйте `Origin` (основной) и `Referer` (fallback) для браузерных запросов
  - Отклоняйте запросы без валидного CSRF token даже при наличии session cookie
- Политика same-origin для session-bound endpoints:
  - Не разрешайте cross-origin CORS для BFF session endpoints
  - Разрешайте только точные frontend origin(s) для CORS non-session API там, где это явно требуется
  - Применяйте проверки `Sec-Fetch-Site` и отклоняйте cross-site запросы для session operations
- Детектирование replay authorization code в login callback:
  - Храните `state` и `nonce` server-side с семантикой single-use и TTL `<=10m`
  - Отклоняйте callback, если `state` отсутствует, истек или уже использован
  - Фиксируйте и отправляйте алерты по попыткам replay (повторно использованный `state`, повторный callback correlation ID)
- Выполняйте rotation локального session ID после успешного login callback и событий повышения привилегий.

---

## 9. Logout, отзыв сессий и отзыв токенов

### 9.1 Типовой безопасный logout flow

1. Уничтожьте локальную сессию приложения
2. Вызовите OIDC RP-Initiated Logout (`end_session_endpoint`)
3. Вернитесь на строго зарегистрированный `post_logout_redirect_uri`

### 9.2 Глобальный экстренный отзыв

В Keycloak:

- `Sign out all active sessions` инвалидирует SSO cookies
- `Revocation` / `Not Before` массово инвалидирует ранее выданные токены
- Некоторые adapters поддерживают push-распространение not-before

Важно: один только sign-out не инвалидирует мгновенно уже выданные access token до `exp`; используйте короткий TTL и стратегию introspection/revocation там, где это требуется.

### 9.3 Endpoint отзыва токенов

- Используйте `/protocol/openid-connect/revoke` (RFC 7009)
- Отзывайте refresh token при logout
- При включенной rotation храните server-side только последний refresh token

### 9.4 Back-channel/front-channel logout

- Настройте back-channel/front-channel logout для экосистем с несколькими RP
- Всегда проектируйте fallback: локальный logout приложения должен оставаться корректным при частичном сбое federation/logout channels

### 9.5 Replay токенов после logout: обязательный контроль

- Для чувствительных API (движение денег, изменение привилегий, экспорт PII, административные действия) introspection обязательна по умолчанию даже для JWT token.
- Применяйте проверки revocation токенов в течение `<=15m` после logout пользователя, глобальных обновлений `Not Before` или revocation по инциденту.
- Отклоняйте токены, которые:
  - неактивны в introspection
  - выданы до текущего realm/client `Not Before`
  - вне разрешенного контекста привязки сессии (когда включены sender-constrained tokens)

---

## 10. Проверки авторизации и актуальности токена

### 10.1 Проверки авторизации

Resource server должен валидировать:
- `scope` (права на операции)
- `realm/client roles`
- `aud` (токен выпущен для этого API)
- Контекстные условия (tenant, владение ресурсом, ABAC/RBAC policy)

### 10.2 Модель актуальности токена

Две модели:

1. Локальная валидация JWT (быстро, низкая стоимость):
- Валидация подписи и claims (`exp`, `nbf`, `iss`, `aud`)
- Подходит для high-throughput API

2. Introspection (RFC 7662):
- Валидация `active` и server-side состояния токена
- Требуется для high-risk операций или почти real-time revocation

Production pattern:
- Локальная валидация по умолчанию
- Introspection обязательна для high-risk операций, подозрительных токенов и пост-инцидентных периодов

### 10.3 Модель устойчивости introspection (обязательно)

Определите и применяйте явное поведение при деградации IdP/introspection:

- Бюджет таймаутов (на один вызов introspection):
  - Connect timeout: `<=100ms`
  - Response timeout: `<=300ms`
  - Общий бюджет запроса: `<=500ms`
- Кэширование результатов (ограниченное и учитывающее revocation):
  - Positive cache TTL: `<=30s` и никогда не больше token `exp` / текущего `Not Before`
  - Negative/inactive cache TTL: `<=5s`
  - Сбрасывайте cache при инцидентах revocation и обновлениях `Not Before`
- Policy по классам endpoints (без неявного поведения):
  - Class A (движение денег, admin, изменения привилегий, экспорт PII): `fail-closed`
  - Class B (state-changing бизнес-операции): `fail-closed`
  - Class C (низкорисковые read-only endpoints): требуется явное решение; `fail-open` допустим только по утвержденному исключению с max degraded window `<=120s`
- Контроли degraded-mode:
  - Триггерите алерт при росте ошибки introspection/SLA breach
  - Включайте circuit breaker и backoff, чтобы предотвратить перегрузку IdP
  - Автоматически возвращайтесь к нормальной policy после подтвержденного восстановления introspection

---

## 11. Пошаговая интеграция с Keycloak

### Step 1. Baseline realm и cryptography

- Настройте ключи realm и план rotation
- Включите audit admin/user events
- Проверьте HTTPS и обработку proxy headers

### Step 2. Создайте типы clients

- `web-bff` (confidential)
- `spa-frontend` (если нужен отдельный public client)
- `mobile-app` (public + PKCE)
- `service-api-client` (confidential + client_credentials)

### Step 3. Зафиксируйте redirect/logout URIs

- Только exact match
- Отдельный набор URI для каждого окружения
- Настройте `Valid Post Logout Redirect URIs`

### Step 4. Включите безопасные capabilities

- Standard Flow: ON
- Implicit: OFF
- Direct Access Grants: OFF (если нет сильной бизнес-необходимости)
- PKCE method: `S256`
- Revoke Refresh Token: ON (обычно)
- Применяйте минимальные client policies (PKCE, безопасные redirects)

### Step 5. Настройте scopes/roles/audience

- Минимальные client scopes
- Отдельные API client roles
- Audience mapping на точные resource servers

### Step 6. Интегрируйте приложение

- Используйте `.well-known/openid-configuration` как источник endpoints
- Закрепляйте доверие к ожидаемому `issuer` и используйте только `jwks_uri` этого issuer
- Authorization Code + PKCE
- Храните browser session cookie, а не bearer tokens в browser storage
- В callback строго валидируйте `state` и `nonce` до создания локальной сессии

### Step 7. Постройте middleware resource server

- Централизуйте JWT/introspection validation
- Применяйте проверки `iss/aud/exp/nbf` и scope/role
- Сохраняйте deny-by-default authorization

### Step 8. Реализуйте logout/revocation/invalidation

- RP-initiated logout
- Путь revocation refresh token
- Incident runbook для массового `Not Before`

### Step 9. Monitoring и detection

- Метрики: ошибки token endpoint, refresh failures, invalid signature, invalid audience
- Алерты: аномалии в refresh/token-exchange/DPoP failures
- SIEM-корреляция между событиями auth и API denial

---

## 12. Threat-driven проверки (обязательны в ревью)

- Перехват authorization code -> PKCE + exact redirect URI
- Кража bearer token -> короткий TTL + DPoP/mTLS
- Повторное использование refresh token -> rotation + reuse detection
- Open redirect -> строгий allowlist
- Mix-up attacks -> валидация `iss` + строгая конфигурация client/issuer
- Повышение привилегий -> строгое разделение audience/scope/role
- Session fixation -> регенерация session ID после login
- Утечка токенов в логах -> redaction и явная policy no-token logging

---

## 13. Anti-patterns

- Использование `id_token` как API bearer
- PKCE `plain` вместо `S256`
- Wildcard redirect URI
- Хранение refresh token в browser storage
- Длинный TTL access token (часы/дни)
- Один client для user login и machine-to-machine трафика без сегрегации
- Отсутствие rotation ключей и процедуры реагирования на компрометацию ключей

---

## 14. Управление исключениями (обязательно)

Любое исключение из этого профиля (TTL, rotation, лимиты сессий, scope introspection, строгость redirect, хранение токенов) должно включать:
- Конкретный owner (команда + ответственное лицо)
- Tracking ticket
- Явное обоснование
- Компенсирующие контроли
- Дату истечения (по умолчанию максимум `30d`, жесткий максимум `90d`)
- Критерии закрытия (что должно быть изменено, чтобы убрать исключение)

Правило release gate:
- Истекшие исключения блокируют релиз до продления с одобрением члена команды безопасности или закрытия.