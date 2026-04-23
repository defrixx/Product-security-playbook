# Security Lens для 16 архитектурных кейсов (ByteByteGo)

## 1. Область и как читать документ

Этот плейбук разбирает 16 кейсов из подборки ByteByteGo с прикладной точки зрения безопасности:
- какие активы нужно защищать;
- какие типовые угрозы и риски возникают;
- какие технические и процессные меры обычно применяются в production;
- какими сигналами проверять, что меры реально работают.

Ограничение:
- это не утверждение о полной внутренней реализации конкретной компании;
- это security-декомпозиция типового архитектурного паттерна, который отражен в названии кейса.

Модель доказательности:
- `Confirmed`: подтверждается публичным первичным источником компании или официальной документацией;
- `Inferred`: практический контроль, логично вытекающий из threat model и отраслевой практики.

Важно для раздела 3:
- в колонке `Меры, которые точно внедрила компания (Confirmed)` указаны только меры с прямыми ссылками;
- если по кейсу нет достаточной публичной детализации, это явно отражается в формулировке `частично подтверждено`.

---

## 2. Единый security lens для архитектурных кейсов

Для каждого кейса проверяйте минимум 7 доменов:

1. Identity и trust boundaries
- machine identity, user identity, привилегии между сервисами;
- отсутствие неявного доверия внутри сети.

2. Data protection
- классификация данных, шифрование in transit/at rest, секреты, ключи, токены;
- запрет хранения чувствительных данных в логах и телеметрии.

3. Abuse и business-logic attacks
- BOLA/BFLA/BOPLA, brute force, scraping, fraud, бот-автоматизация;
- rate limits, risk scoring, step-up controls.

4. Platform/runtime hardening
- sandboxing, изоляция workload, policy-as-code, least privilege;
- безопасные defaults для контейнеров и окружений выполнения.

5. Software supply chain
- provenance/attestations, подпись артефактов, pinning зависимостей;
- защищенный CI/CD и контроль релизных прав.

6. Detection и response
- события authz/authn, data-access, admin-action, policy-deny;
- playbook реагирования и проверяемый путь от алерта до containment.

7. Verifiability
- для каждого контроля должен быть тест или метрический индикатор;
- решения без observability и negative tests считаются неполными.

---

## 3. Сводная таблица по 16 кейсам

| Кейс | Угрозы и риски | Меры, которые точно внедрила компания (`Confirmed`) | Меры, о которых нет информации, но они напрашиваются (`Inferred`) | Подтверждения безопасности (сигналы) |
|---|---|---|---|---|
| Discord - Как Discord хранит сообщения | Горизонтальный доступ к чужим сообщениям; утечка контента звонков/стримов; hijack участников голосовых сессий | E2EE для аудио/видео звонков и Go Live + механизмы проверки шифрования и участников ([Discord E2EE](https://support.discord.com/hc/en-us/articles/25968222946071/)) | Объектные проверки доступа `tenant->channel->message`; короткоживущие webhook/bot credentials; строгая redaction логов сообщений | BOLA negative tests; алерты на аномальный read/export объем; доля старых bot/webhook токенов |
| Netflix - Как Netflix стримит контент | Кража playback токенов; credential abuse; компрометация TLS/сертификатов | Централизованная оркестрация TLS-сертификатов через Lemur ([Netflix Lemur](https://github.com/Netflix/lemur)); публичная программа ответственного раскрытия уязвимостей ([Netflix RVD](https://help.netflix.com/en/node/6657)) | Device binding для playback; anti-replay nonce; adaptive rate limiting для login/playback | Replay/invalid token rate на edge; MTTD/MTTR по account takeover; SLA ротации сертификатов |
| Airbnb - Как эволюционировала архитектура Airbnb | Небезопасные изменения в распределенной архитектуре; фишинг/аккаунт takeover; уязвимости в продуктах | Публичный security disclosure канал через HackerOne ([Airbnb Security](https://www.airbnb.com/info/security)); публичные меры по защите аккаунта и антифишингу ([Help secure account](https://www.airbnb.com/help/article/501)) | Централизованный policy decision point; mTLS/workload identity между сервисами; ПДн labeling в data contracts | Покрытие сервисов централизованным authz; число просроченных policy exceptions; e2e тесты tenant isolation |
| Cursor - Как Cursor поставляет код | Prompt injection через контекст; exfiltration кода/секретов; небезопасный автозапуск действий | SOC 2 Type II, ежегодные pentest; Privacy Mode и zero-retention для провайдеров в этом режиме; AES-256 at rest и TLS 1.2+ ([Cursor Security](https://cursor.com/en-US/security), [Cursor Data Use](https://cursor.com/en-US/data-use), [Cursor Enterprise](https://cursor.com/en-US/enterprise)) | Retrieval allowlist/denylist секретов; mandatory security gates для AI-generated PR; жесткий least-privilege для tool permissions | Prompt-injection test suite pass rate; blocked secret exfiltration attempts; доля AI PR без security checks |
| Tinder - Как Tinder матчится с пользователями | Fake/bot профили; impersonation/catfishing; abuse business flows | Photo Verification и liveness checks; ID + Photo Verification (по доступности) ([Photo Verification](https://www.help.tinder.com/hc/en-us/articles/360034941812-Photo-Verification), [ID + Photo Verification](https://www.help.tinder.com/hc/en-us/articles/19868368795917-ID-Photo-Verification), [How it works](https://www.help.tinder.com/hc/en-us/articles/4422771431309-How-Does-Photo-Verification-Work)) | Velocity/risk scoring для match/message flows; adaptive challenge; защита чувствительных полей профиля | Fake-account detection precision/recall; время блокировки бота после первого сигнала; abuse-to-ban latency |
| OpenAI - Как работает OpenAI Codex | Опасные команды/изменения кода; утечка данных в агентном потоке; небезопасная автономность | Codex CLI: режимы approvals, sandboxed network-disabled `Full Auto`; для API — no training by default и базовые retention controls ([Codex CLI](https://help.openai.com/en/articles/11096431-openai-codex-ci-getting-started), [OpenAI data controls](https://platform.openai.com/docs/guides/your-data)) | Политики egress для инструментов; high-risk change requires human approval; source provenance checks для retrieval | Доля high-risk действий с human approval; sandbox escape incidents; policy-block rate по tool calls |
| Reddit - Как Reddit отправляет уведомления | Аккаунт takeover; spoofed уведомления/доставки; abuse retry/notification storms | Поддержка 2FA (authenticator app) и backup codes ([Reddit 2FA](https://support.reddithelp.com/hc/en-us/articles/360043470031-What-is-two-factor-authentication-and-how-do-I-set-it-up), [backup codes](https://support.reddithelp.com/hc/en-us/articles/360058446411-What-are-two-factor-authentication-backup-codes-and-how-do-I-get-them-)) | Подпись источников событий уведомлений; идемпотентность + дедупликация; bounded retries с jitter | Duplicate notification ratio; spoofing rejects; retry storm detection MTTR |
| X - Как X ранжирует посты | Gaming ranking через coordinated behavior; API abuse; data poisoning | Публичная документация по rate limits/429 для API ([X API rate limits](https://docs.x.com/x-api/fundamentals/rate-limits)); открытый репозиторий рекомендательной системы ([the-algorithm](https://github.com/twitter/the-algorithm)) | Feature provenance checks; разделение ролей model/feature access; bot-behavior correlation controls | Время до подавления coordinated campaign; количество несанкционированных policy/model изменений; false-positive rate anti-abuse |
| Dropbox - Как Dropbox AI выполняет поиск | Cross-tenant retrieval; утечка чувствительного контента в search/chat; интеграционные риски connected apps | По Dash: ответы строятся по контенту, к которому есть доступ; по платформе: AES-256 at rest + TLS/SSL in transit ([Dash search](https://help.dropbox.com/view-edit/dropbox-dash-search-and-explore), [Dropbox security](https://help.dropbox.com/security/how-security-works)) | ACL enforcement на retrieval path; DLP label-aware indexing; connector sandbox + egress allowlist | Tenant-escape tests; DLP coverage on indexed corpus; connector policy violation count |
| Uber - Как Uber контролирует доступ | Privilege escalation; риск суперпользовательских команд; lateral movement | Централизованная ABAC-модель (`Charter`) ([ABAC at Uber](https://www.uber.com/en-DE/blog/attribute-based-access-control-at-uber/)); внедрение SPIFFE/SPIRE для zero-trust workload identity ([SPIFFE/SPIRE at Uber](https://www.uber.com/en-SE/blog/our-journey-adopting-spiffe-spire/)); Superuser Gateway с peer review и удалением прямого superuser-доступа ([Superuser Gateway](https://www.uber.com/pe/en/blog/superuser-gateway-guardrails/)) | JIT/JEA вместо постоянных прав; короткоживущие сервисные креды; строгая сегментация доменов | Median privileged session lifetime; доля сервисов без static secrets; lateral movement block count |
| Google - Как масштабируется Google Spanner | Компрометация data/control plane; ошибки key lifecycle; избыточные права к БД | Spanner: шифрование at rest по умолчанию + CMEK; IAM на уровнях project/instance/database ([Spanner CMEK](https://docs.cloud.google.com/spanner/docs/cmek), [Spanner IAM overview](https://docs.cloud.google.com/spanner/docs/iam)) | Разделение обязанностей в IAM; обязательный аудит DDL/admin операций; контролируемый lifecycle ключей | Key rotation coverage; audit completeness для DDL/admin; unauthorized data-access attempts |
| Stripe - Как Stripe быстро поставляет изменения | Дубли/повтор операций при ретраях; компрометация payment данных; release risk | Idempotency keys для безопасных повторов POST; PCI Service Provider Level 1 ([Idempotent requests](https://docs.stripe.com/api/idempotent_requests), [Security at Stripe](https://docs.stripe.com/security/stripe)) | Подпись артефактов и provenance check на deploy; жесткие security gates в CI; risk-based rate limiting для payment APIs | Доля неподписанных артефактов в runtime; duplicate-charge incidents; security-related CFR |
| AMEX - Как AMEX обрабатывает платежи | Онлайн fraud/card-not-present атаки; компрометация PAN; takeover при checkout | SafeKey на базе EMV 3-D Secure; токенизация Card-on-File c заменой PAN на token и domain controls ([SafeKey](https://www.americanexpress.com/en-us/security/safekey/), [Tokenization](https://network.americanexpress.com/globalnetwork/tokenization/)) | Token lifecycle monitoring; adaptive fraud scoring по каналам; strict CDE segmentation | Fraud rate и chargeback trends; токен vs PAN transaction ratio; authentication challenge success rate |
| Anthropic - Как Anthropic построила агентов | Небезопасное выполнение команд агентом; prompt injection; exfiltration | Claude Code security model: read-only by default + explicit approvals; permission system/modes; в коммерческих продуктах данные по умолчанию не используются для тренировки ([Claude Code security](https://code.claude.com/docs/en/security), [permissions](https://code.claude.com/docs/en/permissions), [data training policy](https://privacy.anthropic.com/en/articles/7996868-i-want-to-opt-out-of-my-prompts-and-results-being-used-for-training-models)) | Capability sandbox для high-risk tools; deny-by-default action classes; human-in-the-loop для destructive операций | High-impact actions with human approval; sandbox policy violation rate; mean time to revoke capability |
| Shopify - Технологический стек Shopify | Избыточные app permissions; webhook spoofing; API abuse и перегрузка | Access scopes model с принципом minimum needed access; HMAC verification для webhook-подобных вызовов; документированные API limits и 429 поведение ([Access scopes](https://shopify.dev/docs/admin-api/access-scopes), [HMAC verification](https://shopify.dev/docs/apps/build/flow/actions/endpoints), [API limits](https://shopify.dev/docs/api/usage/limits)) | Runtime scope governance; mandatory webhook signature validation everywhere; anti-abuse controls для app ecosystem | Excessive-scope apps count; webhook signature failure ratio; rate-limit breach trends |
| Meta - Как Meta анимирует изображения | Манипулированный/AI-generated media abuse; уязвимости платформы; trust issues у пользователей | Публичная политика labeling для AI-generated/manipulated media; большой bug bounty процесс с регулярной отчетностью ([AI labeling approach](https://about.fb.com/news/2024/04/metas-approach-to-labeling-ai-generated-content-and-manipulated-media/), [Meta Bug Bounty](https://www.facebook.com/whitehat), [2024 recap](https://engineering.fb.com/2025/02/13/security/looking-back-at-our-bug-bounty-program-in-2024/)) | Media provenance checks в pipeline; sandboxed media processing; усиленный abuse detection по deepfake-сценариям | Detected-vs-escaped manipulated media ratio; time-to-label/remove; bounty-to-fix cycle time |
