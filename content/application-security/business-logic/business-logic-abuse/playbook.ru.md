# Плейбук защиты от злоупотреблений бизнес-логикой

## 1. Область и цель

Этот плейбук покрывает злоупотребление легитимной функциональностью продукта: давление на захват учетной записи, злоупотребление signup/trial/promo, манипуляции с inventory и booking, нарушение tenant isolation, обход workflow/state machine и автоматизацию против чувствительных бизнес-потоков.

Используйте документ для:
- продуктовых функций, где атакующему не нужна классическая инъекционная уязвимость;
- API и web flows, которые можно автоматизировать, повторно воспроизвести, объединить в цепочку или использовать для экономического злоупотребления;
- предрелизное ревью для потоков signup, login, reset, checkout, referral, credits, admin/support, export, booking и tenant management.

Вне области:
- низкоуровневые механики API-аутентификации и авторизации: используйте [плейбук API security](../../api/api-security-patterns/playbook.ru.md);
- меры контроля сессий и токенов OAuth/OIDC: используйте [плейбук OIDC + OAuth 2.0](../../identity/oidc-oauth/playbook.ru.md);
- меры контроля только браузерного уровня: используйте [плейбук безопасности браузера и frontend-части](../../web/browser-security/playbook.ru.md);
- проверка валидации, кодирования вывода, реализации аутентификации и сессий, защиты от инъекций, обработки файлов, журналирования и корректности криптографии на уровне кода: используйте [плейбук безопасной разработки и ревью кода](../../secure-coding/code-review/playbook.ru.md).

Цель:
- выявлять чувствительные бизнес-потоки до запуска;
- задавать явные лимиты злоупотребления, state-machine guards, проверки владения и сигналы обнаружения;
- сделать устойчивость к abuse проверяемой для product, engineering, AppSec, fraud и operations-команд.

---

## 2. Модель угроз

Активы:
- доступ к учетным записям, идентичность пользователей, tenant isolation, balances/credits, inventory, coupons, referral rewards, payments, booking slots, exports, admin/support actions и целостность аудита.

Атакующие и точки входа:
- внешние пользователи, автоматизирующие public flows;
- fraud actors, использующие ботов, прокси, disposable email, украденные учетные данные или payment instruments;
- authenticated users, злоупотребляющие object IDs, tenant IDs, role transitions или workflow order;
- partner или B2B clients, превышающие intended machine-to-machine usage;
- внутренние пользователи или support users, злоупотребляющие privileged product operations.

High-impact сценарии:
- Credential stuffing проверяет скомпрометированные учетные данные и приводит к захвату учетной записи.
- Trial/signup automation создает множество accounts для credits, free usage abuse, quota bypass или spam.
- Promo/referral abuse закольцовывает rewards через fake accounts или self-referrals.
- Inventory/booking abuse резервирует scarce goods или slots без намерения купить или прийти.
- Tenant isolation abuse меняет `tenant_id`, organization membership, invite state или support-контекст для доступа к другому tenant.
- Workflow abuse вызывает поздние state transitions напрямую: refund without capture, approve without ревью, export without ownership, downgrade after consuming credits.

---

## 3. Инвентаризация sensitive flows

У каждого sensitive business flow должны быть владелец, abuse objective, лимиты и способ проверки.

| Класс потока | Типовой abuse | Обязательные меры контроля |
|---|---|---|
| Login and reset | credential stuffing, account enumeration, reset flooding | adaptive rate limits, обнаружение скомпрометированных учетных данных при наличии такой возможности, MFA/step-up, enumeration-resistant responses, alerting |
| Signup and trial | fake accounts, quota farming, spam, disposable identity abuse | velocity limits, email/phone/domain policy, device/IP reputation там, где это допустимо по закону, delayed trust, abuse ревью queue |
| Promo/referral/credits | self-referral, reward loops, coupon stacking | one-time redemption, graph checks, reward delay, refund/reversal coupling, ledger audit |
| Checkout/payment | scalping, card testing, duplicate capture, refund abuse | idempotency, state machine, меры контроля платежных рисков, лимиты per-account/device/payment |
| Booking/inventory | denial of inventory, reservation hoarding | hold TTL, payment commitment, release jobs, per-actor quotas, обнаружение аномалий |
| Tenant/admin/support | cross-tenant access, privileged action misuse | object/tenant authorization, JIT/JEA admin access, immutable audit, согласование разрушительных действий |
| Export/reporting | bulk data theft, scraping through valid UI/API | row/object authorization, export quotas, асинхронное согласование массового экспорта, watermarking/журналирование |

Рабочая рекомендация:
- Классифицируйте новые или измененные flows как `normal`, `sensitive` или `critical`.
- `Sensitive` flows требуют явных abuse cases и мониторинга до релиза.
- `Critical` flows требуют negative tests, покрытия runbook и утвержденный владельцем решения по релизу.

---

## 4. Базовый профиль

### 4.1 Захват учетной записи и злоупотребление учетными данными

Рабочие настройки:
- Настраивайте rate limit по account, source network, device/session signal и client/application, где это возможно. Одного IP-only лимита недостаточно.
- Не раскрывайте, существует ли username, email, phone или reset token.
- Используйте MFA или step-up для рискованных login, password reset completion, new device, payment change, admin action и bulk export.
- Уведомляйте пользователей о password change, MFA change, new recovery method и suspicious successful login.
- Журналируйте успешные и неуспешные события аутентификации с correlation IDs и risk-контекстом.

Верификация:
- Credential stuffing simulation с known invalid и reused pairs не создает lockout DoS или account enumeration.
- Reset flow нельзя использовать для flood жертвы или определения существования account.
- Успешная последовательность, похожая на захват учетной записи, создает alertable events.

### 4.2 Signup, trial, promo и referral abuse

Рабочие настройки:
- Free-value flows имеют явные budgets per account, tenant, payment instrument, device/browser signal, source network и time window.
- Promo и referral rewards задерживаются до real qualifying event у referred account.
- Reward ledgers должны быть append-only или auditable; reversal возможен при подтвержденном abuse.
- Disposable email, suspicious domain, proxy/Tor и high-velocity patterns направляются во friction или ревью, а не обязательно в hard block.
- Меры противодействия злоупотреблениям проверяются на privacy и региональные правовые требования до использования device fingerprinting или biometric/human-detection signals.

Верификация:
- Automated account creation не должен умножать credits, coupons или trial capacity сверх настроенного бюджета.
- Self-referral и circular referral graphs обнаруживаются или блокируются.
- Coupon stacking и refund-after-reward scenarios должны завершаться безопасным отказом.

### 4.3 Tenant isolation и object/workflow authorization

Рабочие настройки:
- Authorization enforced для каждого object и state transition в service/domain layer.
- Tenant-контекст выводится из authenticated membership и политики, а не только из user-controlled request fields.
- Cross-tenant admin/support actions требуют явный support-контекст, reason, ticket, JIT/JEA access там, где он применим, и immutable audit.
- Bulk operations и exports перепроверяют authorization per object или используют проверенный tenant-scoped query path.

Верификация:
- Пользователь из tenant A не может читать, менять, экспортировать, приглашать, approve или infer objects из tenant B.
- Support/admin impersonation не может незаметно обходить tenant audit.
- Batch, GraphQL, async job и export paths применяют ту же политику, что и single-object APIs.

### 4.4 Конечные автоматы, идемпотентность и повторное воспроизведение

Рабочие настройки:
- Critical workflows используют явные state machines с allowed transitions.
- State-changing requests используют idempotency keys, где ожидаются retries или duplicate events.
- Webhook, payment, refund, booking и fulfillment flows отклоняют stale, duplicate, out-of-order и already-consumed events.
- Изменения бизнес-состояния и external side effects transactionally coupled или компенсируются через tested recovery process.

Верификация:
- Direct calls к поздним workflow states отклоняются.
- Duplicate payment/webhook/booking messages не создают duplicate external effects.
- Replay после настроенного временного окна отклоняется и создает investigation signal.

### 4.5 Abuse monitoring и response

Рабочие настройки:
- Sensitive flows создают structured events с actor, tenant, object, action, result, reason, correlation ID и релевантными risk signals.
- Дашборды отслеживают flow conversion, rejection, velocity, duplicate attempts, reward issuance/reversal, account creation bursts, login failure clusters и export volume.
- Abuse response имеет playbooks для throttling, temporary friction, account/tenant suspension, reward reversal, token/session revocation и customer support communication.
- High-risk flows имеют emergency control, который может отключить рискованное действие, включить throttling или добавить friction без redeploy application code.

Верификация:
- Tabletop или simulation доказывает, что команда может определить affected accounts/tenants, остановить flow, reverse unsafe credits там, где это возможно, и сохранить подтверждения.

### 4.6 Abuse budgets и governance конфигурации

Рабочие настройки:
- У каждого sensitive flow есть versioned abuse budget: actor keys, counters, time windows, thresholds, friction path, владелец и expiry/ревью cadence.
- Начальные бюджеты задаются явно, даже если итоговые значения зависят от продукта: signup/trial — по учетной записи, tenant, платежному инструменту, сигналу устройства или браузера, исходной сети и окнам `24h`/`7d`; reset и OTP — по учетной записи и адресу доставки; booking/inventory — по субъекту и дефицитному ресурсу; export — по субъекту, tenant, числу объектов, объему данных и временному окну.
- Изменения конфигурации лимитов считаются изменениями политик рабочей среды. Повышение лимитов для потоков с высоким риском требует согласования владельца, обоснования, графика развертывания, пути отката и подтверждения мониторинга.
- Поведение при отказе защитного механизма документируется. Если ограничитель, механизм оценки риска, очередь или ledger недоступны, критичные потоки либо запрещают операцию, либо переходят в ограниченный безопасный режим с явно заданным максимальным временем работы.

Верификация:
- Сравните настроенные лимиты с инвентаризацией потоков и подтвердите, что для каждого sensitive flow определены пороговые значения, утвержденные владельцем.
- Проверьте, что bypass лимитов через alternate identifiers, batch APIs, GraphQL aliases, async jobs, retries и учетные данные partner/B2B client отклоняется или учитывается в том же abuse budget.
- Смоделируйте отказ механизма оценки риска или ограничителя и подтвердите, что поток переходит в документированный режим запрета либо в ограниченный безопасный режим.

---

## 5. Решение по ревью

Матрица ниже определяет доменную критичность замечания и решение о релизе. Общие SLA устранения, жизненный цикл исключений, принятие риска и подтверждения закрытия определяет [плейбук управления уязвимостями](../../../review/vulnerability-management/playbook.ru.md); при пересечении требований применяется более строгое.

| Критичность | Условие | Требуемое действие |
|---|---|---|
| Critical | Злоупотребление позволяет выполнить cross-tenant action, массовый account takeover, payment/ledger manipulation, irreversible admin/support action или bulk export sensitive data | Блокировать релиз до устранения; exception допустим только через формальное принятие риска security leadership и владельца бизнеса |
| High | Обход лимита или state-machine guard в critical flow, promo/referral economic abuse, export scraping, signup/trial quota farming или privileged workflow abuse с bounded impact | Назначить владельца и срок устранения, внедрить mitigation или компенсирующие меры, подтвердить negative tests и monitoring |
| High | High-risk flow не имеет versioned abuse budget, emergency throttle/friction control или проверенного поведения fail-closed/safe mode | Блокировать широкий rollout, пока не определены и не проверены limits, владелец, monitoring и резервное поведение |
| Medium | Для sensitive flow нет владелец, abuse objective, лимитов, monitoring, runbook или negative tests, но эксплуатация не дает немедленного high-impact business action | Завести устранение с владельцем, сроком и release follow-up; не расширять flow до закрытия базовых подтверждений |
| Low | Naming, dashboards, labels или documentation неполны, но лимиты, authorization и state guards работают | Исправить планово и проверить при следующем ревью |

Релиз high-risk product flow считается одобренным только когда есть явная классификация flow, abuse cases, лимиты, владелец, negative tests, monitoring signal и решение по residual risk.

---

## 6. Связь с другими проверками

Используйте этот плейбук вместе с [плейбуком безопасной разработки и ревью кода](../../secure-coding/code-review/playbook.ru.md). Ревью кода проверяет корректность реализации защитных механизмов; проверка злоупотреблений бизнес-логикой — возможность нарушить инварианты продукта легитимными действиями. Для потоков продукта с высоким риском перед релизом нужны обе проверки.

---

## 7. Связанные материалы

- [Плейбук безопасности API](../../api/api-security-patterns/playbook.ru.md)
- [Плейбук моделирования угроз](../../../review/threat-modeling/playbook.ru.md)
- [Плейбук безопасной разработки и ревью кода](../../secure-coding/code-review/playbook.ru.md)
- [Плейбук управления уязвимостями](../../../review/vulnerability-management/playbook.ru.md)
