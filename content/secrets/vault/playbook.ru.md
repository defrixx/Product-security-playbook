# Security Playbook для Vault

## 1. Область и цель

Этот документ предназначен для platform engineers, security engineers и service owners, которые запускают Vault в средах на базе Kubernetes.

## 2. Безопасность самого Vault

### 2.1 Харденинг кластера и сети

- Запускайте Vault в HA mode.
- Ограничивайте входящий доступ к Vault listeners с помощью Kubernetes NetworkPolicy и правил perimeter firewall.
- Ограничивайте исходящий доступ из Vault pods только необходимыми backend'ами (KMS/HSM, storage, auth dependencies).
- Принудительно используйте TLS для клиентского трафика и intra-cluster трафика.
- Поддерживайте актуальную версию Vault и соблюдайте регулярное patch window.

### 2.2 Seal/unseal и хранение ключей

- Предпочитайте auto-unseal через cloud KMS или HSM.
- Если используется Shamir unseal, определите M-of-N quorum, именованных key custodians и шаги восстановления.
- Храните unseal material вне повседневного доступа операторов.
- Тестируйте recovery и unseal процедуры не реже одного раза в квартал.

### 2.3 Административная модель

- Root token только для break-glass сценариев.
- Повседневные административные задачи выполняются персонафицированными УЗ через OIDC/SSO с MFA.
- Разделяйте привилегии между platform admin, security admin и emergency admin.
- Изменения policy и изменения auth-mount требуют ревью и audit traceability.

### 2.4 Auth methods и границы доверия

- Kubernetes auth для in-cluster workload'ов.
- OIDC для людей.
- JWT/OIDC для CI pipelines.
- AppRole только там, где недоступна более сильная аттестация идентичности.

Минимумы для Kubernetes auth:

- Привязывайте роли к точным `serviceAccount` и namespace.
- Задавайте и валидируйте `bound_audiences`.
- Используйте явные лимиты TTL/renewal токенов:
  - Workload login token TTL: `15m` по умолчанию, жесткий максимум `1h`
  - Login token max TTL: `<=24h`
  - Token renewal period: `5-15m`, только для long-running workload'ов
  - Human/admin token TTL: `<=1h`, без бессрочных admin tokens
- Избегайте wildcard role bindings.

### 2.5 Аудит и детектирование

- Включайте Vault audit devices до onboarding production workload'ов.
- Пишите audit logs в долговечный и управляемый по доступу sink.
- Настраивайте алерты на необычные auth failures, изменения policy и резкие всплески объема чтения.
- Коррелируйте Vault audit events с Kubernetes audit logs и runtime telemetry.

### 2.6 Операционная устойчивость

- Храните зашифрованные backup'ы и проверяйте restore процедуры.
- Проводите failover и disaster recovery учения с явными целями RTO/RPO.
- Тестируйте емкость на всплески аутентификации (перезапуски node, массовые rollouts pod'ов).

## 3. Безопасность секретов

### 3.1 Модель данных и ownership

- Назначьте owner для каждого secret path.
- Храните только секретные данные; не используйте Vault как общее хранилище данных.
- Классифицируйте секреты по влиянию (например: доступ к пути с клиентскими данными, доступ к платежам, только внутренний доступ).
- Привяжите каждый класс к требованиям TTL и rotation.

Базовые классы секретов (минимум):
- Critical (payments, production DB admin, signing material):
  - Dynamic lease TTL: `5-15m`
  - Max TTL: `<=1h`
  - Rotation статических секретов: каждые `30d`
  - Revoke SLA во время инцидента: `<=15m`
- High (service-to-service production credentials):
  - Dynamic lease TTL: `15-30m`
  - Max TTL: `<=4h`
  - Rotation статических секретов: каждые `60d`
  - Revoke SLA во время инцидента: `<=30m`
- Standard (внутренняя некритичная автоматизация):
  - Dynamic lease TTL: `30-60m`
  - Max TTL: `<=8h`
  - Rotation статических секретов: каждые `90d`
  - Revoke SLA во время инцидента: `<=60m`

### 3.2 Предпочитайте динамические секреты

Используйте dynamic engines везде, где они доступны (database, cloud, broker credentials).
- Выдавайте short-lived credentials.
- Продлевайте только пока workload находится в healthy состоянии.
- Немедленно отзывайте leases для выведенных из эксплуатации workload'ов или при инцидентах.

Операционные команды:

```bash
vault lease lookup <lease_id>
vault lease revoke <lease_id>
vault lease revoke -prefix database/creds/payments-ro
```

### 3.3 Контроли для статических секретов

Если статические секреты неизбежны:
- Определите cadence rotation (например, 30/60/90 дней по классам).
- Используйте overlapping rollout (новое значение активно, приложение переключено, старое значение отозвано).
- Окно overlap rotation должно быть явным:
  - по умолчанию `30m`
  - максимум `24h` (требует одобрения исключения)
- Держите emergency rotation runbooks для каждого класса критичных секретов.

### 3.4 Границы policy для доступа к секретам

- Разделяйте пути `dev`, `stage` и `prod`.
- Разделяйте сервисы по пути и policy.
- Предоставляйте только необходимые capabilities на точных путях (capabilities зависят от конкретного secret engine и семантики путей; не воспринимайте `read`, `list`, `update` как универсальный default набор).

Отклоняйте паттерны вроде широких общих scopes policy:

```hcl
path "kv/*" {
  capabilities = ["read", "list"]
}
```

### 3.5 PKI: выпуск, ротация, отзыв

- Держите root CA offline или под жесткими ограничениями.
- Выпускайте сервисные сертификаты от intermediate CA.
- Ограничивайте PKI roles по домену, правилам SAN, типу ключа и TTL.
- Ротируйте сертификаты до истечения срока через автоматизацию.

Реакция на компрометацию сертификатов:
1. Отзовите по серийному номеру.
2. Подтвердите публикацию CRL/OCSP и потребление downstream-системами.
3. Перевыпустите сертификат и redeploy затронутого workload.
4. Исследуйте использование на основе audit evidence.

Операционные команды:

```bash
vault write pki_int/revoke serial_number="39:dd:2e:..."
vault read pki_int/crl
vault write pki_int/tidy tidy_cert_store=true tidy_revoked_certs=true safety_buffer=72h
```

Важно: отзыв работает только там, где relying systems реально валидируют CRL/OCSP.

### 3.6 Гигиена токенов

- Не храните long-lived широкие токены.
- Немедленно отзывайте токены для offboarded users/services.
- Используйте accessors в incident workflows, чтобы не раскрывать полные значения токенов.

```bash
vault token lookup <token>
vault token revoke <token>
vault token revoke -accessor <accessor>
```

## 4. Работа приложений с секретами

### 4.1 Паттерны интеграции

Используйте один утвержденный паттерн на workload и документируйте, почему он выбран.

Pattern A (preferred): Vault Agent Injector
- Секреты рендерятся в файлы во время выполнения.
- Хорошо подходит для приложений, поддерживающих reload/restart при изменениях.
- Избегает хранения runtime значений секретов в объектах Kubernetes Secret.

Pattern B: Secrets Store CSI Driver (Vault provider)
- Монтирует секреты как файлы через CSI.
- Используйте, когда команды уже зависят от CSI volume workflows.
- Избегайте синхронизации в Kubernetes Secret, если нет жесткого требования совместимости.

Pattern C: External Secrets Operator
- Используйте, когда ограничения приложения или платформы требуют объекты Kubernetes Secret.
- Считайте это более высоким уровнем экспозиции, чем доставка только файлами.
- Требуйте шифрование etcd at rest и строгий RBAC.

### 4.2 Минимальный пример Injector

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: prod-payments
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "payments-api-prod"
        vault.hashicorp.com/agent-inject-secret-app-config: "kv/data/prod/payments/api"
        vault.hashicorp.com/agent-inject-template-app-config: |
          {{- with secret "kv/data/prod/payments/api" -}}
          DB_USER={{ .Data.data.username }}
          DB_PASS={{ .Data.data.password }}
          {{- end -}}
    spec:
      serviceAccountName: payments-api
      volumes:
        - name: vault-secrets
          emptyDir:
            medium: Memory
      containers:
        - name: app
          image: ghcr.io/example/payments-api:1.0.0
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          volumeMounts:
            - name: vault-secrets
              mountPath: /vault/secrets
              readOnly: true
```

### 4.3 Контракт приложения

Каждый сервис должен определить и протестировать:
- Откуда читаются secret files.
- Как применяется rotation (live reload, SIGHUP или контролируемый restart).
- Как старт безопасно завершается при недоступности получения секретов.
- Как логи и метрики не допускают утечку значений секретов.

Поведение во время сбоя Vault для уже запущенных pod'ов должно быть явным:
- Определите для каждого класса секретов, закрывается ли сервис в fail closed или использует ограниченно устаревшие credentials.
- Если устаревшие credentials разрешены, максимальное stale window должно быть задокументировано:
  - Critical: `0m` (fail closed)
  - High: `<=15m`
  - Standard: `<=60m`
- После истечения stale window pod должен проваливать readiness и перезапускаться только после восстановления получения секретов.
- Операции rotation должны автоматически останавливаться, если здоровье Vault деградирует, чтобы избежать split-brain credentials.

### 4.4 Граница CI/CD

- CI может развертывать и конфигурировать, но runtime чтение секретов должно принадлежать workload identity.
- Не встраивайте значения секретов в images, Helm values files или сгенерированные manifests.
- Не передавайте секреты через pipeline logs или artifact storage.

### 4.5 Playbook rotation для service teams

1. Запишите новую версию секрета в Vault.
2. Триггерните rollout или reload.
3. Проверьте health и downstream connectivity с новым значением.
4. Отзовите или удалите старый credential после закрытия overlap window.
5. Проверьте, что после окна revoke SLA не осталось активных leases для старого credential.

### 4.6 Частые ошибки в приложениях

- Чтение секретов только один раз при старте, когда TTL короче жизненного цикла pod.
- Использование переменных окружения для высокоценных long-lived секретов.
- Использование одной Vault role для несвязанных сервисов.
- Пропуск тестирования failure-path для сбоев Vault.

## 5. Действия при инцидентах

### 5.1 Подозрение на кражу workload token

1. Отзовите token/accessor и активные leases.
2. Ужесточите или отключите затронутую роль.
3. Ротируйте связанные секреты.
4. Выполните redeploy workload с пересмотренной policy.

### 5.2 Подозрение на эксфильтрацию секретов

1. Идентифицируйте затронутые paths и owners.
2. Выполните rotation по классам секретов.
3. Усильте мониторинг replay и lateral movement.
4. Постройте таймлайн по Vault и Kubernetes audit trails.

### 5.3 Компрометация CI identity

1. Отключите CI auth role/mount.
2. Отзовите выданные CI токены и leases по prefix.
3. Ротируйте все секреты, доступные в этом CI scope.
4. Включите обратно с суженной policy и более сильными ограничениями identity.

## 6. Чеклист production sign-off

- Модель администрирования Vault исключает root token из рутинной работы.
- Роли жестко привязаны к workload identity (`serviceAccount`, namespace, audience).
- Scopes policy явно определены по окружению и сервису.
- Для классов секретов задокументированы ownership, TTL и cadence rotation.
- Отзыв сертификатов протестирован end-to-end (issuer -> relying service).
- Поведение reload секретов в приложениях протестировано в staging.
- Audit logging и alerting активны и регулярно проверяются.
- Backup restore и DR актуальны.

---

## 7. Управление исключениями (обязательно)

Любое исключение из контролей TTL/renewal/revocation/rotation должно включать:
- Owner (команда + ответственное лицо)
- Tracking ticket
- Обоснование
- Компенсирующие контроли
- Дата истечения (по умолчанию максимум `30d`, жесткий максимум `90d`)
- Критерии закрытия
Истекшие исключения блокируют production rollout до продления с одобрением security или до удаления.