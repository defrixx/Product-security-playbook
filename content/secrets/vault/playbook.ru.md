# Руководство по безопасности Vault

## 1. Область и цель

Этот документ предназначен для платформенных инженеров, инженеров безопасности и владельцев сервисов, которые запускают Vault в средах на базе Kubernetes.

## 2. Безопасность самого Vault

### 2.1 Харденинг кластера и сети

- Запускайте Vault в HA-режиме.
- Ограничивайте входящий доступ к Vault listeners с помощью Kubernetes NetworkPolicy и правил периметрового межсетевого экрана.
- Ограничивайте исходящий доступ из Vault pods только необходимыми бэкендами (KMS/HSM, storage, auth dependencies).
- Принудительно используйте TLS для клиентского и внутрикластерного трафика.
- Поддерживайте актуальную версию Vault и соблюдайте регулярное окно установки обновлений.

### 2.1.1 Харденинг Vault server/runtime для Kubernetes

Рассматривайте Vault как tier-0 сервис. Kubernetes упрощает эксплуатацию, но не отменяет hardening процесса Vault, pod и nodes.

Базовый уровень pod и процесса:
- запускайте Vault от выделенного непривилегированного пользователя (`runAsNonRoot: true`, фиксированные non-zero `runAsUser`/`runAsGroup`);
- задавайте `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `seccompProfile.type: RuntimeDefault` и удаляйте ненужные Linux capabilities;
- не запускайте Vault с shell/debug sidecar, package manager или general-purpose troubleshooting container в production;
- ограничивайте writable paths минимально необходимыми runtime, data и audit-log locations; service account Vault не должен иметь возможность перезаписывать binary или configuration Vault;
- запрещайте `exec` и ephemeral containers для Vault pods, кроме утвержденных break-glass roles с audit logging и коротким expiry;
- по возможности держите Vault pods на dedicated или строго изолированных nodes; если full single tenancy невозможна, документируйте co-tenancy risk и изолируйте через node pools, taints/tolerations, runtime policy, NetworkPolicy и restricted admin access.

Базовый уровень node и OS:
- отключайте swap на nodes, где работает Vault, или используйте эквивалентный node profile, который не позволяет чувствительной памяти Vault попадать на disk;
- отключайте core dumps для процесса/node profile Vault; на Linux это обычно `RLIMIT_CORE=0` или эквивалентный systemd/container-runtime control;
- ограничивайте host access: без broad `hostPath`, runtime socket mounts, host namespaces и privileged mode;
- ограничивайте node-level SSH/debug access и используйте central logging вместо ad hoc shell access.

Required evidence:
- deployed StatefulSet/Pod security context и результат admission policy;
- node pool или scheduling policy, показывающие assumptions по изоляции Vault;
- evidence, что swap и core dumps отключены, или явное exception с compensating controls;
- proof, что normal operator roles не могут менять Vault pods через `exec`/ephemeral debug.

### 2.2 Seal/unseal и хранение ключей

- Предпочитайте auto-unseal через cloud KMS или HSM.
- Если используется Shamir unseal, определите M-of-N quorum, назначьте key custodians и опишите шаги восстановления.
- Храните unseal material вне повседневного доступа операторов.
- Тестируйте recovery и unseal-процедуры не реже одного раза в квартал.

### 2.3 Административная модель

- Root token только для аварийных (break-glass) сценариев.
- Повседневные административные задачи выполняются персонафицированными УЗ через OIDC/SSO с MFA.
- Разделяйте привилегии между platform admin, security admin и emergency admin.
- Изменения policy и auth-mount требуют ревью и audit traceability.

### 2.4 Методы аутентификации и границы доверия

- Kubernetes auth для in-cluster workload'ов.
- OIDC для людей.
- JWT/OIDC для CI pipelines.
- AppRole только там, где недоступна более сильная аттестация идентичности.

Минимумы для Kubernetes auth:

- Привязывайте роли к точным `serviceAccount` и namespace.
- Задавайте и валидируйте `audience` для Kubernetes auth roles. `bound_audiences` — параметр JWT/OIDC auth role; не используйте его в примерах Kubernetes auth role.
- Используйте явные параметры Vault token вместо общего "short-lived":
  - `token_ttl`: `15m` по умолчанию для workload login tokens
  - `token_max_ttl`: `<=1h` для non-renewable workload tokens
  - `token_period`: только для periodic long-running workload tokens, с явным владельцем роли, renewal monitoring и путем incident revocation
  - `token_explicit_max_ttl`: задавайте, когда роли нужен жесткий cap, который renewal не может превысить
  - Human/admin token TTL относится к policy OIDC/SSO auth method: `<=1h`, без бессрочных admin tokens
- Избегайте wildcard role bindings.

Пример Kubernetes auth role:

```bash
vault write auth/kubernetes/role/payments-api-prod \
  bound_service_account_names=payments-api \
  bound_service_account_namespaces=prod-payments \
  audience=vault \
  token_policies=payments-api-prod \
  token_ttl=15m \
  token_max_ttl=1h
```

### 2.5 Аудит и детектирование

- Включайте Vault audit devices до onboarding production workload'ов.
- Пишите audit logs в долговечные и управляемые по доступу sinks.
- Где операционно возможно, включайте минимум два audit devices. Если используется только один audit sink, явно фиксируйте availability risk: Vault может отказывать в обслуживании requests, когда все включенные audit devices не могут записывать события.
- Мониторьте audit device health, write failures, disk/backpressure signals и sink reachability.
- Настраивайте алерты на необычные auth failures, изменения policy и резкие всплески объема чтения.
- Коррелируйте Vault audit events с Kubernetes audit logs и runtime telemetry.
- Ограничивайте доступ к audit logs. Vault хэширует sensitive values в audit entries, но audit logs все равно содержат high-value metadata и могут включать non-hashed request headers, если это явно не настроено.

### 2.6 Операционная устойчивость

- Храните зашифрованные backup'ы и проверяйте restore процедуры.
- Проводите failover и disaster recovery учения с явными целями RTO/RPO.
- Тестируйте емкость на всплески аутентификации (перезапуски node, массовые rollouts pod'ов).

## 3. Безопасность секретов

### 3.1 Модель данных и владение

- Назначьте владельца для каждого пути секрета.
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
- Recommended (внутренняя некритичная автоматизация):
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
- Используйте accessors в incident-процессах, чтобы не раскрывать полные значения токенов.

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
- Используйте, когда команды уже зависят от CSI volume-процессов.
- Избегайте синхронизации в Kubernetes Secret, если нет жесткого требования совместимости.

Pattern C: External Secrets Operator
- Используйте, когда ограничения приложения или платформы требуют объекты Kubernetes Secret.
- Считайте это более высоким уровнем экспозиции, чем доставка только файлами.
- Требуйте шифрование etcd at rest и строгий RBAC.

### 4.2 Минимальный пример Injector

Vault Agent Injector мутирует Pod и по умолчанию сам монтирует shared memory volume в `/vault/secrets`. Не добавляйте ручной `emptyDir` или `volumeMount` приложения для этого пути, если нет проверенной custom-конфигурации injector'а; иначе пример может конфликтовать с мутацией или скрывать реальную модель работы injector'а.

В этом примере отключен стандартный mount Kubernetes ServiceAccount token с API-audience и используется отдельный projected ServiceAccount token с `audience: vault`. Vault Agent Kubernetes auth настроен читать login JWT только из этого projected token. Делайте его короткоживущим и согласуйте с `audience` в Kubernetes auth role Vault.

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
        vault.hashicorp.com/agent-service-account-token-volume-name: "vault-token"
        vault.hashicorp.com/auth-config-token-path: "/var/run/secrets/vaultprojected/token"
        vault.hashicorp.com/agent-inject-containers: "app"
        vault.hashicorp.com/agent-inject-secret-app-config: "kv/data/prod/payments/api"
        vault.hashicorp.com/secret-volume-path-app-config: "/vault/secrets"
        vault.hashicorp.com/agent-inject-file-app-config: "app-config.env"
        vault.hashicorp.com/agent-inject-perms-app-config: "0400"
        vault.hashicorp.com/error-on-missing-key-app-config: "true"
        vault.hashicorp.com/agent-inject-template-app-config: |
          {{- with secret "kv/data/prod/payments/api" -}}
          DB_USER={{ .Data.data.username }}
          DB_PASS={{ .Data.data.password }}
          {{- end -}}
        # Если Vault доступен через нестандартный service или private CA, также задайте:
        # vault.hashicorp.com/service: "https://vault.vault.svc:8200"
        # vault.hashicorp.com/tls-secret: "vault-ca"
        # vault.hashicorp.com/tls-server-name: "vault.vault.svc"
    spec:
      serviceAccountName: payments-api
      automountServiceAccountToken: false
      volumes:
        - name: vault-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  audience: vault
                  expirationSeconds: 600
      containers:
        - name: app
          image: ghcr.io/example/payments-api:1.0.0
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          volumeMounts:
            - name: vault-token
              mountPath: /var/run/secrets/vaultprojected
              readOnly: true
```

### 4.3 Контракт приложения

Каждый сервис должен определить и протестировать:
- Откуда читаются файлы секретов.
- Как применяется rotation (live reload, SIGHUP или контролируемый restart).
- Как старт безопасно завершается при недоступности получения секретов.
- Как логи и метрики не допускают утечку значений секретов.

Поведение во время сбоя Vault для уже запущенных pod'ов должно быть явным:
- Определите для каждого класса секретов, закрывается ли сервис в fail closed или использует ограниченно устаревшие credentials.
- Если устаревшие credentials разрешены, максимальное stale window должно быть задокументировано:
  - Critical: `0m` (fail closed)
  - High: `<=15m`
  - Recommended: `<=60m`
- После истечения stale window pod должен проваливать readiness и перезапускаться только после восстановления получения секретов.
- Операции rotation должны автоматически останавливаться, если состояние Vault деградирует, чтобы избежать split-brain credentials.

### 4.4 Граница CI/CD

- CI может развертывать и конфигурировать, но runtime чтение секретов должно принадлежать workload identity.
- Не встраивайте значения секретов в images, Helm values files или сгенерированные manifests.
- Не передавайте секреты через pipeline logs или artifact storage.

### 4.5 Плейбук ротации для сервисных команд

1. Запишите новую версию секрета в Vault.
2. Запустите rollout или reload.
3. Проверьте состояние сервиса и downstream connectivity с новым значением.
4. Отзовите или удалите старый credential после закрытия overlap window.
5. Проверьте, что после окна revoke SLA не осталось активных leases для старого credential.

### 4.6 Частые ошибки в приложениях

- Чтение секретов только один раз при старте, когда TTL короче жизненного цикла pod.
- Использование переменных окружения для высокоценных long-lived секретов.
- Использование одной Vault role для несвязанных сервисов.
- Пропуск тестирования failure path для сбоев Vault.

## 5. Действия при инцидентах

### 5.1 Подозрение на кражу workload token

1. Отзовите token/accessor и активные leases.
2. Ужесточите или отключите затронутую роль.
3. Ротируйте связанные секреты.
4. Выполните redeploy workload с пересмотренной policy.

### 5.2 Подозрение на эксфильтрацию секретов

1. Идентифицируйте затронутые пути и владельцев.
2. Выполните rotation по классам секретов.
3. Усильте мониторинг replay и lateral movement.
4. Постройте таймлайн по Vault и Kubernetes audit trails.

### 5.3 Компрометация CI identity

1. Отключите CI auth role/mount.
2. Отзовите выданные CI токены и leases по prefix.
3. Ротируйте все секреты, доступные в этой области CI.
4. Включите обратно с суженной policy и более сильными ограничениями identity.

## 6. Чеклист production sign-off

- Модель администрирования Vault исключает root token из рутинной работы.
- Роли жестко привязаны к workload identity (`serviceAccount`, namespace, audience).
- Области policy явно определены по окружению и сервису.
- Для классов секретов задокументированы владение, TTL и cadence rotation.
- Отзыв сертификатов протестирован end-to-end (issuer -> relying service).
- Поведение reload секретов в приложениях протестировано в staging.
- Audit logging и alerting активны и регулярно проверяются.
- Backup restore и DR актуальны.
