# Vault Security Playbook

## 1. Scope and Goal

This document is for platform engineers, security engineers, and service owners who run Vault in Kubernetes-based environments.

## 2. Security of Vault Itself

### 2.1 Cluster and network hardening

- Run Vault in HA mode.
- Restrict inbound access to Vault listeners with Kubernetes NetworkPolicy and perimeter firewall rules.
- Limit outbound access from Vault pods to required backends only (KMS/HSM, storage, auth dependencies).
- Enforce TLS for client traffic and intra-cluster traffic.
- Keep Vault version current and follow a regular patch window.

### 2.2 Seal/unseal and key custody

- Prefer auto-unseal with cloud KMS or HSM.
- If Shamir unseal is used, define M-of-N quorum, named key custodians, and recovery steps.
- Store unseal material outside day-to-day operator access.
- Test recovery and unseal procedures at least quarterly.

### 2.3 Administrative model

- Root token is break-glass only.
- Day-to-day admin tasks use named identities through OIDC/SSO with MFA.
- Split privileges between platform admin, security admin, and emergency admin.
- Policy changes and auth-mount changes require review and audit traceability.

### 2.4 Auth methods and trust boundaries

- Kubernetes auth for in-cluster workloads.
- OIDC for humans.
- JWT/OIDC for CI pipelines.
- AppRole only where stronger identity attestation is not available.

Kubernetes auth minimums:

- Bind roles to exact `serviceAccount` and namespace.
- Set and validate `bound_audiences`.
- Use explicit token TTL/renewal caps:
  - Workload login token TTL: `15m` default, hard max `1h`
  - Login token max TTL: `<=24h`
  - Token renewal period: `5-15m`, only for long-running workloads
  - Human/admin token TTL: `<=1h`, no non-expiring admin tokens
- Avoid wildcard role bindings.

### 2.5 Audit and detection

- Enable Vault audit devices before onboarding production workloads.
- Write audit logs to a durable and access-controlled sink.
- Alert on unusual auth failures, policy changes, and sudden read-volume spikes.
- Correlate Vault audit events with Kubernetes audit logs and runtime telemetry.

### 2.6 Operational resilience

- Keep encrypted backups and verify restore procedures.
- Run failover and disaster recovery exercises with explicit RTO/RPO targets.
- Capacity test authentication bursts (node restarts, mass pod rollouts).

## 3. Security of Secrets

### 3.1 Data model and ownership

- Assign an owner for each secret path.
- Store only secret data; do not use Vault as a general data store.
- Classify secrets by impact (for example: customer data path access, payment access, internal-only).
- Tie each class to TTL and rotation requirements.

Baseline secret classes (minimum):
- Critical (payments, production DB admin, signing material):
  - Dynamic lease TTL: `5-15m`
  - Max TTL: `<=1h`
  - Static secret rotation: every `30d`
  - Revoke SLA during incident: `<=15m`
- High (service-to-service production credentials):
  - Dynamic lease TTL: `15-30m`
  - Max TTL: `<=4h`
  - Static secret rotation: every `60d`
  - Revoke SLA during incident: `<=30m`
- Recommended (internal non-critical automation):
  - Dynamic lease TTL: `30-60m`
  - Max TTL: `<=8h`
  - Static secret rotation: every `90d`
  - Revoke SLA during incident: `<=60m`

### 3.2 Prefer dynamic secrets

Use dynamic engines whenever available (database, cloud, broker credentials).
- Issue short-lived credentials.
- Renew only while workload is healthy.
- Revoke leases immediately for decommissioned workloads or incidents.

Operational commands:

```bash
vault lease lookup <lease_id>
vault lease revoke <lease_id>
vault lease revoke -prefix database/creds/payments-ro
```

### 3.3 Static secret controls

If static secrets are unavoidable:
- Define rotation cadence (for example 30/60/90 days by class).
- Use overlapping rollout (new value live, app switched, old value revoked).
- Rotation overlap window must be explicit:
  - default `30m`
  - maximum `24h` (requires exception approval)
- Keep emergency rotation runbooks for every critical secret class.

### 3.4 Policy boundaries for secret access

- Separate `dev`, `stage`, and `prod` paths.
- Separate services by path and policy.
- Grant only required capabilities on exact paths (capabilities depend on the specific secret engine and path semantics; do not treat `read`, `list`, `update` as a universal default set).

Reject patterns like broad shared policy scopes:

```hcl
path "kv/*" {
  capabilities = ["read", "list"]
}
```

### 3.5 PKI: issuance, rotation, revocation

- Keep root CA offline or heavily restricted.
- Issue service certificates from intermediates.
- Restrict PKI roles by domain, SAN rules, key type, and TTL.
- Rotate certificates before expiry through automation.

Compromise response for certificates:
1. Revoke by serial number.
2. Confirm CRL/OCSP publication and downstream consumption.
3. Re-issue certificate and redeploy affected workload.
4. Investigate usage from audit evidence.

Operational commands:

```bash
vault write pki_int/revoke serial_number="39:dd:2e:..."
vault read pki_int/crl
vault write pki_int/tidy tidy_cert_store=true tidy_revoked_certs=true safety_buffer=72h
```

Important: revocation works only where relying systems actually validate CRL/OCSP.

### 3.6 Token hygiene

- Do not keep long-lived broad tokens.
- Revoke tokens for offboarded users/services immediately.
- Use accessors in incident workflows to avoid exposing full token values.

```bash
vault token lookup <token>
vault token revoke <token>
vault token revoke -accessor <accessor>
```

## 4. Application Secret Handling

### 4.1 Integration patterns

Use one approved pattern per workload and document why it was chosen.

Pattern A (preferred): Vault Agent Injector
- Secrets rendered into files at runtime.
- Works well for apps that support reload/restart on change.
- Avoids storing runtime secret values in Kubernetes Secret objects.

Pattern B: Secrets Store CSI Driver (Vault provider)
- Mounts secrets as files via CSI.
- Use when teams already depend on CSI volume workflows.
- Avoid syncing into Kubernetes Secret unless there is a hard compatibility requirement.

Pattern C: External Secrets Operator
- Use when application or platform constraints require Kubernetes Secret objects.
- Treat this as higher exposure than file-only delivery.
- Require etcd encryption at rest and strict RBAC.

### 4.2 Minimal Injector example

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

### 4.3 Application contract

Each service must define and test:
- Where secret files are read from.
- How rotation is applied (live reload, SIGHUP, or controlled restart).
- How startup fails safely if secret retrieval is unavailable.
- How logs and metrics avoid leaking secret values.

Runtime behavior during Vault outage must be explicit for already-running pods:
- Define per secret class whether the service fails closed or uses bounded stale credentials.
- If stale credentials are allowed, maximum stale window must be documented:
  - Critical: `0m` (fail closed)
  - High: `<=15m`
  - Recommended: `<=60m`
- After stale window expiry, pod must fail readiness and be restarted only after secret retrieval recovers.
- Rotation operations must stop automatically if Vault health is degraded to avoid split-brain credentials.

### 4.4 CI/CD boundary

- CI can deploy and configure, but runtime secret reads belong to workload identity.
- Do not bake secret values into images, Helm values files, or generated manifests.
- Do not pass secrets through pipeline logs or artifact storage.

### 4.5 Rotation playbook for service teams

1. Write new secret version in Vault.
2. Trigger rollout or reload.
3. Validate health and downstream connectivity with new value.
4. Revoke or delete old credential after overlap window closes.
5. Verify no active leases remain for old credential after revocation SLA window.

### 4.6 Common mistakes in applications

- Reading secrets only once at boot when TTL is shorter than pod lifetime.
- Using environment variables for high-value long-lived secrets.
- Sharing one Vault role across unrelated services.
- Skipping failure-path testing for Vault outages.

## 5. Incident Actions

### 5.1 Suspected workload token theft

1. Revoke token/accessor and active leases.
2. Tighten or disable affected role.
3. Rotate related secrets.
4. Redeploy workload with reviewed policy.

### 5.2 Suspected secret exfiltration

1. Identify impacted paths and owners.
2. Rotate by secret class.
3. Increase monitoring for replay and lateral movement.
4. Build timeline from Vault and Kubernetes audit trails.

### 5.3 Compromised CI identity

1. Disable CI auth role/mount.
2. Revoke CI-issued tokens and leases by prefix.
3. Rotate all secrets accessed by that CI scope.
4. Re-enable with narrowed policy and stronger identity constraints.

## 6. Production Sign-off Checklist

- Vault admin model excludes root token from routine work.
- Roles are tightly bound to workload identity (`serviceAccount`, namespace, audience).
- Policy scopes are explicit by environment and service.
- Secret class ownership, TTL, and rotation cadence are documented.
- Certificate revocation is tested end-to-end (issuer to relying service).
- Application secret reload behavior is tested in staging.
- Audit logging and alerting are active and reviewed.
- Backup restore and DR exercises are current.