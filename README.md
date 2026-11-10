# exeris-sku-identity

The Identity and Access Management (IAM) Platform SKU: a composition of Exeris capabilities providing user onboarding, password authentication with Argon2id, TOTP multi-factor authentication, session management with refresh token rotation, federated login, and EdDSA (Ed25519) access token issuance with JWKS publication, running directly on the Exeris kernel HTTP subsystem with no Spring Framework, servlet container or Netty in the data plane.

Status: proof of concept (`poc`), version line 0.1.x, built against `exeris-kernel` 0.13.1, `exeris-sdk` 0.13.3 and `exeris-tooling` 0.11.0 on JDK 25 LTS. Nothing here is stable and no artefact has been published.

## Where it sits

- **Layer:** Tier 3 — Platform SKU (Service Boundary family), in [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md).
- **Composes** 12 capabilities: `exeris-caps-service-boundary-core`, `exeris-caps-rate-limiting`, `exeris-caps-jwt-validation`, `exeris-caps-audit-trail`, `exeris-caps-cors-policy`, `exeris-caps-i18n`, `exeris-caps-credential-store`, `exeris-caps-mfa-totp`, `exeris-caps-token-issuer`, `exeris-caps-session-management`, `exeris-caps-invitations`, and `exeris-caps-federated-login`.
- **Composition manifest:** `composition.json` at the repository root lists the 12 modules and their `@Provides` services (ADR-053). A test regenerates it and fails on drift.
- **Entitlement:** the SKU's entitlement id is `exeris-sku-identity`, its artifactId (ADR-089). Nine of the twelve capabilities are commercial and are entitled by the same licence manifest; `token-issuer`, `cors-policy` and `i18n` are community.
- **Wall (ADR-006):** the data plane is Exeris-native. No `org.springframework.*`, `jakarta.servlet.*`, `io.netty.*` or `reactor.*` type appears.

## What it provides

One strict, frozen route registry on the kernel HTTP subsystem. Every route declares a requirement, and the subject and tenant of an authenticated request come from the verified token, never from the body or the query.

| Route | Access |
| --- | --- |
| `GET /health`, `GET /.well-known/jwks.json` | public |
| `POST /api/v1/auth/login`, `/mfa/verify`, `/refresh` | public, rate limited |
| `POST /api/v1/auth/password/reset-request`, `/password/reset`, `/verification/send` | public, rate limited |
| `POST /api/v1/auth/verification/verify` | public |
| `POST /api/v1/auth/invitations/accept` | public, rate limited |
| `POST /api/v1/auth/password/change`, `/mfa/totp/enrollment`, `/mfa/totp/enrollment/confirm`, `/mfa/recovery-codes`, `/sessions/revoke`, `/sessions/revoke-all`; `GET /api/v1/auth/sessions` | authenticated |
| `POST /api/v1/auth/invitations` | scope `invitations:write`, granted to the roles `owner` and `admin` |

- Passwords are verified with Argon2id and re-hashed at login when the configured parameters change.
- Access tokens are EdDSA (Ed25519), carry `sid`, `tid`, `roles` and `scope`, and are verified in process against the published key set. Keys rotate on a schedule.
- A refresh token is single use. Presenting a used one revokes the session.
- A token names a tenant only when the subject has exactly one membership; otherwise it is tenant-less.
- Second factor is RFC 6238 TOTP with recovery codes.
- Accepting an invitation creates a verified account and grants the membership in the invitation's tenant. The body is `{tenantId, token, email, password}`.
- Error bodies carry a fixed code and never exception text. JSON request bodies are limited to 16 KiB, with unknown and duplicate fields refused.
- CORS is off until `EXERIS_CORS_ALLOWED_ORIGINS` lists origins.

## Not covered

Self sign-up; federated-login routes and providers (the capability is composed but exposes no route); tenant selection and switching; logout as its own route; listing and revoking invitations; disabling a second factor; a durable audit sink (the audit trail is in memory); message catalogues beyond English; and administrative routes.

## Running it

The standalone launcher is `eu.exeris.sku.identity.launcher.IdentitySkuApplication` with two commands: `serve` (the default) and `migrate`.

- **Configuration** comes from the environment, optionally from a file named by `EXERIS_IDENTITY_CONFIG` that uses the same key names; the environment wins. Every problem is reported at once and the process exits with status 78 before the kernel starts. Nothing has a development fallback.
- **Required** secrets and names: `EXERIS_TOKEN_ISSUER_ISSUER`, `EXERIS_TOKEN_ISSUER_AUDIENCE`, a key-encryption keyring for each of the token issuer (`EXERIS_TOKEN_ISSUER_KEKS`), TOTP (`EXERIS_MFA_TOTP_KEKS`) and federated-login state (`EXERIS_FEDERATED_LOGIN_STATE_KEYS`), `EXERIS_MFA_TOTP_PEPPER`, and `EXERIS_DATABASE_URL`, `_USER` and `_PASSWORD`. Each secret also has a `_FILE` form. The remaining keys cover HTTP limits, token and MFA lifetimes, rate-limit groups, trusted proxies, credential policy and Argon2id parameters.
- **Bind address** defaults to loopback; the container image sets `EXERIS_HTTP_BIND_HOST=0.0.0.0`.
- **Database:** the service role must be neither a superuser nor `BYPASSRLS`, and startup refuses one that is. `migrate` applies the ordered migrations with a separate privileged connection (`EXERIS_MIGRATE_DATABASE_URL`, `_USER`, `_PASSWORD`) and, when `EXERIS_MIGRATE_SERVICE_ROLE` names a role, grants it access to every table except the migration record.
- **Membership:** the SKU keeps no membership table. A host supplies a `MembershipDirectory` (`EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY` names its class) and a production-class `EXERIS_ENVIRONMENT`, including an unrecognised value, refuses to start without one. Outside production, accepting an invitation fails at the grant.
- **Notifications:** `EXERIS_IDENTITY_NOTIFICATION_DISPATCHER` names a dispatcher class. Without one, verification and reset tokens are not delivered anywhere and each request logs a warning.
- **Container:** `docker build -t exeris-sku-identity .` after `mvn package`.

Embedding is through `IdentityComposition`: the host passes its strict `ServiceBoundaryCoreModule`, a `TransactionalExecutor`, a `KernelPasswordEncoder`, a `NotificationDispatcher`, a `MembershipDirectory` and a `JobScheduler`, adds its own routes, and calls `start()`, which freezes the registry. Only the launcher names a driver class.

## Build & test

Requires JDK 25 and Maven 3.9+. The capabilities are at `0.1.0-SNAPSHOT` and published nowhere, so each of the 12 `exeris-caps-*` repositories is built from source first, in this order, with two passes each:

```bash
mvn compile -Dexeris.codegen.skip=true
mvn -DskipTests install
```

`service-boundary-core`, `audit-trail`, `cors-policy`, `i18n`, `rate-limiting`, `jwt-validation`, `token-issuer`, `session-management`, `credential-store`, `mfa-totp`, `invitations`, `federated-login`. The kernel, SDK and tooling resolve from Maven Central.

```bash
mvn verify                              # needs Docker for the PostgreSQL integration tests
mvn verify -DexcludedGroups=kernel-boot # without a licence manifest
```

The tests tagged `kernel-boot` boot the real kernel, which refuses to start without a licence manifest entitling `exeris-sku-identity` and its nine commercial capabilities. They read the manifest path from `EXERIS_LICENSE_MANIFEST_PATH` and fail with a message when it is unset. CI writes the manifest from the organisation secret `EXERIS_DEV_LICENSE_MANIFEST`.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [SKU conventions](https://github.com/exeris-systems/exeris-docs/blob/main/standards/sku-conventions.md) — the rules a Platform SKU repository follows.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — Compose Identity as a Tier 3 Platform SKU.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-sku-identity` is a `commercial` SKU under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
