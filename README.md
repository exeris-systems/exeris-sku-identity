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
- Issuing an invitation stores it and hands its single-use token to the host's `InvitationDelivery`, in one transaction; the response carries `{invitationId, tenantId, email, role, expiresAt}` and never the token. If the delivery fails nothing is stored, and with no delivery configured issuing answers 503.
- Accepting an invitation creates a verified account, because the token reached only the invitee's mailbox, and grants the membership in the invitation's tenant. The body is `{tenantId, token, email, password}`. The invitation is consumed, the account created and the membership granted in one transaction, and the response is sent after the commit; a failure part-way leaves no account and the invitation pending.
- Error bodies carry a fixed code and never exception text. JSON request bodies are limited to 16 KiB, with unknown and duplicate fields refused.
- CORS is off until `EXERIS_CORS_ALLOWED_ORIGINS` lists origins.

## Limits

- Revoking sessions (password change, reset, revoke-all) stops refresh, but access tokens already issued stay valid until they expire.
- A session records the TCP peer address, which behind the required TLS terminator is the terminator's; trusted-proxy forwarding applies to rate limiting only.
- The membership grant is an external call. A failure after it and before the commit can leave one grant for a subject that has no account; the next acceptance of the same invitation derives the same subject and finds the grant in place, and until then the grant opens nothing. A directory that writes through the joining executor (see Host parts) takes part in the transaction and leaves nothing behind.

## Not covered

Joining a further tenant with an existing account (an invitation to an address that already has one is refused with `account_exists` and stays pending); self sign-up; federated-login routes and providers (the capability is composed but exposes no route); tenant selection and switching; logout as its own route; listing and revoking invitations; disabling a second factor; a durable audit sink (the audit trail is in memory); message catalogues beyond English; and administrative routes.

## Running it

The standalone launcher is `eu.exeris.sku.identity.launcher.IdentitySkuApplication` with three commands: `serve` (the default), `migrate` and `bootstrap-owner`.

- **Configuration** comes from the environment, optionally from a file named by `EXERIS_IDENTITY_CONFIG` that uses the same key names; the environment wins. Every problem is reported at once and the process exits with status 78 before the kernel starts. The environment must be declared.
- **Required** secrets and names: `EXERIS_TOKEN_ISSUER_ISSUER`, `EXERIS_TOKEN_ISSUER_AUDIENCE`, a key-encryption keyring for each of the token issuer (`EXERIS_TOKEN_ISSUER_KEKS`), TOTP (`EXERIS_MFA_TOTP_KEKS`) and federated-login state (`EXERIS_FEDERATED_LOGIN_STATE_KEYS`), `EXERIS_MFA_TOTP_PEPPER`, and `EXERIS_DATABASE_URL`, `_USER` and `_PASSWORD`. Each secret also has a `_FILE` form. The remaining keys cover HTTP limits, token and MFA lifetimes, rate-limit groups, trusted proxies, credential policy and Argon2id parameters.
- **Bind address** defaults to loopback; the container image sets `EXERIS_HTTP_BIND_HOST=0.0.0.0`.
- **Database:** the service role must be neither a superuser nor `BYPASSRLS`, and startup refuses one that is. `migrate` applies the ordered migrations with a separate privileged connection (`EXERIS_MIGRATE_DATABASE_URL`, `_USER`, `_PASSWORD`) and, when `EXERIS_MIGRATE_SERVICE_ROLE` names a role, grants it access to every table except the migration record.
- **Host parts:** `EXERIS_ENVIRONMENT` must name one of `development`, `staging`, `production`, `production-load-sim`, `dr-cold`, `dr-hot`; the service does not start without it, and the kernel is given the same value. `EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY`, `EXERIS_IDENTITY_NOTIFICATION_DISPATCHER` and `EXERIS_IDENTITY_INVITATION_DELIVERY` name the host's classes. In `production`, `production-load-sim` and `dr-hot` the service refuses to start unless all three are named. In the other environments, a missing directory is replaced by one in which nobody belongs to any tenant (tokens name no tenant and nobody can issue an invitation), a missing dispatcher by one that delivers nothing and logs that a token was not delivered, and with no invitation delivery, issuing an invitation answers 503 and stores nothing. `dr-cold` is not production-class in the kernel's classification, so a cold site promoted without changing `EXERIS_ENVIRONMENT` starts with these stand-ins and only logs warnings; set the environment to `dr-hot` or `production` when promoting.
- **Host parts and the database:** a host part that writes to the service's database from inside a request writes through the executor that joins the service's transactions, so that its write commits and rolls back with the invitation or the account. A part named to the launcher is created through its public no-argument constructor before the kernel boots and receives that executor by implementing `eu.exeris.sku.identity.auth.JoinsServiceTransactions`: the launcher hands it over once, after the composition is built and before any job runs or any request is admitted. A host that embeds the library reads it from `IdentityComposition.transactionalExecutor()`. A write through any other executor is not part of the transaction: on the connection the request already holds it is refused and rolls the whole transaction back, and under another storage context it commits on its own connection and survives a rollback. Because the executor retries a transaction after a serialization failure or a deadlock, `InvitationDelivery.deliver` can run more than once for one request with a different token each time, and only the token of the attempt that commits opens anything; it runs while the transaction holds a connection, so it returns promptly.
- **Row-level security** is switched on for the kernel's persistence in every environment, because the invitations table is isolated by the tenant the kernel publishes for each transaction.
- **Container:** `docker build -t exeris-sku-identity .` after `mvn package`.

### First account

A fresh installation has no account, no self sign-up and no administrative route, so nobody could sign in or hold `invitations:write`. `bootstrap-owner` creates the first account: verified, able to sign in at once, through the credential store's `CredentialProvisioning.provisionFirstVerified`, which creates the account only if the deployment holds none and decides that atomically, so two runs started together create exactly one. It runs once against a migrated database, never starts the HTTP service and exits.

| Key | Required | Meaning |
|---|---|---|
| `EXERIS_IDENTITY_BOOTSTRAP_OWNER_EMAIL` | yes | the account's address |
| `EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD_FILE` | yes | path of a file holding the password |
| `EXERIS_IDENTITY_BOOTSTRAP_OWNER_TENANT` | when a membership directory is configured; refused otherwise | UUID of the tenant the account owns |
| `EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD` | never | refused if set: a password is not read from the environment or from an argument |

It needs everything `serve` needs (the identity configuration, `EXERIS_ENVIRONMENT`, `EXERIS_DATABASE_*` and the host parts) and the same service role, which must be neither a superuser nor `BYPASSRLS`. Any argument after the command is a usage error.

- **The password file** is read as strict UTF-8, trailing line breaks are removed and the rest is the password, inner whitespace included. Its length must lie in the credential policy's window. On a filesystem that reports POSIX permissions only the owner may have access (mode `0400` or `0600`); mounted secrets need `defaultMode: 0400` or the equivalent. Where permissions cannot be checked a warning says so. The content is held in a character array that is zeroed after use.
- **Refusals** change nothing. Before the kernel boots: incomplete or unusable configuration (all problems are listed together), a password outside the policy, a service role that is a superuser or `BYPASSRLS`. These need no licence. After it boots, from inside the transaction: an account already exists (status 73), the schema is not migrated for the service role (65: the credential store's table is missing or the role may not use it) and a credential table under row-level security (78). The host reads no table of the credential store itself, and the service role cannot read the migration record, so these three refusals need the kernel to have booted and therefore a licence.
- **The kernel boots persistence and scheduling only**, no listener, so the licence manifest (`EXERIS_LICENSE_MANIFEST_PATH`) is required as for `serve`; without one a production-class environment ends with status 70 and no account, whatever the database holds.
- **Membership.** This service keeps no membership table; tenant membership and roles belong to the host's `MembershipDirectory`. With a directory configured, the account is granted `owner` in the configured tenant inside the same transaction as the account, so a failing grant leaves no account. The tenant must already mean something to the host. With no directory configured (outside production-class environments only), the account is created and belongs to no tenant: its tokens name no tenant and carry no role and no scope, so it cannot issue an invitation and nobody can be invited. The operator then records the owner role for that subject (its id is logged) in the host's membership store, and the owner signs in again to obtain a token that names the tenant.
- **Nothing secret is logged**: not the password, the file's content, the database password or the address; no token is issued.

| Status | Meaning |
|---|---|
| 0 | the account was created |
| 64 | the command line was not understood |
| 65 | the schema is not migrated for the service role (found after the kernel booted) |
| 69 | the database cannot be reached |
| 70 | the kernel did not boot, the provisioning did not run or the transaction failed; nothing was committed |
| 73 | an account already exists; nothing was changed (found after the kernel booted) |
| 78 | the configuration cannot be used, or the credential table is under row-level security, which the command refuses because the first account is decided for the whole deployment |

The audit event of the creation goes to the in-memory audit sink and is lost when the command exits. Not covered: creating the tenant in the host, a second owner, resetting the bootstrap, password reset and second-factor enrolment for the owner.

Embedding is through `IdentityComposition`: the host passes its strict `ServiceBoundaryCoreModule`, a `TransactionalExecutor`, a `KernelPasswordEncoder`, a `NotificationDispatcher`, an `InvitationDelivery`, a `MembershipDirectory` and a `JobScheduler`, adds its own routes, and calls `start()`, which freezes the registry. Only the launcher names a driver class, but the artefact depends on `exeris-kernel-community` at compile scope for the launcher's Argon2id encoder; an embedding host that supplies its own drivers excludes it.

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

The tests tagged `kernel-boot` boot the real kernel, which refuses to start without a licence manifest entitling `exeris-sku-identity` and its nine commercial capabilities. They read the manifest path from `EXERIS_DEV_LICENSE_MANIFEST_PATH`, hand it to the service they start as `EXERIS_LICENSE_MANIFEST_PATH`, and fail with a message when it is unset. CI writes the manifest from the organisation secret `EXERIS_DEV_LICENSE_MANIFEST`.

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
