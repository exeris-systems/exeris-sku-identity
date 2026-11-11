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
- Access tokens are EdDSA (Ed25519) and are verified in process against the published key set. Keys rotate on a schedule. Every token carries `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti` and `sid`, the session it belongs to. `tid`, `roles` and `scope` appear only when the subject has exactly one membership of a role the service may issue: `tid` is that tenant, `roles` holds its role, and `scope` is present for `owner` and `admin` only, carrying `invitations:write`. A subject with no membership, with several, or only in the host's platform role gets a token without the three, and a token without `tid` is tenant-less. Its lifetime is `EXERIS_TOKEN_ISSUER_TOKEN_TTL`, 15 minutes unless set.
- A refresh token is single use. Presenting a used one revokes the session.
- Second factor is RFC 6238 TOTP with recovery codes.
- Issuing an invitation stores it and hands its single-use token to the host's `InvitationDelivery`, in one transaction; the response carries `{invitationId, tenantId, email, role, expiresAt}` and never the token. If the delivery fails nothing is stored, and with no delivery configured issuing answers 503.
- Accepting an invitation creates a verified account, because the token reached only the invitee's mailbox, and grants the membership in the invitation's tenant. The body is `{tenantId, token, email, password}`. The invitation is consumed, the account created and the membership granted in one transaction, and the response is sent after the commit; a failure part-way leaves no account and the invitation pending.
- Error bodies carry a fixed code and never exception text. JSON request bodies are limited to 16 KiB, with unknown and duplicate fields refused.
- CORS is off until `EXERIS_CORS_ALLOWED_ORIGINS` lists origins.

### Sign in and refresh

Bodies are JSON with `Content-Type: application/json`, at most 16 KiB, and carry only the fields named here. Every refusal has the body `{"error": "<code>"}`.

| Route | Request | Success, 200 |
| --- | --- | --- |
| `POST /api/v1/auth/login` | `email` (at most 254 characters), `password` (1 to 1024 characters) | `tokenType`, `accessToken`, `expiresAt` (the access token's end), `refreshToken`, `refreshExpiresAt`, `sessionId` |
| `POST /api/v1/auth/login`, account with a second factor | as above | `mfaRequired: true`, `challengeToken`, `expiresAt`; the session follows from `/mfa/verify` |
| `POST /api/v1/auth/refresh` | `refreshToken` (at most 512 characters) | the same fields as a login, with the successor refresh token |

| Status and `error` | Meaning |
| --- | --- |
| 400 `invalid_request` | no body, not a JSON object, a missing or over-long field, or a field the route does not name |
| 413 `request_too_large` | the body exceeds 16 KiB |
| 415 `unsupported_media_type` | the `Content-Type` is not `application/json` |
| 401 `invalid_credentials` | login: wrong password, unknown address or locked account, not told apart |
| 403 `account_unverified` | login: the password is right and the mailbox is not verified |
| 401 `invalid_refresh_token` | refresh: the token is unknown, used, revoked or expired; a used one also revokes its session |
| 429 | the route's rate-limit group is exhausted for that client |

`expiresAt` and `refreshExpiresAt` are ISO-8601 instants. There is no logout route: `POST /api/v1/auth/sessions/revoke` with `{"sessionId": "<uuid>"}` ends one of the caller's sessions and answers `{"revoked": 1}`, or 404 `not_found`; `/sessions/revoke-all` takes no body and answers `{"revoked": <count>}`. Both need `Authorization: Bearer <accessToken>`, and revoking stops refresh only.

## Limits

- Revoking sessions (password change, reset, revoke-all) stops refresh, but access tokens already issued stay valid until they expire.
- A session records the TCP peer address, which behind the required TLS terminator is the terminator's; trusted-proxy forwarding applies to rate limiting only.
- The membership grant is an external call. A failure after it and before the commit can leave one grant for a subject that has no account; the next acceptance of the same invitation derives the same subject and finds the grant in place, and until then the grant opens nothing. A directory that writes through the joining executor (see Host parts) takes part in the transaction and leaves nothing behind.

## Not covered

Joining a further tenant with an existing account (an invitation to an address that already has one is refused with `account_exists` and stays pending); self sign-up; federated-login routes and providers (the capability is composed but exposes no route); tenant selection and switching; logout as its own route; listing and revoking invitations; disabling a second factor; a durable audit sink (the audit trail is in memory); message catalogues beyond English; and administrative routes.

## Running it

The standalone launcher is `eu.exeris.sku.identity.launcher.IdentitySkuApplication` with three commands: `serve` (the default), `migrate` and `bootstrap-owner`. A first installation runs them in this order: `migrate`, `bootstrap-owner`, `serve`, then a sign-in.

### Without Docker

The build needs JDK 25 (`maven.compiler.release` is 25) and the capabilities installed as described under Build & test. `mvn -B package -DskipTests` writes `target/exeris-sku-identity-0.1.0-SNAPSHOT.jar` and copies the runtime classpath to `target/lib/`. The jar's manifest names the launcher as its main class and `lib/` as its class path, so no `-cp` is needed while `target/lib/` stays beside it:

```bash
java --enable-native-access=ALL-UNNAMED -jar target/exeris-sku-identity-0.1.0-SNAPSHOT.jar migrate
```

Replace `migrate` with `bootstrap-owner` or `serve`; with no argument the launcher serves, and a second argument is a usage error (status 64). `--enable-native-access=ALL-UNNAMED` is the flag the container image passes, because the kernel's off-heap memory needs native access; further JVM options are the operator's (the image reads them from `JAVA_OPTS`). The configuration is checked before the kernel starts, so a variable that is missing ends the process with status 78 and a list of every problem.

- **`migrate`** reads only the `EXERIS_MIGRATE_*` settings below, never boots the kernel and needs no licence manifest.
- **`bootstrap-owner`** boots the kernel's persistence and scheduling, and so needs the licence manifest (`EXERIS_LICENSE_MANIFEST_PATH`).
- **`serve`** boots the kernel and needs the licence manifest.

### Settings

**Configuration** comes from the environment, optionally from a file named by `EXERIS_IDENTITY_CONFIG` that holds the identity settings under the same names (not the database, `EXERIS_ENVIRONMENT` or host-part settings); the environment wins. A file with a name the service does not know is refused. A blank value counts as unset. Every secret takes either its name or its name plus `_FILE`, the path of a readable file, never both; a trailing line break in the file is removed.

Launcher and database settings:

| Name | Required | Meaning |
| --- | --- | --- |
| `EXERIS_ENVIRONMENT` | `serve`, `bootstrap-owner` | one of `development`, `staging`, `production`, `production-load-sim`, `dr-cold`, `dr-hot`; there is no default |
| `EXERIS_DATABASE_URL` | `serve`, `bootstrap-owner` | JDBC URL of the database, starting `jdbc:postgresql:` |
| `EXERIS_DATABASE_USER` | `serve`, `bootstrap-owner` | the service role |
| `EXERIS_DATABASE_PASSWORD` or `_FILE` | `serve`, `bootstrap-owner` | the service role's password |
| `EXERIS_DATABASE_MAX_POOL_SIZE` | no | most pooled connections, 1 to 1000, default 10 |
| `EXERIS_MIGRATE_DATABASE_URL` | `migrate` | JDBC URL of the same database, starting `jdbc:postgresql:` |
| `EXERIS_MIGRATE_DATABASE_USER` | `migrate` | the migration role |
| `EXERIS_MIGRATE_DATABASE_PASSWORD` or `_FILE` | `migrate` | the migration role's password |
| `EXERIS_MIGRATE_SERVICE_ROLE` | no | the service role `migrate` grants access to; lowercase letters, digits and underscores, starting with a letter or underscore, at most 63 characters |
| `EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY`, `EXERIS_IDENTITY_NOTIFICATION_DISPATCHER`, `EXERIS_IDENTITY_INVITATION_DELIVERY` | in `production`, `production-load-sim` and `dr-hot` | the host's classes, see Host parts |
| `EXERIS_IDENTITY_CONFIG` | no | path of the properties file |
| `EXERIS_LICENSE_MANIFEST_PATH` | `serve`, `bootstrap-owner` | the licence manifest, read by the kernel |

Identity settings, for `serve` and `bootstrap-owner`. Durations are ISO-8601, such as `PT15M`:

| Name | Required | Default and bounds, meaning |
| --- | --- | --- |
| `EXERIS_TOKEN_ISSUER_ISSUER` | yes | the `iss` of every token; at most 2048 characters, no whitespace |
| `EXERIS_TOKEN_ISSUER_AUDIENCE` | yes | the `aud` of every token; same limits |
| `EXERIS_TOKEN_ISSUER_KEKS` or `_FILE` | yes | keyring sealing the signing keys |
| `EXERIS_MFA_TOTP_KEKS` or `_FILE` | yes | keyring sealing the TOTP secrets |
| `EXERIS_FEDERATED_LOGIN_STATE_KEYS` or `_FILE` | yes | keyring sealing federated-login flow state |
| `EXERIS_MFA_TOTP_PEPPER` or `_FILE` | yes | pepper of the recovery-code and challenge hashes |
| `EXERIS_TOKEN_ISSUER_TOKEN_TTL` | no | access-token lifetime, `PT15M`; whole seconds, at least one second, at most the maximum below |
| `EXERIS_TOKEN_ISSUER_MAX_TOKEN_TTL` | no | longest lifetime any token may have, `PT1H`; whole seconds |
| `EXERIS_TOKEN_ISSUER_CLOCK_SKEW` | no | verifier clock tolerance the key publication allows for, `PT1M`; zero or more |
| `EXERIS_TOKEN_ISSUER_KEY_TTL` | no | how long a signing key signs before rotation, `P7D`; must exceed the next two together |
| `EXERIS_TOKEN_ISSUER_JWKS_MAX_AGE` | no | how long a verifier may cache the key set, `PT5M`; whole seconds, at least one |
| `EXERIS_TOKEN_ISSUER_ROTATION_CHECK_INTERVAL` | no | how often rotation is checked, `PT1H` |
| `EXERIS_TOKEN_ISSUER_MANUAL_ROTATION` | no | `true` when the host runs the rotation itself and no scheduler does; `false` by default |
| `EXERIS_JWT_ISSUER`, `EXERIS_JWT_AUDIENCE` | no | the issuer and audience the verifier requires; if set they must equal the token issuer's |
| `EXERIS_JWT_CLOCK_SKEW_SECONDS` | no | verifier clock tolerance, 30; 0 to 3600 |
| `EXERIS_MFA_TOTP_CHALLENGE_TTL` | no | lifetime of a second-factor challenge, `PT5M`; not above the next |
| `EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL` | no | longest challenge lifetime, `PT10M` |
| `EXERIS_HTTP_BIND_HOST` | no | address to bind, `127.0.0.1`; the container image sets `0.0.0.0` |
| `EXERIS_HTTP_PORT` | no | 8080; 1 to 65535 |
| `EXERIS_HTTP_MAX_REQUEST_BODY_BYTES` | no | 65536; 1 to 16 MiB |
| `EXERIS_HTTP_MAX_REQUEST_HEADER_COUNT` | no | 100; 1 to 10000 |
| `EXERIS_HTTP_MAX_REQUEST_HEADER_SIZE` | no | 8192 bytes; 1 to 1048576 |
| `EXERIS_CORS_ALLOWED_ORIGINS` | no | comma-separated origins (`https://host[:port]`); empty switches CORS off, `*` is refused |
| `EXERIS_RATELIMIT_<GROUP>_CAPACITY` | no | burst a client may make, 1 to 1000000; default 5, and 30 for `REFRESH` |
| `EXERIS_RATELIMIT_<GROUP>_REFILL_SECONDS` | no | seconds in which a client regains one request, 1 to 86400; default 60 |
| `EXERIS_RATELIMIT_TRUSTED_PROXIES` | no | comma-separated CIDR ranges whose forwarding header is honoured; none by default |
| `EXERIS_RATELIMIT_FORWARDED_HEADER` | no | header carrying the client address, `x-forwarded-for` |
| `EXERIS_RATELIMIT_MAX_KEYS` | no | live buckets per group, 100000; 1 to 100000000 |
| `EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS` | no | failures that lock an account, 5; 1 to 1000 |
| `EXERIS_CREDENTIALS_LOCKOUT_FAILURE_WINDOW_SECONDS` | no | window in which failures count, 900 |
| `EXERIS_CREDENTIALS_LOCKOUT_DURATION_SECONDS` | no | how long an account stays locked, 900 |
| `EXERIS_CREDENTIALS_TOKEN_VERIFICATION_VALIDITY_SECONDS` | no | verification token lifetime, 86400 |
| `EXERIS_CREDENTIALS_TOKEN_RESET_VALIDITY_SECONDS` | no | reset token lifetime, 900 |
| `EXERIS_CREDENTIALS_TOKEN_ISSUE_COOLDOWN_SECONDS` | no | wait between two tokens for one account, 60 |
| `EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH`, `_MAX_LENGTH` | no | accepted password length, 8 and 128; 1 to 4096 |
| `EXERIS_PASSWORD_ARGON2_MEMORY_KIB` | no | Argon2id memory, 65536; 8192 to 4194304 |
| `EXERIS_PASSWORD_ARGON2_ITERATIONS` | no | Argon2id passes, 3; 1 to 100 |
| `EXERIS_PASSWORD_ARGON2_PARALLELISM` | no | Argon2id lanes, 1; 1 to 64 |

The five rate-limit groups are `LOGIN` (login and `/mfa/verify`), `REFRESH`, `PASSWORD_RESET`, `VERIFICATION` and `INVITATION_ACCEPT`. The lockout and credential-token settings are in seconds, up to 3650 days.

### Secrets

Each of the three keyrings is a comma-separated list of `<id>:<key>` entries. An id is 1 to 32 characters of `A-Za-z0-9._-` and unique within the keyring; a key is exactly 32 random bytes in Base64, 44 characters with the padding (a key containing `-` or `_` is read as URL-safe Base64, any other as standard). The first entry is active and seals everything new; the others only open what was sealed under them, so a key rotates by putting a new entry first and is dropped once nothing stored names it. The pepper is standard Base64 (not URL-safe) of at least 32 random bytes.

Generate each value in a terminal and put it straight into the secret store, or into a file for the `_FILE` form; never into the repository or a command line that is logged:

```bash
printf 'k1:%s\n' "$(openssl rand -base64 32)"   # a keyring with one key, id k1
openssl rand -base64 32                          # a pepper
```

### Database roles

Two roles and one database. The migration role owns the database; it creates the tables, indexes and row-level-security policy, grants access to the service role and is never the role the service runs as. Owning the database is enough: it needs neither superuser nor `CREATEROLE`. The service role must already exist when `migrate` runs, because `migrate` grants to it, but `migrate` does not create it.

```sql
CREATE ROLE identity_migrate LOGIN PASSWORD '<migration-password>' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE identity_service LOGIN PASSWORD '<service-password>' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE identity OWNER identity_migrate;
```

With `EXERIS_MIGRATE_SERVICE_ROLE=identity_service`, `migrate` grants the service role `USAGE` on schema `public`, `SELECT`, `INSERT`, `UPDATE` and `DELETE` on every table in `public`, `USAGE` and `SELECT` on every sequence in `public`, and revokes all of its rights on the migration record `identity_applied_migrations`. It does this on every run, including one that applies nothing, and only in schema `public`. Without that setting the operator grants these. `CONNECT` on the database is held by every role unless the operator revoked it from `PUBLIC`, in which case it is granted to the service role by hand.

The service role must be neither a superuser nor `BYPASSRLS`: `serve` and `bootstrap-owner` check this at start and end with status 78 otherwise, because row-level security only isolates tenants from a role that cannot step around it.

### Host parts and the container

- **Host parts:** the kernel is given the same `EXERIS_ENVIRONMENT` as the service. `EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY`, `EXERIS_IDENTITY_NOTIFICATION_DISPATCHER` and `EXERIS_IDENTITY_INVITATION_DELIVERY` name the host's classes. In `production`, `production-load-sim` and `dr-hot` the service refuses to start unless all three are named. In the other environments, a missing directory is replaced by one in which nobody belongs to any tenant (tokens name no tenant and nobody can issue an invitation), a missing dispatcher by one that delivers nothing and logs that a token was not delivered, and with no invitation delivery, issuing an invitation answers 503 and stores nothing. `dr-cold` is not production-class in the kernel's classification, so a cold site promoted without changing `EXERIS_ENVIRONMENT` starts with these stand-ins and only logs warnings; set the environment to `dr-hot` or `production` when promoting.
- **Host parts and the database:** a host part that writes to the service's database from inside a request writes through the executor that joins the service's transactions, so that its write commits and rolls back with the invitation or the account. A part named to the launcher is created through its public no-argument constructor before the kernel boots and receives that executor by implementing `eu.exeris.sku.identity.auth.JoinsServiceTransactions`: the launcher hands it over once, after the composition is built and before any job runs or any request is admitted. A host that embeds the library reads it from `IdentityComposition.transactionalExecutor()`. A write through any other executor is not part of the transaction: on the connection the request already holds it is refused and rolls the whole transaction back, and under another storage context it commits on its own connection and survives a rollback. Because the executor retries a transaction after a serialization failure or a deadlock, `InvitationDelivery.deliver` can run more than once for one request with a different token each time, and only the token of the attempt that commits opens anything; it runs while the transaction holds a connection, so it returns promptly.
- **Row-level security** is switched on for the kernel's persistence in every environment, because the invitations table is isolated by the tenant the kernel publishes for each transaction.
- **Container:** `docker build -t exeris-sku-identity .` after `mvn package`.

### First account

A fresh installation has no account, no self sign-up and no administrative route, so nobody could sign in or hold `invitations:write`. `bootstrap-owner` creates the first account: verified, able to sign in at once, through the credential store's `CredentialProvisioning.provisionFirstVerified`, which creates the account only if the deployment holds none and decides that atomically, so two runs started together create exactly one. It runs once against a migrated database, never starts the HTTP service and exits.

| Key | Required | Meaning |
| --- | --- | --- |
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
| --- | --- |
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
