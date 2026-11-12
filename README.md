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
- Access tokens are EdDSA (Ed25519) and are verified in process against the published key set. Keys rotate on a schedule.
- A refresh token is single use. Presenting a used one revokes the session.
- Second factor is RFC 6238 TOTP with recovery codes.
- CORS is off until `EXERIS_CORS_ALLOWED_ORIGINS` lists origins.

Request and response shapes, statuses, token claims and the invitation flow are in the [HTTP API reference](docs/reference/http-api.md).

Embedding is through `IdentityComposition`: the host passes its strict `ServiceBoundaryCoreModule`, a `TransactionalExecutor`, a `KernelPasswordEncoder`, a `NotificationDispatcher`, an `InvitationDelivery`, a `MembershipDirectory` and a `JobScheduler`, adds its own routes, and calls `start()`, which freezes the registry. Only the launcher names a driver class, but the artefact depends on `exeris-kernel-community` at compile scope for the launcher's Argon2id encoder; an embedding host that supplies its own drivers excludes it.

## Limits

- Revoking sessions (password change, reset, revoke-all) stops refresh, but access tokens already issued stay valid until they expire.
- A session records the TCP peer address, which behind the required TLS terminator is the terminator's; trusted-proxy forwarding applies to rate limiting only.
- The membership grant is an external call. A failure after it and before the commit can leave one grant for a subject that has no account; the next acceptance of the same invitation derives the same subject and finds the grant in place, and until then the grant opens nothing. A directory that writes through the joining executor (see [Host parts and the service's transactions](docs/explanation/host-parts.md)) takes part in the transaction and leaves nothing behind.

## Not covered

Joining a further tenant with an existing account (an invitation to an address that already has one is refused with `account_exists` and stays pending); self sign-up; federated-login routes and providers (the capability is composed but exposes no route); tenant selection and switching; logout as its own route; listing and revoking invitations; disabling a second factor; a durable audit sink (the audit trail is in memory); message catalogues beyond English; and administrative routes.

## Run it

The standalone launcher runs `migrate`, `bootstrap-owner` and `serve`. The steps, from the database roles to a first sign-in, are in [Run the service](docs/how-to/run-the-service.md); the settings are in the [configuration reference](docs/reference/configuration.md) and the commands in the [launcher reference](docs/reference/launcher.md).

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

- [Run the service](docs/how-to/run-the-service.md), the [configuration](docs/reference/configuration.md), [launcher](docs/reference/launcher.md) and [HTTP API](docs/reference/http-api.md) references, [Host parts and the service's transactions](docs/explanation/host-parts.md), and [Stopping the launcher and redacting its log](docs/explanation/launcher-stop-and-log-redaction.md).
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
