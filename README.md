# exeris-sku-identity

The Identity and Access Management (IAM) Platform SKU: a composition of Exeris capabilities providing user onboarding, password authentication with Argon2id, TOTP multi-factor authentication, session management with refresh token rotation, federated login, and EdDSA (Ed25519) access token issuance with JWKS publication, running directly on the Exeris kernel HTTP subsystem with no Spring Framework, servlet container or Netty in the data plane.

Status: proof of concept (`poc`), version line 0.1.x, built against `exeris-kernel` 0.13.0-SNAPSHOT on JDK 25 LTS. Nothing here is stable and no artefact has been published; code arrives in one import pull request.

## Where it sits

- **Layer:** Tier 3 — Platform SKU (Service Boundary family), in [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md).
- **Composes** 12 capabilities: `exeris-caps-service-boundary-core`, `exeris-caps-rate-limiting`, `exeris-caps-jwt-validation`, `exeris-caps-audit-trail`, `exeris-caps-cors-policy`, `exeris-caps-i18n`, `exeris-caps-credential-store`, `exeris-caps-mfa-totp`, `exeris-caps-token-issuer`, `exeris-caps-session-management`, `exeris-caps-invitations`, and `exeris-caps-federated-login`.
- **Composition manifest:** `composition.json` at the repository root lists the 12 modules and their `@Provides` services (ADR-053).
- **Entitlement:** the SKU's entitlement id is `exeris-sku-identity`, its artifactId (ADR-089).
- **Wall (ADR-006):** the data plane is Exeris-native. No `org.springframework.*`, `jakarta.servlet.*`, `io.netty.*` or `reactor.*` type may appear.

## What the source contains

Code arrives in one import pull request. The incoming implementation provides:

- Identity and Access Management (IAM) workflows exposed through `service-boundary-core` directly on the Exeris kernel HTTP subsystem.
- User onboarding, account verification, credential recovery, and member invitations.
- Password authentication with Argon2id.
- Multi-factor authentication via RFC 6238 TOTP and cryptographic recovery codes.
- Session management with refresh token rotation.
- Access token issuance using EdDSA (Ed25519) and active JWKS publication.
- Federated login linking external OAuth2/OIDC identity providers.
- Substrate driver-swap transparency across Community and Enterprise deployments.

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn test
mvn package -DskipTests
```

The upstreams are not on Maven Central. The 12 `exeris-caps-*` modules above are built from source first, `exeris-sdk` is built from source, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`.

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
- [ADR-070](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-070-service-boundary-substrate-composition.md) — Service Boundary substrate composition.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — Compose Identity as a Tier 3 Platform SKU.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-sku-identity` is a `commercial` SKU under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
