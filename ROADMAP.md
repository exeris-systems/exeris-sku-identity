---
title: "exeris-sku-identity — Roadmap"
type: roadmap
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-10-15
---

# exeris-sku-identity — Roadmap

Status: **poc**. Version line: **0.1.x**. Licence: Exeris Commercial License (ADR-023), entitlement id
`exeris-sku-identity`.

Milestones are versions, not dates. Dates appear only on what has shipped; nothing has shipped yet.

> **`1.0.0` is not on this roadmap.** It is a gate, described in the last section. Status moves
> `poc` → `snapshot` → `released`.

---

## Where this sits

Tier 3 Platform SKU of the Service Boundary family (HLA; ADR-024, ADR-053, ADR-099). A runnable application that boots the kernel HTTP subsystem and provides Identity and Access Management (IAM) on top of `service-boundary-core`. It composes 12 capabilities: `exeris-caps-service-boundary-core`, `exeris-caps-rate-limiting`, `exeris-caps-jwt-validation`, `exeris-caps-audit-trail`, `exeris-caps-cors-policy`, `exeris-caps-i18n`, `exeris-caps-credential-store`, `exeris-caps-mfa-totp`, `exeris-caps-token-issuer`, `exeris-caps-session-management`, `exeris-caps-invitations`, and `exeris-caps-federated-login`.

The implementation coordinates core authentication and authorization flows: user registration and onboarding, Argon2id password authentication, RFC 6238 TOTP multi-factor authentication, session management with refresh token rotation, EdDSA (Ed25519) token issuance with active JWKS publication, federated identity provider integration, and tenant member invitations.

**Upstream constraints this repo does not own:**

| Constraint | Effect here | Owner |
| --- | --- | --- |
| Kernel licence gate (ADR-088, ADR-089) in kernel `0.13.0-SNAPSHOT` | Artefacts stay `0.1.0-SNAPSHOT` until kernel `0.13.0` is released | `exeris-kernel` |
| Each cap's own 0.1.0 / 0.2.0 milestones | The SKU consumes `[0.1.0,0.2.0)` ranges of composed capabilities | capability repositories |
| Kernel `HttpExchange` integration | Ingress dispatch on the kernel HTTP engine | `exeris-kernel` |
| Substrate driver-swap transparency | Reference kernel SPIs (`TransactionalExecutor`, `HttpClientEngine`) without concrete drivers | `exeris-kernel` |
| Composition manifest validation | Deterministic SHA-256 `contentBinding` in `composition.json` | `exeris-sdk`, `exeris-tooling` |

---

## 0.1.0 — the code PR

- [ ] Rebase onto the current capabilities APIs (`TransactionalExecutor`-backed capabilities with PostgreSQL, applying each capability's migrations)
- [ ] Ingress admission through `jwt-validation` with issuer and audience loaded from configuration
- [ ] Explicit route requirement declarations across all endpoints: public onboarding/login routes vs authenticated management routes
- [ ] Subject and tenant identifiers resolved strictly from the authenticated principal or validated session state
- [ ] Parent POM aligned to `eu.exeris:exeris-app-parent:0.10.0`, kernel `0.13.0-SNAPSHOT`, SDK `0.12.0`, tooling `0.10.0`
- [ ] All capability dependencies on `[0.1.0,0.2.0)` ranges
- [ ] Password verification using Argon2id with adaptive memory/time parameters
- [ ] Multi-factor authentication via RFC 6238 TOTP with cryptographic recovery codes
- [ ] EdDSA (Ed25519) access token issuance with active JWKS publication and rotation
- [ ] Session management with atomic refresh token rotation and race-tolerant grace windows
- [ ] Member invitations flow supporting tokenized onboarding and tenant assignment
- [ ] Licence enforcement: `IdentitySkuEntitlement` (id `exeris-sku-identity`) validated against the kernel Phase 0 gate
- [ ] `composition.json` manifest validated with deterministic SHA-256 content binding passing `CompositionStampAssertion`
- [ ] Integration tests against PostgreSQL through Testcontainers for every IAM workflow; unit tests with JUnit 5 and AssertJ

**Exit gate:** `mvn verify` green on JDK 25 with the Testcontainers suite; `CompositionStampAssertion` passes; end-to-end IAM flows verify onboarding, Argon2id authentication, TOTP MFA, and Ed25519 token issuance.

## After 0.1.0

The milestones after 0.1.0 are not decided yet. They are added here when they are.

---

## 1.0.0 — a gate, not a milestone

Entry condition: all composed capabilities have reached stable releases, the boot is fully manifest-driven, and end-to-end IAM flows are verified across Community and Enterprise substrates.
