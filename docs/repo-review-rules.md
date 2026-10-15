---
title: "Review rules for exeris-sku-identity"
type: reference
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-10-15
---

# Review rules for `exeris-sku-identity`

The `repo-routine` extension of `exeris-systems/.github`'s `docs-guardrails-review.md`, applied
**after** its parts and under its severity tags, output format and verdict schema. It adds checks
and raises severities; it lowers nothing and skips nothing. One review, one verdict, one publisher.
A finding cites a rule of this file as `repo-review-rules.md#S<n>`.

**The criteria are not authored here.** They are stated by this repository's `AGENTS.md`,
`README.md`, `CONTRIBUTING.md` and `SECURITY.md`, and by the build that enforces them. This file names the
questions a reviewer must reach for and the severity each answer carries; where a rule restates a
sentence of those documents, the document is the one to read and to change.

## What this repository is answerable for

`exeris-sku-identity` is the Identity and Access Management (IAM) Platform SKU (Tier 3, Service Boundary family), licence commercial (Exeris Commercial License 1.1), a proof of concept with no published artefact. It composes the capabilities named in its README and wires them into one runnable identity service boundary. The shared `code` part judges whether a change is correct. What it cannot know is which of this SKU's surfaces and invariants its own documents promise, and that is what follows.

## Step S — rules of this repository

S1. **Kernel-direct execution holds** (ADR-006, ADR-024; `AGENTS.md` §2). A reference to
    `org.springframework.*`, `jakarta.servlet.*`, `io.netty.*` or `reactor.*` in `src/main`, a
    dependency in `pom.xml` that brings one in, or a Spring Boot starter → `[HARD BLOCK]`. The same
    import in `src/test` is outside what the guard scans and is still forbidden → `[CONTRACT]`.

S2. **`composition.json` is the authored manifest and stays consistent** (ADR-053). A diff that changes
    the composed capabilities in `pom.xml` without the manifest, or the manifest without `pom.xml`,
    edits the stamp by hand, or leaves `stamp.validated` other than `true` → `[HARD BLOCK]`. The
    manifest is checked by the composition stamp assertion in the tests, which the reviewer reads only
    through the build checks.

S3. **Driver-swap transparency** (`standards/sku-conventions.md` rule 4). The manifest and the capability
    wiring are the same for the Community and Enterprise substrates. A concrete kernel driver class
    named in wiring that is meant to be substrate-independent, or a manifest entry that differs by
    substrate → `[CONTRACT]`.

S4. **Composed contracts are `0.1.0` while the capabilities are unreleased.** While no artefact of a
    composed capability has been published, the SKU composes it at a `0.1.x` contract version; a
    `1.0.0` or higher contract version written into the manifest or the POM → `[CONTRACT]`.

S5. **The entitlement id is the artifactId.** The SKU's entitlement id is `exeris-sku-identity`
    (ADR-089). Any other id, or one made conditional → `[HARD BLOCK]`. The licence in `LICENSE`, the
    POM and the README moves together, and a change to one alone → `[CONTRACT]`.

S6. **The build baseline and the test contract hold** (`AGENTS.md` §2, `CONTRIBUTING.md`).
    `maven.compiler.release` stays 25 and no `--enable-preview` appears in any scope, including the
    container entrypoint → `[HARD BLOCK]`. Tests use JUnit 5 and AssertJ only, with hand-written doubles
    and no mocking framework (ADR-058) → `[CONTRACT]`.

S7. **Verification names what ran.** A local run may be cited as `target/surefire-reports` at `<sha>`,
    and the reviewer accepts that as the evidence of what ran locally. A Verification that claims a
    pass without a command, report path or sha → `[STYLE]`.

S8. **Admission and route requirements hold** (ADR-099). Every route explicitly declares its admission
    requirements; protected endpoints enforce JWT admission with issuer and audience validated from
    configuration, and unauthenticated bypass of protected routes → `[HARD BLOCK]`.

S9. **Subject and tenant binding**. Subject and tenant identifiers are resolved strictly from the
    authenticated principal or validated session state. An identity or tenant value accepted from an
    unauthenticated request header or unverified body field → `[HARD BLOCK]`.

S10. **Cryptographic primitives and secret hygiene**. Password verification uses Argon2id; token
    issuance uses EdDSA (Ed25519) keys with proper rotation; tokens and secrets are never logged or
    exposed in error responses → `[HARD BLOCK]`.

## Where this does not apply, and what it costs

The shared `code` and `pr` parts judge correctness, scope, the pull request's body and its commits, and the rules above are not a second copy of them. Whether a change to `internal` is correct is the `code` part's; what this file adds is the list of invariants this SKU's own documents state, which a generic review cannot know to look for. Not to the pull request's body and commits, which the shared `pr` part judges, nor to comments and Javadoc, which the shared `code-docs` part and the Javadoc gate judge.

The cost is that these rules are prose a reviewer applies, not a program. This repository hands the review no `repo-checks` output, so the Wall scan, the manifest comparison and the tests named above are evidence only through the build checks on the pull request, which the reviewer cannot read. A rule the reviewer could only check by running the build is reported as unchecked, not as passing.
