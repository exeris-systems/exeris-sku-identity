---
title: "Launcher reference"
type: reference
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-11
---

# Launcher reference

The commands of the standalone launcher, their requirements and exit statuses, and the settings of `bootstrap-owner`. The procedure is [Run the service](../how-to/run-the-service.md); the other settings are in the [configuration reference](configuration.md).

## Commands

The standalone launcher is `eu.exeris.sku.identity.launcher.IdentitySkuApplication` with three commands: `serve` (the default), `migrate` and `bootstrap-owner`. A first installation runs them in this order: `migrate`, `bootstrap-owner`, `serve`, then a sign-in.

The jar's manifest names the launcher as its main class and `lib/` as its class path, so no `-cp` is needed while `target/lib/` stays beside it. With no argument the launcher serves, and a second argument is a usage error (status 64). `--enable-native-access=ALL-UNNAMED` is the flag the container image passes, because the kernel's off-heap memory needs native access; further JVM options are the operator's (the image reads them from `JAVA_OPTS`). The configuration is checked before the kernel starts, so a variable that is missing ends the process with status 78 and a list of every problem.

- **`migrate`** reads only the `EXERIS_MIGRATE_*` settings, never boots the kernel and needs no licence manifest.
- **`bootstrap-owner`** boots the kernel's persistence and scheduling, and so needs the licence manifest (`EXERIS_LICENSE_MANIFEST_PATH`).
- **`serve`** boots the kernel and needs the licence manifest.

### Exit statuses of `migrate` and `serve`

| Command | Status | Meaning |
| --- | --- | --- |
| `migrate` | 0 | the migrations were applied, or the schema was already current |
| `migrate` | 1 | the database refused a migration or could not be reached; the SQLSTATE is logged |
| `migrate` | 78 | the migration settings cannot be used |
| `serve` | 0 | the service ran and was stopped |
| `serve` | 69 | the database cannot be reached; the service did not start |
| `serve` | 78 | the configuration cannot be used, or the service role is a superuser or bypasses row-level security; the service did not start |
| either | 64 | the command line is not understood |

A kernel that does not boot under `serve`, for example without a licence manifest, ends the process with an uncaught exception rather than one of these statuses. The statuses of `bootstrap-owner` are listed in its section.

## `bootstrap-owner`

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
