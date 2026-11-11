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
| `serve` | 0 | the service ran and its stop was requested by an interrupt of the launcher's thread, which only an embedding host can do; a stop by signal never reports 0 |
| `serve` | 143 (Linux; 128 plus the signal number) | the service ran and was stopped by SIGTERM; the JVM reports the signal, whatever the launcher returned. |
| `serve` | 69 | the database cannot be used: it cannot be reached, or it refuses the service role's credentials (a wrong password is logged as SQLSTATE 28P01); a JDBC URL that carries credentials in its authority (`//user:password@host`) also ends here, with SQLSTATE 08001, because the PostgreSQL driver does not honour them. The service did not start |
| `serve` | 70 | the kernel did not boot, for example without a licence manifest; or the service failed while starting, while serving or while stopping, or a class could not be loaded or initialised at start. One ERROR line is logged. For a kernel that did not boot it carries the kernel's message, such as the licence gate's code and reason, with the database password and any password in a connection URL withheld; for a failure of the service or of a class it names only the exception class. A fatal VM error such as running out of memory also ends with 70, at once and without running the shutdown hooks |
| `serve` | 78 | the configuration cannot be used, or the service role is a superuser or bypasses row-level security; the service did not start |
| either | 64 | the command line is not understood |

No ending of `serve` is an uncaught exception. A supervisor should treat 0 and 143 as a normal stop and every other status as a failure. The launcher exits explicitly, so a kernel thread cannot keep a finished process alive. The statuses of `bootstrap-owner` are listed in its section.

### Stopping `serve`

On SIGTERM the service stops answering (requests get 503), drains in-flight work for at most 15 s per capability, stops its capabilities once, and then the kernel stops its subsystems. A service that no client has kept a connection to stops in under a second.

A connection that a client keeps open can delay the stop by the kernel's HTTP idle timeout (30 s by default). The kernel counts a keep-alive connection as busy while it is parked between requests when its last request was slow, meaning more than about 100 ms from the start of that connection's request-loop iteration to the end of the handler, a time that includes how long the client took to send the request. The stop then waits for the idle timeout to reclaim the connection, and the stopping thread spins on a CPU meanwhile. Any client that pauses more than about 100 ms between requests on a connection it keeps open triggers this, for example a health probe that polls once a second. This is [exeris-kernel issue 835](https://github.com/exeris-systems/exeris-kernel/issues/835), seen with kernel 0.13.1. With the default idle timeout the stop took about 30 to 35 s; a service that no client holds a connection to stops in under a second. Closing the clients' connections before the stop avoids the delay, for example by taking the instance out of the load balancer's rotation before signalling it.

Give the process a stop grace of at least 60 s (for example `TimeoutStopSec=60` in systemd, `--stop-timeout 60` for a container) so the supervisor does not kill it mid-drain with SIGKILL.

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
| 69 | the database cannot be used: it cannot be reached, or it refuses the service role's credentials (SQLSTATE 28P01 for a wrong password; 08001 for credentials placed in the URL) |
| 70 | the kernel did not boot, the provisioning did not run or the transaction failed; nothing was committed |
| 73 | an account already exists; nothing was changed (found after the kernel booted) |
| 78 | the configuration cannot be used, or the credential table is under row-level security, which the command refuses because the first account is decided for the whole deployment |

The audit event of the creation goes to the in-memory audit sink and is lost when the command exits. Not covered: creating the tenant in the host, a second owner, resetting the bootstrap, password reset and second-factor enrolment for the owner.
