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
| `serve` | 0 | the service was stopped on request by an interrupt of the launcher's thread, which only an embedding host can do; an interrupt that arrives before the composition has started ends the call the same way and the service never serves, with no failure logged and the thread's interrupt flag still set. This holds for an interrupt delivered before `serve` is called, and for one delivered while the kernel boots or the capabilities are built, in the cases the next paragraph names. A stop by signal never reports 0 |
| `serve` | 143 (Linux; 128 plus the signal number) | the service ran and was stopped by SIGTERM; the JVM reports the signal, whatever the launcher returned. |
| `serve` | 69 | the database cannot be used: it cannot be reached, or it refuses the service role's credentials (a wrong password is logged as SQLSTATE 28P01); a JDBC URL that carries credentials in its authority (`//user:password@host`) also ends here, with SQLSTATE 08001, because the PostgreSQL driver does not honour them. The service did not start |
| `serve` | 70 | the kernel did not boot, for example without a licence manifest; or the service failed while starting, while serving or while stopping, or a class could not be loaded or initialised at start. One ERROR line is logged. For a kernel that did not boot it carries the kernel's message, such as the licence gate's code and reason, with the database password and any password in a connection URL withheld; for a failure of the service or of a class it names only the exception class. A fatal VM error such as running out of memory also ends with 70, at once and without running the shutdown hooks |
| `serve` | 78 | the configuration cannot be used, or the service role is a superuser or bypasses row-level security; the service did not start |
| either | 64 | the command line is not understood |

No ending of `serve` is an uncaught exception. A supervisor should treat 0 and 143 as a normal stop and every other status as a failure. The launcher exits explicitly, so a kernel thread cannot keep a finished process alive. The statuses of `bootstrap-owner` are listed in its section.

### Stopping `serve`

On SIGTERM the service stops answering (requests get 503), drains in-flight work for at most 15 s per capability, stops its capabilities once, and then the kernel stops its subsystems. A service that no client has kept a connection to stops in under a second.

The stop notice, `Shutdown signal received, draining`, is written once to the standard error by the shutdown hook itself, not through the logging framework: the framework's own shutdown hook runs at the same time and removes its handlers, so a record logged from a hook can be lost. A stop requested while a host part is still joining the transactions, before the composition has started, starts nothing and never logs `Exeris Identity running on`.

A failure is treated as the interrupt's, and not as a failure of the service, only when both hold: the interrupt flag of the launcher's thread is still set, and an `InterruptedException`, an `InterruptedIOException` or a `ClosedByInterruptException` is in the failure's cause chain. That covers a capability that refuses to be built on an interrupted thread and a kernel that surfaces the interrupt as a wrapped exception. The one case that is not recognised is a failure of the kernel's boot, of the configuration check or of the database role check that does not carry such a cause, or after which the flag was cleared: the launcher cannot tell it from a failure of another cause and does not guess, so it ends with the status that failure has (70 for the kernel's boot, 69 or 78 for the checks) and logs it as a failure.

A connection that a client keeps open can delay the stop by the kernel's HTTP idle timeout (30 s by default). The kernel counts a keep-alive connection as busy while it is parked between requests when its last request was slow, meaning more than about 100 ms from the start of that connection's request-loop iteration to the end of the handler, a time that includes how long the client took to send the request. The stop then waits for the idle timeout to reclaim the connection, and the stopping thread spins on a CPU meanwhile. Any client that pauses more than about 100 ms between requests on a connection it keeps open triggers this, for example a health probe that polls once a second. This is [exeris-kernel issue 835](https://github.com/exeris-systems/exeris-kernel/issues/835), seen with kernel 0.13.1. With the default idle timeout the stop took about 30 to 35 s; a service that no client holds a connection to stops in under a second. Closing the clients' connections before the stop avoids the delay, for example by taking the instance out of the load balancer's rotation before signalling it.

Give the process a stop grace of at least 60 s (for example `TimeoutStopSec=60` in systemd, `--stop-timeout 60` for a container) so the supervisor does not kill it mid-drain with SIGKILL.

### Secrets in the launcher's output

A message that the kernel or a driver produced is passed through a redaction before the launcher logs it. A withheld value is replaced by `<withheld>`; a message with nothing to say is logged as `(no message)`. The launcher gives two different assurances.

**Configured secrets: always.** The database password (`EXERIS_DATABASE_*`) is withheld wherever it occurs in such a message, in these forms:

| Form | Matched |
| --- | --- |
| literal | the text as configured, case-sensitive: a differently cased string is another string |
| percent-encoded | any mix of literal characters and `%XX` escapes of the secret's UTF-8 bytes, upper-case or lower-case hexadecimal. The spelling is chosen at each position of the secret on its own: a literal `+` in the message stands for a space only where the secret has a space, and a `+` of the secret matches a literal `+` or `%2B`, so a secret `a b+c` is withheld in `a+b+c`, `a+b%2Bc` and `a%20b+c` |
| Base64, Base64url | the encoding of the secret's UTF-8 bytes, with and without padding, as a contiguous run |

A secret shorter than 3 characters is withheld only where the structure rules below name it. At most 8 distinct secrets are accepted, and a secret has at most six match patterns (its literal text, up to four Base64 forms, and its percent-decoded view), so there is no separate limit on patterns. Beyond 8 secrets, or when a message is built so that checking the percent-decoded view of one secret would take more than 16 steps per byte of message and secret, the launcher logs `(message withheld)` instead of the message. Not recognised: a secret split by a line break, encoded twice, or inside a longer Base64 payload.

**Other credentials in third-party messages: best effort.** The launcher also withholds credentials it recognises by shape, without knowing them. A shape that is not in the table passes through.

| Context | Withheld |
| --- | --- |
| password of a `://user:password@host` authority | the text between the first colon after the scheme and the first `@` |
| quoted value after `=` or `:` of a sensitive name | the text up to the first closing quote of the same kind; `\"` and a doubled quote do not close it; an unclosed value runs to the end of the message |
| name wrapped in quotes (`"password": x`) with an unquoted value | up to `,`, `}`, `]`, `)`, `&`, `;`, a quote or white space |
| unquoted value of a password name, in a URL query (name directly after `?`, `&` or `;`) | up to `&`, `;`, a quote, `)` or white space |
| unquoted value of a password name, anywhere else | up to the end of the line, so `password=my secret pass` and `host=h password=p dbname=d` lose everything after the `=` |
| unquoted value of another sensitive name | up to `&`, `;`, `,`, a quote, `)` or white space; a value that contains one of them leaks its tail |
| `Authorization:` and `Proxy-Authorization:` lines | everything after the scheme, to the end of the line |
| `Cookie:` and `Set-Cookie:` lines | everything after the colon, to the end of the line |
| `--<sensitive name> <word>` | the next word |

**Cost to readability.** An unquoted value of a password name outside a URL query withholds the rest of its line, because nothing in the text says where a password that may hold blanks, commas and `&` ends. A driver message that dumps its properties, such as `{user=u, password=x, ssl=true}`, therefore loses everything that follows the password (`, ssl=true}`). A URL keeps its host, port, database and parameters, because its password ends at the `@` of the authority or at the next `&`, `;` or white space of a query.

A name is a run of letters, digits, `_`, `.` and `-`. A *password name* contains `password`, `passwd`, `pwd` or `passphrase`, in any case. A *sensitive name* is a password name, or contains `secret`, `token` or `credential`, or ends in a key word: its last component (split at `_`, `.`, `-` and case changes) is `key`, or `api`, `ssl`, `tls`, `private`, `access`, `secret`, `auth`, `encryption`, `signing`, `master`, `hmac`, `pass`, `session`, `client`, `license`, `aes`, `rsa` or `jwt` followed by `key`. `monkey`, `keystore` and `key_id` are not sensitive. `Name.java:42` is a stack-trace position, never a label. The `=` form of `authorization` and `cookie`, the short flag `-p<value>`, and a secret in free text (`password is hunter2`) are not covered.

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
