---
title: "Launcher reference"
type: reference
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-12
---

# Launcher reference

The commands of the standalone launcher, their requirements and exit statuses, and the settings of `bootstrap-owner`. The procedure is [Run the service](../how-to/run-the-service.md); the other settings are in the [configuration reference](configuration.md).

## Commands

The standalone launcher is `eu.exeris.sku.identity.launcher.IdentitySkuApplication` with three commands: `serve` (the default), `migrate` and `bootstrap-owner`. A first installation runs them in this order: `migrate`, `bootstrap-owner`, `serve`, then a sign-in.

The jar's manifest names the launcher as its main class and `lib/` as its class path, so no `-cp` is needed while `target/lib/` stays beside it. With no argument the launcher serves, and a second argument is a usage error (status 64). `--enable-native-access=ALL-UNNAMED` is the flag the container image passes, because the kernel's off-heap memory needs native access; further JVM options are the operator's (the image reads them from `JAVA_OPTS`). The configuration is checked before the kernel starts, so a variable that is missing ends the process with status 78 and a list of every problem.

- **`migrate`** reads only the `EXERIS_MIGRATE_*` settings (and the service password, only to withhold it from its log), never boots the kernel and needs no licence manifest.
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
| `serve` | 69 | the database cannot be used: it cannot be reached, or it refuses the service role's credentials (a wrong password is logged as SQLSTATE 28P01); a JDBC URL that does not have the [accepted form](configuration.md#the-jdbc-url-rule), for instance one that carries credentials in its authority (`//user:password@host`), also ends here, with SQLSTATE 08001, without the driver being called. The service did not start |
| `serve` | 70 | the kernel did not boot, for example without a licence manifest; or the service failed while starting, while serving or while stopping, or a class could not be loaded or initialised at start. One ERROR line is logged. For a kernel that did not boot it carries the kernel's message, such as the licence gate's code and reason, with the database password and any password in a connection URL withheld; for a failure of the service or of a class it names only the exception class. A fatal VM error such as running out of memory also ends with 70, at once and without running the shutdown hooks |
| `serve` | 78 | the configuration cannot be used, or the service role is a superuser or bypasses row-level security; the service did not start |
| either | 64 | the command line is not understood |

No ending of `serve` is an uncaught exception. A supervisor should treat 0 and 143 as a normal stop and every other status as a failure. The launcher exits explicitly, so a kernel thread cannot keep a finished process alive. The statuses of `bootstrap-owner` are listed in its section.

### Stopping `serve`

On SIGTERM the service stops answering (requests get 503), drains in-flight work within one budget of 15 s shared by all the capabilities (a drain that overruns it is interrupted and abandoned, and the later capabilities are still stopped), stops its capabilities once, and then the kernel stops its subsystems. The drain is interrupted, not killed: a capability whose drain ignores the interrupt holds the stop until the drain returns, and its `terminate` is never called while the drain runs. After a termination signal the process then stays up until the supervisor kills it, and the overrun warning is logged only when the drain returns. A drain or a terminate that throws is logged by the class of the capability and of the exception only, without the exception's message or stack. A stop that itself fails is reported by one line, `Stopping Identity failed (<exception class>)`, that names the class only; after a termination signal the line is written to the standard error, like the stop notice, when the shutdown hook performed the stop.

The stop notice, `Shutdown signal received, draining`, is written once to the standard error by the shutdown hook itself, not through the logging framework (see [why](../explanation/launcher-stop-and-log-redaction.md#why-the-stop-notice-bypasses-the-logging-framework)). A stop requested while a host part is still joining the transactions, before the composition has started, starts nothing and never logs `Exeris Identity running on`.

A failure is treated as the interrupt's, and not as a failure of the service, only when both hold: the interrupt flag of the launcher's thread is still set, and an `InterruptedException`, an `InterruptedIOException` or a `ClosedByInterruptException` is in the failure's cause chain, where an `InterruptedIOException` counts only by its exact class. A subclass of it does not count, because it is raised for other causes as well: a `SocketTimeoutException` is a connect or read timeout, and it is a failure of the network whatever the flag. That covers a capability that refuses to be built on an interrupted thread and a kernel that surfaces the interrupt as a wrapped exception. The one case that is not recognised is a failure of the kernel's boot that does not carry such a cause, or after which the flag was cleared: the launcher cannot tell it from a failure of another cause and does not guess, so it ends with status 70 and logs it as a failure.

The configuration check and the database role check are never classified as a stop. A failure of either ends with its own status (78 for a configuration or role error, 69 when the database cannot be used) whatever the flag. The consequence is that with the flag already set when `serve` is called nothing is checked, so a configuration or role error is not reported in that call: it ends with 0.

A connection that a client keeps open can delay the stop by the kernel's HTTP idle timeout, the `idleTimeoutMillis` of the kernel's `HttpConfig`, whose default is 30 000 ms and which the launcher does not set. Taking the instance out of the load balancer's rotation before signalling it, or closing the clients' connections, avoids the delay. The cause is [exeris-kernel issue 835](https://github.com/exeris-systems/exeris-kernel/issues/835), seen with kernel 0.13.1; [how a kept-open connection holds the stop](../explanation/launcher-stop-and-log-redaction.md#why-a-kept-open-connection-delays-the-stop) explains it.

Give the process a stop grace of at least 60 s (for example `TimeoutStopSec=60` in systemd, `--stop-timeout 60` for a container) so the supervisor does not kill it mid-drain with SIGKILL.

### Secrets in the launcher's output

Two kinds of text reach the output, and the launcher redacts both.

- **The launcher's own log lines.** Every text such a line carries that the launcher did not write itself (the message of the kernel, of a driver or of a configuration refusal, and a SQLSTATE) is passed through a redaction first. The launcher's own constant lines, and the class names it logs for failures whose message is not ours to print, are logged directly.
- **The records of every other logger written through the JVM's logging** (`java.util.logging`, which is also where `System.Logger` goes by default). The PostgreSQL driver, the kernel and the capabilities log this way, and the driver writes before any exception exists: for a URL it cannot parse it logs a warning that quotes part of the URL. At the start of every command the launcher wraps each handler attached to a logger, and every record of a logger that is not the launcher's own is rewritten before the handler writes it: its message is formatted with its parameters and passed through the redaction with the command's secrets, and its exception is replaced by the class names of the exception and of its causes, so an operator sees where it failed but never the exception's message or stack frames. A secret that becomes known later (the content of the owner password file) is added to the secrets as soon as it has been read. A record that cannot be rewritten is written as `(log record withheld)`. The wrapper is installed in the JVM's root logger and in every logger that exists when the command starts; the Hikari pool logs through SLF4J, and with no SLF4J binding on the class path (this distribution has none) that logging is discarded.

Not covered: anything a library writes directly to the standard output or the standard error; a handler attached to a logger that is created after the command started; a logging configuration that is reset or reloaded afterwards; the content of a host part's own logging when it configures a backend of its own; and the stop notice (see below), which is a constant line. Before the driver is called the launcher also parses the database URL itself, see [the JDBC URL rule](configuration.md#the-jdbc-url-rule), so that a URL the driver would report is refused without reaching it. What the rule lets through can still make the driver write a record, but the text it can quote is a host, a port, a database name or a value of the grammar in that table, never a credential, a path or free text.

A withheld value is replaced by `<withheld>`; a message with nothing to say is logged as `(no message)`. The launcher gives two different assurances.

**Configured secrets: always.** The passwords the command is configured with are withheld wherever they occur in such a message, in these forms. They are read from the environment without recording a problem, so they are known when the configuration itself is what failed:

| Command | Secrets withheld |
| --- | --- |
| `migrate` | the migration password (`EXERIS_MIGRATE_DATABASE_PASSWORD` or its `_FILE`) and, when configured, the service password (`EXERIS_DATABASE_PASSWORD` or its `_FILE`) |
| `serve` | the service password |
| `bootstrap-owner` | the service password and the content of the password file once it has been read |

| Form | Matched |
| --- | --- |
| literal | the text as configured, case-sensitive: a differently cased string is another string |
| percent-encoded | any mix of literal characters and `%XX` escapes of the secret's UTF-8 bytes, upper-case or lower-case hexadecimal. The spelling is chosen at each position of the secret on its own: a literal `+` in the message stands for a space only where the secret has a space, and a `+` of the secret matches a literal `+` or `%2B`, so a secret `a b+c` is withheld in `a+b+c`, `a+b%2Bc` and `a%20b+c` |
| Base64, Base64url | the encoding of the secret's UTF-8 bytes, with and without padding, as a contiguous run |

A secret shorter than 3 characters is withheld only where the structure rules below name it. At most 8 distinct secrets are accepted, and a secret has at most six match patterns (its literal text, up to four Base64 forms, and its percent-decoded view), so there is no separate limit on patterns. Beyond 8 secrets, or when a message is built so that checking the percent-decoded view of one secret would take more than 16 steps per byte of message and secret, the launcher logs `(message withheld)` instead of the message. Not recognised: a secret split by a line break, encoded twice, or inside a longer Base64 payload. A placeholder already present in the text (`<withheld>` or `(message withheld)`) is kept as it is: a secret that occurs only inside such a placeholder, such as `held` inside `<withheld>`, is not an occurrence, while an occurrence of a secret outside a placeholder is withheld as usual.

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

Withholding the rest of the line after an unquoted password name costs readability: a driver message such as `{user=u, password=x, ssl=true}` loses `, ssl=true}`, while a URL keeps its host, port, database and parameters. The reasons are in [why the redaction withholds so much](../explanation/launcher-stop-and-log-redaction.md#why-the-redaction-withholds-so-much).

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

- **The password file** is read as strict UTF-8, every trailing carriage return and line feed is removed and the rest is the password, inner whitespace included. Its length must lie in the credential policy's window, and a file larger than four bytes per permitted character plus two is refused unread. On a filesystem that reports POSIX permissions only the owner may have access (mode `0400` or `0600`); mounted secrets need `defaultMode: 0400` or the equivalent. Where permissions cannot be checked a warning says so. The content is held in a character array that is zeroed after use.
- **Refusals** change nothing. Before the kernel boots: incomplete or unusable configuration (all problems are listed together), a password outside the policy, a service role that is a superuser or `BYPASSRLS`. These need no licence. After it boots, from inside the transaction: an account already exists (status 73), the schema is not migrated for the service role (65: the credential store's table is missing or the role may not use it), a credential table under row-level security (78) and an address the credential store cannot use as a login identifier (78). The host reads no table of the credential store itself, and the service role cannot read the migration record, so these four refusals need the kernel to have booted and therefore a licence.
- **The kernel boots persistence and scheduling only**, no listener, so the licence manifest (`EXERIS_LICENSE_MANIFEST_PATH`) is required as for `serve`; without one the kernel does not boot, in every environment, and the command ends with status 70 and no account, whatever the database holds.
- **Membership.** This service keeps no membership table; tenant membership and roles belong to the host's `MembershipDirectory`. With a directory configured, the account is granted `owner` in the configured tenant inside the same transaction as the account, so a failing grant leaves no account. The tenant must already mean something to the host. With no directory configured (outside production-class environments only), the account is created and belongs to no tenant: its tokens name no tenant and carry no role and no scope, so it cannot issue an invitation and nobody can be invited. The operator then records the owner role for that subject (its id is logged) in the host's membership store, and the owner signs in again to obtain a token that names the tenant.
- **No secret is written by the launcher's own log lines or by the records of other loggers**: not the password, the file's content, the database password or the address; no token is issued. Their messages are logged with the secrets listed under [Secrets in the launcher's output](#secrets-in-the-launchers-output) withheld, which also states what is not covered.

| Status | Meaning |
| --- | --- |
| 0 | the account was created |
| 64 | the command line was not understood |
| 65 | the schema is not migrated for the service role (found after the kernel booted) |
| 69 | the database cannot be used: it cannot be reached, or it refuses the service role's credentials (SQLSTATE 28P01 for a wrong password; 08001 for a URL that is not of the accepted form, such as credentials placed in it) |
| 70 | the kernel did not boot, the provisioning did not run or the transaction failed; nothing was committed. For a kernel that did not boot one ERROR line carries the kernel's message with the service database password, the password file's content and any password in a connection URL withheld; for any other failure it names only the exception class |
| 73 | an account already exists; nothing was changed (found after the kernel booted) |
| 78 | the configuration cannot be used, or the credential table is under row-level security, which the command refuses because the first account is decided for the whole deployment |

The audit event of the creation goes to the in-memory audit sink and is lost when the command exits. Not covered: creating the tenant in the host, a second owner, resetting the bootstrap, password reset and second-factor enrolment for the owner.
