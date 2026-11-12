---
title: "Configuration reference"
type: reference
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-12
---

# Configuration reference

Every setting the launcher reads, the grammar of the keyrings and the pepper, and how the host parts are named, loaded and replaced. The procedure that uses them is [Run the service](../how-to/run-the-service.md); the commands and the settings of `bootstrap-owner` are in the [launcher reference](launcher.md).

## Settings

**Configuration** comes from the environment, optionally from a file named by `EXERIS_IDENTITY_CONFIG` that holds the identity settings under the same names (not the database, `EXERIS_ENVIRONMENT` or host-part settings); the environment wins. A line of the file that is not a known setting is refused by its line number, and its key is named only when it looks like a setting name (`EXERIS_` and at most 80 capitals, digits and underscores). A blank value counts as unset, except for an inline database password, for which only an empty value does. Every secret takes either its name or its name plus `_FILE`, the path of a readable file, never both. The launcher reads the files of the two database passwords as strict UTF-8, removes every trailing carriage return and line feed and nothing else, and refuses a file larger than 1 MiB or without content; an inline database password is used exactly as written. The keyrings and the pepper are read by their capabilities, which read a file as UTF-8 and trim white space from both ends of it, as they do an inline value. A message about a refused setting names the setting, a line number, a bound or, for a host part that cannot be created, the class of the exception; it never repeats a value, a path or a line of a file.

Launcher and database settings:

| Name | Required | Meaning |
| --- | --- | --- |
| `EXERIS_ENVIRONMENT` | `serve`, `bootstrap-owner` | one of `development`, `staging`, `production`, `production-load-sim`, `dr-cold`, `dr-hot`; there is no default |
| `EXERIS_DATABASE_URL` | `serve`, `bootstrap-owner` | JDBC URL of the database, in the form `jdbc:postgresql://host[:port][,host[:port]...]/database[?name=value&...]` (see [the URL rule](#the-jdbc-url-rule)). A URL that starts with `jdbc:postgresql:` and has another shape is refused before the driver sees it, with status 69 (SQLSTATE 08001) and a message that does not quote it; one that does not start with it is a configuration problem (status 78). The role and its password go in `EXERIS_DATABASE_USER` and `EXERIS_DATABASE_PASSWORD` (or `_FILE`) |
| `EXERIS_DATABASE_USER` | `serve`, `bootstrap-owner` | the service role |
| `EXERIS_DATABASE_PASSWORD` or `_FILE` | `serve`, `bootstrap-owner` | the service role's password |
| `EXERIS_DATABASE_MAX_POOL_SIZE` | no | most pooled connections, 1 to 1000, default 10 |
| `EXERIS_MIGRATE_DATABASE_URL` | `migrate` | JDBC URL of the same database, in the same form as `EXERIS_DATABASE_URL` and refused the same way, which for a URL of another shape is status 1 (SQLSTATE 08001) for `migrate`, and status 78 for one that does not start with `jdbc:postgresql:` |
| `EXERIS_MIGRATE_DATABASE_USER` | `migrate` | the migration role |
| `EXERIS_MIGRATE_DATABASE_PASSWORD` or `_FILE` | `migrate` | the migration role's password |
| `EXERIS_MIGRATE_SERVICE_ROLE` | no | the service role `migrate` grants access to; lowercase letters, digits and underscores, starting with a letter or underscore, at most 63 characters |
| `EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY`, `EXERIS_IDENTITY_NOTIFICATION_DISPATCHER`, `EXERIS_IDENTITY_INVITATION_DELIVERY` | in `production`, `production-load-sim` and `dr-hot` | the host's classes, see [Host parts](#host-parts) |
| `EXERIS_IDENTITY_CONFIG` | no | path of the properties file |
| `EXERIS_LICENSE_MANIFEST_PATH` | `serve`, `bootstrap-owner` | the licence manifest, read by the kernel |

Identity settings, for `serve` and `bootstrap-owner`. Durations are ISO-8601, such as `PT15M`:

| Name | Required | Default and bounds, meaning |
| --- | --- | --- |
| `EXERIS_TOKEN_ISSUER_ISSUER` | yes | the `iss` of every token; at most 2048 characters, no white space or control character |
| `EXERIS_TOKEN_ISSUER_AUDIENCE` | yes | the `aud` of every token; same limits |
| `EXERIS_TOKEN_ISSUER_KEKS` or `_FILE` | yes | keyring sealing the signing keys |
| `EXERIS_MFA_TOTP_KEKS` or `_FILE` | yes | keyring sealing the TOTP secrets |
| `EXERIS_FEDERATED_LOGIN_STATE_KEYS` or `_FILE` | yes | keyring sealing federated-login flow state |
| `EXERIS_MFA_TOTP_PEPPER` or `_FILE` | yes | pepper of the recovery-code and challenge hashes |
| `EXERIS_TOKEN_ISSUER_TOKEN_TTL` | no | access-token lifetime, `PT15M`; whole seconds, at least one second, at most the maximum below |
| `EXERIS_TOKEN_ISSUER_MAX_TOKEN_TTL` | no | longest lifetime any token may have, `PT1H`; whole seconds, at least one second |
| `EXERIS_TOKEN_ISSUER_CLOCK_SKEW` | no | verifier clock tolerance the key publication allows for, `PT1M`; zero or more |
| `EXERIS_TOKEN_ISSUER_KEY_TTL` | no | how long a signing key signs before rotation, `P7D`; positive, and must exceed the next two together |
| `EXERIS_TOKEN_ISSUER_JWKS_MAX_AGE` | no | how long a verifier may cache the key set, `PT5M`; whole seconds, at least one |
| `EXERIS_TOKEN_ISSUER_ROTATION_CHECK_INTERVAL` | no | how often rotation is checked, `PT1H`; positive |
| `EXERIS_TOKEN_ISSUER_MANUAL_ROTATION` | no | `true` when the host runs the rotation itself and no scheduler does; `false` by default |
| `EXERIS_JWT_ISSUER`, `EXERIS_JWT_AUDIENCE` | no | the issuer and audience the verifier requires; if set they must equal the token issuer's |
| `EXERIS_JWT_CLOCK_SKEW_SECONDS` | no | verifier clock tolerance in seconds, 30; 0 to 3600 |
| `EXERIS_MFA_TOTP_CHALLENGE_TTL` | no | lifetime of a second-factor challenge, `PT5M`; positive, and not above the next |
| `EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL` | no | longest challenge lifetime, `PT10M`; positive |
| `EXERIS_HTTP_BIND_HOST` | no | address to bind, `127.0.0.1`; the container image sets `0.0.0.0` |
| `EXERIS_HTTP_PORT` | no | 8080; 1 to 65535 |
| `EXERIS_HTTP_MAX_REQUEST_BODY_BYTES` | no | 65536; 1 to 16 MiB |
| `EXERIS_HTTP_MAX_REQUEST_HEADER_COUNT` | no | 100; 1 to 10000 |
| `EXERIS_HTTP_MAX_REQUEST_HEADER_SIZE` | no | 8192 bytes; 1 to 1048576 |
| `EXERIS_CORS_ALLOWED_ORIGINS` | no | comma-separated origins (`http://host[:port]` or `https://host[:port]`, no path); empty switches CORS off, `*` is refused |
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
| `EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH`, `_MAX_LENGTH` | no | accepted password length, 8 and 128; 1 to 4096, and the maximum is not below the minimum |
| `EXERIS_PASSWORD_ARGON2_MEMORY_KIB` | no | Argon2id memory, 65536; 8192 to 4194304 |
| `EXERIS_PASSWORD_ARGON2_ITERATIONS` | no | Argon2id passes, 3; 1 to 100 |
| `EXERIS_PASSWORD_ARGON2_PARALLELISM` | no | Argon2id lanes, 1; 1 to 64 |

The five rate-limit groups are `LOGIN` (login and `/mfa/verify`), `REFRESH`, `PASSWORD_RESET`, `VERIFICATION` and `INVITATION_ACCEPT`. The lockout window and duration and the credential-token settings are in seconds, from 1 second to 3650 days.

## The JDBC URL rule

The launcher parses the database URL itself and calls the PostgreSQL driver only with a URL that has this form, because the driver writes a URL it cannot parse to the log, quoting part of it, before it fails.

- The scheme is `jdbc:postgresql://`.
- The authority holds one or more hosts separated by commas. A host is a name, an IPv4 address or an IPv6 address in brackets, with an optional port from 1 to 65535. **It holds no user-info: an `@` anywhere in the authority is a refusal.** Credentials go in the user and password settings.
- A database name follows the first `/`: letters, digits and `. _ ~ -`, with well-formed percent-escapes. A URL without one is refused, and so is a fragment (`#`).
- A query is optional. The query holds only the parameters of the table below, each once, with a value of the grammar given there.

| Parameter | Value |
| --- | --- |
| `ssl`, `tcpKeepAlive`, `loadBalanceHosts`, `reWriteBatchedInserts` | `true` or `false` |
| `sslmode` | `disable`, `allow`, `prefer`, `require`, `verify-ca` or `verify-full` |
| `connectTimeout`, `socketTimeout`, `loginTimeout`, `cancelSignalTimeout`, `hostRecheckSeconds` | a decimal integer from 0 to 86400 (seconds) |
| `prepareThreshold` | a decimal integer from 0 to 10000 |
| `defaultRowFetchSize` | a decimal integer from 0 to 1000000 |
| `targetServerType` | `any`, `primary`, `master`, `slave`, `secondary`, `preferSlave`, `preferSecondary` or `preferPrimary` |
| `ApplicationName` | 1 to 63 characters of `A-Za-z0-9._-` |
| `currentSchema` | identifiers of `A-Za-z0-9_` separated by commas, at most 255 characters |
| `stringtype` | `unspecified` or `varchar` |
| `assumeMinServerVersion` | one to three groups of up to six digits separated by dots, such as `12` or `14.2` |
| `gssEncMode` | `disable`, `allow`, `prefer` or `require` |
| `channelBinding` | `disable`, `prefer` or `require` |

Names are matched exactly, in the case above, without percent-escapes; a value holds no percent-escape, blank or control character. A number is written in at most nine digits. A parameter that is not in the table, that has no value, or that appears twice is refused, whatever its value. So the settings that name a class (`socketFactory`, `sslfactory`, `authenticationPluginClassName`, `sslhostnameverifier`, `sslpasswordcallback`, `xmlFactoryFactory`), a file or a socket (`sslkey`, `sslcert`, `sslrootcert`, `passfile`, `loggerFile`, `localSocketAddress`, `service`, `socketFactoryArg`, `sslfactoryarg`), free text for the server (`options`), the driver's logging (`loggerLevel`) and every credential or alias of one (`user`, `password`, `sslpassword`, `PGPORT`, `PGHOST`, `PGDBNAME` and the like) are not available through the URL. A parameter named `user`, `password` or `sslpassword`, or any name that contains `password`, `passwd`, `pwd` or `passphrase` in any case or percent-escaped spelling, is refused: a credential in the URL's query would be printed by any message that quotes the URL.

A URL that does not start with `jdbc:postgresql:` is a configuration problem (status 78) found while the settings are read. A URL that starts with it and does not have the form above is refused when the connection is opened: `serve` and `bootstrap-owner` end with status 69, `migrate` with status 1, all with SQLSTATE 08001 and a message that names no part of the URL.

## Keyrings and pepper

Each of the three keyrings is a comma-separated list of `<id>:<key>` entries. An id is 1 to 32 characters of `A-Za-z0-9._-` and unique within the keyring; a key is exactly 32 random bytes in Base64, 44 characters with the padding, which may be left off (a key containing `-` or `_` is read as URL-safe Base64, any other as standard). White space around an entry is ignored. The first entry is active and seals everything new; the others only open what was sealed under them, so a key rotates by putting a new entry first and is dropped once nothing stored names it. The pepper is standard Base64 (not URL-safe) of at least 32 random bytes.

## Host parts

- **Environment and stand-ins:** the kernel is given the same `EXERIS_ENVIRONMENT` as the service. `EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY`, `EXERIS_IDENTITY_NOTIFICATION_DISPATCHER` and `EXERIS_IDENTITY_INVITATION_DELIVERY` name the host's classes. In `production`, `production-load-sim` and `dr-hot` the service refuses to start unless all three are named. In the other environments, a missing directory is replaced by one in which nobody belongs to any tenant (tokens name no tenant and nobody can issue an invitation), a missing dispatcher by one that delivers nothing and logs that a token was not delivered, and with no invitation delivery, issuing an invitation answers 503 and stores nothing. `dr-cold` is not production-class in the kernel's classification, so a cold site promoted without changing `EXERIS_ENVIRONMENT` starts with these stand-ins and only logs warnings; set the environment to `dr-hot` or `production` when promoting.
- **Loading:** a named class must be a `MembershipDirectory`, a `NotificationDispatcher` or an `InvitationDelivery` respectively and is created through its public no-argument constructor before the kernel boots; a class that is not, or cannot be created that way, is a configuration problem (status 78) listed with the others. A part that implements `eu.exeris.sku.identity.auth.JoinsServiceTransactions` is handed the executor that joins the service's transactions once, after the composition is built and before any job runs or any request is admitted. A host that embeds the library reads it from `IdentityComposition.transactionalExecutor()`. Why a part writes through it, what a write through another executor does and why `deliver` can run more than once are in [Host parts and the service's transactions](../explanation/host-parts.md).
- **Row-level security** is switched on for the kernel's persistence in every environment and cannot be switched off by the operator; the reason is in [Why row-level security is always on](../explanation/host-parts.md#why-row-level-security-is-always-on).

## Where this does not apply

This page lists the settings the standalone launcher reads. An embedding host does not use the launcher: it builds an `IdentityConfig` and gives it to `IdentityComposition.Builder.config(...)`. `IdentityConfig.load()` and `IdentityConfig.load(Map)` read the identity settings under the names above (from the environment and the file named by `EXERIS_IDENTITY_CONFIG`), and `IdentityConfig.from(Map)` takes already merged settings under the same names. The other parts of the composition (the transactional executor, the password encoder, the notification dispatcher, the membership directory, the invitation delivery, the job scheduler, the clock, the peer address source, the name authenticator apps show for the second factor and the routes) are given to the builder in code, not by a setting. The launcher's own settings (`EXERIS_ENVIRONMENT`, the database and migration settings, the host-part class names, the settings of `bootstrap-owner` and the licence manifest path) are read by the launcher, not by `IdentityConfig`. The kernel's own settings that the launcher derives from these (the listener, its request limits, the persistence pool and row-level security) are not configurable here.
