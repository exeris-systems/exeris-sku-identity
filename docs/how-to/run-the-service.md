---
title: "Run the service"
type: howto
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-11
---

# Run the service

Goal: take a first installation from an empty PostgreSQL server to a signed-in owner, with the launcher's commands in the order `migrate`, `bootstrap-owner`, `serve`.

## Prerequisites

- JDK 25 (`maven.compiler.release` is 25) and the capabilities installed as described under [Build & test](../../README.md#build--test).
- A PostgreSQL server on which you can create roles and a database.
- A licence manifest for `bootstrap-owner` and `serve` (`EXERIS_LICENSE_MANIFEST_PATH`). `migrate` needs none.
- Every setting named below is described in the [configuration reference](../reference/configuration.md) and the [launcher reference](../reference/launcher.md).

## Steps

1. **Create the database roles.** Two roles and one database. The migration role owns the database; it creates the tables, indexes and row-level-security policy, grants access to the service role and is never the role the service runs as. Owning the database is enough: it needs neither superuser nor `CREATEROLE`. The service role must already exist when `migrate` runs, because `migrate` grants to it, but `migrate` does not create it.

   ```sql
   CREATE ROLE identity_migrate LOGIN PASSWORD '<migration-password>' NOSUPERUSER NOBYPASSRLS;
   CREATE ROLE identity_service LOGIN PASSWORD '<service-password>' NOSUPERUSER NOBYPASSRLS;
   CREATE DATABASE identity OWNER identity_migrate;
   ```

   With `EXERIS_MIGRATE_SERVICE_ROLE=identity_service`, `migrate` grants the service role `USAGE` on schema `public`, `SELECT`, `INSERT`, `UPDATE` and `DELETE` on every table in `public`, `USAGE` and `SELECT` on every sequence in `public`, and revokes all of its rights on the migration record `identity_applied_migrations`. It does this on every run, including one that applies nothing, and only in schema `public`. Without that setting the operator grants these. `CONNECT` on the database is held by every role unless the operator revoked it from `PUBLIC`, in which case it is granted to the service role by hand.

   The service role must be neither a superuser nor `BYPASSRLS`: `serve` and `bootstrap-owner` check this at start and end with status 78 otherwise, because row-level security only isolates tenants from a role that cannot step around it.

2. **Generate the secrets.** Generate each value in a terminal and put it straight into the secret store, or into a file for the `_FILE` form; never into the repository or a command line that is logged. The grammar of the values is in [Keyrings and pepper](../reference/configuration.md#keyrings-and-pepper).

   ```bash
   printf 'k1:%s\n' "$(openssl rand -base64 32)"   # a keyring with one key, id k1
   openssl rand -base64 32                          # a pepper
   ```

3. **Build.** `mvn -B package -DskipTests` writes `target/exeris-sku-identity-0.1.0-SNAPSHOT.jar` and copies the runtime classpath to `target/lib/`.

   To run in a container instead, build the image with `docker build -t exeris-sku-identity .` after `mvn package`.

4. **Migrate.** Set the `EXERIS_MIGRATE_*` settings and run, without a licence manifest:

   ```bash
   java --enable-native-access=ALL-UNNAMED -jar target/exeris-sku-identity-0.1.0-SNAPSHOT.jar migrate
   ```

   Replace `migrate` with `bootstrap-owner` or `serve` in the next two steps. The flag, the default command, usage errors and the status 78 on a missing variable are in [Commands](../reference/launcher.md#commands).

5. **Create the first account.** Write the owner's password to a file readable only by its owner (mode `0400` or `0600`), set `EXERIS_IDENTITY_BOOTSTRAP_OWNER_EMAIL`, `EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD_FILE` and, when a membership directory is configured, `EXERIS_IDENTITY_BOOTSTRAP_OWNER_TENANT`, together with everything `serve` needs, then run `bootstrap-owner`. This command boots the kernel's persistence and scheduling and needs the licence manifest. It exits with status 0 once the account exists; the other statuses and refusals are in [`bootstrap-owner`](../reference/launcher.md#bootstrap-owner).

6. **Serve.** Run `serve` (or no argument) with the identity settings and the licence manifest.

7. **Sign in.** `POST /api/v1/auth/login` with the owner's address and password; the request and response are in [Sign in and refresh](../reference/http-api.md#sign-in-and-refresh).

## Verify

`bootstrap-owner` exits with status 0 and the login of step 7 answers 200 with an `accessToken` and a `refreshToken`.

## Where this does not apply

Embedding the library in a host through `IdentityComposition` does not use the launcher; the [README](../../README.md#what-it-provides) describes it. Creating the tenant in the host, a second owner and resetting the bootstrap are not covered by `bootstrap-owner` (see [`bootstrap-owner`](../reference/launcher.md#bootstrap-owner)).
