---
title: "Host parts and the service's transactions"
type: explanation
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-11
---

# Host parts and the service's transactions

Why a host part that writes to the service's database has to write through the executor that joins the service's transactions, what happens when it writes through another one, why `InvitationDelivery.deliver` can run more than once for one request, and why row-level security is always on. The names of the settings, their defaults and the refusals are in the [configuration reference](../reference/configuration.md#host-parts).

## What a host part is

The service keeps no membership table and has no mail channel of its own. The host supplies a `MembershipDirectory` (where tenant membership and roles live), a `NotificationDispatcher` (verification and password-reset tokens) and an `InvitationDelivery` (the single-use token of an invitation). The service calls them from request threads, in the middle of its own work: `InvitationDelivery.deliver` runs inside the transaction that stores the invitation, and `MembershipDirectory.grant` runs while an invitation is accepted, before the account and the invitation are committed together.

## Why a part writes through the joining executor

The kernel's transactional executor has no propagation. A call to `executeManaged` opens a transaction of its own, and inside a kernel request it reuses the connection the request already holds, which is already in a transaction. The service therefore wraps the kernel's executor in `JoiningTransactionalExecutor`. Inside a unit, every call made through the same wrapper runs on the unit's connection, without a begin or a commit of its own, and sees the unit's earlier writes. The unit commits when its work returns and rolls back when it throws.

A host part that records into an outbox table, or stores grants in the service's database, wants its write to commit and roll back with the invitation or the account. Only a write through the joining executor does that. The launcher hands the executor to a part that implements `JoinsServiceTransactions`, because a part named to the launcher is created through its public no-argument constructor before the kernel boots and so cannot receive the executor at construction. The launcher passes it once, after the composition is built and before any job runs or any request is admitted. A host that embeds the library reads the same instance from `IdentityComposition.transactionalExecutor()`.

## What happens through another executor

A write through the kernel's own executor, or any other, is not part of the unit. Which of two things then happens depends on where the call lands:

- On the connection the request already holds, the write is refused, because that connection is in a transaction, and the refusal rolls the whole unit back. The invitation or the account is not created.
- Under another storage context, the write uses a connection of its own and commits independently of the unit. It survives a rollback of the invitation or the account.

The second case is the dangerous one, because nothing fails. The joining executor itself also refuses what cannot be joined: a second wrapper over the same delegate, a changed storage context inside a unit, a call to `execute` (which manages its own boundaries) and any isolation level other than read committed.

Cost: a part that is not handed the executor must not write to the service's database from inside a request at all, and a part named to the launcher has to implement `JoinsServiceTransactions` and store the executor in a way that is safely published, such as a `volatile` or a final field, because request threads read it after the launcher thread stored it.

## Why `deliver` can run more than once

The executor may run a transaction again after a serialization failure or a deadlock. One request can therefore call `InvitationDelivery.deliver` several times, each time with a different token. Only the token of the attempt that commits opens anything; if the attempt that delivered a token does not commit, the invitee holds a token that opens nothing. The same retry is why the work passed to a unit has to be safe to run more than once, and why actions queued for after the commit are dropped for an attempt that did not commit.

`deliver` also runs while the transaction holds a database connection. It hands the token over, for example to a durable outbox, and does not wait for a mail server. Handing the token to a durable outbox counts as delivered.

## Why a grant can outlive a failed acceptance

The membership grant is an external call that happens before the commit. If the directory does not write through the joining executor, a failure after the grant and before the commit can leave one grant for a subject that has no account. Such a subject has no credential, so the grant opens nothing, and the next acceptance of the same invitation derives the same subject and finds the grant in place. A directory that writes through the joining executor takes part in the transaction and leaves nothing behind. `MembershipDirectory.grant` is idempotent for the same tenant, subject and role for this reason.

## Why row-level security is always on

The invitations table is protected by a policy that reads the tenant the kernel publishes for each transaction, and the kernel publishes it only when row-level security is enabled for its persistence. The launcher sets that in every environment and, because a system property outranks the environment variable, an operator cannot switch it off. The policy isolates tenants only from a role that cannot step around it, which is why the service role must be neither a superuser nor `BYPASSRLS`.

## Where this does not apply

This page is about parts that write to the service's own database. A part that only reads needs no such care. It does not describe how an embedding host builds the rest of the composition, and it does not cover the transaction handling of the capabilities themselves.
