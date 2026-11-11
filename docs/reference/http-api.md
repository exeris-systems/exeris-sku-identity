---
title: "HTTP API reference"
type: reference
visibility: public
owning-repo: exeris-sku-identity
status: active
last-verified: 2026-11-11
---

# HTTP API reference

Request and response shapes, statuses and token claims of the routes the service registers. The routes and the access each one requires are listed in the [README](../../README.md#what-it-provides). Settings that change these behaviours are in the [configuration reference](configuration.md).

## Requests and errors

Error bodies carry a fixed code and never exception text. JSON request bodies are limited to 16 KiB, with unknown and duplicate fields refused.

## Access token claims

Access tokens are EdDSA (Ed25519). Every token carries `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti` and `sid`, the session it belongs to. `tid`, `roles` and `scope` appear only when the subject has exactly one membership of a role the service may issue: `tid` is that tenant, `roles` holds its role, and `scope` is present for `owner` and `admin` only, carrying `invitations:write`. A subject with no membership, with several, or only in the host's platform role gets a token without the three, and a token without `tid` is tenant-less. Its lifetime is `EXERIS_TOKEN_ISSUER_TOKEN_TTL`, 15 minutes unless set.

## Sign in and refresh

Bodies are JSON with `Content-Type: application/json`, at most 16 KiB, and carry only the fields named here. Every refusal has the body `{"error": "<code>"}`.

| Route | Request | Success, 200 |
| --- | --- | --- |
| `POST /api/v1/auth/login` | `email` (at most 254 characters), `password` (1 to 1024 characters) | `tokenType`, `accessToken`, `expiresAt` (the access token's end), `refreshToken`, `refreshExpiresAt`, `sessionId` |
| `POST /api/v1/auth/login`, account with a second factor | as above | `mfaRequired: true`, `challengeToken`, `expiresAt`; the session follows from `/mfa/verify` |
| `POST /api/v1/auth/refresh` | `refreshToken` (at most 512 characters) | the same fields as a login, with the successor refresh token |

| Status and `error` | Meaning |
| --- | --- |
| 400 `invalid_request` | no body, not a JSON object, a missing or over-long field, or a field the route does not name |
| 413 `request_too_large` | the body exceeds 16 KiB |
| 415 `unsupported_media_type` | the `Content-Type` is not `application/json` |
| 401 `invalid_credentials` | login: wrong password, unknown address or locked account, not told apart |
| 403 `account_unverified` | login: the password is right and the mailbox is not verified |
| 401 `invalid_refresh_token` | refresh: the token is unknown, used, revoked or expired; a used one also revokes its session |
| 429 | the route's rate-limit group is exhausted for that client |

`expiresAt` and `refreshExpiresAt` are ISO-8601 instants. There is no logout route: `POST /api/v1/auth/sessions/revoke` with `{"sessionId": "<uuid>"}` ends one of the caller's sessions and answers `{"revoked": 1}`, or 404 `not_found`; `/sessions/revoke-all` takes no body and answers `{"revoked": <count>}`. Both need `Authorization: Bearer <accessToken>`, and revoking stops refresh only.

## Invitations

Issuing an invitation stores it and hands its single-use token to the host's `InvitationDelivery`, in one transaction; the response carries `{invitationId, tenantId, email, role, expiresAt}` and never the token. If the delivery fails nothing is stored, and with no delivery configured issuing answers 503.

Accepting an invitation creates a verified account, because the token reached only the invitee's mailbox, and grants the membership in the invitation's tenant. The body is `{tenantId, token, email, password}`. The invitation is consumed, the account created and the membership granted in one transaction, and the response is sent after the commit; a failure part-way leaves no account and the invitation pending.

## Where this does not apply

This page does not describe the body of a rate-limited response: the rate-limiting capability produces it, and only the 429 status is stated here. It does not cover routes an embedding host adds through a `RouteContributor`. Of the routes in the README table it gives no request or response shape for `GET /health`, `GET /.well-known/jwks.json`, `POST /api/v1/auth/mfa/verify` (named only as the route that completes a login with a second factor), `POST /api/v1/auth/password/reset-request`, `/password/reset`, `/verification/send`, `/verification/verify` and `/password/change`, `POST /api/v1/auth/mfa/totp/enrollment`, `/mfa/totp/enrollment/confirm` and `/mfa/recovery-codes`, and `GET /api/v1/auth/sessions`. The `OPTIONS` preflight routes that exist for each path when `EXERIS_CORS_ALLOWED_ORIGINS` lists origins are not described either.
