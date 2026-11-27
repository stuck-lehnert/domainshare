# Agent API

[Back to DomainShare](../README.md)

The Agent API offers read-only file access over HTTPS. A token identifies the agent; the mandatory `username` query parameter selects the AD user whose current access applies. Browser sessions cannot access the Agent API, and agent tokens cannot sign in to the web UI or use administrative APIs.

## Issue and revoke tokens

In the administration console, open **Agenten-Tokens**. Give the token a name, explicitly list up to ten AD usernames, and set its validity period (1–365 days, 30 by default). Copy the bearer token when it appears; it cannot be retrieved later. The server stores only its hash. Issue separate tokens for separate agents and revoke them from the same screen when no longer needed. Tokens persist across restarts but are not part of DomainShare backups. Reissue them after restoring to a new installation.

Use an AD sign-in name: `alice`, `EXAMPLE\alice`, `alice@example.test`, or the account's assigned UPN such as `alice.smith@people.example.test`. An email address works only if it is also a valid AD sign-in name. DomainShare resolves the name in the configured AD domain and checks the resulting SID on every request. An account recreated with the same name does not inherit a token. An admin account, if explicitly allowed on the token, has the same read access to active Data folders as in the web portal. No account can browse another user's Private folder through this API. FSLogix, archived folders and trash are not exposed.

## Requests

Send `Authorization: Bearer <token>` and exactly one nonempty `username` on each request. Never pass the token in the URL. Authenticate to the server with a trusted HTTPS certificate; avoid disabling certificate validation. All paths below are relative to `/api/agent/v1` and use `GET`.

| Path | Additional parameters | Result |
| --- | --- | --- |
| `/search` | `q`, optional `scope` (`all`, `name`, `content`), `source`, `type`, `sort`, `limit`, `cursor` | The same filename and full-text search as the portal. Pass `nextCursor` as `cursor` with the same filters for the next page. |
| `/list` | None | Accessible roots, each with an `id`, `label` and `kind`. |
| `/list` | `source` (root ID), optional `path` (relative to root), `limit` (1–200, default 100), `after` | Live directory entries in filename order. Pass `nextAfter` as `after` to continue. Entries include relative `path`, `type`, size and modification time. |
| `/file` | `source`, `path` | Original file from a directory listing, even if not yet indexed. Supports byte ranges. |
| `/documents/{id}` | None | Metadata and available extracted text for an indexed result. |
| `/documents/{id}/download` | None | Original file for an indexed result. |
| `/documents/{id}/preview` | None | Indexed image preview, if available. |
| `/documents/{id}/content` | None | Original PDF content with byte-range support. |

For example:

```sh
curl --get 'https://files.example.org/api/agent/v1/search' \
  --header "Authorization: Bearer $DOMAINSHARE_TOKEN" \
  --data-urlencode 'username=alice' \
  --data-urlencode 'q=quarterly forecast'
```

An invalid, expired or revoked token returns `401`. A missing, duplicated or malformed username returns `400`. A user outside the token's scope or no longer eligible for access returns `403`. Missing or inaccessible paths and document IDs return `404`. If DomainShare cannot verify access because AD is unavailable, it does not return file data.
