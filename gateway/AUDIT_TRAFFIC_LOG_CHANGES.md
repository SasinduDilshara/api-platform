# Audit fields in gateway traffic logs

PR description for branch `audit/traffic-log-audit-fields` (base `gateway/v2026.09.24`). Not part of the build.

Suggested labels: `behaviour-change` (or `breaking-change` if the project labels dashboard-visible changes that way), `security`.

## Summary

Each traffic-log line now carries the audit facts the gateway already computes, without request or response body capture:

- the caller identity;
- the engine's attribution of a request it ended (which policy denied it, and in which phase);
- the fault classification;
- guardrail, LLM, MCP and A2A facts;
- a per-line `eventId`, `seq` and gateway identity.

The engine also now records identity and attribution for requests that policies denied, which used to reach the access log with neither.

## Behaviour changes

Most of these are fixes, but several change what existing dashboards and consumers see. They are listed in full.

### Visible outside the new traffic-log blocks

1. **Moesif `userId` and OTel `user.id` are now set on denial events.**
   - **Before:** a request denied by a request-phase policy (for example mcp-authz 403, or a rate limit after authentication) had no `x-wso2-user-id`. Moesif reported it as `anonymous` and OTel sent no `user.id`.
   - **After:** the kernel stamps the caller identity from `SharedContext.AuthContext` on every policy short-circuit, so these events carry the authenticated user.
   - **Not affected:** requests that failed authentication (401) still have no identity.
2. **`$ctx:auth.*` and `$ctx:metadata` global properties now resolve on denial lines.** Before, they resolved to zero values there. They also resolve on lines for requests denied in a response phase.
3. **`$ctx:auth.authenticated` is now true for an authenticated layer without a subject**, for example api-key-auth (see item 6). `$ctx:auth.subject` stays `""` for such a layer.
4. **The non-deferred request-body short-circuit now carries `x-wso2-terminal-reason`.** Before, only the header-phase and deferred paths did. As a result, A2A events for a body-phase policy denial move from a failure origin derived from the status code (`client` for 4xx, `gateway` for 5xx, since the upstream was never contacted) to `failureOrigin=POLICY`. This brings them in line with header-phase and deferred denials. Success-rate dashboards that split failures by origin will shift.
5. **Response-phase policy denials (for example LLM response guardrails) now keep the earlier phases' analytics.**
   - **Before:** their `analytics_data` held only the rejecting policy's metadata. That replaced everything collected earlier: request headers, MCP/A2A facts, AI facts, and identity exported at response headers.
   - **After:** they carry all of it, plus the terminal reason, the denying policy and the caller identity. Moesif, OTel and the traffic log all see the fuller event.
6. **The analytics system policy exports identity for authenticated layers that have no subject.**
   - **Why:** api-key-auth v1.2.1, the version bundled at this tag, authenticates with `AuthType=apikey`, `TokenId` (a SHA-256 fingerprint of the key) and `Properties{ApplicationID, ApplicationName}`, but no `Subject`. API-key calls (AMP's LLM-proxy path) used to carry no identity at all.
   - **Now:** the walk still prefers the first authenticated layer that has a subject. Otherwise it falls back to the first authenticated layer with a credential id or token id.
   - **Effect:** `x-wso2-auth-type`, `-token-id`, `-properties` and `-authorized` are now present on these calls. `x-wso2-user-id` is still not invented.
7. **A policy can no longer assert the engine's attribution.**
   - **What changed:** `buildAnalyticsStruct` now emits `x-wso2-terminal-reason` and the new `x-wso2-denied-by-*` keys only from a map the kernel finished. On any other map, a policy-supplied value for these keys is dropped.
   - **Before:** a policy could set `x-wso2-terminal-reason` on a pass-through request and affect the A2A outcome.

### New traffic-log fields (additive)

All of these are omitted when empty. Each top-level block can be dropped with `exclude_fields`. An event without these facts serializes exactly as before.

| Field | Content |
|---|---|
| `eventId` | UUIDv7, unique per line |
| `seq` | Per-process counter, starts at 1 |
| `gateway` | `{id, organization, environment}` from config |
| `auth` | `subject`, `authenticated`, `type`, `issuer`, `clientId`, `tokenId`, `audience`, `scopes`, `authorized`, `claims` (only the claims named in `audit_claims`) |
| `decision` | `terminalReason`, plus `deniedBy {policy, version, phase}` when the reason is `policy_denied`. `phase` is one of `request_headers`, `request_body`, `response_headers`, `response_body`. |
| `errorType`, `error` | Fault classification |
| `guardrail` | `{hit, name}` |
| `ai` | `provider`, `providerVersion` (the provider API's version, `x-wso2-api-version`), `model`, `requestModel`, token counts, `cost` |
| `mcp` | `method`, `id`, `capability`, `name`, `resourceUri`, `sessionId`, `clientInfo`, `isError`, `errorCode`, `resultType`, `serverInfo` |
| `a2a` | The A2A dimensions |

### New config keys (`[traffic_logging]`)

| Key | Default | Meaning |
|---|---|---|
| `gateway_id`, `organization`, `environment` | `""` | Static identity labels for the `gateway` block |
| `audit_claims` | `["act"]` | Allowlist of custom auth claims emitted under `auth.claims`. `[]` emits none. |

## Security notes

- **Claims are personal data.** jwt-auth puts every non-standard claim into `AuthContext.Properties` (email, username, names, groups, ...). Only the claims listed in `audit_claims` are logged, and the default lists only `act`, the RFC 8693 delegation chain.
- **`tokenId` is now logged by default.** It is a token identifier, not the token: a JWT `jti`, or a SHA-256 fingerprint of an API key or opaque token. For basic auth it is the username. It is a stable per-credential correlator that previously had to be opted into through `$ctx:auth.token_id`. Drop it with `exclude_fields = ["auth.tokenId"]` if that is not wanted.
- **No raw token or secret is newly logged.** Header masking (`masked_headers`) is unchanged. Deployments must add custom credential headers, for example `x-amp-api-key`; the template now says so.
- **Shared metadata now reaches denial lines.** `SharedContext.Metadata` (`x-wso2-metadata`) written before a denial is carried onto the line. It can contain values a policy derived from an unauthenticated request. It is exposed only through `$ctx:metadata` properties, the same as on completed requests.
- **Engine attribution cannot be forged by a policy.** This is enforced through an unexported marker type that only the kernel can construct.

## Migration notes

- **No action needed for the default behaviour.** Existing lines gain fields only when the facts exist.
- **Line size:** log pipelines with a strict schema or size limits should expect the new top-level keys (`eventId`, `seq` and, when configured, `gateway` on every line). Use `exclude_fields` to drop any block.
- **Recovering the old claims behaviour:** operators who relied on `$ctx:auth.property` for claims can keep doing so. To get claims in `auth.claims` instead, list them in `audit_claims`.
- **Dashboards:**
  - A2A failure-origin splits shift for body-phase denials (item 4).
  - Moesif "anonymous" counts drop for authenticated-then-denied requests (item 1).
  - API-key calls now carry auth type and token fingerprint (item 6).
- **`seq` interpretation:** it counts per process, so each replica and each restart starts again at 1. A gap means a line was not delivered (encoding failure or a sink-side drop). Correlate across replicas with `eventId` or `correlationId`, not `seq`.

## Suggested split into 3 PRs

1. **Kernel attribution and the body-path reroute (behaviour change, review separately).** The non-deferred body path goes through `collectShortCircuitAnalytics` and gets a terminal reason. Engine attribution becomes authoritative and unforgeable (`x-wso2-denied-by-*`). Response-phase short-circuits carry earlier analytics and attribution.
2. **Identity on denials and subject-less layers.** Kernel identity and metadata stamping on short-circuits. The analytics system policy's `selectAuthLayer` fallback (system-policies module). The shared golden fixture `gateway/testdata/auth_analytics_golden.json`.
3. **Traffic-log publisher.** The new blocks, `eventId`/`seq`/`gateway`, `audit_claims`, the config keys, the template and the end-to-end tests.

## Tests

- **Kernel:** forged attribution, header/body/deferred/response-header/response-body/merged-response denials, one-source identity, api-key identity, and the golden fixture shared with the analytics system policy.
- **End-to-end:** real kernel output goes through an ALS entry, `analytics.Process` and the Log publisher's file sink. This covers an MCP denial, an A2A body denial (`failureOrigin=POLICY`), a response guardrail denial, and an LLM completion with a forged pass-through attribution.
- **Publisher:** every block, the claims allowlist, malformed properties, and byte-identical output for events without audit facts; `eventId` is a UUIDv7; `seq` is concurrent-safe, unique and gap-free under `-race`; the gateway block; `exclude_fields`.
- **Config:** defaults, TOML, env interpolation, the shipped template, and `audit_claims` defaults/`[]`/custom.
- **Analytics system policy:** the golden fixture and the api-key layer.

## Known limitations and follow-ups

- **Stream terminations are attributed as `response_body_stream`.** A policy that ends a response stream mid-flight (`TerminateResponseChunk`) cannot produce an ImmediateResponse, because the status line is already committed (the client may see a 2xx). The kernel now records it as `terminalReason=policy_denied` with `deniedBy{policy, version, phase: response_body_stream}`, written authoritatively like the other denials. Verified live with `content-length-guardrail` on an LLM proxy (response limit), where the client received HTTP 200 with the guardrail body. **Follow-up in gateway-controllers:** that guardrail's streaming path returns `TerminateResponseChunk{Body}` and drops the `isGuardrailHit`/`guardrailName` analytics it built, so the line has `decision` but no `guardrail` block until the policy passes `AnalyticsMetadata` through.
- **401 lines have no identity**, because authentication failed. `operation.path` and request headers on LLM streaming lines are unchanged.
- **`seq` is per process** (see the migration notes).
- **Docs and runbook (follow-up task required):** the user and configuration docs (`docs-agent-platform`) for the new blocks, `audit_claims` and the gateway identity keys need a task. So does a runbook note for consumers on `seq`, `eventId` and `decision`.
- **Performance:** each line costs one UUIDv7 and one JSON decode of the auth properties. There is no benchmark against the base tag yet (follow-up).
- **Source fix for api-key identity (separate PR in gateway-controllers):** api-key-auth should set `Subject` (the application id) and `CredentialID` so API-key calls carry a subject.
