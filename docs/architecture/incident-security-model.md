# Incident Security Model

Status: **Planning only.** Part of the
[Phase 5 plan](phase5-incident-management-plan.md). Concurrency and
idempotency decisions in
[ADR 0016](decisions/0016-incident-concurrency-and-idempotency.md).
Threats in [the threat model](../security/incident-threat-model.md).

## Tenant isolation

Phase 5 is designed **tenant-aware even though the first deployment is
single-tenant**. This is not speculative generality: R12 in the
[risk register](../risk-register.md) already records that retrofitting
tenancy is a re-architecture, and NFR-3 requires tenant scoping as a
first-class schema dimension from early phases. Phase 8 adds enforcement;
Phase 5 must not make Phase 8 impossible.

Three layers, in order of reliability:

1. **Schema.** `tenant_id` on every table, never inferred from a join.
2. **Repository.** The tenant context is a constructor argument, so a
   query with no tenant predicate cannot be written. This is the layer
   that must not be skipped: an application-level `WHERE tenant_id = $1`
   that a developer can forget is not isolation, it is a convention.
3. **Database roles (Phase 8).** Row-Level Security, evaluated but not
   implemented here. The schema is shaped so it can be enabled without
   migration.

**A valid ID from another tenant returns `404`, never `403`.** A `403`
confirms the resource exists, which turns any ID into an existence
oracle. This applies to every endpoint including audit reads.

Concealment is not authorization, and it is worth being blunt that the
`404` is a *second* line. The first is that the query never selected the
row: the tenant predicate is applied in the repository, so a cross-tenant
read finds nothing rather than finding something and then hiding it. If
the status code were the only control, a single handler that forgot to
check would leak the body.

For that concealment to hold, five things follow, and each is a test:

| Surface | Rule |
|---|---|
| Single fetch | Another tenant's id is indistinguishable from a nonexistent id |
| **Incident number lookup** | `WNM-2026-000123` resolves within the caller's tenant only, and follows the same rule — numbers are per-tenant, so the same string may exist in two tenants and must resolve to at most the caller's |
| **List and search** | Filters are applied *after* the tenant predicate, never before, so a count or a page total can never include another tenant's rows |
| **Export** | Runs through the same tenant-scoped repository as the API; there is no separate export query path to forget the predicate |
| **Cursors** | Signed and carrying the tenant; a cursor from another tenant is rejected, not honoured |

**Timing.** A cross-tenant lookup and a genuinely-absent lookup should
take indistinguishable time. Both resolve to the same tenant-scoped query
returning no rows, so they are naturally similar; the case to avoid is an
implementation that checks existence first and *then* authorizes, which
is both slower and observable. Perfect timing equivalence is not claimed
— it is not achievable against a determined attacker with a database
underneath — and the residual is accepted and recorded under T-04.

**Platform roles** may legitimately need to distinguish absence across
tenants, for support. That is a distinct permission
(`platform.incident.read_all`), never implicit, and every such read is
audited with the tenant that was crossed.

Cross-tenant assignment is refused: the assignee must belong to the
incident's tenant, or to a platform-level team explicitly permitted to
work across tenants. Platform roles are distinct from tenant roles and
are never granted implicitly.

## Permissions

Permissions, not roles. Roles are bundles that differ per deployment;
permissions are what the code checks.

| Permission | Grants |
|---|---|
| `incident.read` | Read one incident |
| `incident.list` | List and search within a tenant |
| `incident.create` | Open an incident by hand ([ADR 0039](decisions/0039-phase5d-manual-incidents.md)) |
| `incident.update` | Title, description, tags |
| `incident.acknowledge` | Acknowledge |
| `incident.assign` | Assign, reassign, unassign, claim, release |
| `incident.investigate` | Begin investigation, mark monitoring |
| `incident.note.create` | Add internal notes, and edit your own |
| `incident.note.redact` | Remove any note's body, with a reason |
| `incident.note.customer_visible` | Mark a note customer-visible — **refused in Phase 5** |
| `incident.severity.change` | Change severity |
| `incident.priority.change` | Change priority |
| `incident.resolve` | Resolve |
| `incident.close` | Close |
| `incident.reopen` | Reopen |
| `incident.suppress` | Suppress and unsuppress |
| `incident.export` | Export |
| `incident.audit.read` | Read the audit trail |
| `incident.config.read` | Read effective-configuration diagnostics |
| `incident.closure_policy.override` | Disable critical manual closure for a tenant or policy |
| `platform.incident.read_all` | Cross-tenant read — platform only |
| `platform.incident.admin` | Cross-tenant administration — platform only |
| `incident.notification.record` | Record a notification's outcome on the timeline — the notifier only, never a human role ([ADR 0045](decisions/0045-phase6e-notification-delivery.md)) |
| `traffic.read` | Read deployment-wide traffic, from the one traffic tenant only ([ADR 0042](decisions/0042-phase6b-traffic-read-api.md)) |
| `mitigation.read` | Read mitigations ([ADR 0046](decisions/0046-phase7a-mitigation-record.md)) |
| `mitigation.request` | Ask for a mitigation; nothing is announced until it is approved |
| `mitigation.approve` | Approve or reject a mitigation; not your own unless the deployment allows it |
| `mitigation.withdraw` | Take an approved mitigation down |
| `mitigation.propose` | Propose a mitigation for an incident — the mitigator only, never a human role |
| `mitigation.execute` | Announce, withdraw and end mitigations — the mitigator only, never a human role |
| `mitigation.kill_switch.engage` | Turn on the deployment-wide kill switch ([ADR 0049](decisions/0049-phase7d-mitigator-service.md)) |
| `mitigation.kill_switch.release` | Turn it off again — platform administrators only, and no API token carries it: `tidegard-api kill-switch release` on the host ([ADR 0050](decisions/0050-phase7e-mitigation-api-cli-ui.md)) |

| `platform.tenant.admin` | Register, suspend and reactivate tenants, and their prefixes — platform only ([ADR 0060](decisions/0060-phase8a-tenant-registry.md)) |
| `tenant.token.admin` | Issue and revoke the API tokens of the tenant acted in |

Suggested bundles, deployment-configurable. The first seven are tenant
roles; the last five are the provider roles of FR-12.2, which act across
tenants (BQ-21) and are held only by platform-scoped principals:

| Role | Permissions |
|---|---|
| `viewer` | read, list, traffic.read, mitigation.read |
| `operator` | viewer + acknowledge, assign, investigate, note.create |
| `senior_operator` | operator + severity.change, priority.change, resolve, close, reopen, create, mitigation.request, mitigation.withdraw |
| `noc_lead` | senior_operator + suppress, export, audit.read, config.read, update, note.redact, mitigation.approve, mitigation.kill_switch.engage |
| `customer_admin` | noc_lead + tenant.token.admin |
| `security_analyst` | viewer + note.create, export, audit.read |
| `automation` | viewer + create, acknowledge, note.create — for service accounts |
| `noc_operator` | senior_operator + platform.incident.read_all |
| `noc_admin` | noc_lead + platform.incident.read_all |
| `auditor` | viewer + audit.read, config.read, platform.incident.read_all |
| `platform_admin` | auditor + platform.incident.admin, platform.tenant.admin, tenant.token.admin, mitigation.kill_switch.release — no incident write |
| `super_admin` | every human permission, including closure_policy.override and note.customer_visible |

`incident.closure_policy.override` appears in **no** default bundle but
`super_admin`'s, not even `noc_lead` or `noc_admin`. Turning off manual closure for critical incidents is the
single most useful configuration change for an attacker who already has a
foothold — it makes criticals close themselves — so it is granted
deliberately or not at all.

### Service accounts are not operators

The detection-ingestion service account gets exactly one permission:
`incident.ingest`, which is not in the operator table above and cannot be
granted to a human role. It may create and update incidents through
correlation. It may **not** acknowledge, assign, resolve, close, or note.

The reasoning is that an ingestion credential is the most likely one to
leak — it lives in configuration on a long-running service — and it must
not be able to close incidents. A compromised ingestion credential should
be able to create noise, not to hide an attack by resolving the incidents
that report it.

Correspondingly: read-only users may not mutate; `severity.change` is
separate from `update` so lowering severity is separately grantable and
separately audited; and lowering severity always requires a reason.

### Browser sessions

A browser never holds an API token. The operator signs in once with one,
and the API answers with a session cookie that lives no longer than the
token: 30 minutes idle, 12 hours in all, and revoking the token ends it
([ADR 0043](decisions/0043-phase6c-browser-sessions.md)). The id is new
at every sign-in, so a planted one is never honoured. A cookie request
that changes anything must carry the session's CSRF value, which only
the page can learn. A refusal is audited.

### Editing and redacting notes

Notes are immutable with supersession ([persistence](incident-persistence.md#incident_notes)).
An edit appends a new note that names the one it replaces; the original
stays, marked superseded, because what an operator first believed is
often what a post-mortem needs. Only a note's author may edit it.
`incident.note.create` is not enough on its own: another operator's
attempt is refused `403` and audited as a denial.

Redaction is the one change made in place. It exists for words that
must go, such as a pasted credential or personal data. It empties the
body and keeps the note, who redacted it, when, and the reason, which is
required. It needs `incident.note.redact`, held by `noc_lead` and above,
because it removes another operator's words. A superseded note can be
redacted too, since the words to remove may be in the original. The
reason goes to the audit trail, not the timeline, which more people read.

## Concurrency

Optimistic concurrency on an integer `version`, incremented on every
mutation.

A command that changes state or a safety-relevant field **must** supply
`expected_version`. If it does not match, the command fails `409` with
the current version and current state, and the client re-reads and
retries. The alternative — last-write-wins — silently discards another
operator's work, which on a bridge call at 3am means two people believe
they own an incident and one of them is wrong.

Commands requiring `expected_version`: all state transitions, severity,
priority, assignment, closure, reopen, suppress.

Commands not requiring it: adding a note (append-only, cannot conflict),
editing or redacting one (a second edit or redaction of the same note is
refused, so neither can be lost), adding a tag (set semantics), and
correlator-driven updates, which
resolve conflicts by retrying the correlation decision rather than by
overwriting.

Named races and their resolution:

| Race | Resolution |
|---|---|
| Two operators acknowledge simultaneously | First commits; second gets `409`; the timeline shows one acknowledgement |
| Assignment during closure | Version conflict; loser re-reads and sees it closed |
| Detection update during manual closure | Correlator retries; incident is closed; event links as evidence with no state change |
| Recovery event during investigation | Automatic `Recovering`; abort restores `Investigating` |
| Duplicate API command | Idempotency key returns the original result |
| Repeated CLI invocation | Same, since the CLI generates and reuses a key per logical command |
| Delayed detector event | Linked, no state change |
| Out-of-order event | Linked; peaks may rise; `last_detected_at` never moves backwards |
| Retry after network timeout | Idempotency key makes the retry safe |

Conflict responses are structured, never a bare 409:

```json
{
  "error": "incident.version_conflict",
  "message": "The incident was modified by another actor.",
  "current_version": 8,
  "expected_version": 6,
  "current_state": "resolved"
}
```

## Idempotency

Every mutating API call accepts `Idempotency-Key`. It is **required** for
state transitions and optional elsewhere.

The record stores a `request_fingerprint`: a hash of the canonicalised
request body plus the operation and resource. Behaviour on reuse:

| Case | Result |
|---|---|
| Same key, same fingerprint, completed | Replay the stored response, `200` |
| Same key, same fingerprint, in flight | `409 incident.request_in_progress` |
| **Same key, different fingerprint** | **`409 incident.idempotency_key_reuse`** |
| New key | Process normally |

The third row is the important one. Returning the *old* response for a
*different* request would silently discard the new request — the caller
believes their change was applied when it was not. Rejecting is the only
safe answer.

Idempotency keys are **not credentials**. Knowing one grants nothing:
records are scoped to `(tenant_id, idempotency_key)` and a key from
another tenant is invisible. They are also not authorization tokens and
must never be logged as if sensitive, nor accepted in place of one.

Keys expire after 24 hours. Clients must generate them randomly with at
least 128 bits of entropy; the server rejects keys shorter than 16 or
longer than 255 characters. Reuse across different operations with the
same key is rejected by the fingerprint check.

## Input handling

- Every input validated at the boundary, with unknown fields **rejected**
  rather than ignored — the same posture Phase 4 took with
  `deny_unknown_fields` on policy documents. Silently ignoring a
  misspelled field is how an operator believes they set something they
  did not.
- Note bodies are stored as **text, never rendered as HTML by the API**.
  Escaping is the responsibility of the consumer, and the API documents
  that notes are untrusted user content. Phase 6's UI must escape on
  output; the API must not attempt to sanitise on input, because
  sanitising on input destroys the operator's actual words.
- All SQL is parameterised. No string interpolation into queries, ever.
- Audit fields that come from the client — user agent especially — are
  length-capped and control characters stripped, so a crafted header
  cannot inject line breaks that make an audit log misparse.
- IDs are validated for shape before any lookup, so a malformed ID is a
  `400` and never reaches the database.

## Rate limiting and exhaustion

| Surface | Default |
|---|---|
| Mutating commands | 60 per minute per actor |
| List and search | 120 per minute per actor |
| Export | 5 per hour per tenant |
| Audit read | 30 per minute per actor |
| Ingestion | Bounded queue with backpressure, not a rate limit |

Every list endpoint has a maximum page size that the server enforces
regardless of what the client asks for, and every query has a bounded
time range. An unbounded query is a denial-of-service primitive that
costs the attacker one request.

## What is deliberately not here

Full RBAC with custom roles, SSO, Entra ID, SCIM provisioning, and
per-field authorization are **Phase 8**. Phase 5 defines the permission
*vocabulary* and the enforcement *point*, so Phase 8 replaces the
identity provider without touching the incident domain. The
`IdentityProvider` and `PermissionResolver` seams exist for exactly that.
