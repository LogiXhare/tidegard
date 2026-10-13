# API Reference

Status: **Milestone 5D, in progress.** The incident REST API
(`tidegard-api`, in `apps/api`) serves liveness and readiness. The
incident endpoints are being built on it.

- [OpenAPI document](openapi.json): generated from the handlers and
  committed. A test fails if it differs from the code
  ([ADR 0037](../architecture/decisions/0037-phase5d-http-framework-and-openapi.md)).
- [Error codes](error-codes.md): every `error` the API returns, with its
  status. Errors are RFC 9457 problem details
  ([ADR 0038](../architecture/decisions/0038-phase5d-api-boundary.md)).
- [Incident API plan](incident-api-plan.md): the endpoint-by-endpoint
  design the implementation follows.

See [../functional-requirements.md](../functional-requirements.md) (FR-8)
for the wider planned resource surface.
