# 0059. The Release Acceptance Test

Status: **Accepted**
Date: 2026-10-26
Deciders: Repository owner (2026-10-26: asked for a live test that
everything works before v1.0.0), the details under the delegation of
2026-10-05 to industry practice

## Context

CI tests every part of Tidegard on each pull request, but each from
source and each on its own: the Compose stack takes synthetic flows to an
incident with mitigation in dry run, the UI test takes one mitigation
through GoBGP, and the two-speaker lab proves a route reaches an edge
router. The release pipeline's last job installs the published tarball
and checks that every service starts.

Nothing ran the whole chain on what an operator downloads. The GHCR
images of 1.0.0-rc.1 were private, so no one could pull them without
signing in, and no check failed: the verify job signs in to GHCR before
it pulls.

A pilot on a live network stays outside v1.0.0 (BQ-18). The test has to
use a lab and synthetic traffic only.

## Decision

`.github/workflows/acceptance.yml` tests a published release by its tag,
run by hand once the release exists. It has two jobs:

1. **As an anonymous user:** without a token, download `SHA256SUMS` from
   the release and pull every image. A failure names the packages that
   are not public.
2. **End to end on the released tarball:** install the x86_64 tarball as
   the release ships it, with systemd, a throwaway PostgreSQL, and
   ClickHouse on loopback. Then:
   - flow-replay sends an IPv6 flood to `2001:db8::/32`, which must
     become an incident and appear in the API's top hosts from ClickHouse;
   - a senior operator requests RTBH for the incident's host; their own
     approval is refused with 403, and a NOC lead approves;
   - the mitigation becomes active, and the lab's edge gobgpd holds the
     `/128` with the blackhole community;
   - the withdrawal removes the route from the edge;
   - a webhook receiver gets `incident.opened` and every mitigation step,
     and each body's HMAC signature verifies.

The product comes from the release and is never built. Only the test
tools are built or fetched from the tag's source: flow-replay, and the
two-speaker GoBGP lab of ADR 0051, pinned by version and SHA-256. Every
address is a documentation prefix, every BGP speaker listens on
loopback, and the guard allows only `2001:db8::/48`.

A release candidate is good when the release pipeline and this test both
pass on it unchanged.

## Consequences

- The test summary of a release cites its acceptance run beside the
  pipeline's.
- The anonymous job fails until the owner makes the GHCR packages public,
  which only the GitHub web interface can do. A package made public stays
  public.
- The run takes about ten minutes on a free runner and needs no secret.

## Alternatives considered

- **A lab virtual machine run by hand.** It tests real hardware, but no
  one can repeat it exactly and it leaves no record in the repository.
  It stays open to the owner after v1.0.0, as part of a pilot.
- **Adding the chain to the release pipeline's verify job.** That job
  runs inside the release, before anyone has looked at it. Keeping the
  acceptance test separate lets it run again on any tag, and lets the
  anonymous pull fail without failing the publish.
