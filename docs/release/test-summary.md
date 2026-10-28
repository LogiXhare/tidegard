# Test Summary

Status: **v1.0.0-rc.2**, 2026-10-26.

What was tested on Tidegard 1.0.0-rc.2, from the runs themselves. Every
figure below comes from a run whose link is given; nothing is estimated.
The [production](production-checklist.md) and
[security](security-checklist.md) checklists point here for the release
candidate they are signed against.

## The release

| What | Result | Run |
|---|---|---|
| The release pipeline: tag check, native builds for x86_64 and aarch64, SBOMs, signing and provenance, publication | 7 of 7 jobs passed | [40282065957](https://github.com/LogiXhare/tidegard/actions/runs/40282065957) |
| Verify and install on a clean runner: every checksum, cosign signature and attestation, then every service ready | Passed | the same run |
| The [release acceptance test](../architecture/decisions/0059-release-acceptance-test.md), end to end on the released tarball | Passed | [40309807295](https://github.com/LogiXhare/tidegard/actions/runs/40309807295) |
| The release acceptance test, as an anonymous user | **Failed**: the images are not public yet (see below) | the same run |

The release: [v1.0.0-rc.2](https://github.com/LogiXhare/tidegard/releases/tag/v1.0.0-rc.2),
28 assets.

### End to end

What the acceptance run did, on the x86_64 tarball as published,
installed with systemd:

1. flow-replay sent a 20-second IPv6 flood to `2001:db8::/32`. Ten
   incidents opened, one for each target host, and the API's top hosts,
   read from ClickHouse, listed the flood's hosts.
2. A senior operator requested RTBH for `2001:db8::a/128`. Their own
   approval was refused with 403. A NOC lead approved it.
3. The mitigation became `active`, and the lab's edge router held the
   route:

   ```text
   *> 2001:db8::a/128  2001:db8:ffff::1  [{Origin: i} {LocalPref: 100} {Communities: blackhole, no-export} ...]
   ```

4. The withdrawal took the mitigation to `withdrawn`, and the route left
   the edge router.
5. The webhook receiver verified the HMAC of every notification:

   | Event | Received |
   |---|---|
   | `incident.opened` | 10 |
   | `mitigation.requested` | 1 |
   | `mitigation.approved` | 1 |
   | `mitigation.active` | 1 |
   | `mitigation.withdrawn` | 1 |

The same test passed on rc.1 ([40279512748](https://github.com/LogiXhare/tidegard/actions/runs/40279512748)).
Its first run there ([40279336449](https://github.com/LogiXhare/tidegard/actions/runs/40279336449))
failed on the test's own timing, which #160 fixed; the product was not
at fault.

## The pull request that made it

The rc.2 pull request (#161), on the commit the tag names. Every check
is required, and the branch had to be up to date with `main`.

| Job | Result | Tests |
|---|---|---|
| Rust: fmt, clippy, test, build, cargo-deny | Passed | 904 passed, none failed or ignored |
| Windows: build, test | Passed | 979 passed |
| PostgreSQL 15, 16, 17, 18 | Passed, each | 264 on PostgreSQL 17 |
| Web UI: lint, types, tests, build, audit, licences | Passed | 21 unit tests; `npm audit` clean |
| Web end-to-end: Playwright, real API and PostgreSQL, a mitigation through GoBGP | Passed | 3 passed |
| Package, x86_64 and aarch64: tarball, systemd, images, Trivy, Compose end to end | Passed, each | |
| Upgrade from v0.9.0 and rollback | Passed | |
| Disaster recovery from an empty runner | Passed | |
| Grafana dashboards, live queries | Passed | |
| Docs: Markdown, YAML, links, MkDocs | Passed | |
| History: secret scan, DCO sign-off | Passed | |
| Fuzz: the IPFIX decoder | Passed | |

Runs: Validate [40281208411](https://github.com/LogiXhare/tidegard/actions/runs/40281208411),
Fuzz [40281208421](https://github.com/LogiXhare/tidegard/actions/runs/40281208421).

## Capacity

rc.2 changes no code on the flow path since these runs. They stand as
measured, on a 4-vCPU runner, as floors and not as promises:

- 200,000 flow records a second with no loss, 13 MiB peak memory.
- API p99 of 107 ms at worst, with 10,000 incidents and 16 clients.
- Five hours at 50,000 records a second: 899,999,914 records, no loss,
  memory +3.5%.

Details and links: [capacity planning](../operations/capacity-planning.md).

## Open before v1.0.0

- **The images are private.** No one can pull them without signing in
  to GHCR, so the [quick start](../quick-start.md) fails for anyone but
  the owner. The owner makes each of the five packages public in the
  GitHub web interface. This cannot be undone, and BQ-16 already decided
  it for v1.0.0. The acceptance test's anonymous job then passes.
- ~~The independent review of the release candidate~~: done
  2026-10-28, 40 findings, the one High fixed
  ([security review](../security/security-review.md#release-candidate-review)).
  Release candidate 1.0.0-rc.3 carries the fixes and is tested again.
- The owner's sign-off of both checklists.
