# Test Summary

Status: **v1.0.0-rc.3**, 2026-10-28.

What was tested on Tidegard 1.0.0-rc.3, from the runs themselves. Every
figure below comes from a run whose link is given; nothing is estimated.
The [production](production-checklist.md) and
[security](security-checklist.md) checklists point here for the release
candidate they are signed against.

rc.3 carries the fixes from the
[independent review](../security/security-review.md#release-candidate-review)
of rc.2.

## The release

| What | Result | Run |
|---|---|---|
| The release pipeline: tag check, native builds for x86_64 and aarch64 with Rust 1.99.1, SBOMs, signing and provenance, publication | 6 of 6 jobs passed | [40648685494](https://github.com/LogiXhare/tidegard/actions/runs/40648685494) |
| Verify and install on a clean runner: every checksum, cosign signature and attestation, the images pulled without signing in, then every service ready | Passed | the same run |
| The [release acceptance test](../architecture/decisions/0059-release-acceptance-test.md), end to end on the released tarball | Passed | [40649834768](https://github.com/LogiXhare/tidegard/actions/runs/40649834768) |
| The release acceptance test, as an anonymous user: the release downloaded and every image pulled without signing in | Passed | the same run |

The release: [v1.0.0-rc.3](https://github.com/LogiXhare/tidegard/releases/tag/v1.0.0-rc.3),
28 assets. The five images on GHCR are public since 2026-10-28.

### End to end

What the acceptance run did, on the x86_64 tarball as published,
installed with systemd:

1. flow-replay sent a 20-second IPv6 flood to `2001:db8::/32`. Ten
   incidents opened, one for each target host, and the API's top hosts,
   read from ClickHouse, listed the flood's hosts.
2. A NOC lead requested RTBH for `2001:db8::a/128`. Their own approval
   was refused with 403 `mitigation.self_approval`, though their role may
   approve; a senior operator's approval was refused with 403 too. A
   second NOC lead approved it.
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

The same test passed on rc.2, the anonymous job included, once the
images were public
([40644127314](https://github.com/LogiXhare/tidegard/actions/runs/40644127314)),
and on rc.1 ([40279512748](https://github.com/LogiXhare/tidegard/actions/runs/40279512748)).

## The pull request that made it

The rc.3 pull request (#172), on the commit the tag names. Every check
is required, and the branch had to be up to date with `main`.

| Job | Result | Tests |
|---|---|---|
| Rust: fmt, clippy, test, build, cargo-deny | Passed | 912 passed, none failed or ignored |
| Windows: build, test | Passed | 987 passed |
| PostgreSQL 15, 16, 17, 18 | Passed, each | 267 on PostgreSQL 17, the mitigator's lock test among them |
| Web UI: lint, types, tests, build, audit, licences | Passed | 21 unit tests; `npm audit` clean |
| Web end-to-end: Playwright, real API and PostgreSQL, a mitigation through GoBGP | Passed | 3 passed |
| Package, x86_64 and aarch64: tarball, systemd, images, Trivy, Compose end to end | Passed, each | |
| Upgrade from v0.9.0 and rollback | Passed | |
| Disaster recovery from an empty runner | Passed | |
| Grafana dashboards, live queries | Passed | |
| Docs: Markdown, YAML, links, MkDocs | Passed | |
| History: secret scan, DCO sign-off | Passed | |
| Fuzz: the IPFIX decoder | Passed | |

Runs: Validate [40647170143](https://github.com/LogiXhare/tidegard/actions/runs/40647170143),
Fuzz [40647170167](https://github.com/LogiXhare/tidegard/actions/runs/40647170167).

## Capacity

rc.3 changes how the collector admits exporters. The pipeline load test
ran again on that code, on a 4-vCPU runner
([40643236503](https://github.com/LogiXhare/tidegard/actions/runs/40643236503)):
200,000 flow records a second for 60 seconds with no loss and 12.4 MiB
peak memory. The figures below stand as measured, as floors and not as
promises:

- 200,000 flow records a second with no loss, 13 MiB peak memory.
- API p99 of 107 ms at worst, with 10,000 incidents and 16 clients.
- Five hours at 50,000 records a second: 899,999,914 records, no loss,
  memory +3.5%.

Details and links: [capacity planning](../operations/capacity-planning.md).

## Open before v1.0.0

- ~~The images are private~~: public since 2026-10-28, and the
  acceptance test's anonymous job passes.
- ~~The independent review of the release candidate~~: done
  2026-10-28, 40 findings, the one High fixed in rc.3
  ([security review](../security/security-review.md#release-candidate-review)).
- The owner's sign-off of both checklists.
