# 0056. Phase 9D Bounds on What the Collector Remembers

Status: **Accepted**
Date: 2026-10-13
Deciders: Repository owner (Phases 9 and 10 plan, 2026-10-12); the
details under the delegation of 2026-10-05 to industry practice

## Context

The collector listens on UDP, which carries no authentication: anyone
who can reach the flow port can send it datagrams with any source
address. The 9D review of that input found three ways a sender could
make the collector grow its memory without bound:

- **Exporters.** The collector kept one state, with its own template
  cache, for every source address and port it ever heard from, and never
  forgot one. Datagrams from spoofed sources each added a state.
- **Templates.** One exporter could define every template ID from 256
  to 65,535, each with thousands of fields: gigabytes from one source.
- **A field count with no fields behind it.** A template record that
  claimed 65,535 fields reserved room for all of them before reading
  any, about 768 KiB per record, even when the record held a few bytes.

The review also found that exporters were keyed by socket address
alone. RFC 7011 scopes template IDs and sequence numbers to an
observation domain, so an exporter sending several domains from one
socket saw each domain's sequence numbers as restarts of the others,
and its templates collide.

The first finding of 9D, a template of zero-length records that made
the decoder loop without end, was the same kind of problem: the input
decides how much the collector allocates.

## Decision

Bound everything the collector keeps per sender, and let the operator
say who the senders are.

- **The exporter is (source address, observation domain).** Each pair
  gets its own template cache and sequence tracking.
- **`TIDEGARD_COLLECTOR_ALLOWED_EXPORTERS`**: a comma-separated
  list of networks or addresses. A datagram from anywhere else is
  dropped before its header is parsed. Unset accepts any source, as
  before, and the collector warns at startup that it does. A network
  with host bits set (`192.0.2.1/24`) is refused at startup, as a typo.
- **`TIDEGARD_COLLECTOR_MAX_EXPORTERS`** (default 1,000): past it,
  a datagram from a new exporter is dropped; exporters already tracked
  carry on. It must be at least 1.
- **`TIDEGARD_COLLECTOR_EXPORTER_IDLE_SECS`** (default 3,600): an
  exporter silent this long is forgotten with its templates, swept every
  30 seconds with the aggregation entries. An hour is well past any
  router's template refresh, so a live exporter is never forgotten.
- **Each template cache holds at most 512 templates and 8,192 field
  specifiers** (`MAX_TEMPLATES`, `MAX_TEMPLATE_FIELDS` in
  `tidegard-protocol-ipfix`). A message defining a template past
  either limit is refused as malformed, and the cache keeps what it had.
  A router defines tens of templates with a few hundred fields in all.
- **A template record reserves at most what its bytes can hold**: four
  per field specifier.
- **`tidegard_collector_datagrams_refused_total{reason}`** counts
  the drops, with two fixed reasons: `not_allowed` and `exporter_limit`.

Together these bound the collector's template memory at about 128 KiB
per exporter, and 125 MiB across the default 1,000 exporters, whatever
is sent to it.

## Consequences

- An operator who sets the allowlist makes spoofed flows from outside it
  cost one address comparison each. The shipped `collector.env` sets
  it, to the documentation range its other examples use.
- A spoofed source inside an allowed network still reaches the decoder,
  within the bounds above. The flow port should also be firewalled to
  the routers; this is defence in depth, not a replacement.
- An exporter with more than 512 templates, or more than 8,192 fields in
  all, loses its messages that define more, logged and counted as parser
  failures. No router we know of comes close. The limits are constants;
  making them settings waits for an exporter that needs it.
- A deployment with more than 1,000 exporter and domain pairs must raise
  `TIDEGARD_COLLECTOR_MAX_EXPORTERS`, and the refusal counter says
  so.

## Alternatives considered

- **Refusing every source by default.** Safer, but every upgrade from
  v0.9.0 would stop collecting until configured. A warning at startup
  and the shipped example get the same result without breaking a
  running collector.
- **Evicting the least recently seen exporter when full**, rather than
  refusing the new one. It lets a flood of spoofed sources push the real
  routers out, which is the attack this guards against.
- **Authenticating flows.** IPFIX over UDP has no authentication; DTLS
  and TLS transports exist in RFC 7011 but few routers implement them.
