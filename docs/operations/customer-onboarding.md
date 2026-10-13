# Customer Onboarding

Status: **Phase 10B**, 2026-10-13.

How to bring a customer's network under an installed WetechiNetMon: their
address space, their routers' flows, their detection policies, their
people and, when they want it, their mitigation. Each step ends with a
check, so you know it worked before you go on.

## First, one deployment or a shared one?

v1.0.0 keeps each customer in its own **tenant**: every incident, note,
token and mitigation belongs to one, and the API answers another
tenant's request as if the record did not exist. That isolation is
enforced by the application, not yet by the database (Phase 8; see
[known issues](../release/known-issues.md)), and a few controls, the kill
switch and the BGP peer list, are deployment-wide (FU-65).

- **One deployment per customer** when the contract needs isolation a
  database administrator cannot cross, or when the customer's own staff
  hold `noc_lead` tokens.
- **A shared deployment, one tenant each,** when your NOC operates it for
  several customers and only your staff hold lead roles.

## What to collect

| From the customer | Used for |
|---|---|
| The prefixes they want watched, and which are in which hostgroup | `WETECHINETMON_COLLECTOR_LOCAL_PREFIXES`, the detection policy's tenants |
| The routers that will export, with their source addresses | `WETECHINETMON_COLLECTOR_ALLOWED_EXPORTERS`, firewall rules |
| Each router's sampling rate | The router's own IPFIX options, or `WETECHINETMON_COLLECTOR_SAMPLING_GLOBAL_DEFAULT` |
| Normal and attack-level traffic for their busiest hosts and networks | The detection thresholds |
| Who receives alerts, and where (email, Slack, Teams, Telegram, webhook) | The notifier's channels and routes |
| The people who will use the NOC UI or the CLI, and what each may do | Tokens and roles |
| For mitigation: the prefixes you may blackhole or filter, and who approves | The guard's allowlist |

## 1. Their address space

Add the prefixes to the collector, with the tenant and an optional
hostgroup ([prefixes](../configuration/prefixes.md)):

```bash
# /etc/wetechinetmon/collector.env
WETECHINETMON_COLLECTOR_LOCAL_PREFIXES=192.0.2.0/24@acme@web,198.51.100.0/24@acme
```

and to the detection policy's `tenants`
([detection policies](../configuration/detection-policies.md)):

```json
{ "tenant": "acme", "prefixes": ["192.0.2.0/24", "198.51.100.0/24"] }
```

**Check:** the collector starts without a prefix error in its log.

## 2. Their routers

Add each router's source address to
`WETECHINETMON_COLLECTOR_ALLOWED_EXPORTERS`, open UDP 2055 to it in the
host's firewall, restart the collector, and have the customer point IPFIX
at the collector ([IPFIX collector](../integrations/ipfix-collector.md)).

**Check:** `wetechinetmon_collector_active_exporters` counts the routers,
`parsed_flow_records_total` rises, and
`datagrams_refused_total{reason="not_allowed"}` does not.

## 3. Their detection policies

Start every policy `dryRun`, with thresholds from the customer's normal
traffic: a host or network well above its busiest normal hour, not at
it. Keep `window` equal to `WETECHINETMON_COLLECTOR_DETECTION_WINDOW_SECS`,
or the collector logs that the policy is never evaluated.

**Check:** the traffic pages of the NOC UI show the customer's top hosts
and networks; after a day, no incident has opened on normal traffic.

## 4. Their alerts

Add a channel per destination and a route for the customer's tenant and
severities to the notifier's configuration
([reference](https://github.com/LogiXhare/wetechi-netmon/blob/main/crates/notification/README.md)).
Webhook, Slack, Teams and Telegram hosts must be on `allowed_hosts`;
secrets go in files, never in the JSON.

**Check:** a test incident's notification arrives, and
`wetechinetmon_notifier_notifications_total{result="delivered"}` rises.

## 5. Their people

Issue one token per person, with the least role they need
(`viewer`, `operator`, `senior_operator` or `noc_lead`), for the
customer's tenant:

```bash
wetechinetmon-api token create --tenant acme --actor-id alice --role operator \
  --days 90 --description "alice, acme NOC"
```

The token is printed once; hand it over through a secure channel.

**Check:** Alice signs in to the NOC UI and sees the customer's
incidents and no one else's.

## 6. Mitigation, if they want it

Mitigation is per prefix, in stages, and starts dry-run. Add the
customer's prefixes to the guard's allowlist for their tenant and the
actions agreed, then follow the
[mitigation installation guide](../installation/mitigation.md) from
dry-run to announcing, and agree with the customer who approves.

**Check:** a requested mitigation for one of their addresses is
approved by someone other than the requester and goes `active`, marked
dry-run, before anything is announced.

## Handover

Give the customer:

- what was configured, from the table above;
- how to reach your NOC, and what an alert from WetechiNetMon looks like;
- the [known issues](../release/known-issues.md) that matter to them.

## Offboarding

Revoke the customer's tokens (`wetechinetmon-api token revoke --token-id`), remove their routers from the allowlist and
the firewall, their prefixes from the collector, the policy and the
guard, and their routes from the notifier. Their incidents and audit
trail stay, as your retention policy decides.
