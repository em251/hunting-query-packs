# Microsoft Defender XDR - Advanced Hunting Query Packs

Four Microsoft Defender portal packs (**phishing, identity, cloud, malware**) plus a
CrowdStrike Falcon process-investigation pack in CQL. Every query is a Markdown
document: the description reads as prose, the query sits in a fenced block you
copy straight into the portal. Every query is self-contained: paste one
file into *Hunting > Advanced hunting*, edit the `let Input...` values at the top,
run.

## Grounding

Table and column names were taken from the live schema reference on
learn.microsoft.com (`defender-xdr/advanced-hunting-*-table`), fetched
**2 Nov 2026** against the schema index last updated **28 Oct 2026**. Nothing in
these packs references a column that is not in the published schema, and no
`Preview`-only tables are used.

Tables used across the packs:

`EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents`,
`UrlClickEvents`, `AlertInfo`, `AlertEvidence`,
`EntraIdSignInEvents`, `EntraIdSpnSignInEvents`, `IdentityLogonEvents`,
`IdentityDirectoryEvents`, `IdentityQueryEvents`,
`CloudAppEvents`, `CloudAuditEvents`, `CloudKeyVaultEvents`,
`CloudStorageAggregatedEvents`, `CloudDnsEvents`, `CloudProcessEvents`,
`OAuthAppInfo`, `GraphAPIAuditEvents`,
`DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`,
`DeviceImageLoadEvents`, `DeviceRegistryEvents`, `DeviceFileCertificateInfo`,
`DeviceLogonEvents`.

## How the inputs work

Every query starts with the same shape:

```kql
let LookbackStart = ago(7d);      // scan window - always bounded
let LookbackEnd   = now();
let InputAccountUpn = "";        // set this; leave "" to ignore the filter
...
| where isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn
```

`isempty()` guards mean a query still runs with nothing filled in (it returns the
whole time window instead of one entity). Once you paste a real value the guard
short-circuits and the filter applies. Each pack has a `00_variables_reference.md`
listing the full variable set for that alert type - copy it, do not run it.

## Conventions

* `Timestamp between (LookbackStart .. LookbackEnd)` is always the first filter -
  the tables are time-partitioned, so this is what keeps scans cheap.
* Entity filters go before joins and `summarize`; aggregates are computed before
  cross-table joins wherever possible.
* Hard result caps (`take 100 / 500 / 1000`) prevent a wide window from
  flooding the portal.
* **No blank lines inside a query.** The advanced hunting query box chokes on an
  empty line mid-pipeline; every fenced block here is written dense.
* Prefer a semi-join (`| where Key in (SmallSet)`) over a full `join` when you
  only need to filter, and project columns before anything that materialises
  rows (`mv-expand`, `make_set`, unions).
* Thresholds are `let` variables, not magic numbers, so you can tune per tenant.

## Packs

### Phishing - `01-phishing/`

email-borne attacks: message triage, campaign scope, click telemetry. Ordered
by how investigations actually run - blast radius first, then interaction, then
the supporting pivots.

| File | Query |
| --- | --- |
| `P01_blast_radius.md` | Blast radius: message-level campaign scope |
| `P02_click_impact.md` | Click impact: who clicked, and what they clicked |
| `P03_message_triage.md` | Message triage by NetworkMessageId |
| `P04_find_campaign.md` | Find the campaign from subject / sender / recipient |
| `P05_attachment_scope.md` | Attachment scope and endpoint landing |
| `P06_url_clicks.md` | URL clicks: who clicked this link, and was it blocked |
| `P07_cluster_expand.md` | Expand a campaign cluster |
| `P08_post_delivery.md` | Post-delivery actions and current mailbox state |
| `P09_spoof_signals.md` | Spoof and authentication failures |
| `P10_sender_infra.md` | Sender infrastructure reuse |
| `P11_alert_pivot.md` | Start from the phishing alert |
| `P12_lookalike_domains.md` | Lookalike and cousin domains |

### Identity - `02-identity/`

sign-in, session/token, hybrid auth, directory changes. Ordered session-first:
impact analysis for the session you are investigating, then on-prem / hybrid AD
attack surface, then the account and fleet-level pivots.

| File | Query |
| --- | --- |
| `I01_session_impact.md` | Session impact: every workload the session touched |
| `I02_session_timeline.md` | Session timeline: chronological replay |
| `I03_office_activity.md` | Mailbox and file activity for the account |
| `I04_token_replay.md` | Session and token replay |
| `I05_join_check.md` | Does the Entra session id resolve in cloud data |
| `I06_ad_logons.md` | On-prem and hybrid authentication |
| `I07_directory_changes.md` | Directory changes for the account |
| `I08_recon.md` | Directory recon and enumeration |
| `I09_endpoint_logons.md` | Endpoint logons for a user or host |
| `I10_signin_overview.md` | Sign-in overview for an account |
| `I11_ip_spray.md` | One IP against many accounts (spray) |
| `I12_new_country.md` | First-time country or IP for an account |
| `I13_mfa_fatigue.md` | MFA fatigue and repeated failures |
| `I14_service_principals.md` | Service principal and managed identity sign-ins |
| `I15_risky_signins.md` | Risky sign-ins and Conditional Access outcomes |
| `I16_ua_reuse.md` | User agent reuse across accounts |
| `I17_alert_pivot.md` | Start from the identity alert |
| `I18_ip_all_tables.md` | One IP across every identity table |

### Cloud - `03-cloud/`

SaaS activity, OAuth consent, cloud audit/KV/storage/DNS/process, Graph, plus
nested `RawEventData` payload work (rule parameters, per-platform principals,
first-seen attributes).

| File | Query |
| --- | --- |
| `C01_activity_summary.md` | Cloud app activity summary for an account |
| `C02_activity_timeline.md` | Cloud app activity timeline (raw rows) |
| `C03_mailbox_rules.md` | Mailbox rules and delegation |
| `C04_oauth_consent.md` | OAuth consent and permission grants |
| `C05_oauth_inventory.md` | OAuth app inventory risk |
| `C06_cloud_audit.md` | Cloud audit events by IP or operation |
| `C07_keyvault_access.md` | Key Vault secret and key access |
| `C08_storage_bulk.md` | Storage bulk read and anonymous access |
| `C09_dns_anomalies.md` | Cloud workload DNS anomalies |
| `C10_cloud_process.md` | Cloud process execution |
| `C11_graph_api.md` | Graph API audit |
| `C12_ip_all_tables.md` | One IP across every cloud table |
| `C13_user_baseline.md` | Is this normal for the user? (30-day baseline) |
| `C14_payload_keys.md` | RawEventData key explorer |
| `C15_first_seen_attrs.md` | First-time-seen attributes for a user |
| `C16_rule_parameters.md` | Mailbox rule parameter pivot |

### Malware - `04-malware/`

hash/name pivots, lineage, persistence, egress, lateral movement.

| File | Query |
| --- | --- |
| `M01_hash_sweep.md` | Hash sweep across file, process, image and alerts |
| `M02_file_sweep.md` | File name and path sweep |
| `M03_process_lineage.md` | Process lineage from hash, name or command line |
| `M04_egress.md` | Network egress for a device or process |
| `M05_persistence.md` | Persistence artifacts |
| `M06_signing_cert.md` | Signer and certificate pivot |
| `M07_lateral_movement.md` | Lateral movement |
| `M08_payload_origin.md` | Payload origin and sibling downloads |
| `M09_family_scope.md` | Alert evidence by threat family |
| `M10_device_triage.md` | Device triage summary |
| `M11_remote_ip.md` | One destination across the estate |

### Cloud v2 - `03-cloud/v2/`

IR-workflow layer on the same tables: enumerate actions per account or per object,
pivot action x actor, replay a user's timeline against an object, answer "has this
been seen before" against a 30-day baseline, and triage the classic cloud alert
(new IP/ISP/UA, storage key read, blob activity) end to end.

| File | Query |
| --- | --- |
| `V01_object_actions.md` | Everything done to one object |
| `V02_actor_actions.md` | What this account did, and to which objects |
| `V03_action_by_actor.md` | Who else did this action |
| `V04_user_object_timeline.md` | Timeline: user and object |
| `V05_new_action_pairs.md` | First-ever action by this account (30-day baseline) |
| `V06_new_attrs_by_ip.md` | First-time attributes from this IP |
| `V07_resource_audit.md` | Azure / AWS / GCP resource audit |
| `V08_privilege_changes.md` | Privilege and permission changes |
| `V09_app_activity.md` | App-initiated activity |
| `V10_object_shape.md` | ActivityObjects shape discovery |
| `V11_storage_keys.md` | Storage key and SAS operations |
| `V12_new_ip_isp_ua.md` | First-seen IP, ISP or user agent against a resource |
| `V13_storage_auth.md` | Storage authentication type and volume |
| `V14_control_plane.md` | Azure control-plane changes |
| `V15_ip_blast_radius.md` | Everything this IP touched |
| `V16_azure_identity_shape.md` | Azure identity payload shape (does the UPN claim resolve?) |

### CrowdStrike Falcon - `05-crowdstrike-falcon/`

Process investigation in CQL (LogScale), not KQL. Execution prevalence, parent /
child lineage, command-line scope, and egress for one hash or one process.

| File | Query |
| --- | --- |
| `CF01_hash_prevalence.md` | Hash prevalence: how many hosts, how many runs |
| `CF02_process_prevalence.md` | How common is this process |
| `CF03_command_line_hunt.md` | Command line hunt |
| `CF04_parent_distribution.md` | What launched it (parent distribution) |
| `CF05_children.md` | Children of a process |
| `CF06_parent_lookup.md` | Parent lookup |
| `CF07_lineage.md` | Three-generation lineage |
| `CF08_who_ran.md` | Who ran it (user distribution) |
| `CF09_rare_pairs.md` | Rarest process and parent pairs |
| `CF10_network_fanout.md` | What the process talked to |

CQL is a different language from KQL: `groupBy([...], function=[...])` instead of
`summarize`, `| head(n)` instead of `take`, `?param` / literal edits instead of
`let`. There is no in-query time filter - set the time picker. `00_inputs_reference.cql`
lists the six values that get edited across the pack.

Two Falcon-specific facts the queries depend on:

* `ComputerName` is populated in the Falcon console but **not** in raw FDR
  `ProcessRollup2` - CrowdStrike's own examples join `fdr_aidmaster.csv` on `aid`
  to restore it. Every query groups by both, so host counts stay correct either way.
* `ProcessRollup2` has no parent command line. It carries `ParentBaseFileName` and
  `ParentProcessId`; resolving the parent's command line needs the join in `CF06`
  (key = child's `ParentProcessId`, field = parent's `TargetProcessId`).

## Cloud pack: nested payloads (`RawEventData`)

`CloudAppEvents.RawEventData` and `CloudAuditEvents.RawEventData` are the source
records, and the evidence usually lives inside them rather than in the typed
columns. Microsoft documents the column but not the JSON, so the paths used here
are grounded in the *source* payload schemas:

| Path | Source of truth |
| --- | --- |
| `RawEventData.Parameters` (mailbox rules) | Office 365 audit record; Microsoft's own inbox-forwarding playbook filters `RuleConfig has <address>` on it, and the names are `New-InboxRule` / `Set-Mailbox` cmdlet parameters |
| `RawEventData.userIdentity.{arn,accountId,accessKeyId,type}` | AWS CloudTrail record contents |
| `RawEventData.protoPayload.{authenticationInfo.principalEmail,methodName,status}` | GCP AuditLog |
| `RawEventData.identity.claims`, `properties.eventName` | Azure Activity Log schema |
| `RawEventData.user.username`, `verb`, `responseStatus` | Kubernetes audit event |
| `RawEventData.AppAccessContext.AADSessionId` | Office 365 audit schema - "The Microsoft Entra SessionId of the Entra sign-in that was performed by the app on behalf of the user". This is the only way to tie Office activity to an Entra session |
| `RawEventData.SessionId` / `CorrelationId` | Office 365 audit schema - workload-level ids, distinct from the Entra ones above |
| `ActivityObjects` | No published inner schema. Treated as opaque text (`tostring(...) has ...`) and never dereferenced by guessed field path; `V10` reveals the actual shape in your tenant |

Because the shape varies by connector, `C14` enumerates the keys actually
present in your tenant (`bag_keys` + sample values) before you hard-code
anything - and `C06`/`C16` coalesce across key casings rather than assuming one.

`CloudAppEvents` also carries two anomaly columns that are easy to miss:

* `UncommonForUser` - `[]` = enriched, nothing unusual; `""` = not enriched;
  populated = the attributes rare for this user.
* `LastSeenForUser` - bag of attribute -> days since last seen. **Negative means
  first time ever**; `C15` expands it into rows.

## Campaign scoping in the phishing pack (P10 / P12)

The other phishing queries pivot on one identifier. `P10` and `P12` do not - they
take every selector you fill (`NetworkMessageId`, `EmailClusterId`,
`SubjectContains`, `SenderFrom`, `SenderDomain`, `AttachmentName`,
`AttachmentSha256`, `UrlContains`, `UrlDomain`) and union the message ids each one
matches. Scope is therefore OR, not AND: "clicked anything from this sender OR
with this subject OR carrying this attachment OR containing this URL" is one
result set.

Two consequences worth knowing:

* Empty selectors contribute nothing. An unfilled `P10` returns zero rows instead
  of scanning the whole window - define a scope first (run `P02` to find one).
* Click scope is intentionally wider than delivery scope: a click is counted when
  the destination URL matches, even if that message body never matched a selector
  (`ScopeByClickedUrl` reads `UrlClickEvents` directly).

## Notes and known limits

* **ActionType values.** Microsoft publishes the columns but points at the
  in-portal schema reference for `ActionType` enumerations. These packs only
  hard-code values that are stable across tenants (`ProcessCreated`,
  `FileCreated`, `LogonSuccess`, `ConnectionSuccess`, `ImageLoaded`,
  `ClickAllowed`) and put anything tenant- or workload-specific into an editable
  `dynamic([...])` list (`MailboxPersistenceActions`, `ConsentActions`,
  `SuspiciousPatterns`) so you can extend it without touching the logic.
* **SHA256 is frequently empty** on `DeviceFileEvents` / `DeviceEvents`. Every
  malware query accepts `InputSha1` as an equal citizen - use SHA1 as the primary
  pivot when SHA256 returns nothing.
* **`CloudAppEvents` has no `AccountUpn`.** The actor is `AccountId` (usually the
  UPN) plus `AccountObjectId`. Queries use `AccountId` and match
  `AccountDisplayName` as a fallback.
* **`CloudAuditEvents` has no actor column at all** - the principal lives inside
  `RawEventData` and its shape differs per platform (AWS, GCP, Azure, K8s). The
  packs keep `RawEventData` intact rather than dereferencing a path that would
  break on other platforms; `C06` shows one optional `UserIdentity.Arn` deref.
* **`EntraIdSignInEvents`** is the current sign-in table. The older
  `AADSignInEventsBeta` table is not used anywhere in these packs.
* **Alert-driven queries** filter evidence on `isnotempty(NetworkMessageId)` /
  `isnotempty(AccountUpn)` rather than guessing `EntityType` strings, which vary
  by alert family.
## File format

Each query is a `.md` file:

```
# P01 — Blast radius: message-level campaign scope

**Pack:** Phishing  ·  **Tables:** ...  ·  **Inputs:** ...

Why the query exists and how to read it.

```kql
<the query>
```
```

Fenced blocks keep the `|` pipeline operators from being parsed as Markdown
tables, and the validator extracts the fence and parses it with Microsoft's KQL
parser — so the docs and the validated artifact are the same file.

## Validation

All 49 queries are parsed and bound with Microsoft's own KQL parser
(`Microsoft.Azure.Kusto.Language` 12.4.1) against a schema of 32 Defender XDR
tables / 1,016 columns scraped from the published reference. Every query passes
parse + semantic analysis: no unknown table, no unknown column, no type mismatch.

Four defects that this caught and a documentation review did not:

| Query | Defect |
| --- | --- |
| `M05_persistence.md` | single backslashes in registry paths (`"\CurrentVersion\Run"`) - KQL rejects the unknown escape; now doubled |
| `C04_oauth_consent.md` | `CloudAppEvents.ApplicationId` is `int`, so `=~` against a string input fails; wrapped in `tostring()` |
| `I09_endpoint_logons.md` | `DeviceLogonEvents` has no `AccountUpn` - it carries `AccountName` / `AccountDomain`; regrouped |
| `M07_lateral_movement.md` | same, in the logon branch of the lateral-movement union |

What this does **not** prove: that a query returns useful rows. Parsing shows the
query compiles and every column exists; it says nothing about thresholds or data
volume. Run each once with a short lookback (e.g. `ago(1h)`) before using it in
anger.
