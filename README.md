# Microsoft Defender XDR - Advanced Hunting Query Packs

Four Microsoft Defender portal packs (**phishing, identity, cloud, malware**) plus a
CrowdStrike Falcon process-investigation pack in CQL. Every query is self-contained: paste one
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
short-circuits and the filter applies. Each pack has a `00_variables_reference.kql`
listing the full variable set for that alert type - copy it, do not run it.

## Conventions

* `Timestamp between (LookbackStart .. LookbackEnd)` is always the first filter -
  the tables are time-partitioned, so this is what keeps scans cheap.
* Entity filters go before joins and `summarize`; aggregates are computed before
  cross-table joins wherever possible.
* Hard result caps (`take 100 / 500 / 1000`) prevent a wide window from
  flooding the portal.
* Thresholds are `let` variables, not magic numbers, so you can tune per tenant.

## Packs

### Phishing - `01-phishing/`

email-borne attacks: message triage, campaign scope, click telemetry.

| File | Query |
| --- | --- |
| `P01_message_triage_by_networkmessageid.kql` | Full message triage by NetworkMessageId |
| `P02_search_by_subject_sender_recipient.kql` | Campaign discovery by subject / sender / recipient attributes |
| `P03_attachment_scope_and_endpoint_landing.kql` | Attachment scope + endpoint landing (email -> device) |
| `P04_click_telemetry_for_urls.kql` | Who clicked - UrlClickEvents joined back to the message |
| `P05_cluster_expansion.kql` | Expand a campaign cluster (EmailClusterId) |
| `P06_post_delivery_actions_and_current_state.kql` | Post-delivery actions (ZAP / purge) and current mailbox state |
| `P07_authentication_and_spoof_signals.kql` | Authentication failures, envelope/header mismatch, first contact |
| `P08_sender_infrastructure_reuse.kql` | Sender infrastructure reuse (same IP / Mail-From domain, many messages) |
| `P09_alert_driven_phishing_pivot.kql` | Alert-driven pivot: phishing alerts -> message -> recipients |
| `P10_impacted_users_remediation_list.kql` | Impacted users - clicks and delivery scoped by ANY selector (OR logic) |
| `P11_lookalike_and_similar_domains.kql` | Lookalike / cousin domains for a brand or partner domain |
| `P12_campaign_scope_messages.kql` | Campaign scope at message level (same OR logic as P10) |

### Identity - `02-identity/`

sign-in, session/token, hybrid auth, directory changes.

| File | Query |
| --- | --- |
| `I01_account_signin_overview.kql` | Account sign-in overview (where / how / how often) |
| `I02_ip_pivot_and_spray.kql` | IP pivot: one source IP against many accounts (spray / AiTM relay) |
| `I03_session_and_token_replay.kql` | Session / token replay: one session id from many IPs or countries |
| `I04_new_country_and_new_ip.kql` | First-time country / IP for an account (30-day baseline) |
| `I05_mfa_failure_burst.kql` | MFA fatigue / repeated MFA failures |
| `I06_service_principal_signins.kql` | Service principal / managed identity sign-ins (app compromise) |
| `I07_hybrid_logon_pivot.kql` | Hybrid / on-prem authentication pivot (IdentityLogonEvents) |
| `I08_directory_changes.kql` | Directory changes touching the account (password, groups, enable/disable) |
| `I09_directory_recon_enumeration.kql` | Directory recon: LDAP / SAMR enumeration from one account or host |
| `I10_risky_signins.kql` | Risky sign-ins and Conditional Access outcomes |
| `I11_alert_pivot_identity.kql` | Identity alert pivot (alert + evidence + source IP) |
| `I12_user_agent_reuse.kql` | Client fingerprint reuse (one UA across many accounts) |
| `I13_device_logon_pivot.kql` | Endpoint logon pivot for a user or host (DeviceLogonEvents) |
| `I14_cross_table_ip_pivot.kql` | One IP across every identity table (union pivot) |

### Cloud - `03-cloud/`

SaaS activity, OAuth consent, cloud audit/KV/storage/DNS/process, Graph.

| File | Query |
| --- | --- |
| `C01_account_activity_summary.kql` | Cloud app activity summary for an account |
| `C02_account_activity_timeline.kql` | Cloud app activity timeline (raw rows for one account) |
| `C03_mailbox_rule_and_delegation_persistence.kql` | Mailbox rule / delegation persistence (exchange online) |
| `C04_oauth_consent_and_grants.kql` | OAuth consent / permission grants enriched with app risk |
| `C05_oauth_app_inventory_risk.kql` | OAuth app inventory: unverified publishers, high privilege, stale use |
| `C06_cloud_audit_events_pivot.kql` | Cloud audit events (AWS / GCP / Azure / K8s) by IP or operation |
| `C07_key_vault_secret_access.kql` | Key Vault secret / key access and failures |
| `C08_cloud_storage_bulk_and_anonymous.kql` | Cloud storage: bulk read and anonymous access |
| `C09_cloud_dns_anomalies.kql` | Cloud workload DNS: query volume, rare responses, long-label tunnelling signal |
| `C10_cloud_process_execution.kql` | Cloud process execution with suspicious command lines |
| `C11_graph_api_audit.kql` | Microsoft Graph API audit: app, scopes, failures |
| `C12_cross_cloud_ip_pivot.kql` | One IP across every cloud table (union pivot) |

### Malware - `04-malware/`

hash/name pivots, lineage, persistence, egress, lateral movement.

| File | Query |
| --- | --- |
| `M01_hash_sweep_all_tables.kql` | Hash sweep: file, process, image-load and alert evidence |
| `M02_file_name_and_path_sweep.kql` | File name / path sweep across endpoints |
| `M03_process_lineage.kql` | Process lineage: target, its parent, children |
| `M04_network_egress.kql` | Network egress for a device, process or remote IP |
| `M05_persistence_artifacts.kql` | Persistence artifacts: run keys, services, startup folders |
| `M06_signer_and_certificate_pivot.kql` | Signer / certificate pivot (same code-signing identity elsewhere) |
| `M07_lateral_movement.kql` | Lateral movement: logon failures + SMB/RDP fan-out |
| `M08_payload_origin_pivot.kql` | Payload origin: file origin URL / IP and who else downloaded it |
| `M09_alert_evidence_by_family.kql` | Malware alert evidence by threat family |
| `M10_device_triage_summary.kql` | Device triage summary |
| `M11_remote_ip_pivot.kql` | Remote IP pivot: one destination across the estate |

### CrowdStrike Falcon - `05-crowdstrike-falcon/`

Process investigation in CQL (LogScale), not KQL. Execution prevalence, parent /
child lineage, command-line scope, and egress for one hash or one process.

| File | Query |
| --- | --- |
| `CF01_hash_prevalence.cql` | Hash scope: how many hosts, how many runs |
| `CF02_process_prevalence.cql` | How common is this process in my environment |
| `CF03_command_line_hunt.cql` | Command line hunt: who ran this, across the environment |
| `CF04_parent_distribution.cql` | What launched it: parent distribution for a hash |
| `CF05_children_of_process.cql` | Children of a process (what it spawned) |
| `CF06_parent_lookup.cql` | Parent lookup: given a process, find what started it |
| `CF07_lineage_correlate.cql` | Three-generation lineage with correlate() |
| `CF08_who_ran_it.cql` | Who ran it: user distribution for a hash |
| `CF09_rare_process_parent_pairs.cql` | Rarest process/parent pairs in the fleet (novelty sweep) |
| `CF10_hash_network_fanout.cql` | What the process talked to: DNS + IPv4 under one Falcon PID |

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
* These queries were checked against the published schema and reviewed for KQL
  syntax; they have not been executed against a live tenant, so run each one once
  with a short lookback (e.g. `ago(1h)`) before using it in anger.
