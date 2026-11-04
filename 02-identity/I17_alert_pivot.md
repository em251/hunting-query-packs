# I17 — Start from the identity alert

**Use when:** walk alert -> evidence -> account and source IP.
**Alert fields:** AccountUpn, IPAddress

**Pack:** Identity  
**Tables:** AlertInfo, AlertEvidence  
**Inputs:** InputAccountUpn, InputIpAddress (OPTIONAL)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Opens the alert set for an identity or cloud-app alert and keeps every row
that carries an account or an IP, so you get the entity graph the alert was
built from without trusting a specific EntityType string.

```kql
let LookbackStart = ago(14d);
let LookbackEnd   = now();
let InputAccountUpn = "";
let InputIpAddress  = "";
let IdentityAlerts =
    AlertInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where ServiceSource has_any ("Identity", "Cloud Apps")
    | project AlertId, AlertTime = Timestamp, Title, Severity, Category,
              DetectionSource, ServiceSource, AttackTechniques;
let Evidence =
    AlertEvidence
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(AccountUpn) or isnotempty(RemoteIP) or isnotempty(AccountName)
    | where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn or AccountName =~ InputAccountUpn)
        and (isempty(InputIpAddress)  or RemoteIP == InputIpAddress or LocalIP == InputIpAddress)
    | project AlertId, EvAccountUpn = AccountUpn, EvAccountName = AccountName,
              EvRemoteIP = RemoteIP, EvDeviceName = DeviceName, EvRemoteUrl = RemoteUrl,
              EvEntityType = EntityType, EvEvidenceRole = EvidenceRole,
              EvProcessCommandLine = ProcessCommandLine, EvSha256 = SHA256;
Evidence
| join kind=inner IdentityAlerts on AlertId
| summarize EvidenceCount = count(),
            Roles         = make_set(EvEvidenceRole, 5),
            EntityTypes   = make_set(EvEntityType, 5),
            Devices       = make_set(EvDeviceName, 10),
            Urls          = make_set(EvRemoteUrl, 10),
            Techniques    = make_set(AttackTechniques, 5)
          by AlertId, AlertTime, Title, Severity, ServiceSource, EvAccountUpn, EvRemoteIP
| order by AlertTime desc
| take 200
```
