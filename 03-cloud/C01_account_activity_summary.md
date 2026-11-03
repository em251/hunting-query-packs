# C01 — Cloud app activity summary for an account

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId, InputIpAddress, InputApplication (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Coarse shape of an account's SaaS activity: what it touched, from where,
whether it used admin operations or an anonymising proxy.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountId   = "";
let InputIpAddress   = "";
let InputApplication = "";

CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputAccountId)   or AccountId =~ InputAccountId
                                   or AccountDisplayName has InputAccountId)
    and (isempty(InputIpAddress)   or IPAddress == InputIpAddress)
    and (isempty(InputApplication) or Application =~ InputApplication)
| summarize Events        = count(),
            DistinctObjects = dcount(ObjectId),
            AdminOps      = countif(IsAdminOperation),
            AnonProxy     = countif(IsAnonymousProxy),
            Ips           = make_set(IPAddress, 10),
            Countries     = make_set(CountryCode, 5),
            UserAgents    = make_set(UserAgent, 3),
            FirstSeen     = min(Timestamp),
            LastSeen      = max(Timestamp)
          by AccountId, AccountDisplayName, Application, ActionType
| order by Events desc
| take 200
```
