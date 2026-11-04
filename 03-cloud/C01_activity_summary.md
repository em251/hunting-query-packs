# C01 — Cloud app activity summary for an account

**Use when:** what did this actor touch, in which app, with which admin operations.
**Alert fields:** AccountId, IPAddress, Application

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId, InputIpAddress, InputApplication (all OPTIONAL), InputSessionId  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** `InputAccountId` narrows this to one actor. Unfiltered it groups every account x application x action, which is the expensive shape - fill at least one input.

Coarse shape of an account's SaaS activity: what it touched, from where,
whether it used admin operations or an anonymising proxy.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountId   = "";
let InputIpAddress   = "";
let InputApplication = "";
let InputSessionId = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputSessionId) or tostring(SessionData.InLineSessionId) =~ InputSessionId or tostring(RawEventData.AppAccessContext.AADSessionId) =~ InputSessionId)
| where (isempty(InputAccountId)   or AccountId =~ InputAccountId
                                   or AccountDisplayName has InputAccountId)
    and (isempty(InputIpAddress)   or IPAddress == InputIpAddress)
    and (isempty(InputApplication) or Application =~ InputApplication)
| summarize Events        = count(),
            DistinctObjects = dcount(ObjectId),
            AdminOps      = countif(IsAdminOperation),
            AnonProxy     = countif(IsAnonymousProxy),
            Ips           = make_set(IPAddress, 5),
            Countries     = make_set(CountryCode, 3),
            UserAgents    = make_set(UserAgent, 2),
            FirstSeen     = min(Timestamp),
            LastSeen      = max(Timestamp)
          by AccountId, AccountDisplayName, Application, ActionType
| order by Events desc
| take 200
```
