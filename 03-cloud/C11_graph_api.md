# C11 — Graph API audit

**Use when:** an app or token is enumerating the tenant through Graph.
**Alert fields:** ApplicationId, IpAddress, AccountObjectId

**Pack:** Cloud  
**Tables:** GraphAPIAuditEvents  
**Inputs:** InputApplicationId, InputIpAddress, InputAccountObjectId (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Graph calls are how a compromised app enumerates your tenant. RequestUri
shows the target collection; non-200 status codes reveal probing.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputApplicationId    = "";
let InputIpAddress        = "";
let InputAccountObjectId  = "";
GraphAPIAuditEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputApplicationId)   or ApplicationId =~ InputApplicationId)
    and (isempty(InputIpAddress)       or IpAddress == InputIpAddress)
    and (isempty(InputAccountObjectId) or AccountObjectId =~ InputAccountObjectId)
| summarize Requests      = count(),
            Failures      = countif(ResponseStatusCode != "200"),
            DistinctUris  = dcount(RequestUri),
            Scopes        = make_set(Scopes, 10),
            Methods       = make_set(RequestMethod, 5),
            StatusCodes   = make_set(ResponseStatusCode, 10),
            FirstSeen     = min(Timestamp),
            LastSeen      = max(Timestamp)
          by ApplicationId, ServicePrincipalId, TargetWorkload
| order by Failures desc, Requests desc
| take 100
```
