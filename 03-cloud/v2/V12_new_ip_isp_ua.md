# V12 — First-seen IP, ISP or user agent against a resource

**Use when:** the alert says unusual ASN, unusual user agent, first activity from an IP.
**Alert fields:** ResourceID, IPAddress

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAuditEvents  
**Inputs:** InputResourceId (optional but recommended), InputSubscription (optional), InputIpAddress  
**Performance:** three thin anti-joins over (resource, dimension) pairs; each side is reduced to a distinct pair set before the join.

Directly answers the alert wording: *unusual ISP, unusual user agent, first activity from this IP.*

There is no ASN column in the schema — `Isp` (the provider name) is the closest signal, and it is what this uses. Each dimension is baselined separately over 30 days and anti-joined against the last 24 hours, so a brand-new IP from a familiar ISP, or a familiar IP with a brand-new user agent, both surface independently.

`Dimension` tells you which signal was new; the event count and first-seen time tell you how much the actor did with it.

```kql
let RecentStart = ago(1d);
let BaselineStart = ago(30d);
let InputResourceId = "";
let InputSubscription = "";
let InputIpAddress = "";
let Recent =
    CloudAuditEvents
    | where Timestamp between (RecentStart .. now())
| where (isempty(InputIpAddress) or IPAddress == InputIpAddress)
    | where isempty(InputResourceId) or ResourceId =~ InputResourceId or ResourceId has InputResourceId
    | where isempty(InputSubscription) or ResourceId has InputSubscription
    | project Timestamp, ResourceId, IPAddress, Isp, UserAgent;
let Baseline =
    CloudAuditEvents
    | where Timestamp between (BaselineStart .. RecentStart)
    | where isempty(InputResourceId) or ResourceId =~ InputResourceId or ResourceId has InputResourceId
    | where isempty(InputSubscription) or ResourceId has InputSubscription
    | project ResourceId, IPAddress, Isp, UserAgent;
union
    (Recent
    | summarize Events = count(), FirstSeen = min(Timestamp) by ResourceId, Value = IPAddress
    | join kind=leftanti (Baseline | summarize by ResourceId, Value = IPAddress) on ResourceId, Value
    | extend Dimension = "IPAddress"),
    (Recent
    | summarize Events = count(), FirstSeen = min(Timestamp) by ResourceId, Value = Isp
    | join kind=leftanti (Baseline | summarize by ResourceId, Value = Isp) on ResourceId, Value
    | extend Dimension = "Isp"),
    (Recent
    | summarize Events = count(), FirstSeen = min(Timestamp) by ResourceId, Value = UserAgent
    | join kind=leftanti (Baseline | summarize by ResourceId, Value = UserAgent) on ResourceId, Value
    | extend Dimension = "UserAgent")
| where isnotempty(Value)
| order by FirstSeen desc
| take 200
```
