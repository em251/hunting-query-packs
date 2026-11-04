# V06 — First-time attributes from this IP

**Use when:** is this IP genuinely new behaviour for the account, or routine.
**Alert fields:** AccountUpn, IPAddress

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId or InputIpAddress (one required)  
**Performance:** one bounded scan, filtered to the account or IP before the bag is expanded.

`LastSeenForUser` is a bag of attribute -> days since last seen for that user, and a negative value means first time ever. The documented example keys include `ActionType`, `OSPlatform` and `ISP`.

Rather than assume key names, this expands the bag and keeps only the negative values, so you get a list of "what is new about this user, from this address" — which is the cleanest way to justify or reject a "suspicious IP" hypothesis.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputAccountId = "";
let InputIpAddress = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputAccountId) or isnotempty(InputIpAddress)
| where (isempty(InputAccountId) or AccountId =~ InputAccountId)
    and (isempty(InputIpAddress) or IPAddress == InputIpAddress)
| where isnotempty(LastSeenForUser)
| mv-expand Attribute = bag_keys(LastSeenForUser)
| extend AttributeName = tostring(Attribute)
| extend DaysSinceSeen = toint(LastSeenForUser[AttributeName])
| where DaysSinceSeen < 0
| summarize FirstSeenEvents = count(), FirstSeenAt = min(Timestamp), LastSeenAt = max(Timestamp),
            Actions = make_set(ActionType, 10), Applications = make_set(Application, 5),
            Ips = make_set(IPAddress, 5), Countries = make_set(CountryCode, 5),
            UserAgents = make_set(UserAgent, 2)
          by AccountId, AttributeName
| order by FirstSeenAt desc
| take 200
```
