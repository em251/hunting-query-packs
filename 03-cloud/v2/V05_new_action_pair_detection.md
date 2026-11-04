# V05 — Has this account ever done this action before? (1 day vs 30-day baseline)

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** none - runs fleet-wide; LookbackStart is fixed at 1 day against a 30-day baseline  
**Performance:** two bounded scans reduced to two thin (AccountId, ActionType) sets before the anti-join.

Novelty at the pair grain, which is the question IR asks and point-in-time anomaly columns cannot answer: *is this user doing something they have never done in the last month?*

An anti-join against the 30-day baseline returns only account/action combinations that appear today and nowhere in the prior month. A first-ever mailbox rule, a first-ever bulk download, a first-ever permission grant all surface here — including ones no detection fired on.

```kql
let RecentStart = ago(1d);
let BaselineStart = ago(30d);
let Recent =
    CloudAppEvents
    | where Timestamp between (RecentStart .. now())
    | where isnotempty(AccountId)
    | summarize Events = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
                Apps = make_set(Application, 3), Ips = make_set(IPAddress, 3),
                Countries = make_set(CountryCode, 3)
              by AccountId, ActionType;
let Baseline =
    CloudAppEvents
    | where Timestamp between (BaselineStart .. RecentStart)
    | where isnotempty(AccountId)
    | summarize BaselineEvents = count() by AccountId, ActionType;
Recent
| join kind=leftanti Baseline on AccountId, ActionType
| order by Events desc
| take 200
```
