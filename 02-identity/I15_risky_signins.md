# I15 — Risky sign-ins and Conditional Access outcomes

**Pack:** Identity  
**Tables:** EntraIdSignInEvents  
**Inputs:** InputAccountUpn (OPTIONAL), Threshold (default 4)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Risk fields plus CA status. ConditionalAccessStatus: 0 = policies applied,
1 = attempt to apply policies failed, 2 = policies not applied - the "2"
rows are the interesting ones for a bypass hypothesis.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 4;
let InputAccountUpn = "";
EntraIdSignInEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
| where RiskLevelDuringSignIn > 0
     or RiskState > 0
     or isnotempty(RiskEventTypes)
     or ConditionalAccessStatus == 1
| summarize Attempts   = count(),
            Ips        = make_set(IPAddress, 10),
            Countries  = make_set(Country, 5),
            Apps       = make_set(Application, 5),
            RiskEvents = make_set(RiskEventTypes, 5),
            CaStatuses = make_set(ConditionalAccessStatus, 3),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
          by AccountUpn, RiskLevelDuringSignIn, RiskState
| where Attempts >= Threshold
| order by RiskLevelDuringSignIn desc, Attempts desc
| take 100
```
