# I08 — Directory recon: LDAP / SAMR enumeration from one account or host

**Pack:** Identity  
**Tables:** IdentityQueryEvents  
**Inputs:** InputAccountUpn, InputDeviceName, InputIpAddress (all OPTIONAL), Threshold (default 25)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Enumeration shows up as many distinct queried objects from one source in a
short window. Threshold on DistinctTargets, not raw query count, so normal
heavy LDAP use by app servers does not dominate.

```kql
let LookbackStart = ago(24h);   // recon is bursty - keep the window tight
let LookbackEnd   = now();
let Threshold     = 25;
let InputAccountUpn = "";
let InputDeviceName = "";
let InputIpAddress  = "";
IdentityQueryEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
    and (isempty(InputDeviceName) or DeviceName =~ InputDeviceName)
    and (isempty(InputIpAddress)  or IPAddress == InputIpAddress)
| summarize Queries          = count(),
            DistinctTargets  = dcount(QueryTarget),
            QueryTypes       = make_set(QueryType, 5),
            Protocols        = make_set(Protocol, 5),
            SampleQueries    = make_set(Query, 5),
            FirstSeen        = min(Timestamp),
            LastSeen         = max(Timestamp)
          by AccountUpn, DeviceName, IPAddress
| where DistinctTargets >= Threshold
| order by DistinctTargets desc
| take 100
```
