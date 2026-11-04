# I04 — Session and token replay

**Use when:** one session or token appears from multiple IPs, countries or users.
**Alert fields:** SessionId, UniqueTokenId, AccountUpn

**Pack:** Identity  
**Tables:** EntraIdSignInEvents  
**Inputs:** InputSessionId, InputUniqueTokenId, InputAccountUpn (all OPTIONAL), Threshold (default 3)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

AiTM and token-theft investigations pivot on SessionId / UniqueTokenId.
A single session surfacing from several IPs or countries is the tell.
Set InputSessionId to expand one session; leave it empty to sweep.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 3;
let InputSessionId = "";
let InputAccountUpn = "";
let InputUniqueTokenId = "";
let SuspiciousSessions =
    EntraIdSignInEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(SessionId)
    | where (isempty(InputSessionId) or SessionId =~ InputSessionId)
        and (isempty(InputUniqueTokenId) or UniqueTokenId =~ InputUniqueTokenId)
        and (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
    | summarize SignIns   = count(),
                Ips       = dcount(IPAddress),
                Countries = dcount(Country),
                Users     = dcount(AccountUpn),
                UserAgents = make_set(UserAgent, 5),
                FirstSeen = min(Timestamp),
                LastSeen  = max(Timestamp)
              by SessionId
    | where Ips >= Threshold or Countries >= Threshold or Users > 1;
EntraIdSignInEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where SessionId in ((SuspiciousSessions | project SessionId))
| project Timestamp, AccountUpn, SessionId, UniqueTokenId, IPAddress, Country, City,
          Application, ResourceDisplayName, UserAgent, ErrorCode, AuthenticationRequirement,
          RiskLevelDuringSignIn, DeviceTrustType, IsManaged, IsCompliant
| order by SessionId asc, Timestamp asc
| take 1000
```
