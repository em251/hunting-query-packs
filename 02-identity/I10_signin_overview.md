# I10 — Sign-in overview for an account

**Use when:** baseline where / how / how often before you judge a single sign-in.
**Alert fields:** AccountUpn

**Pack:** Identity  
**Tables:** EntraIdSignInEvents  
**Inputs:** InputAccountUpn (REQUIRED for a focused look), InputIpAddress, InputSessionId, InputCorrelationId  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** fill `InputAccountUpn` for a single-account run; left empty it groups every account and builds the sample sets per group, which is the expensive shape.

Baseline view: which apps, which countries, which IPs, how many failures,
which MFA mode. Run this first, then pivot with I10/I04.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountUpn = "";   // set to the account under investigation
let InputIpAddress = "";
let InputSessionId = "";
let InputCorrelationId = "";
EntraIdSignInEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputIpAddress) or IPAddress == InputIpAddress)
| where (isempty(InputSessionId) or SessionId =~ InputSessionId)
| where (isempty(InputCorrelationId) or CorrelationId =~ InputCorrelationId)
| where isnotempty(AccountUpn)
| where isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn
| extend Succeeded = ErrorCode == 0
| summarize Attempts   = count(),
            Successes  = countif(Succeeded),
            Failures   = countif(not(Succeeded)),
            Apps       = dcount(Application),
            Resources  = dcount(ResourceDisplayName),
            Ips        = dcount(IPAddress),
            Countries  = make_set(Country, 5),
            Cities     = make_set(City, 5),
            MfaModes   = make_set(AuthenticationRequirement, 3),
            ClientApps = make_set(ClientAppUsed, 5),
            UserAgents = make_set(UserAgent, 2),
            CaStatuses = make_set(ConditionalAccessStatus, 3),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
          by AccountUpn
| order by Failures desc, Attempts desc
| take 50
```
