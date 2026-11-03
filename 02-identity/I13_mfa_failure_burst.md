# I13 — MFA fatigue / repeated MFA failures

**Pack:** Identity  
**Tables:** EntraIdSignInEvents  
**Inputs:** InputAccountUpn, InputIpAddress (both OPTIONAL), Threshold (default 5)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

MFA prompts being answered with failures over and over, then a success, is
the classic fatigue pattern. ErrorCode 500121 = authentication failed during
strong authentication; 50074 = strong authentication required.
Reference: https://aka.ms/AADsigninsErrorCodes

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 5;
let InputAccountUpn = "";
let InputIpAddress  = "";

EntraIdSignInEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
    and (isempty(InputIpAddress)  or IPAddress == InputIpAddress)
| summarize Attempts   = count(),
            Failures   = countif(ErrorCode != 0),
            Successes  = countif(ErrorCode == 0),
            ErrorCodes = make_set(ErrorCode, 10),
            Apps       = make_set(Application, 5),
            UserAgents = make_set(UserAgent, 3),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
          by AccountUpn, IPAddress
| where Failures >= Threshold
| extend FatigueThenSuccess = Failures >= Threshold and Successes > 0
| order by Failures desc
| take 100
```
