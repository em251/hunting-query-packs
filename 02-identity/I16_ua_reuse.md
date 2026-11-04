# I16 — User agent reuse across accounts

**Use when:** the user agent is the indicator (tooling fingerprint).
**Alert fields:** UserAgent

**Pack:** Identity  
**Tables:** EntraIdSignInEvents  
**Inputs:** InputUserAgent (REQUIRED), Threshold (default 3), InputIpAddress, InputAccountUpn  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Toolkit-style phishing proxies and scripted credential use share UA strings
that do not match the browser/user-agent mix of real users. Pivot on the
exact UA you saw in the alert and see who else presented it.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 3;
let InputUserAgent = "";   // REQUIRED - paste the UA from the alert
let InputIpAddress = "";
let InputAccountUpn = "";
EntraIdSignInEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputIpAddress) or IPAddress == InputIpAddress)
| where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
| where UserAgent has InputUserAgent
| summarize Attempts   = count(),
            Accounts   = dcount(AccountUpn),
            Ips        = make_set(IPAddress, 15),
            Countries  = make_set(Country, 5),
            Apps       = make_set(Application, 5),
            ErrorCodes = make_set(ErrorCode, 10),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
          by UserAgent
| where Accounts >= Threshold
| order by Accounts desc
| take 50
```
