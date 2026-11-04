# I12 — First-time country or IP for an account

**Use when:** impossible-travel style alert against a 30-day baseline.
**Alert fields:** AccountUpn

**Pack:** Identity  
**Tables:** EntraIdSignInEvents  
**Inputs:** InputAccountUpn (REQUIRED)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Antijoin against the account's 30-day history: only environments this user
has never signed in from. Cheap impossible-travel substitute that does not
produce false positives from normal travel within known countries.

```kql
let BaselineStart = ago(30d);
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountUpn = "";   // REQUIRED
let BaselineCountries =
    EntraIdSignInEvents
    | where Timestamp between (BaselineStart .. LookbackStart)
    | where AccountUpn =~ InputAccountUpn
    | where isnotempty(Country)
    | distinct Country;
EntraIdSignInEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where AccountUpn =~ InputAccountUpn
| where isnotempty(Country)
| join kind=leftanti BaselineCountries on Country
| summarize Attempts      = count(),
            Successes     = countif(ErrorCode == 0),
            Ips           = make_set(IPAddress, 10),
            Cities        = make_set(City, 10),
            Apps          = make_set(Application, 10),
            UserAgents    = make_set(UserAgent, 5),
            FirstSeen     = min(Timestamp),
            LastSeen      = max(Timestamp)
          by Country
| order by FirstSeen asc
| take 100
```
