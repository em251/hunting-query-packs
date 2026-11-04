# I07 — Directory changes for the account

**Use when:** password resets, group membership changes, enable/disable.
**Alert fields:** AccountUpn

**Pack:** Identity  
**Tables:** IdentityDirectoryEvents  
**Inputs:** InputAccountUpn (REQUIRED)  
**Schema:** columns verified against the current Defender XDR advanced hunting schema (EntraIdSignInEvents is the current sign-in table; the older AADSignInEventsBeta table is not used anywhere in this pack).  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Every domain-controller side change for the account, newest first, with the
AdditionalFields payload (old/new values) for the change itself. No ActionType
filter here on purpose: you want to see the full change history, not a guess
at the strings.

```kql
let LookbackStart = ago(14d);
let LookbackEnd   = now();
let InputAccountUpn = "";   // REQUIRED
IdentityDirectoryEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where AccountUpn =~ InputAccountUpn
     or TargetAccountUpn =~ InputAccountUpn
     or TargetAccountDisplayName =~ InputAccountUpn
| summarize Changes     = count(),
            Applications = make_set(Application, 5),
            SourceDevices = make_set(DeviceName, 10),
            SourceIps    = make_set(IPAddress, 10)
          by ActionType
| order by Changes desc
| take 100
```
