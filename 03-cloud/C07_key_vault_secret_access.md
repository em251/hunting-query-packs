# C07 — Key Vault secret / key access and failures

**Pack:** Cloud  
**Tables:** CloudKeyVaultEvents  
**Inputs:** InputAccountUpn, InputVaultName, InputIpAddress (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Secret retrieval by a human identity, especially with failures or from a new
IP, is the pivot for "attacker stole the app credential" cases.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountUpn = "";
let InputVaultName  = "";
let InputIpAddress  = "";

CloudKeyVaultEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
    and (isempty(InputVaultName)  or VaultName =~ InputVaultName)
    and (isempty(InputIpAddress)  or IPAddress == InputIpAddress)
// Key Vault request URIs are https://{vault}.vault.azure.net/{secrets|keys}/{name}[/{version}]
| extend TargetObject = coalesce(extract(@"/secrets/([^/]+)", 1, RequestUri),
                                 extract(@"/keys/([^/]+)", 1, RequestUri),
                                 extract(@"/certificates/([^/]+)", 1, RequestUri))
| summarize Attempts   = count(),
            Failures   = countif(ResultSignature != "OK"),
            Activities = make_set(ActivityName, 10),
            Ips        = make_set(IPAddress, 10),
            UserAgents = make_set(UserAgentHeader, 5),
            Objects    = make_set(TargetObject, 10),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
          by AccountUpn, AccountObjectId, AccountType, VaultName, Location
| order by Failures desc, Attempts desc
| take 200
```
