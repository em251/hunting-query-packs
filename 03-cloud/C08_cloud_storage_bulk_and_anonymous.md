# C08 — Cloud storage: bulk read and anonymous access

**Pack:** Cloud  
**Tables:** CloudStorageAggregatedEvents  
**Inputs:** InputStorageAccount, InputAccountUpn, InputIpAddress (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Pre-aggregated storage telemetry. Thresholds are on volume and on anonymous
success, which is the exfiltration / public-bucket tell.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 1000;   // bytes-ish volume threshold; tune per tenant
let InputStorageAccount = "";
let InputAccountUpn     = "";
let InputIpAddress      = "";

CloudStorageAggregatedEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputStorageAccount) or StorageAccount =~ InputStorageAccount)
    and (isempty(InputAccountUpn)     or AccountUpn =~ InputAccountUpn)
    and (isempty(InputIpAddress)      or IpAddress == InputIpAddress)
| where AnonymousSuccessfulOperations > 0
     or DistinctGetOperations >= 100
     or TotalResponseLength >= Threshold
| summarize Windows        = count(),
            Operations     = sum(OperationsCount),
            FailedOps      = sum(FailedOperationsCount),
            GetOps         = sum(DistinctGetOperations),
            BytesOut       = sum(TotalResponseLength),
            AnonymousOps   = sum(AnonymousSuccessfulOperations),
            Ips            = make_set(IpAddress, 10),
            UserAgents     = make_set(UserAgentHeader, 5),
            AuthTypes      = make_set(AuthenticationType, 5),
            FirstSeen      = min(DataAggregationStartTime),
            LastSeen       = max(DataAggregationEndTime)
          by StorageAccount, StorageContainer, AccountUpn
| order by BytesOut desc
| take 100
```
