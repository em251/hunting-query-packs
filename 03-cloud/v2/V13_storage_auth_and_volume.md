# V13 — Storage data plane: how it was authenticated, how much moved

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudStorageAggregatedEvents  
**Inputs:** InputStorageAccount (required), InputAccountUpn, InputIpAddress (optional), 7d default  
**Performance:** pre-aggregated rows summed by bucket; the account filter is pushed before any arithmetic.

The corroboration query for a `listKeys` lead. Once a key is read, the actor usually stops authenticating as a user and starts authenticating as `AccountKey` — so the interesting columns are `AuthenticationType`, the anonymous count, and the ratio of bytes out to operations.

Data-plane operations are not row-level events in this schema; this table is aggregated per window, which is why the numbers are summed rather than counted. Read it as "how much left, using which credential, from which IP".

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputStorageAccount = "";
let InputAccountUpn = "";
let InputIpAddress = "";
CloudStorageAggregatedEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputStorageAccount)
| where StorageAccount =~ InputStorageAccount
| where (isempty(InputAccountUpn) or AccountUpn =~ InputAccountUpn)
    and (isempty(InputIpAddress) or IpAddress == InputIpAddress)
| summarize Windows = count(), Operations = sum(OperationsCount),
            Successful = sum(SuccessfulOperationsCount), Failed = sum(FailedOperationsCount),
            Reads = sum(SuccessfulReadOperations), GetOps = sum(DistinctGetOperations),
            BytesOut = sum(TotalResponseLength), Anonymous = sum(AnonymousSuccessfulOperations),
            Ips = make_set(IpAddress, 10), UserAgents = make_set(UserAgentHeader, 5),
            FirstSeen = min(DataAggregationStartTime), LastSeen = max(DataAggregationEndTime)
          by StorageAccount, StorageContainer, ServiceType, AuthenticationType, AccountUpn
| order by BytesOut desc
| take 200
```
