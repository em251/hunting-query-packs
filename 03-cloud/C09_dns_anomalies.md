# C09 — Cloud workload DNS anomalies

**Use when:** tunnelling or DGA behaviour from containers or cloud VMs.
**Alert fields:** HostName, DnsQuery, ResourceId

**Pack:** Cloud  
**Tables:** CloudDnsEvents  
**Inputs:** InputHostName, InputDnsQuery, InputResourceId (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

DNS from containers / cloud VMs. High volume of unique queries plus long
first labels is the cheap tunnelling heuristic; NXDOMAIN rates catch DGA.

```kql
let LookbackStart = ago(24h);
let LookbackEnd   = now();
let InputHostName   = "";
let InputDnsQuery   = "";
let InputResourceId = "";
CloudDnsEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputHostName)   or HostName =~ InputHostName)
    and (isempty(InputDnsQuery)   or DnsQuery has InputDnsQuery)
    and (isempty(InputResourceId) or AzureResourceId =~ InputResourceId
                                  or AwsResourceName =~ InputResourceId
                                  or GcpFullResourceName =~ InputResourceId)
| extend FirstLabel = tostring(split(DnsQuery, ".")[0])
| extend FirstLabelLength = strlen(FirstLabel)
| summarize Queries        = count(),
            DistinctQueries = dcount(DnsQuery),
            NxDomain       = countif(DnsResponseCodeName == "NXDOMAIN"),
            LongLabels     = countif(FirstLabelLength >= 25),
            Processes      = make_set(ProcessName, 10),
            Images         = make_set(ImageName, 5)
          by HostName, ContainerName
| where LongLabels > 0 or NxDomain >= 50 or DistinctQueries >= 1000
| order by LongLabels desc, NxDomain desc
| take 100
```
