# C12 — One IP across every cloud table

**Use when:** you need everything an address touched across apps, audit, Key Vault and Graph.
**Alert fields:** IPAddress

**Pack:** Cloud  
**Tables:** CloudAppEvents, CloudAuditEvents, CloudKeyVaultEvents, GraphAPIAuditEvents  
**Inputs:** InputIpAddress (REQUIRED)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

The "who else is this IP talking to" query. Every branch projects the same
shape so the union stays readable; keep the branches time-bounded or the
union gets expensive.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputIpAddress = "";   // REQUIRED
union
    (CloudAppEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress
     | project Timestamp, Source = "CloudAppEvents", Actor = AccountId,
               Detail = strcat(Application, " | ", ActionType), Resource = ObjectName),
    (CloudAuditEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress
     | project Timestamp, Source = "CloudAuditEvents", Actor = tostring(RawEventData.UserIdentity.Arn),
               Detail = strcat(DataSource, " | ", OperationName), Resource = ResourceId),
    (CloudKeyVaultEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IPAddress == InputIpAddress
     | project Timestamp, Source = "CloudKeyVaultEvents", Actor = AccountUpn,
               Detail = strcat(VaultName, " | ", ActivityName, " | ", ResultSignature),
               Resource = AzureResourceId),
    (GraphAPIAuditEvents
     | where Timestamp between (LookbackStart .. LookbackEnd)
     | where IpAddress == InputIpAddress
     | project Timestamp, Source = "GraphAPIAuditEvents", Actor = ApplicationId,
               Detail = strcat(RequestMethod, " ", RequestUri, " -> ", ResponseStatusCode),
               Resource = TargetWorkload)
| order by Timestamp desc
| take 1000
```
