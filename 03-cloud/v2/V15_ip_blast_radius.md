# V15 — Everything this IP touched

**Use when:** alert triage - fan out by IP across control plane, SaaS and Key Vault.
**Alert fields:** IPAddress

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAuditEvents, CloudAppEvents, CloudKeyVaultEvents  
**Inputs:** InputIpAddress (required), InputResourceText (optional), 24h default  
**Performance:** single IP filter per branch before any union; each branch projects the same five columns so the union stays narrow.

The first query to run on the alert as written: *unusual ISP and user agent, first activity from this IP against subscription/resource group X.*

It ignores the resource boundary deliberately. If the IP is hostile, the storage account is the one you noticed — not necessarily the only one it touched. Three branches cover Azure/AWS/GCP control plane, SaaS activity, and Key Vault, so a key read followed by mailbox or blob activity appears in one timeline.

`Source` tells you which plane the event came from; `Operation` is the platform-specific action name.

```kql
let LookbackStart = ago(24h);
let LookbackEnd = now();
let InputIpAddress = "";
let InputResourceText = "";
union
    (CloudAuditEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputIpAddress) and IPAddress == InputIpAddress
    | project Timestamp, Source = "CloudAudit", Actor = case(
          DataSource =~ "AWS", tostring(RawEventData.userIdentity.arn),
          DataSource =~ "GCP", tostring(RawEventData.protoPayload.authenticationInfo.principalEmail),
          DataSource =~ "Azure", tostring(RawEventData.identity.claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]),
          tostring(RawEventData.user.username)),
      Operation = coalesce(OperationName, tostring(RawEventData.properties.eventName)),
      Resource = ResourceId, CountryCode, UserAgent),
    (CloudAppEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputIpAddress) and IPAddress == InputIpAddress
    | project Timestamp, Source = "CloudApp", Actor = AccountId,
      Operation = ActionType, Resource = coalesce(ObjectName, ObjectId), CountryCode, UserAgent),
    (CloudKeyVaultEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputIpAddress) and IPAddress == InputIpAddress
    | project Timestamp, Source = "KeyVault", Actor = AccountUpn,
      Operation = ActivityName, Resource = coalesce(VaultName, AzureResourceId),
      CountryCode = Location, UserAgent = UserAgentHeader)
| where isempty(InputResourceText) or Resource has InputResourceText
| order by Timestamp asc
| take 1000
```
