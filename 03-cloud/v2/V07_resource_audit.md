# V07 — Azure / AWS / GCP resource audit

**Use when:** control-plane actions against one resource - subscription, RG, storage account.
**Alert fields:** ResourceID, CloudResource, AccountUpn, DataSource

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAuditEvents  
**Inputs:** InputResourceId, InputResourceName, InputPrincipal, InputDataSource (fill at least one)  
**Performance:** 3-day default; Azure resource id is parsed with extract() after the row is already filtered by time.

The control-plane view. `CloudAuditEvents` covers Azure Resource Manager, AWS CloudTrail, GCP audit logs and Kubernetes audit, and has no actor column — the principal lives in the payload.

This resolves the principal per platform, parses the Azure resource id into subscription / resource group / provider / name (`/subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}`), and rolls up operations against one resource. Use it when the hunting lead is a resource rather than a user.

```kql
let LookbackStart = ago(3d);
let LookbackEnd = now();
let InputResourceId = "";
let InputResourceName = "";
let InputPrincipal = "";
let InputDataSource = "";
CloudAuditEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputResourceId) or isnotempty(InputResourceName)
     or isnotempty(InputPrincipal) or isnotempty(InputDataSource)
| extend Principal = case(
      DataSource =~ "AWS", tostring(RawEventData.userIdentity.arn),
      DataSource =~ "GCP", tostring(RawEventData.protoPayload.authenticationInfo.principalEmail),
      DataSource =~ "Azure", tostring(RawEventData.identity.claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]),
      tostring(RawEventData.user.username))
| extend EventName = case(
      DataSource =~ "AWS", tostring(RawEventData.eventName),
      DataSource =~ "GCP", tostring(RawEventData.protoPayload.methodName),
      DataSource =~ "Azure", tostring(RawEventData.properties.eventName),
      tostring(RawEventData.verb))
| extend AzureSubscription = extract(@"/subscriptions/([^/]+)", 1, ResourceId),
         AzureResourceGroup = extract(@"/resourceGroups/([^/]+)", 1, ResourceId),
         AzureProvider = extract(@"/providers/([^/]+)", 1, ResourceId),
         AzureResourceName = extract(@"/providers/[^/]+/[^/]+/([^/]+)", 1, ResourceId)
| where (isempty(InputResourceId)   or ResourceId =~ InputResourceId)
    and (isempty(InputResourceName) or AzureResourceName =~ InputResourceName
                                    or ResourceId has InputResourceName)
    and (isempty(InputPrincipal)    or Principal has InputPrincipal)
    and (isempty(InputDataSource)   or DataSource =~ InputDataSource)
| summarize Events = count(), Principals = dcount(Principal), PrincipalSample = make_set(Principal, 10),
            Operations = make_set(EventName, 10), Ips = make_set(IPAddress, 5),
            Countries = make_set(CountryCode, 3), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DataSource, ActionType, AzureProvider, AzureResourceName
| order by Events desc
| take 200
```
