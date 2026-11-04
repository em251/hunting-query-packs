# V14 — Azure control-plane changes

**Use when:** role, network, firewall and key configuration changes after an alert.
**Alert fields:** ResourceID, AccountUpn

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAuditEvents  
**Inputs:** InputResourceId, InputSubscription, InputPrincipal (all optional), 3d default  
**Performance:** operation filter first; the resource scope is a substring on ResourceId, which is cheap before any aggregation.

The detection set that matters after storage keys are touched: did the actor also change who can reach the resource?

Role assignments, network rules and firewall changes are how an attacker converts a stolen key into durable access. These operations are the Azure RBAC/ARM action names (`Microsoft.Authorization/roleAssignments/write`, `Microsoft.Storage/storageAccounts/write`, virtual network rule changes), matched as substrings because the recorded form varies.

```kql
let LookbackStart = ago(3d);
let LookbackEnd = now();
let InputResourceId = "";
let InputSubscription = "";
let InputPrincipal = "";
let ControlPlaneChanges = dynamic([
    "roleAssignments/write", "roleAssignments/delete", "roleDefinitions/write",
    "storageAccounts/write", "storageAccounts/listKeys", "storageAccounts/regenerateKey",
    "blobServices/write", "fileServices/write", "containers/write", "containers/delete",
    "networkSecurityGroups/write", "virtualNetworks/write", "firewallRules/write",
    "diagnosticSettings/write", "privateEndpointConnections/write", "accessPolicies/write",
    "CreateAccessKey", "AttachUserPolicy", "PutBucketPolicy", "PutBucketAcl"
]);
CloudAuditEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where OperationName has_any (ControlPlaneChanges)
     or tostring(RawEventData.properties.eventName) has_any (ControlPlaneChanges)
     or tostring(RawEventData.eventName) has_any (ControlPlaneChanges)
| where (isempty(InputResourceId) or ResourceId =~ InputResourceId or ResourceId has InputResourceId)
    and (isempty(InputSubscription) or ResourceId has InputSubscription)
| extend Principal = case(
      DataSource =~ "AWS", tostring(RawEventData.userIdentity.arn),
      DataSource =~ "GCP", tostring(RawEventData.protoPayload.authenticationInfo.principalEmail),
      DataSource =~ "Azure", coalesce(
          tostring(RawEventData.identity.claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]),
          tostring(parse_json(tostring(RawEventData.identity.claims))["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]),
          tostring(parse_json(tostring(RawEventData.identity.claims))["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]),
          tostring(parse_json(tostring(RawEventData.identity.claims))["appid"]),
          tostring(RawEventData.identity.authorization.evidence.principalId)),
      tostring(RawEventData.user.username))
| where isempty(InputPrincipal) or Principal has InputPrincipal
| summarize Changes = count(), Principals = make_set(Principal, 10), Ips = make_set(IPAddress, 10),
            Countries = make_set(CountryCode, 5), UserAgents = make_set(UserAgent, 3),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DataSource, OperationName, ResourceId
| order by Changes desc
| take 200
```
