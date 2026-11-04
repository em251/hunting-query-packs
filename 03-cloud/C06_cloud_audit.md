# C06 — Cloud audit events by IP or operation

**Use when:** AWS, GCP, Azure or Kubernetes control-plane activity.
**Alert fields:** IPAddress, DataSource, ResourceId, Principal

**Pack:** Cloud  
**Tables:** CloudAuditEvents  
**Inputs:** InputIpAddress, InputDataSource, InputResourceId, InputPrincipal (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** 3-day default, columns projected before the per-platform `case()` dereferences so the dynamic payload is the only wide column in flight.

CloudAuditEvents has no actor column - the principal is inside RawEventData,
and its shape differs per platform. Each platform is a documented payload:
AWS          RawEventData.userIdentity.{arn,accountId,accessKeyId,type}, eventName, errorCode
GCP          RawEventData.protoPayload.authenticationInfo.principalEmail, methodName, status
Azure        RawEventData.identity.claims, properties.eventName, status.value
Kubernetes   RawEventData.user.username, verb, objectRef.resource, responseStatus.code
Dereferences that do not exist return empty rather than erroring, so this is
safe across a mixed feed - see C14 to confirm the keys in YOUR data.

```kql
let LookbackStart = ago(3d);
let LookbackEnd   = now();
let InputIpAddress  = "";
let InputDataSource = "";   // "AWS", "GCP", "Azure", "Kubernetes Audit"
let InputResourceId = "";
let InputPrincipal  = "";
CloudAuditEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputIpAddress)  or IPAddress == InputIpAddress)
    and (isempty(InputDataSource) or DataSource =~ InputDataSource)
    and (isempty(InputResourceId) or ResourceId =~ InputResourceId)
| project Timestamp, DataSource, ActionType, OperationName, ResourceId, IPAddress,
          CountryCode, City, Isp, IsAnonymousProxy, RawEventData
| extend Principal = case(
      DataSource =~ "AWS", tostring(RawEventData.userIdentity.arn),
      DataSource =~ "GCP", tostring(RawEventData.protoPayload.authenticationInfo.principalEmail),
      DataSource =~ "Azure", tostring(RawEventData.identity.claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]),
      tostring(RawEventData.user.username))
| extend IdentityType = case(
      DataSource =~ "AWS", tostring(RawEventData.userIdentity.type),
      DataSource =~ "Azure", tostring(RawEventData.identity.authorization.evidence.principalType),
      "")
| extend EventName = case(
      DataSource =~ "AWS", tostring(RawEventData.eventName),
      DataSource =~ "GCP", tostring(RawEventData.protoPayload.methodName),
      DataSource =~ "Azure", tostring(RawEventData.properties.eventName),
      tostring(RawEventData.verb))
| extend ErrorText = case(
      DataSource =~ "AWS", tostring(RawEventData.errorCode),
      DataSource =~ "GCP", tostring(RawEventData.protoPayload.status.message),
      DataSource =~ "Azure", tostring(RawEventData.status.value),
      tostring(RawEventData.responseStatus.code))
| where isempty(InputPrincipal) or Principal has InputPrincipal
| summarize Events     = count(),
            Resources  = dcount(ResourceId),
            Principals = make_set(Principal, 10),
            Ips        = make_set(IPAddress, 10),
            Countries  = make_set(CountryCode, 5),
            AnonProxy  = countif(IsAnonymousProxy),
            Failures   = countif(isnotempty(ErrorText) and ErrorText !in ("", "0", "Success", "Succeeded"))
          by DataSource, EventName, ActionType, IdentityType
| order by Events desc
| take 100
```
