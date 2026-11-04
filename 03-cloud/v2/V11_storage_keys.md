# V11 — Storage key and SAS operations

**Use when:** the alert says listKeys, regenerateKey or listAccountSas.
**Alert fields:** ResourceID, IPAddress, AccountUpn

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAuditEvents  
**Inputs:** InputStorageAccount, InputIpAddress, InputPrincipal (all optional), 7d default  
**Performance:** operation-name filter first (a narrow `has_any`), then the resource/actor filters; no joins.

Built for the classic cloud alert: *first activity from a new IP, and the operation was listKeys / regenerateKey / listAccountSas.*

Reading a storage account key is not itself an exfiltration — it is the step that makes the next one possible, because with the key the actor stops appearing as a principal and starts appearing as `AuthenticationType = AccountKey`. The operation list spans Azure, AWS and GCP naming so it works on a mixed feed.

`OperationName` is "as it appears in the record", so matching is by substring (`has_any`) rather than by an exact enumerated value — that survives the differing casings and the `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` form.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputStorageAccount = "";
let InputIpAddress = "";
let InputPrincipal = "";
let StorageCredentialOps = dynamic([
    "listKeys", "regenerateKey", "listAccountSas", "listServiceSas",
    "GetBucketPolicy", "PutBucketPolicy", "PutBucketAcl", "CreateAccessKey",
    "iam.serviceAccountKeys.create", "storage.buckets.update", "storage.objects.get"
]);
CloudAuditEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where OperationName has_any (StorageCredentialOps)
     or tostring(RawEventData.properties.eventName) has_any (StorageCredentialOps)
     or tostring(RawEventData.eventName) has_any (StorageCredentialOps)
| where (isempty(InputStorageAccount) or ResourceId has InputStorageAccount)
    and (isempty(InputIpAddress) or IPAddress == InputIpAddress)
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
| summarize Events = count(), Principals = make_set(Principal, 10), Ips = make_set(IPAddress, 10),
            Countries = make_set(CountryCode, 5), Isp = make_set(Isp, 5),
            UserAgents = make_set(UserAgent, 3), AnonProxy = countif(IsAnonymousProxy),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DataSource, OperationName, ResourceId
| order by Events desc
| take 200
```
