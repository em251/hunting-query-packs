# V16 — Azure identity payload shape (does the UPN claim resolve?)

**Use when:** you are Azure-centric and need to know whether `identity.claims` arrives as an object or a JSON string, and which claims are populated.
**Alert fields:** none - diagnostic, run once per tenant

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAuditEvents  
**Inputs:** none - fixed 24-hour window  
**Performance:** one bounded scan of Azure rows, no joins, one aggregation.

Every Azure principal resolution in this pack (V07, V11, V14, V15, C06, C12) reads `RawEventData.identity.claims`. The Azure Activity Log REST schema puts claims in a nested object, but ingestion through Defender can hand them over as a JSON string instead — and dynamic access is case- and shape-sensitive, so the wrong assumption silently yields an empty `Principal` for every row.

`UpnViaObject` counts rows where the nested-object form resolved; `UpnViaJsonString` counts the string form. Whichever is non-zero is how your tenant delivers it. `AppIdClaim` / `OidClaim` show whether service principals are identified at all - they carry no UPN, which is why the hardened resolver falls back to `appid` and `principalId`.

If both UPN counters are zero, the actor is always a workload identity and you should scope on `OidClaim` instead.

```kql
let LookbackStart = ago(24h);
let LookbackEnd = now();
CloudAuditEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where DataSource =~ "Azure"
| extend Claims = RawEventData.identity.claims
| extend ClaimsAsObject = parse_json(tostring(Claims))
| summarize Rows = count(), UpnViaObject = countif(isnotempty(tostring(Claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]))), UpnViaJsonString = countif(isnotempty(tostring(ClaimsAsObject["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]))), NameClaim = countif(isnotempty(tostring(ClaimsAsObject["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]))), AppIdClaim = countif(isnotempty(tostring(ClaimsAsObject["appid"]))), OidClaim = countif(isnotempty(tostring(ClaimsAsObject["http://schemas.microsoft.com/identity/claims/objectidentifier"]))), SampleIdentity = any(tostring(RawEventData.identity))
```
