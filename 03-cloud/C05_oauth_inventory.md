# C05 — OAuth app inventory risk

**Use when:** sweep every consented app for unverified publishers and high privilege.
**Alert fields:** OAuthAppId

**Pack:** Cloud  
**Tables:** OAuthAppInfo  
**Inputs:** InputOAuthAppId (OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Standalone sweep of every consented app. High privilege + unverified
publisher + no recent use is the shortlist worth revoking.

```kql
let LookbackStart = ago(90d);
let LookbackEnd   = now();
let InputOAuthAppId = "";
OAuthAppInfo
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isempty(InputOAuthAppId) or OAuthAppId =~ InputOAuthAppId
| extend Unverified = isempty(VerifiedPublisher) or VerifiedPublisher has_any ("false", "unverified")
| where Unverified or PrivilegeLevel in ("High", "Medium")
| project AppName, OAuthAppId, ServicePrincipalId, AppStatus, PrivilegeLevel,
          VerifiedPublisher, AppOrigin, AddedOnTime, LastUsedTime, AppOwnerTenantId,
          PermissionCount = array_length(Permissions), Permissions
| order by LastUsedTime asc, PermissionCount desc
| take 200
```
