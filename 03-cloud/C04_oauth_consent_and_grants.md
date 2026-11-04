# C04 — OAuth consent / permission grants enriched with app risk

**Pack:** Cloud  
**Tables:** CloudAppEvents, OAuthAppInfo  
**Inputs:** InputAccountId, InputOAuthAppId, InputApplicationId (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Illicit consent grant. The CloudAppEvents side gives you who consented and
from where; OAuthAppInfo gives publisher verification, privilege level and
the permission set - the difference between a sanctioned app and a phish.

```kql
let LookbackStart = ago(14d);
let LookbackEnd   = now();
let InputAccountId   = "";
let InputOAuthAppId  = "";
let InputApplicationId = "";
let ConsentActions = dynamic([
    "Consent to application", "Add OAuth2PermissionGrant", "Add delegated permission grant",
    "Add app role assignment grant to user", "Add app role assignment to service principal",
    "Add service principal", "Add owner to application", "Update application"
]);
let Consents =
    CloudAppEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where ActionType has_any (ConsentActions) or ActivityType has_any (ConsentActions)
    | where (isempty(InputAccountId)     or AccountId =~ InputAccountId)
        and (isempty(InputOAuthAppId)    or OAuthAppId =~ InputOAuthAppId)
        and (isempty(InputApplicationId) or tostring(ApplicationId) =~ InputApplicationId)
    | project ConsentTime = Timestamp, ActionType, ActivityType, AccountId, AccountDisplayName,
              IPAddress, CountryCode, UserAgent, OAuthAppId, ApplicationId, ObjectName,
              ConsentDetails = RawEventData;
let Apps =
    OAuthAppInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | project OAuthAppId, AppName, AppStatus, VerifiedPublisher, PrivilegeLevel,
              Permissions, AppOrigin, AddedOnTime, LastUsedTime, AppOwnerTenantId;
Consents
| join kind=leftouter Apps on OAuthAppId
| project-reorder ConsentTime, AccountId, ActionType, OAuthAppId, AppName, PrivilegeLevel,
                  VerifiedPublisher, AppStatus, IPAddress, CountryCode
| order by ConsentTime desc
| take 500
```
