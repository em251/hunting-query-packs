# V04 — Timeline: what this user did to what object, from where

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId (required), InputObjectName or InputObjectId or InputObjectType (optional)  
**Performance:** account + optional object filter before the projection; the wide RawEventData column is not carried.

The narrative view for a report or a handover: chronological rows of action, object, source IP, country, ISP, user agent, admin flag, and the session id pulled out of the payload.

`UncommonForUser` and `LastSeenForUser` ride along so you can annotate the first row where the behaviour stopped being routine — that is usually the sentence the report needs.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputAccountId = "";
let InputObjectName = "";
let InputObjectId = "";
let InputObjectType = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputAccountId)
| where AccountId =~ InputAccountId or AccountDisplayName =~ InputAccountId
| where (isempty(InputObjectName) or ObjectName =~ InputObjectName)
    and (isempty(InputObjectId)   or ObjectId =~ InputObjectId)
    and (isempty(InputObjectType) or ObjectType =~ InputObjectType)
| project Timestamp, Application, ActionType, ActivityType, ObjectType, ObjectName, ObjectId,
          IPAddress, CountryCode, City, Isp, UserAgent, IsAdminOperation, IsAnonymousProxy,
          IsImpersonated, AuditSource, UncommonForUser, LastSeenForUser,
          AADSessionId = tostring(RawEventData.AppAccessContext.AADSessionId),
          InLineSessionId = tostring(SessionData.InLineSessionId)
| order by Timestamp asc
| take 1000
```
