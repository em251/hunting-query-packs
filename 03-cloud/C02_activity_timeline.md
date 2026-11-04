# C02 — Cloud app activity timeline (raw rows)

**Use when:** you need the raw rows for one account and one selector.
**Alert fields:** AccountId, Application, ObjectName

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId, InputApplication, InputObjectName (all OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema. CloudAppEvents has NO AccountUpn column - the actor is AccountId (usually the UPN) plus AccountObjectId. CloudAuditEvents has no actor  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Read top-down when reconstructing what an attacker did with a stolen session.
RawEventData carries the operation parameters (mailbox rule contents, sharing
links, permission grants), which is usually where the evidence is.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountId    = "";
let InputApplication  = "";
let InputObjectName   = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
// at least one selector is required: an unscoped timeline drags RawEventData
// for a whole week into memory and tells you nothing
| where isnotempty(InputAccountId) or isnotempty(InputApplication) or isnotempty(InputObjectName)
| where (isempty(InputAccountId)   or AccountId =~ InputAccountId
                                   or AccountDisplayName has InputAccountId)
    and (isempty(InputApplication) or Application =~ InputApplication)
    and (isempty(InputObjectName)  or ObjectName has InputObjectName)
// UncommonForUser / LastSeenForUser are the table's own anomaly signals: '[]'
// means enriched and nothing unusual, '' means not enriched, a populated list
// names the attributes that are rare for this user.
| project Timestamp, Application, ActionType, ActivityType, AccountId,
          AccountDisplayName, IPAddress, CountryCode, City, Isp, UserAgent,
          UserAgentTags, IPTags, IsAdminOperation, IsAnonymousProxy,
          IsExternalUser, IsImpersonated, AuditSource, ObjectType, ObjectName,
          ObjectId, ActivityObjects, UncommonForUser, LastSeenForUser,
          SessionData, RawEventData
| order by Timestamp asc
| take 500
```
