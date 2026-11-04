# V03 — Action x actor matrix for one object type, action or application

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputObjectType, InputActionType, InputApplication, InputObjectName (fill at least one)  
**Performance:** requires a selector; the group count is bounded by the object/action filter rather than by the tenant.

When you know *what* was done — a share, a download, a permission grant — but not *who*, this flips V02 around: one row per actor doing that action, against which objects.

Use it to spot the account that behaves differently from its peers: same action as everyone else, but a different IP, a different user agent, or a far higher volume.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputObjectType = "";
let InputActionType = "";
let InputApplication = "";
let InputObjectName = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputObjectType) or isnotempty(InputActionType)
     or isnotempty(InputApplication) or isnotempty(InputObjectName)
| where (isempty(InputObjectType)   or ObjectType =~ InputObjectType)
    and (isempty(InputActionType)   or ActionType =~ InputActionType)
    and (isempty(InputApplication)  or Application =~ InputApplication)
    and (isempty(InputObjectName)   or ObjectName has InputObjectName)
| summarize Events = count(), Objects = dcount(ObjectId), ObjectSamples = make_set(ObjectName, 10),
            Ips = make_set(IPAddress, 5), Countries = make_set(CountryCode, 5),
            UserAgents = make_set(UserAgent, 2), Apps = make_set(Application, 3),
            AdminOps = countif(IsAdminOperation), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by AccountId, ActionType
| order by Events desc
| take 300
```
