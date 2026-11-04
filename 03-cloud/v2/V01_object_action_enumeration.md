# V01 — Object-centric: everything done to one resource

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputObjectName / InputObjectId / InputObjectType / InputResourceText / InputAccountId / InputIpAddress (fill at least one object or actor selector)  
**Performance:** requires at least one selector; object filters run before the aggregation, and only the columns needed for the rollup are carried.

The question an IR analyst actually asks when they see "anomalous activity on a resource": *what was done to this object, by whom, from where.*

Paste an object name (`ObjectName`), an object id (`ObjectId`), an object type, or a free-text fragment that may appear in the `ActivityObjects` array. The result is one row per action, with the actors, source IPs, countries, user agents, and whether that actor had ever done that action before (`LastSeenForUser` negative = first time).

`ActivityObjects` has no published inner schema, so it is matched as text (`tostring(ActivityObjects) has ...`) rather than by invented field paths. V10 shows you the shape if you need precise extraction.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputObjectName = "";
let InputObjectId = "";
let InputObjectType = "";
let InputResourceText = "";
let InputAccountId = "";
let InputIpAddress = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputObjectName) or isnotempty(InputObjectId) or isnotempty(InputObjectType)
     or isnotempty(InputResourceText) or isnotempty(InputAccountId) or isnotempty(InputIpAddress)
| where (isempty(InputObjectName)   or ObjectName =~ InputObjectName)
    and (isempty(InputObjectId)     or ObjectId =~ InputObjectId)
    and (isempty(InputObjectType)   or ObjectType =~ InputObjectType)
    and (isempty(InputAccountId)    or AccountId =~ InputAccountId)
    and (isempty(InputIpAddress)    or IPAddress == InputIpAddress)
| where isempty(InputResourceText) or ObjectName has InputResourceText
     or tostring(ActivityObjects) has InputResourceText
| extend FirstTimeForActor = tostring(LastSeenForUser) has '":-'
| summarize Events = count(), Actors = dcount(AccountId), ActorsSample = make_set(AccountId, 10),
            Ips = make_set(IPAddress, 10), Countries = make_set(CountryCode, 5),
            UserAgents = make_set(UserAgent, 3), NewForActor = countif(FirstTimeForActor),
            Objects = make_set(ObjectName, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by ActionType, ObjectType, Application
| order by Events desc
| take 200
```
