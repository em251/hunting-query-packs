# V02 — What this account did, and to which objects

**Use when:** actor-centric enumeration of every action performed.
**Alert fields:** AccountUpn, IPAddress, Application

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountId / InputAccountObjectId (one required), InputIpAddress, InputApplication  
**Performance:** account filter first, then a rollup on two fields; sets are capped.

The actor-side mirror of V01. Give it a UPN and it enumerates every action that account performed, grouped by action and object type, with the objects touched, the IPs used, and how many of those actions were administrative.

This is the query that answers "what did the compromised account actually touch" without pulling a raw timeline first.

```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let InputAccountId = "";
let InputAccountObjectId = "";
let InputIpAddress = "";
let InputApplication = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isnotempty(InputAccountId) or isnotempty(InputAccountObjectId)
| where (isempty(InputAccountId)       or AccountId =~ InputAccountId)
    and (isempty(InputAccountObjectId) or AccountObjectId =~ InputAccountObjectId)
    and (isempty(InputIpAddress)       or IPAddress == InputIpAddress)
    and (isempty(InputApplication)     or Application =~ InputApplication)
| summarize Actions = count(), Objects = dcount(ObjectId), ObjectSamples = make_set(ObjectName, 10),
            ObjectTypes = make_set(ObjectType, 5), Ips = make_set(IPAddress, 5),
            Apps = make_set(Application, 5), AdminOps = countif(IsAdminOperation),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by ActionType
| order by AdminOps desc, Actions desc
| take 200
```
