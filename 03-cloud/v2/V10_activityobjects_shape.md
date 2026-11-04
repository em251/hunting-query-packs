# V10 — What is actually inside ActivityObjects (shape discovery)

**Pack:** Cloud (v2 — IR workflow)  
**Tables:** CloudAppEvents  
**Inputs:** InputActionType, InputObjectType (both optional), 24h default  
**Performance:** 500 rows sampled, one column carried; the expand happens after the sample.

`ActivityObjects` is documented only as "list of objects involved in the recorded activity" — the inner shape is not published and varies by connector. Do not guess at `ActivityObjects[0].ObjectName`.

This expands the array and shows the serialized elements with hit counts, so you can see whether your tenant emits `{ObjectType, ObjectId, ObjectName}`, a nested structure, or plain strings. Run it once, then write precise extraction into V01 if you need it.

```kql
let LookbackStart = ago(24h);
let LookbackEnd = now();
let InputActionType = "";
let InputObjectType = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where isempty(InputActionType) or ActionType =~ InputActionType
| where isempty(InputObjectType) or ObjectType =~ InputObjectType
| where isnotempty(ActivityObjects)
| project ActivityObjects
| take 500
| mv-expand ActivityObject = ActivityObjects
| extend Shape = tostring(ActivityObject)
| summarize Hits = count() by Shape
| order by Hits desc
| take 50
```
