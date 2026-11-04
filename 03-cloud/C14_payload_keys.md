# C14 — RawEventData key explorer

**Use when:** you need to learn the payload shape before writing extraction.
**Alert fields:** ActionType, DataSource

**Pack:** Cloud  
**Tables:** CloudAppEvents, CloudAuditEvents  
**Inputs:** InputActionType, InputDataSource (both OPTIONAL)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

Microsoft publishes the column but not the JSON inside it, and the payload
differs by connector. This query enumerates the keys actually present, with a
sample value for each, so you can write precise extraction instead of
guessing at paths. Run it once per investigation area, then hard-code what
you learn into the other queries.

Set InputActionType (e.g. "New-InboxRule") for CloudAppEvents, or
InputDataSource (e.g. "AWS") for CloudAuditEvents.

```kql
let LookbackStart = ago(24h);
let LookbackEnd   = now();
let InputActionType = "";
let InputDataSource = "";
let SampleLimit     = 3;
let AppKeys =
    CloudAppEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isempty(InputActionType) or ActionType =~ InputActionType
    | where isnotempty(RawEventData)
    | project RawEventData
    | take 500
    | extend Keys = bag_keys(RawEventData)
    | mv-expand Key = Keys
    | extend KeyName = tostring(Key),
             SampleValue = tostring(RawEventData[tostring(Key)])
    | summarize Occurrences = count(), Samples = make_set(SampleValue, SampleLimit)
              by Source = "CloudAppEvents", KeyName;
let AuditKeys =
    CloudAuditEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isempty(InputDataSource) or DataSource =~ InputDataSource
    | where isnotempty(RawEventData)
    | project RawEventData
    | take 500
    | extend Keys = bag_keys(RawEventData)
    | mv-expand Key = Keys
    | extend KeyName = tostring(Key),
             SampleValue = tostring(RawEventData[tostring(Key)])
    | summarize Occurrences = count(), Samples = make_set(SampleValue, SampleLimit)
              by Source = "CloudAuditEvents", KeyName;
union AppKeys, AuditKeys
| order by Occurrences desc
| take 200
```
