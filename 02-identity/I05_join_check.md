# I05 — Does the Entra session id resolve in cloud data

**Use when:** before you trust MatchBasis - confirms the tenant emits AppAccessContext.AADSessionId.
**Alert fields:** SessionId

**Pack:** Identity  
**Tables:** EntraIdSignInEvents, CloudAppEvents  
**Inputs:** InputSessionId (REQUIRED - an EntraIdSignInEvents.SessionId)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** two bounded scans, no joins.

Run this once per tenant before trusting the SessionMatched count in I01/I02.
It answers a question the schema cannot: whether this tenant's Office audit
records actually carry AppAccessContext.AADSessionId.

rows under "AppAccessContext.AADSessionId" -> the direct session join works
rows only under "RawEventData.SessionId"    -> that is the Exchange mailbox
session id, a DIFFERENT id
space from the Entra one;
I01 is relying on its window
fallback, not the session id
no rows at all                              -> no AppAccessContext in this
tenant's records; account +
window is doing all the work
SessionData.InLineSessionId rows            -> that is the MCAS session-control
id, a third id space: only
match it with InputMcasSessionId

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputSessionId     = "";   // an EntraIdSignInEvents.SessionId
let InputMcasSessionId = "";   // a Defender for Cloud Apps inline session id
                               // (fill either one)
let EntraSide =
    EntraIdSignInEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where SessionId =~ InputSessionId
    | summarize Rows         = count(),
                Accounts     = make_set(AccountUpn, 5),
                Applications = make_set(Application, 10)
              by MatchField = "EntraIdSignInEvents.SessionId";
let CloudSide =
    CloudAppEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSessionId)
    | where isnotempty(InputSessionId) or isnotempty(InputMcasSessionId)
    | extend AADSessionId        = tostring(RawEventData.AppAccessContext.AADSessionId),
             WorkloadSessionId   = tostring(RawEventData.SessionId),
             WorkloadCorrelation = tostring(RawEventData.CorrelationId),
             InLineSessionId     = tostring(SessionData.InLineSessionId)
    | where (isnotempty(InputSessionId)
             and (AADSessionId =~ InputSessionId
                  or WorkloadSessionId =~ InputSessionId
                  or WorkloadCorrelation =~ InputSessionId))
         or (isnotempty(InputMcasSessionId) and InLineSessionId =~ InputMcasSessionId)
    | extend MatchField = case(
          isnotempty(InputMcasSessionId) and InLineSessionId =~ InputMcasSessionId,
              "CloudAppEvents.SessionData.InLineSessionId",
          AADSessionId =~ InputSessionId,
              "CloudAppEvents.RawEventData.AppAccessContext.AADSessionId",
          WorkloadSessionId =~ InputSessionId,
              "CloudAppEvents.RawEventData.SessionId",
          "CloudAppEvents.RawEventData.CorrelationId")
    | summarize Rows         = count(),
                Accounts     = make_set(AccountId, 5),
                Applications = make_set(Application, 10),
                Actions      = make_set(ActionType, 10)
              by MatchField;
union
    (EntraSide | extend Source = "Entra"),
    (CloudSide | extend Source = "CloudApp")
| project Source, MatchField, Rows, Accounts, Applications, Actions
| order by Source asc, Rows desc
```
