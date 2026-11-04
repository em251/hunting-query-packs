# I02 — Session timeline: chronological replay

**Use when:** you need the ordered story for the report or handover.
**Alert fields:** SessionId, CorrelationId, IPAddress, AccountUpn

**Pack:** Identity  
**Tables:** EntraIdSignInEvents, CloudAppEvents, IdentityLogonEvents  
**Inputs:** InputSessionId / InputCorrelationId / InputIpAddress / InputAccountUpn / InputMcasSessionId (fill at least one) + SessionTailHours  
**Performance:** no join. The anchors collapse to one scalar time window plus a small account set; each table semi-joins (`in`) that set inside the window only, so the scan covers hours rather than the whole lookback.

Same anchor, window and account scope as I01, but every event in order — the "walk me through what this user did" view. Run I01 first to size it, then this to read it. `MatchBasis` shows whether a row came from the derived window, a session id, or the source IP.


```kql
let LookbackStart = ago(7d);
let LookbackEnd = now();
let SessionTailHours = 6;
let InputSessionId = "";
let InputCorrelationId = "";
let InputIpAddress = "";
let InputAccountUpn = "";
let InputMcasSessionId = "";
let Anchor =
    EntraIdSignInEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputSessionId) and SessionId =~ InputSessionId)
         or (isnotempty(InputCorrelationId) and CorrelationId =~ InputCorrelationId)
         or (isnotempty(InputIpAddress) and IPAddress == InputIpAddress)
         or (isnotempty(InputAccountUpn) and AccountUpn =~ InputAccountUpn)
    | summarize FirstEvent = min(Timestamp), LastEvent = max(Timestamp), SignIns = count(),
                Ips = make_set(IPAddress, 10), UserAgents = make_set(UserAgent, 5),
                Apps = make_set(Application, 15)
              by AccountUpn, AccountObjectId;
// one window for the whole investigation instead of a per-account join: the
// anchors define both ends, so anything they reference is inside it already
let SessionStart = toscalar(Anchor | summarize min(FirstEvent)) - 1h;
let SessionEnd = toscalar(Anchor | summarize max(LastEvent)) + SessionTailHours * 1h;
let Accounts = Anchor | project ActorKey = tolower(AccountUpn);
let Activity =
    union
        (EntraIdSignInEvents
        | where Timestamp between (SessionStart .. SessionEnd)
        | extend ActorKey = tolower(AccountUpn)
        | where isnotempty(ActorKey) and ActorKey in (Accounts)
        | project Timestamp, Source = "EntraSignIn", ActorKey, Application,
                  Operation = strcat("SignIn err=", tostring(ErrorCode)),
                  Object = ResourceDisplayName, IPAddress, Country, UserAgent),
        (CloudAppEvents
        | where Timestamp between (SessionStart .. SessionEnd)
        | extend ActorKey = tolower(AccountId)
        | where isnotempty(ActorKey) and ActorKey in (Accounts)
        | project Timestamp, Source = "CloudApp", ActorKey, Application,
                  Operation = ActionType, Object = ObjectName, IPAddress,
                  Country = CountryCode, UserAgent,
                  AADSessionId = tostring(RawEventData.AppAccessContext.AADSessionId),
                  WorkloadSessionId = tostring(RawEventData.SessionId),
                  InLineSessionId = tostring(SessionData.InLineSessionId)),
        (IdentityLogonEvents
        | where Timestamp between (SessionStart .. SessionEnd)
        | extend ActorKey = tolower(AccountUpn)
        | where isnotempty(ActorKey) and ActorKey in (Accounts)
        | project Timestamp, Source = "IdentityLogon", ActorKey, Application,
                  Operation = ActionType, Object = DeviceName, IPAddress,
                  Country = Location, UserAgent = strcat(""));
Activity
| extend MatchBasis = case(
      isnotempty(InputSessionId) and AADSessionId =~ InputSessionId, "AADSessionId",
      isnotempty(InputSessionId) and WorkloadSessionId =~ InputSessionId, "workloadSessionId",
      isnotempty(InputMcasSessionId) and InLineSessionId =~ InputMcasSessionId, "mcasInlineSessionId",
      isnotempty(InputIpAddress) and IPAddress == InputIpAddress, "sourceIp",
      "account+window")
| project-reorder Timestamp, Source, Application, Operation, Object, IPAddress, Country, MatchBasis
| order by Timestamp asc
| take 2000
```
