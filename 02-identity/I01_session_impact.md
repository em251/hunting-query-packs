# I01 — Session impact: every workload the session touched

**Use when:** you have a session id, correlation id, IP or UPN and need one summary of what the session did.
**Alert fields:** SessionId, CorrelationId, IPAddress, AccountUpn

**Pack:** Identity  
**Tables:** EntraIdSignInEvents, CloudAppEvents, IdentityLogonEvents  
**Inputs:** InputSessionId / InputCorrelationId / InputIpAddress / InputAccountUpn / InputMcasSessionId (fill at least one) + SessionTailHours  
**Performance:** no join. The anchors collapse to one scalar time window plus a small account set; each table semi-joins (`in`) that set inside the window only, so the scan covers hours rather than the whole lookback.

The impact-analysis query, scoped to one account. Paste whatever you have — session id, correlation id, source IP, MCAS inline session id — and get one row per source/application/operation: did the session only read mail, or did it send, share, download or change mailbox configuration.

The anchored sign-ins define a single window (first anchored event − 1h .. last + `SessionTailHours`). Every table is filtered to that window and to the anchored accounts first, so nothing downstream ever sees the full 7-day table.

Cloud app rows carry the session id inside the payload, since there is no typed column for it: `RawEventData.AppAccessContext.AADSessionId` (the Entra session id), `RawEventData.SessionId` (Exchange mailbox session, its own id space), and `SessionData.InLineSessionId` (MCAS session-control, a third id space — which is why it has its own input). `MatchBasis` reports which anchor each row ties back to.


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
| summarize Events = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Objects = make_set(Object, 10), Ips = make_set(IPAddress, 5),
            Countries = make_set(Country, 5), UserAgents = make_set(UserAgent, 3),
            DirectlyAnchored = countif(MatchBasis != "account+window")
          by Source, Application, Operation
| order by Events desc
| take 200
```
