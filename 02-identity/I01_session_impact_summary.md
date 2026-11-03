# I01 — Session impact summary: every workload the session touched

**Pack:** Identity  
**Tables:** EntraIdSignInEvents, CloudAppEvents, IdentityLogonEvents  
**Inputs:** InputSessionId / InputCorrelationId / InputIpAddress / InputAccountUpn / InputMcasSessionId (fill at least one) + SessionTailHours  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** anchor is one bounded sign-in scan; each downstream table joins that small per-account window set instead of scanning user history.

The impact-analysis query, scoped to one account. Paste whatever you have -
session id, correlation id, source IP, MCAS inline session id - and see one
row per source/application/operation: did the session only read mail, or did
it send, share, download or change mailbox configuration.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let SessionTailHours = 6;             // activity considered part of the session

// --- anchors: fill any one, they are OR conditions ------------------------
let InputSessionId      = "";         // EntraIdSignInEvents.SessionId
let InputCorrelationId  = "";         // EntraIdSignInEvents.CorrelationId
let InputIpAddress      = "";         // sign-in source IP
let InputAccountUpn     = "";         // the account under investigation
let InputMcasSessionId  = "";         // CloudAppEvents.SessionData.InLineSessionId
                                      // (Defender for Cloud Apps inline session -
                                      //  a DIFFERENT id space from the Entra one)

// --- anchor: the sign-in(s) matching any identifier, per account ----------
let Anchor =
    EntraIdSignInEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputSessionId)     and SessionId =~ InputSessionId)
         or (isnotempty(InputCorrelationId) and CorrelationId =~ InputCorrelationId)
         or (isnotempty(InputIpAddress)     and IPAddress == InputIpAddress)
         or (isnotempty(InputAccountUpn)    and AccountUpn =~ InputAccountUpn)
    | summarize FirstEvent = min(Timestamp),
                LastEvent  = max(Timestamp),
                SignIns    = count(),
                Ips        = make_set(IPAddress, 10),
                UserAgents = make_set(UserAgent, 5),
                Apps       = make_set(Application, 15)
              by AccountUpn, AccountObjectId;
let Window =
    Anchor
    | extend WindowStart = FirstEvent - 1h,
             WindowEnd   = LastEvent + SessionTailHours * 1h
    | project ActorKey = tolower(AccountUpn), WindowStart, WindowEnd;

// Scope = the account (the tent of the investigation). Inside that account the
// rows come from ANY of: the derived session window, the Entra session id, the
// Entra correlation id, the source IP, or the Defender for Cloud Apps inline
// session id. MatchBasis tells you which anchor pulled each row in.
//
// The session id reaches CloudAppEvents through the payload, because there is no
// typed column for it:
//   RawEventData.AppAccessContext.AADSessionId - "the Microsoft Entra SessionId
//      of the Entra sign-in that was performed by the app on behalf of the user"
//   RawEventData.SessionId                    - Exchange mailbox session (its own
//      id space; will not equal an Entra session id)
//   RawEventData.CorrelationId                - workload correlation id
//   SessionData.InLineSessionId               - MCAS session-control id (typed
//      column, but a separate id space again - use InputMcasSessionId for it)
let Activity =
    union
        (EntraIdSignInEvents
        | where Timestamp between (LookbackStart .. LookbackEnd)
        | where isnotempty(AccountUpn)
        | extend ActorKey = tolower(AccountUpn)
        | join kind=inner (Window) on ActorKey
        | where (Timestamp >= WindowStart and Timestamp <= WindowEnd)
             or (isnotempty(InputSessionId)     and SessionId =~ InputSessionId)
             or (isnotempty(InputCorrelationId) and CorrelationId =~ InputCorrelationId)
             or (isnotempty(InputIpAddress)     and IPAddress == InputIpAddress)
        | extend MatchBasis = case(
              isnotempty(InputCorrelationId) and CorrelationId =~ InputCorrelationId, "correlationId",
              isnotempty(InputSessionId)     and SessionId =~ InputSessionId,         "sessionId",
              isnotempty(InputIpAddress)     and IPAddress == InputIpAddress,         "sourceIp",
              "account+window")
        | project Timestamp, Source = "EntraSignIn", ActorKey, Application,
                  Operation = strcat("SignIn err=", tostring(ErrorCode)),
                  Object = ResourceDisplayName, IPAddress, Country, UserAgent,
                  MatchBasis),
        (CloudAppEvents
        | where Timestamp between (LookbackStart .. LookbackEnd)
        | where isnotempty(AccountId)
        | extend ActorKey              = tolower(AccountId),
                 AADSessionId          = tostring(RawEventData.AppAccessContext.AADSessionId),
                 WorkloadSessionId     = tostring(RawEventData.SessionId),
                 WorkloadCorrelationId = tostring(RawEventData.CorrelationId),
                 InLineSessionId       = tostring(SessionData.InLineSessionId)
        | join kind=inner (Window) on ActorKey
        | where (Timestamp >= WindowStart and Timestamp <= WindowEnd)
             or (isnotempty(InputSessionId)
                 and (AADSessionId =~ InputSessionId or WorkloadSessionId =~ InputSessionId))
             or (isnotempty(InputCorrelationId) and WorkloadCorrelationId =~ InputCorrelationId)
             or (isnotempty(InputMcasSessionId) and InLineSessionId =~ InputMcasSessionId)
             or (isnotempty(InputIpAddress)     and IPAddress == InputIpAddress)
        | extend MatchBasis = case(
              isnotempty(InputSessionId)      and AADSessionId =~ InputSessionId,          "AADSessionId",
              isnotempty(InputSessionId)      and WorkloadSessionId =~ InputSessionId,     "workloadSessionId",
              isnotempty(InputCorrelationId)  and WorkloadCorrelationId =~ InputCorrelationId, "workloadCorrelationId",
              isnotempty(InputMcasSessionId)  and InLineSessionId =~ InputMcasSessionId,   "mcasInlineSessionId",
              isnotempty(InputIpAddress)      and IPAddress == InputIpAddress,             "sourceIp",
              "account+window")
        | project Timestamp, Source = "CloudApp", ActorKey, Application,
                  Operation = ActionType, Object = ObjectName, IPAddress,
                  Country = CountryCode, UserAgent, MatchBasis),
        (IdentityLogonEvents
        | where Timestamp between (LookbackStart .. LookbackEnd)
        | where isnotempty(AccountUpn)
        | extend ActorKey = tolower(AccountUpn)
        | join kind=inner (Window) on ActorKey
        | where (Timestamp >= WindowStart and Timestamp <= WindowEnd)
             or (isnotempty(InputIpAddress) and IPAddress == InputIpAddress)
        | extend MatchBasis = case(
              isnotempty(InputIpAddress) and IPAddress == InputIpAddress, "sourceIp",
              "account+window")
        | project Timestamp, Source = "IdentityLogon", ActorKey, Application,
                  Operation = ActionType, Object = DeviceName, IPAddress,
                  Country = Location, UserAgent = strcat(""), MatchBasis);

Activity
| summarize Events         = count(),
            FirstSeen      = min(Timestamp),
            LastSeen       = max(Timestamp),
            Objects        = make_set(Object, 10),
            Ips            = make_set(IPAddress, 5),
            Countries      = make_set(Country, 5),
            UserAgents     = make_set(UserAgent, 3),
            DirectlyAnchored = countif(MatchBasis in ("sessionId","AADSessionId",
                                                      "workloadSessionId","correlationId",
                                                      "workloadCorrelationId","mcasInlineSessionId"))
          by Source, Application, Operation
| order by Events desc
| take 200
```
