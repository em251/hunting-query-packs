# P01 — Blast radius: message-level campaign scope

**Use when:** a campaign is confirmed and you need every message, recipient, click count and match reason in one table.
**Alert fields:** NetworkMessageId, EmailSubject, SenderFromAddress

**Pack:** Phishing  
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents  
**Inputs:** same selector block as P02  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** one bounded scan per branch, ids deduped once, then a single join.

Message-level companion to P02: same OR selectors, but one row per message
with why it is in scope, where it landed, and how many users clicked it.
Use this to sanity-check the scope before you act on the P02 worklist.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputNetworkMessageId = "";
let InputEmailClusterId   = "";
let InputSubjectContains  = "";
let InputSenderFrom       = "";
let InputSenderDomain     = "";
let InputAttachmentName   = "";
let InputAttachmentSha256 = "";
let InputUrlContains      = "";
let InputUrlDomain        = "";
let ScopeByMessageId =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputNetworkMessageId) and NetworkMessageId =~ InputNetworkMessageId
    | project NetworkMessageId | extend Match = "NetworkMessageId";
let ScopeByCluster =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputEmailClusterId) and tostring(EmailClusterId) == InputEmailClusterId
    | project NetworkMessageId | extend Match = "Cluster";
let ScopeBySubject =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSubjectContains) and Subject has InputSubjectContains
    | project NetworkMessageId | extend Match = "Subject";
let ScopeBySender =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSenderFrom) and SenderFromAddress has InputSenderFrom
    | project NetworkMessageId | extend Match = "Sender";
let ScopeBySenderDomain =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSenderDomain) and SenderFromDomain =~ InputSenderDomain
    | project NetworkMessageId | extend Match = "SenderDomain";
let ScopeByAttachment =
    EmailAttachmentInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputAttachmentName)   and FileName =~ InputAttachmentName)
         or (isnotempty(InputAttachmentSha256) and SHA256 =~ InputAttachmentSha256)
    | project NetworkMessageId | extend Match = "Attachment";
let ScopeByHtmlUrls =
    EmailUrlInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputUrlContains) and Url has InputUrlContains)
         or (isnotempty(InputUrlDomain)   and UrlDomain =~ InputUrlDomain)
    | project NetworkMessageId | extend Match = "UrlInMessage";
let ScopeByClickedUrl =
    UrlClickEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputUrlContains) and Url has InputUrlContains)
         or (isnotempty(InputUrlDomain)   and Url has InputUrlDomain)
    | project NetworkMessageId | extend Match = "UrlClicked";
let Scope =
    union ScopeByMessageId, ScopeByCluster, ScopeBySubject, ScopeBySender,
          ScopeBySenderDomain, ScopeByAttachment, ScopeByHtmlUrls, ScopeByClickedUrl
    | where isnotempty(NetworkMessageId)
    | summarize MatchReasons = strcat_array(make_set(Match, 10), "+") by NetworkMessageId;
let MessageDetail =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId in (Scope)
    | summarize arg_max(Timestamp, *) by NetworkMessageId
    | project NetworkMessageId, SentTime = Timestamp, Subject, SenderFromAddress,
              SenderFromDomain, SenderIPv4, EmailClusterId, DeliveryAction,
              DeliveryLocation, LatestDeliveryAction, LatestDeliveryLocation,
              ThreatTypes, ThreatNames, DetectionMethods, AuthenticationDetails;
let Recipients =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId in (Scope)
    | summarize Recipients = dcount(RecipientEmailAddress) by NetworkMessageId;
let Clicks =
    UrlClickEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId in (Scope)
    | summarize Clickers = dcount(AccountUpn),
                Clicks = count(),
                BlockedClicks = countif(ActionType != "ClickAllowed")
              by NetworkMessageId;
MessageDetail
| join kind=leftouter Scope      on NetworkMessageId
| join kind=leftouter Recipients on NetworkMessageId
| join kind=leftouter Clicks     on NetworkMessageId
| project-reorder SentTime, Subject, SenderFromAddress, DeliveryAction, DeliveryLocation,
                  Recipients, Clickers, Clicks, MatchReasons
| order by Clickers desc, SentTime desc
| take 1000
```
