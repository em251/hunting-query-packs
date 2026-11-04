# P02 — Campaign interaction: users who clicked, and what they clicked

**Pack:** Phishing  
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents  
**Inputs:** InputNetworkMessageId, InputEmailClusterId, InputSubjectContains, InputSenderFrom, InputSenderDomain, InputAttachmentName, InputAttachmentSha256, InputUrlContains, InputUrlDomain (all OPTIONAL but fill at least one)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** every scope branch is time-bounded and projects only NetworkMessageId before the union; the click and delivery joins run on that id set.

OR-scoped campaign, not id-scoped. Each selector contributes message ids
independently, so "users who clicked anything from this sender OR with this
subject OR carrying this attachment OR containing this URL" is one result.
Click scope is deliberately wider than delivery scope: a click on a matching
URL counts even when the message attribute itself did not match.

Clicks are NOT filtered by mailbox state. The click side joins UrlClickEvents
on NetworkMessageId only, and Impacted unions clickers with delivered
recipients - so a user whose message was quarantined, purged or ZAP'd after
the click still appears here. StillInMailbox is a reported column, not a
filter. The only ways a click is missed: the click fell outside LookbackStart,
or the tenant runs no Safe Links policy, in which case UrlClickEvents is empty
for everyone.

Empty selectors contribute nothing - unlike the single-pivot queries in this
pack, an unfilled P02 returns no rows rather than the whole window. That is
intentional: the answer is meaningless without a scope definition.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
// --- scope selectors: fill any combination --------------------------------
let InputNetworkMessageId = "";
let InputEmailClusterId   = "";
let InputSubjectContains  = "";
let InputSenderFrom       = "";
let InputSenderDomain     = "";
let InputAttachmentName   = "";
let InputAttachmentSha256 = "";
let InputUrlContains      = "";
let InputUrlDomain        = "";
// --- one branch per selector; each guarded so an empty input adds no ids ---
let ScopeByMessageId =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputNetworkMessageId) and NetworkMessageId =~ InputNetworkMessageId
    | project NetworkMessageId
    | extend Match = "NetworkMessageId";
let ScopeByCluster =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputEmailClusterId) and tostring(EmailClusterId) == InputEmailClusterId
    | project NetworkMessageId
    | extend Match = "Cluster";
let ScopeBySubject =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSubjectContains) and Subject has InputSubjectContains
    | project NetworkMessageId
    | extend Match = "Subject";
let ScopeBySender =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSenderFrom) and SenderFromAddress has InputSenderFrom
    | project NetworkMessageId
    | extend Match = "Sender";
let ScopeBySenderDomain =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where isnotempty(InputSenderDomain) and SenderFromDomain =~ InputSenderDomain
    | project NetworkMessageId
    | extend Match = "SenderDomain";
let ScopeByAttachment =
    EmailAttachmentInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputAttachmentName)   and FileName =~ InputAttachmentName)
         or (isnotempty(InputAttachmentSha256) and SHA256 =~ InputAttachmentSha256)
    | project NetworkMessageId
    | extend Match = "Attachment";
let ScopeByHtmlUrls =
    EmailUrlInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputUrlContains) and Url has InputUrlContains)
         or (isnotempty(InputUrlDomain)   and UrlDomain =~ InputUrlDomain)
    | project NetworkMessageId
    | extend Match = "UrlInMessage";
// clicks on a matching URL count even if the message body was never indexed
let ScopeByClickedUrl =
    UrlClickEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isnotempty(InputUrlContains) and Url has InputUrlContains)
         or (isnotempty(InputUrlDomain)   and Url has InputUrlDomain)
    | project NetworkMessageId
    | extend Match = "UrlClicked";
let Scope =
    union ScopeByMessageId, ScopeByCluster, ScopeBySubject, ScopeBySender,
          ScopeBySenderDomain, ScopeByAttachment, ScopeByHtmlUrls, ScopeByClickedUrl
    | where isnotempty(NetworkMessageId)
    | summarize MatchReasons = strcat_array(make_set(Match, 10), "+") by NetworkMessageId;
// --- impacted = delivered recipients UNION clickers -----------------------
let Delivered =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId in (Scope)
    | summarize arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              DeliveryAction, DeliveryLocation, LatestDeliveryLocation, ThreatTypes;
let Clicked =
    UrlClickEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId in (Scope)
    | extend RecipientEmailAddress = tolower(AccountUpn)
    | summarize Clicks         = count(),
                BlockedClicks  = countif(ActionType != "ClickAllowed"),
                ClickedThrough = countif(IsClickedThrough),
                FirstClick     = min(Timestamp),
                LastClick      = max(Timestamp),
                ClickedUrls    = make_set(Url, 5),
                ClickActions   = make_set(ActionType, 5)
              by RecipientEmailAddress, NetworkMessageId;
// recipients who got it, users who clicked it, deduplicated to the pair
let Impacted =
    union
        (Delivered | project NetworkMessageId, RecipientEmailAddress),
        (Clicked   | project NetworkMessageId, RecipientEmailAddress)
    | distinct NetworkMessageId, RecipientEmailAddress;
Impacted
| join kind=leftouter Delivered on NetworkMessageId, RecipientEmailAddress
| join kind=leftouter Clicked   on NetworkMessageId, RecipientEmailAddress
| join kind=leftouter Scope     on NetworkMessageId
| extend ClickedAny    = isnotempty(FirstClick),
         StillInMailbox = LatestDeliveryLocation has_any ("Inbox", "Junk", "Deleted")
| summarize InScopeMessages = dcount(NetworkMessageId),
            DeliveredCount  = countif(isnotempty(DeliveryAction)),
            ClickedMessages = dcountif(NetworkMessageId, ClickedAny),
            BlockedClicks   = sum(BlockedClicks),
            ClickedThrough  = sum(ClickedThrough),
            FirstClick      = min(FirstClick),
            LastClick       = max(LastClick),
            StillInMailbox  = countif(StillInMailbox),
            DeliveryActions = make_set(DeliveryAction, 5),
            Locations       = make_set(LatestDeliveryLocation, 5),
            Subjects        = make_set(Subject, 5),
            Senders         = make_set(SenderFromAddress, 5),
            SampleClickedUrls = any(ClickedUrls),
            ClickActions    = make_set(ClickActions, 5),
            MatchReasons    = make_set(MatchReasons, 10)
          by RecipientEmailAddress
| extend ClickedAny = ClickedMessages > 0
| order by ClickedMessages desc, InScopeMessages desc
| take 2000
```
