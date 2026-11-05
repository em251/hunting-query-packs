# P03 — Message triage by NetworkMessageId

**Use when:** you have one message id and need verdict, action, attachments, URLs and whether each recipient clicked.
**Alert fields:** NetworkMessageId

**Pack:** Phishing  
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents  
**Inputs:** InputNetworkMessageId (REQUIRED)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

One row per recipient with: delivery verdict, final action, attachments (name + hash), every URL in the body, and that recipient's click outcome. This is the "open the email" query - it now answers "did they click" without a second step.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputNetworkMessageId = "";   // REQUIRED - paste the NetworkMessageId
let MessageEvents =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId =~ InputNetworkMessageId
    | summarize arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
    | project Timestamp, NetworkMessageId, InternetMessageId, EmailClusterId,
              Subject, SenderFromAddress, SenderDisplayName, SenderFromDomain,
              SenderMailFromDomain, SenderIPv4, RecipientEmailAddress, RecipientDomain,
              EmailDirection, DeliveryAction, DeliveryLocation, LatestDeliveryAction,
              LatestDeliveryLocation, ThreatTypes, ThreatNames, DetectionMethods,
              ConfidenceLevel, AuthenticationDetails, EmailAction, EmailActionPolicy,
              AttachmentCount, UrlCount, IsFirstContact;
let AttachmentSummary =
    EmailAttachmentInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId =~ InputNetworkMessageId
    | summarize AttachmentFiles  = make_set(FileName, 20),
                AttachmentHashes = make_set(SHA256, 20),
                AttachmentTypes  = make_set(FileType, 10),
                AttachmentSizes  = make_set(FileSize, 20),
                AttachmentVerdict = make_set(ThreatTypes, 5),
                AttachmentDetections = make_set(DetectionMethods, 5)
              by NetworkMessageId, RecipientEmailAddress;
let UrlSummary =
    EmailUrlInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId =~ InputNetworkMessageId
    | summarize UrlDomains = make_set(UrlDomain, 20),
                Urls       = make_set(Url, 20)
              by NetworkMessageId;
let ClickSummary =
    UrlClickEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId =~ InputNetworkMessageId
    | extend RecipientEmailAddress = tolower(AccountUpn)
    | summarize Clicks          = count(),
                BlockedClicks   = countif(ActionType != "ClickAllowed"),
                ClickedThrough  = countif(IsClickedThrough),
                FirstClick      = min(Timestamp),
                ClickedUrls     = make_set(Url, 10),
                ClickActions    = make_set(ActionType, 5)
              by NetworkMessageId, RecipientEmailAddress;
MessageEvents
| join kind=leftouter AttachmentSummary on NetworkMessageId, RecipientEmailAddress
| join kind=leftouter UrlSummary on NetworkMessageId
| join kind=leftouter ClickSummary on NetworkMessageId, RecipientEmailAddress
| extend Clicked = isnotempty(FirstClick)
| project-reorder Timestamp, RecipientEmailAddress, Clicked, ClickedUrls, Clicks,
                  BlockedClicks, Subject, SenderFromAddress, DeliveryAction, DeliveryLocation,
                  ThreatTypes, ThreatNames, AttachmentFiles, AttachmentHashes
| order by Timestamp desc
| take 500
```
