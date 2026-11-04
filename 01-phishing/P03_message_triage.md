# P03 — Message triage by NetworkMessageId

**Use when:** you have one message id and need verdict, action, attachments and URLs.
**Alert fields:** NetworkMessageId

**Pack:** Phishing  
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo  
**Inputs:** InputNetworkMessageId (REQUIRED)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

One row per recipient with: delivery verdict, final action, attachments
(name + hash), and every URL in the body. This is the "open the email" query.

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
MessageEvents
| join kind=leftouter AttachmentSummary on NetworkMessageId, RecipientEmailAddress
| join kind=leftouter UrlSummary on NetworkMessageId
| project-reorder Timestamp, RecipientEmailAddress, Subject, SenderFromAddress,
                  DeliveryAction, DeliveryLocation, ThreatTypes, ThreatNames
| order by Timestamp desc
| take 500
```
