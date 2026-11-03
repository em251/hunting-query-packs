# 

**Pack:** Phishing

```kql
let LookbackStart = ago(7d);            // widen for long-running campaigns
let LookbackEnd   = now();
let Threshold     = 3;                  // generic count threshold for "suspicious enough"

// --- message identity -------------------------------------------------------
let InputNetworkMessageId = "";         // EmailEvents.NetworkMessageId (best pivot)
let InputInternetMessageId = "";        // EmailEvents.InternetMessageId (Message-ID header)
let InputEmailClusterId   = "";         // EmailEvents.EmailClusterId (campaign cluster)

// --- content / envelope -----------------------------------------------------
let InputSubjectContains  = "";         // subject substring, e.g. "invoice"
let InputSenderFrom       = "";         // full sender address
let InputSenderDomain     = "";         // SenderFromDomain exact
let InputSenderIp         = "";         // EmailEvents.SenderIPv4
let InputRecipient        = "";         // RecipientEmailAddress exact
let InputRecipientDomain  = "";         // RecipientDomain exact

// --- payload ----------------------------------------------------------------
let InputAttachmentName   = "";         // EmailAttachmentInfo.FileName
let InputAttachmentSha256 = "";         // EmailAttachmentInfo.SHA256
let InputUrlContains      = "";         // EmailUrlInfo.Url substring
let InputUrlDomain        = "";         // EmailUrlInfo.UrlDomain exact

// --- verdict ----------------------------------------------------------------
let InputThreatType       = "Phish";    // ThreatTypes value: Phish / Malware / Spam
```
