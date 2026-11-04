# P05 — Attachment scope and endpoint landing

**Use when:** the payload is an attachment and you need who received it and whether it ran.
**Alert fields:** FileName, SHA256, NetworkMessageId

**Pack:** Phishing  
**Tables:** EmailAttachmentInfo, EmailEvents, DeviceFileEvents  
**Inputs:** InputAttachmentName, InputAttachmentSha256 (both OPTIONAL)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Answers: which recipients got this attachment, and did the same SHA256 land
on an endpoint? The endpoint join is the difference between "blocked" and
"executed".

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAttachmentName   = "";   // e.g. "invoice.htm"
let InputAttachmentSha256 = "";
let TargetedAttachments =
    EmailAttachmentInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isempty(InputAttachmentName)   or FileName =~ InputAttachmentName)
        and (isempty(InputAttachmentSha256) or SHA256 =~ InputAttachmentSha256)
    | project NetworkMessageId, RecipientEmailAddress, FileName, FileType, FileExtension,
              SHA256, FileSize, AttachmentVerdict = ThreatTypes;
let Messages =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | project NetworkMessageId, RecipientEmailAddress, MessageTime = Timestamp, Subject,
              SenderFromAddress, SenderIPv4, DeliveryAction, DeliveryLocation,
              MessageVerdict = ThreatTypes, DetectionMethods;
let LandedFiles =
    DeviceFileEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where ActionType in ("FileCreated", "FileModified")
    | where isnotempty(SHA256)
    | project SHA256, DeviceName, DeviceId, LandingTime = Timestamp,
              LandedFolderPath = FolderPath, LandedFileName = FileName,
              FileOriginUrl, FileOriginIP, InitiatingProcessFileName, InitiatingProcessAccountUpn;
TargetedAttachments
| join kind=inner Messages on NetworkMessageId, RecipientEmailAddress
| join kind=leftouter LandedFiles on SHA256
| extend LandedOnDevice = isnotempty(DeviceName)
| project-reorder MessageTime, RecipientEmailAddress, Subject, SenderFromAddress, DeliveryAction,
                  FileName, SHA256, LandedOnDevice, DeviceName, LandedFolderPath, LandingTime
| order by MessageTime desc
| take 1000
```
