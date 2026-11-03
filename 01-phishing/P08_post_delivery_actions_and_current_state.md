# P08 — Post-delivery actions (ZAP / purge) and current mailbox state

**Pack:** Phishing  
**Tables:** EmailEvents, EmailPostDeliveryEvents  
**Inputs:** InputNetworkMessageId (REQUIRED)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Delivery verdict at time of delivery vs today, plus every post-delivery
action taken (ZAP, manual purge, user report) with actor and result.

```kql
let LookbackStart = ago(30d);   // post-delivery actions land later than delivery
let LookbackEnd   = now();
let InputNetworkMessageId = "";   // REQUIRED

let CurrentState =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId =~ InputNetworkMessageId
    | summarize arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              DetectedAt = Timestamp, DeliveryAction, DeliveryLocation,
              OriginalThreatTypes, OriginalDetectionMethods,
              LatestDeliveryAction, LatestDeliveryLocation,
              CurrentThreatTypes = ThreatTypes, CurrentDetectionMethods = DetectionMethods;
let PostDelivery =
    EmailPostDeliveryEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where NetworkMessageId =~ InputNetworkMessageId
    | summarize PostDeliveryActions = make_set(strcat(ActionType, " / ", Action, " -> ", ActionResult), 20),
                ActionTriggers = make_set(ActionTrigger, 5),
                ActionTimes = make_set(Timestamp, 20),
                ActionBySource = make_set(SourceLocation, 5)
              by NetworkMessageId, RecipientEmailAddress;
CurrentState
| join kind=leftouter PostDelivery on NetworkMessageId, RecipientEmailAddress
| order by DetectedAt desc
| take 500
```
