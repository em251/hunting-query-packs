# P04 — Campaign discovery by subject / sender / recipient attributes

**Pack:** Phishing  
**Tables:** EmailEvents  
**Inputs:** InputSubjectContains, InputSenderFrom, InputSenderDomain, InputSenderIp, InputRecipientDomain (all OPTIONAL)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Groups matching mail into clusters so you can see campaign shape before
pivoting to a single message. Start here when you have no ID yet.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputSubjectContains = "";   // e.g. "invoice"
let InputSenderFrom      = "";
let InputSenderDomain    = "";
let InputSenderIp        = "";
let InputRecipientDomain = "";

EmailEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isempty(InputSubjectContains) or Subject has InputSubjectContains)
    and (isempty(InputSenderFrom)      or SenderFromAddress has InputSenderFrom)
    and (isempty(InputSenderDomain)    or SenderFromDomain =~ InputSenderDomain)
    and (isempty(InputSenderIp)        or SenderIPv4 == InputSenderIp)
    and (isempty(InputRecipientDomain) or RecipientDomain =~ InputRecipientDomain)
| summarize Emails          = count(),
            Recipients      = dcount(RecipientEmailAddress),
            Senders         = dcount(SenderFromAddress),
            SenderIps       = dcount(SenderIPv4),
            FirstSeen       = min(Timestamp),
            LastSeen        = max(Timestamp),
            DeliveryActions = make_set(DeliveryAction, 5),
            Locations       = make_set(DeliveryLocation, 5),
            Threats         = make_set(ThreatTypes, 5),
            SampleSubjects  = make_set(Subject, 5),
            SampleSenders   = make_set(SenderFromAddress, 5)
          by EmailClusterId
| order by Emails desc
| take 25
```
