# P10 — Sender infrastructure reuse

**Use when:** you want sibling campaigns from the same sending IP or Mail-From domain.
**Alert fields:** SenderIPv4, SenderMailFromDomain

**Pack:** Phishing  
**Tables:** EmailEvents  
**Inputs:** Threshold (default 3), InputThreatType (OPTIONAL)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Sending IPs and Mail-From domains that pushed multiple distinct messages at
you - the pivot that finds sibling campaigns the alert did not surface.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let Threshold     = 3;
let InputThreatType = "";   // e.g. "Phish"
let SuspiciousMail =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where EmailDirection == "Inbound"
    | where (isempty(InputThreatType)
             or ThreatTypes has InputThreatType
             or DeliveryAction in ("Junked", "Blocked"))
    | project Timestamp, NetworkMessageId, SenderIPv4, SenderMailFromDomain,
              SenderFromDomain, SenderFromAddress, RecipientEmailAddress, Subject,
              DeliveryAction, ThreatTypes;
SuspiciousMail
| summarize Messages   = dcount(NetworkMessageId),
            Recipients = dcount(RecipientEmailAddress),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp),
            SenderDomains = make_set(SenderFromDomain, 10),
            SampleSubjects = make_set(Subject, 5)
          by SenderIPv4, SenderMailFromDomain
| where Messages >= Threshold
| order by Messages desc
| take 50
```
