# P09 — Authentication failures, envelope/header mismatch, first contact

**Pack:** Phishing  
**Tables:** EmailEvents  
**Inputs:** InputSenderDomain, InputRecipientDomain, InputThreatType (all OPTIONAL)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Triage a wave of inbound mail for spoofing indicators: DMARC/DKIM/SPF
failures, From-domain != Mail-From domain, first-ever contact, and the
sender infrastructure behind them.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputSenderDomain    = "";
let InputRecipientDomain = "";
let InputThreatType      = "";   // "Phish", "Malware", "Spam" or ""
EmailEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where EmailDirection == "Inbound"
| where (isempty(InputSenderDomain)    or SenderFromDomain =~ InputSenderDomain)
    and (isempty(InputRecipientDomain) or RecipientDomain =~ InputRecipientDomain)
    and (isempty(InputThreatType)      or ThreatTypes has InputThreatType)
| extend AuthFailures = AuthenticationDetails has_any ("fail", "softfail", "none"),
         EnvelopeMismatch = not(SenderFromDomain =~ SenderMailFromDomain),
         FirstContact = IsFirstContact == 1
| where AuthFailures or EnvelopeMismatch or FirstContact
| summarize Emails = count(),
            Recipients = dcount(RecipientEmailAddress),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            AuthDetails = make_set(AuthenticationDetails, 5),
            SenderIps = make_set(SenderIPv4, 10),
            SenderDomains = make_set(SenderFromDomain, 5),
            EnvelopeDomains = make_set(SenderMailFromDomain, 5),
            Threats = make_set(ThreatTypes, 5),
            SampleSubjects = make_set(Subject, 5)
          by SenderFromAddress, EnvelopeMismatch, FirstContact
| order by Emails desc
| take 100
```
