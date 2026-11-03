# P12 — Lookalike / cousin domains for a brand or partner domain

**Pack:** Phishing  
**Tables:** EmailEvents, EmailUrlInfo  
**Inputs:** InputBrandDomain (REQUIRED, e.g. contoso.com)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Finds senders or URL domains that contain the brand token but are not the
real domain. Cheap approximation of a typosquat sweep across mail and URLs.

```kql
let LookbackStart = ago(14d);
let LookbackEnd   = now();
let InputBrandDomain = "";   // REQUIRED - e.g. "contoso.com"
let BrandToken = tostring(split(InputBrandDomain, ".")[0]);   // "contoso"

let MailSenders =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where EmailDirection == "Inbound"
    | where SenderFromDomain has BrandToken and SenderFromDomain !~ InputBrandDomain
    | summarize Emails = count(), Recipients = dcount(RecipientEmailAddress),
                LastSeen = max(Timestamp), Threats = make_set(ThreatTypes, 3)
              by SenderFromDomain
    | extend Vector = "Sender domain";
let UrlDomains =
    EmailUrlInfo
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where UrlDomain has BrandToken and UrlDomain !~ InputBrandDomain
    | summarize Emails = count(), Recipients = dcount(NetworkMessageId),
                LastSeen = max(Timestamp)
              by UrlDomain
    | extend Threats = dynamic([]), Vector = "URL domain";
union MailSenders, UrlDomains
| extend Domain = coalesce(SenderFromDomain, UrlDomain)
| project-reorder Domain, Vector, Emails, Recipients, LastSeen, Threats
| order by Emails desc
| take 100
```
