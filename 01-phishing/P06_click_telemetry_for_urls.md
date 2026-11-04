# P06 — Who clicked - UrlClickEvents joined back to the message

**Pack:** Phishing  
**Tables:** UrlClickEvents, EmailEvents  
**Inputs:** InputUrlDomain, InputUrlContains, InputNetworkMessageId (all OPTIONAL)  
**Schema:** every column below exists in the current Defender XDR advanced hunting schema (learn.microsoft.com/defender-xdr/advanced-hunting-*-table).  
**Performance:** time-bounded with 'between', filters pushed before joins/summarize.

Safe Links click records: allowed vs blocked, clicked-through, per user.
This is the fastest way to size user exposure after a campaign.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputUrlDomain        = "";
let InputUrlContains      = "";
let InputNetworkMessageId = "";
let Clicks =
    UrlClickEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | where (isempty(InputUrlDomain)        or Url has InputUrlDomain)
        and (isempty(InputUrlContains)      or Url has InputUrlContains)
        and (isempty(InputNetworkMessageId) or NetworkMessageId =~ InputNetworkMessageId)
    | summarize Clicks       = count(),
                FirstClick   = min(Timestamp),
                LastClick    = max(Timestamp),
                Blocked      = countif(ActionType != "ClickAllowed"),
                ClickedThrough = countif(IsClickedThrough),
                ClickActions = make_set(ActionType, 5),
                SourceIps    = make_set(IPAddress, 10),
                Workloads    = make_set(Workload, 3)
              by AccountUpn, Url, NetworkMessageId
    | extend RecipientEmailAddress = tolower(AccountUpn);
let Messages =
    EmailEvents
    | where Timestamp between (LookbackStart .. LookbackEnd)
    | summarize arg_max(Timestamp, *) by NetworkMessageId, RecipientEmailAddress
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              DeliveryAction, DeliveryLocation, ThreatTypes;
Clicks
| join kind=leftouter Messages on NetworkMessageId, RecipientEmailAddress
| project-reorder FirstClick, AccountUpn, Url, Clicks, Blocked, ClickedThrough,
                  Subject, SenderFromAddress, DeliveryAction, DeliveryLocation
| order by Clicks desc
| take 500
```
