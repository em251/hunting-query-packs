# C15 — First-time-seen attributes for a user (LastSeenForUser < 0)

**Pack:** Cloud  
**Tables:** CloudAppEvents  
**Inputs:** InputAccountObjectId or InputAccountId (REQUIRED)  
**Schema:** verified against the current Defender XDR advanced hunting schema.  
**Performance:** time-bounded with 'between'; entity filters before summarize/joins.

LastSeenForUser is a bag of attribute -> days since that attribute was last
seen for this user. A negative value means "first time ever", which is the
cleanest anomaly signal in the table and is easy to throw away by accident.
Expands the bag so each new attribute is its own row with context.

```kql
let LookbackStart = ago(7d);
let LookbackEnd   = now();
let InputAccountObjectId = "";
let InputAccountId       = "";
CloudAppEvents
| where Timestamp between (LookbackStart .. LookbackEnd)
| where (isnotempty(InputAccountObjectId) and AccountObjectId =~ InputAccountObjectId)
     or (isnotempty(InputAccountId) and AccountId =~ InputAccountId)
| where isnotempty(LastSeenForUser)
| mv-expand Attribute = bag_keys(LastSeenForUser)
| extend AttributeName = tostring(Attribute)
| extend DaysSinceSeen = toint(LastSeenForUser[AttributeName])
| where DaysSinceSeen < 0
| summarize FirstSeenEvents = count(),
            FirstSeenAt    = min(Timestamp),
            Actions        = make_set(ActionType, 10),
            Applications   = make_set(Application, 5),
            Countries      = make_set(CountryCode, 5),
            Ips            = make_set(IPAddress, 5)
          by AttributeName
| order by FirstSeenAt desc
| take 100
```
